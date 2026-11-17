import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { createApiServer } from '../src/api/server.js';
import { closeDocStore, listDocsUnder } from '../src/api/docStore.js';
import { generateSigningKey } from '../src/signing.js';
import { buildAccountExport, verifyAccountExport } from '../src/accountExport.js';

// AD-077 (knock-out 2026-11-17): GET /v1/account/export returns one signed JSON bundle with everything the account
// holds (account record without the API key hash, records, uploaded and job files), never another account's data;
// POST /v1/public/verify-report reads it as "account-export" and a one-character change fails; 5 per hour; and after
// deletion nothing remains under the account (files or Postgres rows). Files always; Postgres with PQC_TEST_DATABASE_URL.
const pgUrl = process.env.PQC_TEST_DATABASE_URL;
const sha256 = (s) => createHash('sha256').update(s).digest('hex');
const json = (h) => ({ ...h, 'content-type': 'application/json' });

async function scenario() {
  const apiHome = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-export-'));
  const keyFile = path.join(apiHome, 'signing-key.json');
  await fs.writeFile(keyFile, JSON.stringify(generateSigningKey()));
  const { server } = createApiServer({ apiHome, signingKeyPath: keyFile, handlers: { scan: async () => ({ ok: true, findings: 1 }) } });
  await new Promise((resolve) => server.listen(0, resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const signup = async (name) => (await (await fetch(`${base}/v1/signup`, { method: 'POST', headers: json({}), body: JSON.stringify({ name, email: `${name.replace(/\W/g, '')}@example.test` }) })).json());
    const a = await signup('Export Alpha Co'), b = await signup('Bravo Hidden Co');
    const ah = json({ authorization: `Bearer ${a.apiKey}` }), bh = json({ authorization: `Bearer ${b.apiKey}` });
    const conf = 'ssl_protocols TLSv1.2;\nssl_ciphers RSA;\n';
    const ws = await (await fetch(`${base}/v1/workspaces`, { method: 'POST', headers: ah, body: JSON.stringify({ files: [{ path: 'nginx.conf', content: conf }] }) })).json();
    await fetch(`${base}/v1/workspaces`, { method: 'POST', headers: bh, body: JSON.stringify({ files: [{ path: 'b-secret.conf', content: 'bravo only' }] }) });
    const job = await (await fetch(`${base}/v1/jobs`, { method: 'POST', headers: ah, body: JSON.stringify({ type: 'scan', params: { workspaceId: ws.workspaceId } }) })).json();
    for (let i = 0; i < 200; i++) { const j = await (await fetch(`${base}/v1/jobs/${job.jobId}`, { headers: ah })).json(); if (['succeeded', 'failed'].includes(j.status)) break; await new Promise((r) => setTimeout(r, 25)); }

    assert.equal((await fetch(`${base}/v1/account/export`)).status, 401, 'needs the API key');
    const r = await fetch(`${base}/v1/account/export`, { headers: ah });
    assert.equal(r.status, 200);
    assert.match(r.headers.get('content-disposition') || '', /attachment; filename="pqc-forge-export-/);
    const text = await r.text();
    const bundle = JSON.parse(text);
    assert.equal(bundle.schema, 'pqc-forge.account-export/v1');
    assert.equal(bundle.tenantId, a.tenantId);
    assert.equal(bundle.account.name, 'Export Alpha Co');
    assert.equal(bundle.account.apiKeyHash, undefined);
    const tenantRec = bundle.records.find((x) => x.key === 'tenant.json');
    assert.ok(tenantRec && tenantRec.value.apiKeyHash === undefined, 'tenant record exported without its API key hash');
    assert.ok(bundle.records.some((x) => x.key === `jobs/${job.jobId}/job.json`), 'job record exported');
    assert.ok(bundle.records.some((x) => x.key === `jobs/${job.jobId}/result.json`), 'job result exported');
    const file = bundle.files.find((f) => f.path.endsWith('/nginx.conf'));
    assert.ok(file && Buffer.from(file.contentBase64, 'base64').toString() === conf && file.sha256 === sha256(conf), 'uploaded file exported with content and SHA-256');
    assert.ok(!text.includes(a.apiKey), 'API key never in the export');
    assert.ok(!text.includes(sha256(a.apiKey)), 'API key hash never in the export');
    assert.ok(!text.includes(b.tenantId) && !text.includes('Bravo Hidden Co') && !text.includes('bravo only'), 'another account never appears');
    assert.ok(bundle.excluded.some((e) => e.field === 'apiKeyHash') && bundle.excluded.some((e) => e.field === 'signing key'));

    const verify = async (doc) => (await (await fetch(`${base}/v1/public/verify-report`, { method: 'POST', headers: json({}), body: JSON.stringify(doc) })).json());
    const ok = await verify(bundle);
    assert.equal(ok.valid, true, JSON.stringify(ok));
    assert.equal(ok.kind, 'account-export');
    const edited = JSON.parse(text); edited.account.name = 'Export Alphb Co';
    assert.equal((await verify(edited)).valid, false, 'one character changed fails');
    const forgedFile = JSON.parse(text); forgedFile.files[0].sha256 = '0'.repeat(64);
    assert.equal((await verify(forgedFile)).valid, false, 'a changed file hash fails');

    const bText = await (await fetch(`${base}/v1/account/export`, { headers: bh })).text();
    assert.ok(!bText.includes(a.tenantId) && !bText.includes('Export Alpha Co'), "B's export holds nothing of A");

    const codes = [];
    for (let i = 0; i < 5; i++) codes.push((await fetch(`${base}/v1/account/export`, { headers: ah })).status);
    assert.deepEqual(codes, [200, 200, 200, 200, 429], '5 per hour (the first export counted)');

    // Delete completeness: nothing left under the account, files or rows.
    assert.equal((await fetch(`${base}/v1/account/delete`, { method: 'POST', headers: ah, body: '{"confirm":"DELETE"}' })).status, 200);
    const dir = path.join(apiHome, 'tenants', a.tenantId);
    await assert.rejects(fs.access(dir), 'tenant folder removed');
    assert.deepEqual(await listDocsUnder(apiHome, dir), [], 'no stored record left under the account');
    assert.ok((await listDocsUnder(apiHome, path.join(apiHome, 'tenants', b.tenantId))).length >= (process.env.DATABASE_URL ? 1 : 0), 'other account untouched');
    await fs.access(path.join(apiHome, 'tenants', b.tenantId));
    return { apiHome };
  } finally {
    await new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); });
  }
}

test('account export (files)', async () => {
  const saved = process.env.DATABASE_URL; delete process.env.DATABASE_URL;
  try { await scenario(); } finally { if (saved !== undefined) process.env.DATABASE_URL = saved; }
});

test('account export (Postgres): records come from the database, none left after delete', { skip: !pgUrl && 'set PQC_TEST_DATABASE_URL to a local throwaway Postgres' }, async () => {
  const saved = process.env.DATABASE_URL; process.env.DATABASE_URL = pgUrl;
  try { await scenario(); } finally { await closeDocStore(); if (saved === undefined) delete process.env.DATABASE_URL; else process.env.DATABASE_URL = saved; }
});

test('large files are listed with their SHA-256 instead of inlined; the bundle still verifies', async () => {
  const saved = process.env.DATABASE_URL; delete process.env.DATABASE_URL;
  const apiHome = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-export-cap-'));
  try {
    const K = generateSigningKey();
    const tenantId = 't_0123456789abcdef';
    const dir = path.join(apiHome, 'tenants', tenantId, 'workspaces', 'w1');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(path.join(dir, 'big.bin'), Buffer.alloc(2048, 7));
    const bundle = await buildAccountExport({ apiHome, tenant: { schema: 'pqc-forge.tenant/v1', tenantId, name: 'Cap Co', apiKeyHash: 'sha256:x' }, signingKey: K, inlineLimit: 1024 });
    const big = bundle.files.find((f) => f.path.endsWith('big.bin'));
    assert.ok(big && !big.contentBase64 && /size limit/.test(big.omitted) && big.sha256 === sha256(Buffer.alloc(2048, 7)));
    assert.equal(verifyAccountExport(bundle, [K]).valid, true);
  } finally { if (saved !== undefined) process.env.DATABASE_URL = saved; }
});
