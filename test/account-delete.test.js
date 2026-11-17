import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { createApiServer } from '../src/api/server.js';
import { closeDocStore } from '../src/api/docStore.js';
import { applySubscriptionEvent, setManualPlan } from '../src/billing/entitlements.js';
import { generateSigningKey } from '../src/signing.js';
import { createMigrationReceipt, verifyReceipt } from '../src/breaklab/receipt.js';

// S-14 (knock-out Phase 5): self-service account deletion. POST /v1/account/delete { confirm: "DELETE" } removes the
// account, API key hash, subscription, job records/results and uploaded files; the key stops working; another
// tenant is untouched; it is refused while a paid provider subscription is active or a job is running; receipts
// signed earlier still verify. Runs on files always, and on Postgres when PQC_TEST_DATABASE_URL is set.
const pgUrl = process.env.PQC_TEST_DATABASE_URL;

async function start(handlers) {
  const apiHome = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-del-'));
  const keyFile = path.join(apiHome, 'signing-key.json');
  const K = generateSigningKey();
  await fs.writeFile(keyFile, JSON.stringify(K));
  const { server } = createApiServer({ apiHome, signingKeyPath: keyFile, handlers });
  await new Promise((resolve) => server.listen(0, resolve));
  return { apiHome, K, base: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); }) };
}
const json = (h) => ({ ...h, 'content-type': 'application/json' });

async function scenario() {
  let release;
  const gate = new Promise((r) => { release = r; });
  const s = await start({ scan: async (ctx) => { if (ctx.params && ctx.params.hold) await gate; return { ok: true }; } });
  try {
    const signup = async (name) => (await (await fetch(`${s.base}/v1/signup`, { method: 'POST', headers: json({}), body: JSON.stringify({ name, email: `${name.replace(/\W/g, '')}@example.test` }) })).json());
    const a = await signup('Delete Me Co'), b = await signup('Keep Me Co');
    const ah = json({ authorization: `Bearer ${a.apiKey}` }), bh = json({ authorization: `Bearer ${b.apiKey}` });
    const del = (h, body) => fetch(`${s.base}/v1/account/delete`, { method: 'POST', headers: h, body: JSON.stringify(body) });
    const ws = await (await fetch(`${s.base}/v1/workspaces`, { method: 'POST', headers: ah, body: JSON.stringify({ files: [{ path: 'nginx.conf', content: 'ssl_protocols TLSv1.2;\n' }] }) })).json();
    await (await fetch(`${s.base}/v1/workspaces`, { method: 'POST', headers: bh, body: JSON.stringify({ files: [{ path: 'b.conf', content: 'x' }] }) })).json();
    const waitDone = async (h, id) => { for (let i = 0; i < 200; i++) { const j = await (await fetch(`${s.base}/v1/jobs/${id}`, { headers: h })).json(); if (['succeeded', 'failed'].includes(j.status)) return j; await new Promise((r) => setTimeout(r, 25)); } return null; };
    const job = await (await fetch(`${s.base}/v1/jobs`, { method: 'POST', headers: ah, body: JSON.stringify({ type: 'scan', params: { workspaceId: ws.workspaceId } }) })).json();
    assert.equal((await waitDone(ah, job.jobId)).status, 'succeeded');
    const receipt = createMigrationReceipt({ root: '/workspaces/x', filesChanged: 1, changes: [] }, s.K);

    assert.equal((await fetch(`${s.base}/v1/account/delete`, { method: 'POST', headers: json({}), body: '{"confirm":"DELETE"}' })).status, 401, 'needs the API key');
    assert.equal((await del(ah, {})).status, 400, 'needs the confirmation');
    assert.equal((await del(ah, { confirm: 'delete' })).status, 400, 'exact confirmation');

    const held = await (await fetch(`${s.base}/v1/jobs`, { method: 'POST', headers: ah, body: JSON.stringify({ type: 'scan', params: { workspaceId: ws.workspaceId, hold: true } }) })).json();
    await new Promise((r) => setTimeout(r, 100));
    assert.equal((await del(ah, { confirm: 'DELETE' })).status, 409, 'refused while a job is running');
    release();
    await waitDone(ah, held.jobId);

    await applySubscriptionEvent(s.apiHome, a.tenantId, { plan: 'pro', status: 'active', provider: 'dodo', providerRef: 'sub_x', occurredAt: new Date().toISOString() });
    const paid = await del(ah, { confirm: 'DELETE' });
    assert.equal(paid.status, 409, 'refused while a provider-billed subscription is active');
    assert.match(JSON.stringify(await paid.json()), /Cancel it from the Billing tab/);
    await setManualPlan(s.apiHome, a.tenantId, { plan: 'pro' });

    const ok = await del(ah, { confirm: 'DELETE' });
    assert.equal(ok.status, 200);
    const body = await ok.json();
    assert.equal(body.deleted, true);
    assert.match(body.note, /stay verifiable/);
    assert.equal((await fetch(`${s.base}/v1/subscription`, { headers: ah })).status, 401, 'the deleted key no longer works');
    assert.equal((await fetch(`${s.base}/v1/jobs/${job.jobId}`, { headers: ah })).status, 401);
    await assert.rejects(fs.access(path.join(s.apiHome, 'tenants', a.tenantId)), 'tenant folder (workspaces, job files) removed');
    assert.equal((await fetch(`${s.base}/v1/subscription`, { headers: bh })).status, 200, 'the other tenant still works');
    assert.equal((await (await fetch(`${s.base}/v1/jobs`, { headers: bh })).json()).total, 0);
    await fs.access(path.join(s.apiHome, 'tenants', b.tenantId));
    assert.equal(verifyReceipt(receipt, { trustedPublicKeys: [s.K] }).valid, true, 'receipts signed before the deletion still verify');
    return body;
  } finally {
    await s.close();
  }
}

test('account deletion (files)', async () => {
  const saved = process.env.DATABASE_URL; delete process.env.DATABASE_URL;
  try { const body = await scenario(); assert.equal(body.databaseRecordsDeleted, 0); }
  finally { if (saved !== undefined) process.env.DATABASE_URL = saved; }
});

test('account deletion (Postgres): rows under the tenant are removed', { skip: !pgUrl && 'set PQC_TEST_DATABASE_URL to a local throwaway Postgres' }, async () => {
  const saved = process.env.DATABASE_URL; process.env.DATABASE_URL = pgUrl;
  try { const body = await scenario(); assert.ok(body.databaseRecordsDeleted >= 3, 'tenant, subscription, job records: ' + body.databaseRecordsDeleted); }
  finally { await closeDocStore(); if (saved === undefined) delete process.env.DATABASE_URL; else process.env.DATABASE_URL = saved; }
});
