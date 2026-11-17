import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

// PF-05 (knock-out 2026-11-17) with DATABASE_URL: monitoring settings and signed runs live in Postgres, so they
// survive a restart onto an empty disk; the scheduler finds due accounts through the database; account deletion
// removes them. Injected probe only (no network). Postgres only (PQC_TEST_DATABASE_URL).
const pgUrl = process.env.PQC_TEST_DATABASE_URL;

test('monitoring settings and runs survive a restart; scheduler finds accounts in Postgres; delete removes them', { skip: !pgUrl && 'set PQC_TEST_DATABASE_URL', timeout: 60_000 }, async () => {
  process.env.DATABASE_URL = pgUrl;
  const { createApiServer, provisionTenant } = await import('../src/api/server.js');
  const { setManualPlan } = await import('../src/billing/entitlements.js');
  const { closeDocStore, docDb } = await import('../src/api/docStore.js');
  const { generateSigningKey } = await import('../src/signing.js');
  const K = generateSigningKey();
  const probe = async (target) => ({ target, ok: true, evidence: { generatedAt: new Date().toISOString(), protocol: 'TLSv1.3', ephemeralKey: { name: 'X25519MLKEM768' }, peerSignatureAlgorithm: 'ecdsa_secp256r1_sha256', authorized: true, verdict: { pqKeyExchange: true, pqAuthentication: false }, certificate: { subject: 'e', issuer: 'ca', validFrom: '2026-01-01T00:00:00Z', validTo: '2027-06-01T00:00:00Z', fingerprint256: 'AA', publicKey: 'EC prime256v1' } } });
  async function start() {
    const apiHome = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-monpg-'));
    const keyFile = path.join(apiHome, 'signing-key.json');
    await fs.writeFile(keyFile, JSON.stringify(K));
    const { server, runMonitorPass } = createApiServer({ apiHome, signingKeyPath: keyFile, monitorProbe: probe });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    return { apiHome, runMonitorPass, base: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); }) };
  }
  let A = await start();
  let B = null;
  try {
    const pro = await provisionTenant(A.apiHome, 'Monitor PG Co');
    await setManualPlan(A.apiHome, pro.tenantId, { plan: 'pro' });
    const h = { authorization: `Bearer ${pro.apiKey}`, 'content-type': 'application/json' };
    assert.equal((await fetch(`${A.base}/v1/monitor`, { method: 'POST', headers: h, body: JSON.stringify({ cadence: 'weekly', endpoints: ['edge.example.com'] }) })).status, 200);
    const run1 = await (await fetch(`${A.base}/v1/monitor/run`, { method: 'POST', headers: h })).json();
    assert.match(run1.runId, /^mr_/);
    await A.close(); A = null;

    B = await start(); // empty home, same database
    const listing = await (await fetch(`${B.base}/v1/monitor`, { headers: h })).json();
    assert.equal(listing.cadence, 'weekly');
    assert.deepEqual(listing.endpoints, ['edge.example.com']);
    assert.equal(listing.runs.length, 1);
    assert.equal(listing.runs[0].runId, run1.runId);
    const pass = await B.runMonitorPass(new Date(Date.now() + 8 * 86400000));
    const mine = pass.find((p) => p.tenantId === pro.tenantId);
    assert.ok(mine && mine.runId, JSON.stringify(pass));
    const run2 = await (await fetch(`${B.base}/v1/monitor/runs/${mine.runId}`, { headers: h })).json();
    assert.equal(run2.comparedWith.receiptDigest, run1.receiptDigest);
    const pv = await (await fetch(`${B.base}/v1/public/verify-report`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(run2) })).json();
    assert.equal(pv.valid, true); assert.equal(pv.kind, 'monitor-run');

    const del = await fetch(`${B.base}/v1/account/delete`, { method: 'POST', headers: h, body: JSON.stringify({ confirm: 'DELETE' }) });
    assert.equal(del.status, 200, await del.clone().text());
    const { rows } = await (await docDb()).query(`SELECT count(*)::int AS n FROM pqcf_documents WHERE key LIKE $1`, [`%${pro.tenantId}/monitor%`]);
    assert.equal(rows[0].n, 0, 'monitoring settings and runs are deleted with the account');
  } finally {
    if (A) await A.close();
    if (B) await B.close();
    await closeDocStore();
    delete process.env.DATABASE_URL;
  }
});
