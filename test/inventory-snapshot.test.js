import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { createApiServer, provisionTenant } from '../src/api/server.js';
import { setManualPlan } from '../src/billing/entitlements.js';
import { generateSigningKey } from '../src/signing.js';
import { buildInventorySnapshot, signSnapshot, verifySnapshot, SNAPSHOT_SCHEMA } from '../src/inventorySnapshot.js';

// AD-071 (knock-out Phase 5): a signed point-in-time cryptography inventory for auditors. Pro and above run it
// (Community is refused with the plan message, prices unchanged); it uses no report credit; the downloaded file
// verifies on the public verifier with the server's published keys and fails after a one-character change.
const scan = { filesScanned: 2, unreadableFiles: ['vendor/locked.bin'], findings: [
  { id: 'QF-RSA', category: 'quantum-vulnerable-algorithm', severity: 'high', file: 'src\\pay.js', line: 4, language: 'javascript' },
  { id: 'QF-SHA1', category: 'weak-hash', severity: 'medium', file: 'src/legacy.js', line: 9 },
], summary: { critical: 0, high: 1, medium: 1, low: 0, total: 2, automatable: 0, suppressed: 0 } };

test('snapshot: inventory only, unreadable files listed, signed, tamper and schema checks', () => {
  const snap = buildInventorySnapshot({ label: 'Q4 audit', scan, now: new Date('2026-11-17T00:00:00Z') });
  assert.equal(snap.schema, SNAPSHOT_SCHEMA);
  assert.equal(snap.inventory.length, 2);
  assert.equal(snap.inventory[0].file, 'src/pay.js', 'paths normalised');
  assert.deepEqual(snap.scope.unreadableFiles, ['vendor/locked.bin']);
  assert.match(snap.scope.note, /not a readiness verdict/);
  assert.equal(snap.summary.bySeverity.high, 1);
  assert.ok(!('readiness' in snap) && !('score' in snap), 'no score or stage in a snapshot');
  const K = generateSigningKey();
  const signed = signSnapshot(snap, K);
  assert.equal(verifySnapshot(signed, [K]).valid, true);
  assert.equal(verifySnapshot({ ...signed, label: 'Q4 audiT' }, [K]).valid, false, 'one character changed');
  assert.equal(verifySnapshot({ ...signed, schema: 'pqc-forge.readiness-report/v1' }, [K]).valid, false);
  assert.equal(verifySnapshot(signed, [generateSigningKey()]).valid, false, 'another key is not trusted');
  assert.throws(() => buildInventorySnapshot({ label: 'x', scan: null }), /scanned workspace/);
  assert.doesNotMatch(JSON.stringify(signed), /quantum-safe|quantum-proof/i);
});

test('hosted: Pro runs the snapshot job without a report credit; Community is refused; public verify checks it', async () => {
  const apiHome = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-snap-'));
  const { server } = createApiServer({ apiHome });
  await new Promise((resolve) => server.listen(0, resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const run = async (headers, params) => (await fetch(`${base}/v1/jobs`, { method: 'POST', headers, body: JSON.stringify({ type: 'inventory-snapshot', params }) }));
  try {
    const pro = await provisionTenant(apiHome, 'Pro Co');
    await setManualPlan(apiHome, pro.tenantId, { plan: 'pro' });
    const ph = { authorization: `Bearer ${pro.apiKey}`, 'content-type': 'application/json' };
    const { workspaceId } = await (await fetch(`${base}/v1/workspaces`, { method: 'POST', headers: ph, body: JSON.stringify({ files: [{ path: 'src/token.js', content: "jwt.sign(payload, key, { algorithm: 'RS256' });\n" }] }) })).json();
    const sub = await run(ph, { workspaceId, label: 'Q4 audit' });
    assert.equal(sub.status, 202, await sub.clone().text());
    const job = await sub.json();
    let done;
    for (let i = 0; i < 300; i++) { done = await (await fetch(`${base}/v1/jobs/${job.jobId}`, { headers: ph })).json(); if (['succeeded', 'failed'].includes(done.status)) break; await new Promise((r) => setTimeout(r, 50)); }
    assert.equal(done.status, 'succeeded', JSON.stringify(done));
    const result = await (await fetch(`${base}/v1/jobs/${job.jobId}/result`, { headers: ph })).json();
    assert.deepEqual(result.files, ['inventory-snapshot.json']);
    const file = await fetch(`${base}/v1/jobs/${job.jobId}/files/inventory-snapshot.json`, { headers: ph });
    assert.equal(file.status, 200);
    const doc = await file.json();
    assert.equal(doc.schema, SNAPSHOT_SCHEMA);
    assert.ok(doc.inventory.length >= 1);
    const pv = async (d) => (await (await fetch(`${base}/v1/public/verify-report`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(d) })).json());
    const ok = await pv(doc);
    assert.equal(ok.valid, true, JSON.stringify(ok));
    assert.equal(ok.kind, 'inventory-snapshot');
    assert.equal(ok.organization, 'Q4 audit');
    assert.equal((await pv({ ...doc, label: 'Q4 audiT' })).valid, false);
    const sub2 = await (await fetch(`${base}/v1/subscription`, { headers: ph })).json();
    assert.ok(!JSON.stringify(sub2).includes('"reportCredits":-'), 'no report credit spent');

    const com = await provisionTenant(apiHome, 'Community Co');
    const ch = { authorization: `Bearer ${com.apiKey}`, 'content-type': 'application/json' };
    const ws2 = await (await fetch(`${base}/v1/workspaces`, { method: 'POST', headers: ch, body: JSON.stringify({ files: [{ path: 'a.js', content: 'x' }] }) })).json();
    const refused = await run(ch, { workspaceId: ws2.workspaceId });
    assert.ok([402, 403].includes(refused.status), 'Community is refused: ' + refused.status);

    const noWs = await run(ph, {});
    let nd = await noWs.json();
    if (noWs.status === 202) { for (let i = 0; i < 200; i++) { nd = await (await fetch(`${base}/v1/jobs/${nd.jobId}`, { headers: ph })).json(); if (['succeeded', 'failed'].includes(nd.status)) break; await new Promise((r) => setTimeout(r, 50)); } assert.equal(nd.status, 'failed'); }
    else assert.equal(noWs.status, 400);
  } finally {
    await new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); });
  }
});
