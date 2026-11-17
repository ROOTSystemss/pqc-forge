import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { createApiServer, provisionTenant } from '../src/api/server.js';
import { setManualPlan } from '../src/billing/entitlements.js';
import { generateSigningKey } from '../src/signing.js';
import { buildEndpointInventory, signEndpointInventory, verifyEndpointInventory, ENDPOINT_INVENTORY_SCHEMA } from '../src/endpointInventory.js';

// AD-065 (knock-out Phase 5): passive TLS endpoint inventory. Three states per endpoint; an endpoint that did not
// answer is Not verified (never counted as post-quantum or classical); signed; verifies on the public verifier.
const ev = (group, sig, pq) => ({ ok: true, evidence: { generatedAt: '2026-11-17T00:00:00.000Z', protocol: 'TLSv1.3', ephemeralKey: { name: group }, peerSignatureAlgorithm: sig, authorized: true, verdict: { pqKeyExchange: pq, pqAuthentication: false } } });

test('inventory rows: post-quantum, classical-only and Not verified; summary counts; signed; tamper fails', () => {
  const inv = buildEndpointInventory({ label: 'Edge Q4', now: new Date('2026-11-17T00:00:00Z'), endpoints: [
    { target: 'pq.example.com', ...ev('X25519MLKEM768', 'ecdsa_secp256r1_sha256', true) },
    { target: 'old.example.com', ...ev('X25519', 'rsa_pss_rsae_sha256', false) },
    { target: 'down.example.com', ok: false, error: 'TLS connection to down.example.com:443 failed: timeout' },
  ] });
  assert.equal(inv.schema, ENDPOINT_INVENTORY_SCHEMA);
  assert.deepEqual(inv.summary, { postQuantumKeyExchange: 1, classicalOnly: 1, notVerified: 1 });
  assert.equal(inv.endpoints[0].status, 'Post-quantum key exchange observed');
  assert.equal(inv.endpoints[1].status, 'Classical key exchange only');
  assert.match(inv.endpoints[2].status, /^Not verified/);
  assert.ok(!('protocol' in inv.endpoints[2]), 'an unreachable endpoint gets no made-up protocol');
  assert.match(inv.scope.method, /Passive/);
  assert.ok(!('score' in inv) && !('readiness' in inv));
  assert.doesNotMatch(JSON.stringify(inv), /quantum-safe|quantum-proof/i);
  const K = generateSigningKey();
  const signed = signEndpointInventory(inv, K);
  assert.equal(verifyEndpointInventory(signed, [K]).valid, true);
  assert.equal(verifyEndpointInventory({ ...signed, summary: { ...signed.summary, notVerified: 0 } }, [K]).valid, false, 'hiding a Not verified endpoint breaks the signature');
  assert.equal(verifyEndpointInventory(signed, [generateSigningKey()]).valid, false);
  assert.throws(() => buildEndpointInventory({ endpoints: [] }), /at least one/);
});

test('hosted: Pro runs endpoint-inventory (private target refused -> Not verified); Community refused; public verify', async () => {
  const apiHome = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-epinv-'));
  const before = process.env.PQC_FORGE_API_ALLOW_PRIVATE_TARGETS; delete process.env.PQC_FORGE_API_ALLOW_PRIVATE_TARGETS;
  const { server } = createApiServer({ apiHome });
  await new Promise((resolve) => server.listen(0, resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const pro = await provisionTenant(apiHome, 'Pro Co');
    await setManualPlan(apiHome, pro.tenantId, { plan: 'pro' });
    const ph = { authorization: `Bearer ${pro.apiKey}`, 'content-type': 'application/json' };
    const bad = await fetch(`${base}/v1/jobs`, { method: 'POST', headers: ph, body: JSON.stringify({ type: 'endpoint-inventory', params: { endpoints: Array.from({ length: 11 }, (_, i) => `h${i}.example.com`) } }) });
    const badJob = await bad.json();
    let b; for (let i = 0; i < 300; i++) { b = await (await fetch(`${base}/v1/jobs/${badJob.jobId}`, { headers: ph })).json(); if (['succeeded', 'failed'].includes(b.status)) break; await new Promise((r) => setTimeout(r, 50)); }
    assert.equal(b.status, 'failed'); assert.match(JSON.stringify(b), /at most 10/);
    const sub = await fetch(`${base}/v1/jobs`, { method: 'POST', headers: ph, body: JSON.stringify({ type: 'endpoint-inventory', params: { endpoints: ['127.0.0.1:443'], label: 'Edge' } }) });
    assert.equal(sub.status, 202, await sub.clone().text());
    const job = await sub.json();
    let done; for (let i = 0; i < 300; i++) { done = await (await fetch(`${base}/v1/jobs/${job.jobId}`, { headers: ph })).json(); if (['succeeded', 'failed'].includes(done.status)) break; await new Promise((r) => setTimeout(r, 50)); }
    assert.equal(done.status, 'succeeded', JSON.stringify(done));
    const doc = await (await fetch(`${base}/v1/jobs/${job.jobId}/files/endpoint-inventory.json`, { headers: ph })).json();
    assert.equal(doc.summary.notVerified, 1, 'a refused private target is Not verified, never classical or post-quantum');
    assert.equal(doc.summary.classicalOnly + doc.summary.postQuantumKeyExchange, 0);
    const pv = async (d) => (await fetch(`${base}/v1/public/verify-report`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(d) })).json();
    const ok = await pv(doc); assert.equal(ok.valid, true); assert.equal(ok.kind, 'endpoint-inventory');
    assert.equal((await pv({ ...doc, label: 'Edgf' })).valid, false);
    const com = await provisionTenant(apiHome, 'Free Co');
    const cs = await fetch(`${base}/v1/jobs`, { method: 'POST', headers: { authorization: `Bearer ${com.apiKey}`, 'content-type': 'application/json' }, body: JSON.stringify({ type: 'endpoint-inventory', params: { endpoints: ['example.com'] } }) });
    assert.ok([402, 403].includes(cs.status), 'Community is refused: ' + cs.status);
  } finally {
    server.close();
    if (before !== undefined) process.env.PQC_FORGE_API_ALLOW_PRIVATE_TARGETS = before;
  }
});
