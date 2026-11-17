import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import { test } from 'node:test';
import { createApiServer, provisionTenant } from '../src/api/server.js';
import { setManualPlan } from '../src/billing/entitlements.js';
import { generateSigningKey } from '../src/signing.js';
import { certsFromPemText, buildCertificateInventory, signCertificateInventory, verifyCertificateInventory, readWorkspaceCertificates, CERT_INVENTORY_SCHEMA } from '../src/certificateInventory.js';
import { certificateFacts } from '../src/verifier.js';

// AD-066 (knock-out Phase 5): certificate inventory and expiry. Real public certificates (Node's bundled root CAs)
// are the fixtures. Expired / expiring / valid follow the report time; unreadable certificates are Not verified;
// private-key files are listed by name only and never read into the output; signed; public verify checks it.
const ROOT = tls.rootCertificates[0];
const FAKE_KEY = '-----BEGIN PRIVATE KEY-----\nTk9UQVJFQUxLRVlfZG9fbm90X2xlYWs=\n-----END PRIVATE KEY-----\n';

test('PEM parse, expiry states by report time, Not verified for garbage, signed, tamper fails', () => {
  const [c] = certsFromPemText(ROOT);
  assert.equal(c.ok, true);
  assert.ok(c.facts.validTo && c.facts.publicKey, JSON.stringify(c.facts));
  const validTo = new Date(c.facts.validTo);
  const ws = { files: [{ source: 'file:ca.pem', ...c }, { source: 'file:bad.crt', ok: false, error: 'x' }], unreadable: ['huge.pem'], privateKeyFiles: ['key.pem'] };
  const soon = buildCertificateInventory({ workspace: ws, now: new Date(validTo.getTime() - 10 * 86400000) });
  assert.equal(soon.schema, CERT_INVENTORY_SCHEMA);
  assert.equal(soon.certificates[0].expiry, 'expires within 30 days');
  assert.equal(soon.summary.expiringSoon, 1);
  assert.equal(soon.summary.notVerified, 2, 'unparsable and unreadable files are Not verified');
  assert.equal(soon.certificates[0].algorithmClass, 'classical');
  const late = buildCertificateInventory({ workspace: ws, now: new Date(validTo.getTime() + 86400000) });
  assert.equal(late.certificates[0].expiry, 'expired');
  assert.equal(late.summary.expired, 1);
  assert.deepEqual(late.scope.privateKeyFilesFound, ['key.pem']);
  const ok = buildCertificateInventory({ workspace: ws, now: new Date(validTo.getTime() - 400 * 86400000) });
  assert.equal(ok.certificates[0].expiry, 'valid');
  assert.throws(() => buildCertificateInventory({ endpoints: [], workspace: { files: [], unreadable: [], privateKeyFiles: [] } }), /No certificate found/);
  const K = generateSigningKey();
  const signed = signCertificateInventory(soon, K);
  assert.equal(verifyCertificateInventory(signed, [K]).valid, true);
  assert.equal(verifyCertificateInventory({ ...signed, summary: { ...signed.summary, expired: 0, expiringSoon: 0 } }, [K]).valid, false, 'hiding an expiring certificate breaks the signature');
  assert.doesNotMatch(JSON.stringify(signed), /quantum-safe|quantum-proof/i);
});

test('endpoint certificate facts: unreachable endpoint is Not verified; facts come from the TLS handshake', () => {
  const facts = certificateFacts({ subject: { CN: 'example.com' }, issuer: { CN: 'Example CA' }, valid_from: 'Jan 1 00:00:00 2026 GMT', valid_to: 'Jan 1 00:00:00 2027 GMT', fingerprint256: 'AA:BB', asn1Curve: 'prime256v1' });
  assert.deepEqual([facts.subject, facts.issuer, facts.publicKey], ['example.com', 'Example CA', 'EC prime256v1']);
  assert.equal(certificateFacts({}), null);
  const inv = buildCertificateInventory({ now: new Date('2026-12-15T00:00:00Z'), endpoints: [
    { target: 'a.example.com', ok: true, evidence: { certificate: facts, peerSignatureAlgorithm: 'ecdsa_secp256r1_sha256' } },
    { target: 'b.example.com', ok: false, error: 'timeout' },
  ] });
  assert.equal(inv.certificates[0].expiry, 'expires within 30 days');
  assert.equal(inv.certificates[0].algorithmClass, 'classical');
  assert.match(inv.certificates[1].status, /^Not verified/);
});

test('hosted: Pro runs certificate-inventory on a workspace + endpoint; private key never read; Community refused; public verify', async () => {
  const apiHome = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-certinv-'));
  const before = process.env.PQC_FORGE_API_ALLOW_PRIVATE_TARGETS; delete process.env.PQC_FORGE_API_ALLOW_PRIVATE_TARGETS;
  const { server } = createApiServer({ apiHome });
  await new Promise((resolve) => server.listen(0, resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const pro = await provisionTenant(apiHome, 'Pro Co');
    await setManualPlan(apiHome, pro.tenantId, { plan: 'pro' });
    const ph = { authorization: `Bearer ${pro.apiKey}`, 'content-type': 'application/json' };
    const { workspaceId } = await (await fetch(`${base}/v1/workspaces`, { method: 'POST', headers: ph, body: JSON.stringify({ files: [
      { path: 'certs/ca.pem', content: ROOT }, { path: 'certs/broken.crt', content: '-----BEGIN CERTIFICATE-----\nnotacert\n-----END CERTIFICATE-----\n' },
      { path: 'certs/server-key.pem', content: FAKE_KEY }, { path: 'src/app.js', content: 'console.log(1);\n' },
    ] }) })).json();
    const sub = await fetch(`${base}/v1/jobs`, { method: 'POST', headers: ph, body: JSON.stringify({ type: 'certificate-inventory', params: { workspaceId, endpoints: ['127.0.0.1:443'], label: 'Certs Q4' } }) });
    assert.equal(sub.status, 202, await sub.clone().text());
    const job = await sub.json();
    let done; for (let i = 0; i < 600; i++) { done = await (await fetch(`${base}/v1/jobs/${job.jobId}`, { headers: ph })).json(); if (['succeeded', 'failed'].includes(done.status)) break; await new Promise((r) => setTimeout(r, 50)); }
    assert.equal(done.status, 'succeeded', JSON.stringify(done));
    const text = await (await fetch(`${base}/v1/jobs/${job.jobId}/files/certificate-inventory.json`, { headers: ph })).text();
    const doc = JSON.parse(text);
    assert.equal(doc.summary.read, 1, 'the CA certificate is read');
    assert.equal(doc.summary.notVerified, 2, 'refused endpoint + unparsable file are Not verified');
    assert.deepEqual(doc.scope.privateKeyFilesFound, ['certs/server-key.pem']);
    assert.ok(!text.includes('Tk9UQVJFQUxLRVlf'), 'private key content never in the output');
    const pv = async (d) => (await fetch(`${base}/v1/public/verify-report`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(d) })).json();
    const ok = await pv(doc); assert.equal(ok.valid, true); assert.equal(ok.kind, 'certificate-inventory');
    assert.equal((await pv({ ...doc, label: 'Certs Q5' })).valid, false);
    const com = await provisionTenant(apiHome, 'Free Co');
    const cs = await fetch(`${base}/v1/jobs`, { method: 'POST', headers: { authorization: `Bearer ${com.apiKey}`, 'content-type': 'application/json' }, body: JSON.stringify({ type: 'certificate-inventory', params: { endpoints: ['example.com'] } }) });
    assert.ok([402, 403].includes(cs.status), 'Community is refused: ' + cs.status);
  } finally {
    server.close();
    if (before !== undefined) process.env.PQC_FORGE_API_ALLOW_PRIVATE_TARGETS = before;
  }
});

test('workspace reader skips non-certificate files and caps work', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-certws-'));
  await fs.mkdir(path.join(dir, 'node_modules', 'x'), { recursive: true });
  await fs.writeFile(path.join(dir, 'node_modules', 'x', 'skip.pem'), ROOT);
  await fs.writeFile(path.join(dir, 'a.crt'), ROOT + ROOT);
  await fs.writeFile(path.join(dir, 'notes.txt'), ROOT);
  const ws = await readWorkspaceCertificates(dir);
  assert.equal(ws.files.length, 2, 'two certificates in a.crt; node_modules and .txt skipped');
  assert.deepEqual(ws.files.map((f) => f.source), ['file:a.crt#1', 'file:a.crt#2']);
});
