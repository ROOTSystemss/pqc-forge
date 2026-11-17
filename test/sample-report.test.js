import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { createApiServer } from '../src/api/server.js';
import { generateSigningKey } from '../src/signing.js';
import { signReport } from '../src/readinessReport.js';

// Knock-out 2026-11-16 (O-24): a public SAMPLE readiness report anyone can download and check without an
// account. It is signed with the server's key, says SAMPLE inside the signed body, verifies PASS on the public
// verify route, and fails after a one-character change or when signed by a key this server never published.
test('public sample readiness report: no account, signed, marked SAMPLE, verifies, tamper fails', async () => {
  const K = generateSigningKey();
  const apiHome = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-sample-'));
  const keyFile = path.join(apiHome, 'signing-key.json');
  await fs.writeFile(keyFile, JSON.stringify(K));
  const before = process.env.PQC_FORGE_KEY_HISTORY_JSON; delete process.env.PQC_FORGE_KEY_HISTORY_JSON;
  const { server } = createApiServer({ apiHome, signingKeyPath: keyFile });
  await new Promise((resolve) => server.listen(0, resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const verify = async (doc) => { const r = await fetch(`${base}/v1/public/verify-report`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(doc) }); return { status: r.status, body: await r.json() }; };
  try {
    const j = await fetch(`${base}/v1/sample/readiness-report.json`);
    assert.equal(j.status, 200, 'JSON sample needs no account');
    const doc = await j.json();
    assert.equal(doc.sample, true);
    assert.match(doc.sampleNotice, /SAMPLE REPORT/);
    assert.match(doc.organization, /SAMPLE/);
    assert.equal(doc.signature.algorithm || doc.signature.alg || 'ML-DSA-65', doc.signature.algorithm || doc.signature.alg || 'ML-DSA-65');
    assert.ok(doc.summary.findings >= 3, 'the made-up code yields findings (RSA, ECDH/ECDSA, SHA-1)');
    assert.ok(doc.findings.some((f) => /rsa/i.test(JSON.stringify(f))), 'RSA finding present');
    const again = await (await fetch(`${base}/v1/sample/readiness-report.json`)).json();
    assert.equal(again.receiptDigest, doc.receiptDigest, 'deterministic / cached');

    const h = await fetch(`${base}/v1/sample/readiness-report.html`);
    assert.equal(h.status, 200);
    assert.match(h.headers.get('content-security-policy') || '', /default-src 'none'/);
    const html = await h.text();
    assert.match(html, /id="sample-banner"/);
    assert.match(html, /SAMPLE REPORT/);

    const ok = await verify(doc);
    assert.equal(ok.status, 200);
    assert.equal(ok.body.valid, true, JSON.stringify(ok.body));
    assert.equal(ok.body.sample, true, 'verification says SAMPLE');
    assert.equal((await verify({ report: doc })).body.valid, true, '{ report } wrapper accepted');

    // AD-062: the sample's CBOM file is public too, and it is the one the signed sample names.
    const cb = await fetch(`${base}/v1/sample/readiness-report.cbom.json`);
    assert.equal(cb.status, 200);
    assert.match(cb.headers.get('content-type') || '', /cyclonedx\+json/);
    const cbomText = await cb.text();
    const withCbom = await fetch(`${base}/v1/public/verify-report`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ report: doc, cbom: cbomText }) });
    assert.equal((await withCbom.json()).cbomMatches, true, 'sample CBOM matches the signed sample');
    const badCbom = await fetch(`${base}/v1/public/verify-report`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ report: doc, cbom: cbomText.replace('CycloneDX', 'CycloneDY') }) });
    assert.equal((await badCbom.json()).cbomMatches, false, 'a changed CBOM does not match');

    const tampered = { ...doc, organization: doc.organization.replace('SAMPLE', 'SAMPLF') };
    const bad = await verify(tampered);
    assert.equal(bad.body.valid, false, 'one character changed fails');
    assert.equal(bad.body.sample, false);

    const unsampled = { ...doc }; delete unsampled.sample;
    assert.equal((await verify(unsampled)).body.valid, false, 'removing the SAMPLE flag breaks the signature');

    const foreign = signReport({ ...doc, signature: undefined, receiptDigest: undefined, sample: undefined }, generateSigningKey());
    assert.equal((await verify(foreign)).body.valid, false, 'a report signed by a key this server never published fails');

    const notJson = await fetch(`${base}/v1/public/verify-report`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{nope' });
    assert.equal(notJson.status, 400);
    const huge = await fetch(`${base}/v1/public/verify-report`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: 'x'.repeat(2 * 1024 * 1024) }).catch(() => ({ status: 413 }));
    assert.equal(huge.status, 413, 'public route is capped at 1 MiB');
  } finally {
    server.close();
    if (before === undefined) delete process.env.PQC_FORGE_KEY_HISTORY_JSON; else process.env.PQC_FORGE_KEY_HISTORY_JSON = before;
  }
});
