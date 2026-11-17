import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { createApiServer, provisionTenant } from '../src/api/server.js';
import { applySubscriptionEvent } from '../src/billing/entitlements.js';
import { scanRepository } from '../src/scanner.js';
import { generateSigningKey } from '../src/signing.js';
import { buildReadinessReport, signReport, verifyReport, validateCbom, cbomFileText, cbomFileMatches, CBOM_FILE_NAME, renderReportHtml } from '../src/readinessReport.js';

// AD-062 (knock-out 2026-11-17): the CycloneDX 1.6 CBOM is a standalone file in the report package, its
// SHA-256 is inside the signed report, and the same inputs give the same CBOM (serial number included).
const sampleRoot = path.join(path.dirname(path.dirname(fileURLToPath(import.meta.url))), 'samples', 'readiness-sample');
const now = new Date('2026-11-16T00:00:00Z');
const sha = (t) => createHash('sha256').update(t).digest('hex');

test('CBOM file: shape-checked, fingerprint inside the signed report, deterministic, tamper detected', async () => {
  const scan = await scanRepository(sampleRoot, { now });
  const a = buildReadinessReport({ organization: 'Acme', scan, migration: null, now });
  const b = buildReadinessReport({ organization: 'Acme', scan, migration: null, now });
  assert.deepEqual(validateCbom(a.cbom), [], 'emitted CBOM passes the CycloneDX 1.6 shape check');
  assert.equal(a.cbom.specVersion, '1.6');
  assert.ok(a.cbom.components.length >= 3 && a.cbom.components.every((c) => c.type === 'cryptographic-asset'));
  assert.equal(a.cbom.serialNumber, b.cbom.serialNumber, 'same inputs, same serial number');
  assert.match(a.cbom.serialNumber, /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.equal(cbomFileText(a.cbom), cbomFileText(b.cbom), 'byte-identical CBOM file');
  assert.equal(a.cbomFile.name, CBOM_FILE_NAME);
  assert.equal(a.cbomFile.sha256, sha(cbomFileText(a.cbom)));
  assert.equal(a.cbomFile.components, a.cbom.components.length);

  const key = generateSigningKey();
  const signed = signReport(a, key);
  assert.equal(verifyReport(signed).valid, true);
  assert.equal(cbomFileMatches(signed, cbomFileText(signed.cbom)), true);
  const edited = cbomFileText(signed.cbom).replace('"specVersion": "1.6"', '"specVersion": "1.5"');
  assert.equal(cbomFileMatches(signed, edited), false, 'a changed CBOM file no longer matches');
  const swapped = { ...signed, cbomFile: { ...signed.cbomFile, sha256: sha(edited) } };
  assert.equal(verifyReport(swapped).valid, false, 'pointing the report at another CBOM breaks the signature');
  assert.match(renderReportHtml(signed), new RegExp('id="cbom-file"[\\s\\S]*' + signed.cbomFile.sha256));

  assert.deepEqual(validateCbom({ bomFormat: 'CycloneDX', specVersion: '1.5', serialNumber: 'x', components: [{ type: 'library', 'bom-ref': 'r' }], vulnerabilities: [{ 'bom-ref': 'v', affects: [{ ref: 'missing' }] }] }).length, 5, 'specVersion, serial, component type, assetType, unknown ref');
  const noScan = buildReadinessReport({ organization: 'Acme', scan: null, migration: null, endpoints: [], now });
  assert.equal(noScan.cbom, null);
  assert.equal(noScan.cbomFile, null);
});

test('hosted: the readiness report job hands out cbom.json, matching the signed report', async () => {
  const apiHome = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-cbom-'));
  const { server } = createApiServer({ apiHome });
  await new Promise((resolve) => server.listen(0, resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const { tenantId, apiKey } = await provisionTenant(apiHome, 'Acme');
  const headers = { authorization: `Bearer ${apiKey}`, 'content-type': 'application/json' };
  try {
    await applySubscriptionEvent(apiHome, tenantId, { kind: 'report', credits: 1, occurredAt: new Date().toISOString() });
    const { workspaceId } = await (await fetch(`${base}/v1/workspaces`, { method: 'POST', headers, body: JSON.stringify({ files: [{ path: 'src/token.js', content: "jwt.sign(payload, key, { algorithm: 'RS256' });\n" }] }) })).json();
    const job = await (await fetch(`${base}/v1/jobs`, { method: 'POST', headers, body: JSON.stringify({ type: 'readiness-report', params: { organization: 'Acme', workspaceId } }) })).json();
    let done;
    for (let i = 0; i < 300; i++) { done = await (await fetch(`${base}/v1/jobs/${job.jobId}`, { headers })).json(); if (['succeeded', 'failed'].includes(done.status)) break; await new Promise((r) => setTimeout(r, 50)); }
    assert.equal(done.status, 'succeeded', JSON.stringify(done));
    const result = await (await fetch(`${base}/v1/jobs/${job.jobId}/result`, { headers })).json();
    assert.ok(result.files.includes('cbom.json'), JSON.stringify(result.files));
    const cbomRes = await fetch(`${base}/v1/jobs/${job.jobId}/files/cbom.json`, { headers });
    assert.equal(cbomRes.status, 200);
    assert.match(cbomRes.headers.get('content-type'), /cyclonedx\+json/);
    const cbomText = await cbomRes.text();
    const report = await (await fetch(`${base}/v1/jobs/${job.jobId}/files/readiness-report.json`, { headers })).json();
    assert.equal(cbomFileMatches(report, cbomText), true, 'downloaded cbom.json is the one the signed report names');
    assert.deepEqual(validateCbom(JSON.parse(cbomText)), []);
  } finally {
    await new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); });
  }
});
