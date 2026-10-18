import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { createApiServer, provisionTenant } from '../src/api/server.js';
import { applySubscriptionEvent, entitlement } from '../src/billing/entitlements.js';
import { buildReadinessReport, scoreReadiness, roadmap, signReport, verifyReport, renderReportHtml, REPORT_SCHEMA } from '../src/readinessReport.js';
import { generateSigningKey } from '../src/signing.js';
import { verifyReceipt } from '../src/breaklab/receipt.js';

const finding = (id, severity, category, automatable = false, file = 'nginx.conf') => ({ id, severity, category, file, line: 3, excerpt: 'x', reason: 'r', remediation: 'm', standard: 's', automatable });
const scanOf = (findings) => ({
  schema: 'pqc-forge.scan/v1', generatedAt: new Date().toISOString(), root: '/tmp/x', filesScanned: 4,
  summary: findings.reduce((s, f) => { s.total++; s[f.severity]++; if (f.automatable) s.automatable++; return s; }, { total: 0, critical: 0, high: 0, medium: 0, low: 0, automatable: 0, suppressed: 0 }),
  findings, suppressedFindings: [],
});
const endpoint = (target, group) => ({ target, ok: true, evidence: { generatedAt: new Date().toISOString(), protocol: 'TLSv1.3', ephemeralKey: { name: group }, peerSignatureAlgorithm: 'ecdsa-with-SHA256', verdict: { pqKeyExchange: /MLKEM/.test(group), pqAuthentication: false } } });

test('stages and scores follow the published rules', () => {
  const weak = scanOf([finding('QF-WEAK-RSA-SIZE', 'critical', 'cryptographic-debt')]);
  assert.equal(scoreReadiness(weak, []).stage.id, 'urgent');
  assert.equal(scoreReadiness(weak, []).score, 85);
  const classical = scanOf([finding('QF-ALG-RSA', 'high', 'quantum-vulnerable-algorithm', false, 'src/jwt.js')]);
  assert.equal(scoreReadiness(classical, [endpoint('a.example:443', 'X25519')]).stage.id, 'exposed');
  assert.equal(scoreReadiness(classical, [endpoint('a.example:443', 'X25519')]).score, 85);
  const fixable = scanOf([finding('QF-TLS-CLASSICAL-GROUPS', 'high', 'key-establishment', true)]);
  assert.equal(scoreReadiness(fixable, []).stage.id, 'transition', 'a change PQC Forge can generate means the move has started');
  assert.equal(scoreReadiness(scanOf([]), [endpoint('a.example:443', 'X25519MLKEM768')]).stage.id, 'ready');
  assert.equal(scoreReadiness(scanOf([]), [endpoint('a.example:443', 'X25519MLKEM768')]).score, 100);
  const many = scanOf(Array.from({ length: 9 }, () => finding('QF-WEAK-RSA-SIZE', 'critical', 'cryptographic-debt')));
  assert.equal(scoreReadiness(many, []).score, 55, 'each penalty is capped');
});

test('the roadmap puts weak keys first, then server key exchange, then code, then upkeep', () => {
  const scan = scanOf([
    finding('QF-ALG-RSA', 'high', 'quantum-vulnerable-algorithm', false, 'src/jwt.js'),
    finding('QF-TLS-CLASSICAL-GROUPS', 'high', 'key-establishment', true, 'nginx.conf'),
    finding('QF-WEAK-RSA-SIZE', 'critical', 'cryptographic-debt', false, 'keys.cfg'),
  ]);
  const steps = roadmap(scan, { changeCount: 1 }, [endpoint('shop.example:443', 'X25519')]);
  assert.deepEqual(steps.map((s) => s.priority), ['Now', 'Next 3 months', 'Next 3 months', 'Next 12 months', 'Ongoing']);
  assert.match(steps[0].title, /too weak/);
  assert.deepEqual(steps[0].where, ['keys.cfg']);
  assert.equal(steps[1].automated, true);
  assert.deepEqual(steps[2].where, ['shop.example:443']);
  assert.deepEqual(steps[3].where, ['src/jwt.js']);
});

test('the report is signed like every receipt; a changed report fails; the page escapes what it shows', () => {
  const key = generateSigningKey();
  const report = buildReadinessReport({ organization: 'Acme <script>', scan: scanOf([finding('QF-ALG-ECC', 'high', 'quantum-vulnerable-algorithm')]), migration: { changeCount: 0 }, endpoints: [endpoint('a.example:443', 'X25519')] });
  assert.equal(report.schema, REPORT_SCHEMA);
  assert.ok(report.mappings.some((m) => m.control === '12.3.3'));
  assert.ok(report.deadlines.length >= 3);
  assert.ok(report.cbom, 'the crypto bill of materials is inside');
  const signed = signReport(report, key);
  assert.equal(verifyReport(signed).valid, true);
  assert.equal(verifyReceipt(signed).valid, true, 'the generic receipt check accepts it');
  assert.equal(verifyReport({ ...signed, readiness: { ...signed.readiness, score: 100 } }).valid, false);
  assert.equal(verifyReport(signed, [generateSigningKey().publicKey]).valid, false, 'a different trusted key fails');
  const html = renderReportHtml(signed);
  assert.match(html, /Acme &lt;script&gt;/);
  assert.doesNotMatch(html, /Acme <script>/);
  assert.match(html, /PCI DSS v4\.0\.1/);
});

async function start() {
  const apiHome = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-report-'));
  const { server } = createApiServer({ apiHome });
  await new Promise((resolve) => server.listen(0, resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const { tenantId, apiKey } = await provisionTenant(apiHome, 'Acme');
  const headers = { authorization: `Bearer ${apiKey}`, 'content-type': 'application/json' };
  return { apiHome, base, tenantId, headers, close: () => new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); }) };
}
async function poll(ctx, jobId) {
  for (let i = 0; i < 300; i++) {
    const r = await (await fetch(`${ctx.base}/v1/jobs/${jobId}`, { headers: ctx.headers })).json();
    if (r.status === 'succeeded' || r.status === 'failed') return r;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error('job did not finish');
}
const submit = (ctx, params) => fetch(`${ctx.base}/v1/jobs`, { method: 'POST', headers: ctx.headers, body: JSON.stringify({ type: 'readiness-report', params }) });

test('hosted: no credit, no report; with a credit the report is built from the uploaded code, downloadable, verifiable, and spends the credit once', async () => {
  const ctx = await start();
  try {
    const noCredit = await submit(ctx, { organization: 'Acme' });
    assert.equal(noCredit.status, 402);
    assert.match((await noCredit.json()).error, /report credit/);

    await applySubscriptionEvent(ctx.apiHome, ctx.tenantId, { kind: 'report', credits: 1, occurredAt: new Date().toISOString() });
    const upload = await fetch(`${ctx.base}/v1/workspaces`, { method: 'POST', headers: ctx.headers, body: JSON.stringify({ files: [
      { path: 'nginx.conf', content: 'ssl_protocols TLSv1 TLSv1.2 TLSv1.3;\nssl_ecdh_curve X25519:prime256v1;\n' },
      { path: 'src/token.js', content: "jwt.sign(payload, key, { algorithm: 'RS256' });\n" },
    ] }) });
    const { workspaceId } = await upload.json();

    // A bad request fails and keeps the credit.
    const bad = await (await submit(ctx, { organization: 'Acme' })).json();
    assert.equal((await poll(ctx, bad.jobId)).status, 'failed');
    assert.equal((await entitlement(ctx.apiHome, ctx.tenantId)).reportCredits, 1, 'a failed run does not spend the credit');

    const job = await (await submit(ctx, { organization: 'Acme Payments', workspaceId, endpoints: ['127.0.0.1:443'] })).json();
    const done = await poll(ctx, job.jobId);
    assert.equal(done.status, 'succeeded', JSON.stringify(done));
    const result = await (await fetch(`${ctx.base}/v1/jobs/${job.jobId}/result`, { headers: ctx.headers })).json();
    assert.ok(result.readiness.score < 100 && ['exposed', 'transition'].includes(result.readiness.stage), JSON.stringify(result.readiness));
    assert.ok(result.summary.migrationChangesReady >= 1, 'the server change PQC Forge can generate is counted');
    assert.equal(result.summary.endpointsUnreachable, 1, 'a private address is refused, shown as not reached, never connected to');

    const html = await fetch(`${ctx.base}/v1/jobs/${job.jobId}/files/readiness-report.html`, { headers: ctx.headers });
    assert.equal(html.status, 200);
    assert.match(html.headers.get('content-type'), /text\/html/);
    const page = await html.text();
    assert.match(page, /Acme Payments/);
    assert.match(page, /src\/token\.js/);
    const json = await (await fetch(`${ctx.base}/v1/jobs/${job.jobId}/files/readiness-report.json`, { headers: ctx.headers })).json();
    const check = await (await fetch(`${ctx.base}/v1/verify-receipt`, { method: 'POST', headers: ctx.headers, body: JSON.stringify({ receipt: json }) })).json();
    assert.equal(check.valid, true, JSON.stringify(check));
    assert.equal((await fetch(`${ctx.base}/v1/jobs/${job.jobId}/files/job.json`, { headers: ctx.headers })).status, 404, 'only the report files can be downloaded');

    assert.equal((await entitlement(ctx.apiHome, ctx.tenantId)).reportCredits, 0, 'the credit was spent');
    assert.equal((await submit(ctx, { organization: 'Acme', workspaceId })).status, 402, 'no second report without a new credit');

    const other = await provisionTenant(ctx.apiHome, 'Other');
    assert.equal((await fetch(`${ctx.base}/v1/jobs/${job.jobId}/files/readiness-report.html`, { headers: { authorization: `Bearer ${other.apiKey}` } })).status, 404, 'another account cannot download it');
  } finally {
    await ctx.close();
  }
});
