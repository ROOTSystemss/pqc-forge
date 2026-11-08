// Live QA 2026-11-02 E2 + E4: API errors and the paid report package.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createApiServer } from '../src/api/server.js';
import { createTenant } from '../src/api/tenants.js';
import { redactServerPaths } from '../src/api/jobs.js';
import { buildReadinessReport, findingStatus, endpointStatus, DEADLINES, signReport, verifyReport, renderReportHtml } from '../src/readinessReport.js';
import { scanRepository, SCAN_COVERAGE } from '../src/scanner.js';
import { generateSigningKey } from '../src/signing.js';
import { buildReportPackage } from '../src/reportPackage.js';

const here = path.dirname(fileURLToPath(import.meta.url));

async function api() {
  const home = await mkdtemp(path.join(tmpdir(), 'pqc-e2-'));
  const { apiKey } = await createTenant(home, { name: 'E2' });
  const { server } = createApiServer({ apiHome: home });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  const call = async (method, p, body) => {
    const r = await fetch(base + p, { method, headers: { authorization: `Bearer ${apiKey}`, 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
    return { status: r.status, type: r.headers.get('content-type') || '', json: await r.json().catch(() => null) };
  };
  return { home, server, base, call };
}

test('E2: unknown job type -> 400 "Unknown job type" (not "needs Pro")', async () => {
  const { server, call } = await api();
  try {
    const r = await call('POST', '/v1/jobs', { type: 'definitely-not-a-job', params: {} });
    assert.equal(r.status, 400);
    assert.match(r.json.error, /^Unknown job type/);
    assert.doesNotMatch(r.json.error, /Pro/);
  } finally { server.close(); }
});

test('E2: a job for a workspace that does not exist -> 404 at submit; an escaping path -> JSON 400', async () => {
  const { server, call } = await api();
  try {
    let r = await call('POST', '/v1/jobs', { type: 'scan', params: { workspaceId: 'ws_0123456789abcdef' } });
    assert.equal(r.status, 404);
    assert.match(r.json.error, /No such workspace/);
    const ws = await call('POST', '/v1/workspaces', { files: [{ path: 'nginx.conf', content: 'ssl_protocols TLSv1 TLSv1.2;' }] });
    r = await call('POST', '/v1/jobs', { type: 'scan', params: { workspaceId: ws.json.workspaceId, relativePath: '../../../etc' } });
    assert.equal(r.status, 400);
    assert.match(r.type, /json/);
    assert.match(r.json.error, /Path escapes workspace\.$/);
  } finally { server.close(); }
});

test('E2: path traversal in the URL -> JSON 400, not an HTML page', async () => {
  const { server, base } = await api();
  try {
    // Sent raw with node:http: fetch would normalise "%2e%2e" away before it ever reached the server.
    const { request } = await import('node:http');
    const raw = (p) => new Promise((resolve, reject) => { const u = new URL(base); const req = request({ host: u.hostname, port: u.port, path: p, method: 'GET' }, (res) => { res.resume(); resolve({ status: res.statusCode, type: res.headers['content-type'] || '' }); }); req.on('error', reject); req.end(); });
    for (const p of ['/%2e%2e/%2e%2e/etc/passwd', '/v1/jobs/..%2f..%2fsecret', '/..%5c..%5cwindows', '/../../etc/passwd']) {
      const r = await raw(p);
      assert.equal(r.status, 400, p);
      assert.match(r.type, /json/, p);
    }
  } finally { server.close(); }
});

test('E2: a job result root never shows the server data directory; signed objects are left as signed', () => {
  const home = path.resolve('/srv/pqc-data');
  const ws = path.join(home, 'tenants', 't_1', 'workspaces', 'ws_0123456789abcdef');
  const signed = { root: ws, signature: { algorithm: 'ML-DSA-65' } };
  const out = redactServerPaths({ root: ws, scan: { root: path.join(home, 'jobs', 'j1') }, receipt: signed, plain: 'nginx.conf' }, home, 't_1');
  assert.equal(out.root, 'workspace:ws_0123456789abcdef');
  assert.equal(out.scan.root, '[server]/jobs/j1');
  assert.equal(out.plain, 'nginx.conf');
  assert.deepEqual(out.receipt, signed, 'a signed receipt is not rewritten (its signature and rollback depend on it)');
});

test('E4b: status labels for findings and endpoints', () => {
  assert.equal(findingStatus({ id: 'QF-ALG-RSA', category: 'quantum-vulnerable-algorithm' }), 'Quantum-vulnerable');
  assert.equal(findingStatus({ id: 'QF-TLS-LEGACY', category: 'protocol-baseline' }), 'Deprecated (TLS 1.0-1.1)');
  assert.equal(findingStatus({ id: 'QF-SSL-PROTOCOL', category: 'protocol-baseline' }), 'Unsafe (SSL)');
  assert.equal(findingStatus({ id: 'QF-SSH-CLASSICAL-HOSTKEY', category: 'quantum-vulnerable-algorithm' }), 'Transitional');
  assert.equal(endpointStatus({ ok: true, evidence: { protocol: 'TLSv1.3', verdict: { pqKeyExchange: true, pqAuthentication: true } } }), 'Quantum-safe');
  assert.equal(endpointStatus({ ok: true, evidence: { protocol: 'TLSv1.1', verdict: { pqKeyExchange: false } } }), 'Deprecated (TLS 1.0-1.1)');
  assert.equal(endpointStatus({ ok: true, evidence: { protocol: 'TLSv1.3', verdict: { pqKeyExchange: false } } }), 'Quantum-vulnerable');
});

test('E4c/d: deadlines cite sources; the scope names languages and what is not covered', async () => {
  for (const d of DEADLINES) assert.match(d.source, /^https:\/\//, d.body);
  assert.ok(DEADLINES.some((d) => /FIPS 203/.test(d.body)) && DEADLINES.some((d) => /8547/.test(d.body)));
  const scan = await scanRepository(path.join(here, 'fixtures', 'lang-corpus', 'vulnerable'), { ignoreFile: null });
  const report = buildReadinessReport({ organization: 'T', scan, migration: null, endpoints: [], coverage: SCAN_COVERAGE });
  assert.ok(report.scope.languages.includes('Go') && report.scope.notCovered.length >= 3);
  assert.ok(report.findings.every((f) => f.status));
  const html = renderReportHtml(signReport(report, generateSigningKey()));
  assert.match(html, /Not covered by this scan/);
  assert.match(html, /csrc\.nist\.gov/);
  assert.match(html, /<th>Status<\/th>/);
});

test('E4f: one command writes the signed report, HTML, CBOM, cross-check and manifest in one folder', async () => {
  const out = await mkdtemp(path.join(tmpdir(), 'pqc-pkg-'));
  const repo = await mkdtemp(path.join(tmpdir(), 'pqc-repo-'));
  await mkdir(path.join(repo, 'src'));
  await writeFile(path.join(repo, 'src', 'keys.py'), 'from cryptography.hazmat.primitives.asymmetric import rsa\nk = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n');
  const key = generateSigningKey();
  // Cross-check tools are pointed at a name that does not exist: the package must say "not run", not hide it.
  const result = await buildReportPackage({ repo, organization: 'Pkg Test', outDir: out, signingKey: key, semgrep: 'no-such-semgrep-xyz', sslyze: 'no-such-sslyze-xyz' });
  const files = await readdir(out);
  for (const f of ['report.json', 'report.html', 'cbom.json', 'crosscheck.json', 'MANIFEST.txt']) assert.ok(files.includes(f), f);
  const doc = JSON.parse(await readFile(path.join(out, 'report.json'), 'utf8'));
  assert.equal(verifyReport(doc).valid, true);
  assert.ok(!JSON.stringify(doc).includes(repo), 'the local folder path is not in the report');
  assert.equal(doc.crossCheck.tools[0].ran, false);
  assert.match(doc.crossCheck.tools[0].reason, /not installed/);
  assert.equal(JSON.parse(await readFile(path.join(out, 'cbom.json'), 'utf8')).bomFormat, 'CycloneDX');
  const manifest = await readFile(path.join(out, 'MANIFEST.txt'), 'utf8');
  assert.match(manifest, /[0-9a-f]{64} {2}report\.json/);
  assert.ok(result.receiptDigest.startsWith('sha256:'));
});

test('E3: Billing without checkout says "Paid plans: contact hello@rootsystems.app" and links the contact page', async () => {
  const src = await readFile(path.join(here, '..', 'web', 'src', 'components', 'BillingTab.tsx'), 'utf8');
  assert.match(src, /Paid plans: contact <a href="mailto:hello@rootsystems\.app">hello@rootsystems\.app<\/a>/);
  assert.match(src, /https:\/\/rootsystems\.app\/contact\?topic=PQC%20Forge/);
  assert.doesNotMatch(src, /Self-serve checkout is not configured/);
});
