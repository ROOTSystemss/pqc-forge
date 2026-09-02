import assert from 'node:assert/strict';
import { test } from 'node:test';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import { scanRepository } from '../src/scanner.js';
import { compareScans, findingFingerprint } from '../src/baseline.js';
import { scanToSarif } from '../src/sarif.js';

const fixture = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures', 'vulnerable');

test('scanner emits file and line evidence for vulnerable crypto', async () => {
  const report = await scanRepository(fixture);
  assert.ok(report.filesScanned >= 2);
  assert.ok(report.findings.some((finding) => finding.id === 'QF-ALG-RSA'));
  assert.ok(report.findings.some((finding) => finding.id === 'QF-TLS-CLASSICAL-GROUPS'));
  assert.ok(report.findings.every((finding) => finding.file && finding.line > 0));
});

test('scanner does not classify TLS 1.2 or TLS 1.3 as legacy TLS', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-modern-tls-'));
  await fs.writeFile(path.join(root, 'nginx.conf'), 'ssl_protocols TLSv1.2 TLSv1.3;\nssl_ecdh_curve X25519MLKEM768:X25519;\n');
  const report = await scanRepository(root);
  assert.equal(report.findings.some((finding) => finding.id === 'QF-TLS-LEGACY'), false);
});

test('scanner identifies HAProxy classical groups and legacy minimum TLS without flagging a hybrid policy', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-haproxy-scan-'));
  const config = path.join(root, 'haproxy.cfg');
  await fs.writeFile(config, 'global\n  ssl-default-bind-curves X25519:P-256\n  ssl-default-bind-options ssl-min-ver TLSv1.1 no-tls-tickets\nfrontend https\n  bind *:443 ssl crt /cert.pem\n');
  const vulnerable = await scanRepository(root);
  assert.equal(vulnerable.findings.some((finding) => finding.id === 'QF-HAPROXY-CLASSICAL-GROUPS'), true);
  assert.equal(vulnerable.findings.some((finding) => finding.id === 'QF-HAPROXY-LEGACY-TLS'), true);
  await fs.writeFile(config, 'global\n  ssl-default-bind-curves X25519MLKEM768:X25519\n  ssl-default-bind-options ssl-min-ver TLSv1.2\nfrontend https\n  bind *:443 ssl crt /cert.pem\n');
  const migrated = await scanRepository(root);
  assert.equal(migrated.findings.some((finding) => finding.id.startsWith('QF-HAPROXY-')), false);
});

test('scanner reports a missing HAProxy group policy only when TLS is terminated', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-haproxy-policy-'));
  const config = path.join(root, 'haproxy.cfg');
  await fs.writeFile(config, 'global\n  daemon\nfrontend https\n  bind *:443 ssl crt /cert.pem\n');
  const tls = await scanRepository(root);
  assert.equal(tls.findings.some((finding) => finding.id === 'QF-HAPROXY-MISSING-GROUP-POLICY'), true);
  await fs.writeFile(config, 'global\n  daemon\nfrontend http\n  bind *:80\n');
  const cleartext = await scanRepository(root);
  assert.equal(cleartext.findings.some((finding) => finding.id === 'QF-HAPROXY-MISSING-GROUP-POLICY'), false);
});

test('scanner identifies Apache classical and missing group policies per TLS virtual host', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-apache-scan-'));
  const config = path.join(root, 'ssl.conf');
  await fs.writeFile(config, '<VirtualHost *:443>\n  SSLEngine on\n  SSLOpenSSLConfCmd Curves X25519:prime256v1\n</VirtualHost>\n<VirtualHost *:8443>\n  SSLEngine on\n</VirtualHost>\n');
  const vulnerable = await scanRepository(root);
  assert.equal(vulnerable.findings.some((finding) => finding.id === 'QF-APACHE-CLASSICAL-GROUPS'), true);
  assert.equal(vulnerable.findings.some((finding) => finding.id === 'QF-APACHE-MISSING-GROUP-POLICY'), true);
  await fs.writeFile(config, 'SSLOpenSSLConfCmd Groups X25519MLKEM768:X25519\n<VirtualHost *:443>\n  SSLEngine on\n</VirtualHost>\n');
  const migrated = await scanRepository(root);
  assert.equal(migrated.findings.some((finding) => finding.id.startsWith('QF-APACHE-')), false);
});

test('scanner exports valid SARIF with stable fingerprints', async () => {
  const report = await scanRepository(fixture);
  const sarif = scanToSarif(report);
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs[0].results.length, report.findings.length);
  assert.ok(sarif.runs[0].results.every((result) => result.partialFingerprints['pqcForge/v1']));
  const moved = { ...report.findings[0], line: report.findings[0].line + 10 };
  assert.equal(findingFingerprint(moved), findingFingerprint(report.findings[0]));
});

test('baseline comparison isolates new blocking and resolved findings', async () => {
  const report = await scanRepository(fixture);
  const baseline = { ...report, findings: report.findings.slice(0, -1) };
  const delta = compareScans(report, baseline);
  assert.equal(delta.summary.new, 1);
  assert.equal(delta.summary.resolved, 0);
  assert.equal(delta.summary.unchanged, report.findings.length - 1);
  assert.equal(delta.summary.newBlocking, delta.newFindings[0].severity === 'high' || delta.newFindings[0].severity === 'critical' ? 1 : 0);
  assert.throws(() => compareScans(report, { schema: 'wrong', findings: [] }), /scan\/v1/);
});

test('audited suppressions hide matching findings only until expiry', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-ignore-'));
  await fs.writeFile(path.join(root, 'service.js'), "const algorithm = 'RSA-PSS';\n");
  await fs.writeFile(path.join(root, '.pqc-forge-ignore.json'), JSON.stringify({
    schema: 'pqc-forge.ignore/v1',
    suppressions: [{ ruleId: 'QF-ALG-RSA', path: '*.js', reason: 'Temporary compatibility exception', expires: '2030-01-01' }]
  }));
  const active = await scanRepository(root, { now: new Date('2029-01-01T00:00:00Z') });
  assert.equal(active.summary.total, 0);
  assert.equal(active.summary.suppressed, 1);
  assert.equal(active.suppressedFindings[0].suppression.reason, 'Temporary compatibility exception');
  const expired = await scanRepository(root, { now: new Date('2031-01-01T00:00:00Z') });
  assert.equal(expired.summary.total, 1);
  assert.equal(expired.summary.suppressed, 0);
});
