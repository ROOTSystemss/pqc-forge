import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildReadinessReport, signReport, verifyReport, renderReportHtml, rankFinding, protects, checkDataLifetime, DEFAULT_DATA_LIFETIME_YEARS } from '../src/readinessReport.js';
import { generateSigningKey } from '../src/signing.js';

// BM-46 (knock-out 2026-11-17): findings ranked by severity + time to the nearest deadline; for key exchange /
// encryption the data lifetime is subtracted (harvest now, decrypt later); never for signatures. Deterministic,
// with a written reason per finding.
const f = (id, severity, category, file = 'src/a.js', line = 1) => ({ id, severity, category, file, line, excerpt: 'x', reason: 'r', remediation: 'm', standard: 's', automatable: false });
const scanOf = (findings) => ({ schema: 'pqc-forge.scan/v1', generatedAt: '2026-11-16T00:00:00.000Z', root: '/tmp/x', filesScanned: 3,
  summary: findings.reduce((s, x) => { s.total++; s[x.severity]++; return s; }, { total: 0, critical: 0, high: 0, medium: 0, low: 0, automatable: 0, suppressed: 0 }), findings, suppressedFindings: [] });
const now = new Date('2026-11-16T00:00:00Z');
const findings = [
  f('QF-SSH-CLASSICAL-HOSTKEY', 'high', 'quantum-vulnerable-algorithm', 'sshd_config', 4),
  f('QF-TLS-CLASSICAL-GROUPS', 'medium', 'key-establishment', 'nginx.conf', 9),
  f('QF-WEAK-RSA-SIZE', 'critical', 'cryptographic-debt', 'keys.cfg', 2),
  f('QF-TLS-LEGACY', 'low', 'protocol-baseline', 'nginx.conf', 3),
];

test('harvest-now-decrypt-later applies to key exchange, not to signatures', () => {
  assert.equal(protects(findings[0]), 'authenticity');
  assert.equal(protects(findings[1]), 'confidentiality');
  assert.equal(protects(f('QF-ALG-RSA', 'high', 'quantum-vulnerable-algorithm')), 'confidentiality (assumed)');
  const deadline = { kind: 'date', date: '2030-12-31', yearsAway: 4.1, daysAway: 1506 };
  const sig = rankFinding({ ...findings[0], deadline }, 10);
  const kex = rankFinding({ ...f('QF-TLS-CLASSICAL-GROUPS', 'high', 'key-establishment'), deadline }, 10);
  assert.equal(sig.rankScore, 30 + 30, 'signature: 50 - 5 x 4.1 = 29.5 -> 30');
  assert.equal(kex.rankScore, 30 + 50, 'key exchange with 10-year data: already past the deadline -> 50');
  assert.match(sig.rankWhy, /data lifetime does not apply to signatures/);
  assert.match(kex.rankWhy, /minus 10 years the data must stay secret/);
  assert.equal(rankFinding({ ...f('QF-TLS-CLASSICAL-GROUPS', 'high', 'key-establishment'), deadline }, 0).rankScore, 60, 'no data lifetime: same as a signature');
  assert.equal(checkDataLifetime(undefined), DEFAULT_DATA_LIFETIME_YEARS);
  assert.equal(checkDataLifetime('25'), 25);
  assert.throws(() => checkDataLifetime(-1), /0 to 100/);
  assert.throws(() => checkDataLifetime(2.5), /whole number/);
});

test('report findings are ranked, explained, signed and deterministic; the data lifetime changes the order', () => {
  const a = buildReadinessReport({ organization: 'Acme', scan: scanOf(findings), migration: null, now });
  const b = buildReadinessReport({ organization: 'Acme', scan: scanOf([...findings].reverse()), migration: null, now });
  assert.deepEqual(a.findings.map((x) => x.id), b.findings.map((x) => x.id), 'same findings, same order, whatever the scan order');
  assert.deepEqual(a.findings.map((x) => x.rank), [1, 2, 3, 4]);
  assert.equal(a.findings[0].id, 'QF-WEAK-RSA-SIZE', 'critical and due now first');
  assert.ok(a.findings.every((x) => typeof x.rankScore === 'number' && x.rankWhy && x.protects));
  assert.equal(a.ranking.dataLifetimeYears, 10);
  assert.equal(a.ranking.dataLifetimeSource, 'default');
  assert.match(a.method, /harvest now, decrypt later/);
  assert.match(a.method, /does not apply to signatures/);
  const kexRank = (r) => r.findings.find((x) => x.id === 'QF-TLS-CLASSICAL-GROUPS').rank;
  const sshRank = (r) => r.findings.find((x) => x.id === 'QF-SSH-CLASSICAL-HOSTKEY').rank;
  assert.ok(kexRank(a) < sshRank(a), '10-year data: the medium key-exchange finding outranks the high signature finding');
  const short = buildReadinessReport({ organization: 'Acme', scan: scanOf(findings), migration: null, now, dataLifetimeYears: 0 });
  assert.equal(short.ranking.dataLifetimeSource, 'set by the customer');
  assert.ok(sshRank(short) < kexRank(short), 'no data lifetime: severity decides between them');
  assert.throws(() => buildReadinessReport({ organization: 'Acme', scan: scanOf(findings), migration: null, now, dataLifetimeYears: 500 }), /0 to 100/);
  const signed = signReport(a, generateSigningKey());
  assert.equal(verifyReport(signed).valid, true);
  assert.equal(verifyReport({ ...signed, findings: [...signed.findings].reverse() }).valid, false, 'the ranking is signed');
  const html = renderReportHtml(signed);
  assert.match(html, /<th>Rank<\/th>/);
  assert.match(html, /class="muted rank-why"/);
});
