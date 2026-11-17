import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildReadinessReport, signReport, verifyReport, renderReportHtml, milestonesFrom, deadlineFor, DEADLINES } from '../src/readinessReport.js';
import { generateSigningKey } from '../src/signing.js';

// AD-068 (knock-out 2026-11-17): per finding and plan step, the nearest published deadline from the DEADLINES
// data (each date taken from its own source text) and how far away it is from the report date.
const finding = (id, severity, category, file = 'src/a.js') => ({ id, severity, category, file, line: 1, excerpt: 'x', reason: 'r', remediation: 'm', standard: 's', automatable: false });
const scanOf = (findings) => ({ schema: 'pqc-forge.scan/v1', generatedAt: '2026-11-16T00:00:00.000Z', root: '/tmp/x', filesScanned: 2,
  summary: findings.reduce((s, f) => { s.total++; s[f.severity]++; return s; }, { total: 0, critical: 0, high: 0, medium: 0, low: 0, automatable: 0, suppressed: 0 }), findings, suppressedFindings: [] });

test('milestones come only from DEADLINES, each with its source, measured from the report date', () => {
  const ms = milestonesFrom('2026-11-16T00:00:00.000Z');
  const dated = DEADLINES.flatMap((d) => (d.milestones || []).map((m) => m.date));
  assert.equal(ms.length, dated.length);
  assert.ok(ms.every((m) => m.source && /^https:\/\//.test(m.source)), 'every milestone cites its source');
  const nist = ms.find((m) => m.body.startsWith('NIST IR 8547') && m.kind === 'deprecated');
  assert.equal(nist.date, '2030-12-31');
  assert.equal(nist.daysAway, 1506);
  assert.equal(nist.yearsAway, 4.1);
  assert.ok(ms.every((m, i) => i === 0 || ms[i - 1].date <= m.date), 'sorted by date');
  const later = milestonesFrom('2031-06-01T00:00:00.000Z');
  assert.ok(later.find((m) => m.date === '2030-12-31').passed);
});

test('nearest deadline per finding and step; weak keys and legacy TLS are due now; start dates never count', () => {
  const ms = milestonesFrom('2026-11-16T00:00:00.000Z');
  const d = deadlineFor(finding('QF-ALG-RSA', 'high', 'quantum-vulnerable-algorithm'), ms);
  assert.equal(d.kind, 'date');
  assert.equal(d.date, '2030-12-31', 'the EU 2026 start date is not counted; the nearest deadline is end of 2030');
  assert.ok(d.alsoDue.length >= 1, 'other sources with the same date are named');
  assert.equal(deadlineFor(finding('QF-WEAK-RSA-SIZE', 'critical', 'cryptographic-debt'), ms).kind, 'now');
  assert.equal(deadlineFor(finding('QF-TLS-LEGACY', 'medium', 'protocol-baseline'), ms).kind, 'now');
  assert.equal(deadlineFor({ key: 'inventory' }, ms), null);
  assert.equal(deadlineFor(finding('QF-ALG-RSA', 'high', 'quantum-vulnerable-algorithm'), milestonesFrom('2036-01-01T00:00:00.000Z')).kind, 'passed');

  const now = new Date('2026-11-16T00:00:00Z');
  const r = buildReadinessReport({ organization: 'Acme', scan: scanOf([finding('QF-ALG-ECC', 'high', 'quantum-vulnerable-algorithm'), finding('QF-WEAK-RSA-SIZE', 'critical', 'cryptographic-debt', 'keys.cfg')]), migration: null, now });
  assert.equal(r.deadlineTracker.asOf, '2026-11-16');
  assert.ok(r.findings.every((f) => f.deadline));
  assert.equal(r.roadmap.find((s) => s.key === 'code-migration').deadline.date, '2030-12-31');
  assert.equal(r.roadmap.find((s) => s.key === 'weak-keys').deadline.kind, 'now');
  const signed = signReport(r, generateSigningKey());
  assert.equal(verifyReport(signed).valid, true);
  assert.equal(verifyReport({ ...signed, deadlineTracker: { ...signed.deadlineTracker, asOf: '2026-01-01' } }).valid, false, 'the tracker is signed');
  const html = renderReportHtml(signed);
  assert.match(html, /id="deadline-tracker"/);
  assert.match(html, /Nearest deadline/);
  assert.match(html, /2030-12-31 \(1506 days, 4\.1 years\)/);
  assert.match(html, /not counted as a deadline/);
  assert.doesNotMatch(html, /quantum-safe|quantum-proof/i);
});
