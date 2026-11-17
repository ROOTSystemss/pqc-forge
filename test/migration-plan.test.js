import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildReadinessReport, signReport, verifyReport, renderReportHtml, migrationPlan, checkPlanInputs, roadmap, PLAN_STEP_KEYS } from '../src/readinessReport.js';
import { generateSigningKey } from '../src/signing.js';

// AD-067 (knock-out 2026-11-17): the roadmap is a migration plan. Every step has a rank, a risk, an owner role
// (suggested, or set by the customer), a target date and a status, all inside the signed report.
const finding = (id, severity, category, file = 'nginx.conf') => ({ id, severity, category, file, line: 3, excerpt: 'x', reason: 'r', remediation: 'm', standard: 's', automatable: category === 'key-establishment' });
const scanOf = (findings) => ({ schema: 'pqc-forge.scan/v1', generatedAt: '2026-11-16T00:00:00.000Z', root: '/tmp/x', filesScanned: 3,
  summary: findings.reduce((s, f) => { s.total++; s[f.severity]++; if (f.automatable) s.automatable++; return s; }, { total: 0, critical: 0, high: 0, medium: 0, low: 0, automatable: 0, suppressed: 0 }), findings, suppressedFindings: [] });
const scan = scanOf([finding('QF-ALG-RSA', 'high', 'quantum-vulnerable-algorithm', 'src/jwt.js'), finding('QF-TLS-CLASSICAL-GROUPS', 'high', 'key-establishment'), finding('QF-WEAK-RSA-SIZE', 'critical', 'cryptographic-debt', 'keys.cfg')]);
const now = new Date('2026-11-16T00:00:00Z');

test('plan: ranked by risk, suggested owners, dates from the report date, status not started', () => {
  const r = buildReadinessReport({ organization: 'Acme', scan, migration: { changeCount: 1 }, now });
  assert.deepEqual(r.roadmap.map((s) => s.rank), r.roadmap.map((_, i) => i + 1));
  assert.equal(r.roadmap[0].key, 'weak-keys');
  assert.equal(r.roadmap[0].risk, 'critical');
  assert.equal(r.roadmap[0].targetDate, '2026-12-16', 'Now = report date + 30 days');
  assert.equal(r.roadmap.find((s) => s.key === 'hybrid-kex').targetDate, '2027-02-14', 'Next 3 months = +90 days');
  assert.equal(r.roadmap.find((s) => s.key === 'code-migration').risk, 'high');
  assert.equal(r.roadmap.at(-1).key, 'inventory');
  assert.ok(r.roadmap.every((s) => s.status === 'not started' && s.owner && s.ownerSource === 'suggested role'));
  assert.ok(r.roadmap.every((s) => PLAN_STEP_KEYS.includes(s.key)));
});

test('plan: customer owners, status and dates are kept, signed and shown; bad input is refused', () => {
  const plan = { owners: { 'hybrid-kex': 'Jordan (platform team)' }, status: { 'weak-keys': 'in progress' }, targetDates: { 'code-migration': '2027-06-30' } };
  const r = buildReadinessReport({ organization: 'Acme', scan, migration: { changeCount: 1 }, now, plan });
  const by = Object.fromEntries(r.roadmap.map((s) => [s.key, s]));
  assert.equal(by['hybrid-kex'].owner, 'Jordan (platform team)');
  assert.equal(by['hybrid-kex'].ownerSource, 'set by the customer');
  assert.equal(by['weak-keys'].status, 'in progress');
  assert.equal(by['code-migration'].targetDate, '2027-06-30');
  const key = generateSigningKey();
  const signed = signReport(r, key);
  assert.equal(verifyReport(signed).valid, true);
  const changed = { ...signed, roadmap: signed.roadmap.map((s) => (s.key === 'weak-keys' ? { ...s, status: 'done' } : s)) };
  assert.equal(verifyReport(changed).valid, false, 'changing a step status breaks the signature');
  const html = renderReportHtml(signed);
  assert.match(html, /Migration plan, in order/);
  assert.match(html, /Owner <b>Jordan \(platform team\)<\/b>/);
  assert.match(html, /Status <b>in progress<\/b>/);
  assert.throws(() => checkPlanInputs({ owners: { nope: 'x' } }), /unknown plan step/);
  assert.throws(() => checkPlanInputs({ status: { 'weak-keys': 'finished' } }), /must be one of/);
  assert.throws(() => checkPlanInputs({ targetDates: { 'weak-keys': '2027-02-30' } }), /YYYY-MM-DD/);
  assert.throws(() => checkPlanInputs({ owners: { 'weak-keys': 'x'.repeat(81) } }), /1-80/);
  assert.throws(() => checkPlanInputs({ owners: ['a'] }), /object keyed by plan step/);
  assert.deepEqual(migrationPlan(roadmap(null, null, []), now.toISOString()).map((s) => s.key), ['inventory'], 'no scan: upkeep only');
});
