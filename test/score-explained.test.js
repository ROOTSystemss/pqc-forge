import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildReadinessReport, renderReportHtml, signReport, verifyReport } from '../src/readinessReport.js';
import { generateSigningKey } from '../src/signing.js';

// AD-063 (knock-out Phase 5): the readiness score is one number, explained. The signed report carries every
// deduction (count, points each, cap, points taken) so anyone can recompute it; the HTML shows the sum.
const scan = (critical, high, medium) => ({ summary: { critical, high, medium, low: 0, automatable: 0, total: critical + high + medium, suppressed: 0 }, findings: [], filesScanned: 5 });

test('score breakdown: each deduction listed, sums to the score, caps respected, inside the signed body', () => {
  const r = buildReadinessReport({ organization: 'Explain Co', scan: scan(4, 9, 1), migration: null, endpoints: [{ target: 'down.example', ok: false, error: 'timeout' }], now: new Date('2026-11-17T00:00:00Z') });
  const b = r.readiness.breakdown;
  assert.deepEqual(b.map((p) => p.key), ['critical', 'high', 'medium', 'unreachable-endpoints']);
  assert.equal(b.find((p) => p.key === 'critical').points, 45, 'critical capped at 45 (4 x 15 = 60)');
  assert.equal(b.find((p) => p.key === 'high').points, 35, 'high capped at 35 (9 x 5 = 45)');
  assert.equal(100 - b.reduce((n, p) => n + p.points, 0), Math.max(0, r.readiness.score), 'breakdown recomputes the score');
  const K = generateSigningKey();
  const signed = signReport(r, K);
  assert.equal(verifyReport(signed, [K]).valid, true);
  const tampered = { ...signed, readiness: { ...signed.readiness, breakdown: signed.readiness.breakdown.slice(1) } };
  assert.equal(verifyReport(tampered, [K]).valid, false, 'removing a deduction breaks the signature');
});

test('score breakdown: clean scan has no deductions; HTML says so; unverified stage hides the number', () => {
  const clean = buildReadinessReport({ organization: 'Clean Co', scan: scan(0, 0, 0), migration: null, endpoints: [], now: new Date('2026-11-17T00:00:00Z') });
  assert.deepEqual(clean.readiness.breakdown, []);
  const html = renderReportHtml(signReport(clean, generateSigningKey()));
  assert.match(html, /id="score-explained"/);
  assert.match(html, /No deduction applied/);
  const busy = buildReadinessReport({ organization: 'Busy Co', scan: scan(1, 2, 0), migration: null, endpoints: [], now: new Date('2026-11-17T00:00:00Z') });
  const h2 = renderReportHtml(signReport(busy, generateSigningKey()));
  const line = (h2.match(/<div id="score-explained">[\s\S]*?<\/div>/) || [''])[0].replace(/<[^>]+>/g, '');
  assert.match(line, /100/);
  assert.match(line, /= 75\./, line);
  const nothing = buildReadinessReport({ organization: 'Nothing Co', scan: null, migration: null, endpoints: [{ target: 'x.example', ok: false, error: 'dns' }], now: new Date('2026-11-17T00:00:00Z') });
  assert.equal(nothing.readiness.stage, 'unverified');
  assert.match(renderReportHtml(signReport(nothing, generateSigningKey())), /Not verified, so the number is not shown as a result/);
  assert.doesNotMatch(html + h2, /quantum-safe|quantum-proof/i);
});
