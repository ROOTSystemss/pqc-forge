import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test, mock } from 'node:test';
import { scanRepository } from '../src/scanner.js';
import { scoreReadiness, endpointStatus, buildReadinessReport, signReport, verifyReport, renderReportHtml } from '../src/readinessReport.js';
import { generateSigningKey } from '../src/signing.js';

// BM-05 three-state rule (knock-out 2026-11-17): what could not be checked is "Not verified" - never "Ready",
// never "Exposed: classical cryptography only" without evidence; observed weaknesses still decide the stage.
const clean = { filesScanned: 3, unreadableCount: 0, summary: { critical: 0, high: 0, medium: 0, low: 0, automatable: 0, total: 0, suppressed: 0 }, findings: [] };
const pqEnd = { target: 'pq.example.com', ok: true, evidence: { protocol: 'TLSv1.3', ephemeralKey: { name: 'X25519MLKEM768' }, peerSignatureAlgorithm: 'ecdsa', verdict: { pqKeyExchange: true, pqAuthentication: false }, generatedAt: '2026-11-17T00:00:00Z' } };
const classicalEnd = { target: 'old.example.com', ok: true, evidence: { protocol: 'TLSv1.3', ephemeralKey: { name: 'X25519' }, peerSignatureAlgorithm: 'rsa', verdict: { pqKeyExchange: false, pqAuthentication: false }, generatedAt: '2026-11-17T00:00:00Z' } };
const down = { target: 'down.example.com', ok: false, error: 'connect ETIMEDOUT' };

test('three-state stages: unchecked is Not verified, never ready, never a made-up exposed', () => {
  assert.equal(scoreReadiness(null, [down]).stage.id, 'unverified', 'only an unreachable endpoint (before: exposed)');
  assert.equal(scoreReadiness({ ...clean, filesScanned: 0 }, []).stage.id, 'unverified', 'nothing scanned (before: ready)');
  assert.equal(scoreReadiness(clean, [pqEnd, down]).stage.id, 'unverified', 'clean code + one endpoint did not answer');
  assert.equal(scoreReadiness({ ...clean, unreadableCount: 2 }, []).stage.id, 'unverified', 'clean but two files unreadable (before: ready)');
  assert.equal(scoreReadiness(clean, [pqEnd]).stage.id, 'ready', 'everything checked and clean');
  assert.equal(scoreReadiness(clean, [classicalEnd, down]).stage.id, 'exposed', 'an observed classical endpoint still decides');
  const urgent = { ...clean, summary: { ...clean.summary, critical: 1, total: 1 } };
  assert.equal(scoreReadiness(urgent, [down]).stage.id, 'urgent', 'an observed critical finding is never hidden by unknowns');
  assert.equal(scoreReadiness(clean, [down]).pqEndpoints, 0, 'an unreachable endpoint never counts as post-quantum');
  assert.equal(endpointStatus(down), 'Not verified (not reachable)');
});

test('scanner: a file that cannot be read is not counted as scanned and is listed', async () => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'pqc-3s-'));
  await fsp.writeFile(path.join(dir, 'ok.js'), "const k = require('crypto').generateKeyPairSync('rsa', { modulusLength: 2048 });\n");
  await fsp.writeFile(path.join(dir, 'locked.js'), "console.log('x');\n");
  const real = fsp.readFile.bind(fsp);
  const m = mock.method(fsp, 'readFile', async (p, ...rest) => { if (String(p).endsWith('locked.js')) { const e = new Error('EACCES: permission denied'); e.code = 'EACCES'; throw e; } return real(p, ...rest); });
  try {
    const scan = await scanRepository(dir);
    assert.equal(scan.unreadableCount, 1);
    assert.deepEqual(scan.unreadableFiles, ['locked.js']);
    assert.equal(scan.filesScanned, 1, 'only the readable file counts as scanned (before: 2)');
    const allLocked = await scanRepository(path.join(dir, 'locked.js'));
    assert.equal(allLocked.filesScanned, 0);
    assert.equal(scoreReadiness(allLocked, []).stage.id, 'unverified', 'a tree nobody could read is never ready');
  } finally { m.mock.restore(); }
});

test('signed report and HTML say Not verified; the signature still verifies and a change fails', () => {
  const K = generateSigningKey();
  const scan = { ...clean, unreadableCount: 1, unreadableFiles: ['secret.bin'], filesScanned: 2 };
  const report = buildReadinessReport({ organization: 'Three State Co', scan, migration: null, endpoints: [down], now: new Date('2026-11-17T00:00:00Z') });
  assert.equal(report.readiness.stage, 'unverified');
  assert.equal(report.readiness.stageLabel, 'Not verified');
  assert.equal(report.summary.endpointsUnreachable, 1);
  assert.equal(report.summary.filesNotVerified, 1);
  assert.deepEqual(report.scope.unreadableFiles, ['secret.bin']);
  assert.equal(report.endpoints[0].status, 'Not verified (not reachable)');
  assert.match(report.method, /Not verified when nothing weak was found but something could not be checked/);
  const signed = signReport(report, K);
  assert.equal(verifyReport(signed, [K]).valid, true);
  assert.equal(verifyReport({ ...signed, readiness: { ...signed.readiness, stage: 'ready' } }, [K]).valid, false, 'flipping the stage to ready breaks the signature');
  const html = renderReportHtml(signed);
  assert.match(html, /Not verified/);
  assert.match(html, /<div class="score">&ndash;<\/div>/, 'no score number is shown for an unverified report');
  assert.doesNotMatch(html, /Ready for the deadlines/);
});
