import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { createRuntimeReceipt, createTlsReceipt, verifyReceipt } from '../src/breaklab/receipt.js';
import { evaluateStagingGate, writeStagingEvidence } from '../src/staging-gate.js';

function manifest(overrides = {}) {
  return {
    schema: 'pqc-forge.staging-manifest/v1',
    target: 'isolated-staging-us-1',
    runtimeReceipts: ['./runtime-receipt.json'],
    endpointReceipts: ['./tls-receipt.json'],
    requirePqAuthentication: false,
    metrics: {
      handshakeErrorRatePct: 0.05,
      p95HandshakeLatencyMs: 85,
      cpuIncreasePct: 12,
      memoryIncreasePct: 8,
      soakMinutes: 120
    },
    thresholds: {
      maxHandshakeErrorRatePct: 0.1,
      maxP95HandshakeLatencyMs: 100,
      maxCpuIncreasePct: 20,
      maxMemoryIncreasePct: 15,
      minSoakMinutes: 60
    },
    rollback: { tested: true, recoverySeconds: 45, maxRecoverySeconds: 120 },
    canary: { trafficPercent: 5, monitoringConfigured: true, rollbackTriggersConfigured: true },
    operatorApproval: { approved: true, approvedBy: 'staging-owner@example.test' },
    ...overrides
  };
}

function receipts() {
  return {
    runtimeReceipts: [createRuntimeReceipt({ verdict: { pass: true }, target: 'isolated-staging-us-1' })],
    endpointReceipts: [createTlsReceipt({
      target: 'staging.example.test:443', authorized: true,
      verdict: { pqKeyExchange: true, pqAuthentication: false, status: 'pq-confidentiality-observed' }
    })]
  };
}

async function fixture(customManifest = manifest()) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-staging-'));
  const evidence = receipts();
  await fs.writeFile(path.join(root, 'runtime-receipt.json'), `${JSON.stringify(evidence.runtimeReceipts[0], null, 2)}\n`);
  await fs.writeFile(path.join(root, 'tls-receipt.json'), `${JSON.stringify(evidence.endpointReceipts[0], null, 2)}\n`);
  await fs.writeFile(path.join(root, 'manifest.json'), `${JSON.stringify(customManifest, null, 2)}\n`);
  return { root, evidence };
}

test('staging gate passes only to an authorized canary and creates verifiable evidence', async () => {
  const { root } = await fixture();
  const result = await writeStagingEvidence(path.join(root, 'manifest.json'), path.join(root, 'output'));
  assert.equal(result.run.verdict.pass, true);
  assert.equal(result.run.verdict.status, 'ready-for-authorized-canary');
  assert.equal(result.run.verdict.productionDeploymentAuthorized, false);
  assert.equal(verifyReceipt(result.receipt).valid, true);
  assert.match(await fs.readFile(path.join(root, 'output', 'STAGING_REPORT.md'), 'utf8'), /Production deployment authorized: \*\*NO\*\*/);
});

test('staging gate reports every failed threshold and operational control', () => {
  const blocked = manifest({
    metrics: { handshakeErrorRatePct: 2, p95HandshakeLatencyMs: 180, cpuIncreasePct: 50, memoryIncreasePct: 30, soakMinutes: 10 },
    rollback: { tested: false, recoverySeconds: 300, maxRecoverySeconds: 120 },
    canary: { trafficPercent: 25, monitoringConfigured: false, rollbackTriggersConfigured: false },
    operatorApproval: { approved: false, approvedBy: '' }
  });
  const run = evaluateStagingGate(blocked, receipts());
  assert.equal(run.verdict.pass, false);
  assert.deepEqual(run.verdict.failures.sort(), [
    'canaryTrafficPercent', 'cpuIncreasePct', 'handshakeErrorRatePct', 'memoryIncreasePct',
    'monitoringConfigured', 'operatorApprovalRecorded', 'p95HandshakeLatencyMs',
    'rollbackRecoverySeconds', 'rollbackTested', 'rollbackTriggersConfigured', 'soakMinutes'
  ].sort());
});

test('staging gate enforces PQ authentication when requested', () => {
  const run = evaluateStagingGate(manifest({ requirePqAuthentication: true }), receipts());
  assert.equal(run.verdict.pass, false);
  assert.deepEqual(run.verdict.failures, ['endpointReceipt[0]']);
});

test('staging gate rejects a tampered input receipt before producing evidence', async () => {
  const { root } = await fixture();
  const receiptPath = path.join(root, 'runtime-receipt.json');
  const receipt = JSON.parse(await fs.readFile(receiptPath, 'utf8'));
  receipt.probe.verdict.pass = false;
  await fs.writeFile(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`);
  await assert.rejects(
    () => writeStagingEvidence(path.join(root, 'manifest.json'), path.join(root, 'output')),
    /failed digest verification/
  );
  await assert.rejects(() => fs.access(path.join(root, 'output')));
});

test('staging gate refuses to overwrite an existing evidence directory', async () => {
  const { root } = await fixture();
  const output = path.join(root, 'output');
  await fs.mkdir(output);
  await fs.writeFile(path.join(output, 'keep.txt'), 'user evidence');
  await assert.rejects(() => writeStagingEvidence(path.join(root, 'manifest.json'), output), /Refusing to overwrite/);
});
