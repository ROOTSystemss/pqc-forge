import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { evaluateCandidate, runBreakLab } from '../src/breaklab/engine.js';
import { createReceipt, verifyReceipt } from '../src/breaklab/receipt.js';
import { renderBreakLabHtml } from '../src/breaklab/report.js';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const scenario = JSON.parse(await readFile(path.join(root, 'scenarios', 'tls-migration-demo.json'), 'utf8'));

test('evaluator detects silent classical downgrade', () => {
  const result = evaluateCandidate(scenario, {
    client: 'legacy-classical', server: 'pq-preferred', certificate: 'rsa-pss', network: 'datacenter', allowClassicalFallback: true
  });
  assert.equal(result.negotiatedGroup, 'X25519');
  assert.ok(result.findings.some((finding) => finding.code === 'CLASSICAL_DOWNGRADE'));
});

test('BreakLab is deterministic and compares all strategies fairly', () => {
  const first = runBreakLab(scenario, { budget: 30, seed: 7 });
  const second = runBreakLab(scenario, { budget: 30, seed: 7 });
  assert.equal(first.totalStates, 72);
  assert.equal(first.strategies.length, 4);
  const stable = (run) => run.strategies.map((item) => [item.strategy, item.maxSeverity, item.uniqueFailureModes]);
  assert.deepEqual(stable(first), stable(second));
  assert.ok(first.counterexamples.some((item) => item.failureCode === 'CLASSICAL_DOWNGRADE'));
});

test('receipt detects tampering and HTML presents evidence', () => {
  const run = runBreakLab(scenario, { budget: 20, seed: 42 });
  const receipt = createReceipt(run, scenario);
  assert.equal(verifyReceipt(receipt).valid, true);
  assert.match(renderBreakLabHtml(receipt), /Minimal counterexamples/);
  receipt.run.winner = 'tampered';
  assert.equal(verifyReceipt(receipt).valid, false);
});
