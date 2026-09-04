import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { evaluateCandidate, runBreakLab } from '../src/breaklab/engine.js';
import { createReceipt, verifyReceipt } from '../src/breaklab/receipt.js';
import { generateSigningKey } from '../src/signing.js';
import { renderBreakLabHtml } from '../src/breaklab/report.js';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const scenario = JSON.parse(await readFile(path.join(root, 'scenarios', 'tls-migration-demo.json'), 'utf8'));
const key = generateSigningKey();

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
  const receipt = createReceipt(run, scenario, key);
  assert.equal(verifyReceipt(receipt).valid, true);
  assert.match(renderBreakLabHtml(receipt), /Minimal counterexamples/);
  receipt.run.winner = 'tampered';
  assert.equal(verifyReceipt(receipt).valid, false);
});

test('receipt is rejected when the signature is missing or from an untrusted key', () => {
  const run = runBreakLab(scenario, { budget: 20, seed: 42 });
  const receipt = createReceipt(run, scenario, key);

  const { signature, ...unsigned } = receipt;
  const missingSignature = verifyReceipt(unsigned);
  assert.equal(missingSignature.valid, false);
  assert.ok(missingSignature.errors.includes('signature-missing'));

  const trustedElsewhere = verifyReceipt(receipt, { trustedPublicKeys: [generateSigningKey().publicKey] });
  assert.equal(trustedElsewhere.valid, false);
  assert.ok(trustedElsewhere.errors.includes('signer-not-trusted'));

  const trustedHere = verifyReceipt(receipt, { trustedPublicKeys: [key.publicKey] });
  assert.equal(trustedHere.valid, true);
});

test('createReceipt refuses to produce an unsigned receipt', () => {
  const run = runBreakLab(scenario, { budget: 10, seed: 1 });
  assert.throws(() => createReceipt(run, scenario, null), /signing key is required/);
});
