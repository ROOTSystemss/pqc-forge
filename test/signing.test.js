import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  generateSigningKey, loadSigningKey, publicKeyDocument,
  signPayload, verifySignature, keyIdFor, validateSigningKey
} from '../src/signing.js';
import { createMigrationReceipt, verifyReceipt } from '../src/breaklab/receipt.js';

const execute = promisify(execFile);
const projectRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const cli = path.join(projectRoot, 'bin', 'pqc-forge.js');

test('generateSigningKey produces a valid, self-consistent ML-DSA-65 identity', () => {
  const key = generateSigningKey();
  assert.equal(key.algorithm, 'ML-DSA-65');
  assert.equal(key.keyId, keyIdFor(key.publicKey));
  assert.doesNotThrow(() => validateSigningKey(key));
  const pub = publicKeyDocument(key);
  assert.equal(pub.secretKey, undefined);
  assert.equal(pub.publicKey, key.publicKey);
  assert.equal(pub.keyId, key.keyId);
});

test('sign -> verify round trip succeeds, and tampering the payload is detected', () => {
  const key = generateSigningKey();
  const payload = { schema: 'test/v1', value: 42 };
  const signature = signPayload(payload, key);
  assert.equal(verifySignature(payload, signature), true);
  assert.equal(verifySignature({ ...payload, value: 43 }, signature), false);
});

test('two keys produce different signatures and cannot verify each other', () => {
  const a = generateSigningKey();
  const b = generateSigningKey();
  const payload = { schema: 'test/v1', value: 'same-input' };
  const sigA = signPayload(payload, a);
  assert.equal(verifySignature(payload, sigA), true);
  const forged = { ...sigA, publicKey: b.publicKey, keyId: b.keyId };
  assert.equal(verifySignature(payload, forged), false);
});

test('verifyReceipt: clean signed receipt passes end to end', () => {
  const key = generateSigningKey();
  const receipt = createMigrationReceipt({ schema: 'pqc-forge.migration/v1', root: '/x', mode: 'dry-run', changeCount: 0, changes: [], artifacts: [] }, key);
  const result = verifyReceipt(receipt);
  assert.equal(result.valid, true);
  assert.equal(result.digestValid, true);
  assert.equal(result.signaturePresent, true);
  assert.equal(result.signatureValid, true);
  assert.equal(result.keyId, key.keyId);
  assert.deepEqual(result.errors, []);
});

test('verifyReceipt: sign -> tamper -> detect for every mutation shape', () => {
  const key = generateSigningKey();
  const receipt = createMigrationReceipt({ schema: 'pqc-forge.migration/v1', root: '/x', mode: 'applied', changeCount: 1, changes: [], artifacts: [] }, key);

  const payloadTampered = structuredClone(receipt);
  payloadTampered.migration.changeCount = 999;
  const payloadResult = verifyReceipt(payloadTampered);
  assert.equal(payloadResult.valid, false);
  assert.equal(payloadResult.digestValid, false);
  assert.ok(payloadResult.errors.includes('digest-mismatch'));

  const signatureTampered = structuredClone(receipt);
  signatureTampered.signature.value = Buffer.from('not-a-real-signature').toString('base64');
  const signatureResult = verifyReceipt(signatureTampered);
  assert.equal(signatureResult.valid, false);
  assert.equal(signatureResult.digestValid, true);
  assert.equal(signatureResult.signatureValid, false);
  assert.ok(signatureResult.errors.includes('signature-invalid'));

  const { signature, ...unsigned } = receipt;
  const missingResult = verifyReceipt(unsigned);
  assert.equal(missingResult.valid, false);
  assert.ok(missingResult.errors.includes('signature-missing'));

  const cleanResult = verifyReceipt(receipt);
  assert.equal(cleanResult.valid, true);
});

test('verifyReceipt: trustedPublicKeys pins signer identity', () => {
  const key = generateSigningKey();
  const impostor = generateSigningKey();
  const receipt = createMigrationReceipt({ schema: 'pqc-forge.migration/v1', root: '/x', mode: 'dry-run', changeCount: 0, changes: [], artifacts: [] }, key);

  assert.equal(verifyReceipt(receipt, { trustedPublicKeys: [key.publicKey] }).valid, true);
  assert.equal(verifyReceipt(receipt, { trustedPublicKeys: [publicKeyDocument(key)] }).valid, true);
  const untrusted = verifyReceipt(receipt, { trustedPublicKeys: [impostor.publicKey] });
  assert.equal(untrusted.valid, false);
  assert.ok(untrusted.errors.includes('signer-not-trusted'));
});

test('create*Receipt throws without a signing key rather than emitting an unsigned receipt', () => {
  assert.throws(() => createMigrationReceipt({ schema: 'pqc-forge.migration/v1', root: '/x', mode: 'dry-run', changeCount: 0, changes: [], artifacts: [] }, null), /signing key is required/);
});

test('loadSigningKey auto-provisions once and reuses the same identity thereafter', async () => {
  const home = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-home-'));
  const previousHome = process.env.PQC_FORGE_HOME;
  process.env.PQC_FORGE_HOME = home;
  try {
    const first = await loadSigningKey();
    assert.equal(first.autoProvisioned, true);
    const second = await loadSigningKey();
    assert.equal(second.autoProvisioned, false);
    assert.equal(second.key.keyId, first.key.keyId);
  } finally {
    if (previousHome === undefined) delete process.env.PQC_FORGE_HOME;
    else process.env.PQC_FORGE_HOME = previousHome;
  }
});

test('loadSigningKey rejects an explicit path that does not exist', async () => {
  await assert.rejects(() => loadSigningKey(path.join(os.tmpdir(), 'pqc-forge-does-not-exist', 'key.json')), /Signing key not found/);
});

test('CLI keygen writes a secret and public key file, and refuses to overwrite', async () => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-keygen-'));
  const out = path.join(base, 'keys');
  await execute(process.execPath, [cli, 'keygen', '--out', out]);
  const key = JSON.parse(await fs.readFile(path.join(out, 'signing-key.json'), 'utf8'));
  const pub = JSON.parse(await fs.readFile(path.join(out, 'signing-key.pub.json'), 'utf8'));
  validateSigningKey(key);
  assert.equal(pub.publicKey, key.publicKey);
  assert.equal(pub.secretKey, undefined);
  await assert.rejects(execute(process.execPath, [cli, 'keygen', '--out', out]));
});

test('CLI verify-receipt: valid signed receipt passes, tampered receipt fails, untrusted signer fails', async () => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-verify-receipt-'));
  const keysA = path.join(base, 'keys-a');
  const keysB = path.join(base, 'keys-b');
  await execute(process.execPath, [cli, 'keygen', '--out', keysA]);
  await execute(process.execPath, [cli, 'keygen', '--out', keysB]);

  const repository = path.join(base, 'repository');
  await fs.mkdir(repository);
  await fs.writeFile(path.join(repository, 'nginx.conf'), 'ssl_protocols TLSv1 TLSv1.2 TLSv1.3;\nssl_ecdh_curve X25519;\n');
  const migrationOut = path.join(base, 'migration');
  await execute(process.execPath, [cli, 'migrate', repository, '--out', migrationOut, '--signing-key', path.join(keysA, 'signing-key.json')]);
  const receiptPath = path.join(migrationOut, 'migration-receipt.json');

  const clean = await execute(process.execPath, [cli, 'verify-receipt', receiptPath, '--json']);
  assert.equal(JSON.parse(clean.stdout).valid, true);

  const trustedOk = await execute(process.execPath, [cli, 'verify-receipt', receiptPath, '--trusted-key', path.join(keysA, 'signing-key.pub.json'), '--json']);
  assert.equal(JSON.parse(trustedOk.stdout).valid, true);

  await assert.rejects(execute(process.execPath, [cli, 'verify-receipt', receiptPath, '--trusted-key', path.join(keysB, 'signing-key.pub.json'), '--json']));

  const receipt = JSON.parse(await fs.readFile(receiptPath, 'utf8'));
  receipt.migration.changeCount = 999;
  const tamperedPath = path.join(base, 'tampered-receipt.json');
  await fs.writeFile(tamperedPath, JSON.stringify(receipt));
  await assert.rejects(execute(process.execPath, [cli, 'verify-receipt', tamperedPath, '--json']));
});
