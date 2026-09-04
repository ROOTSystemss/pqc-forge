import { test } from "node:test";
import assert from "node:assert/strict";
import {
  generateKeyPair,
  toKeyFile,
  parseKeyFile,
  keyFileToPair,
  computeKeyId,
  ALGORITHM,
  KEY_SCHEMA,
} from "./keys.js";

test("generateKeyPair produces ML-DSA-65-sized keys", () => {
  const pair = generateKeyPair();
  assert.equal(pair.publicKey.length, 1952);
  assert.equal(pair.secretKey.length, 4032);
});

test("generateKeyPair rejects a seed of the wrong length", () => {
  assert.throws(() => generateKeyPair(new Uint8Array(16)), /seed must be 32 bytes/);
});

test("generateKeyPair is deterministic given the same seed", () => {
  const seed = new Uint8Array(32).fill(7);
  const a = generateKeyPair(seed);
  const b = generateKeyPair(seed);
  assert.deepEqual(Buffer.from(a.publicKey), Buffer.from(b.publicKey));
  assert.deepEqual(Buffer.from(a.secretKey), Buffer.from(b.secretKey));
});

test("toKeyFile / parseKeyFile round-trip", () => {
  const pair = generateKeyPair();
  const created = new Date("2026-01-01T00:00:00.000Z");
  const file = toKeyFile(pair, created);

  assert.equal(file.schema, KEY_SCHEMA);
  assert.equal(file.algorithm, ALGORITHM);
  assert.equal(file.createdAt, created.toISOString());
  assert.equal(file.keyId, computeKeyId(file.publicKey));

  const parsed = parseKeyFile(JSON.stringify(file));
  assert.deepEqual(parsed, file);

  const roundTripped = keyFileToPair(parsed);
  assert.deepEqual(Buffer.from(roundTripped.publicKey), Buffer.from(pair.publicKey));
  assert.deepEqual(Buffer.from(roundTripped.secretKey), Buffer.from(pair.secretKey));
});

test("parseKeyFile rejects a tampered keyId", () => {
  const file = toKeyFile(generateKeyPair());
  const tampered = { ...file, keyId: "sha256:" + "0".repeat(64) };
  assert.throws(() => parseKeyFile(JSON.stringify(tampered)), /keyId mismatch/);
});

test("parseKeyFile rejects an unknown schema", () => {
  const file = toKeyFile(generateKeyPair());
  const tampered = { ...file, schema: "something-else/v1" };
  assert.throws(() => parseKeyFile(JSON.stringify(tampered)), /unexpected key schema/);
});

test("parseKeyFile rejects an unsupported algorithm", () => {
  const file = toKeyFile(generateKeyPair());
  const tampered = { ...file, algorithm: "ML-DSA-44" };
  assert.throws(() => parseKeyFile(JSON.stringify(tampered)), /unsupported algorithm/);
});

test("computeKeyId matches the known real-world key format", () => {
  // Regression check for the format used by the pre-existing
  // ~/.pqc-forge/signing-key.json: keyId is sha256 of the base64
  // *string* of the public key, not of the raw public key bytes.
  const publicKeyB64 = "AAAA";
  const expected = "sha256:63c1dd951ffedf6f7fd968ad4efa39b8ed584f162f46e715114ee184f8de9201";
  assert.equal(computeKeyId(publicKeyB64), expected);
});
