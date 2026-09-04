import { test } from "node:test";
import assert from "node:assert/strict";
import {
  generateKemKeyPair,
  toKemKeyFile,
  toKemPublicKeyFile,
  parseKemKeyFile,
  kemKeyFileToPair,
  kemKeyFileToPublicKey,
  computeKemKeyId,
  KEM_ALGORITHM,
  KEM_KEY_SCHEMA,
} from "./kem.js";

test("generateKemKeyPair produces ML-KEM-768-sized keys", () => {
  const pair = generateKemKeyPair();
  assert.equal(pair.publicKey.length, 1184);
  assert.equal(pair.secretKey.length, 2400);
});

test("generateKemKeyPair rejects a seed of the wrong length", () => {
  assert.throws(() => generateKemKeyPair(new Uint8Array(32)), /seed must be 64 bytes/);
});

test("generateKemKeyPair is deterministic given the same seed", () => {
  const seed = new Uint8Array(64).fill(3);
  const a = generateKemKeyPair(seed);
  const b = generateKemKeyPair(seed);
  assert.deepEqual(Buffer.from(a.publicKey), Buffer.from(b.publicKey));
  assert.deepEqual(Buffer.from(a.secretKey), Buffer.from(b.secretKey));
});

test("toKemKeyFile / parseKemKeyFile round-trip", () => {
  const pair = generateKemKeyPair();
  const created = new Date("2026-01-01T00:00:00.000Z");
  const file = toKemKeyFile(pair, created);

  assert.equal(file.schema, KEM_KEY_SCHEMA);
  assert.equal(file.algorithm, KEM_ALGORITHM);
  assert.equal(file.createdAt, created.toISOString());
  assert.equal(file.keyId, computeKemKeyId(file.publicKey));

  const parsed = parseKemKeyFile(JSON.stringify(file));
  assert.deepEqual(parsed, file);

  const roundTripped = kemKeyFileToPair(parsed);
  assert.deepEqual(Buffer.from(roundTripped.publicKey), Buffer.from(pair.publicKey));
  assert.deepEqual(Buffer.from(roundTripped.secretKey), Buffer.from(pair.secretKey));
});

test("parseKemKeyFile rejects a tampered keyId", () => {
  const file = toKemKeyFile(generateKemKeyPair());
  const tampered = { ...file, keyId: "sha256:" + "0".repeat(64) };
  assert.throws(() => parseKemKeyFile(JSON.stringify(tampered)), /keyId mismatch/);
});

test("parseKemKeyFile rejects an unknown schema", () => {
  const file = toKemKeyFile(generateKemKeyPair());
  const tampered = { ...file, schema: "something-else/v1" };
  assert.throws(() => parseKemKeyFile(JSON.stringify(tampered)), /unexpected key schema/);
});

test("parseKemKeyFile rejects an unsupported algorithm", () => {
  const file = toKemKeyFile(generateKemKeyPair());
  const tampered = { ...file, algorithm: "ML-KEM-512" };
  assert.throws(() => parseKemKeyFile(JSON.stringify(tampered)), /unsupported algorithm/);
});

test("toKemPublicKeyFile strips the secret key but keeps keyId/publicKey intact", () => {
  const file = toKemKeyFile(generateKemKeyPair());
  const pub = toKemPublicKeyFile(file);
  assert.equal(pub.secretKey, undefined);
  assert.equal(pub.publicKey, file.publicKey);
  assert.equal(pub.keyId, file.keyId);
  assert.equal(JSON.stringify(pub).includes("secretKey"), false);
});

test("kemKeyFileToPublicKey works on a public-only export", () => {
  const pair = generateKemKeyPair();
  const pub = toKemPublicKeyFile(toKemKeyFile(pair));
  const decoded = kemKeyFileToPublicKey(pub);
  assert.deepEqual(Buffer.from(decoded), Buffer.from(pair.publicKey));
});

test("kemKeyFileToPair throws a clear error on a public-only export", () => {
  const pub = toKemPublicKeyFile(toKemKeyFile(generateKemKeyPair()));
  assert.throws(() => kemKeyFileToPair(pub), /has no secret key/);
});
