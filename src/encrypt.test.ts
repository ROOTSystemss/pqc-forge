import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKemKeyPair, toKemKeyFile } from "./kem.js";
import { encryptForRecipient, decryptWithKey, ENCRYPTED_SCHEMA } from "./encrypt.js";

test("encryptForRecipient / decryptWithKey round-trip", () => {
  const pair = generateKemKeyPair();
  const keyFile = toKemKeyFile(pair);
  const plaintext = new TextEncoder().encode("top secret post-quantum payload");

  const encrypted = encryptForRecipient(pair.publicKey, keyFile.keyId, plaintext);
  assert.equal(encrypted.schema, ENCRYPTED_SCHEMA);
  assert.equal(encrypted.keyId, keyFile.keyId);

  const result = decryptWithKey(pair, keyFile.keyId, encrypted);
  assert.equal(result.ok, true);
  assert.equal(Buffer.from(plaintext).equals((result as { plaintext: Buffer }).plaintext), true);
});

test("each encryption uses a fresh KEM encapsulation and IV", () => {
  const pair = generateKemKeyPair();
  const keyFile = toKemKeyFile(pair);
  const plaintext = new TextEncoder().encode("same message twice");

  const a = encryptForRecipient(pair.publicKey, keyFile.keyId, plaintext);
  const b = encryptForRecipient(pair.publicKey, keyFile.keyId, plaintext);

  assert.notEqual(a.kemCiphertext, b.kemCiphertext);
  assert.notEqual(a.iv, b.iv);
  assert.notEqual(a.ciphertext, b.ciphertext);
});

test("decryptWithKey rejects the wrong secret key", () => {
  const recipient = generateKemKeyPair();
  const recipientKeyFile = toKemKeyFile(recipient);
  const attacker = generateKemKeyPair();
  const plaintext = new TextEncoder().encode("for recipient's eyes only");

  const encrypted = encryptForRecipient(recipient.publicKey, recipientKeyFile.keyId, plaintext);
  const result = decryptWithKey(attacker, recipientKeyFile.keyId, encrypted);
  assert.equal(result.ok, false);
});

test("decryptWithKey rejects a tampered ciphertext", () => {
  const pair = generateKemKeyPair();
  const keyFile = toKemKeyFile(pair);
  const plaintext = new TextEncoder().encode("integrity matters");
  const encrypted = encryptForRecipient(pair.publicKey, keyFile.keyId, plaintext);

  const corrupted = Buffer.from(encrypted.ciphertext, "base64");
  corrupted[0] ^= 0xff;
  const tampered = { ...encrypted, ciphertext: corrupted.toString("base64") };

  const result = decryptWithKey(pair, keyFile.keyId, tampered);
  assert.equal(result.ok, false);
  assert.match((result as { reason: string }).reason, /decryption failed/);
});

test("decryptWithKey rejects a malformed (wrong-length) KEM ciphertext without throwing", () => {
  const pair = generateKemKeyPair();
  const keyFile = toKemKeyFile(pair);
  const plaintext = new TextEncoder().encode("payload");
  const encrypted = encryptForRecipient(pair.publicKey, keyFile.keyId, plaintext);

  const tampered = { ...encrypted, kemCiphertext: Buffer.from([1, 2, 3]).toString("base64") };
  const result = decryptWithKey(pair, keyFile.keyId, tampered);
  assert.equal(result.ok, false);
  assert.match((result as { reason: string }).reason, /KEM decapsulation failed/);
});

test("decryptWithKey rejects a keyId mismatch", () => {
  const pair = generateKemKeyPair();
  const keyFile = toKemKeyFile(pair);
  const plaintext = new TextEncoder().encode("payload");
  const encrypted = encryptForRecipient(pair.publicKey, keyFile.keyId, plaintext);

  const result = decryptWithKey(pair, "sha256:" + "1".repeat(64), encrypted);
  assert.equal(result.ok, false);
  assert.match((result as { reason: string }).reason, /keyId mismatch/);
});
