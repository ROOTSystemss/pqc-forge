import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, toKeyFile } from "./keys.js";
import { signBytes, verifyBytes, buildSignatureFile, verifySignatureFile } from "./sign.js";

test("signBytes / verifyBytes round-trip", () => {
  const pair = generateKeyPair();
  const message = new TextEncoder().encode("hello pqc world");
  const signature = signBytes(pair.secretKey, message);
  assert.equal(verifyBytes(pair.publicKey, message, signature), true);
});

test("verifyBytes rejects a tampered message", () => {
  const pair = generateKeyPair();
  const message = new TextEncoder().encode("original");
  const signature = signBytes(pair.secretKey, message);
  const tampered = new TextEncoder().encode("original!");
  assert.equal(verifyBytes(pair.publicKey, tampered, signature), false);
});

test("verifyBytes returns false (not a throw) for a malformed-length signature", () => {
  const pair = generateKeyPair();
  const message = new TextEncoder().encode("hello");
  assert.equal(verifyBytes(pair.publicKey, message, new Uint8Array(10)), false);
});

test("verifyBytes rejects a signature made with a different key", () => {
  const a = generateKeyPair();
  const b = generateKeyPair();
  const message = new TextEncoder().encode("hello");
  const signature = signBytes(a.secretKey, message);
  assert.equal(verifyBytes(b.publicKey, message, signature), false);
});

test("buildSignatureFile / verifySignatureFile happy path", () => {
  const pair = generateKeyPair();
  const keyFile = toKeyFile(pair);
  const message = new TextEncoder().encode("release artifact bytes");

  const sig = buildSignatureFile(pair, keyFile.keyId, message);
  const result = verifySignatureFile(pair.publicKey, keyFile.keyId, message, sig);
  assert.deepEqual(result, { ok: true });
});

test("verifySignatureFile catches a modified message (digest mismatch)", () => {
  const pair = generateKeyPair();
  const keyFile = toKeyFile(pair);
  const message = new TextEncoder().encode("release artifact bytes");
  const sig = buildSignatureFile(pair, keyFile.keyId, message);

  const modified = new TextEncoder().encode("release artifact bytes, but different");
  const result = verifySignatureFile(pair.publicKey, keyFile.keyId, modified, sig);
  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /digest does not match/);
});

test("verifySignatureFile catches a keyId mismatch", () => {
  const pair = generateKeyPair();
  const keyFile = toKeyFile(pair);
  const message = new TextEncoder().encode("payload");
  const sig = buildSignatureFile(pair, keyFile.keyId, message);

  const result = verifySignatureFile(pair.publicKey, "sha256:" + "1".repeat(64), message, sig);
  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /keyId mismatch/);
});

test("verifySignatureFile catches an unsupported algorithm", () => {
  const pair = generateKeyPair();
  const keyFile = toKeyFile(pair);
  const message = new TextEncoder().encode("payload");
  const sig = buildSignatureFile(pair, keyFile.keyId, message);

  const result = verifySignatureFile(pair.publicKey, keyFile.keyId, message, {
    ...sig,
    algorithm: "ML-DSA-44" as typeof sig.algorithm,
  });
  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /unsupported algorithm/);
});

test("verifySignatureFile rejects a forged signature blob with a correct digest", () => {
  const pair = generateKeyPair();
  const other = generateKeyPair();
  const keyFile = toKeyFile(pair);
  const message = new TextEncoder().encode("payload");
  const sig = buildSignatureFile(pair, keyFile.keyId, message);

  // Attacker swaps in a signature produced by a different key, but keeps
  // the original digest/keyId fields intact.
  const forgedSig = signBytes(other.secretKey, message);
  const forged = { ...sig, signature: Buffer.from(forgedSig).toString("base64") };

  const result = verifySignatureFile(pair.publicKey, keyFile.keyId, message, forged);
  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /cryptographic signature check failed/);
});
