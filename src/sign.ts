import { ml_dsa65 } from "@noble/post-quantum/ml-dsa";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import type { KeyPair } from "./keys.js";
import { ALGORITHM } from "./keys.js";

export const SIGNATURE_SCHEMA = "pqc-forge.signature/v1" as const;

export interface SignatureFile {
  schema: typeof SIGNATURE_SCHEMA;
  algorithm: typeof ALGORITHM;
  keyId: string;
  createdAt: string;
  digestAlgorithm: "sha256";
  digest: string; // hex sha256 of the signed message bytes
  signature: string; // base64
}

/** Signs raw message bytes with an ML-DSA-65 secret key. */
export function signBytes(secretKey: Uint8Array, message: Uint8Array): Uint8Array {
  return ml_dsa65.sign(secretKey, message);
}

/** Verifies an ML-DSA-65 signature against a public key and message bytes. */
export function verifyBytes(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  return ml_dsa65.verify(publicKey, message, signature);
}

export function buildSignatureFile(
  pair: Pick<KeyPair, "secretKey">,
  keyId: string,
  message: Uint8Array,
  createdAt: Date = new Date(),
): SignatureFile {
  const signature = signBytes(pair.secretKey, message);
  return {
    schema: SIGNATURE_SCHEMA,
    algorithm: ALGORITHM,
    keyId,
    createdAt: createdAt.toISOString(),
    digestAlgorithm: "sha256",
    digest: bytesToHex(sha256(message)),
    signature: Buffer.from(signature).toString("base64"),
  };
}

export interface VerifyResult {
  ok: boolean;
  reason?: string;
}

export function verifySignatureFile(
  publicKey: Uint8Array,
  expectedKeyId: string,
  message: Uint8Array,
  sig: SignatureFile,
): VerifyResult {
  if (sig.algorithm !== ALGORITHM) {
    return { ok: false, reason: `unsupported algorithm: ${sig.algorithm}` };
  }
  if (sig.keyId !== expectedKeyId) {
    return { ok: false, reason: `keyId mismatch: signature was made with ${sig.keyId}, expected ${expectedKeyId}` };
  }
  const digest = bytesToHex(sha256(message));
  if (digest !== sig.digest) {
    return { ok: false, reason: "message digest does not match signature (file was modified)" };
  }
  const signature = Buffer.from(sig.signature, "base64");
  const ok = verifyBytes(publicKey, message, signature);
  return ok ? { ok: true } : { ok: false, reason: "cryptographic signature check failed" };
}
