import { ml_kem768 } from "@noble/post-quantum/ml-kem";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { randomBytes } from "node:crypto";

export const KEM_ALGORITHM = "ML-KEM-768" as const;
export const KEM_KEY_SCHEMA = "pqc-forge.kem-key/v1" as const;

export interface KemKeyFile {
  schema: typeof KEM_KEY_SCHEMA;
  algorithm: typeof KEM_ALGORITHM;
  keyId: string;
  createdAt: string;
  publicKey: string; // base64
  /** Absent for a public-key-only export (see toKemPublicKeyFile) — such a file can encrypt but not decrypt. */
  secretKey?: string; // base64
}

export interface KemKeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

/** Same convention as signing keys: sha256 of the base64-encoded public key string. */
export function computeKemKeyId(publicKeyB64: string): string {
  const digest = sha256(Buffer.from(publicKeyB64, "utf8"));
  return `sha256:${bytesToHex(digest)}`;
}

export function generateKemKeyPair(seed?: Uint8Array): KemKeyPair {
  const s = seed ?? randomBytes(64);
  if (s.length !== 64) {
    throw new Error(`seed must be 64 bytes, got ${s.length}`);
  }
  return ml_kem768.keygen(s);
}

export function toKemKeyFile(pair: KemKeyPair, createdAt: Date = new Date()): KemKeyFile {
  const publicKey = Buffer.from(pair.publicKey).toString("base64");
  const secretKey = Buffer.from(pair.secretKey).toString("base64");
  return {
    schema: KEM_KEY_SCHEMA,
    algorithm: KEM_ALGORITHM,
    keyId: computeKemKeyId(publicKey),
    createdAt: createdAt.toISOString(),
    publicKey,
    secretKey,
  };
}

/** Strips the secret key so the result is safe to hand to someone else (they can encrypt to it, not decrypt). */
export function toKemPublicKeyFile(key: KemKeyFile): KemKeyFile {
  return {
    schema: key.schema,
    algorithm: key.algorithm,
    keyId: key.keyId,
    createdAt: key.createdAt,
    publicKey: key.publicKey,
  };
}

export function parseKemKeyFile(raw: string): KemKeyFile {
  const parsed = JSON.parse(raw) as KemKeyFile;
  if (parsed.schema !== KEM_KEY_SCHEMA) {
    throw new Error(`unexpected key schema: ${parsed.schema}`);
  }
  if (parsed.algorithm !== KEM_ALGORITHM) {
    throw new Error(`unsupported algorithm: ${parsed.algorithm}`);
  }
  const expectedKeyId = computeKemKeyId(parsed.publicKey);
  if (expectedKeyId !== parsed.keyId) {
    throw new Error(
      `keyId mismatch: file claims ${parsed.keyId}, computed ${expectedKeyId} (key file may be corrupt or tampered)`,
    );
  }
  return parsed;
}

/** Decodes the public key only — works for both full keypair files and public-only exports. */
export function kemKeyFileToPublicKey(key: KemKeyFile): Uint8Array {
  return Buffer.from(key.publicKey, "base64");
}

/** Decodes the full keypair. Throws if `key` is a public-only export (no secretKey). */
export function kemKeyFileToPair(key: KemKeyFile): KemKeyPair {
  if (!key.secretKey) {
    throw new Error(
      "this key file has no secret key (it looks like a public-key-only export) — it can encrypt but not decrypt",
    );
  }
  return {
    publicKey: kemKeyFileToPublicKey(key),
    secretKey: Buffer.from(key.secretKey, "base64"),
  };
}
