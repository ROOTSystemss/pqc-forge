import { ml_dsa65 } from "@noble/post-quantum/ml-dsa";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { randomBytes } from "node:crypto";

export const ALGORITHM = "ML-DSA-65" as const;
export const KEY_SCHEMA = "pqc-forge.signing-key/v1" as const;

export interface SigningKeyFile {
  schema: typeof KEY_SCHEMA;
  algorithm: typeof ALGORITHM;
  keyId: string;
  createdAt: string;
  publicKey: string; // base64
  secretKey: string; // base64
}

export interface KeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

/** keyId is sha256 of the base64-encoded public key string, matching the existing pqc-forge key format. */
export function computeKeyId(publicKeyB64: string): string {
  const digest = sha256(Buffer.from(publicKeyB64, "utf8"));
  return `sha256:${bytesToHex(digest)}`;
}

export function generateKeyPair(seed?: Uint8Array): KeyPair {
  const s = seed ?? randomBytes(32);
  if (s.length !== 32) {
    throw new Error(`seed must be 32 bytes, got ${s.length}`);
  }
  return ml_dsa65.keygen(s);
}

export function toKeyFile(pair: KeyPair, createdAt: Date = new Date()): SigningKeyFile {
  const publicKey = Buffer.from(pair.publicKey).toString("base64");
  const secretKey = Buffer.from(pair.secretKey).toString("base64");
  return {
    schema: KEY_SCHEMA,
    algorithm: ALGORITHM,
    keyId: computeKeyId(publicKey),
    createdAt: createdAt.toISOString(),
    publicKey,
    secretKey,
  };
}

export function parseKeyFile(raw: string): SigningKeyFile {
  const parsed = JSON.parse(raw) as SigningKeyFile;
  if (parsed.schema !== KEY_SCHEMA) {
    throw new Error(`unexpected key schema: ${parsed.schema}`);
  }
  if (parsed.algorithm !== ALGORITHM) {
    throw new Error(`unsupported algorithm: ${parsed.algorithm}`);
  }
  const expectedKeyId = computeKeyId(parsed.publicKey);
  if (expectedKeyId !== parsed.keyId) {
    throw new Error(
      `keyId mismatch: file claims ${parsed.keyId}, computed ${expectedKeyId} (key file may be corrupt or tampered)`,
    );
  }
  return parsed;
}

export function keyFileToPair(key: SigningKeyFile): KeyPair {
  return {
    publicKey: Buffer.from(key.publicKey, "base64"),
    secretKey: Buffer.from(key.secretKey, "base64"),
  };
}
