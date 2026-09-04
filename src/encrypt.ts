import { ml_kem768 } from "@noble/post-quantum/ml-kem";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { KEM_ALGORITHM, type KemKeyPair } from "./kem.js";

export const ENCRYPTED_SCHEMA = "pqc-forge.encrypted/v1" as const;
export const CIPHER_ALGORITHM = "AES-256-GCM" as const;
const HKDF_INFO = new TextEncoder().encode("pqc-forge encrypted-file v1");
const AES_KEY_LEN = 32;
const IV_LEN = 12; // GCM standard nonce size

export interface EncryptedFile {
  schema: typeof ENCRYPTED_SCHEMA;
  kemAlgorithm: typeof KEM_ALGORITHM;
  cipherAlgorithm: typeof CIPHER_ALGORITHM;
  keyId: string;
  createdAt: string;
  kemCiphertext: string; // base64, ML-KEM encapsulation ciphertext
  iv: string; // base64
  authTag: string; // base64
  ciphertext: string; // base64
}

/** Derives a 32-byte AES-256-GCM key from an ML-KEM shared secret via HKDF-SHA256. */
function deriveAesKey(sharedSecret: Uint8Array): Uint8Array {
  return hkdf(sha256, sharedSecret, undefined, HKDF_INFO, AES_KEY_LEN);
}

/**
 * Encrypts `plaintext` for the holder of `recipientPublicKey`: an ML-KEM-768
 * encapsulation establishes a shared secret, HKDF-SHA256 derives an
 * AES-256-GCM key from it, and that key encrypts the plaintext.
 */
export function encryptForRecipient(
  recipientPublicKey: Uint8Array,
  recipientKeyId: string,
  plaintext: Uint8Array,
  createdAt: Date = new Date(),
): EncryptedFile {
  const { cipherText: kemCiphertext, sharedSecret } = ml_kem768.encapsulate(recipientPublicKey);
  const aesKey = Buffer.from(deriveAesKey(sharedSecret));
  const iv = randomBytes(IV_LEN);

  const cipher = createCipheriv("aes-256-gcm", aesKey, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    schema: ENCRYPTED_SCHEMA,
    kemAlgorithm: KEM_ALGORITHM,
    cipherAlgorithm: CIPHER_ALGORITHM,
    keyId: recipientKeyId,
    createdAt: createdAt.toISOString(),
    kemCiphertext: Buffer.from(kemCiphertext).toString("base64"),
    iv: iv.toString("base64"),
    authTag: authTag.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
  };
}

export interface DecryptResult {
  ok: true;
  plaintext: Buffer;
}

export interface DecryptFailure {
  ok: false;
  reason: string;
}

/** Decrypts an `EncryptedFile` using the matching ML-KEM secret key. */
export function decryptWithKey(
  pair: Pick<KemKeyPair, "secretKey">,
  expectedKeyId: string,
  file: EncryptedFile,
): DecryptResult | DecryptFailure {
  if (file.schema !== ENCRYPTED_SCHEMA) {
    return { ok: false, reason: `unexpected schema: ${file.schema}` };
  }
  if (file.kemAlgorithm !== KEM_ALGORITHM) {
    return { ok: false, reason: `unsupported KEM algorithm: ${file.kemAlgorithm}` };
  }
  if (file.cipherAlgorithm !== CIPHER_ALGORITHM) {
    return { ok: false, reason: `unsupported cipher algorithm: ${file.cipherAlgorithm}` };
  }
  if (file.keyId !== expectedKeyId) {
    return {
      ok: false,
      reason: `keyId mismatch: file was encrypted for ${file.keyId}, this key is ${expectedKeyId}`,
    };
  }

  const kemCiphertext = Buffer.from(file.kemCiphertext, "base64");
  let sharedSecret: Uint8Array;
  try {
    sharedSecret = ml_kem768.decapsulate(kemCiphertext, pair.secretKey);
  } catch (err) {
    return { ok: false, reason: `KEM decapsulation failed: ${(err as Error).message}` };
  }
  const aesKey = Buffer.from(deriveAesKey(sharedSecret));
  const iv = Buffer.from(file.iv, "base64");
  const authTag = Buffer.from(file.authTag, "base64");
  const ciphertext = Buffer.from(file.ciphertext, "base64");

  try {
    const decipher = createDecipheriv("aes-256-gcm", aesKey, iv);
    decipher.setAuthTag(authTag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return { ok: true, plaintext };
  } catch {
    // Wrong key, or the ciphertext/authTag was tampered with — AES-GCM
    // authentication failure surfaces as a generic decipher error.
    return { ok: false, reason: "decryption failed: wrong key or corrupted/tampered ciphertext" };
  }
}
