import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { createHash, randomBytes } from 'node:crypto';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { canonicalJson } from './canonical.js';

// FIPS 204 ML-DSA-65 (Module-Lattice-Based Digital Signature Algorithm, security
// category 3). PQC Forge does not implement this primitive itself: it calls the
// audited @noble/post-quantum implementation, consistent with the project's
// standing rule that it never rolls its own cryptography.
export const SIGNATURE_ALGORITHM = 'ML-DSA-65';
export const SIGNING_KEY_SCHEMA = 'pqc-forge.signing-key/v1';
export const SIGNING_PUBLIC_KEY_SCHEMA = 'pqc-forge.signing-public-key/v1';

function toBase64(bytes) {
  return Buffer.from(bytes).toString('base64');
}

function fromBase64(value) {
  return new Uint8Array(Buffer.from(value, 'base64'));
}

export function keyIdFor(publicKeyBase64) {
  return `sha256:${createHash('sha256').update(publicKeyBase64).digest('hex')}`;
}

/**
 * Generate a new ML-DSA-65 keypair. Pure and synchronous: callers decide
 * whether/where to persist it.
 */
export function generateSigningKey() {
  const seed = randomBytes(32);
  const { publicKey, secretKey } = ml_dsa65.keygen(seed);
  const publicKeyBase64 = toBase64(publicKey);
  return {
    schema: SIGNING_KEY_SCHEMA,
    algorithm: SIGNATURE_ALGORITHM,
    keyId: keyIdFor(publicKeyBase64),
    createdAt: new Date().toISOString(),
    publicKey: publicKeyBase64,
    secretKey: toBase64(secretKey)
  };
}

export function publicKeyDocument(key) {
  validateSigningKey(key);
  return {
    schema: SIGNING_PUBLIC_KEY_SCHEMA,
    algorithm: key.algorithm,
    keyId: key.keyId,
    createdAt: key.createdAt,
    publicKey: key.publicKey
  };
}

export function validateSigningKey(key) {
  if (!key || key.schema !== SIGNING_KEY_SCHEMA || key.algorithm !== SIGNATURE_ALGORITHM || typeof key.publicKey !== 'string' || typeof key.secretKey !== 'string') {
    throw new Error('Invalid or missing PQC Forge ML-DSA signing key. Run `pqc-forge keygen` to create one.');
  }
  if (key.keyId !== keyIdFor(key.publicKey)) {
    throw new Error('Signing key keyId does not match its publicKey; the key file is corrupt or was hand-edited.');
  }
}

function defaultKeyDirectory() {
  return process.env.PQC_FORGE_HOME || path.join(os.homedir(), '.pqc-forge');
}

function defaultKeyPath() {
  return path.join(defaultKeyDirectory(), 'signing-key.json');
}

/**
 * Resolve the signing key to use.
 *
 * Precedence: explicit `keyPath` argument, then PQC_FORGE_SIGNING_KEY, then an
 * auto-provisioned identity at PQC_FORGE_HOME (or ~/.pqc-forge) which is
 * created once and reused on every later call. Auto-provisioning exists so
 * the CLI keeps working with zero setup; any deployment that needs an
 * organization-managed identity should set one of the two explicit paths.
 */
export async function loadSigningKey(keyPath) {
  const explicit = keyPath || process.env.PQC_FORGE_SIGNING_KEY || null;
  if (explicit) {
    const resolved = path.resolve(explicit);
    let raw;
    try {
      raw = await fs.readFile(resolved, 'utf8');
    } catch (error) {
      if (error.code === 'ENOENT') throw new Error(`Signing key not found: ${resolved}. Run \`pqc-forge keygen --out <directory>\` first.`);
      throw error;
    }
    const key = JSON.parse(raw);
    validateSigningKey(key);
    return { key, path: resolved, autoProvisioned: false };
  }
  const fallback = defaultKeyPath();
  try {
    const key = JSON.parse(await fs.readFile(fallback, 'utf8'));
    validateSigningKey(key);
    return { key, path: fallback, autoProvisioned: false };
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  const key = generateSigningKey();
  await fs.mkdir(path.dirname(fallback), { recursive: true });
  await fs.writeFile(fallback, `${JSON.stringify(key, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  try {
    await fs.chmod(fallback, 0o600);
  } catch {
    // Best-effort on platforms without POSIX permission bits (e.g. FAT volumes).
  }
  return { key, path: fallback, autoProvisioned: true };
}

/**
 * Sign an already-digested receipt payload (the full receipt object minus its
 * own `signature` field). Returns the signature block to attach.
 */
export function signPayload(payload, key) {
  validateSigningKey(key);
  const message = new TextEncoder().encode(canonicalJson(payload));
  const signatureBytes = ml_dsa65.sign(message, fromBase64(key.secretKey));
  return {
    algorithm: SIGNATURE_ALGORITHM,
    keyId: key.keyId,
    publicKey: key.publicKey,
    value: toBase64(signatureBytes)
  };
}

/**
 * Verify a signature block against the payload it was supposedly produced
 * over. Never throws: any malformed input is simply not a valid signature.
 */
export function verifySignature(payload, signature) {
  if (!signature || typeof signature !== 'object') return false;
  if (signature.algorithm !== SIGNATURE_ALGORITHM) return false;
  if (typeof signature.publicKey !== 'string' || typeof signature.value !== 'string' || typeof signature.keyId !== 'string') return false;
  if (signature.keyId !== keyIdFor(signature.publicKey)) return false;
  try {
    const message = new TextEncoder().encode(canonicalJson(payload));
    return ml_dsa65.verify(fromBase64(signature.value), message, fromBase64(signature.publicKey));
  } catch {
    return false;
  }
}
