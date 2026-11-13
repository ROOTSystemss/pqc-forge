import { keyIdFor, SIGNATURE_ALGORITHM, validateSigningKey } from './signing.js';

// The signing key history (key survival), so a receipt signed before a key rotation still verifies
// afterwards. Same design as the other RootSystems products (Offboarding Proof's lib/keyHistory.js),
// with PQC Forge's own key ids (sha256:<hex of the base64 public key>).
//
// With one key the history is that key alone. After a rotation, set PQC_FORGE_KEY_HISTORY_JSON to
// { "format": "pqc-forge.keyring/v1", "keys": [ { keyId, publicKey, status: "active" | "retired",
// validFrom, validUntil } ] }: the new key "active", earlier keys "retired" with the date they stopped
// signing. It is used only when it is well formed, every keyId matches its public key, and its one
// active key is the key signing now; otherwise it is ignored and only the current key is trusted
// (fail closed: an unpublished key never verifies).

export const KEYRING_FORMAT = 'pqc-forge.keyring/v1';
const STATUSES = new Set(['active', 'retired']);
const isDate = (v) => v === null || v === undefined || !Number.isNaN(Date.parse(v));

export function wellFormedKeyring(ring) {
  if (!ring || ring.format !== KEYRING_FORMAT || !Array.isArray(ring.keys) || !ring.keys.length) return false;
  for (const k of ring.keys) {
    if (!k || typeof k.publicKey !== 'string' || !STATUSES.has(k.status) || !isDate(k.validFrom) || !isDate(k.validUntil)) return false;
    if (k.keyId !== keyIdFor(k.publicKey)) return false;
  }
  return ring.keys.filter((k) => k.status === 'active').length === 1;
}

const publicEntry = (k) => ({ keyId: k.keyId, algorithm: k.algorithm || SIGNATURE_ALGORITHM, publicKey: k.publicKey, status: k.status, validFrom: k.validFrom || null, validUntil: k.validUntil || null });

let warned = false;
export function keyHistory(currentKey, raw = process.env.PQC_FORGE_KEY_HISTORY_JSON) {
  validateSigningKey(currentKey);
  if (raw) {
    let ring = null;
    try { ring = JSON.parse(raw); } catch { /* reported below */ }
    if (wellFormedKeyring(ring) && ring.keys.find((k) => k.status === 'active').publicKey === currentKey.publicKey) {
      return { format: KEYRING_FORMAT, keys: ring.keys.map(publicEntry) };
    }
    if (!warned) { warned = true; console.warn('[keyHistory] PQC_FORGE_KEY_HISTORY_JSON ignored: it is not a well-formed keyring whose active key is the key signing now.'); }
  }
  return { format: KEYRING_FORMAT, keys: [publicEntry({ ...currentKey, status: 'active', validFrom: currentKey.createdAt || null, validUntil: null })] };
}
