// Knock-out Phase 5: one signing pattern for the small signed inventory documents (endpoint inventory, certificate
// inventory). Same shape as every PQC Forge receipt (receiptDigest + ML-DSA-65 signature over it), so
// verify-receipt, POST /v1/verify-receipt and POST /v1/public/verify-report all check them unchanged.
import { createHash } from 'node:crypto';
import { canonicalJson } from './canonical.js';
import { signPayload } from './signing.js';
import { verifyReceipt } from './breaklab/receipt.js';

export function signDoc(doc, signingKey) {
  const receiptDigest = `sha256:${createHash('sha256').update(canonicalJson(doc)).digest('hex')}`;
  const withDigest = { ...doc, receiptDigest };
  return { ...withDigest, signature: signPayload(withDigest, signingKey) };
}

export function verifyDoc(doc, schema, label, trustedPublicKeys = null) {
  if (!doc || doc.schema !== schema) return { valid: false, errors: [`not a PQC Forge ${label}`] };
  return verifyReceipt(doc, { trustedPublicKeys });
}
