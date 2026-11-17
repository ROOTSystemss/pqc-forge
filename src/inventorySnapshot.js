// AD-071 (knock-out Phase 5): signed point-in-time cryptography inventory for auditors. It is the inventory the
// scanner found in the uploaded files at one moment (static analysis only), not a readiness verdict: no score, no
// stage, no advice. Signed like every other PQC Forge receipt (receiptDigest + ML-DSA-65 signature over it), so
// verify-receipt, POST /v1/verify-receipt and POST /v1/public/verify-report all check it unchanged.
import { createHash } from 'node:crypto';
import { canonicalJson } from './canonical.js';
import { signPayload } from './signing.js';
import { verifyReceipt } from './breaklab/receipt.js';
import { scanToCbom } from './cbom.js';

export const SNAPSHOT_SCHEMA = 'pqc-forge.inventory-snapshot/v1';
const slash = (p) => String(p || '').split('\\').join('/');

export function buildInventorySnapshot({ label, scan, dependencies = null, now = new Date() }) {
  if (!scan) throw new Error('An inventory snapshot needs a scanned workspace.');
  const findings = (scan.findings || []).slice(0, 5000).map((f) => ({ id: f.id, category: f.category, severity: f.severity, file: slash(f.file), line: f.line, ...(f.language ? { language: f.language } : {}), ...(f.algorithm ? { algorithm: f.algorithm } : {}) }));
  const count = (key) => findings.reduce((m, f) => ((m[f[key]] = (m[f[key]] || 0) + 1), m), {});
  const unreadable = (scan.unreadableFiles || []).map(slash);
  return {
    schema: SNAPSHOT_SCHEMA,
    generatedAt: new Date(now).toISOString(),
    label: String(label || 'Inventory snapshot').slice(0, 120),
    scope: {
      filesScanned: scan.filesScanned || 0,
      unreadableFiles: unreadable,
      note: 'Point-in-time inventory of cryptography found by static analysis of the uploaded files only. It is not a readiness verdict and does not cover other repositories, devices, vendors, HSMs or managed cloud services. Files that could not be read are listed and were not checked.',
    },
    summary: { findings: findings.length, bySeverity: count('severity'), byCategory: count('category') },
    inventory: findings,
    cbom: scanToCbom(scan),
    // AD-070: declared cryptography libraries (manifests only), inside the signed snapshot when provided.
    ...(dependencies ? { dependencies } : {}),
  };
}

export function signSnapshot(snapshot, signingKey) {
  const receiptDigest = `sha256:${createHash('sha256').update(canonicalJson(snapshot)).digest('hex')}`;
  const withDigest = { ...snapshot, receiptDigest };
  return { ...withDigest, signature: signPayload(withDigest, signingKey) };
}

export function verifySnapshot(doc, trustedPublicKeys = null) {
  if (!doc || doc.schema !== SNAPSHOT_SCHEMA) return { valid: false, errors: ['not a PQC Forge inventory snapshot'] };
  return verifyReceipt(doc, { trustedPublicKeys });
}
