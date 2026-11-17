// AD-066 (knock-out Phase 5): certificate inventory and expiry. Certificates come from (a) the public endpoints the
// customer lists (the certificate each one presents in one ordinary TLS 1.3 handshake) and/or (b) certificate files
// (.pem/.crt/.cer) in an uploaded workspace. For each: subject, issuer, valid-from/to, days left, public key and
// signature algorithm, and whether the algorithm is post-quantum or classical. Three-state: a certificate that could
// not be read (endpoint unreachable, file unparsable) is Not verified, never counted as valid. Private-key blocks are
// NEVER read or stored: a file that contains one is listed by name only, as a warning. Signed like every receipt.
import { X509Certificate } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { signDoc, verifyDoc } from './signedDoc.js';

export const CERT_INVENTORY_SCHEMA = 'pqc-forge.certificate-inventory/v1';
export const EXPIRY_WARNING_DAYS = 30;
const CERT_EXT = /\.(pem|crt|cer)$/i;
const MAX_FILES = 500, MAX_BYTES = 1024 * 1024;
const PQ = /ML-?DSA|SLH-?DSA|DILITHIUM|SPHINCS|FALCON/i;
const CLASSICAL = /RSA|EC|ECDSA|ED25519|ED448|DSA|SECP|PRIME256|P-256|P-384/i;

const classOf = (...parts) => {
  const s = parts.filter(Boolean).join(' ');
  if (PQ.test(s)) return 'post-quantum';
  if (CLASSICAL.test(s)) return 'classical';
  return 'unknown';
};

function expiry(validTo, now) {
  const days = Math.floor((new Date(validTo).getTime() - now.getTime()) / 86400000);
  return { daysLeft: days, expiry: days < 0 ? 'expired' : days <= EXPIRY_WARNING_DAYS ? `expires within ${EXPIRY_WARNING_DAYS} days` : 'valid' };
}

export function rowFromFacts(source, facts, signatureAlgorithm, now) {
  if (!facts || !facts.validTo) return { source, state: 'not-verified', status: 'Not verified (no certificate could be read)' };
  return {
    source, state: 'read',
    subject: facts.subject, issuer: facts.issuer, validFrom: facts.validFrom, validTo: facts.validTo,
    fingerprint256: facts.fingerprint256, publicKey: facts.publicKey, signatureAlgorithm: signatureAlgorithm || 'unknown',
    algorithmClass: classOf(facts.publicKey, signatureAlgorithm),
    ...expiry(facts.validTo, now),
  };
}

export function certsFromPemText(text) {
  const blocks = String(text).match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [];
  return blocks.map((pem) => {
    try {
      const x = new X509Certificate(pem);
      const k = x.publicKey;
      const d = k.asymmetricKeyDetails || {};
      const keyType = String(k.asymmetricKeyType || 'unknown').toUpperCase();
      const publicKey = d.modulusLength ? `${keyType} ${d.modulusLength}` : d.namedCurve ? `${keyType} ${d.namedCurve}` : keyType;
      const cn = (dn) => ((String(dn || '').match(/CN=([^\n,]+)/) || [])[1] || null);
      return { ok: true, facts: { subject: cn(x.subject), issuer: cn(x.issuer), validFrom: x.validFromDate ? x.validFromDate.toISOString() : new Date(x.validFrom).toISOString(), validTo: x.validToDate ? x.validToDate.toISOString() : new Date(x.validTo).toISOString(), fingerprint256: x.fingerprint256, publicKey }, signatureAlgorithm: x.signatureAlgorithm || null };
    } catch (error) {
      return { ok: false, error: String(error.message || error).slice(0, 120) };
    }
  });
}

export async function readWorkspaceCertificates(root) {
  const out = { files: [], unreadable: [], privateKeyFiles: [] };
  const walk = async (dir) => {
    let entries = [];
    try { entries = await fs.readdir(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (out.files.length >= MAX_FILES) return;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) { if (e.name !== '.git' && e.name !== 'node_modules') await walk(full); continue; }
      if (!CERT_EXT.test(e.name)) continue;
      const rel = path.relative(root, full).split(path.sep).join('/');
      try {
        const st = await fs.stat(full);
        if (st.size > MAX_BYTES) { out.unreadable.push(rel); continue; }
        const text = await fs.readFile(full, 'utf8');
        if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(text)) out.privateKeyFiles.push(rel); // listed by name only
        const certs = certsFromPemText(text);
        if (!certs.length) { if (!out.privateKeyFiles.includes(rel)) out.unreadable.push(rel); continue; }
        certs.forEach((c, i) => out.files.push({ source: `file:${rel}${certs.length > 1 ? `#${i + 1}` : ''}`, ...c }));
      } catch { out.unreadable.push(rel); }
    }
  };
  await walk(root);
  return out;
}

export function buildCertificateInventory({ label, endpoints = [], workspace = null, now = new Date() }) {
  const at = new Date(now);
  const rows = [];
  for (const e of endpoints) {
    if (!e.ok) rows.push({ source: `endpoint:${e.target}`, state: 'not-verified', status: 'Not verified (endpoint not reachable or no TLS 1.3 handshake)' });
    else rows.push(rowFromFacts(`endpoint:${e.target}`, e.evidence.certificate, e.evidence.peerSignatureAlgorithm, at));
  }
  if (workspace) {
    for (const f of workspace.files) rows.push(f.ok ? rowFromFacts(f.source, f.facts, f.signatureAlgorithm, at) : { source: f.source, state: 'not-verified', status: 'Not verified (certificate could not be parsed)' });
    for (const u of workspace.unreadable) rows.push({ source: `file:${u}`, state: 'not-verified', status: 'Not verified (file could not be read)' });
  }
  if (!rows.length) throw new Error('No certificate found: list an endpoint or upload certificate files (.pem, .crt, .cer).');
  const read = rows.filter((r) => r.state === 'read');
  const n = (fn) => read.filter(fn).length;
  return {
    schema: CERT_INVENTORY_SCHEMA,
    generatedAt: at.toISOString(),
    label: String(label || 'Certificate inventory').slice(0, 120),
    scope: {
      sources: { endpoints: endpoints.length, workspaceFiles: workspace ? workspace.files.length + workspace.unreadable.length : 0 },
      note: `Certificates presented by the endpoints you listed and certificate files in the uploaded workspace only, at the moment shown. Expiring means within ${EXPIRY_WARNING_DAYS} days. Anything that could not be read is Not verified and is not counted as valid. Private-key files are never read: they are listed by name only.`,
      privateKeyFilesFound: workspace ? workspace.privateKeyFiles : [],
    },
    summary: {
      certificates: rows.length, read: read.length, notVerified: rows.length - read.length,
      expired: n((r) => r.expiry === 'expired'), expiringSoon: n((r) => r.expiry.startsWith('expires within')),
      postQuantum: n((r) => r.algorithmClass === 'post-quantum'), classical: n((r) => r.algorithmClass === 'classical'),
    },
    certificates: rows,
  };
}

export const signCertificateInventory = signDoc;
export const verifyCertificateInventory = (doc, keys = null) => verifyDoc(doc, CERT_INVENTORY_SCHEMA, 'certificate inventory', keys);
