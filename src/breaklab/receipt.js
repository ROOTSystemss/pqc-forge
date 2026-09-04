import { createHash } from 'node:crypto';
import { VERSION } from '../version.js';
import { canonicalJson } from '../canonical.js';
import { signPayload, validateSigningKey, verifySignature } from '../signing.js';

export { canonicalJson };

function requireKey(key, schema) {
  if (!key) throw new Error(`An ML-DSA signing key is required to create a ${schema} receipt. Run \`pqc-forge keygen\` or pass --signing-key.`);
  validateSigningKey(key);
}

function seal(payload, key, schema) {
  requireKey(key, schema);
  const receiptDigest = `sha256:${createHash('sha256').update(canonicalJson(payload)).digest('hex')}`;
  const withDigest = { ...payload, receiptDigest };
  const signature = signPayload(withDigest, key);
  return { ...withDigest, signature };
}

export function createReceipt(run, scenario, key) {
  const scenarioDigest = createHash('sha256').update(canonicalJson(scenario)).digest('hex');
  const payload = {
    schema: 'pqc-forge.breaklab-receipt/v1', generatedAt: new Date().toISOString(),
    engine: { name: 'PQC Forge BreakLab', version: VERSION }, scenarioDigest: `sha256:${scenarioDigest}`, run
  };
  return seal(payload, key, payload.schema);
}

export function createProtocolReceipt(run, matrix, key) {
  const matrixDigest = createHash('sha256').update(canonicalJson(matrix)).digest('hex');
  const payload = {
    schema: 'pqc-forge.protocol-lab-receipt/v1', generatedAt: new Date().toISOString(),
    engine: { name: 'PQC Forge Protocol Lab', version: VERSION }, matrixDigest: `sha256:${matrixDigest}`, run
  };
  return seal(payload, key, payload.schema);
}

export function createMigrationReceipt(migration, key) {
  const payload = {
    schema: 'pqc-forge.migration-receipt/v1', generatedAt: new Date().toISOString(),
    engine: { name: 'PQC Forge Migrator', version: VERSION }, migration
  };
  return seal(payload, key, payload.schema);
}

export function createPrPackReceipt(summary, artifacts, key) {
  const payload = {
    schema: 'pqc-forge.pr-pack-receipt/v1', generatedAt: new Date().toISOString(),
    engine: { name: 'PQC Forge PR Pack', version: VERSION }, summary, artifacts
  };
  return seal(payload, key, payload.schema);
}

export function createValidationReceipt(manifest, run, key) {
  const manifestDigest = createHash('sha256').update(canonicalJson(manifest)).digest('hex');
  const payload = {
    schema: 'pqc-forge.validation-receipt/v1', generatedAt: new Date().toISOString(),
    engine: { name: 'PQC Forge Validation', version: VERSION }, manifestDigest: `sha256:${manifestDigest}`, run
  };
  return seal(payload, key, payload.schema);
}

export function createReleaseReceipt(run, key) {
  const payload = {
    schema: 'pqc-forge.release-receipt/v1', generatedAt: new Date().toISOString(),
    engine: { name: 'PQC Forge Release Gate', version: VERSION }, run
  };
  return seal(payload, key, payload.schema);
}

export function createRuntimeReceipt(probe, key) {
  const payload = {
    schema: 'pqc-forge.runtime-receipt/v1', generatedAt: new Date().toISOString(),
    engine: { name: 'PQC Forge Runtime Probe', version: VERSION }, probe: structuredClone(probe)
  };
  return seal(payload, key, payload.schema);
}

export function createTlsReceipt(evidence, key) {
  const payload = {
    schema: 'pqc-forge.tls-receipt/v1', generatedAt: new Date().toISOString(),
    engine: { name: 'PQC Forge TLS Verifier', version: VERSION }, evidence: structuredClone(evidence)
  };
  return seal(payload, key, payload.schema);
}

export function createStagingReceipt(run, key) {
  const payload = {
    schema: 'pqc-forge.staging-receipt/v1', generatedAt: new Date().toISOString(),
    engine: { name: 'PQC Forge Staging Gate', version: VERSION }, run: structuredClone(run)
  };
  return seal(payload, key, payload.schema);
}

/**
 * Verify a receipt's SHA-256 digest and ML-DSA signature.
 *
 * `valid` is true only when the digest matches, a signature is present, that
 * signature verifies against its own embedded public key, AND — if
 * `trustedPublicKeys` is supplied — that public key is one of the caller's
 * trusted signers. A receipt with a missing or invalid signature is always
 * invalid; there is no way to opt back into hash-only trust.
 */
export function verifyReceipt(receipt, { trustedPublicKeys = null } = {}) {
  const errors = [];
  const { signature, ...withDigest } = receipt ?? {};
  const { receiptDigest, ...payload } = withDigest;
  const actual = `sha256:${createHash('sha256').update(canonicalJson(payload)).digest('hex')}`;
  const digestValid = actual === receiptDigest;
  if (!digestValid) errors.push('digest-mismatch');

  const signaturePresent = Boolean(signature);
  if (!signaturePresent) errors.push('signature-missing');

  let signatureValid = false;
  if (signaturePresent) {
    signatureValid = verifySignature(withDigest, signature);
    if (!signatureValid) errors.push('signature-invalid');
  }

  let keyTrusted = null;
  if (trustedPublicKeys) {
    const trustedSet = new Set(trustedPublicKeys.map((entry) => (typeof entry === 'string' ? entry : entry?.publicKey)));
    keyTrusted = signaturePresent && trustedSet.has(signature.publicKey);
    if (!keyTrusted) errors.push('signer-not-trusted');
  }

  const valid = digestValid && signaturePresent && signatureValid && (trustedPublicKeys ? keyTrusted : true);
  return {
    valid, digestValid, signaturePresent, signatureValid, keyTrusted,
    expected: receiptDigest, actual,
    keyId: signature?.keyId ?? null,
    errors
  };
}
