import { createHash } from 'node:crypto';
import { VERSION } from '../version.js';

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
  return value;
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

export function createReceipt(run, scenario) {
  const scenarioDigest = createHash('sha256').update(canonicalJson(scenario)).digest('hex');
  const payload = {
    schema: 'pqc-forge.breaklab-receipt/v1', generatedAt: new Date().toISOString(),
    engine: { name: 'PQC Forge BreakLab', version: VERSION }, scenarioDigest: `sha256:${scenarioDigest}`, run
  };
  const receiptDigest = createHash('sha256').update(canonicalJson(payload)).digest('hex');
  return { ...payload, receiptDigest: `sha256:${receiptDigest}` };
}

export function createProtocolReceipt(run, matrix) {
  const matrixDigest = createHash('sha256').update(canonicalJson(matrix)).digest('hex');
  const payload = {
    schema: 'pqc-forge.protocol-lab-receipt/v1', generatedAt: new Date().toISOString(),
    engine: { name: 'PQC Forge Protocol Lab', version: VERSION }, matrixDigest: `sha256:${matrixDigest}`, run
  };
  const receiptDigest = createHash('sha256').update(canonicalJson(payload)).digest('hex');
  return { ...payload, receiptDigest: `sha256:${receiptDigest}` };
}

export function createMigrationReceipt(migration) {
  const payload = {
    schema: 'pqc-forge.migration-receipt/v1', generatedAt: new Date().toISOString(),
    engine: { name: 'PQC Forge Migrator', version: VERSION }, migration
  };
  const receiptDigest = createHash('sha256').update(canonicalJson(payload)).digest('hex');
  return { ...payload, receiptDigest: `sha256:${receiptDigest}` };
}

export function createPrPackReceipt(summary, artifacts) {
  const payload = {
    schema: 'pqc-forge.pr-pack-receipt/v1', generatedAt: new Date().toISOString(),
    engine: { name: 'PQC Forge PR Pack', version: VERSION }, summary, artifacts
  };
  const receiptDigest = createHash('sha256').update(canonicalJson(payload)).digest('hex');
  return { ...payload, receiptDigest: `sha256:${receiptDigest}` };
}

export function createValidationReceipt(manifest, run) {
  const manifestDigest = createHash('sha256').update(canonicalJson(manifest)).digest('hex');
  const payload = {
    schema: 'pqc-forge.validation-receipt/v1', generatedAt: new Date().toISOString(),
    engine: { name: 'PQC Forge Validation', version: VERSION }, manifestDigest: `sha256:${manifestDigest}`, run
  };
  const receiptDigest = createHash('sha256').update(canonicalJson(payload)).digest('hex');
  return { ...payload, receiptDigest: `sha256:${receiptDigest}` };
}

export function createReleaseReceipt(run) {
  const payload = {
    schema: 'pqc-forge.release-receipt/v1', generatedAt: new Date().toISOString(),
    engine: { name: 'PQC Forge Release Gate', version: VERSION }, run
  };
  const receiptDigest = createHash('sha256').update(canonicalJson(payload)).digest('hex');
  return { ...payload, receiptDigest: `sha256:${receiptDigest}` };
}

export function createRuntimeReceipt(probe) {
  const payload = {
    schema: 'pqc-forge.runtime-receipt/v1', generatedAt: new Date().toISOString(),
    engine: { name: 'PQC Forge Runtime Probe', version: VERSION }, probe: structuredClone(probe)
  };
  const receiptDigest = createHash('sha256').update(canonicalJson(payload)).digest('hex');
  return { ...payload, receiptDigest: `sha256:${receiptDigest}` };
}

export function createTlsReceipt(evidence) {
  const payload = {
    schema: 'pqc-forge.tls-receipt/v1', generatedAt: new Date().toISOString(),
    engine: { name: 'PQC Forge TLS Verifier', version: VERSION }, evidence: structuredClone(evidence)
  };
  const receiptDigest = createHash('sha256').update(canonicalJson(payload)).digest('hex');
  return { ...payload, receiptDigest: `sha256:${receiptDigest}` };
}

export function createStagingReceipt(run) {
  const payload = {
    schema: 'pqc-forge.staging-receipt/v1', generatedAt: new Date().toISOString(),
    engine: { name: 'PQC Forge Staging Gate', version: VERSION }, run: structuredClone(run)
  };
  const receiptDigest = createHash('sha256').update(canonicalJson(payload)).digest('hex');
  return { ...payload, receiptDigest: `sha256:${receiptDigest}` };
}

export function verifyReceipt(receipt) {
  const { receiptDigest, ...payload } = receipt;
  const actual = `sha256:${createHash('sha256').update(canonicalJson(payload)).digest('hex')}`;
  return { valid: actual === receiptDigest, expected: receiptDigest, actual };
}
