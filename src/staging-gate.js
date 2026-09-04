import { promises as fs } from 'node:fs';
import path from 'node:path';
import { createStagingReceipt, verifyReceipt } from './breaklab/receipt.js';

function finite(value) {
  return typeof value === 'number' && Number.isFinite(value);
}

function check(name, pass, observed, requirement) {
  return { name, pass: Boolean(pass), observed, requirement };
}

function requireNumber(object, name, { min = 0, exclusiveMin = false } = {}) {
  const value = object?.[name];
  if (!finite(value) || (exclusiveMin ? value <= min : value < min)) {
    throw new Error(`${name} must be a finite number ${exclusiveMin ? 'greater than' : 'at least'} ${min}.`);
  }
  return value;
}

export function evaluateStagingGate(manifest, { runtimeReceipts, endpointReceipts }) {
  if (manifest?.schema !== 'pqc-forge.staging-manifest/v1') throw new Error('Unsupported staging manifest schema.');
  if (!manifest.target || typeof manifest.target !== 'string') throw new Error('Staging manifest requires a target name.');
  if (!Array.isArray(manifest.runtimeReceipts) || manifest.runtimeReceipts.length === 0) throw new Error('At least one runtime receipt is required.');
  if (!Array.isArray(manifest.endpointReceipts) || manifest.endpointReceipts.length === 0) throw new Error('At least one endpoint receipt is required.');
  if (runtimeReceipts.length !== manifest.runtimeReceipts.length || endpointReceipts.length !== manifest.endpointReceipts.length) throw new Error('Loaded receipt count does not match the manifest.');

  const metrics = manifest.metrics ?? {};
  const thresholds = manifest.thresholds ?? {};
  const handshakeErrorRatePct = requireNumber(metrics, 'handshakeErrorRatePct');
  const p95HandshakeLatencyMs = requireNumber(metrics, 'p95HandshakeLatencyMs');
  const cpuIncreasePct = requireNumber(metrics, 'cpuIncreasePct');
  const memoryIncreasePct = requireNumber(metrics, 'memoryIncreasePct');
  const soakMinutes = requireNumber(metrics, 'soakMinutes');
  const maxHandshakeErrorRatePct = requireNumber(thresholds, 'maxHandshakeErrorRatePct');
  const maxP95HandshakeLatencyMs = requireNumber(thresholds, 'maxP95HandshakeLatencyMs', { exclusiveMin: true });
  const maxCpuIncreasePct = requireNumber(thresholds, 'maxCpuIncreasePct');
  const maxMemoryIncreasePct = requireNumber(thresholds, 'maxMemoryIncreasePct');
  const minSoakMinutes = requireNumber(thresholds, 'minSoakMinutes', { exclusiveMin: true });
  const rollbackRecoverySeconds = requireNumber(manifest.rollback, 'recoverySeconds');
  const maxRollbackRecoverySeconds = requireNumber(manifest.rollback, 'maxRecoverySeconds', { exclusiveMin: true });
  const canaryTrafficPercent = requireNumber(manifest.canary, 'trafficPercent', { exclusiveMin: true });

  const checks = [];
  for (const [index, receipt] of runtimeReceipts.entries()) {
    checks.push(check(`runtimeReceipt[${index}]`, receipt.schema === 'pqc-forge.runtime-receipt/v1' && receipt.probe?.verdict?.pass === true, receipt.probe?.verdict?.pass ?? null, 'valid passing runtime receipt'));
  }
  for (const [index, receipt] of endpointReceipts.entries()) {
    const requiresAuthentication = manifest.requirePqAuthentication === true;
    const evidence = receipt.evidence ?? {};
    const pass = receipt.schema === 'pqc-forge.tls-receipt/v1'
      && evidence.authorized === true
      && evidence.verdict?.pqKeyExchange === true
      && (!requiresAuthentication || evidence.verdict?.pqAuthentication === true);
    checks.push(check(`endpointReceipt[${index}]`, pass, evidence.verdict?.status ?? null, requiresAuthentication ? 'authorized PQ key exchange and PQ authentication' : 'authorized PQ key exchange'));
  }
  checks.push(check('handshakeErrorRatePct', handshakeErrorRatePct <= maxHandshakeErrorRatePct, handshakeErrorRatePct, `<= ${maxHandshakeErrorRatePct}`));
  checks.push(check('p95HandshakeLatencyMs', p95HandshakeLatencyMs <= maxP95HandshakeLatencyMs, p95HandshakeLatencyMs, `<= ${maxP95HandshakeLatencyMs}`));
  checks.push(check('cpuIncreasePct', cpuIncreasePct <= maxCpuIncreasePct, cpuIncreasePct, `<= ${maxCpuIncreasePct}`));
  checks.push(check('memoryIncreasePct', memoryIncreasePct <= maxMemoryIncreasePct, memoryIncreasePct, `<= ${maxMemoryIncreasePct}`));
  checks.push(check('soakMinutes', soakMinutes >= minSoakMinutes, soakMinutes, `>= ${minSoakMinutes}`));
  checks.push(check('rollbackTested', manifest.rollback.tested === true, manifest.rollback.tested ?? false, 'true'));
  checks.push(check('rollbackRecoverySeconds', rollbackRecoverySeconds <= maxRollbackRecoverySeconds, rollbackRecoverySeconds, `<= ${maxRollbackRecoverySeconds}`));
  checks.push(check('monitoringConfigured', manifest.canary.monitoringConfigured === true, manifest.canary.monitoringConfigured ?? false, 'true'));
  checks.push(check('rollbackTriggersConfigured', manifest.canary.rollbackTriggersConfigured === true, manifest.canary.rollbackTriggersConfigured ?? false, 'true'));
  checks.push(check('canaryTrafficPercent', canaryTrafficPercent <= 10, canaryTrafficPercent, '<= 10'));
  checks.push(check('operatorApprovalRecorded', manifest.operatorApproval?.approved === true && typeof manifest.operatorApproval?.approvedBy === 'string' && manifest.operatorApproval.approvedBy.trim().length > 0, manifest.operatorApproval?.approved ?? false, 'approved=true with approvedBy'));

  const failures = checks.filter((item) => !item.pass).map((item) => item.name);
  return {
    schema: 'pqc-forge.staging-run/v1',
    target: manifest.target,
    evaluatedAt: new Date().toISOString(),
    checks,
    evidence: {
      runtimeReceiptDigests: runtimeReceipts.map((item) => item.receiptDigest),
      endpointReceiptDigests: endpointReceipts.map((item) => item.receiptDigest)
    },
    verdict: {
      pass: failures.length === 0,
      status: failures.length === 0 ? 'ready-for-authorized-canary' : 'blocked',
      failures,
      productionDeploymentAuthorized: false
    }
  };
}

async function loadReceipt(manifestDirectory, reference, expectedSchema) {
  if (typeof reference !== 'string' || !reference.trim()) throw new Error('Receipt paths must be non-empty strings.');
  const resolved = path.resolve(manifestDirectory, reference);
  const receipt = JSON.parse(await fs.readFile(resolved, 'utf8'));
  if (receipt.schema !== expectedSchema) throw new Error(`Expected ${expectedSchema} at ${resolved}.`);
  const verification = verifyReceipt(receipt);
  if (!verification.valid) throw new Error(`Receipt failed digest verification: ${resolved}`);
  return receipt;
}

function reportMarkdown(receipt) {
  const rows = receipt.run.checks.map((item) => `| ${item.name} | ${item.pass ? 'PASS' : 'BLOCKED'} | ${String(item.observed)} | ${item.requirement} |`).join('\n');
  return `# PQC Forge staging acceptance\n\nTarget: **${receipt.run.target}**\n\nVerdict: **${receipt.run.verdict.status.toUpperCase()}**\n\nProduction deployment authorized: **NO**\n\n| Check | Result | Observed | Requirement |\n|---|---|---:|---|\n${rows}\n\nA passing result permits only the explicitly approved canary. Expansion still requires a human review of live canary telemetry.\n\nReceipt: \`${receipt.receiptDigest}\`\n`;
}

export async function writeStagingEvidence(manifestPath, outputDirectory, { signingKey = null } = {}) {
  if (!signingKey) throw new Error('writeStagingEvidence requires a signingKey (see loadSigningKey in src/signing.js or `pqc-forge keygen`).');
  const resolvedManifest = path.resolve(manifestPath);
  const manifestDirectory = path.dirname(resolvedManifest);
  const manifest = JSON.parse(await fs.readFile(resolvedManifest, 'utf8'));
  const output = path.resolve(outputDirectory);
  try {
    const existing = await fs.readdir(output);
    if (existing.length) throw new Error(`Refusing to overwrite non-empty staging evidence directory: ${output}`);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  const runtimeReceipts = await Promise.all((manifest.runtimeReceipts ?? []).map((reference) => loadReceipt(manifestDirectory, reference, 'pqc-forge.runtime-receipt/v1')));
  const endpointReceipts = await Promise.all((manifest.endpointReceipts ?? []).map((reference) => loadReceipt(manifestDirectory, reference, 'pqc-forge.tls-receipt/v1')));
  const run = evaluateStagingGate(manifest, { runtimeReceipts, endpointReceipts });
  const receipt = createStagingReceipt(run, signingKey);
  await fs.mkdir(output, { recursive: true });
  await fs.writeFile(path.join(output, 'staging-receipt.json'), `${JSON.stringify(receipt, null, 2)}\n`, 'utf8');
  await fs.writeFile(path.join(output, 'STAGING_REPORT.md'), reportMarkdown(receipt), 'utf8');
  return { output, run, receipt };
}
