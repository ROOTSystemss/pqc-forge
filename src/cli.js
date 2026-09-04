import { scanRepository } from './scanner.js';
import { migrateRepository } from './migrator.js';
import { verifyTls } from './verifier.js';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { runBreakLab } from './breaklab/engine.js';
import { createMigrationReceipt, createProtocolReceipt, createReceipt, createTlsReceipt, verifyReceipt } from './breaklab/receipt.js';
import { renderBreakLabHtml } from './breaklab/report.js';
import { dockerStatus, PROTOCOL_CASES, runDockerProtocolLab } from './protocol-lab/docker.js';
import { renderProtocolLabHtml } from './protocol-lab/report.js';
import { compareScans } from './baseline.js';
import { scanToSarif } from './sarif.js';
import { scanToCbom } from './cbom.js';
import { rollbackMigration } from './rollback.js';
import { createPrPack } from './pr-pack.js';
import { validateCorpus } from './validation.js';
import { createContainerRunner, writeRuntimeEvidence } from './runtime-probe.js';
import { writeStagingEvidence } from './staging-gate.js';
import { generateSigningKey, loadSigningKey, publicKeyDocument } from './signing.js';
import { provisionTenant } from './api/server.js';

const HELP = `PQC Forge — repository-to-patch migration evidence

Usage:
  pqc-forge scan <path> [--json] [--report file] [--sarif file] [--cbom file] [--baseline scan.json] [--ignore file|--no-ignore]
  pqc-forge migrate <path> [--write --accept-runtime-requirement] [--out directory] [--signing-key file] [--json]
  pqc-forge rollback <migration-receipt.json> [--write] [--json]
  pqc-forge pr-pack <repository> --out directory [--protocol-receipt file] [--runtime-receipt file] [--signing-key file] [--json]
  pqc-forge runtime-probe <nginx|haproxy|apache|envoy> --config file --out directory [--openssl executable] [--server-executable executable] [--container name --container-config path] [--docker executable] [--target name] [--signing-key file] [--json]
  pqc-forge staging-gate <manifest.json> --out directory [--signing-key file] [--json]
  pqc-forge validate-corpus <manifest.json> --out directory [--signing-key file] [--json]
  pqc-forge verify <host[:port]> [--insecure] [--out directory] [--signing-key file] [--json]
  pqc-forge breaklab <scenario.json> [--budget 64] [--seed 42] [--out directory] [--signing-key file] [--no-fail] [--json]
  pqc-forge protocol-lab [--out directory] [--signing-key file] [--no-fail] [--json]
  pqc-forge doctor [--json]
  pqc-forge keygen --out <directory> [--json]
  pqc-forge verify-receipt <receipt.json> [--trusted-key file]... [--json]
  pqc-forge tenant-create --name <name> --out <api-data-directory> [--json]

Commands:
  scan      Find quantum-vulnerable crypto with file/line evidence.
  migrate   Generate safe supported edits; --write applies them with backups.
  rollback  Restore an applied migration only when receipt and file digests match.
  pr-pack   Generate a non-destructive migration patch and complete PR evidence bundle.
  runtime-probe  Prove target OpenSSL capability and patched server-config syntax without reloading it.
  staging-gate  Combine runtime, endpoint, load, rollback, monitoring, and approval evidence into a canary gate.
  validate-corpus  Test pinned public configurations, patches, and evidence end to end.
  verify    Record the TLS 1.3 group and authentication actually negotiated.
  breaklab  Search a migration compatibility matrix and minimize failures.
  protocol-lab  Execute real OpenSSL 3.5/Nginx TLS handshakes in Docker.
  doctor    Check Docker, Compose, and engine readiness with corrective guidance.
  keygen    Generate an ML-DSA-65 signing identity for evidence receipts.
  verify-receipt  Verify a PQC Forge receipt's SHA-256 digest and ML-DSA signature.
  tenant-create  Provision a new API tenant and print its API key once.

Signing:
  Every receipt PQC Forge writes is ML-DSA-65 signed as well as SHA-256
  digested; a receipt with a missing or invalid signature is never valid.
  --signing-key selects an identity file created by \`keygen\`. Without it,
  PQC_FORGE_SIGNING_KEY is used if set, and otherwise an identity is
  auto-provisioned once at PQC_FORGE_HOME (or ~/.pqc-forge) and reused after
  that. Auto-provisioning keeps the CLI zero-setup for local use; pass an
  explicit --signing-key wherever an organization-managed identity matters.
  \`verify-receipt --trusted-key <public-key-file>\` (repeatable) additionally
  requires the receipt's signer to be one of the named public keys.
`;

function optionValue(args, name, fallback) {
  const index = args.indexOf(name);
  return index >= 0 && args[index + 1] ? args[index + 1] : fallback;
}

function optionValues(args, name) {
  const values = [];
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] === name && args[index + 1]) values.push(args[index + 1]);
  }
  return values;
}

function printScan(report) {
  console.log(`Scanned ${report.filesScanned} files; found ${report.summary.total} items (${report.summary.critical} critical, ${report.summary.high} high, ${report.summary.medium} medium).`);
  if (report.delta) {
    console.log(`Baseline delta: ${report.delta.summary.new} new (${report.delta.summary.newBlocking} blocking), ${report.delta.summary.resolved} resolved, ${report.delta.summary.unchanged} unchanged.`);
  }
  if (report.summary.suppressed) console.log(`Suppressed with active audited exceptions: ${report.summary.suppressed}.`);
  for (const finding of report.findings) {
    console.log(`[${finding.severity.toUpperCase()}] ${finding.id} ${finding.file}:${finding.line}`);
    console.log(`  ${finding.excerpt}`);
    console.log(`  ${finding.remediation}`);
  }
}

function printMigration(report) {
  console.log(`${report.mode === 'applied' ? 'Applied' : 'Proposed'} ${report.changeCount} migration change(s).`);
  console.log(`Runtime requirement: ${report.runtimeRequirement}`);
  for (const change of report.changes) {
    console.log(`${change.file}:${change.line} ${change.ruleId}`);
    if (change.before !== null) console.log(`- ${change.before}`);
    console.log(`+ ${change.after}`);
  }
}

function printEvidence(evidence) {
  console.log(`${evidence.target}: ${evidence.verdict.status}`);
  console.log(`Protocol: ${evidence.protocol}; group: ${evidence.ephemeralKey.name ?? evidence.ephemeralKey.type ?? 'unknown'}`);
  console.log(`Peer signature: ${evidence.peerSignatureAlgorithm}`);
  console.log(`Runtime: Node ${evidence.runtime.node}, OpenSSL ${evidence.runtime.openssl}`);
}

function printBreakLab(receipt, outputDirectory) {
  const { run } = receipt;
  console.log(`${run.scenario}: ${run.verdict.pass ? 'PASS' : 'FAIL'} (highest severity ${run.verdict.highestSeverity})`);
  console.log(`Explored ${run.totalStates} states with ${run.evaluationBudgetPerStrategy} evaluations per strategy.`);
  console.log(`Measured winner: ${run.winner}`);
  for (const strategy of run.strategies) {
    console.log(`  ${strategy.strategy}: ${strategy.failingConfigurations} failing configurations, ${strategy.uniqueFailureModes.length} modes, max ${strategy.maxSeverity}`);
  }
  console.log(`Minimal counterexamples: ${run.counterexamples.length}`);
  console.log(`Receipt: ${receipt.receiptDigest}`);
  if (outputDirectory) console.log(`Evidence written to ${outputDirectory}`);
}

export async function run(args) {
  const [command, target] = args;
  if (!command || ['help', '--help', '-h'].includes(command)) {
    console.log(HELP);
    return;
  }
  if (!target && !['protocol-lab', 'doctor', 'keygen', 'tenant-create'].includes(command)) throw new Error(`Missing target.\n\n${HELP}`);

  const json = args.includes('--json');
  const signingKeyOption = optionValue(args, '--signing-key', null);
  const resolveSigningKey = async () => (await loadSigningKey(signingKeyOption)).key;

  if (command === 'keygen') {
    const outValue = optionValue(args, '--out', null);
    if (!outValue) throw new Error('keygen requires --out <directory>.');
    const outputDirectory = path.resolve(outValue);
    await fs.mkdir(outputDirectory, { recursive: true });
    const keyPath = path.join(outputDirectory, 'signing-key.json');
    try {
      await fs.access(keyPath);
      throw new Error(`Refusing to overwrite an existing signing key: ${keyPath}`);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    const key = generateSigningKey();
    await fs.writeFile(keyPath, `${JSON.stringify(key, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
    try { await fs.chmod(keyPath, 0o600); } catch { /* best-effort outside POSIX filesystems */ }
    const publicPath = path.join(outputDirectory, 'signing-key.pub.json');
    await fs.writeFile(publicPath, `${JSON.stringify(publicKeyDocument(key), null, 2)}\n`, 'utf8');
    if (json) console.log(JSON.stringify({ keyId: key.keyId, algorithm: key.algorithm, keyPath, publicPath }, null, 2));
    else {
      console.log(`Generated ${key.algorithm} signing key ${key.keyId}`);
      console.log(`Secret key (keep private): ${keyPath}`);
      console.log(`Public key (safe to distribute as a trust root): ${publicPath}`);
      console.log('Set PQC_FORGE_SIGNING_KEY to this secret key path, or pass --signing-key, to sign receipts with it.');
    }
    return;
  }
  if (command === 'tenant-create') {
    const outValue = optionValue(args, '--out', null);
    const name = optionValue(args, '--name', null);
    if (!outValue) throw new Error('tenant-create requires --out <api-data-directory>.');
    if (!name) throw new Error('tenant-create requires --name <name>.');
    const { tenantId, apiKey } = await provisionTenant(path.resolve(outValue), name);
    if (json) console.log(JSON.stringify({ tenantId, apiKey }, null, 2));
    else {
      console.log(`Tenant ${tenantId} created.`);
      console.log(`API key (shown once, not recoverable): ${apiKey}`);
      console.log('Store it now — only its hash is persisted.');
    }
    return;
  }
  if (command === 'doctor') {
    const status = await dockerStatus();
    if (json) console.log(JSON.stringify(status, null, 2));
    else {
      console.log(`Protocol lab preflight: ${status.ready ? 'READY' : 'BLOCKED'} (${status.code})`);
      console.log(`Docker command: ${status.command}`);
      console.log(status.detail);
      if (status.action) console.log(`Action: ${status.action}`);
    }
    process.exitCode = status.ready ? 0 : 7;
    return;
  }
  if (command === 'scan') {
    const ignoreValue = optionValue(args, '--ignore', undefined);
    if (args.includes('--ignore') && !ignoreValue) throw new Error('--ignore requires a file.');
    const report = await scanRepository(target, { ignoreFile: args.includes('--no-ignore') ? null : ignoreValue });
    const baselinePath = optionValue(args, '--baseline', null);
    if (baselinePath) {
      const baseline = JSON.parse(await fs.readFile(path.resolve(baselinePath), 'utf8'));
      report.delta = compareScans(report, baseline);
    }
    const sarifPath = optionValue(args, '--sarif', null);
    if (args.includes('--sarif') && !sarifPath) throw new Error('--sarif requires an output file.');
    if (sarifPath) {
      const resolvedSarif = path.resolve(sarifPath);
      await fs.mkdir(path.dirname(resolvedSarif), { recursive: true });
      await fs.writeFile(resolvedSarif, `${JSON.stringify(scanToSarif(report), null, 2)}\n`, 'utf8');
      if (!json) console.log(`SARIF written to ${resolvedSarif}`);
    }
    const cbomPath = optionValue(args, '--cbom', null);
    if (args.includes('--cbom') && !cbomPath) throw new Error('--cbom requires an output file.');
    if (cbomPath) {
      const resolvedCbom = path.resolve(cbomPath);
      await fs.mkdir(path.dirname(resolvedCbom), { recursive: true });
      await fs.writeFile(resolvedCbom, `${JSON.stringify(scanToCbom(report), null, 2)}\n`, 'utf8');
      if (!json) console.log(`CycloneDX CBOM written to ${resolvedCbom}`);
    }
    const reportPath = optionValue(args, '--report', null);
    if (args.includes('--report') && !reportPath) throw new Error('--report requires an output file.');
    if (reportPath) {
      const resolvedReport = path.resolve(reportPath);
      await fs.mkdir(path.dirname(resolvedReport), { recursive: true });
      await fs.writeFile(resolvedReport, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
      if (!json) console.log(`JSON report written to ${resolvedReport}`);
    }
    json ? console.log(JSON.stringify(report, null, 2)) : printScan(report);
    process.exitCode = report.delta
      ? (report.delta.summary.newBlocking > 0 ? 2 : 0)
      : (report.summary.critical > 0 ? 2 : 0);
    return;
  }
  if (command === 'migrate') {
    const report = await migrateRepository(target, {
      write: args.includes('--write'),
      acknowledgeRuntime: args.includes('--accept-runtime-requirement')
    });
    const outValue = optionValue(args, '--out', null);
    if (args.includes('--out') && !outValue) throw new Error('--out requires an output directory.');
    if (outValue) {
      const outputDirectory = path.resolve(outValue);
      const receipt = createMigrationReceipt(report, await resolveSigningKey());
      await fs.mkdir(outputDirectory, { recursive: true });
      await fs.writeFile(path.join(outputDirectory, 'migration-receipt.json'), `${JSON.stringify(receipt, null, 2)}\n`, 'utf8');
      if (!json) console.log(`Migration receipt written to ${outputDirectory}`);
    }
    json ? console.log(JSON.stringify(report, null, 2)) : printMigration(report);
    return;
  }
  if (command === 'rollback') {
    const receipt = JSON.parse(await fs.readFile(path.resolve(target), 'utf8'));
    const report = await rollbackMigration(receipt, { write: args.includes('--write') });
    if (json) console.log(JSON.stringify(report, null, 2));
    else {
      console.log(`${report.mode === 'applied' ? 'Restored' : 'Validated'} ${report.restoredCount} file(s).`);
      for (const item of report.files) console.log(`${item.file} <- ${item.backup}`);
      if (report.mode === 'dry-run') console.log('Use --write to apply this verified rollback.');
    }
    return;
  }
  if (command === 'pr-pack') {
    const outValue = optionValue(args, '--out', null);
    if (!outValue) throw new Error('pr-pack requires --out <directory>.');
    const protocolReceiptPath = optionValue(args, '--protocol-receipt', null);
    if (args.includes('--protocol-receipt') && !protocolReceiptPath) throw new Error('--protocol-receipt requires a file.');
    const runtimeReceiptPaths = optionValues(args, '--runtime-receipt');
    if (args.includes('--runtime-receipt') && runtimeReceiptPaths.length === 0) throw new Error('--runtime-receipt requires a file.');
    const result = await createPrPack(target, outValue, { protocolReceiptPath, runtimeReceiptPaths, signingKey: await resolveSigningKey() });
    if (json) console.log(JSON.stringify(result, null, 2));
    else {
      console.log(`PR pack created with ${result.summary.changeCount} change(s) and ${result.summary.resolvedFindings} resolved finding(s).`);
      console.log(`Remaining critical/high findings: ${result.summary.remainingBlockingFindings}`);
      console.log(`Receipt: ${result.receiptDigest}`);
      console.log(`Output: ${result.output}`);
    }
    return;
  }
  if (command === 'runtime-probe') {
    const configPath = optionValue(args, '--config', null);
    const outValue = optionValue(args, '--out', null);
    if (!configPath || !outValue) throw new Error('runtime-probe requires --config <patched-file> and --out <directory>.');
    const container = optionValue(args, '--container', null);
    const containerConfig = optionValue(args, '--container-config', null);
    if (container && !containerConfig) throw new Error('--container requires --container-config <path-inside-container>.');
    if (!container && args.includes('--container-config')) throw new Error('--container-config requires --container <name>.');
    const result = await writeRuntimeEvidence(target, outValue, {
      configPath,
      opensslExecutable: optionValue(args, '--openssl', 'openssl'),
      serverExecutable: optionValue(args, '--server-executable', undefined),
      target: optionValue(args, '--target', 'local-staging-environment'),
      executionConfigPath: containerConfig ?? undefined,
      runner: container ? createContainerRunner(container, { dockerExecutable: optionValue(args, '--docker', 'docker') }) : undefined,
      signingKey: await resolveSigningKey()
    });
    if (json) console.log(JSON.stringify(result.probe, null, 2));
    else {
      console.log(`Target runtime probe: ${result.probe.verdict.pass ? 'PASS' : 'BLOCKED'} (${target}).`);
      if (result.probe.verdict.failures.length) console.log(`Failed checks: ${result.probe.verdict.failures.join(', ')}`);
      console.log(`Receipt: ${result.receipt.receiptDigest}`);
      console.log(`Output: ${result.output}`);
    }
    process.exitCode = result.probe.verdict.pass ? 0 : 8;
    return;
  }
  if (command === 'staging-gate') {
    const outValue = optionValue(args, '--out', null);
    if (!outValue) throw new Error('staging-gate requires --out <directory>.');
    const result = await writeStagingEvidence(target, outValue, { signingKey: await resolveSigningKey() });
    if (json) console.log(JSON.stringify(result.run, null, 2));
    else {
      console.log(`Staging acceptance: ${result.run.verdict.status.toUpperCase()}.`);
      if (result.run.verdict.failures.length) console.log(`Failed checks: ${result.run.verdict.failures.join(', ')}`);
      console.log('Production deployment authorized: NO');
      console.log(`Receipt: ${result.receipt.receiptDigest}`);
      console.log(`Output: ${result.output}`);
    }
    process.exitCode = result.run.verdict.pass ? 0 : 9;
    return;
  }
  if (command === 'validate-corpus') {
    const outValue = optionValue(args, '--out', null);
    if (!outValue) throw new Error('validate-corpus requires --out <directory>.');
    const result = await validateCorpus(target, outValue, { signingKey: await resolveSigningKey() });
    if (json) console.log(JSON.stringify(result, null, 2));
    else {
      console.log(`Public corpus: PASS (${result.run.totalCases}/${result.run.totalCases} cases).`);
      console.log(`Receipt: ${result.receiptDigest}`);
      console.log(`Output: ${result.output}`);
    }
    return;
  }
  if (command === 'verify') {
    const evidence = await verifyTls(target, { insecure: args.includes('--insecure') });
    const outValue = optionValue(args, '--out', null);
    if (args.includes('--out') && !outValue) throw new Error('--out requires an output directory.');
    if (outValue) {
      const output = path.resolve(outValue);
      try {
        const existing = await fs.readdir(output);
        if (existing.length) throw new Error(`Refusing to overwrite non-empty TLS evidence directory: ${output}`);
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }
      const receipt = createTlsReceipt(evidence, await resolveSigningKey());
      await fs.mkdir(output, { recursive: true });
      await fs.writeFile(path.join(output, 'tls-receipt.json'), `${JSON.stringify(receipt, null, 2)}\n`, 'utf8');
      if (!json) {
        console.log(`TLS receipt: ${receipt.receiptDigest}`);
        console.log(`Output: ${output}`);
      }
    }
    json ? console.log(JSON.stringify(evidence, null, 2)) : printEvidence(evidence);
    process.exitCode = evidence.verdict.pqKeyExchange ? 0 : 3;
    return;
  }
  if (command === 'breaklab') {
    const scenarioPath = path.resolve(target);
    const scenario = JSON.parse(await fs.readFile(scenarioPath, 'utf8'));
    const budget = Number(optionValue(args, '--budget', 64));
    const seed = Number(optionValue(args, '--seed', 42));
    if (!Number.isInteger(budget) || budget < 1) throw new Error('--budget must be a positive integer.');
    if (!Number.isInteger(seed)) throw new Error('--seed must be an integer.');
    const runReport = runBreakLab(scenario, { budget, seed });
    const receipt = createReceipt(runReport, scenario, await resolveSigningKey());
    const outValue = optionValue(args, '--out', null);
    let outputDirectory = null;
    if (outValue) {
      outputDirectory = path.resolve(outValue);
      await fs.mkdir(outputDirectory, { recursive: true });
      await fs.writeFile(path.join(outputDirectory, 'breaklab-receipt.json'), `${JSON.stringify(receipt, null, 2)}\n`, 'utf8');
      await fs.writeFile(path.join(outputDirectory, 'breaklab-report.html'), renderBreakLabHtml(receipt), 'utf8');
    }
    json ? console.log(JSON.stringify(receipt, null, 2)) : printBreakLab(receipt, outputDirectory);
    process.exitCode = runReport.verdict.pass || args.includes('--no-fail') ? 0 : 4;
    return;
  }
  if (command === 'protocol-lab') {
    const runReport = await runDockerProtocolLab();
    const receipt = createProtocolReceipt(runReport, { schema: 'pqc-forge.protocol-matrix/v1', cases: PROTOCOL_CASES }, await resolveSigningKey());
    const outValue = optionValue(args, '--out', null);
    let outputDirectory = null;
    if (outValue) {
      outputDirectory = path.resolve(outValue);
      await fs.mkdir(outputDirectory, { recursive: true });
      await fs.writeFile(path.join(outputDirectory, 'protocol-lab-receipt.json'), `${JSON.stringify(receipt, null, 2)}\n`, 'utf8');
      await fs.writeFile(path.join(outputDirectory, 'protocol-lab-report.html'), renderProtocolLabHtml(receipt), 'utf8');
    }
    if (json) console.log(JSON.stringify(receipt, null, 2));
    else {
      console.log(`Real protocol lab: ${runReport.verdict.pass ? 'PASS' : 'FAIL'}`);
      for (const result of runReport.cases) console.log(`  ${result.name}: ${result.expectationMet ? 'MATCH' : 'MISMATCH'} · ${result.negotiatedGroup ?? 'no group'} · ${result.findings.map((finding) => finding.code).join(', ') || 'clean'}`);
      console.log(`Receipt: ${receipt.receiptDigest}`);
      if (outputDirectory) console.log(`Evidence written to ${outputDirectory}`);
    }
    process.exitCode = runReport.verdict.pass || args.includes('--no-fail') ? 0 : 6;
    return;
  }
  if (command === 'verify-receipt') {
    const receipt = JSON.parse(await fs.readFile(path.resolve(target), 'utf8'));
    const trustedKeyPaths = optionValues(args, '--trusted-key');
    if (args.includes('--trusted-key') && trustedKeyPaths.length === 0) throw new Error('--trusted-key requires a public-key file.');
    const trustedPublicKeys = trustedKeyPaths.length
      ? await Promise.all(trustedKeyPaths.map(async (keyPath) => {
          const doc = JSON.parse(await fs.readFile(path.resolve(keyPath), 'utf8'));
          if (doc.schema !== 'pqc-forge.signing-public-key/v1' && doc.schema !== 'pqc-forge.signing-key/v1') throw new Error(`${keyPath} is not a PQC Forge signing key or public-key document.`);
          return doc.publicKey;
        }))
      : null;
    const verification = verifyReceipt(receipt, { trustedPublicKeys });
    if (json) console.log(JSON.stringify(verification, null, 2));
    else if (verification.valid) console.log(`Receipt is valid. Signed by ${verification.keyId}.`);
    else console.log(`Receipt is invalid: ${verification.errors.join(', ')}.\nExpected digest: ${verification.expected}\nActual digest:   ${verification.actual}`);
    process.exitCode = verification.valid ? 0 : 5;
    return;
  }
  throw new Error(`Unknown command: ${command}\n\n${HELP}`);
}
