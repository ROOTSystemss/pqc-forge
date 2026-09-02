import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { createPrPack } from '../src/pr-pack.js';
import { validateCorpus, verifyPackArtifacts } from '../src/validation.js';
import { createReleaseReceipt, verifyReceipt } from '../src/breaklab/receipt.js';
import { VERSION } from '../src/version.js';

const project = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const value = (name, fallback) => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : fallback;
};
const output = path.resolve(project, value('--out', `release-output/release-${VERSION}`));
const skipPublic = args.includes('--skip-public');
const npmCli = process.env.npm_execpath;
const steps = [];

function execute(command, commandArgs, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, commandArgs, { cwd: project, windowsHide: true, ...options });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; process.stdout.write(chunk); });
    child.stderr.on('data', (chunk) => { stderr += chunk; process.stderr.write(chunk); });
    child.once('error', reject);
    child.once('close', (code) => code === 0 ? resolve({ stdout, stderr }) : reject(new Error(`${command} ${commandArgs.join(' ')} exited ${code}\n${stderr}`)));
  });
}

async function step(name, action) {
  const started = Date.now();
  process.stdout.write(`\n[release] ${name}\n`);
  try {
    const detail = await action();
    steps.push({ name, status: 'pass', durationMs: Date.now() - started, ...detail });
  } catch (error) {
    steps.push({ name, status: 'fail', durationMs: Date.now() - started, error: error.message });
    throw error;
  }
}

function executeNpm(npmArgs, options = {}) {
  if (npmCli) return execute(process.execPath, [npmCli, ...npmArgs], options);
  if (process.platform === 'win32') throw new Error('On Windows, run this gate through `npm run release:check` so npm_execpath is available.');
  return execute('npm', npmArgs, options);
}

async function assertNewOutput() {
  try {
    const existing = await fs.readdir(output);
    if (existing.length) throw new Error(`Refusing to overwrite non-empty release directory: ${output}`);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  await fs.mkdir(output, { recursive: true });
}

function markdown(receipt) {
  const rows = receipt.run.steps.map((item) => `| ${item.name} | ${item.status.toUpperCase()} | ${item.durationMs} ms |`).join('\n');
  return `# PQC Forge ${VERSION} release gate\n\nVerdict: **${receipt.run.verdict.pass ? 'PASS' : 'FAIL'}**\n\n| Gate | Result | Duration |\n|---|---|---:|\n${rows}\n\nReceipt: \`${receipt.receiptDigest}\`\n`;
}

async function finish(pass, error = null) {
  const run = { schema: 'pqc-forge.release-run/v1', version: VERSION, verdict: { pass }, platform: process.platform, node: process.version, steps, error };
  const receipt = createReleaseReceipt(run);
  await fs.writeFile(path.join(output, 'release-report.json'), `${JSON.stringify(run, null, 2)}\n`);
  await fs.writeFile(path.join(output, 'release-receipt.json'), `${JSON.stringify(receipt, null, 2)}\n`);
  await fs.writeFile(path.join(output, 'RELEASE_REPORT.md'), markdown(receipt));
  return receipt;
}

await assertNewOutput();
try {
  await step('unit-and-integration-tests', async () => {
    const result = await executeNpm(['test']);
    await fs.writeFile(path.join(output, 'test.log'), result.stdout + result.stderr);
    return { tests: 'passed' };
  });
  if (skipPublic) {
    steps.push({ name: 'pinned-public-corpus', status: 'skipped', durationMs: 0, reason: '--skip-public' });
  } else {
    await step('pinned-public-corpus', async () => {
      const result = await validateCorpus(path.join(project, 'validation', 'corpus.json'), path.join(output, 'public-validation'));
      return { cases: result.run.totalCases, receiptDigest: result.receiptDigest };
    });
  }
  await step('breaklab-evidence', async () => {
    const directory = path.join(output, 'breaklab');
    const scenario = JSON.parse(await fs.readFile(path.join(project, 'scenarios', 'tls-migration-demo.json'), 'utf8'));
    await execute(process.execPath, ['./bin/pqc-forge.js', 'breaklab', './scenarios/tls-migration-demo.json', '--budget', '30', '--seed', '42', '--out', directory, '--no-fail']);
    const receipt = JSON.parse(await fs.readFile(path.join(directory, 'breaklab-receipt.json'), 'utf8'));
    if (!verifyReceipt(receipt).valid) throw new Error('BreakLab receipt verification failed.');
    const modes = new Set(receipt.run.strategies.flatMap((strategy) => strategy.uniqueFailureModes)).size;
    const expected = scenario.releaseExpectation;
    if (!expected || receipt.run.verdict.pass !== expected.verdictPass || modes < expected.minFailureModes) {
      throw new Error(`BreakLab detector expectation failed: verdict=${receipt.run.verdict.pass}, failureModes=${modes}`);
    }
    return { receiptDigest: receipt.receiptDigest, detectorExpectationMet: true, observedScenarioPass: receipt.run.verdict.pass, failureModes: modes };
  });
  await step('release-pr-pack', async () => {
    const protocol = path.join(project, 'protocol-output', 'protocol-lab-receipt.json');
    let protocolReceiptPath = null;
    try {
      const receipt = JSON.parse(await fs.readFile(protocol, 'utf8'));
      if (verifyReceipt(receipt).valid) protocolReceiptPath = protocol;
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    const directory = path.join(output, 'pr-pack');
    const result = await createPrPack(path.join(project, 'test', 'fixtures', 'vulnerable'), directory, { protocolReceiptPath });
    await verifyPackArtifacts(directory);
    return {
      receiptDigest: result.receiptDigest,
      protocolEvidenceIncluded: result.summary.protocolEvidenceIncluded,
      targetRuntimeEvidenceComplete: result.summary.targetRuntimeEvidenceComplete,
      productionDeploymentAuthorized: result.summary.productionDeploymentAuthorized
    };
  });
  let tarball;
  await step('npm-package', async () => {
    const directory = path.join(output, 'package');
    await fs.mkdir(directory, { recursive: true });
    const result = await executeNpm(['pack', '--json', '--pack-destination', directory, '--cache', path.join(project, '.npm-cache')]);
    const metadata = JSON.parse(result.stdout);
    tarball = path.join(directory, metadata[0].filename);
    const bytes = await fs.readFile(tarball);
    return { file: metadata[0].filename, bytes: bytes.length, sha256: `sha256:${createHash('sha256').update(bytes).digest('hex')}`, npmIntegrity: metadata[0].integrity };
  });
  await step('installed-package-smoke-test', async () => {
    const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-install-'));
    try {
      await executeNpm(['install', '--ignore-scripts', '--no-audit', '--no-fund', tarball], { cwd: temporary });
      const installed = path.join(temporary, 'node_modules', '@rootsystems', 'pqc-forge', 'bin', 'pqc-forge.js');
      const result = await execute(process.execPath, [installed, '--help'], { cwd: temporary });
      if (!result.stdout.includes('validate-corpus') || !result.stdout.includes('runtime-probe') || !result.stdout.includes('staging-gate')) throw new Error('Installed CLI is missing a required safety command.');
      return { cli: 'passed' };
    } finally {
      await fs.rm(temporary, { recursive: true, force: true });
    }
  });
  const receipt = await finish(true);
  console.log(`\nRelease gate PASS: ${receipt.receiptDigest}\nArtifacts: ${output}`);
} catch (error) {
  const receipt = await finish(false, error.message);
  console.error(`\nRelease gate FAIL: ${receipt.receiptDigest}\n${error.message}`);
  process.exitCode = 1;
}
