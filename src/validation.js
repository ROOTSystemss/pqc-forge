import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { scanRepository } from './scanner.js';
import { migrateRepository } from './migrator.js';
import { createPrPack } from './pr-pack.js';
import { createValidationReceipt, verifyReceipt } from './breaklab/receipt.js';

const MAX_SOURCE_BYTES = 1024 * 1024;
const digest = (content) => `sha256:${createHash('sha256').update(content).digest('hex')}`;

function runGit(args, cwd) {
  return new Promise((resolve, reject) => {
    const child = spawn('git', args, { cwd, windowsHide: true });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.once('error', reject);
    child.once('close', (code) => code === 0 ? resolve({ stdout, stderr }) : reject(new Error(`git ${args.join(' ')} failed: ${stderr.trim()}`)));
  });
}

async function assertEmptyOutput(output) {
  try {
    const files = await fs.readdir(output);
    if (files.length) throw new Error(`Refusing to overwrite non-empty validation directory: ${output}`);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
}

function assertManifest(manifest) {
  if (manifest.schema !== 'pqc-forge.public-corpus/v1') throw new Error('Unsupported corpus manifest schema.');
  if (!Array.isArray(manifest.cases) || manifest.cases.length === 0) throw new Error('Corpus manifest must contain cases.');
  const ids = new Set();
  for (const item of manifest.cases) {
    if (!item.id || !/^[a-z0-9][a-z0-9._-]*$/i.test(item.id) || ['.', '..'].includes(item.id) || ids.has(item.id)) {
      throw new Error(`Corpus case id is unsafe, missing, or duplicated: ${item.id ?? '<missing>'}`);
    }
    ids.add(item.id);
    const url = new URL(item.url);
    if (url.protocol !== 'https:') throw new Error(`Corpus source must use HTTPS: ${item.id}`);
    if (!/^sha256:[a-f0-9]{64}$/.test(item.sha256)) throw new Error(`Invalid SHA-256 for corpus case: ${item.id}`);
    if (!item.filename || ['.', '..'].includes(item.filename) || path.isAbsolute(item.filename) || path.basename(item.filename) !== item.filename) {
      throw new Error(`Unsafe filename for corpus case: ${item.id}`);
    }
  }
}

async function download(item, fetchImpl) {
  const response = await fetchImpl(item.url, {
    redirect: 'follow', headers: { 'user-agent': 'pqc-forge-validation' }, signal: AbortSignal.timeout(20_000)
  });
  if (!response.ok) throw new Error(`${item.id}: download returned HTTP ${response.status}`);
  if (response.url && new URL(response.url).protocol !== 'https:') throw new Error(`${item.id}: redirect target must use HTTPS`);
  const declared = Number(response.headers.get('content-length') ?? 0);
  if (declared > MAX_SOURCE_BYTES) throw new Error(`${item.id}: source exceeds ${MAX_SOURCE_BYTES} bytes`);
  const source = Buffer.from(await response.arrayBuffer());
  if (source.length > MAX_SOURCE_BYTES) throw new Error(`${item.id}: source exceeds ${MAX_SOURCE_BYTES} bytes`);
  const actual = digest(source);
  if (actual !== item.sha256) throw new Error(`${item.id}: integrity mismatch; expected ${item.sha256}, received ${actual}`);
  return source;
}

async function verifyPackArtifacts(packDirectory) {
  const root = path.resolve(packDirectory);
  const receipt = JSON.parse(await fs.readFile(path.join(root, 'pr-pack-receipt.json'), 'utf8'));
  if (!verifyReceipt(receipt).valid) throw new Error('PR-pack receipt digest is invalid.');
  for (const artifact of receipt.artifacts) {
    const artifactPath = path.resolve(root, artifact.file);
    if (!artifact.file || artifactPath === root || !artifactPath.startsWith(`${root}${path.sep}`)) {
      throw new Error(`Unsafe PR-pack artifact path: ${artifact.file}`);
    }
    const content = await fs.readFile(artifactPath);
    if (content.length !== artifact.bytes || digest(content) !== artifact.digest) {
      throw new Error(`PR-pack artifact integrity failed: ${artifact.file}`);
    }
  }
  const migrationReceipt = JSON.parse(await fs.readFile(path.join(root, 'migration-receipt.json'), 'utf8'));
  if (!verifyReceipt(migrationReceipt).valid) throw new Error('Migration receipt digest is invalid.');
  const afterDigests = new Set(migrationReceipt.migration.artifacts.map((artifact) => artifact.afterDigest));
  for (const artifact of receipt.artifacts.filter((item) => /^runtime-receipt(?:-\d+)?\.json$/.test(item.file))) {
    const runtimeReceipt = JSON.parse(await fs.readFile(path.join(root, artifact.file), 'utf8'));
    if (runtimeReceipt.schema !== 'pqc-forge.runtime-receipt/v1' || !verifyReceipt(runtimeReceipt).valid || !runtimeReceipt.probe?.verdict?.pass) {
      throw new Error(`Embedded target runtime receipt is invalid or blocked: ${artifact.file}`);
    }
    if (!afterDigests.has(runtimeReceipt.probe.config?.digest)) throw new Error(`Embedded target runtime receipt does not match a migrated artifact: ${artifact.file}`);
  }
  if (receipt.artifacts.some((item) => item.file === 'protocol-lab-receipt.json')) {
    const protocolReceipt = JSON.parse(await fs.readFile(path.join(root, 'protocol-lab-receipt.json'), 'utf8'));
    if (protocolReceipt.schema !== 'pqc-forge.protocol-lab-receipt/v1' || !verifyReceipt(protocolReceipt).valid) {
      throw new Error('Embedded protocol-lab receipt is invalid.');
    }
  }
  return receipt;
}

function meets(actual, minimum, label, id) {
  if (minimum !== undefined && actual < minimum) throw new Error(`${id}: expected ${label} >= ${minimum}, received ${actual}`);
}

async function validateCase(item, root, fetchImpl) {
  const source = await download(item, fetchImpl);
  const repository = path.join(root, 'repository');
  const pack = path.join(root, 'pr-pack');
  await fs.mkdir(repository, { recursive: true });
  await fs.writeFile(path.join(repository, item.filename), source);
  const before = await scanRepository(repository, { ignoreFile: null });
  const migration = await migrateRepository(repository);
  meets(before.summary.total, item.expect?.minFindings, 'findings', item.id);
  meets(migration.changeCount, item.expect?.minChanges, 'changes', item.id);

  let resolved = 0;
  let packDigest = null;
  if (item.expect?.pack) {
    const result = await createPrPack(repository, pack);
    resolved = result.summary.resolvedFindings;
    meets(resolved, item.expect.minResolved, 'resolved findings', item.id);
    await verifyPackArtifacts(pack);
    const applyRoot = path.join(root, 'apply-check');
    await fs.cp(repository, applyRoot, { recursive: true });
    await runGit(['init', '--quiet'], applyRoot);
    const patchFile = path.join(pack, 'migration.patch');
    // Mirror the checked-out file's line-ending policy. Public files are
    // downloaded directly rather than checked out through Git, so the lab must
    // explicitly model the repository setting that would produce those bytes.
    const autocrlf = source.includes(Buffer.from('\r\n')) ? 'true' : 'false';
    const portableApply = ['-c', `core.autocrlf=${autocrlf}`, 'apply'];
    await runGit([...portableApply, '--check', patchFile], applyRoot);
    await runGit([...portableApply, patchFile], applyRoot);
    await runGit([...portableApply, '--check', '--reverse', patchFile], applyRoot);
    await runGit([...portableApply, '--reverse', patchFile], applyRoot);
    const restored = await fs.readFile(path.join(applyRoot, item.filename));
    if (!restored.equals(source)) throw new Error(`${item.id}: reverse patch did not restore source (${digest(source)} expected, ${digest(restored)} received; ${source.length}/${restored.length} bytes)`);
    packDigest = result.receiptDigest;
  } else if (migration.changeCount !== 0) {
    throw new Error(`${item.id}: clean control unexpectedly produced ${migration.changeCount} changes`);
  }
  if (!Buffer.from(await fs.readFile(path.join(repository, item.filename))).equals(source)) throw new Error(`${item.id}: validation modified source repository`);
  return {
    id: item.id, source: item.source, revision: item.revision, sourceDigest: item.sha256,
    bytes: source.length, findings: before.summary.total, changes: migration.changeCount,
    resolvedFindings: resolved, patchApplyAndReverse: Boolean(item.expect?.pack), packReceiptDigest: packDigest,
    pass: true
  };
}

function renderMarkdown(receipt) {
  const rows = receipt.run.cases.map((item) => `| ${item.id} | ${item.findings} | ${item.changes} | ${item.resolvedFindings} | PASS |`).join('\n');
  return `# PQC Forge public-corpus validation\n\nVerdict: **${receipt.run.verdict.pass ? 'PASS' : 'FAIL'}**\n\n| Case | Findings | Changes | Resolved | Result |\n|---|---:|---:|---:|---|\n${rows}\n\nReceipt: \`${receipt.receiptDigest}\`\n`;
}

export async function validateCorpus(manifestPath, outputPath, { fetchImpl = globalThis.fetch } = {}) {
  const manifest = JSON.parse(await fs.readFile(path.resolve(manifestPath), 'utf8'));
  assertManifest(manifest);
  const output = path.resolve(outputPath);
  await assertEmptyOutput(output);
  const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-corpus-'));
  try {
    const cases = [];
    for (const item of manifest.cases) cases.push(await validateCase(item, path.join(temporary, item.id), fetchImpl));
    const run = { schema: 'pqc-forge.validation-run/v1', verdict: { pass: true }, totalCases: cases.length, cases };
    const receipt = createValidationReceipt(manifest, run);
    await fs.mkdir(output, { recursive: true });
    await fs.writeFile(path.join(output, 'validation-report.json'), `${JSON.stringify(run, null, 2)}\n`, 'utf8');
    await fs.writeFile(path.join(output, 'validation-receipt.json'), `${JSON.stringify(receipt, null, 2)}\n`, 'utf8');
    await fs.writeFile(path.join(output, 'VALIDATION_REPORT.md'), renderMarkdown(receipt), 'utf8');
    return { output, receiptDigest: receipt.receiptDigest, run };
  } finally {
    await fs.rm(temporary, { recursive: true, force: true });
  }
}

export { verifyPackArtifacts };
