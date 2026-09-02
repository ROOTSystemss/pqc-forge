import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { createPrPack } from '../src/pr-pack.js';
import { migrateRepository } from '../src/migrator.js';
import { createContainerRunner, parseOpenSslVersion, probeRuntime, writeRuntimeEvidence } from '../src/runtime-probe.js';
import { verifyReceipt } from '../src/breaklab/receipt.js';
import { verifyPackArtifacts } from '../src/validation.js';

function successfulRunner(calls) {
  return async (executable, args) => {
    calls.push({ executable, args });
    if (executable === 'openssl' && args[0] === 'version') return { executable, args, code: 0, stdout: 'OpenSSL 3.5.2 5 Aug 2025', stderr: '', error: null, durationMs: 1 };
    if (executable === 'openssl') return { executable, args, code: 0, stdout: 'X25519MLKEM768\nX25519\n', stderr: '', error: null, durationMs: 1 };
    return { executable, args, code: 0, stdout: `${executable} version`, stderr: '', error: null, durationMs: 1 };
  };
}

test('OpenSSL version parsing is conservative', () => {
  assert.equal(parseOpenSslVersion('OpenSSL 3.5.0').atLeast35, true);
  assert.equal(parseOpenSslVersion('OpenSSL 3.4.9').atLeast35, false);
  assert.equal(parseOpenSslVersion('LibreSSL 4.1').atLeast35, false);
});

test('container runner executes every probe directly through docker without a shell', async () => {
  const calls = [];
  const baseRunner = async (executable, args) => {
    calls.push({ executable, args });
    return { executable, args, code: 0, stdout: '', stderr: '', error: null, durationMs: 1 };
  };
  const runner = createContainerRunner('staging-nginx', { dockerExecutable: 'docker-test', runner: baseRunner });
  await runner('openssl', ['version']);
  assert.deepEqual(calls, [{ executable: 'docker-test', args: ['exec', 'staging-nginx', 'openssl', 'version'] }]);
});

test('container probe hashes the host artifact but syntax-checks its in-container path', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-container-runtime-'));
  const config = path.join(root, 'nginx.conf');
  await fs.writeFile(config, 'ssl_ecdh_curve X25519MLKEM768:X25519;\n');
  const calls = [];
  const probe = await probeRuntime('nginx', {
    configPath: config,
    executionConfigPath: '/etc/nginx/nginx.conf',
    runner: successfulRunner(calls)
  });
  assert.equal(probe.verdict.pass, true);
  assert.equal(probe.config.path, path.resolve(config));
  assert.equal(probe.config.executionPath, '/etc/nginx/nginx.conf');
  assert.equal(calls.some((call) => call.args.includes('/etc/nginx/nginx.conf')), true);
  assert.equal(calls.some((call) => call.args.includes(path.resolve(config))), false);
});

for (const server of ['nginx', 'haproxy', 'apache']) {
  test(`runtime probe passes ${server} only with hybrid config, OpenSSL capability, build, and syntax`, async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), `pqc-forge-runtime-${server}-`));
    const config = path.join(root, `${server}.conf`);
    await fs.writeFile(config, 'X25519MLKEM768\n');
    const calls = [];
    const probe = await probeRuntime(server, { configPath: config, runner: successfulRunner(calls), serverExecutable: `${server}-test` });
    assert.equal(probe.verdict.pass, true);
    assert.equal(probe.config.digest.startsWith('sha256:'), true);
    assert.equal(calls.length, 4);
    assert.equal(calls.some((call) => call.args.includes(config)), true);
  });
}

test('runtime probe reports every failed safety condition without throwing away evidence', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-runtime-blocked-'));
  const config = path.join(root, 'nginx.conf');
  await fs.writeFile(config, 'ssl_ecdh_curve X25519;\n');
  const runner = async (executable, args) => {
    if (executable === 'openssl' && args[0] === 'version') return { executable, args, code: 0, stdout: 'OpenSSL 3.4.3', stderr: '', error: null, durationMs: 1 };
    if (executable === 'openssl') return { executable, args, code: 0, stdout: 'X25519', stderr: '', error: null, durationMs: 1 };
    return { executable, args, code: args.includes('-t') ? 1 : 0, stdout: '', stderr: args.includes('-t') ? 'syntax error' : '', error: null, durationMs: 1 };
  };
  const result = await writeRuntimeEvidence('nginx', path.join(root, 'evidence'), { configPath: config, runner });
  assert.equal(result.probe.verdict.pass, false);
  assert.deepEqual(result.probe.verdict.failures.sort(), ['configContainsHybridGroup', 'configSyntaxValid', 'hybridGroupAvailable', 'openSslVersion'].sort());
  assert.equal(verifyReceipt(result.receipt).valid, true);
  assert.match(await fs.readFile(path.join(root, 'evidence', 'RUNTIME_REPORT.md'), 'utf8'), /BLOCKED/);
});

test('PR pack binds only passing runtime evidence matching generated after-content', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-runtime-bind-'));
  const repository = path.join(root, 'repository');
  await fs.mkdir(repository);
  await fs.writeFile(path.join(repository, 'nginx.conf'), 'ssl_protocols TLSv1.2 TLSv1.3;\nssl_ecdh_curve X25519;\n');
  const migration = await migrateRepository(repository, { includeContent: true });
  const patched = path.join(root, 'patched-nginx.conf');
  await fs.writeFile(patched, migration.artifacts[0].afterContent);
  const evidence = await writeRuntimeEvidence('nginx', path.join(root, 'runtime'), { configPath: patched, runner: successfulRunner([]) });
  const result = await createPrPack(repository, path.join(root, 'pack'), { runtimeReceiptPath: path.join(root, 'runtime', 'runtime-receipt.json') });
  assert.equal(result.summary.targetRuntimeEvidenceIncluded, true);
  assert.equal(result.summary.targetRuntimeEvidenceComplete, true);
  assert.deepEqual(result.summary.runtimeCoveredFiles, ['nginx.conf']);
  assert.equal(result.files.includes('runtime-receipt.json'), true);
  await verifyPackArtifacts(path.join(root, 'pack'));

  const unrelated = path.join(root, 'unrelated.conf');
  await fs.writeFile(unrelated, 'X25519MLKEM768 but not the generated configuration\n');
  await writeRuntimeEvidence('nginx', path.join(root, 'unrelated-runtime'), { configPath: unrelated, runner: successfulRunner([]) });
  await assert.rejects(
    () => createPrPack(repository, path.join(root, 'bad-pack'), { runtimeReceiptPath: path.join(root, 'unrelated-runtime', 'runtime-receipt.json') }),
    /does not match a generated post-migration artifact/
  );
  assert.equal(evidence.probe.verdict.pass, true);
});

test('PR pack reports partial and complete runtime coverage across multiple migrated files', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-runtime-coverage-'));
  const repository = path.join(root, 'repository');
  await fs.mkdir(repository);
  await fs.writeFile(path.join(repository, 'nginx.conf'), 'ssl_ecdh_curve X25519;\n');
  await fs.writeFile(path.join(repository, 'haproxy.cfg'), 'global\n  ssl-default-bind-curves X25519:P-256\nfrontend https\n  bind *:443 ssl crt /cert.pem\n');
  const migration = await migrateRepository(repository, { includeContent: true });
  const receipts = [];
  for (const artifact of migration.artifacts) {
    const patched = path.join(root, `patched-${path.basename(artifact.file)}`);
    await fs.writeFile(patched, artifact.afterContent);
    const server = artifact.file === 'nginx.conf' ? 'nginx' : 'haproxy';
    const directory = path.join(root, `runtime-${server}`);
    await writeRuntimeEvidence(server, directory, { configPath: patched, runner: successfulRunner([]) });
    receipts.push(path.join(directory, 'runtime-receipt.json'));
  }
  const partial = await createPrPack(repository, path.join(root, 'partial-pack'), { runtimeReceiptPaths: [receipts[0]] });
  assert.equal(partial.summary.targetRuntimeEvidenceComplete, false);
  assert.equal(partial.summary.runtimeCoveredFiles.length, 1);
  assert.equal(partial.summary.runtimeUncoveredFiles.length, 1);
  const complete = await createPrPack(repository, path.join(root, 'complete-pack'), { runtimeReceiptPaths: receipts });
  assert.equal(complete.summary.targetRuntimeEvidenceComplete, true);
  assert.equal(complete.files.includes('runtime-receipt-1.json'), true);
  assert.equal(complete.files.includes('runtime-receipt-2.json'), true);
  await verifyPackArtifacts(path.join(root, 'complete-pack'));
});
