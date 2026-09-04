import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { createRuntimeReceipt } from './breaklab/receipt.js';

const SERVERS = {
  nginx: { executable: 'nginx', versionArgs: ['-V'], syntaxArgs: (config) => ['-t', '-c', config], tlsLibrary: 'openssl' },
  haproxy: { executable: 'haproxy', versionArgs: ['-vv'], syntaxArgs: (config) => ['-c', '-f', config], tlsLibrary: 'openssl' },
  apache: { executable: process.platform === 'win32' ? 'httpd.exe' : 'apachectl', versionArgs: ['-v'], syntaxArgs: (config) => ['-t', '-f', config], tlsLibrary: 'openssl' },
  // Envoy links a static BoringSSL build, not the host's OpenSSL, so the
  // OpenSSL version/group-list checks below are simply the wrong artifact
  // for it — see the tlsLibrary: 'boringssl' branch in probeRuntime.
  envoy: { executable: 'envoy', versionArgs: ['--version'], syntaxArgs: (config) => ['--mode', 'validate', '-c', config], tlsLibrary: 'boringssl' }
};

const digest = (content) => `sha256:${createHash('sha256').update(content).digest('hex')}`;

function execute(executable, args, { timeoutMs = 15_000 } = {}) {
  return new Promise((resolve) => {
    const started = Date.now();
    const child = spawn(executable, args, { windowsHide: true });
    let stdout = '';
    let stderr = '';
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ executable, args, durationMs: Date.now() - started, stdout: stdout.slice(0, 32_768), stderr: stderr.slice(0, 32_768), ...result });
    };
    const timer = setTimeout(() => {
      child.kill();
      finish({ code: null, error: `timed out after ${timeoutMs}ms` });
    }, timeoutMs);
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.once('error', (error) => finish({ code: null, error: error.message }));
    child.once('close', (code) => finish({ code: code ?? null, error: null }));
  });
}

export function createContainerRunner(container, { dockerExecutable = 'docker', runner = execute } = {}) {
  if (typeof container !== 'string' || !container.trim()) throw new Error('Container name must be a non-empty string.');
  return (executable, args) => runner(dockerExecutable, ['exec', container, executable, ...args]);
}

function parseOpenSslVersion(output) {
  const match = output.match(/\bOpenSSL\s+(\d+)\.(\d+)\.(\d+)/i);
  if (!match) return { raw: output.trim().slice(0, 240), parsed: null, atLeast35: false };
  const parsed = { major: Number(match[1]), minor: Number(match[2]), patch: Number(match[3]) };
  return { raw: match[0], parsed, atLeast35: parsed.major > 3 || (parsed.major === 3 && parsed.minor >= 5) };
}

function publicCommand(result) {
  return {
    executable: result.executable, args: result.args, code: result.code, durationMs: result.durationMs,
    stdout: result.stdout, stderr: result.stderr, error: result.error
  };
}

function renderMarkdown(receipt) {
  const probe = receipt.probe;
  const rows = (probe.tlsLibrary?.name === 'boringssl'
    ? [
      ['Server build reports BoringSSL', probe.checks.tlsLibraryRecognized],
      ['Server executable responds', probe.checks.serverBuildAvailable],
      ['Patched config contains hybrid group', probe.checks.configContainsHybridGroup],
      ['Server syntax accepts patched config', probe.checks.configSyntaxValid]
    ]
    : [
      ['OpenSSL 3.5+', probe.checks.openSslVersion],
      ['X25519MLKEM768 listed', probe.checks.hybridGroupAvailable],
      ['Server executable responds', probe.checks.serverBuildAvailable],
      ['Patched config contains hybrid group', probe.checks.configContainsHybridGroup],
      ['Server syntax accepts patched config', probe.checks.configSyntaxValid]
    ]).map(([name, pass]) => `| ${name} | ${pass ? 'PASS' : 'FAIL'} |`).join('\n');
  return `# PQC Forge target-runtime probe\n\nServer: **${probe.server}**\n\nVerdict: **${probe.verdict.pass ? 'PASS' : 'BLOCKED'}**\n\n| Check | Result |\n|---|---|\n${rows}\n\nThis receipt proves only the commands and configuration tested in this environment. It does not prove client compatibility, load tolerance, canary health, or production readiness.\n\nReceipt: \`${receipt.receiptDigest}\`\n`;
}

async function assertEmptyOutput(output) {
  try {
    const files = await fs.readdir(output);
    if (files.length) throw new Error(`Refusing to overwrite non-empty runtime-probe directory: ${output}`);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
}

export async function probeRuntime(server, options = {}) {
  const definition = SERVERS[server];
  if (!definition) throw new Error(`Unsupported server '${server}'. Expected nginx, haproxy, apache, or envoy.`);
  if (!options.configPath) throw new Error('runtime-probe requires a patched configuration file.');
  const configPath = path.resolve(options.configPath);
  const executionConfigPath = options.executionConfigPath ?? configPath;
  const config = await fs.readFile(configPath);
  const runner = options.runner ?? execute;
  const serverExecutable = options.serverExecutable ?? definition.executable;
  const configContainsHybridGroup = /\bX25519MLKEM768\b/i.test(config.toString('utf8'));

  if (definition.tlsLibrary === 'boringssl') {
    const [serverResult, syntaxResult] = await Promise.all([
      runner(serverExecutable, definition.versionArgs),
      runner(serverExecutable, definition.syntaxArgs(executionConfigPath))
    ]);
    const versionText = `${serverResult.stdout}\n${serverResult.stderr}`;
    const checks = {
      // BoringSSL exposes no CLI to enumerate its supported TLS groups, so
      // unlike the OpenSSL adapters this can only confirm the binary is
      // actually linked against BoringSSL (a precondition for the hybrid
      // group to exist at all) — not that X25519MLKEM768 specifically
      // negotiates. That stronger claim requires a live handshake, which is
      // what `protocol-lab` proves for the reference Envoy build.
      tlsLibraryRecognized: serverResult.code === 0 && /boringssl/i.test(versionText),
      serverBuildAvailable: serverResult.code === 0,
      configContainsHybridGroup,
      configSyntaxValid: syntaxResult.code === 0
    };
    const failures = Object.entries(checks).filter(([, pass]) => !pass).map(([name]) => name);
    return {
      schema: 'pqc-forge.runtime-probe/v1', generatedAt: new Date().toISOString(), server,
      target: options.target ?? 'local-staging-environment',
      config: { path: configPath, executionPath: executionConfigPath, digest: digest(config), bytes: config.length },
      tlsLibrary: { name: 'boringssl', versionCommand: publicCommand(serverResult) },
      serverBuildCommand: publicCommand(serverResult), syntaxCommand: publicCommand(syntaxResult),
      checks, verdict: { pass: failures.length === 0, status: failures.length === 0 ? 'target-runtime-and-syntax-confirmed' : 'blocked', failures }
    };
  }

  const opensslExecutable = options.opensslExecutable ?? 'openssl';
  const [versionResult, groupsResult, serverResult] = await Promise.all([
    runner(opensslExecutable, ['version']),
    runner(opensslExecutable, ['list', '-tls1_3', '-tls-groups']),
    runner(serverExecutable, definition.versionArgs)
  ]);
  const syntaxResult = await runner(serverExecutable, definition.syntaxArgs(executionConfigPath));
  const version = parseOpenSslVersion(`${versionResult.stdout}\n${versionResult.stderr}`);
  const checks = {
    openSslVersion: versionResult.code === 0 && version.atLeast35,
    hybridGroupAvailable: groupsResult.code === 0 && /\bX25519MLKEM768\b/i.test(`${groupsResult.stdout}\n${groupsResult.stderr}`),
    serverBuildAvailable: serverResult.code === 0,
    configContainsHybridGroup,
    configSyntaxValid: syntaxResult.code === 0
  };
  const failures = Object.entries(checks).filter(([, pass]) => !pass).map(([name]) => name);
  return {
    schema: 'pqc-forge.runtime-probe/v1', generatedAt: new Date().toISOString(), server,
    target: options.target ?? 'local-staging-environment',
    config: { path: configPath, executionPath: executionConfigPath, digest: digest(config), bytes: config.length },
    openssl: { version, versionCommand: publicCommand(versionResult), groupsCommand: publicCommand(groupsResult) },
    serverBuildCommand: publicCommand(serverResult), syntaxCommand: publicCommand(syntaxResult),
    checks, verdict: { pass: failures.length === 0, status: failures.length === 0 ? 'target-runtime-and-syntax-confirmed' : 'blocked', failures }
  };
}

export async function writeRuntimeEvidence(server, outputPath, options = {}) {
  if (!options.signingKey) throw new Error('writeRuntimeEvidence requires options.signingKey (see loadSigningKey in src/signing.js or `pqc-forge keygen`).');
  const output = path.resolve(outputPath);
  await assertEmptyOutput(output);
  const probe = await probeRuntime(server, options);
  const receipt = createRuntimeReceipt(probe, options.signingKey);
  await fs.mkdir(output, { recursive: true });
  await fs.writeFile(path.join(output, 'runtime-probe.json'), `${JSON.stringify(probe, null, 2)}\n`, 'utf8');
  await fs.writeFile(path.join(output, 'runtime-receipt.json'), `${JSON.stringify(receipt, null, 2)}\n`, 'utf8');
  await fs.writeFile(path.join(output, 'RUNTIME_REPORT.md'), renderMarkdown(receipt), 'utf8');
  return { output, receipt, probe };
}

export { parseOpenSslVersion };
