import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseOpenSslEvidence } from './parser.js';

const projectRoot = path.dirname(path.dirname(path.dirname(fileURLToPath(import.meta.url))));
const composeFile = path.join(projectRoot, 'lab', 'compose.yml');

export function resolveDockerCommand({ platform = process.platform, env = process.env, fileExists = existsSync } = {}) {
  if (env.PQC_FORGE_DOCKER) return env.PQC_FORGE_DOCKER;
  if (platform === 'win32') {
    const programFiles = env.ProgramFiles || 'C:\\Program Files';
    const desktopCli = path.win32.join(programFiles, 'Docker', 'Docker', 'resources', 'bin', 'docker.exe');
    if (fileExists(desktopCli)) return desktopCli;
  }
  return 'docker';
}

export function explainDockerFailure(detail = '') {
  const normalized = detail.toLowerCase();
  if (/enoent|not recognized|not found|cannot find/.test(normalized)) {
    return { code: 'DOCKER_CLI_MISSING', action: 'Install Docker Desktop or set PQC_FORGE_DOCKER to the Docker CLI path.' };
  }
  if (/permission denied|access is denied/.test(normalized)) {
    return { code: 'DOCKER_PERMISSION_DENIED', action: 'Sign out and back in so docker-users group membership is applied, then reopen Docker Desktop.' };
  }
  if (/docker_engine|daemon|engine.*(stopped|running)|_ping|503/.test(normalized)) {
    return { code: 'DOCKER_ENGINE_UNAVAILABLE', action: 'Start Docker Desktop and wait until the engine reports Running.' };
  }
  if (/compose/.test(normalized)) {
    return { code: 'DOCKER_COMPOSE_UNAVAILABLE', action: 'Install or enable the Docker Compose plugin.' };
  }
  return { code: 'DOCKER_UNAVAILABLE', action: 'Run pqc-forge doctor and inspect the Docker diagnostic detail.' };
}

export const PROTOCOL_CASES = [
  { name: 'hybrid-client-to-hybrid-server', target: 'hybrid-rsa:443', groups: 'X25519MLKEM768:X25519', requirePqKeyExchange: true, requirePqAuthentication: false, expectedFindings: [] },
  { name: 'legacy-client-fallback', target: 'hybrid-rsa:443', groups: 'X25519', requirePqKeyExchange: true, requirePqAuthentication: false, expectedFindings: ['CLASSICAL_DOWNGRADE'] },
  { name: 'legacy-client-to-pq-only-server', target: 'pqonly-rsa:443', groups: 'X25519', requirePqKeyExchange: true, requirePqAuthentication: false, expectedFindings: ['HANDSHAKE_FAILED'] },
  { name: 'hybrid-client-to-classical-server', target: 'classical-rsa:443', groups: 'X25519MLKEM768:X25519', requirePqKeyExchange: true, requirePqAuthentication: false, expectedFindings: ['CLASSICAL_DOWNGRADE'] },
  { name: 'full-pq-client-and-server', target: 'hybrid-mldsa:443', groups: 'X25519MLKEM768:X25519', requirePqKeyExchange: true, requirePqAuthentication: true, expectedFindings: [] },
  // Same four negotiation scenarios as the nginx/OpenSSL cases above,
  // against the official Envoy image instead — proves the hybrid group
  // actually negotiates through Envoy's statically linked BoringSSL, not
  // just through the OpenSSL/nginx build this project compiles itself.
  { name: 'envoy-hybrid-client-to-hybrid-server', target: 'envoy-hybrid:443', groups: 'X25519MLKEM768:X25519', requirePqKeyExchange: true, requirePqAuthentication: false, expectedFindings: [] },
  { name: 'envoy-legacy-client-fallback', target: 'envoy-hybrid:443', groups: 'X25519', requirePqKeyExchange: true, requirePqAuthentication: false, expectedFindings: ['CLASSICAL_DOWNGRADE'] },
  { name: 'envoy-legacy-client-to-pq-only-server', target: 'envoy-pqonly:443', groups: 'X25519', requirePqKeyExchange: true, requirePqAuthentication: false, expectedFindings: ['HANDSHAKE_FAILED'] },
  { name: 'envoy-hybrid-client-to-classical-server', target: 'envoy-classical:443', groups: 'X25519MLKEM768:X25519', requirePqKeyExchange: true, requirePqAuthentication: false, expectedFindings: ['CLASSICAL_DOWNGRADE'] }
];

const ENVOY_IMAGE_DIGEST = 'sha256:3a76238cdf52c7a3e33951f44c02d694108e6481feffe6663bf9319f55ec1394'; // envoyproxy/envoy v1.36.10 (BoringSSL), resolved 2026-09-03

function execute(file, args, { cwd = projectRoot, timeoutMs = 180000 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(file, args, { cwd, windowsHide: true });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => child.kill(), timeoutMs);
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.once('error', (error) => { clearTimeout(timer); reject(error); });
    child.once('close', (code) => { clearTimeout(timer); resolve({ code: code ?? 1, stdout, stderr }); });
    child.stdin.end();
  });
}

const composeArgs = (...args) => ['compose', '-f', composeFile, '--project-name', 'pqc-forge-lab', ...args];

async function runCase(testCase) {
  const args = composeArgs('run', '--rm', '--no-deps', '--entrypoint', '/opt/openssl/bin/openssl', 'client',
    's_client', '-connect', testCase.target, '-servername', testCase.target.split(':')[0], '-tls1_3', '-groups', testCase.groups, '-brief');
  let execution;
  for (let attempt = 1; attempt <= 4; attempt += 1) {
    execution = await execute(resolveDockerCommand(), args, { timeoutMs: 30000 });
    if (execution.code === 0 || attempt === 4) break;
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  const evidence = parseOpenSslEvidence(`${execution.stdout}\n${execution.stderr}`, execution.code, testCase);
  const observed = evidence.findings.map((finding) => finding.code).sort();
  const expected = [...testCase.expectedFindings].sort();
  return {
    ...evidence, expectedFindings: expected,
    missingExpectedFindings: expected.filter((code) => !observed.includes(code)),
    unexpectedFindings: observed.filter((code) => !expected.includes(code)),
    expectationMet: expected.length === observed.length && expected.every((code, index) => code === observed[index])
  };
}

export async function dockerStatus() {
  const command = resolveDockerCommand();
  try {
    const compose = await execute(command, ['compose', 'version'], { timeoutMs: 10000 });
    if (compose.code !== 0) {
      const detail = (compose.stderr || compose.stdout).trim();
      return { ready: false, command, ...explainDockerFailure(detail), detail };
    }
    const engine = await execute(command, ['info', '--format', '{{.ServerVersion}}|{{.OSType}}'], { timeoutMs: 15000 });
    if (engine.code !== 0) {
      const detail = (engine.stderr || engine.stdout).trim();
      return { ready: false, command, compose: (compose.stdout || compose.stderr).trim(), ...explainDockerFailure(detail), detail };
    }
    const [serverVersion, osType] = engine.stdout.trim().split('|');
    return {
      ready: true, code: 'READY', command,
      compose: (compose.stdout || compose.stderr).trim(), serverVersion, osType,
      detail: `Docker ${serverVersion} (${osType}) is ready.`
    };
  } catch (error) {
    return { ready: false, command, ...explainDockerFailure(error.message), detail: error.message };
  }
}

export async function runDockerProtocolLab() {
  const status = await dockerStatus();
  if (!status.ready) throw new Error(`${status.code}: ${status.detail}\nAction: ${status.action}`);
  const docker = status.command;
  const build = await execute(docker, composeArgs('build'), { timeoutMs: 900000 });
  if (build.code !== 0) throw new Error(`Protocol lab image build failed: ${(build.stderr || build.stdout).slice(-4000)}`);
  const certInit = await execute(docker, composeArgs('run', '--rm', 'envoy-cert-init'), { timeoutMs: 60000 });
  if (certInit.code !== 0) throw new Error(`Envoy cert generation failed: ${(certInit.stderr || certInit.stdout).slice(-4000)}`);
  const started = await execute(docker, composeArgs('up', '-d',
    'classical-rsa', 'hybrid-rsa', 'pqonly-rsa', 'hybrid-mldsa',
    'envoy-hybrid', 'envoy-pqonly', 'envoy-classical'), { timeoutMs: 120000 });
  const results = [];
  let serviceState = null;
  let serviceLogs = null;
  try {
    if (started.code !== 0) throw new Error(`Protocol lab services failed to start: ${(started.stderr || started.stdout).slice(-4000)}`);
    const requiredServices = ['classical-rsa', 'hybrid-rsa', 'pqonly-rsa', 'hybrid-mldsa', 'envoy-hybrid', 'envoy-pqonly', 'envoy-classical'];
    let runningServices = [];
    for (let attempt = 1; attempt <= 10; attempt += 1) {
      const running = await execute(docker, composeArgs('ps', '--status', 'running', '--services'), { timeoutMs: 30000 });
      runningServices = running.stdout.split(/\r?\n/).map((item) => item.trim()).filter(Boolean);
      if (requiredServices.every((service) => runningServices.includes(service))) break;
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
    const [state, logs] = await Promise.all([
      execute(docker, composeArgs('ps', '--all'), { timeoutMs: 30000 }),
      execute(docker, composeArgs('logs', '--no-color'), { timeoutMs: 30000 })
    ]);
    serviceState = `${state.stdout}\n${state.stderr}`.trim();
    serviceLogs = `${logs.stdout}\n${logs.stderr}`.trim();
    if (!requiredServices.every((service) => runningServices.includes(service))) {
      throw new Error(`Protocol lab servers did not remain running.\n${serviceState}\n${serviceLogs}`);
    }
    for (const testCase of PROTOCOL_CASES) results.push(await runCase(testCase));
  } finally {
    await execute(docker, composeArgs('down', '--volumes', '--remove-orphans'), { timeoutMs: 120000 }).catch(() => {});
  }
  const highestSeverity = Math.max(0, ...results.map((result) => result.severity));
  const unexpectedHighestSeverity = Math.max(0, ...results.flatMap((result) => result.findings.filter((finding) => result.unexpectedFindings.includes(finding.code)).map((finding) => finding.severity)));
  return {
    schema: 'pqc-forge.protocol-lab-run/v1', generatedAt: new Date().toISOString(),
    components: { openssl: '3.5.8', nginx: '1.30.4', envoy: '1.36.10', envoyImageDigest: ENVOY_IMAGE_DIGEST },
    services: { state: serviceState, logs: serviceLogs }, cases: results,
    verdict: {
      pass: results.every((result) => result.expectationMet), highestSeverity, unexpectedHighestSeverity,
      failureModes: [...new Set(results.flatMap((result) => result.findings.map((finding) => finding.code)))].sort(),
      failedExpectations: results.filter((result) => !result.expectationMet).map((result) => result.name)
    }
  };
}
