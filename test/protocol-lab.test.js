import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseOpenSslEvidence } from '../src/protocol-lab/parser.js';
import { explainDockerFailure, PROTOCOL_CASES, resolveDockerCommand } from '../src/protocol-lab/docker.js';
import { createProtocolReceipt, verifyReceipt } from '../src/breaklab/receipt.js';
import { generateSigningKey } from '../src/signing.js';
import { renderProtocolLabHtml } from '../src/protocol-lab/report.js';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const projectRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

test('OpenSSL parser recognizes hybrid ML-KEM evidence', () => {
  const testCase = { name: 'hybrid', target: 'server:443', groups: 'X25519MLKEM768:X25519', requirePqKeyExchange: true, requirePqAuthentication: false };
  const evidence = parseOpenSslEvidence('Protocol version: TLSv1.3\nNegotiated TLS1.3 group: X25519MLKEM768\nPeer signature type: RSA-PSS', 0, testCase);
  assert.equal(evidence.pqKeyExchangeObserved, true);
  assert.equal(evidence.findings.length, 0);
});

test('OpenSSL parser identifies downgrade and failed handshake controls', () => {
  const downgrade = parseOpenSslEvidence('Protocol version: TLSv1.3\nPeer Temp Key: X25519, 253 bits', 0, { name: 'downgrade', target: 'x', groups: 'X25519', requirePqKeyExchange: true, requirePqAuthentication: false });
  assert.equal(downgrade.handshakeSucceeded, true);
  assert.equal(downgrade.negotiatedGroup, 'X25519');
  assert.ok(downgrade.findings.some((finding) => finding.code === 'CLASSICAL_DOWNGRADE'));
  const failed = parseOpenSslEvidence('no suitable key share', 1, { name: 'failed', target: 'x', groups: 'X25519', requirePqKeyExchange: true, requirePqAuthentication: false });
  assert.equal(failed.handshakeSucceeded, false);
  assert.ok(failed.findings.some((finding) => finding.code === 'HANDSHAKE_FAILED'));
});

test('protocol matrix and receipt are fixed, verifiable, and presentable', () => {
  assert.equal(PROTOCOL_CASES.length, 5);
  assert.ok(PROTOCOL_CASES.every((item) => Array.isArray(item.expectedFindings)));
  const run = { schema: 'pqc-forge.protocol-lab-run/v1', components: { openssl: '3.5.8', nginx: '1.30.4' }, cases: [], verdict: { pass: true } };
  const receipt = createProtocolReceipt(run, PROTOCOL_CASES, generateSigningKey());
  assert.equal(verifyReceipt(receipt).valid, true);
  assert.match(renderProtocolLabHtml(receipt), /Real protocol evidence/);
});

test('Docker preflight resolves Windows Desktop and explains common blockers', () => {
  const expected = 'C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe';
  const resolved = resolveDockerCommand({
    platform: 'win32', env: { ProgramFiles: 'C:\\Program Files' }, fileExists: (candidate) => candidate === expected
  });
  assert.equal(resolved, expected);
  assert.equal(explainDockerFailure('permission denied while connecting to docker_engine').code, 'DOCKER_PERMISSION_DENIED');
  assert.equal(explainDockerFailure('failed to connect to the docker daemon').code, 'DOCKER_ENGINE_UNAVAILABLE');
});

test('protocol image installs the OpenSSL provider configuration and checks it at startup', async () => {
  const dockerfile = await fs.readFile(path.join(projectRoot, 'lab', 'Dockerfile'), 'utf8');
  const entrypoint = await fs.readFile(path.join(projectRoot, 'lab', 'entrypoint.sh'), 'utf8');
  assert.match(dockerfile, /apps\/openssl\.cnf/);
  assert.match(dockerfile, /OPENSSL_CONF/);
  assert.match(entrypoint, /test -r "\$OPENSSL_CONF"/);
});
