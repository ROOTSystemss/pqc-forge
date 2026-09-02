import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { test } from 'node:test';
import { createPrPack } from '../src/pr-pack.js';
import { createProtocolReceipt, verifyReceipt } from '../src/breaklab/receipt.js';

const execute = promisify(execFile);

test('PR pack is non-destructive, verifiable, and produces an apply-ready patch', async () => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-pr-pack-'));
  const repository = path.join(base, 'repository');
  const output = path.join(base, 'output');
  await fs.mkdir(repository);
  const original = 'server {\r\n  ssl_protocols TLSv1 TLSv1.2 TLSv1.3;\r\n  ssl_ecdh_curve X25519;\r\n}\r\n';
  await fs.writeFile(path.join(repository, 'nginx.conf'), original);

  const protocolReceiptPath = path.join(base, 'protocol-receipt.json');
  const protocolReceipt = createProtocolReceipt(
    { schema: 'pqc-forge.protocol-lab-run/v1', verdict: { pass: true }, cases: [] },
    { schema: 'pqc-forge.protocol-matrix/v1', cases: [] }
  );
  await fs.writeFile(protocolReceiptPath, JSON.stringify(protocolReceipt));
  const result = await createPrPack(repository, output, { protocolReceiptPath });
  assert.equal(result.summary.changeCount, 2);
  assert.equal(result.summary.resolvedFindings >= 2, true);
  assert.equal(await fs.readFile(path.join(repository, 'nginx.conf'), 'utf8'), original);
  assert.match(await fs.readFile(path.join(output, 'migration.patch'), 'utf8'), /X25519MLKEM768:X25519/);
  assert.match(await fs.readFile(path.join(output, 'PR_DESCRIPTION.md'), 'utf8'), /PQC migration/);
  assert.equal(result.summary.protocolEvidenceIncluded, true);
  assert.equal(JSON.parse(await fs.readFile(path.join(output, 'protocol-lab-receipt.json'), 'utf8')).receiptDigest, protocolReceipt.receiptDigest);
  const receipt = JSON.parse(await fs.readFile(path.join(output, 'pr-pack-receipt.json'), 'utf8'));
  assert.equal(verifyReceipt(receipt).valid, true);

  const applyRoot = path.join(base, 'apply-check');
  await fs.cp(repository, applyRoot, { recursive: true });
  await execute('git', ['init', '--quiet'], { cwd: applyRoot });
  await execute('git', ['config', 'core.autocrlf', 'true'], { cwd: applyRoot });
  await execute('git', ['apply', '--check', path.join(output, 'migration.patch')], { cwd: applyRoot });
  await execute('git', ['apply', path.join(output, 'migration.patch')], { cwd: applyRoot });
  assert.match(await fs.readFile(path.join(applyRoot, 'nginx.conf'), 'utf8'), /X25519MLKEM768:X25519/);
  await execute('git', ['apply', '--reverse', path.join(output, 'migration.patch')], { cwd: applyRoot });
  assert.equal(await fs.readFile(path.join(applyRoot, 'nginx.conf'), 'utf8'), original);
  await assert.rejects(() => createPrPack(repository, output, { protocolReceiptPath }), /Refusing to overwrite/);
});

test('PR pack preserves a trailing blank context line in a patch hunk', async () => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-pr-blank-'));
  const repository = path.join(base, 'repository');
  const output = path.join(base, 'output');
  await fs.mkdir(repository);
  await fs.writeFile(path.join(repository, 'nginx.conf'), 'server {\n  ssl_protocols TLSv1.2;\n  ssl_ecdh_curve secp384r1;\n\n}\n');
  await createPrPack(repository, output);
  await execute('git', ['init', '--quiet'], { cwd: repository });
  await execute('git', ['-c', 'core.autocrlf=false', 'apply', '--check', path.join(output, 'migration.patch')], { cwd: repository });
});

test('PR pack turns a missing HAProxy group policy into resolved evidence', async () => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-pr-haproxy-'));
  const repository = path.join(base, 'repository');
  const output = path.join(base, 'output');
  await fs.mkdir(repository);
  await fs.writeFile(path.join(repository, 'haproxy.cfg'), 'global\n  daemon\nfrontend https\n  bind *:443 ssl crt /cert.pem\n');
  const result = await createPrPack(repository, output);
  assert.equal(result.summary.changeCount, 1);
  assert.equal(result.summary.resolvedFindings >= 1, true);
  assert.match(await fs.readFile(path.join(output, 'migration.patch'), 'utf8'), /ssl-default-bind-curves X25519MLKEM768/);
});
