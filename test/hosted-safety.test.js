import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { createApiServer, provisionTenant } from '../src/api/server.js';
import { isPrivateAddress, resolvePublicTarget } from '../src/api/hosted-safety.js';
import { generateSigningKey } from '../src/signing.js';
import { createMigrationReceipt } from '../src/breaklab/receipt.js';

// The hosted API is shared by strangers: no request may reach another tenant's
// files, the server's own filesystem, programs on the host, or its private
// network. These tests try each of those through the public HTTP API.

async function startServer(options = {}) {
  const apiHome = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-hosted-'));
  const { server } = createApiServer({ apiHome, ...options });
  await new Promise((resolve) => server.listen(0, resolve));
  return { apiHome, base: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((resolve) => server.close(resolve)) };
}

async function tenant(apiHome, name) {
  const { tenantId, apiKey } = await provisionTenant(apiHome, name);
  return { tenantId, headers: { authorization: `Bearer ${apiKey}`, 'content-type': 'application/json' } };
}

async function post(base, route, headers, body) {
  const response = await fetch(`${base}${route}`, { method: 'POST', headers, body: JSON.stringify(body) });
  return { status: response.status, body: await response.json() };
}

async function runJob(base, headers, type, params) {
  const submitted = await post(base, '/v1/jobs', headers, { type, params });
  if (submitted.status !== 202) return { submitted };
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    const record = await (await fetch(`${base}/v1/jobs/${submitted.body.jobId}`, { headers })).json();
    if (record.status === 'succeeded' || record.status === 'failed') {
      const result = record.status === 'succeeded' ? await (await fetch(`${base}/v1/jobs/${record.jobId}/result`, { headers })).json() : null;
      return { submitted, record, result };
    }
    await new Promise((resolve) => setTimeout(resolve, 40));
  }
  throw new Error('job did not finish');
}

async function migratedWorkspace(base, headers) {
  const upload = await post(base, '/v1/workspaces', headers, { files: [{ path: 'nginx.conf', content: 'ssl_protocols TLSv1.2 TLSv1.3;\nssl_ecdh_curve X25519;\n' }] });
  const { workspaceId } = upload.body;
  const migrated = await runJob(base, headers, 'migrate', { workspaceId, write: true, acknowledgeRuntime: true });
  assert.equal(migrated.record.status, 'succeeded', migrated.record.error);
  return { workspaceId, receipt: migrated.result.receipt };
}

test('rollback through the API still works for the caller\'s own migration', async () => {
  const ctx = await startServer();
  try {
    const alice = await tenant(ctx.apiHome, 'Alice');
    const { workspaceId, receipt } = await migratedWorkspace(ctx.base, alice.headers);
    const rolled = await runJob(ctx.base, alice.headers, 'rollback', { migrationReceipt: receipt, write: true });
    assert.equal(rolled.record.status, 'succeeded', rolled.record.error);
    const restored = await fs.readFile(path.join(ctx.apiHome, 'tenants', alice.tenantId, 'workspaces', workspaceId, 'nginx.conf'), 'utf8');
    assert.match(restored, /ssl_ecdh_curve X25519;/);
    assert.doesNotMatch(restored, /MLKEM/);
  } finally {
    await ctx.close();
  }
});

test('rollback refuses a receipt the caller signed with their own key (it could name any folder on the host)', async () => {
  const ctx = await startServer();
  try {
    const mallory = await tenant(ctx.apiHome, 'Mallory');
    // A file outside every tenant directory that the forged receipt tries to overwrite.
    const victim = path.join(ctx.apiHome, 'server-owned.conf');
    await fs.writeFile(victim, 'original\n');
    const { receipt: genuine } = await migratedWorkspace(ctx.base, mallory.headers);
    const forged = createMigrationReceipt({ ...genuine.migration, root: ctx.apiHome }, generateSigningKey());
    const rolled = await runJob(ctx.base, mallory.headers, 'rollback', { migrationReceipt: forged, write: true });
    assert.equal(rolled.record.status, 'failed');
    assert.match(rolled.record.error, /signer-not-trusted/);
    assert.equal(await fs.readFile(victim, 'utf8'), 'original\n');
  } finally {
    await ctx.close();
  }
});

test('rollback refuses another tenant\'s genuine receipt, so Bob cannot roll back Alice\'s workspace', async () => {
  const ctx = await startServer();
  try {
    const alice = await tenant(ctx.apiHome, 'Alice');
    const bob = await tenant(ctx.apiHome, 'Bob');
    const { workspaceId, receipt } = await migratedWorkspace(ctx.base, alice.headers);
    const rolled = await runJob(ctx.base, bob.headers, 'rollback', { migrationReceipt: receipt, write: true });
    assert.equal(rolled.record.status, 'failed');
    assert.match(rolled.record.error, /outside your own workspaces/);
    const untouched = await fs.readFile(path.join(ctx.apiHome, 'tenants', alice.tenantId, 'workspaces', workspaceId, 'nginx.conf'), 'utf8');
    assert.match(untouched, /MLKEM/, 'Alice\'s migrated file must be unchanged');
  } finally {
    await ctx.close();
  }
});

test('jobs that run programs on the host are off unless the operator enables them', async () => {
  const off = await startServer({ safety: { allowHostExecution: false, allowPrivateTargets: false } });
  try {
    const t = await tenant(off.apiHome, 'Acme');
    for (const type of ['runtime-probe', 'protocol-lab']) {
      const response = await post(off.base, '/v1/jobs', t.headers, { type, params: { server: 'nginx', serverExecutable: 'C:/Windows/System32/cmd.exe' } });
      assert.equal(response.status, 400, type);
      assert.match(response.body.error, /runs programs on the server/);
    }
  } finally {
    await off.close();
  }
  // With the operator's opt-in the job is accepted (a stub handler stands in for the real probe).
  const on = await startServer({ safety: { allowHostExecution: true, allowPrivateTargets: false }, handlers: { 'runtime-probe': async () => ({ ok: true }) } });
  try {
    const t = await tenant(on.apiHome, 'Acme');
    const response = await post(on.base, '/v1/jobs', t.headers, { type: 'runtime-probe', params: {} });
    assert.equal(response.status, 202);
  } finally {
    await on.close();
  }
});

test('verify cannot reach loopback, private networks or cloud metadata through the API', async () => {
  const ctx = await startServer({ safety: { allowHostExecution: false, allowPrivateTargets: false } });
  try {
    const t = await tenant(ctx.apiHome, 'Acme');
    for (const target of ['127.0.0.1:443', 'localhost:8443', '169.254.169.254:443', '10.0.0.5:443', '[::1]:443']) {
      const ran = await runJob(ctx.base, t.headers, 'verify', { target });
      assert.equal(ran.record.status, 'failed', target);
      assert.match(ran.record.error, /only reaches public addresses/, target);
    }
  } finally {
    await ctx.close();
  }
});

test('address rules: private, reserved and mapped addresses are refused; public ones pass', async () => {
  for (const address of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '224.0.0.1', '::1', '::', 'fd00::1', 'fe80::1', '::ffff:127.0.0.1', '64:ff9b::a00:1', 'not-an-ip']) {
    assert.equal(isPrivateAddress(address), true, address);
  }
  for (const address of ['8.8.8.8', '1.1.1.1', '172.32.0.1', '2606:4700:4700::1111']) {
    assert.equal(isPrivateAddress(address), false, address);
  }
  const lookup = async (host) => ({ 'public.example': [{ address: '93.184.216.34' }], 'mixed.example': [{ address: '93.184.216.34' }, { address: '10.0.0.1' }] })[host] ?? [];
  assert.deepEqual(await resolvePublicTarget('public.example:8443', { lookup }), { host: 'public.example', port: 8443, address: '93.184.216.34' });
  await assert.rejects(resolvePublicTarget('mixed.example', { lookup }), /private or reserved/);
  assert.equal((await resolvePublicTarget('10.0.0.1:443', { lookup, allowPrivateTargets: true })).address, '10.0.0.1');
  await assert.rejects(resolvePublicTarget('', { lookup }), /requires a target/);
});
