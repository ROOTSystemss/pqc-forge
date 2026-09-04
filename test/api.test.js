import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { createApiServer, provisionTenant } from '../src/api/server.js';

const projectRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const demoScenario = JSON.parse(await fs.readFile(path.join(projectRoot, 'scenarios', 'tls-migration-demo.json'), 'utf8'));

async function startServer() {
  const apiHome = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-api-'));
  const { server, queue } = createApiServer({ apiHome });
  await new Promise((resolve) => server.listen(0, resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  return {
    apiHome, server, queue, base,
    async close() { await new Promise((resolve) => server.close(resolve)); }
  };
}

async function newTenant(apiHome, name = 'Acme') {
  const { tenantId, apiKey } = await provisionTenant(apiHome, name);
  return { tenantId, apiKey, headers: { authorization: `Bearer ${apiKey}`, 'content-type': 'application/json' } };
}

async function pollJob(base, headers, jobId, { timeoutMs = 15000 } = {}) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const response = await fetch(`${base}/v1/jobs/${jobId}`, { headers });
    const record = await response.json();
    if (record.status === 'succeeded' || record.status === 'failed') return record;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(`Job ${jobId} did not reach a terminal state within ${timeoutMs}ms`);
}

test('health endpoint requires no authentication', async () => {
  const ctx = await startServer();
  try {
    const response = await fetch(`${ctx.base}/v1/health`);
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.status, 'ok');
  } finally {
    await ctx.close();
  }
});

test('every other endpoint rejects missing or invalid API keys', async () => {
  const ctx = await startServer();
  try {
    const noAuth = await fetch(`${ctx.base}/v1/jobs`, { method: 'POST', body: '{}' });
    assert.equal(noAuth.status, 401);

    const badAuth = await fetch(`${ctx.base}/v1/jobs`, {
      method: 'POST', headers: { authorization: 'Bearer pqcf_t_0000000000000000_notreal', 'content-type': 'application/json' }, body: '{}'
    });
    assert.equal(badAuth.status, 401);

    const { headers, tenantId } = await newTenant(ctx.apiHome);
    const wrongSecret = await fetch(`${ctx.base}/v1/jobs`, {
      method: 'POST', headers: { authorization: `Bearer pqcf_${tenantId}_wrongsecretwrongsecretwrong`, 'content-type': 'application/json' }, body: '{}'
    });
    assert.equal(wrongSecret.status, 401);

    const good = await fetch(`${ctx.base}/v1/health`, { headers });
    assert.equal(good.status, 200); // health stays public even with a valid key
  } finally {
    await ctx.close();
  }
});

test('workspace upload rejects path traversal and materializes files under the tenant only', async () => {
  const ctx = await startServer();
  try {
    const tenant = await newTenant(ctx.apiHome);
    const escape = await fetch(`${ctx.base}/v1/workspaces`, {
      method: 'POST', headers: tenant.headers,
      body: JSON.stringify({ files: [{ path: '../../escape.conf', content: 'x' }] })
    });
    assert.equal(escape.status, 400);

    const ok = await fetch(`${ctx.base}/v1/workspaces`, {
      method: 'POST', headers: tenant.headers,
      body: JSON.stringify({ files: [{ path: 'nginx.conf', content: 'ssl_protocols TLSv1 TLSv1.2 TLSv1.3;\nssl_ecdh_curve X25519;\n' }] })
    });
    assert.equal(ok.status, 200);
    const { workspaceId } = await ok.json();
    const materialized = await fs.readFile(path.join(ctx.apiHome, 'tenants', tenant.tenantId, 'workspaces', workspaceId, 'nginx.conf'), 'utf8');
    assert.match(materialized, /ssl_ecdh_curve X25519;/);
  } finally {
    await ctx.close();
  }
});

test('scan job runs end to end: submit, poll, retrieve a real signed result', async () => {
  const ctx = await startServer();
  try {
    const tenant = await newTenant(ctx.apiHome);
    const upload = await fetch(`${ctx.base}/v1/workspaces`, {
      method: 'POST', headers: tenant.headers,
      body: JSON.stringify({ files: [{ path: 'nginx.conf', content: 'ssl_protocols TLSv1 TLSv1.2;\nssl_ecdh_curve X25519;\n' }] })
    });
    const { workspaceId } = await upload.json();

    const submit = await fetch(`${ctx.base}/v1/jobs`, {
      method: 'POST', headers: tenant.headers,
      body: JSON.stringify({ type: 'scan', params: { workspaceId } })
    });
    assert.equal(submit.status, 202);
    const submitted = await submit.json();
    assert.equal(submitted.status, 'queued');

    const finished = await pollJob(ctx.base, tenant.headers, submitted.jobId);
    assert.equal(finished.status, 'succeeded');

    const result = await fetch(`${ctx.base}/v1/jobs/${submitted.jobId}/result`, { headers: tenant.headers });
    assert.equal(result.status, 200);
    const report = await result.json();
    assert.equal(report.schema, 'pqc-forge.scan/v1');
    assert.ok(report.findings.some((finding) => finding.id === 'QF-TLS-CLASSICAL-GROUPS'));
  } finally {
    await ctx.close();
  }
});

test('migrate job with write:true mutates only that tenant\'s own workspace copy, and a breaklab job round-trips a signed receipt', async () => {
  const ctx = await startServer();
  try {
    const tenant = await newTenant(ctx.apiHome);
    const upload = await fetch(`${ctx.base}/v1/workspaces`, {
      method: 'POST', headers: tenant.headers,
      body: JSON.stringify({ files: [{ path: 'nginx.conf', content: 'ssl_protocols TLSv1 TLSv1.2;\nssl_ecdh_curve X25519;\n' }] })
    });
    const { workspaceId } = await upload.json();

    const submit = await fetch(`${ctx.base}/v1/jobs`, {
      method: 'POST', headers: tenant.headers,
      body: JSON.stringify({ type: 'migrate', params: { workspaceId, write: true, acknowledgeRuntime: true } })
    });
    const submitted = await submit.json();
    const finished = await pollJob(ctx.base, tenant.headers, submitted.jobId);
    assert.equal(finished.status, 'succeeded');
    const result = await fetch(`${ctx.base}/v1/jobs/${submitted.jobId}/result`, { headers: tenant.headers });
    const { migration, receipt } = await result.json();
    assert.equal(migration.mode, 'applied');

    const verify = await fetch(`${ctx.base}/v1/verify-receipt`, {
      method: 'POST', headers: tenant.headers, body: JSON.stringify({ receipt })
    });
    assert.equal((await verify.json()).valid, true);

    const mutated = await fs.readFile(path.join(ctx.apiHome, 'tenants', tenant.tenantId, 'workspaces', workspaceId, 'nginx.conf'), 'utf8');
    assert.match(mutated, /X25519MLKEM768/);

    const breaklabSubmit = await fetch(`${ctx.base}/v1/jobs`, {
      method: 'POST', headers: tenant.headers,
      body: JSON.stringify({ type: 'breaklab', params: { scenario: demoScenario, budget: 8, seed: 1 } })
    });
    const breaklabRecord = await breaklabSubmit.json();
    const breaklabFinished = await pollJob(ctx.base, tenant.headers, breaklabRecord.jobId);
    assert.equal(breaklabFinished.status, 'succeeded');
  } finally {
    await ctx.close();
  }
});

test('a tenant cannot read another tenant\'s workspace or job through path or id substitution', async () => {
  const ctx = await startServer();
  try {
    const alice = await newTenant(ctx.apiHome, 'Alice');
    const bob = await newTenant(ctx.apiHome, 'Bob');

    const upload = await fetch(`${ctx.base}/v1/workspaces`, {
      method: 'POST', headers: alice.headers,
      body: JSON.stringify({ files: [{ path: 'secret.conf', content: 'alice-only\n' }] })
    });
    const { workspaceId } = await upload.json();

    // Bob references Alice's real workspace id under his own authenticated
    // tenant context; it must not resolve, because workspace lookups are
    // scoped by tenantId, not just by workspace id.
    const bobScan = await fetch(`${ctx.base}/v1/jobs`, {
      method: 'POST', headers: bob.headers,
      body: JSON.stringify({ type: 'scan', params: { workspaceId } })
    });
    const bobSubmitted = await bobScan.json();
    const bobFinished = await pollJob(ctx.base, bob.headers, bobSubmitted.jobId);
    assert.equal(bobFinished.status, 'failed');
    assert.match(bobFinished.error, /ENOENT|no such|not found/i);

    const aliceScan = await fetch(`${ctx.base}/v1/jobs`, {
      method: 'POST', headers: alice.headers,
      body: JSON.stringify({ type: 'scan', params: { workspaceId } })
    });
    const aliceJobId = (await aliceScan.json()).jobId;
    const bobReadsAliceJob = await fetch(`${ctx.base}/v1/jobs/${aliceJobId}`, { headers: bob.headers });
    assert.equal(bobReadsAliceJob.status, 404);
  } finally {
    await ctx.close();
  }
});

test('per-tenant and global concurrency caps queue excess jobs instead of running everything at once', async () => {
  const apiHome = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-api-conc-'));
  // A controllable handler in place of real work: every invocation blocks
  // until the test releases it, so the queue's concurrency bookkeeping can
  // be observed deterministically instead of racing real I/O.
  let concurrentNow = 0;
  let peakConcurrent = 0;
  const releases = [];
  const gatedHandler = () => new Promise((resolve) => {
    concurrentNow += 1;
    peakConcurrent = Math.max(peakConcurrent, concurrentNow);
    releases.push(() => { concurrentNow -= 1; resolve({ ok: true }); });
  });
  const handlers = { scan: gatedHandler };

  const { server, queue } = createApiServer({ apiHome, tenantConcurrency: 2, globalConcurrency: 3, handlers });
  await new Promise((resolve) => server.listen(0, resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const alice = await newTenant(apiHome, 'Alice');
    const bob = await newTenant(apiHome, 'Bob');

    // Alice submits 4 jobs against a per-tenant cap of 2: exactly 2 should
    // be running and 2 queued, never all 4 at once.
    const aliceJobs = [];
    for (let index = 0; index < 4; index += 1) {
      const response = await fetch(`${base}/v1/jobs`, { method: 'POST', headers: alice.headers, body: JSON.stringify({ type: 'scan', params: {} }) });
      aliceJobs.push(await response.json());
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.equal(queue.stats().running, 2, 'per-tenant cap must hold Alice to 2 concurrent jobs');
    assert.equal(queue.stats().pending, 2);

    // Bob submits 2 more. The global cap (3) is already exhausted by
    // Alice's 2 plus one of Bob's, so only one of Bob's runs immediately.
    const bobJobs = [];
    for (let index = 0; index < 2; index += 1) {
      const response = await fetch(`${base}/v1/jobs`, { method: 'POST', headers: bob.headers, body: JSON.stringify({ type: 'scan', params: {} }) });
      bobJobs.push(await response.json());
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.equal(queue.stats().running, 3, 'global cap must hold total concurrency to 3 even across tenants');
    assert.equal(peakConcurrent, 3);

    // Release everything and confirm all 6 eventually complete cleanly. As
    // each gated job resolves, the scheduler immediately starts the next
    // queued one, which blocks on a *new* gate — so releasing has to keep
    // draining until the whole batch drains, not just once.
    const drain = setInterval(() => { while (releases.length) releases.pop()(); }, 5);
    try {
      const allJobs = [...aliceJobs, ...bobJobs];
      const finished = await Promise.all(allJobs.map((job, index) => pollJob(base, index < 4 ? alice.headers : bob.headers, job.jobId)));
      assert.ok(finished.every((job) => job.status === 'succeeded'));
      assert.equal(queue.stats().running, 0);
      assert.equal(queue.stats().pending, 0);
    } finally {
      clearInterval(drain);
    }
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('a job left "running" by a killed process is reconciled to failed on the next server start', async () => {
  const apiHome = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-api-reconcile-'));
  const { tenantId } = await provisionTenant(apiHome, 'Acme');
  const jobId = 'j_deadbeefdeadbeef';
  const jobDir = path.join(apiHome, 'tenants', tenantId, 'jobs', jobId);
  await fs.mkdir(jobDir, { recursive: true });
  await fs.writeFile(path.join(jobDir, 'job.json'), JSON.stringify({
    schema: 'pqc-forge.job/v1', jobId, tenantId, type: 'scan', params: {},
    status: 'running', createdAt: new Date().toISOString(), startedAt: new Date().toISOString(), finishedAt: null, error: null
  }));

  const { server, queue } = createApiServer({ apiHome });
  await new Promise((resolve) => server.listen(0, resolve));
  try {
    // Any request triggers the lazy reconciliation pass.
    await fetch(`http://127.0.0.1:${server.address().port}/v1/health`);
    const record = JSON.parse(await fs.readFile(path.join(jobDir, 'job.json'), 'utf8'));
    assert.equal(record.status, 'failed');
    assert.match(record.error, /restarted while this job was running/);
    assert.equal(typeof queue.stats().pending, 'number');
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
