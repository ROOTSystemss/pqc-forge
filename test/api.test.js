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

test('breaklab-grid job resolves the real client×server matrix incrementally, observable mid-run', async () => {
  const ctx = await startServer();
  try {
    const tenant = await newTenant(ctx.apiHome);
    const submit = await fetch(`${ctx.base}/v1/jobs`, {
      method: 'POST', headers: tenant.headers,
      // A real (if short) pace between cells so a poller mid-run can
      // observe a genuinely partial `progress`, not just queued/succeeded.
      body: JSON.stringify({ type: 'breaklab-grid', params: { scenario: demoScenario, paceMs: 60 } })
    });
    const submitted = await submit.json();
    assert.equal(submitted.status, 'queued');
    assert.equal(submitted.progress, null);

    // Poll once shortly after submission: with 9 cells (3 clients × 3
    // servers) at 60ms apart, this should land mid-run with some cells
    // resolved and fewer than the total — proof this is real incremental
    // progress, not a single atomic jump from empty to complete.
    await new Promise((resolve) => setTimeout(resolve, 150));
    const midRun = await (await fetch(`${ctx.base}/v1/jobs/${submitted.jobId}`, { headers: tenant.headers })).json();
    assert.equal(midRun.progress.total, 9);
    assert.ok(midRun.progress.completed > 0, 'expected at least one cell resolved by now');
    assert.ok(midRun.progress.completed < midRun.progress.total, 'expected the run to still be mid-flight, not already complete');
    assert.equal(midRun.progress.cells.length, midRun.progress.completed);

    const finished = await pollJob(ctx.base, tenant.headers, submitted.jobId, { timeoutMs: 5000 });
    assert.equal(finished.status, 'succeeded');
    assert.equal(finished.progress.completed, 9);

    const result = await (await fetch(`${ctx.base}/v1/jobs/${submitted.jobId}/result`, { headers: tenant.headers })).json();
    assert.equal(result.schema, 'pqc-forge.breaklab-grid/v1');
    assert.deepEqual(result.dimensions.client, demoScenario.dimensions.client);
    assert.deepEqual(result.dimensions.server, demoScenario.dimensions.server);
    assert.equal(result.cells.length, 9);
    // Cross-check one real cell against the engine's own pure function
    // directly, so this test would fail if the handler ever diverged from
    // real evaluation (e.g. started faking results).
    const { evaluateCandidate, validateScenario } = await import('../src/breaklab/engine.js');
    const scenario = validateScenario(demoScenario);
    const expectedCell = result.cells[0];
    const directEval = evaluateCandidate(scenario, { client: expectedCell.client, server: expectedCell.server, ...result.fixed });
    assert.equal(expectedCell.negotiatedGroup, directEval.negotiatedGroup);
    assert.deepEqual(expectedCell.findings, directEval.findings);
  } finally {
    await ctx.close();
  }
});

test('breaklab-grid rejects a scenario whose client×server matrix exceeds the cell cap, and clamps an oversized pace', async () => {
  const ctx = await startServer();
  try {
    const tenant = await newTenant(ctx.apiHome);
    // 65 clients x 65 servers = 4225 cells, one over the 4096 cap - built
    // programmatically since validateScenario requires a real profile entry
    // for every dimension value, not just a long dimension array.
    const oversized = structuredClone(demoScenario);
    const clientNames = Array.from({ length: 65 }, (_, i) => `client-${i}`);
    const serverNames = Array.from({ length: 65 }, (_, i) => `server-${i}`);
    oversized.dimensions.client = clientNames;
    oversized.dimensions.server = serverNames;
    for (const name of clientNames) oversized.profiles.clients[name] = { groups: ['X25519'], signatures: ['RSA-PSS'] };
    for (const name of serverNames) oversized.profiles.servers[name] = { groups: ['X25519'] };

    const submit = await fetch(`${ctx.base}/v1/jobs`, {
      method: 'POST', headers: tenant.headers,
      body: JSON.stringify({ type: 'breaklab-grid', params: { scenario: oversized } })
    });
    const submitted = await submit.json();
    const finished = await pollJob(ctx.base, tenant.headers, submitted.jobId, { timeoutMs: 5000 });
    assert.equal(finished.status, 'failed');
    assert.match(finished.error, /4225 client×server cells.*limit is 4096/);

    // A tenant-supplied paceMs of an hour must not be allowed to pin a
    // concurrency slot for anywhere near that long - it should clamp to
    // the 2000ms cap. The first cell resolves immediately (the pace delay
    // comes *after* each cell), so after ~2.2s an unclamped hour-long pace
    // would still show exactly 1 cell done - clamping shows a 2nd.
    const clamped = await fetch(`${ctx.base}/v1/jobs`, {
      method: 'POST', headers: tenant.headers,
      body: JSON.stringify({ type: 'breaklab-grid', params: { scenario: demoScenario, paceMs: 60 * 60 * 1000 } })
    });
    const clampedSubmitted = await clamped.json();
    await new Promise((resolve) => setTimeout(resolve, 2200));
    const midRun = await (await fetch(`${ctx.base}/v1/jobs/${clampedSubmitted.jobId}`, { headers: tenant.headers })).json();
    assert.equal(midRun.status, 'running');
    assert.ok(midRun.progress.completed >= 2, `expected paceMs to be clamped to 2000ms (>=2 cells by now), got ${midRun.progress.completed}`);
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

test('a malformed job id is rejected by an explicit format check, not left to path.join and the router alone', async () => {
  const ctx = await startServer();
  try {
    const tenant = await newTenant(ctx.apiHome);
    // None of these have a real path-traversal effect given how the HTTP
    // router and path.join each behave (verified separately) - the point of
    // this test is that job lookups reject anything not shaped like a real
    // generated job id by explicit check, the same way workspaceId already
    // does, rather than relying on those other layers' behavior to remain
    // safe. A regression here (e.g. someone switching jobDirectory to
    // path.resolve) would be caught by "traversal-shaped" cases at minimum.
    for (const malformed of ['..', 'j_deadbeefdeadbee', 'j_deadbeefdeadbeefextra', '../../etc/passwd', 'not-a-job-id']) {
      const response = await fetch(`${ctx.base}/v1/jobs/${encodeURIComponent(malformed)}`, { headers: tenant.headers });
      assert.equal(response.status, 404, `expected 404 for job id ${JSON.stringify(malformed)}`);
    }
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

test('GET /v1/jobs lists only the caller\'s own jobs, newest first, filterable by type and status', async () => {
  const ctx = await startServer();
  try {
    const tenant = await newTenant(ctx.apiHome);
    const other = await newTenant(ctx.apiHome, 'Other');

    const jobIds = [];
    for (const budget of [4, 8]) {
      const submit = await fetch(`${ctx.base}/v1/jobs`, {
        method: 'POST', headers: tenant.headers,
        body: JSON.stringify({ type: 'breaklab', params: { scenario: demoScenario, budget, seed: 1 } })
      });
      const { jobId } = await submit.json();
      jobIds.push(jobId);
      await pollJob(ctx.base, tenant.headers, jobId);
    }
    // A job belonging to a different tenant must never appear in this list.
    const otherSubmit = await fetch(`${ctx.base}/v1/jobs`, {
      method: 'POST', headers: other.headers,
      body: JSON.stringify({ type: 'breaklab', params: { scenario: demoScenario, budget: 4, seed: 1 } })
    });
    await pollJob(ctx.base, other.headers, (await otherSubmit.json()).jobId);

    const listed = await (await fetch(`${ctx.base}/v1/jobs`, { headers: tenant.headers })).json();
    assert.equal(listed.total, 2);
    assert.deepEqual(listed.jobs.map((job) => job.jobId), [...jobIds].reverse());
    assert.ok(listed.jobs.every((job) => job.tenantId === tenant.tenantId));

    const limited = await (await fetch(`${ctx.base}/v1/jobs?limit=1`, { headers: tenant.headers })).json();
    assert.equal(limited.jobs.length, 1);
    assert.equal(limited.total, 2);

    const wrongType = await (await fetch(`${ctx.base}/v1/jobs?type=scan`, { headers: tenant.headers })).json();
    assert.equal(wrongType.total, 0);

    const noAuth = await fetch(`${ctx.base}/v1/jobs`);
    assert.equal(noAuth.status, 401);
  } finally {
    await ctx.close();
  }
});

test('CORS headers allow a browser dashboard to call the API from another origin', async () => {
  const ctx = await startServer();
  try {
    const preflight = await fetch(`${ctx.base}/v1/jobs`, {
      method: 'OPTIONS', headers: { 'access-control-request-method': 'POST', origin: 'http://localhost:5173' }
    });
    assert.equal(preflight.status, 204);
    assert.equal(preflight.headers.get('access-control-allow-origin'), '*');
    assert.match(preflight.headers.get('access-control-allow-headers') ?? '', /authorization/);

    const health = await fetch(`${ctx.base}/v1/health`);
    assert.equal(health.headers.get('access-control-allow-origin'), '*');
    assert.equal(health.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(health.headers.get('referrer-policy'), 'no-referrer');
  } finally {
    await ctx.close();
  }
});

test('the built dashboard is served from the same origin, with SPA fallback, and never shadows the /v1 API', async () => {
  const webDistPath = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-web-dist-'));
  await fs.writeFile(path.join(webDistPath, 'index.html'), '<!doctype html><title>PQC Forge</title>');
  await fs.mkdir(path.join(webDistPath, 'assets'), { recursive: true });
  await fs.writeFile(path.join(webDistPath, 'assets', 'app.js'), 'console.log("app")');

  const apiHome = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-api-webdist-'));
  const { server } = createApiServer({ apiHome, webDistPath });
  await new Promise((resolve) => server.listen(0, resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const root = await fetch(`${base}/`);
    assert.equal(root.status, 200);
    assert.match(await root.text(), /PQC Forge/);

    const asset = await fetch(`${base}/assets/app.js`);
    assert.equal(asset.status, 200);
    assert.match(asset.headers.get('content-type') ?? '', /javascript/);
    assert.match(await asset.text(), /console\.log/);

    // A client-side route with no matching file falls back to index.html
    // so a hard refresh on a deep link still loads the app shell.
    const deepLink = await fetch(`${base}/jobs/j_deadbeefdeadbeef`);
    assert.equal(deepLink.status, 200);
    assert.match(await deepLink.text(), /PQC Forge/);

    // Static serving must never shadow the real API: an unauthenticated
    // /v1/ request still gets the API's own 401, not the app shell.
    const apiRoute = await fetch(`${base}/v1/jobs`, { method: 'POST', body: '{}' });
    assert.equal(apiRoute.status, 401);

    const traversal = await fetch(`${base}/..%2f..%2fetc%2fpasswd`);
    assert.equal(traversal.status, 404); // resolveStaticFile refuses the escape outright, no SPA fallback
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
