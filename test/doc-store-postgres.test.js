import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { createApiServer } from '../src/api/server.js';
import { closeDocStore } from '../src/api/docStore.js';
import { entitlement, setManualPlan } from '../src/billing/entitlements.js';

// 2026-11-09: the hosted service has no disk, so every account vanished on sleep/redeploy. With DATABASE_URL set,
// accounts, API keys (hashes), plans and job records live in Postgres. This starts the API, signs up, runs a job,
// then starts a NEW server on an EMPTY folder (what a redeploy looks like) and checks all of it is still there.
// Needs a throwaway local Postgres: PQC_TEST_DATABASE_URL=postgres://...@127.0.0.1:.../pqcforge_test
const url = process.env.PQC_TEST_DATABASE_URL;

async function start() {
  const apiHome = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-pg-'));
  const { server } = createApiServer({ apiHome, handlers: { scan: async () => ({ ok: true }) } });
  await new Promise((resolve) => server.listen(0, resolve));
  return { apiHome, base: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); }) };
}

test('accounts, API keys, plans and jobs survive a restart on an empty disk when DATABASE_URL is set', { skip: !url && 'set PQC_TEST_DATABASE_URL to a local throwaway Postgres' }, async () => {
  const saved = process.env.DATABASE_URL;
  process.env.DATABASE_URL = url;
  try {
    const first = await start();
    const signup = await (await fetch(`${first.base}/v1/signup`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name: 'Restart test', email: 'restart@example.com' }) })).json();
    const headers = { authorization: `Bearer ${signup.apiKey}`, 'content-type': 'application/json' };
    const ws = await (await fetch(`${first.base}/v1/workspaces`, { method: 'POST', headers, body: JSON.stringify({ files: [{ path: 'nginx.conf', content: 'ssl_protocols TLSv1.2;\n' }] }) })).json();
    const job = await (await fetch(`${first.base}/v1/jobs`, { method: 'POST', headers, body: JSON.stringify({ type: 'scan', params: { workspaceId: ws.workspaceId } }) })).json();
    for (let i = 0; i < 50; i += 1) {
      if ((await (await fetch(`${first.base}/v1/jobs/${job.jobId}`, { headers })).json()).status === 'succeeded') break;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    await setManualPlan(first.apiHome, signup.tenantId, { plan: 'pro' });
    await first.close();
    await fs.rm(first.apiHome, { recursive: true, force: true }); // the disk is gone

    const second = await start();
    try {
      const sub = await fetch(`${second.base}/v1/subscription`, { headers });
      assert.equal(sub.status, 200, 'the same API key still works');
      assert.equal((await sub.json()).plan, 'pro', 'the plan survived');
      const got = await (await fetch(`${second.base}/v1/jobs/${job.jobId}`, { headers })).json();
      assert.equal(got.status, 'succeeded', 'the job record survived');
      assert.deepEqual(await (await fetch(`${second.base}/v1/jobs/${job.jobId}/result`, { headers })).json(), { ok: true }, 'the job result survived');
      assert.equal((await (await fetch(`${second.base}/v1/jobs`, { headers })).json()).total, 1);
      assert.equal((await fetch(`${second.base}/v1/subscription`, { headers: { authorization: `Bearer ${signup.apiKey}x` } })).status, 401, 'a wrong key is still refused');
      assert.equal((await entitlement(second.apiHome, signup.tenantId)).plan, 'pro');
    } finally {
      await second.close();
    }
  } finally {
    await closeDocStore();
    if (saved === undefined) delete process.env.DATABASE_URL; else process.env.DATABASE_URL = saved;
  }
});
