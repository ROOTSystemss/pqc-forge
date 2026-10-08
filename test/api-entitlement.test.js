import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { createApiServer, provisionTenant } from '../src/api/server.js';
import { setManualPlan } from '../src/billing/entitlements.js';

async function start() {
  const apiHome = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-ent-'));
  const handlers = {
    scan: async () => ({ ok: true }),
    migrate: async () => ({ migration: { mode: 'applied' }, receipt: {} }),
    verify: async () => ({ evidence: {}, receipt: {} }),
    'pr-pack': async () => ({ ok: true })
  };
  const { server } = createApiServer({ apiHome, handlers });
  await new Promise((resolve) => server.listen(0, resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const { tenantId, apiKey } = await provisionTenant(apiHome, 'Acme');
  const headers = { authorization: `Bearer ${apiKey}`, 'content-type': 'application/json' };
  return {
    apiHome, base, tenantId, headers,
    close: () => new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); })
  };
}

test('hosted API returns 402 for paid job types on Community and allows them after Pro', async () => {
  const ctx = await start();
  try {
    const denied = await fetch(`${ctx.base}/v1/jobs`, {
      method: 'POST', headers: ctx.headers,
      body: JSON.stringify({ type: 'pr-pack', params: { workspaceId: 'w_x' } })
    });
    assert.equal(denied.status, 402);

    const migrate = await fetch(`${ctx.base}/v1/jobs`, {
      method: 'POST', headers: ctx.headers,
      body: JSON.stringify({ type: 'migrate', params: { workspaceId: 'w_x', write: true } })
    });
    assert.equal(migrate.status, 202);

    await setManualPlan(ctx.apiHome, ctx.tenantId, { plan: 'pro', quantity: 1, until: '2099-01-01T00:00:00.000Z' });
    const paid = await fetch(`${ctx.base}/v1/jobs`, {
      method: 'POST', headers: ctx.headers,
      body: JSON.stringify({ type: 'pr-pack', params: { workspaceId: 'w_x' } })
    });
    assert.equal(paid.status, 202);
  } finally {
    await ctx.close();
  }
});
