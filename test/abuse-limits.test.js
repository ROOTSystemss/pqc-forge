import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { createApiServer } from '../src/api/server.js';
import { QUOTAS, clientAddress } from '../src/api/abuseLimits.js';

// Audit 2026-11-13 (fixed 2026-11-14): /v1/signup is rate-limited per client address and per day, and each
// account has a workspace and storage quota checked before anything is written.
async function start(signupLimits) {
  const apiHome = await fs.mkdtemp(path.join(os.tmpdir(), 'pqcf-abuse-'));
  const { server } = createApiServer({ apiHome, signupLimits });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { server, base: `http://127.0.0.1:${server.address().port}`, apiHome };
}
const signup = (base, xff) => fetch(`${base}/v1/signup`, { method: 'POST', headers: { 'content-type': 'application/json', ...(xff ? { 'x-forwarded-for': xff } : {}) }, body: JSON.stringify({ name: 'Abuse Test' }) });

test('client address: the right-most public address in X-Forwarded-For; private hops skipped', () => {
  assert.equal(clientAddress({ headers: { 'x-forwarded-for': '9.9.9.9, 8.8.8.8' }, socket: { remoteAddress: '10.0.0.5' } }), '8.8.8.8');
  assert.equal(clientAddress({ headers: { 'x-forwarded-for': '8.8.8.8, 10.1.2.3' }, socket: { remoteAddress: '10.0.0.5' } }), '8.8.8.8');
  assert.equal(clientAddress({ headers: {}, socket: { remoteAddress: '::ffff:127.0.0.1' } }), '127.0.0.1');
});

test('signup: per-address limit, a forged prepended address does not help, and a server-wide daily cap', async () => {
  const { server, base } = await start({ perIpPerHour: 2, perDay: 4 });
  try {
    assert.equal((await signup(base, '8.8.8.8')).status, 201);
    assert.equal((await signup(base, '1.1.1.1, 8.8.8.8')).status, 201, 'same real address with a forged one in front still counts as 8.8.8.8');
    const third = await signup(base, '7.7.7.7, 8.8.8.8');
    assert.equal(third.status, 429);
    assert.ok(Number(third.headers.get('retry-after')) > 0);
    assert.equal((await signup(base, '4.4.4.4')).status, 201, 'another address is still allowed');
    assert.equal((await signup(base, '5.5.5.5')).status, 201);
    const capped = await signup(base, '6.6.6.6');
    assert.equal(capped.status, 429, 'the daily cap holds whatever the address');
    assert.match((await capped.json()).error, /today/);
  } finally { server.close(); }
});

test('storage quota per account: workspace count and total bytes, checked before writing', async () => {
  const before = { ...QUOTAS.community };
  QUOTAS.community.workspaces = 2;
  QUOTAS.community.bytes = 3000;
  const { server, base, apiHome } = await start({ perIpPerHour: 100, perDay: 100 });
  try {
    const { apiKey, tenantId } = await (await signup(base)).json();
    const ws = (content) => fetch(`${base}/v1/workspaces`, { method: 'POST', headers: { authorization: `Bearer ${apiKey}`, 'content-type': 'application/json' }, body: JSON.stringify({ files: [{ path: 'a.txt', content }] }) });
    assert.equal((await ws('x'.repeat(1000))).status, 200);
    const tooBig = await ws('y'.repeat(2500));
    assert.equal(tooBig.status, 413, 'over the byte quota');
    assert.match((await tooBig.json()).error, /Storage limit/);
    assert.equal((await ws('z'.repeat(100))).status, 200);
    const tooMany = await ws('w');
    assert.equal(tooMany.status, 413, 'over the workspace count');
    assert.match((await tooMany.json()).error, /Workspace limit/);
    const dirs = await fs.readdir(path.join(apiHome, 'tenants', tenantId, 'workspaces')).catch(async () => (await fs.readdir(apiHome, { recursive: true })).filter((p) => /ws_[0-9a-f]{16}$/.test(p)));
    assert.equal(dirs.filter((d) => /ws_[0-9a-f]{16}$/.test(d)).length, 2, 'nothing was written for the refused uploads');
  } finally {
    server.close();
    Object.assign(QUOTAS.community, before);
  }
});
