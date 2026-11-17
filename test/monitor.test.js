import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { createApiServer, provisionTenant } from '../src/api/server.js';
import { setManualPlan } from '../src/billing/entitlements.js';
import { generateSigningKey } from '../src/signing.js';
import { buildMonitorRun, verifyMonitorRun, isDue, normalizeSettings, defaultProbe, writeSettings, MONITOR_RUN_SCHEMA } from '../src/monitor.js';
import { signDoc } from '../src/signedDoc.js';

// PF-05 / PF-02 / BM-44 (knock-out 2026-11-17): TLS and certificate monitoring. No real network anywhere: the probe
// is injected (fake handshake evidence), and the one default-probe check uses 127.0.0.1, which is refused as a
// private address before any connection is made.
const NOW = new Date('2026-11-17T00:00:00Z');
const days = (n) => new Date(NOW.getTime() + n * 86400000).toISOString();
const evidence = (group, pq, { validTo = days(200), fp = 'AA:BB' } = {}) => ({
  generatedAt: NOW.toISOString(), protocol: 'TLSv1.3', ephemeralKey: { name: group }, peerSignatureAlgorithm: 'ecdsa_secp256r1_sha256', authorized: true,
  verdict: { pqKeyExchange: pq, pqAuthentication: false },
  certificate: { subject: 'edge.example.com', issuer: 'Example CA', validFrom: days(-100), validTo, fingerprint256: fp, publicKey: 'EC prime256v1' },
});

test('monitoring run: drift between two runs (key exchange, PQ status, certificate replaced, expiring, stopped answering); signed; tamper fails', { timeout: 10_000 }, () => {
  const first = buildMonitorRun({ now: NOW, probes: [
    { target: 'a.example.com', ok: true, evidence: evidence('X25519MLKEM768', true) },
    { target: 'b.example.com', ok: true, evidence: evidence('X25519', false) },
    { target: 'c.example.com', ok: true, evidence: evidence('X25519', false) },
  ] });
  assert.equal(first.schema, MONITOR_RUN_SCHEMA);
  assert.equal(first.comparedWith, null);
  assert.deepEqual(first.endpoints.map((e) => e.changes), [[], [], []], 'first run: nothing to compare with');
  const K = generateSigningKey();
  const s1 = signDoc(first, K);
  const second = buildMonitorRun({ now: new Date(NOW.getTime() + 86400000), previous: s1, probes: [
    { target: 'a.example.com', ok: true, evidence: evidence('X25519', false) },
    { target: 'b.example.com', ok: true, evidence: evidence('X25519', false, { validTo: days(20), fp: 'CC:DD' }) },
    { target: 'c.example.com', ok: false, error: 'TLS connection failed: timeout' },
    { target: 'd.example.com', ok: true, evidence: evidence('X25519', false, { validTo: days(-1) }) },
  ] });
  const [a, b, c, d] = second.endpoints;
  assert.ok(a.changes.includes('key exchange changed: X25519MLKEM768 -> X25519'));
  assert.ok(a.changes.some((x) => /post-quantum status changed/.test(x)));
  assert.ok(b.changes.includes('certificate replaced'));
  assert.ok(b.changes.some((x) => /expires within 30 days \(19 days left\)/.test(x)), JSON.stringify(b.changes));
  assert.equal(c.tls.state, 'not-verified');
  assert.deepEqual(c.changes, ['stopped answering: Not verified']);
  assert.equal(c.certificate.state, 'not-verified');
  assert.ok(d.changes.includes('new endpoint (no earlier run to compare)'));
  assert.ok(d.changes.includes('certificate expired'));
  assert.deepEqual(second.summary, { endpoints: 4, postQuantumKeyExchange: 0, classicalOnly: 3, notVerified: 1, endpointsWithChanges: 4, certificatesExpiringOrExpired: 2 });
  assert.equal(second.comparedWith.receiptDigest, s1.receiptDigest);
  assert.doesNotMatch(JSON.stringify(second), /quantum-safe|quantum-proof/i);
  const s2 = signDoc(second, K);
  assert.equal(verifyMonitorRun(s2, [K]).valid, true);
  assert.equal(verifyMonitorRun({ ...s2, summary: { ...s2.summary, notVerified: 0 } }, [K]).valid, false, 'hiding a Not verified endpoint breaks the signature');
  assert.equal(verifyMonitorRun(s2, [generateSigningKey()]).valid, false);
});

test('settings validation and schedule due logic', { timeout: 10_000 }, () => {
  assert.deepEqual(normalizeSettings({}), { cadence: 'off', endpoints: [] });
  assert.deepEqual(normalizeSettings({ cadence: 'weekly', endpoints: ['Edge.Example.com', 'edge.example.com', 'api.example.com:8443'] }), { cadence: 'weekly', endpoints: ['edge.example.com', 'api.example.com:8443'] });
  assert.throws(() => normalizeSettings({ cadence: 'hourly', endpoints: ['a.com'] }), /off, daily or weekly/);
  assert.throws(() => normalizeSettings({ cadence: 'daily', endpoints: [] }), /at least one/);
  assert.throws(() => normalizeSettings({ endpoints: Array.from({ length: 11 }, (_, i) => `h${i}.example.com`) }), /at most 10/);
  assert.throws(() => normalizeSettings({ endpoints: ['https://x.com/path'] }), /Not a host/);
  const t = NOW.getTime();
  assert.equal(isDue({ cadence: 'off', endpoints: ['a.com'] }, t), false);
  assert.equal(isDue({ cadence: 'daily', endpoints: [] }, t), false);
  assert.equal(isDue({ cadence: 'daily', endpoints: ['a.com'], lastRunAt: null }, t), true);
  assert.equal(isDue({ cadence: 'daily', endpoints: ['a.com'], lastRunAt: days(-0.5) }, t), false);
  assert.equal(isDue({ cadence: 'daily', endpoints: ['a.com'], lastRunAt: days(-1) }, t), true);
  assert.equal(isDue({ cadence: 'weekly', endpoints: ['a.com'], lastRunAt: days(-3) }, t), false);
  assert.equal(isDue({ cadence: 'weekly', endpoints: ['a.com'], lastRunAt: days(-7) }, t), true);
});

test('default probe refuses a private address (Not verified, no connection made)', { timeout: 10_000 }, async () => {
  const r = await defaultProbe({ allowPrivateTargets: false })('127.0.0.1:443');
  assert.equal(r.ok, false);
  assert.equal(r.target, '127.0.0.1:443');
});

test('hosted: Community 402 on schedule/run; Pro saves, runs now, scheduler records drift; signed runs verify publicly', { timeout: 30_000 }, async () => {
  const apiHome = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-monitor-'));
  let state = 'pq';
  const probe = async (target) => {
    if (target.startsWith('down.')) return { target, ok: false, error: 'TLS connection failed: refused' };
    return state === 'pq'
      ? { target, ok: true, evidence: evidence('X25519MLKEM768', true) }
      : { target, ok: true, evidence: evidence('X25519', false, { validTo: new Date(Date.now() + 10 * 86400000).toISOString(), fp: 'EE:FF' }) };
  };
  const { server, runMonitorPass } = createApiServer({ apiHome, monitorProbe: probe });
  await new Promise((resolve) => server.listen(0, resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const call = (key, method, p, body) => fetch(`${base}${p}`, { method, headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json' }, ...(body ? { body: JSON.stringify(body) } : {}) });
  try {
    const free = await provisionTenant(apiHome, 'Free Co');
    const off = await (await call(free.apiKey, 'GET', '/v1/monitor')).json();
    assert.equal(off.cadence, 'off', 'off by default');
    assert.deepEqual(off.runs, []);
    assert.equal((await call(free.apiKey, 'POST', '/v1/monitor', { cadence: 'daily', endpoints: ['edge.example.com'] })).status, 402);
    assert.equal((await call(free.apiKey, 'POST', '/v1/monitor', { cadence: 'off', endpoints: ['edge.example.com'] })).status, 200, 'Community may save endpoints with monitoring off');
    assert.equal((await call(free.apiKey, 'POST', '/v1/monitor/run')).status, 402);

    const pro = await provisionTenant(apiHome, 'Pro Co');
    await setManualPlan(apiHome, pro.tenantId, { plan: 'pro' });
    assert.equal((await call(pro.apiKey, 'POST', '/v1/monitor/run')).status, 400, 'nothing saved yet');
    assert.equal((await call(pro.apiKey, 'POST', '/v1/monitor', { cadence: 'hourly', endpoints: ['a.com'] })).status, 400);
    const saved = await (await call(pro.apiKey, 'POST', '/v1/monitor', { cadence: 'daily', endpoints: ['edge.example.com', 'down.example.com'] })).json();
    assert.equal(saved.cadence, 'daily');
    const run1 = await (await call(pro.apiKey, 'POST', '/v1/monitor/run')).json();
    assert.match(run1.runId, /^mr_[0-9a-f]{16}$/);
    assert.equal(run1.summary.postQuantumKeyExchange, 1);
    assert.equal(run1.summary.notVerified, 1, 'unreachable is Not verified, never counted');
    const again = await call(pro.apiKey, 'POST', '/v1/monitor/run');
    assert.equal(again.status, 429, 'run now: once per 5 minutes');
    assert.ok(Number(again.headers.get('retry-after')) > 0);

    // Scheduler: not due yet (ran just now); a day later it runs Pro only (Free is off) and records the drift.
    assert.deepEqual(await runMonitorPass(new Date()), []);
    state = 'classical';
    const pass = await runMonitorPass(new Date(Date.now() + 86400000 + 1000));
    assert.equal(pass.length, 1);
    assert.equal(pass[0].tenantId, pro.tenantId);
    const run2 = await (await call(pro.apiKey, 'GET', `/v1/monitor/runs/${pass[0].runId}`)).json();
    assert.equal(run2.trigger, 'schedule');
    const edge = run2.endpoints.find((e) => e.target === 'edge.example.com');
    assert.ok(edge.changes.includes('key exchange changed: X25519MLKEM768 -> X25519'), JSON.stringify(edge.changes));
    assert.ok(edge.changes.includes('certificate replaced'));
    assert.ok(edge.changes.some((x) => /expires within 30 days/.test(x)));
    assert.equal(run2.comparedWith.receiptDigest, run1.receiptDigest);

    const listing = await (await call(pro.apiKey, 'GET', '/v1/monitor')).json();
    assert.equal(listing.runs.length, 2);
    assert.equal(listing.runs[0].runId, pass[0].runId, 'newest first');
    assert.match(listing.alerts, /no email or webhook/);

    const pv = async (d) => (await fetch(`${base}/v1/public/verify-report`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(d) })).json();
    const ok = await pv(run2);
    assert.equal(ok.valid, true); assert.equal(ok.kind, 'monitor-run');
    assert.equal((await pv({ ...run2, endpoints: run2.endpoints.map((e) => ({ ...e, changes: [] })) })).valid, false, 'removing a change breaks the signature');

    // Another account cannot read Pro's run; a bad id is 404.
    assert.equal((await call(free.apiKey, 'GET', `/v1/monitor/runs/${pass[0].runId}`)).status, 404);
    assert.equal((await call(pro.apiKey, 'GET', '/v1/monitor/runs/..%2Fx')).status, 400);
    assert.equal((await call(pro.apiKey, 'GET', '/v1/monitor/runs/mr_zz')).status, 404);

    // A plan that lapsed: monitoring left on, but the scheduler skips the account and records nothing.
    await writeSettings(apiHome, free.tenantId, { cadence: 'daily', endpoints: ['edge.example.com'], lastRunAt: null, lastRunId: null });
    const pass2 = await runMonitorPass(new Date(Date.now() + 3 * 86400000));
    assert.deepEqual(pass2.find((p) => p.tenantId === free.tenantId), { tenantId: free.tenantId, skipped: 'not a paid plan' });
    assert.deepEqual((await (await call(free.apiKey, 'GET', '/v1/monitor')).json()).runs, []);
  } finally {
    await new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); });
  }
});

test('scheduler is off unless asked for, and its timer never keeps the process alive', { timeout: 10_000 }, async () => {
  const apiHome = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-monitor-tick-'));
  let probes = 0;
  const probe = async (target) => { probes += 1; return { target, ok: true, evidence: evidence('X25519', false) }; };
  const t = await provisionTenant(apiHome, 'Tick Co');
  await setManualPlan(apiHome, t.tenantId, { plan: 'pro' });
  await writeSettings(apiHome, t.tenantId, { cadence: 'weekly', endpoints: ['edge.example.com'], lastRunAt: null, lastRunId: null });
  const offServer = createApiServer({ apiHome, monitorProbe: probe, monitorTickMs: 20 }).server;
  await new Promise((resolve) => offServer.listen(0, '127.0.0.1', resolve));
  await new Promise((r) => setTimeout(r, 120));
  assert.equal(probes, 0, 'no scheduler unless monitorScheduler: true');
  await new Promise((resolve) => offServer.close(resolve));
  const { server } = createApiServer({ apiHome, monitorProbe: probe, monitorScheduler: true, monitorTickMs: 20 });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    for (let i = 0; i < 100 && probes === 0; i++) await new Promise((r) => setTimeout(r, 20));
    assert.equal(probes, 1, 'the due weekly account ran once');
    await new Promise((r) => setTimeout(r, 120));
    assert.equal(probes, 1, 'not due again for a week');
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
