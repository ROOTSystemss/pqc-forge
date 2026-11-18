import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { createApiServer, provisionTenant } from '../src/api/server.js';

// QA 2026-11-18 lows for PQC Forge: F14 (failed sign-ups no longer use up the hourly limit), F15 (upload errors do not
// show the server's folder path), F16 (the checkout return address must be this service, rootsystems.app or local).
async function start(billingEnv = {}) {
  const apiHome = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-qafix-'));
  const { server } = createApiServer({ apiHome, billingEnv });
  await new Promise((resolve) => server.listen(0, resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  return { apiHome, base, close: () => new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); }) };
}
const json = (headers = {}) => ({ 'content-type': 'application/json', ...headers });

test('F14: sign-ups that fail validation do not count toward the per-address limit', async () => {
  const s = await start();
  try {
    const xff = { 'x-forwarded-for': '198.51.100.77' };
    const signup = (body) => fetch(`${s.base}/v1/signup`, { method: 'POST', headers: json(xff), body: typeof body === 'string' ? body : JSON.stringify(body) });
    for (const bad of [{ name: 'x' }, { name: 'Valid Name', email: 'not-an-email' }, { name: '<b>bad</b>' }, '{broken json']) assert.equal((await signup(bad)).status, 400);
    const codes = [];
    for (let i = 0; i < 3; i++) codes.push((await signup({ name: 'Good Co ' + i })).status);
    assert.deepEqual(codes, [201, 201, 201], 'the 4 failed attempts used none of the slots (QA: the 3rd good one was 429)');
  } finally { await s.close(); }
});

test('F15: a file the disk refuses gives a plain message without the server path', async () => {
  const s = await start();
  try {
    const { apiKey } = await provisionTenant(s.apiHome, 'Acme');
    const r = await fetch(`${s.base}/v1/workspaces`, { method: 'POST', headers: json({ authorization: `Bearer ${apiKey}` }), body: JSON.stringify({ files: [{ path: 'app/bad<name>.js', content: 'x' }, { path: 'app/' + 'a'.repeat(300) + '.js', content: 'x' }] }) });
    const body = await r.json();
    assert.equal(r.status, 400);
    assert.ok(!body.error.includes(s.apiHome) && !/tenants[\\/]t_|workspaces[\\/]ws_/.test(body.error), body.error);
  } finally { await s.close(); }
});

test('F16: checkout sends the buyer back only to this service, rootsystems.app or a local address', async () => {
  const s = await start({ PQC_FORGE_BILLING_PROVIDER: 'mock', PQC_FORGE_PUBLIC_URL: 'https://pqc-forge.example' });
  try {
    const { apiKey } = await provisionTenant(s.apiHome, 'Acme');
    const checkout = async (returnUrl) => (await (await fetch(`${s.base}/v1/billing/checkout`, { method: 'POST', headers: json({ authorization: `Bearer ${apiKey}` }), body: JSON.stringify({ item: 'report', country: 'US', returnUrl }) })).json()).url;
    assert.match(await checkout('https://evil.example/steal'), /^https:\/\/pqc-forge\.example/, 'another site is ignored: back to the service');
    assert.match(await checkout('https://pqc-forge.example/?tab=billing'), /^https:\/\/pqc-forge\.example\/\?tab=billing/);
    assert.match(await checkout('https://rootsystems.app/pricing'), /^https:\/\/rootsystems\.app\/pricing/);
    assert.match(await checkout('http://127.0.0.1:8787/?tab=billing'), /^http:\/\/127\.0\.0\.1:8787/);
    assert.match(await checkout('https://pqc-forge.example.evil.example/'), /^https:\/\/pqc-forge\.example[/?]/, 'a look-alike host is ignored');
    // With no PQC_FORGE_PUBLIC_URL (as on live), the service's own address (its Host) is accepted.
  } finally { await s.close(); }
  const t = await start({ PQC_FORGE_BILLING_PROVIDER: 'mock' });
  try {
    const { apiKey } = await provisionTenant(t.apiHome, 'Acme');
    const host = new URL(t.base).host;
    const r = await (await fetch(`${t.base}/v1/billing/checkout`, { method: 'POST', headers: json({ authorization: `Bearer ${apiKey}` }), body: JSON.stringify({ item: 'report', country: 'US', returnUrl: `https://${host}/?tab=billing` }) })).json();
    assert.match(r.url, new RegExp('^https://' + host.replace('.', '\\.') + '/\\?tab=billing'));
    const evil = await (await fetch(`${t.base}/v1/billing/checkout`, { method: 'POST', headers: json({ authorization: `Bearer ${apiKey}` }), body: JSON.stringify({ item: 'report', country: 'US', returnUrl: 'https://evil.example/steal' }) })).json();
    assert.doesNotMatch(evil.url, /evil\.example/);
  } finally { await t.close(); }
});
