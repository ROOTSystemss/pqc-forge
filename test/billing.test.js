import assert from 'node:assert/strict';
import { createHmac, randomBytes } from 'node:crypto';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { createApiServer, provisionTenant } from '../src/api/server.js';
import { setManualPlan, entitlement, useReportCredit } from '../src/billing/entitlements.js';
import { verifyStandardWebhook } from '../src/billing/providers.js';

const WEBHOOK_SECRET = `whsec_${randomBytes(24).toString('base64')}`;
const PRODUCTS = { 'pro:month': 'pdt_pro_m', 'pro:year': 'pdt_pro_y', 'team:month': 'pdt_team_m', 'team:year': 'pdt_team_y', report: 'pdt_report' };
const BILLING_ENV = { DODO_PAYMENTS_API_KEY: 'test_key', DODO_PAYMENTS_WEBHOOK_KEY: WEBHOOK_SECRET, PQC_FORGE_DODO_PRODUCTS: JSON.stringify(PRODUCTS) };

async function start({ billingEnv = BILLING_ENV, fetchImpl } = {}) {
  const apiHome = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-billing-'));
  const { server } = createApiServer({ apiHome, billingEnv, ...(fetchImpl ? { fetchImpl } : {}) });
  await new Promise((resolve) => server.listen(0, resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const { tenantId, apiKey } = await provisionTenant(apiHome, 'Acme');
  const headers = { authorization: `Bearer ${apiKey}`, 'content-type': 'application/json' };
  return { apiHome, base, tenantId, headers, close: () => new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); }) };
}

function signed(event, { id = `msg_${randomBytes(6).toString('hex')}`, secret = WEBHOOK_SECRET, timestamp = Math.floor(Date.now() / 1000) } = {}) {
  const body = JSON.stringify(event);
  const sig = createHmac('sha256', Buffer.from(secret.replace(/^whsec_/, ''), 'base64')).update(`${id}.${timestamp}.${body}`).digest('base64');
  return { body, headers: { 'content-type': 'application/json', 'webhook-id': id, 'webhook-timestamp': String(timestamp), 'webhook-signature': `v1,${sig}` } };
}

function subEvent(type, tenantId, { item = 'pro:month', quantity = 3, status, at = new Date().toISOString(), productId } = {}) {
  return { type, timestamp: at, data: { subscription_id: 'sub_1', product_id: productId ?? PRODUCTS[item], quantity, status, next_billing_date: new Date(Date.now() + 30 * 864e5).toISOString(), metadata: { tenant_id: tenantId, item } } };
}

const post = (ctx, p, body, headers = ctx.headers) => fetch(ctx.base + p, { method: 'POST', headers, body: typeof body === 'string' ? body : JSON.stringify(body) });
const deliver = (ctx, event, opts) => { const s = signed(event, opts); return fetch(`${ctx.base}/v1/billing/webhook/dodo`, { method: 'POST', headers: s.headers, body: s.body }); };

test('plans are public and annual billing is ten months at the decided prices', async () => {
  const ctx = await start();
  const plans = await (await fetch(`${ctx.base}/v1/plans`)).json();
  const pro = plans.plans.find((p) => p.id === 'pro');
  const team = plans.plans.find((p) => p.id === 'team');
  const business = plans.plans.find((p) => p.id === 'business');
  assert.equal(pro.priceUsdMonthly, 79);
  assert.equal(pro.priceUsdYearly, 790);
  assert.equal(pro.repoLimit, 5);
  assert.equal(pro.perRepo, false);
  assert.equal(team.priceUsdMonthly, 399);
  assert.equal(team.priceUsdYearly, 3990);
  assert.equal(team.repoLimit, 25);
  assert.equal(business.priceUsdMonthly, 999);
  assert.equal(business.repoLimit, 100);
  assert.equal(plans.oneTime[0].priceUsdOnce, 2500, 'the same price rootsystems.app shows');
  assert.equal(plans.services[0].priceUsdFrom, 7500);
  assert.equal(plans.foundingOffer.discountPercent, 40);
  assert.equal(plans.checkoutAvailable, true);
  assert.equal(plans.billingProvider, 'dodo');
  await ctx.close();
});

test('self-serve signup creates a Community account and returns the key once', async () => {
  const ctx = await start();
  const res = await post(ctx, '/v1/signup', { name: 'Nova Labs', email: 'ops@nova.example' }, { 'content-type': 'application/json' });
  assert.equal(res.status, 201);
  const body = await res.json();
  assert.match(body.apiKey, /^pqcf_t_[0-9a-f]{16}_/);
  assert.equal(body.plan, 'community');
  const sub = await (await fetch(`${ctx.base}/v1/subscription`, { headers: { authorization: `Bearer ${body.apiKey}` } })).json();
  assert.equal(sub.plan, 'community');
  const bad = await post(ctx, '/v1/signup', { name: 'x' }, { 'content-type': 'application/json' });
  assert.equal(bad.status, 400);
  await ctx.close();
});

test('a new account is on Community: one public repository, no private ones', async () => {
  const ctx = await start();
  const sub = await (await fetch(`${ctx.base}/v1/subscription`, { headers: ctx.headers })).json();
  assert.equal(sub.plan, 'community');
  assert.equal(sub.repoLimit, 1);
  let r = await (await post(ctx, '/v1/gate/check', { repo: 'acme/secret', private: true })).json();
  assert.equal(r.allowed, false);
  assert.match(r.reason, /Pro or Team/);
  r = await (await post(ctx, '/v1/gate/check', { repo: 'acme/public-one' })).json();
  assert.equal(r.allowed, true);
  r = await (await post(ctx, '/v1/gate/check', { repo: 'acme/public-one' })).json();
  assert.equal(r.allowed, true, 'the same repository keeps working');
  r = await (await post(ctx, '/v1/gate/check', { repo: 'acme/public-two' })).json();
  assert.equal(r.allowed, false, 'a second repository is over the Community limit');
  await ctx.close();
});

test('Community cannot start paid hosted jobs; Pro can', async () => {
  const ctx = await start();
  const denied = await post(ctx, '/v1/jobs', { type: 'verify', params: { target: 'example.com:443' } });
  assert.equal(denied.status, 402);
  assert.match((await denied.json()).error, /Pro or Team/);
  const migrateOk = await post(ctx, '/v1/jobs', { type: 'migrate', params: { workspaceId: 'w_missing', write: false } });
  assert.equal(migrateOk.status, 202);
  await setManualPlan(ctx.apiHome, ctx.tenantId, { plan: 'pro', quantity: 2, until: '2099-01-01T00:00:00.000Z' });
  const allowed = await post(ctx, '/v1/jobs', { type: 'verify', params: { target: 'example.com:443' } });
  assert.equal(allowed.status, 202);
  await ctx.close();
});

test('mock checkout applies Pro immediately without Dodo', async () => {
  const ctx = await start({ billingEnv: { PQC_FORGE_BILLING_PROVIDER: 'mock', PQC_FORGE_PUBLIC_URL: 'http://127.0.0.1:8787' } });
  const plans = await (await fetch(`${ctx.base}/v1/plans`)).json();
  assert.equal(plans.checkoutAvailable, true);
  assert.equal(plans.billingProvider, 'mock');
  const r = await (await post(ctx, '/v1/billing/checkout', { plan: 'team', interval: 'month', returnUrl: 'http://127.0.0.1:8787/?tab=billing' })).json();
  assert.match(r.url, /checkout=success/);
  assert.match(r.url, /mock=1/);
  const sub = await (await fetch(`${ctx.base}/v1/subscription`, { headers: ctx.headers })).json();
  assert.equal(sub.plan, 'team');
  assert.equal(sub.repoLimit, 25);
  await ctx.close();
});

test('the gate needs a valid key', async () => {
  const ctx = await start();
  const r = await post(ctx, '/v1/gate/check', { repo: 'acme/x' }, { 'content-type': 'application/json' });
  assert.equal(r.status, 401);
  await ctx.close();
});

test('a signed Dodo event activates Pro (5 private repositories), and limits follow it', async () => {
  const ctx = await start();
  const res = await deliver(ctx, subEvent('subscription.active', ctx.tenantId, { quantity: 1, status: 'active' }));
  assert.equal(res.status, 200);
  assert.equal((await res.json()).applied, true);
  const sub = await (await fetch(`${ctx.base}/v1/subscription`, { headers: ctx.headers })).json();
  assert.equal(sub.plan, 'pro');
  assert.equal(sub.repoLimit, 5);
  for (const name of ['a', 'b', 'c', 'd', 'e']) assert.equal((await (await post(ctx, '/v1/gate/check', { repo: `acme/${name}`, private: true })).json()).allowed, true);
  assert.equal((await (await post(ctx, '/v1/gate/check', { repo: 'acme/f', private: true })).json()).allowed, false);
  assert.equal((await (await post(ctx, '/v1/gate/release', { repo: 'acme/a' })).json()).released, true);
  assert.equal((await (await post(ctx, '/v1/gate/check', { repo: 'acme/f', private: true })).json()).allowed, true, 'releasing a repository frees its place');
  await ctx.close();
});

test('repositories are stored only as fingerprints, never by name', async () => {
  const ctx = await start();
  await post(ctx, '/v1/gate/check', { repo: 'Acme-Corp/Very-Secret-Repo' });
  const stored = await fs.readFile(path.join(ctx.apiHome, 'tenants', ctx.tenantId, 'repos.json'), 'utf8');
  assert.doesNotMatch(stored.toLowerCase(), /very-secret-repo|acme-corp/);
  assert.match(stored, /sha256:[0-9a-f]{64}/);
  await ctx.close();
});

test('unsigned, wrongly signed and stale webhooks are refused', async () => {
  const ctx = await start();
  const event = subEvent('subscription.active', ctx.tenantId, { status: 'active' });
  let r = await fetch(`${ctx.base}/v1/billing/webhook/dodo`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(event) });
  assert.equal(r.status, 400);
  r = await deliver(ctx, event, { secret: `whsec_${randomBytes(24).toString('base64')}` });
  assert.equal(r.status, 400);
  r = await deliver(ctx, event, { timestamp: Math.floor(Date.now() / 1000) - 3600 });
  assert.equal(r.status, 400);
  const sub = await (await fetch(`${ctx.base}/v1/subscription`, { headers: ctx.headers })).json();
  assert.equal(sub.plan, 'community', 'nothing was applied');
  await ctx.close();
});

test('a repeated delivery is applied once, and an older event cannot undo a newer one', async () => {
  const ctx = await start();
  const t0 = new Date(Date.now() - 60_000).toISOString();
  const t1 = new Date().toISOString();
  const first = subEvent('subscription.active', ctx.tenantId, { status: 'active', at: t0 });
  assert.equal((await (await deliver(ctx, first, { id: 'msg_same' })).json()).applied, true);
  assert.equal((await (await deliver(ctx, first, { id: 'msg_same' })).json()).reason, 'duplicate delivery');
  await deliver(ctx, subEvent('subscription.cancelled', ctx.tenantId, { status: 'cancelled', at: t1 }));
  const late = await (await deliver(ctx, subEvent('subscription.renewed', ctx.tenantId, { status: 'active', at: t0 }))).json();
  assert.equal(late.applied, false);
  const sub = await (await fetch(`${ctx.base}/v1/subscription`, { headers: ctx.headers })).json();
  assert.equal(sub.plan, 'community', 'the cancellation stands');
  await ctx.close();
});

test('on hold keeps access while a renewal is retried; expiry removes it', async () => {
  const ctx = await start();
  await deliver(ctx, subEvent('subscription.active', ctx.tenantId, { item: 'team:year', status: 'active', at: new Date(Date.now() - 2000).toISOString() }));
  await deliver(ctx, subEvent('subscription.on_hold', ctx.tenantId, { item: 'team:year', at: new Date(Date.now() - 1000).toISOString() }));
  let sub = await (await fetch(`${ctx.base}/v1/subscription`, { headers: ctx.headers })).json();
  assert.equal(sub.plan, 'team');
  assert.equal(sub.repoLimit, 25);
  await deliver(ctx, subEvent('subscription.expired', ctx.tenantId, { item: 'team:year' }));
  sub = await (await fetch(`${ctx.base}/v1/subscription`, { headers: ctx.headers })).json();
  assert.equal(sub.plan, 'community');
  await ctx.close();
});

test('events for unknown accounts or other products are ignored', async () => {
  const ctx = await start();
  let r = await (await deliver(ctx, subEvent('subscription.active', 't_0000000000000000', { status: 'active' }))).json();
  assert.equal(r.applied, false);
  r = await (await deliver(ctx, { type: 'subscription.active', timestamp: new Date().toISOString(), data: { product_id: 'pdt_someone_else', metadata: {} } })).json();
  assert.equal(r.applied, false);
  await ctx.close();
});

test('buying the readiness report adds one credit, which can be spent once', async () => {
  const ctx = await start();
  const r = await (await deliver(ctx, { type: 'payment.succeeded', timestamp: new Date().toISOString(), data: { payment_id: 'pay_1', product_id: PRODUCTS.report, metadata: { tenant_id: ctx.tenantId, item: 'report' } } })).json();
  assert.equal(r.applied, true);
  assert.equal((await entitlement(ctx.apiHome, ctx.tenantId)).reportCredits, 1);
  assert.equal(await useReportCredit(ctx.apiHome, ctx.tenantId), true);
  assert.equal(await useReportCredit(ctx.apiHome, ctx.tenantId), false);
  await ctx.close();
});

test('checkout sends the right product, quantity and account to the provider', async () => {
  const calls = [];
  const fetchImpl = async (url, init) => { calls.push({ url, body: JSON.parse(init.body), auth: init.headers.authorization }); return new Response(JSON.stringify({ checkout_url: 'https://checkout.example/abc', session_id: 'cks_1' }), { status: 200 }); };
  const ctx = await start({ fetchImpl });
  const r = await (await post(ctx, '/v1/billing/checkout', { plan: 'pro', interval: 'year', quantity: 4 })).json();
  assert.equal(r.url, 'https://checkout.example/abc');
  assert.equal(calls[0].url, 'https://test.dodopayments.com/checkouts');
  assert.deepEqual(calls[0].body.product_cart, [{ product_id: 'pdt_pro_y', quantity: 4 }]);
  assert.equal(calls[0].body.metadata.tenant_id, ctx.tenantId);
  assert.equal((await post(ctx, '/v1/billing/checkout', { plan: 'selfhosted' })).status, 400, 'invoiced plans are not sold at checkout');
  await ctx.close();
});

test('checkout says so plainly when billing is not configured', async () => {
  const ctx = await start({ billingEnv: {} });
  const r = await post(ctx, '/v1/billing/checkout', { plan: 'pro' });
  assert.equal(r.status, 503);
  assert.equal((await (await fetch(`${ctx.base}/v1/plans`)).json()).checkoutAvailable, false);
  assert.equal((await fetch(`${ctx.base}/v1/billing/webhook/dodo`, { method: 'POST', body: '{}' })).status, 404);
  await ctx.close();
});

test('an operator can set an invoiced self-hosted plan', async () => {
  const ctx = await start();
  await setManualPlan(ctx.apiHome, ctx.tenantId, { plan: 'selfhosted', quantity: 50, until: '2099-01-01T00:00:00.000Z' });
  const ent = await entitlement(ctx.apiHome, ctx.tenantId);
  assert.equal(ent.plan, 'selfhosted');
  assert.equal(ent.repoLimit, 50);
  await setManualPlan(ctx.apiHome, ctx.tenantId, { plan: 'team', until: '2000-01-01T00:00:00.000Z' });
  assert.equal((await entitlement(ctx.apiHome, ctx.tenantId)).plan, 'community', 'a lapsed invoiced plan falls back to Community');
  await ctx.close();
});

test('Standard Webhooks verification accepts any listed v1 signature', () => {
  const s = signed({ ok: true });
  const headers = { ...s.headers, 'webhook-signature': `v1,${Buffer.alloc(32).toString('base64')} ${s.headers['webhook-signature']}` };
  assert.doesNotThrow(() => verifyStandardWebhook(WEBHOOK_SECRET, s.body, headers));
});

test('the GitHub Action checks the plan before scanning and never interpolates inputs into scripts', async () => {
  const action = await fs.readFile(path.join(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')), '..', 'action.yml'), 'utf8');
  assert.ok(action.indexOf('Check PQC Forge plan') < action.indexOf("inputs.mode == 'scan'"));
  assert.match(action, /PQC_FORGE_API_KEY: \$\{\{ inputs\.api_key \}\}/);
  assert.match(action, /private repositories need a Pro or Team plan/);
  assert.doesNotMatch(action, /run:.*\$\{\{ inputs\./);
});
