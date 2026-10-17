import { createHmac, timingSafeEqual } from 'node:crypto';

// Payment providers behind one interface, so the checkout can move to another
// provider (or our own) without touching plans or entitlements:
//   configured()                                 -> boolean
//   createCheckout({ tenantId, item, quantity, returnUrl }) -> { url, ref }
//   verifyWebhook(rawBody, headers)              -> parsed event, or throws
//   normalize(event)                             -> { eventId, tenantId, kind, plan, interval, status, quantity,
//                                                     currentPeriodEnd, providerRef, occurredAt } or null to ignore
// `item` is 'pro:month', 'pro:year', 'team:month', 'team:year' or 'report'.

export const ITEMS = ['pro:month', 'pro:year', 'team:month', 'team:year', 'report'];

// ---------- Standard Webhooks (used by Dodo Payments) ----------
const TOLERANCE_SECONDS = 5 * 60;

export function verifyStandardWebhook(secret, rawBody, headers, now = Date.now()) {
  const id = headers['webhook-id'];
  const timestamp = headers['webhook-timestamp'];
  const signatures = headers['webhook-signature'];
  if (!id || !timestamp || !signatures) throw new Error('Missing webhook signature headers.');
  const ts = Number(timestamp);
  if (!Number.isFinite(ts) || Math.abs(now / 1000 - ts) > TOLERANCE_SECONDS) throw new Error('Webhook timestamp outside tolerance.');
  const key = Buffer.from(String(secret).replace(/^whsec_/, ''), 'base64');
  const expected = createHmac('sha256', key).update(`${id}.${timestamp}.${rawBody}`).digest();
  const ok = String(signatures).split(' ').some((part) => {
    const [version, sig] = part.split(',');
    if (version !== 'v1' || !sig) return false;
    const given = Buffer.from(sig, 'base64');
    return given.length === expected.length && timingSafeEqual(given, expected);
  });
  if (!ok) throw new Error('Webhook signature does not match.');
  return { id, timestamp: ts };
}

// ---------- Dodo Payments ----------
function dodoConfig(env) {
  let products = {};
  try { products = JSON.parse(env.PQC_FORGE_DODO_PRODUCTS || '{}'); } catch { products = {}; }
  return {
    apiKey: env.DODO_PAYMENTS_API_KEY || '',
    webhookKey: env.DODO_PAYMENTS_WEBHOOK_KEY || '',
    base: env.DODO_ENVIRONMENT === 'live_mode' ? 'https://live.dodopayments.com' : 'https://test.dodopayments.com',
    products
  };
}

export function dodoProvider(env = process.env, fetchImpl = globalThis.fetch) {
  const cfg = dodoConfig(env);
  const itemFor = (productId) => Object.entries(cfg.products).find(([, id]) => id === productId)?.[0] ?? null;
  return {
    name: 'dodo',
    configured() {
      return Boolean(cfg.apiKey && cfg.webhookKey && ITEMS.every((item) => typeof cfg.products[item] === 'string' && cfg.products[item]));
    },
    async createCheckout({ tenantId, item, quantity = 1, returnUrl }) {
      if (!ITEMS.includes(item)) throw new Error(`Unknown item: ${item}`);
      const response = await fetchImpl(`${cfg.base}/checkouts`, {
        method: 'POST',
        headers: { authorization: `Bearer ${cfg.apiKey}`, 'content-type': 'application/json' },
        body: JSON.stringify({
          product_cart: [{ product_id: cfg.products[item], quantity: item.startsWith('pro:') ? quantity : 1 }],
          return_url: returnUrl,
          metadata: { tenant_id: tenantId, item }
        })
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok || !body.checkout_url) throw new Error(`Checkout could not be created (${response.status}).`);
      return { url: body.checkout_url, ref: body.session_id ?? null };
    },
    verifyWebhook(rawBody, headers) {
      const { id } = verifyStandardWebhook(cfg.webhookKey, rawBody, headers);
      const event = JSON.parse(rawBody);
      return { ...event, __id: id };
    },
    normalize(event) {
      const data = event.data ?? {};
      const tenantId = data.metadata?.tenant_id;
      const item = data.metadata?.item ?? itemFor(data.product_id);
      if (!tenantId || !item) return null;
      const base = { eventId: event.__id, tenantId, provider: 'dodo', providerRef: data.subscription_id ?? data.payment_id ?? null, occurredAt: event.timestamp ?? new Date().toISOString(), billingCountry: data.billing?.country ?? null };
      if (item === 'report') {
        return event.type === 'payment.succeeded' ? { ...base, kind: 'report', credits: 1 } : null;
      }
      if (!String(event.type).startsWith('subscription.')) return null;
      const [plan, interval] = item.split(':');
      const status = event.type === 'subscription.on_hold' ? 'on_hold'
        : ['subscription.cancelled', 'subscription.expired', 'subscription.failed'].includes(event.type) ? event.type.slice('subscription.'.length)
        : (data.status ?? 'active');
      return { ...base, kind: 'subscription', plan, interval, status, quantity: data.quantity ?? 1, currentPeriodEnd: data.next_billing_date ?? null };
    }
  };
}

/**
 * Local / demo billing. Entitlements apply immediately on checkout — no Dodo
 * products or webhook keys required. Set PQC_FORGE_BILLING_PROVIDER=mock.
 */
export function mockProvider(env = process.env) {
  return {
    name: 'mock',
    configured() {
      return env.PQC_FORGE_BILLING_PROVIDER === 'mock' || env.PQC_FORGE_MOCK_BILLING === '1';
    },
    async createCheckout({ tenantId, item, quantity = 1, returnUrl }) {
      if (!ITEMS.includes(item)) throw new Error(`Unknown item: ${item}`);
      const sep = returnUrl.includes('?') ? '&' : '?';
      return {
        url: `${returnUrl}${sep}checkout=success&item=${encodeURIComponent(item)}&quantity=${quantity}&mock=1`,
        ref: `mock_${tenantId}_${item}_${Date.now()}`,
        // Server uses applyImmediately to grant access without a webhook.
        applyImmediately: true,
        item,
        quantity: item.startsWith('pro:') ? quantity : 1
      };
    },
    verifyWebhook() {
      throw new Error('Mock billing has no webhooks; entitlements apply at checkout.');
    },
    normalize() {
      return null;
    }
  };
}

export function providerByName(name, env = process.env, fetchImpl) {
  if (name === 'dodo') return dodoProvider(env, fetchImpl);
  if (name === 'mock') return mockProvider(env);
  return null;
}

/** The provider used for new checkouts. One env switch moves new sales to another provider. */
export function checkoutProvider(env = process.env, fetchImpl) {
  return providerByName(env.PQC_FORGE_BILLING_PROVIDER || 'dodo', env, fetchImpl);
}
