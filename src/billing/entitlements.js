import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { PLANS } from './plans.js';

// What an account has paid for, and which repositories use it. Stored per tenant,
// next to tenant.json. Data minimization: repositories are kept only as a SHA-256
// of their normalized name, never the name itself, and no card or billing
// details are stored (the payment provider holds those).

export const SUBSCRIPTION_SCHEMA = 'pqc-forge.subscription/v1';
const ACTIVE = new Set(['active', 'on_hold']); // on_hold: a failed renewal being retried, access kept

function tenantDir(apiHome, tenantId) {
  if (!/^t_[0-9a-f]{16}$/.test(tenantId ?? '')) throw new Error('Invalid tenant id.');
  return path.join(apiHome, 'tenants', tenantId);
}

async function readJson(file, fallback) {
  try { return JSON.parse(await fs.readFile(file, 'utf8')); }
  catch (error) { if (error.code === 'ENOENT') return fallback; throw error; }
}

async function writeJson(file, value) {
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
  await fs.writeFile(tmp, `${JSON.stringify(value, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  await fs.rename(tmp, file);
}

export function repoFingerprint(repo) {
  const normalized = String(repo ?? '').trim().toLowerCase().replace(/\.git$/, '').replace(/^https?:\/\/[^/]+\//, '');
  if (!/^[a-z0-9_.-]+\/[a-z0-9_.-]+$/.test(normalized)) throw new Error('Repository must look like owner/name.');
  return `sha256:${createHash('sha256').update(normalized).digest('hex')}`;
}

export async function readSubscription(apiHome, tenantId) {
  return readJson(path.join(tenantDir(apiHome, tenantId), 'subscription.json'), null);
}

/**
 * Apply a normalized billing event. Returns { applied, reason }.
 * Events older than the last one applied are ignored, so a late retry of an old
 * event can never undo a newer cancellation or upgrade.
 */
export async function applySubscriptionEvent(apiHome, tenantId, event) {
  const file = path.join(tenantDir(apiHome, tenantId), 'subscription.json');
  const current = await readJson(file, null);
  const occurredAt = Date.parse(event.occurredAt);
  if (!Number.isFinite(occurredAt)) throw new Error('Billing event needs a valid occurredAt.');
  if (current?.lastEventAt && Date.parse(current.lastEventAt) > occurredAt) return { applied: false, reason: 'older than the last applied event' };
  if (event.kind === 'report') {
    const next = { ...(current ?? { schema: SUBSCRIPTION_SCHEMA, plan: 'community', status: 'none' }), reportCredits: (current?.reportCredits ?? 0) + (event.credits ?? 1), lastEventAt: event.occurredAt, updatedAt: new Date().toISOString() };
    await writeJson(file, next);
    return { applied: true, reason: 'report credit added' };
  }
  if (!PLANS[event.plan]) throw new Error(`Unknown plan: ${event.plan}`);
  const next = {
    schema: SUBSCRIPTION_SCHEMA,
    plan: event.plan,
    status: event.status,
    interval: event.interval ?? current?.interval ?? 'month',
    quantity: Math.max(1, Number(event.quantity ?? 1) || 1),
    currentPeriodEnd: event.currentPeriodEnd ?? current?.currentPeriodEnd ?? null,
    provider: event.provider,
    providerRef: event.providerRef ?? null,
    reportCredits: current?.reportCredits ?? 0,
    lastEventAt: event.occurredAt,
    updatedAt: new Date().toISOString()
  };
  await writeJson(file, next);
  return { applied: true, reason: `${next.plan} ${next.status}` };
}

/** Invoiced plans (self-hosted, or a customer who pays outside the checkout) are set by an operator. */
export async function setManualPlan(apiHome, tenantId, { plan, quantity = 1, until = null }) {
  if (!PLANS[plan]) throw new Error(`Unknown plan: ${plan}`);
  return applySubscriptionEvent(apiHome, tenantId, {
    plan, status: 'active', quantity, currentPeriodEnd: until, provider: 'manual', providerRef: null, occurredAt: new Date().toISOString()
  });
}

export async function entitlement(apiHome, tenantId, now = Date.now()) {
  const sub = await readSubscription(apiHome, tenantId);
  const expired = sub?.currentPeriodEnd ? Date.parse(sub.currentPeriodEnd) < now : false;
  const paid = sub && ACTIVE.has(sub.status) && !expired && sub.plan !== 'community';
  const planId = paid ? sub.plan : 'community';
  const plan = PLANS[planId];
  const repoLimit = plan.perRepo ? sub.quantity : plan.id === 'selfhosted' ? (sub.quantity > 1 ? sub.quantity : null) : plan.repoLimit;
  const repos = await readJson(path.join(tenantDir(apiHome, tenantId), 'repos.json'), { fingerprints: [] });
  return {
    plan: planId,
    status: sub?.status ?? 'none',
    interval: paid ? sub.interval : null,
    currentPeriodEnd: paid ? sub.currentPeriodEnd : null,
    privateRepos: plan.privateRepos,
    repoLimit,
    reposInUse: repos.fingerprints.length,
    reportCredits: sub?.reportCredits ?? 0,
    features: plan.features
  };
}

/**
 * The CI gate asks: may this repository run? A repository already registered to the
 * account always may. A new one is registered if the plan has room. Private
 * repositories need a paid plan.
 */
export async function checkRepository(apiHome, tenantId, { repo, isPrivate }) {
  const fp = repoFingerprint(repo);
  const ent = await entitlement(apiHome, tenantId);
  if (isPrivate && !ent.privateRepos) return { allowed: false, plan: ent.plan, reason: 'Private repositories need the Pro or Team plan.' };
  const file = path.join(tenantDir(apiHome, tenantId), 'repos.json');
  const repos = await readJson(file, { fingerprints: [] });
  if (repos.fingerprints.includes(fp)) return { allowed: true, plan: ent.plan, reason: 'repository already on this plan' };
  if (ent.repoLimit !== null && repos.fingerprints.length >= ent.repoLimit) {
    return { allowed: false, plan: ent.plan, reason: `This plan covers ${ent.repoLimit} repositor${ent.repoLimit === 1 ? 'y' : 'ies'} and all are in use. Add repositories or move to Team.` };
  }
  repos.fingerprints.push(fp);
  await writeJson(file, repos);
  return { allowed: true, plan: ent.plan, reason: 'repository added to this plan' };
}

export async function releaseRepository(apiHome, tenantId, repo) {
  const fp = repoFingerprint(repo);
  const file = path.join(tenantDir(apiHome, tenantId), 'repos.json');
  const repos = await readJson(file, { fingerprints: [] });
  const before = repos.fingerprints.length;
  repos.fingerprints = repos.fingerprints.filter((x) => x !== fp);
  await writeJson(file, repos);
  return { released: repos.fingerprints.length < before };
}

/** Spend one report credit (the self-serve readiness report). */
export async function useReportCredit(apiHome, tenantId) {
  const file = path.join(tenantDir(apiHome, tenantId), 'subscription.json');
  const sub = await readJson(file, null);
  if (!sub || !(sub.reportCredits > 0)) return false;
  sub.reportCredits -= 1;
  sub.updatedAt = new Date().toISOString();
  await writeJson(file, sub);
  return true;
}

/** Dedupe webhook deliveries by the provider's event id. */
export async function claimEvent(apiHome, provider, eventId) {
  if (!/^[A-Za-z0-9_.:-]{1,200}$/.test(eventId ?? '')) throw new Error('Invalid event id.');
  const dir = path.join(apiHome, 'billing-events', provider);
  await fs.mkdir(dir, { recursive: true });
  const name = createHash('sha256').update(eventId).digest('hex');
  try {
    await fs.writeFile(path.join(dir, name), new Date().toISOString(), { flag: 'wx' });
    return true;
  } catch (error) {
    if (error.code === 'EEXIST') return false;
    throw error;
  }
}
