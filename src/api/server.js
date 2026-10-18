import { createServer } from 'node:http';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { CONTENT_TYPES, resolveStaticFile } from './static.js';
import { authenticate, createTenant, tenantJobsDirectory, tenantWorkspacesDirectory } from './tenants.js';
import { createWorkspace, workspaceExists } from './workspace.js';
import { createJobQueue, JOB_TYPES } from './jobs.js';
import { verifyReceipt } from '../breaklab/receipt.js';
import { loadSigningKey } from '../signing.js';
import { VERSION } from '../version.js';
import { publicCatalog, SELF_SERVE_PLANS, INTERVALS } from '../billing/plans.js';
import { entitlement, checkRepository, releaseRepository, applySubscriptionEvent, claimEvent, assertJobAllowed } from '../billing/entitlements.js';
import { checkoutProvider, providerByName } from '../billing/providers.js';
import { normalizeCountry, isBlockedCountry, grantsAccess } from '../billing/exportControl.js';
import { loadTenant } from './tenants.js';

const MAX_BODY_BYTES = 68 * 1024 * 1024; // above the 64 MiB workspace cap, plus headroom for JSON overhead
const SIGNUP_NAME_MAX = 80;

function readRawBody(req, limit = 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let bytes = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      bytes += chunk.length;
      if (bytes > limit) { reject(Object.assign(new Error('Request body too large.'), { statusCode: 413 })); req.destroy(); return; }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let bytes = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      bytes += chunk.length;
      if (bytes > MAX_BODY_BYTES) {
        reject(Object.assign(new Error('Request body too large.'), { statusCode: 413 }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (chunks.length === 0) { resolve({}); return; }
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(Object.assign(new Error('Request body must be valid JSON.'), { statusCode: 400 }));
      }
    });
    req.on('error', reject);
  });
}

function send(res, statusCode, body) {
  const payload = `${JSON.stringify(body, null, 2)}\n`;
  res.writeHead(statusCode, { 'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(payload) });
  res.end(payload);
}

class HttpError extends Error {
  constructor(statusCode, message) {
    super(message);
    this.statusCode = statusCode;
  }
}

/** Accept https production URLs and local http for mock/dev return after checkout. */
function resolveReturnUrl(requested, billingEnv) {
  if (typeof requested === 'string') {
    const trimmed = requested.trim();
    if (/^https:\/\/[^\s"'<>]+$/i.test(trimmed)) return trimmed;
    if (/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?(\/|$)/i.test(trimmed)) return trimmed;
  }
  const fallback = billingEnv.PQC_FORGE_PUBLIC_URL || '';
  if (/^https:\/\//i.test(fallback) || /^http:\/\/(localhost|127\.0\.0\.1)/i.test(fallback)) return fallback;
  return 'https://rootsystems.app/pricing';
}

function mockSubscriptionEvent(tenantId, item, quantity) {
  const occurredAt = new Date().toISOString();
  if (item === 'report') {
    return { kind: 'report', credits: 1, provider: 'mock', providerRef: `mock_report_${Date.now()}`, occurredAt };
  }
  const [plan, interval] = item.split(':');
  return {
    kind: 'subscription',
    plan,
    interval,
    status: 'active',
    quantity,
    currentPeriodEnd: new Date(Date.now() + (interval === 'year' ? 365 : 30) * 864e5).toISOString(),
    provider: 'mock',
    providerRef: `mock_sub_${Date.now()}`,
    occurredAt
  };
}

/**
 * Create (but do not start) the PQC Forge API server.
 *
 * `apiHome` roots all tenant data (`<apiHome>/tenants/<tenantId>/...`);
 * every request is authenticated to exactly one tenant, and every
 * filesystem path a handler touches is resolved underneath that tenant's
 * own directory (see workspace.js) — there is no code path from an
 * authenticated request to another tenant's data or to an arbitrary host
 * path.
 */
export function createApiServer({ apiHome, signingKeyPath = null, globalConcurrency, tenantConcurrency, dockerConcurrency, handlers, safety, webDistPath = null, billingEnv = process.env, fetchImpl = globalThis.fetch } = {}) {
  if (!apiHome) throw new Error('createApiServer requires apiHome.');
  const resolveSigningKey = async () => (await loadSigningKey(signingKeyPath)).key;
  const queue = createJobQueue({
    apiHome, resolveSigningKey,
    ...(globalConcurrency !== undefined ? { globalConcurrency } : {}),
    ...(tenantConcurrency !== undefined ? { tenantConcurrency } : {}),
    ...(dockerConcurrency !== undefined ? { dockerConcurrency } : {}),
    ...(handlers !== undefined ? { handlers } : {}),
    ...(safety !== undefined ? { safety } : {})
  });
  let reconciled = false;

  async function ensureReconciled() {
    if (reconciled) return;
    reconciled = true;
    let tenantIds = [];
    try {
      tenantIds = await fs.readdir(path.join(apiHome, 'tenants'));
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    await queue.reconcile(tenantIds);
  }

  async function requireTenant(req) {
    const record = await authenticate(apiHome, req.headers.authorization);
    if (!record) throw new HttpError(401, 'Missing or invalid Authorization: Bearer <api key>.');
    return record;
  }

  const routes = [
    {
      method: 'GET', pattern: /^\/v1\/health$/, public: true,
      handler: async () => ({ status: 'ok', version: VERSION, ...queue.stats() })
    },
    {
      method: 'POST', pattern: /^\/v1\/signup$/, public: true, status: 201,
      handler: async (req, res, params, body) => {
        const name = typeof body.name === 'string' ? body.name.trim() : '';
        if (name.length < 2 || name.length > SIGNUP_NAME_MAX) {
          throw new HttpError(400, `Provide a name between 2 and ${SIGNUP_NAME_MAX} characters.`);
        }
        if (!/^[\p{L}\p{N} .'_&+-]+$/u.test(name)) {
          throw new HttpError(400, 'Name may only include letters, numbers, spaces, and .\'+_&-.');
        }
        const email = typeof body.email === 'string' ? body.email.trim().slice(0, 160) : '';
        if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
          throw new HttpError(400, 'Email does not look valid.');
        }
        await fs.mkdir(apiHome, { recursive: true });
        const created = await createTenant(apiHome, { name, email: email || undefined });
        const ent = await entitlement(apiHome, created.tenantId);
        return {
          tenantId: created.tenantId,
          apiKey: created.apiKey,
          plan: ent.plan,
          message: 'Save this API key now — it is shown once. Only its hash is stored.'
        };
      }
    },
    {
      method: 'POST', pattern: /^\/v1\/workspaces$/,
      handler: async (req, res, params, body, tenant) => {
        if (!Array.isArray(body.files)) throw new HttpError(400, 'Body requires a files array: [{ path, content, encoding? }].');
        let result;
        try {
          result = await createWorkspace(apiHome, tenant.tenantId, body.files);
        } catch (error) {
          throw new HttpError(400, error.message);
        }
        return { workspaceId: result.workspaceId, files: result.files, totalBytes: result.totalBytes };
      }
    },
    {
      method: 'GET', pattern: /^\/v1\/workspaces\/([^/]+)$/,
      handler: async (req, res, [workspaceId], body, tenant) => {
        const exists = await workspaceExists(apiHome, tenant.tenantId, workspaceId);
        if (!exists) throw new HttpError(404, `No such workspace: ${workspaceId}`);
        return { workspaceId, exists: true };
      }
    },
    {
      method: 'POST', pattern: /^\/v1\/jobs$/, status: 202,
      handler: async (req, res, params, body, tenant) => {
        if (typeof body.type !== 'string') throw new HttpError(400, `Body requires a job type: one of ${JOB_TYPES.join(', ')}.`);
        const ent = await entitlement(apiHome, tenant.tenantId);
        const gate = assertJobAllowed(ent, body.type, body.params ?? {});
        if (!gate.allowed) throw new HttpError(402, gate.reason);
        try {
          return await queue.submit(tenant.tenantId, body.type, body.params ?? {});
        } catch (error) {
          throw new HttpError(400, error.message);
        }
      }
    },
    {
      method: 'GET', pattern: /^\/v1\/jobs$/,
      handler: async (req, res, params, body, tenant) => {
        const url = new URL(req.url, 'http://internal');
        return queue.listJobs(tenant.tenantId, {
          limit: url.searchParams.get('limit') ?? undefined,
          status: url.searchParams.get('status') ?? null,
          type: url.searchParams.get('type') ?? null
        });
      }
    },
    {
      method: 'GET', pattern: /^\/v1\/jobs\/([^/]+)$/,
      handler: async (req, res, [jobId], body, tenant) => {
        const record = await queue.getJob(tenant.tenantId, jobId);
        if (!record) throw new HttpError(404, `No such job: ${jobId}`);
        return record;
      }
    },
    {
      // A job's downloadable file (the readiness report as HTML or signed JSON), by exact name only.
      method: 'GET', pattern: /^\/v1\/jobs\/([^/]+)\/files\/([a-z0-9.-]+)$/,
      handler: async (req, res, [jobId, name], body, tenant) => {
        const file = await queue.getFile(tenant.tenantId, jobId, name);
        if (!file) throw new HttpError(404, 'No such file for this job.');
        res.writeHead(200, { 'content-type': file.contentType, 'content-disposition': `attachment; filename="${name}"`, 'cache-control': 'no-store' });
        res.end(file.body);
        return null;
      }
    },
    {
      method: 'GET', pattern: /^\/v1\/jobs\/([^/]+)\/result$/,
      handler: async (req, res, [jobId], body, tenant) => {
        const record = await queue.getJob(tenant.tenantId, jobId);
        if (!record) throw new HttpError(404, `No such job: ${jobId}`);
        if (record.status !== 'succeeded' && record.status !== 'failed') throw new HttpError(409, `Job is still ${record.status}; poll GET /v1/jobs/${jobId} until it reaches a terminal state.`);
        if (record.status === 'failed') throw new HttpError(422, record.error ?? 'Job failed.');
        const result = await queue.getResult(tenant.tenantId, jobId);
        if (!result) throw new HttpError(404, 'Job succeeded but its result is missing.');
        return result;
      }
    },
    // ---------- subscription ----------
    {
      method: 'GET', pattern: /^\/v1\/plans$/, public: true,
      handler: async () => {
        const provider = checkoutProvider(billingEnv, fetchImpl);
        return {
          ...publicCatalog(),
          checkoutAvailable: Boolean(provider?.configured()),
          billingProvider: provider?.configured() ? provider.name : null
        };
      }
    },
    {
      method: 'GET', pattern: /^\/v1\/subscription$/,
      handler: async (req, res, params, body, tenant) => entitlement(apiHome, tenant.tenantId)
    },
    {
      method: 'POST', pattern: /^\/v1\/billing\/checkout$/,
      handler: async (req, res, params, body, tenant) => {
        const provider = checkoutProvider(billingEnv, fetchImpl);
        if (!provider || !provider.configured()) throw new HttpError(503, 'Checkout is not available yet. Contact RootSystems to buy a plan, or set PQC_FORGE_BILLING_PROVIDER=mock for local demo.');
        const item = body.item === 'report' ? 'report' : `${body.plan}:${body.interval ?? 'month'}`;
        if (item !== 'report' && (!SELF_SERVE_PLANS.includes(body.plan) || !INTERVALS.includes(body.interval ?? 'month'))) {
          throw new HttpError(400, 'Choose plan "pro" or "team" and interval "month" or "year", or item "report". Business and Self-hosted are invoiced — contact RootSystems.');
        }
        const country = normalizeCountry(body.country);
        if (!country) throw new HttpError(400, 'Choose the country you are buying from (two-letter code, e.g. "US").');
        if (isBlockedCountry(country, billingEnv)) throw new HttpError(451, 'PQC Forge is cryptographic software and cannot be sold to buyers in this country under export-control and sanctions rules.');
        const quantity = Math.min(500, Math.max(1, Number.parseInt(body.quantity ?? 1, 10) || 1));
        const returnUrl = resolveReturnUrl(body.returnUrl, billingEnv);
        let checkout;
        try {
          checkout = await provider.createCheckout({ tenantId: tenant.tenantId, item, quantity, returnUrl });
        } catch (error) {
          throw new HttpError(502, error.message);
        }
        if (checkout.applyImmediately) {
          const event = mockSubscriptionEvent(tenant.tenantId, checkout.item ?? item, checkout.quantity ?? quantity);
          await applySubscriptionEvent(apiHome, tenant.tenantId, event);
        }
        return { url: checkout.url, ref: checkout.ref ?? null };
      }
    },
    {
      method: 'POST', pattern: /^\/v1\/billing\/webhook\/([a-z]+)$/, public: true, raw: true,
      handler: async (req, res, [providerName], rawBody) => {
        const provider = providerByName(providerName, billingEnv, fetchImpl);
        if (!provider || !provider.configured()) throw new HttpError(404, 'Unknown billing provider.');
        let event;
        try { event = provider.verifyWebhook(rawBody, req.headers); } catch (error) { throw new HttpError(400, error.message); }
        const normalized = provider.normalize(event);
        if (!normalized) return { received: true, applied: false, reason: 'event not relevant to PQC Forge' };
        if (!(await loadTenant(apiHome, normalized.tenantId))) return { received: true, applied: false, reason: 'unknown account' };
        if (!(await claimEvent(apiHome, provider.name, normalized.eventId))) return { received: true, applied: false, reason: 'duplicate delivery' };
        // The billing country the provider saw wins over what was chosen at checkout; a sanctioned
        // country never gets access (cancellations still apply).
        if (grantsAccess(normalized) && isBlockedCountry(normalized.billingCountry, billingEnv)) {
          console.warn(`[billing] export control: refused ${normalized.kind} for account ${normalized.tenantId} (billing country blocked); refund ${normalized.providerRef ?? 'the payment'}`);
          return { received: true, applied: false, reason: 'export control: billing country is blocked; refund this payment' };
        }
        const result = await applySubscriptionEvent(apiHome, normalized.tenantId, normalized);
        return { received: true, ...result };
      }
    },
    {
      method: 'POST', pattern: /^\/v1\/gate\/check$/,
      handler: async (req, res, params, body, tenant) => {
        try {
          return await checkRepository(apiHome, tenant.tenantId, { repo: body.repo, isPrivate: body.private === true });
        } catch (error) {
          throw new HttpError(400, error.message);
        }
      }
    },
    {
      method: 'POST', pattern: /^\/v1\/gate\/release$/,
      handler: async (req, res, params, body, tenant) => {
        try { return await releaseRepository(apiHome, tenant.tenantId, body.repo); } catch (error) { throw new HttpError(400, error.message); }
      }
    },
    {
      method: 'POST', pattern: /^\/v1\/verify-receipt$/,
      handler: async (req, res, params, body) => {
        if (!body.receipt) throw new HttpError(400, 'Body requires a receipt.');
        return verifyReceipt(body.receipt, { trustedPublicKeys: body.trustedPublicKeys ?? null });
      }
    }
  ];

  const resolvedWebDist = webDistPath ? path.resolve(webDistPath) : null;

  const server = createServer(async (req, res) => {
    // Baseline response hardening on every route, including the static
    // dashboard: never let a browser guess a content-type into something
    // executable, and never leak this origin's URLs (job ids, tenant ids)
    // to a third party via the Referer header on an outbound link.
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    // Permissive CORS: the dashboard authenticates with a bearer API key in
    // a header, never a cookie, so there is no ambient credential for a
    // third-party origin to ride along with — `*` here does not widen what
    // a caller can do, only where a browser will let a script call from.
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Headers', 'authorization, content-type, webhook-id, webhook-timestamp, webhook-signature');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }
    try {
      await ensureReconciled();
      const url = new URL(req.url, 'http://internal');
      const route = routes.find((candidate) => candidate.method === req.method && candidate.pattern.test(url.pathname));
      if (!route) {
        if (req.method === 'GET' && resolvedWebDist && !url.pathname.startsWith('/v1/')) {
          const file = await resolveStaticFile(resolvedWebDist, url.pathname);
          if (file) {
            const data = await fs.readFile(file);
            res.writeHead(200, { 'content-type': CONTENT_TYPES[path.extname(file).toLowerCase()] ?? 'application/octet-stream' });
            res.end(data);
            return;
          }
        }
        send(res, 404, { error: 'Not found.' });
        return;
      }
      const match = route.pattern.exec(url.pathname);
      const tenant = route.public ? null : await requireTenant(req);
      const body = req.method === 'GET' ? {} : route.raw ? await readRawBody(req) : await readJsonBody(req);
      const result = await route.handler(req, res, match.slice(1), body, tenant);
      if (res.headersSent || res.writableEnded) return; // the handler wrote a file download itself
      send(res, route.status ?? 200, result);
    } catch (error) {
      const statusCode = error.statusCode ?? 500;
      if (statusCode >= 500 && !(error instanceof HttpError)) {
        // Never leak internals of an unexpected failure to the caller.
        console.error(error);
        send(res, 500, { error: 'Internal server error.' });
      } else {
        send(res, statusCode, { error: error.message });
      }
    }
  });

  return { server, queue, apiHome };
}

export async function provisionTenant(apiHome, name) {
  await fs.mkdir(apiHome, { recursive: true });
  return createTenant(apiHome, { name });
}

export { tenantJobsDirectory, tenantWorkspacesDirectory };
