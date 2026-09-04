import { createServer } from 'node:http';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { authenticate, createTenant, tenantJobsDirectory, tenantWorkspacesDirectory } from './tenants.js';
import { createWorkspace, workspaceExists } from './workspace.js';
import { createJobQueue, JOB_TYPES } from './jobs.js';
import { verifyReceipt } from '../breaklab/receipt.js';
import { loadSigningKey } from '../signing.js';
import { VERSION } from '../version.js';

const MAX_BODY_BYTES = 68 * 1024 * 1024; // above the 64 MiB workspace cap, plus headroom for JSON overhead

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
export function createApiServer({ apiHome, signingKeyPath = null, globalConcurrency, tenantConcurrency, dockerConcurrency, handlers } = {}) {
  if (!apiHome) throw new Error('createApiServer requires apiHome.');
  const resolveSigningKey = async () => (await loadSigningKey(signingKeyPath)).key;
  const queue = createJobQueue({
    apiHome, resolveSigningKey,
    ...(globalConcurrency !== undefined ? { globalConcurrency } : {}),
    ...(tenantConcurrency !== undefined ? { tenantConcurrency } : {}),
    ...(dockerConcurrency !== undefined ? { dockerConcurrency } : {}),
    ...(handlers !== undefined ? { handlers } : {})
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
        try {
          return await queue.submit(tenant.tenantId, body.type, body.params ?? {});
        } catch (error) {
          throw new HttpError(400, error.message);
        }
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
    {
      method: 'POST', pattern: /^\/v1\/verify-receipt$/,
      handler: async (req, res, params, body) => {
        if (!body.receipt) throw new HttpError(400, 'Body requires a receipt.');
        return verifyReceipt(body.receipt, { trustedPublicKeys: body.trustedPublicKeys ?? null });
      }
    }
  ];

  const server = createServer(async (req, res) => {
    try {
      await ensureReconciled();
      const url = new URL(req.url, 'http://internal');
      const route = routes.find((candidate) => candidate.method === req.method && candidate.pattern.test(url.pathname));
      if (!route) { send(res, 404, { error: 'Not found.' }); return; }
      const match = route.pattern.exec(url.pathname);
      const tenant = route.public ? null : await requireTenant(req);
      const body = req.method === 'GET' ? {} : await readJsonBody(req);
      const result = await route.handler(req, res, match.slice(1), body, tenant);
      send(res, route.status ?? 200, result);
    } catch (error) {
      const statusCode = error.statusCode ?? 500;
      if (statusCode >= 500) {
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
