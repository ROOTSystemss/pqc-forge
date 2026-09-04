import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';

export const TENANT_SCHEMA = 'pqc-forge.tenant/v1';

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function tenantDirectory(apiHome, tenantId) {
  return path.join(apiHome, 'tenants', tenantId);
}

function tenantRecordPath(apiHome, tenantId) {
  return path.join(tenantDirectory(apiHome, tenantId), 'tenant.json');
}

/**
 * Create a new tenant. Returns the raw API key exactly once — only its
 * SHA-256 hash is ever persisted, matching how signing.js handles secret
 * keys. Losing the returned key means provisioning a new one; there is no
 * recovery path, by design.
 */
export async function createTenant(apiHome, { name } = {}) {
  if (!name || typeof name !== 'string' || !name.trim()) throw new Error('Tenant creation requires a non-empty name.');
  const tenantId = `t_${randomBytes(8).toString('hex')}`;
  const secret = randomBytes(24).toString('base64url');
  const apiKey = `pqcf_${tenantId}_${secret}`;
  const record = {
    schema: TENANT_SCHEMA,
    tenantId,
    name: name.trim(),
    createdAt: new Date().toISOString(),
    apiKeyHash: `sha256:${sha256(apiKey)}`
  };
  const directory = tenantDirectory(apiHome, tenantId);
  try {
    await fs.access(directory);
    throw new Error(`Tenant directory already exists: ${directory}`);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  await fs.mkdir(path.join(directory, 'workspaces'), { recursive: true });
  await fs.mkdir(path.join(directory, 'jobs'), { recursive: true });
  await fs.writeFile(tenantRecordPath(apiHome, tenantId), `${JSON.stringify(record, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  try { await fs.chmod(tenantRecordPath(apiHome, tenantId), 0o600); } catch { /* best-effort outside POSIX filesystems */ }
  return { tenantId, apiKey, record };
}

export async function loadTenant(apiHome, tenantId) {
  if (!/^t_[0-9a-f]{16}$/.test(tenantId ?? '')) return null;
  try {
    const record = JSON.parse(await fs.readFile(tenantRecordPath(apiHome, tenantId), 'utf8'));
    if (record.schema !== TENANT_SCHEMA || record.tenantId !== tenantId) return null;
    return record;
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
}

/**
 * Authenticate a bearer API key of the form `pqcf_<tenantId>_<secret>`.
 * The tenantId embedded in the key gives an O(1) record lookup — the server
 * never compares a presented key against every tenant's hash, which avoids
 * both an O(n) scan and the timing signal that scan order would leak.
 * The final comparison is still constant-time.
 */
export async function authenticate(apiHome, authorizationHeader) {
  const match = /^Bearer\s+(pqcf_(t_[0-9a-f]{16})_[A-Za-z0-9_-]+)$/.exec(authorizationHeader ?? '');
  if (!match) return null;
  const [, apiKey, tenantId] = match;
  const record = await loadTenant(apiHome, tenantId);
  if (!record) return null;
  const presented = Buffer.from(sha256(apiKey), 'hex');
  const expected = Buffer.from(record.apiKeyHash.replace(/^sha256:/, ''), 'hex');
  if (presented.length !== expected.length || !timingSafeEqual(presented, expected)) return null;
  return record;
}

export function tenantWorkspacesDirectory(apiHome, tenantId) {
  return path.join(tenantDirectory(apiHome, tenantId), 'workspaces');
}

export function tenantJobsDirectory(apiHome, tenantId) {
  return path.join(tenantDirectory(apiHome, tenantId), 'jobs');
}
