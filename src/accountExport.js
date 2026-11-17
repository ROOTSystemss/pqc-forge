// AD-077 (knock-out 2026-11-17): self-serve data export. GET /v1/account/export returns ONE signed JSON bundle with
// everything this account holds: the account record (without its API key hash), every stored record (subscription,
// repositories, job records and results), and every file under the account's folder (uploaded workspaces, job
// output files such as readiness reports and CBOMs) with its SHA-256 and, up to a size cap, its content (base64).
// Secrets are left out and listed (API key hash; the server's signing key is never account data). The bundle is
// signed like every other PQC Forge receipt (receiptDigest + ML-DSA-65), so POST /v1/public/verify-report checks it
// (kind "account-export") and one changed character fails.
import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { canonicalJson } from './canonical.js';
import { signPayload } from './signing.js';
import { verifyReceipt } from './breaklab/receipt.js';
import { listDocsUnder } from './api/docStore.js';

export const EXPORT_SCHEMA = 'pqc-forge.account-export/v1';
export const DEFAULT_INLINE_LIMIT = 25 * 1024 * 1024; // file contents beyond this total are listed (name, size, SHA-256) only

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');
const slash = (p) => String(p).split(path.sep).join('/');
const EXCLUDED = [
  { record: 'tenant.json', field: 'apiKeyHash', why: 'hash of your API key: anyone holding it could test guesses against it; the key itself was shown once and is never stored' },
  { record: '(none)', field: 'signing key', why: "the server's signing key is not account data; its public keys are at /.well-known/rootsystems-signing-keys.json" },
];

function stripSecrets(key, value) {
  if (/(^|\/)tenant\.json$/.test(key) && value && typeof value === 'object') { const { apiKeyHash, ...rest } = value; return rest; }
  return value;
}

async function walk(dir, base = dir) {
  let entries;
  try { entries = await fs.readdir(dir, { withFileTypes: true }); } catch (error) { if (error.code === 'ENOENT') return []; throw error; }
  const out = [];
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...(await walk(full, base)));
    else if (e.isFile() && !e.name.endsWith('.tmp')) out.push({ full, rel: slash(path.relative(base, full)) });
  }
  return out.sort((a, b) => a.rel.localeCompare(b.rel));
}

export async function buildAccountExport({ apiHome, tenant, signingKey, inlineLimit = DEFAULT_INLINE_LIMIT, now = new Date() }) {
  const dir = path.join(apiHome, 'tenants', tenant.tenantId);
  const records = (await listDocsUnder(apiHome, dir)).map(({ key, value }) => ({ key, value: stripSecrets(key, value) }));
  const files = [];
  let inlined = 0;
  for (const { full, rel } of await walk(dir)) {
    const data = await fs.readFile(full);
    const entry = { path: rel, bytes: data.length, sha256: sha256(data) };
    // Without a database the JSON records live on disk too: export them as records, secrets removed.
    if (rel.endsWith('.json') && !rel.startsWith('workspaces/') && !records.some((r) => r.key === rel)) {
      try { records.push({ key: rel, value: stripSecrets(rel, JSON.parse(data.toString('utf8'))) }); continue; } catch { /* not JSON: keep as a file */ }
    }
    if (inlined + data.length <= inlineLimit) { entry.contentBase64 = data.toString('base64'); inlined += data.length; }
    else entry.omitted = 'over the export size limit: listed with its SHA-256 only';
    files.push(entry);
  }
  records.sort((a, b) => a.key.localeCompare(b.key));
  const { apiKeyHash, ...account } = tenant;
  const doc = {
    schema: EXPORT_SCHEMA,
    generatedAt: new Date(now).toISOString(),
    tenantId: tenant.tenantId,
    account,
    records,
    files,
    excluded: EXCLUDED,
    note: 'Everything PQC Forge stores for this account. Uploaded files and job outputs are included up to the size limit; larger ones are listed with their SHA-256. Check this file at POST /v1/public/verify-report: it reads account-export.',
  };
  const receiptDigest = `sha256:${sha256(Buffer.from(canonicalJson(doc), 'utf8'))}`;
  const withDigest = { ...doc, receiptDigest };
  return { ...withDigest, signature: signPayload(withDigest, signingKey) };
}

export function verifyAccountExport(doc, trustedPublicKeys = null) {
  if (!doc || doc.schema !== EXPORT_SCHEMA) return { valid: false, errors: ['not a PQC Forge account export'] };
  return verifyReceipt(doc, { trustedPublicKeys });
}
