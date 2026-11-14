// Abuse limits for the hosted API (audit finding 2026-11-13, fixed 2026-11-14).
//
// 1. Signup rate limit. /v1/signup is public and needs no email, so without a limit anyone could create
//    unlimited accounts. Two counters, both in memory:
//      - per client address: PQC_FORGE_SIGNUPS_PER_IP_HOUR (default 5) an hour;
//      - for the whole server: PQC_FORGE_SIGNUPS_PER_DAY (default 200) a day. This one holds even against
//        rotating or forged addresses.
//    The client address is the right-most PUBLIC address in X-Forwarded-For (the proxy in front of us
//    appends the address it saw; a client can only prepend made-up ones), else the socket address.
//    A restart resets the counters (accepted: the daily cap still bounds a burst).
// 2. Storage quota per account. Every workspace upload is checked before anything is written: at most
//    N workspaces and B bytes per account, by plan (Community 10 workspaces / 100 MiB; paid 200 / 2 GiB).
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { isPrivateAddress } from './hosted-safety.js';

const num = (v, d) => { const n = Number(v); return Number.isFinite(n) && n > 0 ? n : d; };
const HOUR = 60 * 60 * 1000, DAY = 24 * HOUR;

export function clientAddress(req) {
  const hops = String(req.headers['x-forwarded-for'] || '').split(',').map((s) => s.trim()).filter(Boolean);
  for (let i = hops.length - 1; i >= 0; i--) {
    const ip = hops[i].replace(/^::ffff:/, '');
    try { if (!isPrivateAddress(ip)) return ip; } catch { /* not an address */ }
  }
  return String(req.socket?.remoteAddress || 'unknown').replace(/^::ffff:/, '');
}

export function createSignupLimiter({ perIpPerHour, perDay, now = Date.now } = {}) {
  const ipLimit = () => num(perIpPerHour ?? process.env.PQC_FORGE_SIGNUPS_PER_IP_HOUR, 5);
  const dayLimit = () => num(perDay ?? process.env.PQC_FORGE_SIGNUPS_PER_DAY, 200);
  const byIp = new Map();
  let all = [];
  return {
    // Counts the attempt when allowed. Returns { ok, retryAfterSeconds, reason }.
    take(ip) {
      const t = now();
      all = all.filter((x) => t - x < DAY);
      const mine = (byIp.get(ip) || []).filter((x) => t - x < HOUR);
      if (all.length >= dayLimit()) return { ok: false, retryAfterSeconds: Math.ceil((all[0] + DAY - t) / 1000), reason: 'server' };
      if (mine.length >= ipLimit()) { byIp.set(ip, mine); return { ok: false, retryAfterSeconds: Math.ceil((mine[0] + HOUR - t) / 1000), reason: 'address' }; }
      mine.push(t); all.push(t); byIp.set(ip, mine);
      if (byIp.size > 50000) for (const k of byIp.keys()) { if (!(byIp.get(k) || []).some((x) => t - x < HOUR)) byIp.delete(k); }
      return { ok: true };
    },
  };
}

export const QUOTAS = {
  community: { workspaces: 10, bytes: 100 * 1024 * 1024 },
  paid: { workspaces: 200, bytes: 2 * 1024 * 1024 * 1024 },
};
export function quotaFor(plan) { return plan && plan !== 'community' ? QUOTAS.paid : QUOTAS.community; }

async function dirBytes(dir) {
  let total = 0;
  let entries;
  try { entries = await fs.readdir(dir, { withFileTypes: true }); } catch { return 0; }
  for (const e of entries) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) total += await dirBytes(p);
    else if (e.isFile()) { try { total += (await fs.stat(p)).size; } catch { /* gone */ } }
  }
  return total;
}

// Current use of one account's workspaces directory: { workspaces, bytes }.
export async function workspaceUsage(workspacesDir) {
  let entries;
  try { entries = await fs.readdir(workspacesDir, { withFileTypes: true }); } catch { return { workspaces: 0, bytes: 0 }; }
  const dirs = entries.filter((e) => e.isDirectory() && /^ws_[0-9a-f]{16}$/.test(e.name));
  let bytes = 0;
  for (const d of dirs) bytes += await dirBytes(path.join(workspacesDir, d.name));
  return { workspaces: dirs.length, bytes };
}

// Bytes this upload would add (decoded), without writing anything.
export function uploadBytes(files) {
  let total = 0;
  for (const f of files || []) total += Buffer.byteLength(String(f?.content ?? ''), f?.encoding === 'base64' ? 'base64' : 'utf8');
  return total;
}
