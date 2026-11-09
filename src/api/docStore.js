import { randomBytes } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';

/**
 * Where the API keeps its small JSON records: accounts (tenant.json, with only the API key's hash),
 * subscription.json, repos.json, billing-event claims, and each job's job.json and result.json.
 *
 * Without DATABASE_URL they are files under apiHome, as before. With DATABASE_URL they are rows in one
 * Postgres table keyed by the same relative path, so they survive a host that loses its disk on sleep or
 * redeploy (the hosted service runs on one). Uploaded workspaces and job output files stay on disk.
 */

const TABLE = 'pqcf_documents';
let pool = null;
let ready = null;

function databaseUrl() {
  return process.env.DATABASE_URL || '';
}

export function usingDatabase() {
  return Boolean(databaseUrl());
}

async function db() {
  if (!pool) {
    const { default: pg } = await import('pg');
    const url = databaseUrl();
    const local = /@(localhost|127\.0\.0\.1)[:/]/.test(url);
    pool = new pg.Pool({ connectionString: url, max: 5, allowExitOnIdle: true, ssl: local ? false : { rejectUnauthorized: true } });
    ready = pool.query(`CREATE TABLE IF NOT EXISTS ${TABLE} (key text PRIMARY KEY, value jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now())`);
  }
  await ready;
  return pool;
}

/** Closes the database pool (tests, shutdown). */
export async function closeDocStore() {
  if (pool) { const p = pool; pool = null; ready = null; await p.end(); }
}

function keyFor(apiHome, file) {
  const relative = path.relative(apiHome, file);
  if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) throw new Error('Document path is outside the API home.');
  return relative.split(path.sep).join('/');
}

/** The record at `file` (an absolute path under apiHome), or `fallback` if there is none. */
export async function readDoc(apiHome, file, fallback = null) {
  if (usingDatabase()) {
    const { rows } = await (await db()).query(`SELECT value FROM ${TABLE} WHERE key = $1`, [keyFor(apiHome, file)]);
    return rows.length ? rows[0].value : fallback;
  }
  try { return JSON.parse(await fs.readFile(file, 'utf8')); }
  catch (error) { if (error.code === 'ENOENT') return fallback; throw error; }
}

/** Writes the record at `file`. On disk the write is atomic (temp file, then rename), so a reader never sees half of it. */
export async function writeDoc(apiHome, file, value) {
  if (usingDatabase()) {
    await (await db()).query(
      `INSERT INTO ${TABLE} (key, value, updated_at) VALUES ($1, $2, now()) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
      [keyFor(apiHome, file), JSON.stringify(value)]
    );
    return;
  }
  await fs.mkdir(path.dirname(file), { recursive: true });
  const temp = `${file}.${randomBytes(4).toString('hex')}.tmp`;
  await fs.writeFile(temp, `${JSON.stringify(value, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  // On Windows a rename onto a file another handle is reading can fail briefly with EPERM/EBUSY.
  for (let attempt = 1; ; attempt += 1) {
    try { await fs.rename(temp, file); return; }
    catch (error) {
      if (!['EPERM', 'EBUSY'].includes(error.code) || attempt >= 5) throw error;
      await new Promise((resolve) => setTimeout(resolve, 10 * attempt));
    }
  }
}

/** Writes the record only if none exists at `file`; returns false if one already did. */
export async function createDoc(apiHome, file, value) {
  if (usingDatabase()) {
    const { rowCount } = await (await db()).query(
      `INSERT INTO ${TABLE} (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING`, [keyFor(apiHome, file), JSON.stringify(value)]);
    return rowCount === 1;
  }
  await fs.mkdir(path.dirname(file), { recursive: true });
  try { await fs.writeFile(file, `${JSON.stringify(value, null, 2)}\n`, { encoding: 'utf8', mode: 0o600, flag: 'wx' }); return true; }
  catch (error) { if (error.code === 'EEXIST') return false; throw error; }
}

/**
 * The names of the entries directly inside `dir` (an absolute directory under apiHome) that hold a record
 * named `leaf`, e.g. listDocDirs(home, <home>/tenants, 'tenant.json') -> tenant ids.
 */
export async function listDocDirs(apiHome, dir, leaf) {
  if (usingDatabase()) {
    const prefix = `${keyFor(apiHome, path.join(dir, 'x')).slice(0, -1)}`;
    const like = `${prefix.replace(/[\\%_]/g, (c) => `\\${c}`)}%/${leaf.replace(/[\\%_]/g, (c) => `\\${c}`)}`;
    const { rows } = await (await db()).query(`SELECT key FROM ${TABLE} WHERE key LIKE $1`, [like]);
    return rows.map((r) => r.key.slice(prefix.length, -(leaf.length + 1))).filter((name) => name && !name.includes('/'));
  }
  try {
    const names = await fs.readdir(dir);
    const found = await Promise.all(names.map(async (name) => {
      try { await fs.access(path.join(dir, name, leaf)); return name; } catch { return null; }
    }));
    return found.filter(Boolean);
  } catch (error) {
    if (error.code === 'ENOENT') return [];
    throw error;
  }
}
