import { promises as fs } from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { docDb, usingDatabase } from './docStore.js';

/**
 * N-PF-06 (knock-out 2026-11-17): uploaded workspace files and job output files survive a restart.
 *
 * The hosted service runs on a host that loses its disk on sleep or redeploy. Job records already live in Postgres
 * (docStore.js); with DATABASE_URL set, every uploaded workspace file and every downloadable job output file is now
 * also kept in Postgres (table pqcf_files, keyed by its path relative to apiHome, gzip-compressed when smaller) and
 * written back to disk lazily, the first time something needs it (a job on that workspace, a download, an export).
 * The disk copy stays the working copy; without DATABASE_URL nothing here runs and file mode is exactly as before.
 * Sizes stay bounded by the existing upload quotas (checked before anything is written).
 */

const TABLE = 'pqcf_files';
let ready = null;
let readyPool = null;

async function db() {
  const pool = await docDb();
  if (!ready || readyPool !== pool) {
    readyPool = pool;
    ready = pool.query(`CREATE TABLE IF NOT EXISTS ${TABLE} (key text PRIMARY KEY, data bytea NOT NULL, size integer NOT NULL, gzip boolean NOT NULL DEFAULT false, updated_at timestamptz NOT NULL DEFAULT now())`)
      .catch((error) => { ready = null; throw error; });
  }
  await ready;
  return pool;
}

/** Forget the table-ready promise (tests that drop and recreate the database). */
export function resetFileStore() { ready = null; }

function keyFor(apiHome, file) {
  const relative = path.relative(apiHome, file);
  if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) throw new Error('File path is outside the API home.');
  return relative.split(path.sep).join('/');
}

function likePrefix(apiHome, dir) {
  const prefix = keyFor(apiHome, path.join(dir, 'x')).slice(0, -1);
  return { prefix, like: `${prefix.replace(/[\\%_]/g, (c) => `\\${c}`)}%` };
}

/** Keeps `buffer` as the stored copy of `file` (an absolute path under apiHome). No-op without DATABASE_URL. */
export async function storeFile(apiHome, file, buffer) {
  if (!usingDatabase()) return false;
  const packed = zlib.gzipSync(buffer);
  const gzip = packed.length < buffer.length;
  await (await db()).query(
    `INSERT INTO ${TABLE} (key, data, size, gzip, updated_at) VALUES ($1, $2, $3, $4, now())
     ON CONFLICT (key) DO UPDATE SET data = EXCLUDED.data, size = EXCLUDED.size, gzip = EXCLUDED.gzip, updated_at = now()`,
    [keyFor(apiHome, file), gzip ? packed : buffer, buffer.length, gzip]
  );
  return true;
}

const unpack = (row) => (row.gzip ? zlib.gunzipSync(row.data) : Buffer.from(row.data));

/** The stored copy of `file`, or null. */
export async function readStoredFile(apiHome, file) {
  if (!usingDatabase()) return null;
  const { rows } = await (await db()).query(`SELECT data, gzip FROM ${TABLE} WHERE key = $1`, [keyFor(apiHome, file)]);
  return rows.length ? unpack(rows[0]) : null;
}

/**
 * Writes every stored file under `dir` back to disk where the disk copy is missing. Returns how many files are
 * stored under `dir` (0 = nothing stored). Never writes outside apiHome.
 */
export async function restoreFilesUnder(apiHome, dir) {
  if (!usingDatabase()) return 0;
  const { like } = likePrefix(apiHome, dir);
  const { rows } = await (await db()).query(`SELECT key, data, gzip FROM ${TABLE} WHERE key LIKE $1`, [like]);
  const home = path.resolve(apiHome);
  for (const row of rows) {
    const target = path.resolve(home, ...row.key.split('/'));
    if (!target.startsWith(`${home}${path.sep}`)) continue;
    try { await fs.access(target); continue; } catch { /* missing: restore it */ }
    await fs.mkdir(path.dirname(target), { recursive: true });
    await fs.writeFile(target, unpack(row));
  }
  return rows.length;
}

/** Deletes every stored file under `dir`; returns how many. */
export async function deleteFilesUnder(apiHome, dir) {
  if (!usingDatabase()) return 0;
  const { like } = likePrefix(apiHome, dir);
  const { rowCount } = await (await db()).query(`DELETE FROM ${TABLE} WHERE key LIKE $1`, [like]);
  return rowCount;
}

/** Workspace usage as stored (survives restarts): { workspaces, bytes } for the ws_* folders under `workspacesDir`. */
export async function storedWorkspaceUsage(apiHome, workspacesDir) {
  if (!usingDatabase()) return { workspaces: 0, bytes: 0 };
  const { prefix, like } = likePrefix(apiHome, workspacesDir);
  const { rows } = await (await db()).query(`SELECT key, size FROM ${TABLE} WHERE key LIKE $1`, [like]);
  const ids = new Set();
  let bytes = 0;
  for (const r of rows) {
    const id = r.key.slice(prefix.length).split('/')[0];
    if (/^ws_[0-9a-f]{16}$/.test(id)) { ids.add(id); bytes += Number(r.size) || 0; }
  }
  return { workspaces: ids.size, bytes };
}
