import { randomBytes } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { tenantWorkspacesDirectory } from './tenants.js';

const MAX_FILES = 2000;
const MAX_FILE_BYTES = 2 * 1024 * 1024; // 2 MiB per file
const MAX_TOTAL_BYTES = 64 * 1024 * 1024; // 64 MiB per workspace

/**
 * Every job handler that touches "a repository" resolves it through here,
 * never through a raw filesystem path supplied directly in a request body.
 * Accepting an arbitrary host path from an API caller would let one tenant
 * read (and, for `migrate --write`, write) anything the server process can
 * reach — including other tenants' workspaces. A workspace is instead an
 * explicit, size-bounded upload materialized under that tenant's own
 * directory, and every path within it is containment-checked before use.
 */
export function resolveWorkspacePath(apiHome, tenantId, workspaceId, relativePath = '.') {
  if (!/^ws_[0-9a-f]{16}$/.test(workspaceId ?? '')) throw new Error('Invalid workspace id.');
  const root = path.resolve(tenantWorkspacesDirectory(apiHome, tenantId), workspaceId);
  const target = path.resolve(root, relativePath || '.');
  if (target !== root && !target.startsWith(`${root}${path.sep}`)) {
    throw new Error(`Path escapes workspace: ${relativePath}`);
  }
  return { root, target };
}

function assertSafeRelativePath(relativePath) {
  if (typeof relativePath !== 'string' || !relativePath.trim()) throw new Error('Each uploaded file requires a non-empty path.');
  const normalized = relativePath.replace(/\\/g, '/');
  if (path.posix.isAbsolute(normalized)) throw new Error(`Uploaded file path must be relative: ${relativePath}`);
  const segments = normalized.split('/');
  if (segments.some((segment) => segment === '..' || segment === '')) throw new Error(`Unsafe uploaded file path: ${relativePath}`);
  return normalized;
}

/**
 * Create a new workspace from an inline file list:
 * `files: [{ path: 'nginx.conf', content: '...', encoding: 'utf8'|'base64' }]`.
 * A JSON file list rather than a tarball/zip upload keeps this dependency-free
 * while still proving the real isolation boundary end to end.
 */
export async function createWorkspace(apiHome, tenantId, files) {
  if (!Array.isArray(files) || files.length === 0) throw new Error('Workspace creation requires a non-empty files array.');
  if (files.length > MAX_FILES) throw new Error(`Workspace exceeds the ${MAX_FILES}-file limit.`);
  const workspaceId = `ws_${randomBytes(8).toString('hex')}`;
  const root = path.join(tenantWorkspacesDirectory(apiHome, tenantId), workspaceId);
  await fs.mkdir(root, { recursive: true });
  let totalBytes = 0;
  const written = [];
  try {
    for (const file of files) {
      const relativePath = assertSafeRelativePath(file.path);
      const encoding = file.encoding === 'base64' ? 'base64' : 'utf8';
      const buffer = Buffer.from(file.content ?? '', encoding);
      if (buffer.length > MAX_FILE_BYTES) throw new Error(`File exceeds ${MAX_FILE_BYTES} bytes: ${relativePath}`);
      totalBytes += buffer.length;
      if (totalBytes > MAX_TOTAL_BYTES) throw new Error(`Workspace exceeds ${MAX_TOTAL_BYTES} total bytes.`);
      const absolute = path.resolve(root, relativePath);
      if (absolute !== root && !absolute.startsWith(`${root}${path.sep}`)) throw new Error(`Path escapes workspace: ${relativePath}`);
      await fs.mkdir(path.dirname(absolute), { recursive: true });
      await fs.writeFile(absolute, buffer);
      written.push({ path: relativePath, bytes: buffer.length });
    }
  } catch (error) {
    await fs.rm(root, { recursive: true, force: true }).catch(() => {});
    throw error;
  }
  return { workspaceId, root, files: written, totalBytes };
}

export async function workspaceExists(apiHome, tenantId, workspaceId) {
  try {
    const { root } = resolveWorkspacePath(apiHome, tenantId, workspaceId);
    const stat = await fs.stat(root);
    return stat.isDirectory();
  } catch {
    return false;
  }
}
