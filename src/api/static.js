import { promises as fs } from 'node:fs';
import path from 'node:path';

export const CONTENT_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8',
  '.map': 'application/json; charset=utf-8'
};

/**
 * Resolve a request pathname to a file under `root` (the built web
 * dashboard's dist directory), containment-checked exactly like every
 * tenant-scoped path in workspace.js — a request path is never trusted to
 * stay inside `root` without that check. This tree is static, shipped
 * application assets, not tenant data, so it carries no auth of its own;
 * the API routes it sits alongside still require a bearer key.
 *
 * QA 2026-11-18 F11: unknown paths are NOT answered with the dashboard any more (every address, including /.env and
 * /.git/config, used to return 200 + index.html, so crawlers and uptime checks saw them as real pages). The dashboard
 * routes with query parameters on "/" only (?tab=...), so only "/" and "/index.html" serve index.html; any other path
 * must be a real file in the build. A dot-segment ("/.env", "/.git/...") is never served. Returns null -> 404.
 */
export async function resolveStaticFile(root, pathname) {
  const decoded = decodeURIComponent(pathname);
  const relative = decoded.replace(/^\/+/, '') || 'index.html';
  if (relative.split(/[\\/]/).some((segment) => segment.startsWith('.'))) return null;
  const target = path.resolve(root, relative);
  if (target !== root && !target.startsWith(`${root}${path.sep}`)) return null;
  try {
    const stat = await fs.stat(target);
    if (stat.isFile()) return target;
  } catch {
    // not a file in the build
  }
  return null;
}
