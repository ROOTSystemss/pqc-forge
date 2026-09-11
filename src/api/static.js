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
 * Unknown paths fall back to `index.html` so the dashboard's client-side
 * routing survives a hard refresh on a deep link. Returns null only when
 * the request tries to escape `root` or `root` has no `index.html` at all
 * (i.e. no build was ever produced).
 */
export async function resolveStaticFile(root, pathname) {
  const decoded = decodeURIComponent(pathname);
  const relative = decoded.replace(/^\/+/, '') || 'index.html';
  const target = path.resolve(root, relative);
  if (target !== root && !target.startsWith(`${root}${path.sep}`)) return null;

  for (const candidate of [target, path.join(root, 'index.html')]) {
    try {
      const stat = await fs.stat(candidate);
      if (stat.isFile()) return candidate;
    } catch {
      // try the next candidate (SPA fallback)
    }
  }
  return null;
}
