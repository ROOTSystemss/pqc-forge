#!/usr/bin/env node

import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createApiServer } from '../src/api/server.js';

const projectRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const port = Number(process.env.PQC_FORGE_API_PORT ?? 8787);
const apiHome = path.resolve(process.env.PQC_FORGE_API_HOME ?? './pqc-forge-api-data');
const signingKeyPath = process.env.PQC_FORGE_SIGNING_KEY || null;

// Serve the built dashboard from the same origin as the API when it has
// been built (`npm run web:build`). Same-origin means the dashboard needs
// no CORS setup and no separate static host to run this end to end; the
// permissive CORS headers below still apply too, for dashboards served
// elsewhere (e.g. `npm run web:dev`) or a custom integration.
const defaultWebDist = path.join(projectRoot, 'web', 'dist');
const webDistPath = process.env.PQC_FORGE_WEB_DIST
  ? path.resolve(process.env.PQC_FORGE_WEB_DIST)
  : await fs.access(path.join(defaultWebDist, 'index.html')).then(() => defaultWebDist).catch(() => null);

const { server } = createApiServer({ apiHome, signingKeyPath, webDistPath });

server.listen(port, () => {
  console.log(`PQC Forge API listening on :${port}`);
  console.log(`Tenant data: ${apiHome}`);
  console.log(webDistPath ? `Dashboard: http://localhost:${port}/ (serving ${webDistPath})` : 'Dashboard: not built — run `npm run web:build` to serve it from this same server.');
  console.log('Provision a tenant with: node ./bin/pqc-forge.js tenant-create --name "<name>" --out ' + apiHome);
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    server.close(() => process.exit(0));
  });
}
