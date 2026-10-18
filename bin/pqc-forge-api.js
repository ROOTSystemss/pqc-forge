#!/usr/bin/env node

import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createApiServer } from '../src/api/server.js';

const projectRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const port = Number(process.env.PQC_FORGE_API_PORT ?? 8787);
// Loopback-only by default: this server speaks plain HTTP and authenticates
// with a bearer API key in a header, so binding every interface (Node's own
// default with no host argument) would put that key on the wire, unencrypted,
// to anyone who can reach the host over the network - not just localhost.
// An operator who wants it reachable beyond this machine sets this
// explicitly, and is then responsible for putting a TLS-terminating reverse
// proxy in front of it (see the warning below and README.md).
const host = process.env.PQC_FORGE_API_HOST || '127.0.0.1';
const apiHome = path.resolve(process.env.PQC_FORGE_API_HOME ?? './pqc-forge-api-data');
// The hosted signing key lives with the tenant data (the persistent disk), so every report and receipt
// keeps verifying against the same key across restarts and deploys. Created once if missing; set
// PQC_FORGE_SIGNING_KEY to use an organisation-managed key file instead.
async function hostedSigningKeyPath() {
  if (process.env.PQC_FORGE_SIGNING_KEY) return process.env.PQC_FORGE_SIGNING_KEY;
  const keyPath = path.join(apiHome, 'signing-key.json');
  try {
    await fs.access(keyPath);
  } catch {
    const { generateSigningKey } = await import('../src/signing.js');
    await fs.mkdir(apiHome, { recursive: true });
    await fs.writeFile(keyPath, `${JSON.stringify(generateSigningKey(), null, 2)}\n`, { encoding: 'utf8', mode: 0o600, flag: 'wx' }).catch((error) => { if (error.code !== 'EEXIST') throw error; });
    console.log(`Created the hosted signing key at ${keyPath} (keep this disk backed up).`);
  }
  return keyPath;
}
const signingKeyPath = await hostedSigningKeyPath();

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

server.listen(port, host, () => {
  console.log(`PQC Forge API listening on ${host}:${port}`);
  console.log(`Tenant data: ${apiHome}`);
  console.log(webDistPath ? `Dashboard: http://localhost:${port}/ (serving ${webDistPath})` : 'Dashboard: not built — run `npm run web:build` to serve it from this same server.');
  console.log('Provision a tenant with: node ./bin/pqc-forge.js tenant-create --name "<name>" --out ' + apiHome);
  if (host !== '127.0.0.1' && host !== 'localhost' && host !== '::1') {
    console.log(`WARNING: bound to ${host}, not loopback-only. This server speaks plain HTTP with a bearer API key — put a TLS-terminating reverse proxy in front of it before exposing it beyond this machine.`);
  }
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    server.close(() => process.exit(0));
  });
}
