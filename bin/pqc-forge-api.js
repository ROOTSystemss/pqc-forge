#!/usr/bin/env node

import path from 'node:path';
import { createApiServer } from '../src/api/server.js';

const port = Number(process.env.PQC_FORGE_API_PORT ?? 8787);
const apiHome = path.resolve(process.env.PQC_FORGE_API_HOME ?? './pqc-forge-api-data');
const signingKeyPath = process.env.PQC_FORGE_SIGNING_KEY || null;

const { server } = createApiServer({ apiHome, signingKeyPath });

server.listen(port, () => {
  console.log(`PQC Forge API listening on :${port}`);
  console.log(`Tenant data: ${apiHome}`);
  console.log('Provision a tenant with: node ./bin/pqc-forge.js tenant-create --name "<name>" --out ' + apiHome);
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    server.close(() => process.exit(0));
  });
}
