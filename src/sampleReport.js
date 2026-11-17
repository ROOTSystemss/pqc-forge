// Public SAMPLE PQC Readiness Report (knock-out 2026-11-16, O-24). Built from the made-up code in
// samples/readiness-sample, with a fixed date, signed with this server's real ML-DSA-65 key, and marked
// sample: true INSIDE the signed body (so a sample can never pass as a real customer report).
// Never touches customer data or storage; cached in memory per signing key.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanRepository } from './scanner.js';
import { migrateRepository } from './migrator.js';
import { buildReadinessReport, signReport, verifyReport, renderReportHtml } from './readinessReport.js';

const SAMPLE_ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'samples', 'readiness-sample');
export const SAMPLE_NOTICE = 'SAMPLE REPORT. Made-up code and organization; no real company was assessed and this is not evidence about anyone.';
const SAMPLE_DATE = new Date('2026-11-16T00:00:00Z');
const cache = new Map();

export async function sampleReadinessReport(signingKey) {
  const id = signingKey.keyId || signingKey.publicKey;
  if (cache.has(id)) return cache.get(id);
  const scan = await scanRepository(SAMPLE_ROOT, { now: SAMPLE_DATE });
  const migration = await migrateRepository(SAMPLE_ROOT, { write: false });
  const report = buildReadinessReport({ organization: 'SAMPLE Co (made-up example)', scan, migration, endpoints: [], now: SAMPLE_DATE });
  const signed = signReport({ ...report, sample: true, sampleNotice: SAMPLE_NOTICE }, signingKey);
  const out = { json: JSON.stringify(signed, null, 2), html: renderReportHtml(signed), receiptDigest: signed.receiptDigest };
  cache.set(id, out);
  return out;
}

// Public check: only readiness reports, only keys this server published. Says whether it is a SAMPLE.
export function publicVerifyReport(doc, publishedKeys) {
  const r = verifyReport(doc, publishedKeys);
  return {
    valid: r.valid === true,
    errors: r.errors || [],
    sample: r.valid === true && doc.sample === true,
    organization: r.valid === true ? doc.organization : null,
    generatedAt: r.valid === true ? doc.generatedAt : null,
    receiptDigest: r.valid === true ? doc.receiptDigest : null,
    note: 'Valid means: signed by this PQC Forge server (a key it publishes at /.well-known/rootsystems-signing-keys.json) and unchanged since. It does not prove the scanned code is the code you run.',
  };
}
