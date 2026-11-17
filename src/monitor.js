// PF-05 / PF-02 / BM-44 (knock-out 2026-11-17): TLS and certificate monitoring for the public endpoints an account
// saves. On a schedule the account chooses (off by default; daily or weekly; paid plans only), PQC Forge repeats the
// same passive check as the endpoint and certificate inventories (one ordinary TLS 1.3 handshake per endpoint, no
// scanning) and records what changed since the previous run: the key exchange changed, the post-quantum status
// changed, the certificate was replaced, the certificate expires within 30 days or has expired, or the endpoint stopped
// answering (Not verified). Every run is a signed document (same receipt shape as every PQC Forge receipt), checkable at
// POST /v1/public/verify-report (kind "monitor-run"). PQC Forge has no outbound alert channel, so changes are shown
// in the run and the API, not emailed.
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { endpointRow } from './endpointInventory.js';
import { rowFromFacts, EXPIRY_WARNING_DAYS } from './certificateInventory.js';
import { signDoc, verifyDoc } from './signedDoc.js';
import { readDoc, writeDoc, listDocDirs, deleteDocsUnder, usingDatabase } from './api/docStore.js';

export const MONITOR_RUN_SCHEMA = 'pqc-forge.monitor-run/v1';
export const MONITOR_SETTINGS_SCHEMA = 'pqc-forge.monitor-settings/v1';
export const CADENCE_DAYS = { off: 0, daily: 1, weekly: 7 };
export const MAX_MONITOR_ENDPOINTS = 10;
export const KEEP_RUNS = 60;
const TARGET = /^[a-z0-9.-]{1,253}(:\d{1,5})?$/i;

const tenantDir = (apiHome, tenantId) => path.join(apiHome, 'tenants', tenantId);
const settingsFile = (apiHome, tenantId) => path.join(tenantDir(apiHome, tenantId), 'monitor.json');
const runsDir = (apiHome, tenantId) => path.join(tenantDir(apiHome, tenantId), 'monitor-runs');
const runFile = (apiHome, tenantId, runId) => path.join(runsDir(apiHome, tenantId), runId, 'run.json');

/** Validates { cadence, endpoints } from a request. Throws with a plain message. */
export function normalizeSettings(body) {
  const cadence = String(body?.cadence ?? 'off');
  if (!Object.hasOwn(CADENCE_DAYS, cadence)) throw new Error('cadence must be off, daily or weekly.');
  const raw = Array.isArray(body?.endpoints) ? body.endpoints : [];
  const endpoints = [...new Set(raw.map((e) => String(e).trim().toLowerCase()).filter(Boolean))];
  if (endpoints.length > MAX_MONITOR_ENDPOINTS) throw new Error(`Save at most ${MAX_MONITOR_ENDPOINTS} endpoints.`);
  for (const e of endpoints) if (!TARGET.test(e)) throw new Error(`Not a host or host:port: ${e.slice(0, 80)}`);
  if (cadence !== 'off' && !endpoints.length) throw new Error('Save at least one public endpoint before switching monitoring on.');
  return { cadence, endpoints };
}

export async function readSettings(apiHome, tenantId) {
  return readDoc(apiHome, settingsFile(apiHome, tenantId), { schema: MONITOR_SETTINGS_SCHEMA, cadence: 'off', endpoints: [], lastRunAt: null, lastRunId: null });
}

export async function writeSettings(apiHome, tenantId, settings) {
  await writeDoc(apiHome, settingsFile(apiHome, tenantId), { schema: MONITOR_SETTINGS_SCHEMA, ...settings, updatedAt: new Date().toISOString() });
}

/** True when monitoring is on and the last run is at least one cadence period old (5 minutes slack). */
export function isDue(settings, now = Date.now()) {
  const days = CADENCE_DAYS[settings?.cadence] || 0;
  if (!days || !settings.endpoints?.length) return false;
  if (!settings.lastRunAt) return true;
  return now - new Date(settings.lastRunAt).getTime() >= days * 86400000 - 5 * 60000;
}

function certRow(e, at) {
  if (!e.ok) return { state: 'not-verified', status: 'Not verified (endpoint not reachable or no TLS 1.3 handshake)' };
  return rowFromFacts(`endpoint:${e.target}`, e.evidence.certificate, e.evidence.peerSignatureAlgorithm, at);
}

/** Builds (unsigned) one monitoring run from probe results and the previous run (or null). */
export function buildMonitorRun({ label, probes, previous = null, now = new Date(), trigger = 'manual', cadence = 'off' }) {
  const at = new Date(now);
  const prevByTarget = new Map((previous?.endpoints || []).map((r) => [r.target, r]));
  const rows = probes.map((p) => {
    const tls = endpointRow(p);
    const cert = certRow(p, at);
    const prev = prevByTarget.get(p.target) || null;
    const changes = [];
    const verified = tls.state !== 'not-verified';
    if (!verified) changes.push(prev && prev.tls.state !== 'not-verified' ? 'stopped answering: Not verified' : 'Not verified (not reachable or no TLS 1.3 handshake)');
    if (previous && !prev) changes.push('new endpoint (no earlier run to compare)');
    if (verified && prev && prev.tls.state !== 'not-verified') {
      if (prev.tls.keyExchange !== tls.keyExchange) changes.push(`key exchange changed: ${prev.tls.keyExchange} -> ${tls.keyExchange}`);
      if (prev.tls.state !== tls.state) changes.push(`post-quantum status changed: ${prev.tls.status} -> ${tls.status}`);
      if (prev.certificate?.fingerprint256 && cert.fingerprint256 && prev.certificate.fingerprint256 !== cert.fingerprint256) changes.push('certificate replaced');
    }
    if (cert.state === 'read' && cert.daysLeft < 0) changes.push('certificate expired');
    else if (cert.state === 'read' && cert.daysLeft <= EXPIRY_WARNING_DAYS) changes.push(`certificate expires within ${EXPIRY_WARNING_DAYS} days (${cert.daysLeft} days left)`);
    const certificate = cert.state === 'read'
      ? { subject: cert.subject, issuer: cert.issuer, validTo: cert.validTo, daysLeft: cert.daysLeft, expiry: cert.expiry, fingerprint256: cert.fingerprint256, signatureAlgorithm: cert.signatureAlgorithm, algorithmClass: cert.algorithmClass }
      : { state: 'not-verified', status: cert.status };
    return { target: p.target, tls, certificate, changes };
  });
  const count = (f) => rows.filter(f).length;
  return {
    schema: MONITOR_RUN_SCHEMA,
    generatedAt: at.toISOString(),
    label: String(label || 'TLS and certificate monitoring').slice(0, 120),
    trigger, cadence,
    comparedWith: previous ? { generatedAt: previous.generatedAt, receiptDigest: previous.receiptDigest } : null,
    method: 'Passive: one ordinary TLS 1.3 handshake per saved endpoint (what any browser does); no port scanning, no other hosts. Changes are compared with the previous signed run. An endpoint that did not answer reads Not verified and is never counted as post-quantum or classical.',
    summary: {
      endpoints: rows.length,
      postQuantumKeyExchange: count((r) => r.tls.state === 'pq-key-exchange'),
      classicalOnly: count((r) => r.tls.state === 'classical-only'),
      notVerified: count((r) => r.tls.state === 'not-verified'),
      endpointsWithChanges: count((r) => r.changes.length > 0),
      certificatesExpiringOrExpired: count((r) => typeof r.certificate.daysLeft === 'number' && r.certificate.daysLeft <= EXPIRY_WARNING_DAYS),
    },
    endpoints: rows,
  };
}

export const verifyMonitorRun = (doc, keys = null) => verifyDoc(doc, MONITOR_RUN_SCHEMA, 'monitoring run', keys);

/** The default probe: the same passive handshake as the endpoint inventory (private addresses refused). */
export function defaultProbe(safety) {
  return async (target) => {
    const { resolvePublicTarget } = await import('./api/hosted-safety.js');
    const { verifyTls } = await import('./verifier.js');
    try {
      const { address } = await resolvePublicTarget(target, { allowPrivateTargets: safety?.allowPrivateTargets });
      return { target, ok: true, evidence: await verifyTls(target, { connectAddress: address }) };
    } catch (error) {
      return { target, ok: false, error: error.message };
    }
  };
}

export async function listRuns(apiHome, tenantId) {
  const ids = await listDocDirs(apiHome, runsDir(apiHome, tenantId), 'run.json');
  const runs = (await Promise.all(ids.map(async (id) => ({ id, doc: await readDoc(apiHome, runFile(apiHome, tenantId, id)) })))).filter((r) => r.doc);
  runs.sort((a, b) => (a.doc.generatedAt < b.doc.generatedAt ? 1 : -1));
  return runs;
}

export async function readRun(apiHome, tenantId, runId) {
  if (!/^mr_[0-9a-f]{16}$/.test(runId ?? '')) return null;
  return readDoc(apiHome, runFile(apiHome, tenantId, runId));
}

/** Runs monitoring once for one account now: probes, compares with the last run, signs, stores, prunes. */
export async function runMonitorOnce({ apiHome, tenantId, signingKey, probe, now = new Date(), trigger = 'manual' }) {
  const settings = await readSettings(apiHome, tenantId);
  if (!settings.endpoints?.length) throw new Error('Save at least one public endpoint first.');
  const previous = settings.lastRunId ? await readRun(apiHome, tenantId, settings.lastRunId) : null;
  const probes = await Promise.all(settings.endpoints.map((target) => probe(target).catch((error) => ({ target, ok: false, error: error.message }))));
  const signed = signDoc(buildMonitorRun({ probes, previous, now, trigger, cadence: settings.cadence }), signingKey);
  const runId = `mr_${randomBytes(8).toString('hex')}`;
  await writeDoc(apiHome, runFile(apiHome, tenantId, runId), signed);
  await writeSettings(apiHome, tenantId, { cadence: settings.cadence, endpoints: settings.endpoints, lastRunAt: signed.generatedAt, lastRunId: runId });
  const all = await listRuns(apiHome, tenantId);
  for (const old of all.slice(KEEP_RUNS)) {
    const dir = path.dirname(runFile(apiHome, tenantId, old.id));
    await deleteDocsUnder(apiHome, dir);
    if (!usingDatabase()) await fs.rm(dir, { recursive: true, force: true });
  }
  return { runId, run: signed };
}

/**
 * Scheduler step: every account with monitoring on, a paid plan and a run due gets one run. `isPaid(tenantId)`
 * decides the plan rule; errors for one account never stop the others. Returns what it did.
 */
export async function runDueMonitors({ apiHome, signingKey, probe, isPaid, now = new Date() }) {
  const tenantIds = await listDocDirs(apiHome, path.join(apiHome, 'tenants'), 'monitor.json');
  const done = [];
  for (const tenantId of tenantIds) {
    try {
      const settings = await readSettings(apiHome, tenantId);
      if (!isDue(settings, now.getTime())) continue;
      if (!(await isPaid(tenantId))) { done.push({ tenantId, skipped: 'not a paid plan' }); continue; }
      const { runId } = await runMonitorOnce({ apiHome, tenantId, signingKey, probe, now, trigger: 'schedule' });
      done.push({ tenantId, runId });
    } catch (error) {
      done.push({ tenantId, error: error.message });
    }
  }
  return done;
}
