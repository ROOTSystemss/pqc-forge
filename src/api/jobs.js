import { randomBytes } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { scanRepository } from '../scanner.js';
import { migrateRepository } from '../migrator.js';
import { rollbackMigration } from '../rollback.js';
import { createPrPack } from '../pr-pack.js';
import { verifyTls } from '../verifier.js';
import { writeRuntimeEvidence } from '../runtime-probe.js';
import { evaluateStagingGate } from '../staging-gate.js';
import { validateCorpus } from '../validation.js';
import { runBreakLab, evaluateCandidate, validateScenario } from '../breaklab/engine.js';
import { runDockerProtocolLab } from '../protocol-lab/docker.js';
import { compareScans } from '../baseline.js';
import {
  createMigrationReceipt, createProtocolReceipt, createReceipt,
  createStagingReceipt, createTlsReceipt, verifyReceipt
} from '../breaklab/receipt.js';
import { tenantJobsDirectory, tenantWorkspacesDirectory } from './tenants.js';
import { resolveWorkspacePath } from './workspace.js';
import { HOST_EXECUTION_JOB_TYPES, resolvePublicTarget, safetyOptionsFromEnv } from './hosted-safety.js';

const JOB_SCHEMA = 'pqc-forge.job/v1';
const TERMINAL_STATES = new Set(['succeeded', 'failed']);

// Two independent concurrency ceilings. Docker-backed jobs (protocol-lab)
// are additionally capped separately and much lower, since each one builds
// an image and runs several containers — letting those share the same
// budget as cheap jobs like `scan` would let one tenant's lab runs starve
// everyone else's fast requests.
const DEFAULT_GLOBAL_CONCURRENCY = Number(process.env.PQC_FORGE_API_MAX_CONCURRENCY ?? 4);
const DEFAULT_TENANT_CONCURRENCY = Number(process.env.PQC_FORGE_API_MAX_TENANT_CONCURRENCY ?? 2);
const DEFAULT_DOCKER_CONCURRENCY = Number(process.env.PQC_FORGE_API_MAX_DOCKER_CONCURRENCY ?? 1);
const DOCKER_JOB_TYPES = new Set(['protocol-lab']);

// Every jobId this module ever generates (submit(), below) matches this
// exact format. Enforcing it here — the same way tenants.js and
// workspace.js validate their own ids before any path.join — means path
// containment for job lookups holds by explicit design, not merely as an
// accident of how the URL router and path.join each happen to behave on
// the untrusted id a request supplies (path.join does not honor an
// absolute-looking segment the way path.resolve would, and the HTTP
// router only ever captures a single non-'/' path segment, but neither of
// those is a contract this module should have to keep re-deriving).
const JOB_ID_PATTERN = /^j_[0-9a-f]{16}$/;

function jobDirectory(apiHome, tenantId, jobId) {
  return path.join(tenantJobsDirectory(apiHome, tenantId), jobId);
}

async function writeTempJson(jobDir, name, value) {
  const file = path.join(jobDir, name);
  await fs.writeFile(file, JSON.stringify(value), 'utf8');
  return file;
}

async function requireValidReceipt(receipt, expectedSchema, label) {
  if (receipt?.schema !== expectedSchema) throw new Error(`${label} must be a ${expectedSchema} document.`);
  const verification = verifyReceipt(receipt);
  if (!verification.valid) throw new Error(`${label} failed verification: ${verification.errors.join(', ')}.`);
  return receipt;
}

// One handler per wrapped CLI command. Every handler receives already-
// authenticated, tenant-scoped context and returns the JSON-serializable
// result to persist as this job's output.
const HANDLERS = {
  async scan({ apiHome, tenantId, params }) {
    const { root: workspaceRoot } = resolveWorkspacePath(apiHome, tenantId, params.workspaceId, params.relativePath);
    const report = await scanRepository(workspaceRoot, { ignoreFile: params.noIgnore ? null : undefined });
    if (params.baseline) report.delta = compareScans(report, params.baseline);
    return report;
  },

  async migrate({ apiHome, tenantId, params, signingKey }) {
    const { root: workspaceRoot } = resolveWorkspacePath(apiHome, tenantId, params.workspaceId, params.relativePath);
    const migration = await migrateRepository(workspaceRoot, {
      write: Boolean(params.write), acknowledgeRuntime: Boolean(params.acknowledgeRuntime)
    });
    const receipt = createMigrationReceipt(migration, signingKey);
    return { migration, receipt };
  },

  async rollback({ apiHome, tenantId, params, signingKey }) {
    const receipt = await requireValidReceipt(params.migrationReceipt, 'pqc-forge.migration-receipt/v1', 'migrationReceipt');
    // Only a receipt this server signed, for one of the caller's own workspaces: anyone can sign a
    // receipt with their own key and name any folder on the host as its root.
    return rollbackMigration(receipt, {
      write: Boolean(params.write),
      trustedPublicKeys: [signingKey.publicKey],
      allowedRoot: tenantWorkspacesDirectory(apiHome, tenantId)
    });
  },

  async 'pr-pack'({ apiHome, tenantId, jobDir, params, signingKey }) {
    const { root: workspaceRoot } = resolveWorkspacePath(apiHome, tenantId, params.workspaceId, params.relativePath);
    const output = path.join(jobDir, 'pr-pack');
    const protocolReceiptPath = params.protocolReceipt ? await writeTempJson(jobDir, 'protocol-receipt.json', params.protocolReceipt) : null;
    const runtimeReceiptPaths = await Promise.all(
      (params.runtimeReceipts ?? []).map((receipt, index) => writeTempJson(jobDir, `runtime-receipt-${index}.json`, receipt))
    );
    const result = await createPrPack(workspaceRoot, output, { protocolReceiptPath, runtimeReceiptPaths, signingKey });
    return { ...result, files: await fs.readdir(output) };
  },

  async verify({ params, signingKey, safety }) {
    const { address } = await resolvePublicTarget(params.target, { allowPrivateTargets: safety.allowPrivateTargets });
    const evidence = await verifyTls(params.target, { insecure: Boolean(params.insecure), connectAddress: address });
    const receipt = createTlsReceipt(evidence, signingKey);
    return { evidence, receipt };
  },

  async 'runtime-probe'({ apiHome, tenantId, jobDir, params, signingKey }) {
    // Deliberately not sandboxed further than the rest of this process: the
    // safety contract here is identical to the CLI's (see
    // PRODUCTION_SAFETY.md) — it invokes real server binaries on whatever
    // host runs this API process. An operator exposing this endpoint over
    // the network is responsible for running the API itself on a
    // target-like, least-privilege runner, exactly as the composite
    // GitHub Action's `runtime` mode already requires for self-hosted
    // runners. This is not something a shared/generic API host can offer
    // safely without that same operator guarantee.
    const { target: configPath } = resolveWorkspacePath(apiHome, tenantId, params.workspaceId, params.relativePath);
    return writeRuntimeEvidence(params.server, path.join(jobDir, 'runtime-probe'), {
      configPath,
      opensslExecutable: params.opensslExecutable,
      serverExecutable: params.serverExecutable,
      target: params.target,
      signingKey
    });
  },

  async 'staging-gate'({ params, signingKey }) {
    const runtimeReceipts = await Promise.all((params.runtimeReceipts ?? []).map((receipt) => requireValidReceipt(receipt, 'pqc-forge.runtime-receipt/v1', 'runtimeReceipt')));
    const endpointReceipts = await Promise.all((params.endpointReceipts ?? []).map((receipt) => requireValidReceipt(receipt, 'pqc-forge.tls-receipt/v1', 'endpointReceipt')));
    const run = evaluateStagingGate(params.manifest, { runtimeReceipts, endpointReceipts });
    const receipt = createStagingReceipt(run, signingKey);
    return { run, receipt };
  },

  async 'validate-corpus'({ jobDir, params, signingKey }) {
    const manifestPath = await writeTempJson(jobDir, 'corpus-manifest.json', params.manifest);
    return validateCorpus(manifestPath, path.join(jobDir, 'validation'), { signingKey });
  },

  async breaklab({ params, signingKey }) {
    const budget = Number(params.budget ?? 64);
    const seed = Number(params.seed ?? 42);
    if (!Number.isInteger(budget) || budget < 1) throw new Error('budget must be a positive integer.');
    if (!Number.isInteger(seed)) throw new Error('seed must be an integer.');
    const run = runBreakLab(params.scenario, { budget, seed });
    return createReceipt(run, params.scenario, signingKey);
  },

  async 'protocol-lab'({ jobId, signingKey }) {
    // One Docker Compose project per job (see the comment on composeArgs in
    // src/protocol-lab/docker.js) so concurrent lab jobs never collide on
    // container, network, or volume names.
    const run = await runDockerProtocolLab({ projectName: `pqc-forge-lab-job-${jobId}` });
    const receipt = createProtocolReceipt(run, { schema: 'pqc-forge.protocol-matrix/v1' }, signingKey);
    return { run, receipt };
  },

  /**
   * Full client×server compatibility matrix for one fixed
   * certificate/network/fallback slice, computed with the real
   * `evaluateCandidate` — the same pure function `breaklab`'s search
   * strategies call — for every combination, not a budget-limited sample.
   * This is a distinct artifact from `breaklab`: that job is the
   * authoritative, receipted, multi-strategy search evidence; this one
   * exists so a UI can render an honest, exhaustive grid for one slice
   * of the scenario. Cells are evaluated and persisted to job.progress
   * one at a time with a real (small, configurable) pause between them,
   * so a concurrent poller sees the true, current set of resolved cells
   * — not a fabricated animation replaying already-known results.
   */
  async 'breaklab-grid'({ params, reportProgress }) {
    const scenario = validateScenario(params.scenario);
    const clients = scenario.dimensions.client;
    const servers = scenario.dimensions.server;
    const fixed = {
      certificate: params.certificate ?? scenario.dimensions.certificate[0],
      network: params.network ?? scenario.dimensions.network[0],
      allowClassicalFallback: params.allowClassicalFallback ?? scenario.dimensions.allowClassicalFallback[0]
    };
    if (!scenario.profiles.certificates[fixed.certificate]) throw new Error(`Unknown certificate profile: ${fixed.certificate}`);
    if (!scenario.profiles.networks[fixed.network]) throw new Error(`Unknown network profile: ${fixed.network}`);
    // Both bounded against the same abuse shape as `breaklab`'s own
    // enumeration limit: an authenticated tenant fully controls `scenario`
    // and `paceMs`, and this loop is unbudgeted (breaklab's evaluations are
    // capped by `budget`; a grid evaluates every cell). Without a cap here,
    // a scenario with large client/server dimensions turns one job into an
    // effectively unbounded CPU/memory/disk-write loop - job.progress is
    // rewritten to disk with the full, ever-growing `cells` array on every
    // iteration - that also pins one of the shared concurrency slots.
    const MAX_GRID_CELLS = 4096;
    const MAX_PACE_MS = 2000;
    const total = clients.length * servers.length;
    if (total > MAX_GRID_CELLS) throw new Error(`Grid has ${total} client×server cells; the limit is ${MAX_GRID_CELLS}. Use a scenario with fewer client/server values.`);
    const paceMs = Number.isFinite(params.paceMs) ? Math.min(MAX_PACE_MS, Math.max(0, Number(params.paceMs))) : 180;

    const cells = [];
    await reportProgress?.({ total, completed: 0, cells: [] });
    for (const client of clients) {
      for (const server of servers) {
        const evaluated = evaluateCandidate(scenario, { client, server, ...fixed });
        cells.push({
          client, server, negotiatedGroup: evaluated.negotiatedGroup,
          findings: evaluated.findings, severity: evaluated.severity, pass: evaluated.findings.length === 0
        });
        await reportProgress?.({ total, completed: cells.length, cells: [...cells] });
        if (paceMs > 0 && cells.length < total) await new Promise((resolve) => setTimeout(resolve, paceMs));
      }
    }
    return { schema: 'pqc-forge.breaklab-grid/v1', scenario: scenario.name, dimensions: { client: clients, server: servers }, fixed, cells };
  }
};

export const JOB_TYPES = Object.keys(HANDLERS);

export function createJobQueue({
  apiHome, resolveSigningKey,
  globalConcurrency = DEFAULT_GLOBAL_CONCURRENCY, tenantConcurrency = DEFAULT_TENANT_CONCURRENCY, dockerConcurrency = DEFAULT_DOCKER_CONCURRENCY,
  handlers = HANDLERS, // overridable so tests can exercise the scheduler deterministically without real work
  safety = safetyOptionsFromEnv() // see hosted-safety.js
}) {
  const pending = [];
  const running = new Map(); // jobId -> { tenantId, isDocker }

  function runningCountForTenant(tenantId) {
    let count = 0;
    for (const job of running.values()) if (job.tenantId === tenantId) count += 1;
    return count;
  }

  function runningDockerCount() {
    let count = 0;
    for (const job of running.values()) if (job.isDocker) count += 1;
    return count;
  }

  async function persist(tenantId, jobId, record) {
    // A concurrent GET can poll job.json at any moment, including mid-write
    // of a status transition from a different request. Writing straight to
    // job.json risks that read observing a truncated file. Write to a sibling
    // temp file and rename over the target instead: rename is atomic on both
    // POSIX and NTFS, so a reader only ever sees the old or the new content,
    // never a partial one.
    const target = path.join(jobDirectory(apiHome, tenantId, jobId), 'job.json');
    const temp = `${target}.${randomBytes(4).toString('hex')}.tmp`;
    await fs.writeFile(temp, `${JSON.stringify(record, null, 2)}\n`, 'utf8');
    // On Windows, renaming onto a destination another handle currently has
    // open for reading can transiently fail with EPERM/EBUSY even though
    // nothing is actually wrong — it clears as soon as that read completes.
    // POSIX doesn't have this failure mode, so this only ever retries there.
    for (let attempt = 1; ; attempt += 1) {
      try {
        await fs.rename(temp, target);
        return;
      } catch (error) {
        if (!['EPERM', 'EBUSY'].includes(error.code) || attempt >= 5) throw error;
        await new Promise((resolve) => setTimeout(resolve, 10 * attempt));
      }
    }
  }

  async function execute(entry) {
    running.set(entry.jobId, { tenantId: entry.tenantId, isDocker: entry.isDocker });
    const jobDir = jobDirectory(apiHome, entry.tenantId, entry.jobId);
    entry.record.status = 'running';
    entry.record.startedAt = new Date().toISOString();
    await persist(entry.tenantId, entry.jobId, entry.record);
    try {
      const signingKey = await resolveSigningKey();
      const reportProgress = async (progress) => {
        entry.record.progress = progress;
        await persist(entry.tenantId, entry.jobId, entry.record);
      };
      const result = await handlers[entry.record.type]({
        apiHome, tenantId: entry.tenantId, jobId: entry.jobId, jobDir, params: entry.record.params, signingKey, reportProgress, safety
      });
      await fs.writeFile(path.join(jobDir, 'result.json'), `${JSON.stringify(result, null, 2)}\n`, 'utf8');
      entry.record.status = 'succeeded';
    } catch (error) {
      entry.record.status = 'failed';
      entry.record.error = error.message;
    }
    entry.record.finishedAt = new Date().toISOString();
    await persist(entry.tenantId, entry.jobId, entry.record);
    running.delete(entry.jobId);
    schedule();
  }

  function schedule() {
    if (running.size >= globalConcurrency) return;
    for (let index = 0; index < pending.length; index += 1) {
      const entry = pending[index];
      if (running.size >= globalConcurrency) break;
      if (runningCountForTenant(entry.tenantId) >= tenantConcurrency) continue;
      if (entry.isDocker && runningDockerCount() >= dockerConcurrency) continue;
      pending.splice(index, 1);
      index -= 1;
      execute(entry);
    }
  }

  async function submit(tenantId, type, params) {
    if (!handlers[type]) throw new Error(`Unknown job type '${type}'. Expected one of: ${JOB_TYPES.join(', ')}.`);
    if (HOST_EXECUTION_JOB_TYPES.has(type) && !safety.allowHostExecution) {
      throw new Error(`'${type}' runs programs on the server, so it is off on this API. Run it with the pqc-forge CLI or the GitHub Action on your own runner.`);
    }
    const jobId = `j_${randomBytes(8).toString('hex')}`;
    const jobDir = jobDirectory(apiHome, tenantId, jobId);
    await fs.mkdir(jobDir, { recursive: true });
    const record = {
      schema: JOB_SCHEMA, jobId, tenantId, type, params,
      status: 'queued', createdAt: new Date().toISOString(), startedAt: null, finishedAt: null, error: null, progress: null
    };
    await persist(tenantId, jobId, record);
    // Snapshot before scheduling: execute() mutates `record` in place (so
    // that persisted state and in-memory state never drift apart), and for
    // an immediately-runnable job that mutation can happen synchronously
    // within schedule() below, before this function returns. A POST
    // response should reflect the job as submitted, not as it happens to
    // stand a tick later — callers poll GET /v1/jobs/:id for that.
    const snapshot = { ...record };
    pending.push({ jobId, tenantId, isDocker: DOCKER_JOB_TYPES.has(type), record });
    schedule();
    return snapshot;
  }

  async function getJob(tenantId, jobId) {
    if (!JOB_ID_PATTERN.test(jobId ?? '')) return null;
    try {
      const record = JSON.parse(await fs.readFile(path.join(jobDirectory(apiHome, tenantId, jobId), 'job.json'), 'utf8'));
      if (record.tenantId !== tenantId) return null;
      return record;
    } catch (error) {
      if (error.code === 'ENOENT') return null;
      throw error;
    }
  }

  /**
   * List a tenant's own jobs, newest first. There is no separate index —
   * job.json files are the only source of truth, so this reads every job
   * directory the tenant has. That is fine at the scale a single tenant
   * directory holds (job history a dashboard would page through, not an
   * unbounded event log); an operator running this at a much larger scale
   * would want a real index instead of directory-scan-on-every-request.
   */
  async function listJobs(tenantId, { limit = 50, status = null, type = null } = {}) {
    const dir = tenantJobsDirectory(apiHome, tenantId);
    let jobIds;
    try {
      jobIds = await fs.readdir(dir);
    } catch (error) {
      if (error.code === 'ENOENT') return { jobs: [], total: 0 };
      throw error;
    }
    const records = (await Promise.all(jobIds.map((jobId) => getJob(tenantId, jobId)))).filter(Boolean);
    records.sort((a, b) => (a.createdAt < b.createdAt ? 1 : a.createdAt > b.createdAt ? -1 : 0));
    const filtered = records.filter((record) => (!status || record.status === status) && (!type || record.type === type));
    const capped = Math.min(Math.max(1, Number(limit) || 50), 200);
    return { jobs: filtered.slice(0, capped), total: filtered.length };
  }

  async function getResult(tenantId, jobId) {
    if (!JOB_ID_PATTERN.test(jobId ?? '')) return null;
    try {
      return JSON.parse(await fs.readFile(path.join(jobDirectory(apiHome, tenantId, jobId), 'result.json'), 'utf8'));
    } catch (error) {
      if (error.code === 'ENOENT') return null;
      throw error;
    }
  }

  /**
   * Reconcile job state left behind by a prior process (a crash or restart
   * mid-job). A 'running' record cannot be resumed — its in-memory work is
   * gone — so it is honestly marked failed rather than left claiming to
   * still be in progress forever. A 'queued' record never started real
   * work and is safe to re-enqueue.
   */
  async function reconcile(tenantIds) {
    for (const tenantId of tenantIds) {
      const dir = tenantJobsDirectory(apiHome, tenantId);
      let jobIds;
      try {
        jobIds = await fs.readdir(dir);
      } catch (error) {
        if (error.code === 'ENOENT') continue;
        throw error;
      }
      for (const jobId of jobIds) {
        const record = await getJob(tenantId, jobId);
        if (!record || TERMINAL_STATES.has(record.status)) continue;
        if (record.status === 'running') {
          record.status = 'failed';
          record.error = 'Interrupted: the server restarted while this job was running.';
          record.finishedAt = new Date().toISOString();
          await persist(tenantId, jobId, record);
        } else if (record.status === 'queued') {
          pending.push({ jobId, tenantId, isDocker: DOCKER_JOB_TYPES.has(record.type), record });
        }
      }
    }
    schedule();
  }

  return { submit, getJob, getResult, listJobs, reconcile, stats: () => ({ pending: pending.length, running: running.size }) };
}
