import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

// N-PF-06 (knock-out 2026-11-17): with DATABASE_URL, uploaded workspaces and job output files survive a restart.
// Server A takes an upload and runs a job that writes a downloadable file; then a FRESH server B starts on an EMPTY
// home folder (what a host that lost its disk looks like) with the same database: the download still works, a new job
// on the old workspace still runs (the workspace is put back on disk), the quota still counts it, the account export
// includes the files, and account deletion removes the stored copies. Postgres only (PQC_TEST_DATABASE_URL).
const pgUrl = process.env.PQC_TEST_DATABASE_URL;

test('uploads and job files survive a restart (Postgres)', { skip: !pgUrl && 'set PQC_TEST_DATABASE_URL', timeout: 90_000 }, async () => {
  process.env.DATABASE_URL = pgUrl;
  const { createApiServer } = await import('../src/api/server.js');
  const { closeDocStore, docDb } = await import('../src/api/docStore.js');
  const { storedWorkspaceUsage } = await import('../src/api/fileStore.js');
  const { tenantWorkspacesDirectory } = await import('../src/api/tenants.js');
  const { generateSigningKey } = await import('../src/signing.js');
  const K = generateSigningKey();
  const REPORT = '<html><body>KO restart survival ' + Date.now() + '</body></html>';
  const handlers = {
    scan: async ({ jobDir, params, apiHome, tenantId }) => {
      if (params.workspaceId) {
        const { resolveWorkspacePath } = await import('../src/api/workspace.js');
        const { root } = resolveWorkspacePath(apiHome, tenantId, params.workspaceId);
        const content = await fs.readFile(path.join(root, 'nginx.conf'), 'utf8');
        await fs.writeFile(path.join(jobDir, 'readiness-report.html'), REPORT + content, 'utf8');
      }
      return { ok: true };
    },
  };
  async function start() {
    const apiHome = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-restart-'));
    const keyFile = path.join(apiHome, 'signing-key.json');
    await fs.writeFile(keyFile, JSON.stringify(K));
    const { server } = createApiServer({ apiHome, signingKeyPath: keyFile, handlers });
    await new Promise((resolve) => server.listen(0, resolve));
    return { apiHome, base: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); }) };
  }
  const json = (h) => ({ ...h, 'content-type': 'application/json' });
  const waitDone = async (base, h, id) => { for (let i = 0; i < 400; i++) { const j = await (await fetch(`${base}/v1/jobs/${id}`, { headers: h })).json(); if (['succeeded', 'failed'].includes(j.status)) return j; await new Promise((r) => setTimeout(r, 25)); } return null; };

  // --- server A: upload, run a job, download ---
  const a = await start();
  const signup = await (await fetch(`${a.base}/v1/signup`, { method: 'POST', headers: json({}), body: JSON.stringify({ name: 'Restart Co', email: 'restart@example.test' }) })).json();
  const h = json({ authorization: `Bearer ${signup.apiKey}` });
  const ws = await (await fetch(`${a.base}/v1/workspaces`, { method: 'POST', headers: h, body: JSON.stringify({ files: [{ path: 'nginx.conf', content: 'ssl_protocols TLSv1.2;\n' }] }) })).json();
  assert.match(ws.workspaceId, /^ws_[0-9a-f]{16}$/);
  const job = await (await fetch(`${a.base}/v1/jobs`, { method: 'POST', headers: h, body: JSON.stringify({ type: 'scan', params: { workspaceId: ws.workspaceId } }) })).json();
  assert.equal((await waitDone(a.base, h, job.jobId)).status, 'succeeded');
  const first = await fetch(`${a.base}/v1/jobs/${job.jobId}/files/readiness-report.html`, { headers: h });
  assert.equal(first.status, 200);
  const firstBody = await first.text();
  assert.ok(firstBody.includes('KO restart survival'));
  await a.close();
  await closeDocStore();

  // --- server B: empty home folder, same database ---
  const b = await start();
  assert.notEqual(b.apiHome, a.apiHome);
  await assert.rejects(fs.access(path.join(b.apiHome, 'tenants')), 'the new home starts empty');
  const again = await fetch(`${b.base}/v1/jobs/${job.jobId}/files/readiness-report.html`, { headers: h });
  assert.equal(again.status, 200, 'the job file is served after the restart');
  assert.equal(await again.text(), firstBody, 'byte-for-byte the same file');

  const job2 = await (await fetch(`${b.base}/v1/jobs`, { method: 'POST', headers: h, body: JSON.stringify({ type: 'scan', params: { workspaceId: ws.workspaceId } }) })).json();
  assert.ok(job2.jobId, 'a job on the old workspace is accepted (workspace put back): ' + JSON.stringify(job2));
  assert.equal((await waitDone(b.base, h, job2.jobId)).status, 'succeeded', 'and it runs against the restored files');
  const restored = await fs.readFile(path.join(tenantWorkspacesDirectory(b.apiHome, signup.tenantId), ws.workspaceId, 'nginx.conf'), 'utf8');
  assert.equal(restored, 'ssl_protocols TLSv1.2;\n');

  const usage = await storedWorkspaceUsage(b.apiHome, tenantWorkspacesDirectory(b.apiHome, signup.tenantId));
  assert.equal(usage.workspaces, 1, 'the quota still counts the stored workspace');
  assert.equal(usage.bytes, Buffer.byteLength('ssl_protocols TLSv1.2;\n'));

  // Export after a second empty-disk restart still includes the files.
  await b.close();
  await closeDocStore();
  const c = await start();
  const exp = await (await fetch(`${c.base}/v1/account/export`, { headers: h })).json();
  const paths = (exp.files || []).map((f) => f.path);
  assert.ok(paths.some((p) => p.endsWith(`${ws.workspaceId}/nginx.conf`)), 'export includes the uploaded file: ' + paths.join(','));
  assert.ok(paths.some((p) => p.endsWith(`${job.jobId}/readiness-report.html`)), 'export includes the job file');

  // Delete removes the stored copies.
  const del = await fetch(`${c.base}/v1/account/delete`, { method: 'POST', headers: h, body: JSON.stringify({ confirm: 'DELETE' }) });
  assert.equal(del.status, 200);
  const { rows } = await (await docDb()).query(`SELECT count(*)::int AS n FROM pqcf_files WHERE key LIKE $1`, [`tenants/${signup.tenantId}/%`]);
  assert.equal(rows[0].n, 0, 'no stored file left for the deleted account');
  await c.close();
  await closeDocStore();
});
