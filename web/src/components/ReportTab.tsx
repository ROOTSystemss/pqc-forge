import { useEffect, useState } from 'react';
import type { PqcForgeClient } from '../api';
import { ApiError } from '../api';
import { useJobRunner } from '../useJobRunner';
import { EXAMPLE_WORKSPACES } from '../fixtures';
import type { WorkspaceFile } from '../types';
import { EmptyState, ErrorNote, Panel, Spinner } from './common';
import { WorkspaceEditor } from './WorkspaceEditor';

interface ReportJobResult {
  readiness: { score: number; stage: string; stageLabel: string; stageSummary: string };
  summary: { findings: number; critical: number; high: number; medium: number; migrationChangesReady: number; endpointsPostQuantum: number; endpointsClassicalOnly: number; endpointsUnreachable: number };
  roadmap: { priority: string; title: string }[];
  files: string[];
}

// The paid readiness report: upload code/configuration and list live endpoints; PQC Forge scans,
// checks and signs, and the report is downloaded as one HTML page plus the signed JSON.
export function ReportTab({ client, onBuyCredit }: { client: PqcForgeClient | null; onBuyCredit?: () => void }) {
  const [files, setFiles] = useState<WorkspaceFile[]>(EXAMPLE_WORKSPACES['Nginx (classical groups)']);
  const [organization, setOrganization] = useState('');
  const [endpoints, setEndpoints] = useState('');
  const [credits, setCredits] = useState<number | null>(null);
  const [uploading, setUploading] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);
  const { job, result, error, running, run } = useJobRunner<ReportJobResult>(client);

  useEffect(() => {
    if (!client) return;
    client.subscription().then((s) => setCredits(s.reportCredits)).catch(() => setCredits(null));
  }, [client, result]);

  async function handleRun() {
    if (!client) return;
    setLocalError(null);
    const list = endpoints.split(/[\s,]+/).map((e) => e.trim()).filter(Boolean);
    if (list.length > 10) { setLocalError('List at most 10 endpoints.'); return; }
    setUploading(true);
    try {
      const workspace = files.length ? await client.createWorkspace(files) : null;
      await run('readiness-report', { organization: organization.trim() || 'Your organization', workspaceId: workspace ? workspace.workspaceId : undefined, endpoints: list });
    } catch (err) {
      setLocalError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setUploading(false);
    }
  }

  async function download(name: string) {
    if (!client || !job) return;
    try {
      const blob = await client.getJobFile(job.jobId, name);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = name; a.click();
      setTimeout(() => URL.revokeObjectURL(url), 2000);
    } catch (err) {
      setLocalError(err instanceof ApiError ? err.message : String(err));
    }
  }

  const busy = uploading || running;
  const noCredit = credits !== null && credits < 1;

  return (
    <div className="tab-grid">
      <Panel title="Readiness report">
        <p className="muted small">A signed post-quantum readiness report built from your real code and live endpoints: readiness score and stage, a fix-first plan, every finding with file and line, deadlines (NIST, CNSA 2.0, EU) and where it counts as evidence (PCI DSS 12.3.3, ISO 27001 A.8.24, NIS2, DORA). One report credit per report; the credit is used only when the report is produced.</p>
        <p className="small">Report credits: <strong>{credits ?? '…'}</strong>{noCredit && <> · <button type="button" className="link-button" onClick={onBuyCredit}>buy a report credit</button></>}</p>
        <label htmlFor="report-org">Organization name (shown on the report)</label>
        <input id="report-org" type="text" maxLength={120} value={organization} onChange={(e) => setOrganization(e.target.value)} placeholder="Acme Payments Ltd" />
        <label htmlFor="report-endpoints">Live endpoints to check (up to 10, public only)</label>
        <textarea id="report-endpoints" rows={3} value={endpoints} onChange={(e) => setEndpoints(e.target.value)} placeholder={'shop.example.com:443\napi.example.com'} />
        <p className="muted small">Code and configuration to scan (paste or edit files below):</p>
        <WorkspaceEditor files={files} onChange={setFiles} />
        <div className="run-row">
          <button className="primary" onClick={handleRun} disabled={!client || busy || noCredit}>
            {busy ? <Spinner /> : null} Generate report
          </button>
        </div>
        <ErrorNote message={localError ?? error} />
      </Panel>

      <Panel title="Result">
        {!result && <EmptyState icon="◇" message="Generate a report to see your readiness here." hint="Takes under a minute for typical uploads." />}
        {result && (
          <>
            <div className="summary-row">
              <span className="badge pass">{result.readiness.score}/100</span>
              <strong>{result.readiness.stageLabel}</strong>
            </div>
            <p className="muted small">{result.readiness.stageSummary}</p>
            <div className="summary-row">
              <span className="badge critical">{result.summary.critical} critical</span>
              <span className="badge high">{result.summary.high} high</span>
              <span className="badge medium">{result.summary.medium} medium</span>
              <span className="muted">{result.summary.migrationChangesReady} change(s) PQC Forge can generate · {result.summary.endpointsPostQuantum} endpoint(s) post-quantum, {result.summary.endpointsClassicalOnly} classical only</span>
            </div>
            <ol className="small">
              {result.roadmap.map((step, i) => <li key={i}><strong>{step.priority}:</strong> {step.title}</li>)}
            </ol>
            <div className="run-row">
              <button className="primary" onClick={() => download('readiness-report.html')}>Download report (HTML)</button>
              <button className="ghost" onClick={() => download('readiness-report.json')}>Download signed JSON</button>
            </div>
            <p className="muted small">Open the HTML in a browser and print to PDF to share it. Anyone can check the signed JSON on the Verify Receipt tab.</p>
          </>
        )}
      </Panel>
    </div>
  );
}
