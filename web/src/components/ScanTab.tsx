import { useState } from 'react';
import type { PqcForgeClient } from '../api';
import { ApiError } from '../api';
import { useJobRunner } from '../useJobRunner';
import { EXAMPLE_WORKSPACES } from '../fixtures';
import type { ScanReport, WorkspaceFile } from '../types';
import { ErrorNote, Panel, SeverityBadge, Spinner } from './common';
import { WorkspaceEditor } from './WorkspaceEditor';

export function ScanTab({ client }: { client: PqcForgeClient | null }) {
  const [files, setFiles] = useState<WorkspaceFile[]>(EXAMPLE_WORKSPACES['Nginx (classical groups)']);
  const [noIgnore, setNoIgnore] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const { result, error, running, run } = useJobRunner<ScanReport>(client);

  async function handleRun() {
    if (!client) return;
    setUploadError(null);
    setUploading(true);
    try {
      const workspace = await client.createWorkspace(files);
      await run('scan', { workspaceId: workspace.workspaceId, noIgnore });
    } catch (err) {
      setUploadError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setUploading(false);
    }
  }

  const busy = uploading || running;

  return (
    <div className="tab-grid">
      <Panel title="Configuration">
        <WorkspaceEditor files={files} onChange={setFiles} />
        <div className="run-row">
          <label className="checkbox-label">
            <input type="checkbox" checked={noIgnore} onChange={(event) => setNoIgnore(event.target.checked)} />
            Ignore audited suppressions (--no-ignore)
          </label>
          <button className="primary" onClick={handleRun} disabled={!client || busy}>
            {busy ? <Spinner /> : null} Run scan
          </button>
        </div>
        <ErrorNote message={uploadError ?? error} />
      </Panel>

      <Panel title="Findings">
        {!result && <p className="muted">Run a scan to see findings here.</p>}
        {result && (
          <>
            <div className="summary-row">
              <span>{result.filesScanned} files scanned</span>
              <span className="badge critical">{result.summary.critical} critical</span>
              <span className="badge high">{result.summary.high} high</span>
              <span className="badge medium">{result.summary.medium} medium</span>
              <span className="badge low">{result.summary.low} low</span>
              <span className="muted">{result.summary.automatable} automatable, {result.summary.suppressed} suppressed</span>
            </div>
            {result.findings.length === 0 ? (
              <p className="muted">No findings — this configuration looks clean.</p>
            ) : (
              <table>
                <thead>
                  <tr><th>Severity</th><th>Rule</th><th>Location</th><th>Reason</th><th>Remediation</th></tr>
                </thead>
                <tbody>
                  {result.findings.map((finding, index) => (
                    <tr key={index}>
                      <td><SeverityBadge severity={finding.severity} /></td>
                      <td className="mono">{finding.id}</td>
                      <td className="mono">{finding.file}:{finding.line}</td>
                      <td>{finding.reason}</td>
                      <td>{finding.remediation}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </>
        )}
      </Panel>
    </div>
  );
}
