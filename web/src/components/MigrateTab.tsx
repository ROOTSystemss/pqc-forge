import { useEffect, useState } from 'react';
import type { PqcForgeClient } from '../api';
import { ApiError } from '../api';
import { useJobRunner } from '../useJobRunner';
import { EXAMPLE_WORKSPACES } from '../fixtures';
import type { MigrationResult, Receipt, ReceiptVerification, WorkspaceFile } from '../types';
import { EmptyState, ErrorNote, PassFailBadge, Panel, Spinner } from './common';
import { WorkspaceEditor } from './WorkspaceEditor';

export function MigrateTab({ client }: { client: PqcForgeClient | null }) {
  const [files, setFiles] = useState<WorkspaceFile[]>(EXAMPLE_WORKSPACES['Nginx (classical groups)']);
  const [write, setWrite] = useState(false);
  const [acknowledgeRuntime, setAcknowledgeRuntime] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [verification, setVerification] = useState<ReceiptVerification | null>(null);
  const { result, error, running, run } = useJobRunner<{ migration: MigrationResult; receipt: Receipt }>(client);

  useEffect(() => {
    setVerification(null);
    if (!client || !result) return;
    client.verifyReceipt(result.receipt).then(setVerification).catch(() => setVerification(null));
  }, [client, result]);

  async function handleRun() {
    if (!client) return;
    setUploadError(null);
    setUploading(true);
    try {
      const workspace = await client.createWorkspace(files);
      await run('migrate', { workspaceId: workspace.workspaceId, write, acknowledgeRuntime });
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
        <div className="run-row column">
          <label className="checkbox-label">
            <input type="checkbox" checked={write} onChange={(event) => setWrite(event.target.checked)} />
            Write changes (otherwise dry-run only)
          </label>
          <label className="checkbox-label" style={write ? undefined : { opacity: 0.5 }}>
            <input
              type="checkbox" checked={acknowledgeRuntime} disabled={!write}
              onChange={(event) => setAcknowledgeRuntime(event.target.checked)}
            />
            I confirm the deployment runtime supports X25519MLKEM768 (required to write)
          </label>
          <button className="primary" onClick={handleRun} disabled={!client || busy || (write && !acknowledgeRuntime)}>
            {busy ? <Spinner /> : null} Run migration
          </button>
        </div>
        <ErrorNote message={uploadError ?? error} />
      </Panel>

      <Panel title="Proposed changes">
        {!result && <EmptyState icon="⇄" message="Run a migration to see proposed changes here." />}
        {result && (
          <>
            <div className="summary-row">
              <span className={`badge ${result.migration.mode === 'applied' ? 'pass' : 'low'}`}>{result.migration.mode}</span>
              <span>{result.migration.changeCount} change{result.migration.changeCount === 1 ? '' : 's'}</span>
              {verification && <PassFailBadge pass={verification.valid} passLabel="receipt verified" failLabel="receipt invalid" />}
            </div>
            {result.migration.changes.length === 0 ? (
              <EmptyState icon="✓" message="No changes needed — this configuration is already hybrid-ready." />
            ) : (
              <div className="diff-list">
                {result.migration.changes.map((change, index) => (
                  <div key={index} className="diff-card">
                    <div className="diff-head mono">{change.ruleId} — {change.file}:{change.line}</div>
                    {change.before !== null && <div className="diff-line removed">- {change.before}</div>}
                    {change.after !== null && <div className="diff-line added">+ {change.after}</div>}
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </Panel>
    </div>
  );
}
