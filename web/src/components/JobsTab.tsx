import { useEffect, useState } from 'react';
import type { PqcForgeClient } from '../api';
import { ApiError } from '../api';
import type { JobRecord } from '../types';
import { ErrorNote, JsonBlock, Panel, StatusBadge } from './common';

export function JobsTab({ client }: { client: PqcForgeClient | null }) {
  const [jobs, setJobs] = useState<JobRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<JobRecord | null>(null);
  const [result, setResult] = useState<unknown>(null);

  async function refresh() {
    if (!client) return;
    try {
      const response = await client.listJobs({ limit: 100 });
      setJobs(response.jobs);
      setTotal(response.total);
      setError(null);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    }
  }

  useEffect(() => {
    refresh();
    const timer = setInterval(refresh, 4000);
    return () => clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [client]);

  async function inspect(job: JobRecord) {
    setSelected(job);
    setResult(null);
    if (job.status === 'succeeded' && client) {
      try { setResult(await client.getJobResult(job.jobId)); } catch { /* result may have expired or not exist */ }
    }
  }

  return (
    <div className="tab-grid">
      <Panel title={`Jobs (${total})`} actions={<button className="ghost" onClick={refresh}>refresh</button>}>
        <ErrorNote message={error} />
        {jobs.length === 0 ? <p className="muted">No jobs submitted yet from this tenant.</p> : (
          <table>
            <thead><tr><th>Type</th><th>Status</th><th>Created</th><th>Progress</th><th></th></tr></thead>
            <tbody>
              {jobs.map((job) => (
                <tr key={job.jobId}>
                  <td className="mono">{job.type}</td>
                  <td><StatusBadge status={job.status} /></td>
                  <td className="mono small">{new Date(job.createdAt).toLocaleString()}</td>
                  <td>{job.progress ? `${job.progress.completed}/${job.progress.total}` : '—'}</td>
                  <td><button className="ghost" onClick={() => inspect(job)}>view</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      {selected && (
        <Panel title={`Job ${selected.jobId}`} actions={<button className="ghost" onClick={() => setSelected(null)}>close</button>}>
          <JsonBlock value={selected} />
          {selected.status === 'succeeded' && (
            <>
              <h3>Result</h3>
              <JsonBlock value={result ?? 'loading…'} />
            </>
          )}
        </Panel>
      )}
    </div>
  );
}
