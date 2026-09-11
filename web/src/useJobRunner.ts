import { useCallback, useRef, useState } from 'react';
import { ApiError, pollJob, type PqcForgeClient } from './api';
import type { JobRecord } from './types';

export interface JobRunnerState<T> {
  job: JobRecord | null;
  result: T | null;
  error: string | null;
  running: boolean;
}

/**
 * Submits one job, polls it to completion, and fetches its result —
 * the same submit/poll/fetch-result cycle every tab in this dashboard
 * needs, generalized so each tab only supplies the job type and params.
 */
export function useJobRunner<T>(client: PqcForgeClient | null, intervalMs = 400) {
  const [state, setState] = useState<JobRunnerState<T>>({ job: null, result: null, error: null, running: false });
  const abortRef = useRef<AbortController | null>(null);

  const run = useCallback(async (type: string, params: Record<string, unknown>) => {
    if (!client) return;
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    setState({ job: null, result: null, error: null, running: true });
    try {
      const submitted = await client.submitJob(type, params);
      setState((prev) => ({ ...prev, job: submitted }));
      const finished = await pollJob(client, submitted.jobId, {
        intervalMs, signal: controller.signal,
        onUpdate: (record) => setState((prev) => ({ ...prev, job: record }))
      });
      if (finished.status === 'failed') {
        setState({ job: finished, result: null, error: finished.error ?? 'Job failed.', running: false });
        return;
      }
      const result = await client.getJobResult<T>(finished.jobId);
      setState({ job: finished, result, error: null, running: false });
    } catch (error) {
      if (controller.signal.aborted) return;
      setState((prev) => ({ ...prev, error: error instanceof ApiError ? error.message : String(error), running: false }));
    }
  }, [client, intervalMs]);

  const reset = useCallback(() => setState({ job: null, result: null, error: null, running: false }), []);

  return { ...state, run, reset };
}
