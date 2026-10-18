import type {
  HealthResponse, JobListResponse, JobRecord, PlansResponse, ReceiptVerification,
  SubscriptionResponse, WorkspaceFile, WorkspaceUploadResponse
} from './types';

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = 'ApiError';
  }
}

async function parseResponse<T>(response: Response, _baseUrl: string): Promise<T> {
  const text = await response.text();
  const body = text ? JSON.parse(text) : {};
  if (!response.ok) throw new ApiError(response.status, body.error ?? `Request failed with status ${response.status}.`);
  return body as T;
}

/** Public signup — no API key yet. */
export async function signup(baseUrl: string, body: { name: string; email?: string }) {
  let response: Response;
  try {
    response = await fetch(`${baseUrl.replace(/\/+$/, '')}/v1/signup`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body)
    });
  } catch {
    throw new ApiError(0, `Could not reach ${baseUrl} — check the base URL and that the API server is running.`);
  }
  return parseResponse<{ tenantId: string; apiKey: string; plan: string; message: string }>(response, baseUrl);
}

/**
 * Thin fetch wrapper bound to one base URL + tenant API key. Every call
 * throws ApiError with the server's own message on a non-2xx response,
 * so callers can render `error.message` directly instead of a generic
 * "request failed".
 */
export class PqcForgeClient {
  baseUrl: string;
  apiKey: string;

  constructor(baseUrl: string, apiKey: string) {
    this.baseUrl = baseUrl;
    this.apiKey = apiKey;
  }

  private async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    let response: Response;
    try {
      response = await fetch(`${this.baseUrl}${path}`, {
        ...init,
        headers: {
          ...(this.apiKey ? { authorization: `Bearer ${this.apiKey}` } : {}),
          ...(init.body ? { 'content-type': 'application/json' } : {}),
          ...init.headers
        }
      });
    } catch {
      throw new ApiError(0, `Could not reach ${this.baseUrl} — check the base URL and that the API server is running.`);
    }
    return parseResponse<T>(response, this.baseUrl);
  }

  health() {
    return this.request<HealthResponse>('/v1/health');
  }

  plans() {
    return this.request<PlansResponse>('/v1/plans');
  }

  subscription() {
    return this.request<SubscriptionResponse>('/v1/subscription');
  }

  checkout(body: { plan?: string; interval?: string; quantity?: number; item?: string; country?: string; returnUrl?: string }) {
    return this.request<{ url: string; ref: string | null }>('/v1/billing/checkout', {
      method: 'POST', body: JSON.stringify(body)
    });
  }

  createWorkspace(files: WorkspaceFile[]) {
    return this.request<WorkspaceUploadResponse>('/v1/workspaces', { method: 'POST', body: JSON.stringify({ files }) });
  }

  submitJob(type: string, params: Record<string, unknown> = {}) {
    return this.request<JobRecord>('/v1/jobs', { method: 'POST', body: JSON.stringify({ type, params }) });
  }

  getJob(jobId: string) {
    return this.request<JobRecord>(`/v1/jobs/${jobId}`);
  }

  getJobResult<T>(jobId: string) {
    return this.request<T>(`/v1/jobs/${jobId}/result`);
  }

  /** A job's downloadable file (the readiness report), as a Blob to save. */
  async getJobFile(jobId: string, name: string): Promise<Blob> {
    let response: Response;
    try {
      response = await fetch(`${this.baseUrl}/v1/jobs/${jobId}/files/${name}`, { headers: this.apiKey ? { authorization: `Bearer ${this.apiKey}` } : {} });
    } catch {
      throw new ApiError(0, `Could not reach ${this.baseUrl}.`);
    }
    if (!response.ok) throw new ApiError(response.status, `Download failed (${response.status}).`);
    return response.blob();
  }

  listJobs(params: { limit?: number; status?: string; type?: string } = {}) {
    const query = new URLSearchParams();
    if (params.limit) query.set('limit', String(params.limit));
    if (params.status) query.set('status', params.status);
    if (params.type) query.set('type', params.type);
    const suffix = query.toString() ? `?${query.toString()}` : '';
    return this.request<JobListResponse>(`/v1/jobs${suffix}`);
  }

  verifyReceipt(receipt: unknown, trustedPublicKeys: string[] | null = null) {
    return this.request<ReceiptVerification>('/v1/verify-receipt', {
      method: 'POST', body: JSON.stringify({ receipt, trustedPublicKeys })
    });
  }
}

const TERMINAL: JobRecord['status'][] = ['succeeded', 'failed'];

/**
 * Poll a job until it reaches a terminal state, calling `onUpdate` with
 * every intermediate record (including in-flight `progress`) so a caller
 * can render live updates — e.g. the BreakLab grid filling in cell by
 * cell — rather than only the final state.
 */
export async function pollJob(
  client: PqcForgeClient, jobId: string,
  { intervalMs = 400, signal, onUpdate }: { intervalMs?: number; signal?: AbortSignal; onUpdate?: (record: JobRecord) => void } = {}
): Promise<JobRecord> {
  for (;;) {
    if (signal?.aborted) throw new ApiError(0, 'Cancelled.');
    const record = await client.getJob(jobId);
    onUpdate?.(record);
    if (TERMINAL.includes(record.status)) return record;
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
}
