// Shapes returned by the PQC Forge REST API (src/api/*.js). Kept loose
// where a field is receipt/evidence payload that the dashboard only ever
// displays verbatim or hands back to verify-receipt, never inspects.

export interface HealthResponse {
  status: string;
  version: string;
  pending: number;
  running: number;
}

export type JobStatus = 'queued' | 'running' | 'succeeded' | 'failed';

export interface JobProgress {
  total: number;
  completed: number;
  cells?: BreakLabGridCell[];
}

export interface JobRecord {
  schema: string;
  jobId: string;
  tenantId: string;
  type: string;
  params: Record<string, unknown>;
  status: JobStatus;
  createdAt: string;
  startedAt: string | null;
  finishedAt: string | null;
  error: string | null;
  progress: JobProgress | null;
}

export interface JobListResponse {
  jobs: JobRecord[];
  total: number;
}

export interface WorkspaceFile {
  path: string;
  content: string;
}

export interface WorkspaceUploadResponse {
  workspaceId: string;
  files: { path: string; bytes: number }[];
  totalBytes: number;
}

export interface ScanFinding {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: string;
  file: string;
  line: number;
  excerpt: string;
  reason: string;
  remediation: string;
  standard: string;
  automatable: boolean;
}

export interface ScanReport {
  schema: string;
  generatedAt: string;
  root: string;
  filesScanned: number;
  summary: {
    total: number; critical: number; high: number; medium: number; low: number;
    automatable: number; suppressed: number;
  };
  suppressionFile: string | null;
  findings: ScanFinding[];
  suppressedFindings: unknown[];
}

export interface MigrationChange {
  ruleId: string;
  file: string;
  line: number;
  before: string | null;
  after: string | null;
}

export interface MigrationResult {
  schema: string;
  generatedAt: string;
  root: string;
  mode: 'applied' | 'dry-run';
  runtimeRequirement: string;
  changeCount: number;
  changes: MigrationChange[];
}

// Every receipt shares this signed envelope shape; payload fields beyond it
// vary by receipt type and are rendered generically (raw JSON), never
// depended on structurally by the dashboard.
export interface Receipt {
  schema: string;
  generatedAt: string;
  receiptDigest: string;
  signature: { publicKey: string; keyId?: string;[key: string]: unknown };
  [key: string]: unknown;
}

export interface ReceiptVerification {
  valid: boolean;
  digestValid: boolean;
  signaturePresent: boolean;
  signatureValid: boolean;
  keyTrusted: boolean | null;
  expected: string;
  actual: string;
  keyId: string | null;
  errors: string[];
}

export interface TlsEvidence {
  schema: string;
  generatedAt: string;
  target: string;
  elapsedMs: number;
  authorized: boolean;
  authorizationError: string | null;
  protocol: string;
  cipher: { name: string; standardName?: string; version?: string };
  ephemeralKey: { name?: string; type?: string; size?: number };
  peerSignatureAlgorithm: string;
  runtime: { node: string; openssl: string };
  verdict: {
    pqKeyExchange: boolean;
    pqAuthentication: boolean;
    status: 'full-pq-observed' | 'pq-confidentiality-observed' | 'no-pq-negotiation-observed';
  };
}

export interface BreakLabFinding {
  code: string;
  severity: number;
  message: string;
}

export interface BreakLabStrategy {
  strategy: string;
  terminology: string;
  evaluations: number;
  stateCoverage: number;
  failingConfigurations: number;
  uniqueFailureModes: string[];
  maxSeverity: number;
  runtimeMs: number;
  seed: number;
}

export interface BreakLabCounterexample {
  failureCode: string;
  candidate: Record<string, string | boolean>;
  negotiatedGroup: string;
  signatureAlgorithm: string;
  handshakeBytes: number;
  fragments: number;
  latencyMs: number;
  findings: BreakLabFinding[];
  severity: number;
  changedDimensions: string[];
}

export interface BreakLabRun {
  schema: string;
  scenario: string;
  seed: number;
  evaluationBudgetPerStrategy: number;
  totalStates: number;
  winner: string;
  strategies: BreakLabStrategy[];
  counterexamples: BreakLabCounterexample[];
  verdict: { highestSeverity: number; failureModes: string[]; pass: boolean };
}

export interface BreakLabGridCell {
  client: string;
  server: string;
  negotiatedGroup: string;
  findings: BreakLabFinding[];
  severity: number;
  pass: boolean;
}

export interface BreakLabGridResult {
  schema: string;
  scenario: string;
  dimensions: { client: string[]; server: string[] };
  fixed: { certificate: string; network: string; allowClassicalFallback: boolean };
  cells: BreakLabGridCell[];
}

export interface BreakLabScenario {
  schema: string;
  name: string;
  dimensions: {
    client: string[]; server: string[]; certificate: string[];
    network: string[]; allowClassicalFallback: boolean[];
  };
  [key: string]: unknown;
}
