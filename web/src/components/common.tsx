import type { ReactNode } from 'react';

export function Panel({ title, actions, children }: { title?: string; actions?: ReactNode; children: ReactNode }) {
  return (
    <section className="panel">
      {(title || actions) && (
        <header className="panel-head">
          {title && <h2>{title}</h2>}
          {actions}
        </header>
      )}
      <div className="panel-body">{children}</div>
    </section>
  );
}

const SEVERITY_CLASS: Record<string, string> = {
  critical: 'critical', high: 'high', medium: 'medium', low: 'low'
};

export function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`badge ${SEVERITY_CLASS[severity] ?? 'low'}`}>{severity}</span>;
}

export function StatusBadge({ status }: { status: string }) {
  const cls = status === 'succeeded' ? 'pass' : status === 'failed' ? 'fail' : status === 'running' ? 'medium' : 'low';
  return <span className={`badge ${cls}`}>{status}</span>;
}

export function PassFailBadge({ pass, passLabel = 'pass', failLabel = 'fail' }: { pass: boolean; passLabel?: string; failLabel?: string }) {
  return <span className={`badge ${pass ? 'pass' : 'fail'}`}>{pass ? passLabel : failLabel}</span>;
}

export function JsonBlock({ value }: { value: unknown }) {
  return <pre className="json-block">{JSON.stringify(value, null, 2)}</pre>;
}

export function ErrorNote({ message }: { message: string | null }) {
  if (!message) return null;
  return <div className="error-note">{message}</div>;
}

export function Spinner() {
  return <span className="spinner" aria-label="working" />;
}
