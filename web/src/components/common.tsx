import type { ReactNode } from 'react';

export function Panel({
  title, actions, children, tone, wide
}: { title?: string; actions?: ReactNode; children: ReactNode; tone?: 'accent' | 'critical'; wide?: boolean }) {
  return (
    <section className={`panel${tone ? ` tone-${tone}` : ''}${wide ? ' span-all' : ''}`}>
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
  return <span className={`badge ${cls}${status === 'running' ? ' badge-live' : ''}`}>{status}</span>;
}

export function PassFailBadge({ pass, passLabel = 'pass', failLabel = 'fail' }: { pass: boolean; passLabel?: string; failLabel?: string }) {
  return <span className={`badge ${pass ? 'pass' : 'fail'}`}>{pass ? passLabel : failLabel}</span>;
}

export function JsonBlock({ value }: { value: unknown }) {
  return <pre className="json-block">{JSON.stringify(value, null, 2)}</pre>;
}

export function ErrorNote({ message }: { message: string | null }) {
  if (!message) return null;
  return <div className="error-note">⚠ {message}</div>;
}

export function Spinner() {
  return <span className="spinner" aria-label="working" />;
}

export function EmptyState({ icon = '◌', message, hint }: { icon?: string; message: string; hint?: string }) {
  return (
    <div className="empty-state">
      <span className="empty-icon">{icon}</span>
      <p>{message}</p>
      {hint && <p className="muted small">{hint}</p>}
    </div>
  );
}

/** Hover/focus tooltip driven by a CSS pseudo-element — no portal, no JS positioning. */
export function Tip({ text, children }: { text: string; children: ReactNode }) {
  return (
    <div className="tip" data-tip={text} tabIndex={0}>
      {children}
    </div>
  );
}

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'] as const;

export function SeverityBar({ counts }: { counts: Record<'critical' | 'high' | 'medium' | 'low', number> }) {
  const total = SEVERITY_ORDER.reduce((sum, key) => sum + counts[key], 0);
  if (!total) return null;
  return (
    <div className="severity-bar" role="img" aria-label={SEVERITY_ORDER.map((key) => `${counts[key]} ${key}`).join(', ')}>
      {SEVERITY_ORDER.filter((key) => counts[key] > 0).map((key) => (
        <span key={key} className={`seg ${key}`} style={{ width: `${(counts[key] / total) * 100}%` }} />
      ))}
    </div>
  );
}
