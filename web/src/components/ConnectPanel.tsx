import { useState, type FormEvent } from 'react';
import { ApiError, PqcForgeClient, signup } from '../api';
import { ErrorNote, Panel, Spinner } from './common';

type Mode = 'signup' | 'key';

export function ConnectPanel({
  initialBaseUrl, initialApiKey, onConnect
}: {
  initialBaseUrl: string; initialApiKey: string;
  onConnect: (client: PqcForgeClient, baseUrl: string, apiKey: string) => void;
}) {
  const [mode, setMode] = useState<Mode>(initialApiKey ? 'key' : 'signup');
  const [baseUrl, setBaseUrl] = useState(initialBaseUrl);
  const [apiKey, setApiKey] = useState(initialApiKey);
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [revealedKey, setRevealedKey] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function connectWithKey(url: string, key: string) {
    const trimmedUrl = url.trim().replace(/\/+$/, '');
    const trimmedKey = key.trim();
    const client = new PqcForgeClient(trimmedUrl, trimmedKey);
    await client.health();
    await client.listJobs({ limit: 1 });
    onConnect(client, trimmedUrl, trimmedKey);
  }

  async function handleConnect(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await connectWithKey(baseUrl, apiKey);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function handleSignup(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    setRevealedKey(null);
    const trimmedUrl = baseUrl.trim().replace(/\/+$/, '');
    try {
      const created = await signup(trimmedUrl, { name: name.trim(), email: email.trim() || undefined });
      setRevealedKey(created.apiKey);
      setApiKey(created.apiKey);
      await connectWithKey(trimmedUrl, created.apiKey);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
      setBusy(false);
    }
  }

  return (
    <div className="connect-screen">
      <Panel>
        <div className="connect-hero">
          <img className="brand-mark-lg" src="/rs-logo.svg" alt="" width="40" height="44" />
          <h1>PQC Forge</h1>
          <p>Repository-to-proof migration for post-quantum TLS.</p>
        </div>
        <ul className="connect-features">
          <li>Static crypto discovery</li>
          <li>Signed, tamper-evident receipts</li>
          <li>Live TLS 1.3 verification</li>
          <li>Compatibility BreakLab search</li>
        </ul>

        <div className="connect-mode-tabs" role="tablist" aria-label="Sign in method">
          <button type="button" className={mode === 'signup' ? 'tab active' : 'tab'} onClick={() => setMode('signup')}>
            Create free account
          </button>
          <button type="button" className={mode === 'key' ? 'tab active' : 'tab'} onClick={() => setMode('key')}>
            I have an API key
          </button>
        </div>

        {mode === 'signup' ? (
          <form onSubmit={handleSignup} className="connect-form">
            <div>
              <label htmlFor="signup-base">API base URL</label>
              <input id="signup-base" type="text" value={baseUrl} onChange={(event) => setBaseUrl(event.target.value)} placeholder="http://localhost:8787" />
            </div>
            <div>
              <label htmlFor="signup-name">Name</label>
              <input id="signup-name" type="text" value={name} onChange={(event) => setName(event.target.value)} placeholder="Acme Security" required minLength={2} maxLength={80} />
            </div>
            <div>
              <label htmlFor="signup-email">Email <span className="muted">(optional)</span></label>
              <input id="signup-email" type="email" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="you@company.com" />
            </div>
            <button className="primary" type="submit" disabled={busy || !baseUrl.trim() || name.trim().length < 2}>
              {busy ? <><Spinner /> Creating…</> : 'Start free →'}
            </button>
            <ErrorNote message={error} />
            {revealedKey && (
              <p className="billing-notice">
                Your API key (shown once): <code className="api-key-reveal">{revealedKey}</code>
              </p>
            )}
            <p className="muted small">
              Free Community plan: public-repo CI, dashboard scan &amp; BreakLab. Upgrade anytime from Billing.
            </p>
          </form>
        ) : (
          <form onSubmit={handleConnect} className="connect-form">
            <div>
              <label htmlFor="key-base">API base URL</label>
              <input id="key-base" type="text" value={baseUrl} onChange={(event) => setBaseUrl(event.target.value)} placeholder="http://localhost:8787" />
            </div>
            <div>
              <label htmlFor="key-api">Tenant API key</label>
              <input id="key-api" type="password" value={apiKey} onChange={(event) => setApiKey(event.target.value)} placeholder="pqcf_t_…" />
            </div>
            <button className="primary" type="submit" disabled={busy || !baseUrl.trim() || !apiKey.trim()}>
              {busy ? <><Spinner /> Connecting…</> : 'Connect →'}
            </button>
            <ErrorNote message={error} />
            <p className="muted small">
              Prefer the CLI? An operator can still run:<br />
              <code>node ./bin/pqc-forge.js tenant-create --name &quot;your-name&quot; --out ./pqc-forge-api-data</code>
            </p>
          </form>
        )}
      </Panel>
    </div>
  );
}
