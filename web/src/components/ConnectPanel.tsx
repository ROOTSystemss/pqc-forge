import { useState, type FormEvent } from 'react';
import { ApiError, PqcForgeClient } from '../api';
import { ErrorNote, Panel } from './common';

export function ConnectPanel({
  initialBaseUrl, initialApiKey, onConnect
}: {
  initialBaseUrl: string; initialApiKey: string;
  onConnect: (client: PqcForgeClient, baseUrl: string, apiKey: string) => void;
}) {
  const [baseUrl, setBaseUrl] = useState(initialBaseUrl);
  const [apiKey, setApiKey] = useState(initialApiKey);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function handleConnect(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    const trimmedUrl = baseUrl.trim().replace(/\/+$/, '');
    const trimmedKey = apiKey.trim();
    const client = new PqcForgeClient(trimmedUrl, trimmedKey);
    try {
      await client.health();
      // Health is public; listing jobs proves the API key itself is valid
      // before we hand the client to the rest of the app.
      await client.listJobs({ limit: 1 });
      onConnect(client, trimmedUrl, trimmedKey);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="connect-screen">
      <Panel title="Connect to PQC Forge">
        <form onSubmit={handleConnect} className="connect-form">
          <div>
            <label>API base URL</label>
            <input type="text" value={baseUrl} onChange={(event) => setBaseUrl(event.target.value)} placeholder="http://localhost:8787" />
          </div>
          <div>
            <label>Tenant API key</label>
            <input type="password" value={apiKey} onChange={(event) => setApiKey(event.target.value)} placeholder="pqcf_t_…" />
          </div>
          <button className="primary" type="submit" disabled={busy || !baseUrl.trim() || !apiKey.trim()}>
            {busy ? 'Connecting…' : 'Connect'}
          </button>
          <ErrorNote message={error} />
        </form>
        <p className="muted small">
          No API key yet? An operator provisions one from the server host:<br />
          <code>node ./bin/pqc-forge.js tenant-create --name "your-name" --out ./pqc-forge-api-data</code>
          <br />The key is shown once and only its hash is stored — save it somewhere safe.
        </p>
      </Panel>
    </div>
  );
}
