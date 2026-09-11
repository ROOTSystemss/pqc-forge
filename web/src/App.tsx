import { useEffect, useState } from 'react';
import { PqcForgeClient } from './api';
import type { HealthResponse } from './types';
import { useTheme } from './useTheme';
import { ThemeToggle } from './components/ThemeToggle';
import { ConnectPanel } from './components/ConnectPanel';
import { ScanTab } from './components/ScanTab';
import { MigrateTab } from './components/MigrateTab';
import { VerifyTlsTab } from './components/VerifyTlsTab';
import { BreakLabTab } from './components/BreakLabTab';
import { BreakLabGridTab } from './components/BreakLabGridTab';
import { JobsTab } from './components/JobsTab';
import { ReceiptTab } from './components/ReceiptTab';

const STORAGE_BASE_URL = 'pqcf.baseUrl';
const STORAGE_API_KEY = 'pqcf.apiKey';

const TABS = [
  { id: 'scan', label: 'Scan' },
  { id: 'migrate', label: 'Migrate' },
  { id: 'verify', label: 'Verify TLS' },
  { id: 'breaklab', label: 'BreakLab' },
  { id: 'grid', label: 'BreakLab Grid' },
  { id: 'jobs', label: 'Jobs' },
  { id: 'receipt', label: 'Verify Receipt' }
] as const;

type TabId = typeof TABS[number]['id'];

function readStorage(key: string): string {
  try { return localStorage.getItem(key) ?? ''; } catch { return ''; }
}

export default function App() {
  const [client, setClient] = useState<PqcForgeClient | null>(null);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [tab, setTab] = useState<TabId>('scan');
  const { theme, setTheme } = useTheme();

  useEffect(() => {
    if (!client) return;
    let cancelled = false;
    const poll = () => client.health().then((response) => { if (!cancelled) setHealth(response); }).catch(() => {});
    poll();
    const timer = setInterval(poll, 5000);
    return () => { cancelled = true; clearInterval(timer); };
  }, [client]);

  function handleConnect(newClient: PqcForgeClient, baseUrl: string, apiKey: string) {
    try {
      localStorage.setItem(STORAGE_BASE_URL, baseUrl);
      localStorage.setItem(STORAGE_API_KEY, apiKey);
    } catch { /* private browsing / storage disabled — the session still works */ }
    setClient(newClient);
  }

  function handleDisconnect() {
    try {
      localStorage.removeItem(STORAGE_API_KEY);
    } catch { /* ignore */ }
    setClient(null);
    setHealth(null);
  }

  if (!client) {
    return (
      <div className="app">
        <AppHeader health={null} onDisconnect={null} theme={theme} onThemeChange={setTheme} />
        <ConnectPanel initialBaseUrl={readStorage(STORAGE_BASE_URL) || 'http://localhost:8787'} initialApiKey={readStorage(STORAGE_API_KEY)} onConnect={handleConnect} />
      </div>
    );
  }

  return (
    <div className="app">
      <AppHeader health={health} onDisconnect={handleDisconnect} theme={theme} onThemeChange={setTheme} />
      <nav className="tabs">
        <div className="tabs-track">
          {TABS.map(({ id, label }) => (
            <button key={id} className={id === tab ? 'tab active' : 'tab'} onClick={() => setTab(id)}>{label}</button>
          ))}
        </div>
      </nav>
      <main className="tab-content" key={tab}>
        {tab === 'scan' && <ScanTab client={client} />}
        {tab === 'migrate' && <MigrateTab client={client} />}
        {tab === 'verify' && <VerifyTlsTab client={client} />}
        {tab === 'breaklab' && <BreakLabTab client={client} />}
        {tab === 'grid' && <BreakLabGridTab client={client} />}
        {tab === 'jobs' && <JobsTab client={client} />}
        {tab === 'receipt' && <ReceiptTab client={client} />}
      </main>
    </div>
  );
}

function AppHeader({
  health, onDisconnect, theme, onThemeChange
}: {
  health: HealthResponse | null; onDisconnect: (() => void) | null;
  theme: ReturnType<typeof useTheme>['theme']; onThemeChange: ReturnType<typeof useTheme>['setTheme'];
}) {
  return (
    <header className="app-header">
      <div className="brand">
        <span className="brand-mark">◈</span>
        <span>PQC Forge</span>
        {health && <span className="chip">v{health.version}</span>}
      </div>
      <div className="header-status">
        {health && (
          <span className="muted small queue-status">
            <span className="dot online" /> {health.pending} pending · {health.running} running
          </span>
        )}
        {!health && onDisconnect === null && <span className="muted small">not connected</span>}
        <ThemeToggle theme={theme} onChange={onThemeChange} />
        {onDisconnect && <button className="ghost" onClick={onDisconnect}>disconnect</button>}
      </div>
    </header>
  );
}
