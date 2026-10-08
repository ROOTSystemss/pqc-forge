import { useEffect, useState } from 'react';
import { PqcForgeClient } from './api';
import type { HealthResponse } from './types';
import { useTheme } from './useTheme';
import { ThemeToggle } from './components/ThemeToggle';
import { LatticeBackground } from './components/LatticeBackground';
import { ConnectPanel } from './components/ConnectPanel';
import { ScanTab } from './components/ScanTab';
import { MigrateTab } from './components/MigrateTab';
import { VerifyTlsTab } from './components/VerifyTlsTab';
import { BreakLabTab } from './components/BreakLabTab';
import { BreakLabGridTab } from './components/BreakLabGridTab';
import { JobsTab } from './components/JobsTab';
import { ReceiptTab } from './components/ReceiptTab';
import { BillingTab } from './components/BillingTab';
import './billing.css';

const STORAGE_BASE_URL = 'pqcf.baseUrl';
const STORAGE_API_KEY = 'pqcf.apiKey';

const TABS = [
  { id: 'scan', label: 'Scan' },
  { id: 'migrate', label: 'Migrate' },
  { id: 'verify', label: 'Verify TLS' },
  { id: 'breaklab', label: 'BreakLab' },
  { id: 'grid', label: 'BreakLab Grid' },
  { id: 'jobs', label: 'Jobs' },
  { id: 'receipt', label: 'Verify Receipt' },
  { id: 'billing', label: 'Billing' }
] as const;

type TabId = typeof TABS[number]['id'];

function readStorage(key: string): string {
  try { return localStorage.getItem(key) ?? ''; } catch { return ''; }
}

function tabFromUrl(): TabId {
  const params = new URLSearchParams(window.location.search);
  const tab = params.get('tab');
  if (TABS.some((entry) => entry.id === tab)) return tab as TabId;
  return 'scan';
}

export default function App() {
  const [client, setClient] = useState<PqcForgeClient | null>(null);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [tab, setTab] = useState<TabId>(tabFromUrl);
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
    if (new URLSearchParams(window.location.search).get('tab') === 'billing') setTab('billing');
  }

  function handleDisconnect() {
    try {
      localStorage.removeItem(STORAGE_API_KEY);
    } catch { /* ignore */ }
    setClient(null);
    setHealth(null);
  }

  function selectTab(id: TabId) {
    setTab(id);
    const params = new URLSearchParams(window.location.search);
    if (id === 'scan') params.delete('tab');
    else params.set('tab', id);
    const next = `${window.location.pathname}${params.toString() ? `?${params}` : ''}`;
    window.history.replaceState({}, '', next);
  }

  if (!client) {
    return (
      <div className="app">
        <LatticeBackground />
        <AppHeader health={null} onDisconnect={null} theme={theme} onThemeChange={setTheme} />
        <ConnectPanel initialBaseUrl={readStorage(STORAGE_BASE_URL) || window.location.origin} initialApiKey={readStorage(STORAGE_API_KEY)} onConnect={handleConnect} />
      </div>
    );
  }

  return (
    <div className="app">
      <LatticeBackground />
      <AppHeader health={health} onDisconnect={handleDisconnect} theme={theme} onThemeChange={setTheme} />
      <nav className="tabs">
        <div className="tabs-track">
          {TABS.map(({ id, label }) => (
            <button key={id} className={id === tab ? 'tab active' : 'tab'} onClick={() => selectTab(id)}>{label}</button>
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
        {tab === 'billing' && <BillingTab client={client} />}
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
        <img className="brand-mark" src="/rs-logo.svg" alt="" width="22" height="24" />
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
