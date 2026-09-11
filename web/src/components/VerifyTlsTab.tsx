import { useEffect, useState } from 'react';
import type { PqcForgeClient } from '../api';
import { useJobRunner } from '../useJobRunner';
import type { Receipt, ReceiptVerification, TlsEvidence } from '../types';
import { ErrorNote, PassFailBadge, Panel, Spinner } from './common';

const VERDICT_LABEL: Record<string, string> = {
  'full-pq-observed': 'Full PQ observed (key exchange + authentication)',
  'pq-confidentiality-observed': 'PQ key exchange observed (classical authentication)',
  'no-pq-negotiation-observed': 'No PQ negotiation observed'
};

export function VerifyTlsTab({ client }: { client: PqcForgeClient | null }) {
  const [target, setTarget] = useState('');
  const [insecure, setInsecure] = useState(false);
  const [verification, setVerification] = useState<ReceiptVerification | null>(null);
  const { result, error, running, run } = useJobRunner<{ evidence: TlsEvidence; receipt: Receipt }>(client);

  useEffect(() => {
    setVerification(null);
    if (!client || !result) return;
    client.verifyReceipt(result.receipt).then(setVerification).catch(() => setVerification(null));
  }, [client, result]);

  return (
    <div className="tab-grid single">
      <Panel title="Endpoint">
        <label>Target (host:port or https URL)</label>
        <div className="run-row">
          <input
            type="text" value={target} onChange={(event) => setTarget(event.target.value)}
            placeholder="example.com:443"
          />
          <button className="primary" onClick={() => run('verify', { target, insecure })} disabled={!client || running || !target.trim()}>
            {running ? <Spinner /> : null} Verify
          </button>
        </div>
        <label className="checkbox-label">
          <input type="checkbox" checked={insecure} onChange={(event) => setInsecure(event.target.checked)} />
          Skip certificate verification (self-signed / staging endpoints)
        </label>
        <ErrorNote message={error} />
      </Panel>

      {result && (
        <Panel title="Observed handshake">
          <div className="summary-row">
            <span className={`badge ${result.evidence.verdict.pqKeyExchange ? 'pass' : 'fail'}`}>
              {VERDICT_LABEL[result.evidence.verdict.status] ?? result.evidence.verdict.status}
            </span>
            {verification && <PassFailBadge pass={verification.valid} passLabel="receipt verified" failLabel="receipt invalid" />}
          </div>
          <table>
            <tbody>
              <tr><th>Target</th><td className="mono">{result.evidence.target}</td></tr>
              <tr><th>Protocol</th><td className="mono">{result.evidence.protocol}</td></tr>
              <tr><th>Cipher</th><td className="mono">{result.evidence.cipher?.name ?? result.evidence.cipher?.standardName}</td></tr>
              <tr><th>Key exchange group</th><td className="mono">{result.evidence.ephemeralKey?.name ?? result.evidence.ephemeralKey?.type ?? 'unknown'}</td></tr>
              <tr><th>Certificate signature</th><td className="mono">{result.evidence.peerSignatureAlgorithm}</td></tr>
              <tr><th>Certificate trusted</th><td>{result.evidence.authorized ? 'yes' : `no — ${result.evidence.authorizationError ?? 'unauthorized'}`}</td></tr>
              <tr><th>Elapsed</th><td>{result.evidence.elapsedMs}ms</td></tr>
            </tbody>
          </table>
        </Panel>
      )}
    </div>
  );
}
