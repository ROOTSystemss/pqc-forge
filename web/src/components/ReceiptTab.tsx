import { useState } from 'react';
import type { PqcForgeClient } from '../api';
import { ApiError } from '../api';
import type { ReceiptVerification } from '../types';
import { ErrorNote, PassFailBadge, Panel } from './common';

const PLACEHOLDER = `Paste a PQC Forge receipt JSON here — the signed output of scan, migrate,
verify, breaklab, runtime-probe, staging-gate, or any other command that
emits a tamper-evident receipt.`;

export function ReceiptTab({ client }: { client: PqcForgeClient | null }) {
  const [raw, setRaw] = useState('');
  const [verification, setVerification] = useState<ReceiptVerification | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function handleVerify() {
    if (!client) return;
    setError(null);
    setVerification(null);
    let receipt: unknown;
    try {
      receipt = JSON.parse(raw);
    } catch {
      setError('That is not valid JSON.');
      return;
    }
    setBusy(true);
    try {
      setVerification(await client.verifyReceipt(receipt));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="tab-grid single">
      <Panel title="Verify a receipt">
        <textarea
          rows={16} value={raw} onChange={(event) => setRaw(event.target.value)}
          placeholder={PLACEHOLDER} spellCheck={false}
        />
        <div className="run-row">
          <button className="primary" onClick={handleVerify} disabled={!client || busy || !raw.trim()}>Verify</button>
        </div>
        <ErrorNote message={error} />
      </Panel>

      {verification && (
        <Panel title="Result">
          <div className="summary-row">
            <PassFailBadge pass={verification.valid} passLabel="valid" failLabel="invalid" />
            {verification.keyTrusted !== null && <PassFailBadge pass={verification.keyTrusted} passLabel="signer trusted" failLabel="signer not trusted" />}
          </div>
          <table>
            <tbody>
              <tr><th>Digest matches</th><td>{verification.digestValid ? 'yes' : 'no — payload was altered after signing'}</td></tr>
              <tr><th>Signature present</th><td>{verification.signaturePresent ? 'yes' : 'no'}</td></tr>
              <tr><th>Signature valid</th><td>{verification.signatureValid ? 'yes' : 'no'}</td></tr>
              <tr><th>Signer key id</th><td className="mono">{verification.keyId ?? '—'}</td></tr>
              {verification.errors.length > 0 && <tr><th>Errors</th><td className="mono">{verification.errors.join(', ')}</td></tr>}
            </tbody>
          </table>
        </Panel>
      )}
    </div>
  );
}
