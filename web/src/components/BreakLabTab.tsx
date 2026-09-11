import { useEffect, useState } from 'react';
import type { PqcForgeClient } from '../api';
import { useJobRunner } from '../useJobRunner';
import { DEMO_SCENARIO } from '../fixtures';
import type { BreakLabReceipt, ReceiptVerification } from '../types';
import { EmptyState, ErrorNote, JsonBlock, PassFailBadge, Panel, Spinner } from './common';

export function BreakLabTab({ client }: { client: PqcForgeClient | null }) {
  const [budget, setBudget] = useState(32);
  const [seed, setSeed] = useState(42);
  const [showScenario, setShowScenario] = useState(false);
  const [verification, setVerification] = useState<ReceiptVerification | null>(null);
  // The job result *is* the signed receipt — the run lives at result.run
  // (see the BreakLabReceipt type). There is no separate { run, receipt }.
  const { result, error, running, run } = useJobRunner<BreakLabReceipt>(client);

  useEffect(() => {
    setVerification(null);
    if (!client || !result) return;
    client.verifyReceipt(result).then(setVerification).catch(() => setVerification(null));
  }, [client, result]);

  return (
    <div className="tab-grid">
      <Panel
        title={`Scenario: ${DEMO_SCENARIO.name}`}
        actions={<button className="ghost" onClick={() => setShowScenario((v) => !v)}>{showScenario ? 'hide' : 'view'} raw scenario</button>}
      >
        <p className="muted">
          Compatibility search across {DEMO_SCENARIO.dimensions.client.length} clients × {DEMO_SCENARIO.dimensions.server.length} servers ×{' '}
          {DEMO_SCENARIO.dimensions.certificate.length} certificates × {DEMO_SCENARIO.dimensions.network.length} networks ×{' '}
          {DEMO_SCENARIO.dimensions.allowClassicalFallback.length} fallback policies. This scenario intentionally fails its own
          release policy so a first run has real failures to show.
        </p>
        {showScenario && <JsonBlock value={DEMO_SCENARIO} />}
        <div className="run-row">
          <div>
            <label>Budget (evaluations per strategy)</label>
            <input type="number" min={1} value={budget} onChange={(event) => setBudget(Number(event.target.value))} />
          </div>
          <div>
            <label>Seed</label>
            <input type="number" value={seed} onChange={(event) => setSeed(Number(event.target.value))} />
          </div>
          <button
            className="primary" style={{ alignSelf: 'flex-end' }}
            onClick={() => run('breaklab', { scenario: DEMO_SCENARIO, budget, seed })}
            disabled={!client || running}
          >
            {running ? <Spinner /> : null} Run BreakLab
          </button>
        </div>
        <ErrorNote message={error} />
      </Panel>

      {result && (
        <>
          <Panel title="Verdict" tone={result.run.verdict.pass ? undefined : 'critical'}>
            <div className="summary-row">
              <PassFailBadge pass={result.run.verdict.pass} passLabel="deployment policy PASS" failLabel="deployment policy FAIL" />
              <span>highest severity {result.run.verdict.highestSeverity}</span>
              <span>winner: <strong className="mono">{result.run.winner}</strong></span>
              {verification && <PassFailBadge pass={verification.valid} passLabel="receipt verified" failLabel="receipt invalid" />}
            </div>
            <p className="muted">Failure modes: {result.run.verdict.failureModes.join(', ') || 'none'}</p>
          </Panel>

          <Panel title="Strategy comparison (fair, equal budget)" wide>
            <div className="strategy-bars">
              {result.run.strategies.map((strategy) => (
                <div key={strategy.strategy} className="strategy-bar-row">
                  <span className="mono small strategy-bar-label">{strategy.strategy}{strategy.strategy === result.run.winner ? ' ★' : ''}</span>
                  <div className="strategy-bar-track">
                    <div className="strategy-bar-fill" style={{ width: `${strategy.stateCoverage * 100}%` }} />
                  </div>
                  <span className="mono small">{(strategy.stateCoverage * 100).toFixed(1)}%</span>
                </div>
              ))}
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr><th>Strategy</th><th>Evaluations</th><th>State coverage</th><th>Failing</th><th>Max severity</th><th>Failure modes</th><th>Runtime</th></tr>
                </thead>
                <tbody>
                  {result.run.strategies.map((strategy) => (
                    <tr key={strategy.strategy} className={strategy.strategy === result.run.winner ? 'winner-row' : undefined}>
                      <td className="mono">{strategy.strategy}{strategy.strategy === result.run.winner ? ' ★' : ''}</td>
                      <td>{strategy.evaluations}</td>
                      <td>{(strategy.stateCoverage * 100).toFixed(1)}%</td>
                      <td>{strategy.failingConfigurations}</td>
                      <td>{strategy.maxSeverity}</td>
                      <td className="mono">{strategy.uniqueFailureModes.join(', ') || '—'}</td>
                      <td>{strategy.runtimeMs.toFixed(1)}ms</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>

          <Panel title="Minimal counterexamples" wide>
            {result.run.counterexamples.length === 0 ? <EmptyState icon="✓" message="No failures found at this budget." /> : (
              <div className="diff-list">
                {result.run.counterexamples.map((example) => (
                  <div key={example.failureCode} className="diff-card">
                    <div className="diff-head mono">{example.failureCode} (severity {example.severity})</div>
                    <div className="mono small">
                      {Object.entries(example.candidate).map(([key, value]) => `${key}=${String(value)}`).join('  ')}
                    </div>
                    <ul className="finding-list">
                      {example.findings.map((finding, index) => <li key={index}>{finding.message}</li>)}
                    </ul>
                  </div>
                ))}
              </div>
            )}
          </Panel>
        </>
      )}
    </div>
  );
}
