import { useState } from 'react';
import type { PqcForgeClient } from '../api';
import { useJobRunner } from '../useJobRunner';
import { DEMO_SCENARIO } from '../fixtures';
import type { BreakLabRun } from '../types';
import { ErrorNote, JsonBlock, PassFailBadge, Panel, Spinner } from './common';

export function BreakLabTab({ client }: { client: PqcForgeClient | null }) {
  const [budget, setBudget] = useState(32);
  const [seed, setSeed] = useState(42);
  const [showScenario, setShowScenario] = useState(false);
  const { result, error, running, run } = useJobRunner<BreakLabRun>(client);

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
          <Panel title="Verdict">
            <div className="summary-row">
              <PassFailBadge pass={result.verdict.pass} passLabel="deployment policy PASS" failLabel="deployment policy FAIL" />
              <span>highest severity {result.verdict.highestSeverity}</span>
              <span>winner: <strong className="mono">{result.winner}</strong></span>
            </div>
            <p className="muted">Failure modes: {result.verdict.failureModes.join(', ') || 'none'}</p>
          </Panel>

          <Panel title="Strategy comparison (fair, equal budget)">
            <table>
              <thead>
                <tr><th>Strategy</th><th>Evaluations</th><th>State coverage</th><th>Failing</th><th>Max severity</th><th>Failure modes</th><th>Runtime</th></tr>
              </thead>
              <tbody>
                {result.strategies.map((strategy) => (
                  <tr key={strategy.strategy} className={strategy.strategy === result.winner ? 'winner-row' : undefined}>
                    <td className="mono">{strategy.strategy}{strategy.strategy === result.winner ? ' ★' : ''}</td>
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
          </Panel>

          <Panel title="Minimal counterexamples">
            {result.counterexamples.length === 0 ? <p className="muted">No failures found at this budget.</p> : (
              <div className="diff-list">
                {result.counterexamples.map((example) => (
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
