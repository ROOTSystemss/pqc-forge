import { useState } from 'react';
import type { PqcForgeClient } from '../api';
import { useJobRunner } from '../useJobRunner';
import { DEMO_SCENARIO } from '../fixtures';
import type { BreakLabGridCell, BreakLabGridResult } from '../types';
import { ErrorNote, Panel, Spinner, Tip } from './common';

/**
 * Renders the exhaustive client×server matrix live, cell by cell, as the
 * `breaklab-grid` job resolves them — this tab is the reason that job
 * exists (see the handler's own comment in src/api/jobs.js). Polling at
 * roughly the job's own cell pace makes each cell visibly resolve rather
 * than jumping from empty to complete between polls.
 */
export function BreakLabGridTab({ client }: { client: PqcForgeClient | null }) {
  const [paceMs, setPaceMs] = useState(180);
  const { job, result, error, running, run } = useJobRunner<BreakLabGridResult>(client, 150);

  const clients = result?.dimensions.client ?? DEMO_SCENARIO.dimensions.client;
  const servers = result?.dimensions.server ?? DEMO_SCENARIO.dimensions.server;
  const cells: BreakLabGridCell[] = result?.cells ?? job?.progress?.cells ?? [];
  const total = job?.progress?.total ?? clients.length * servers.length;
  const completed = job?.progress?.completed ?? (result ? total : 0);

  // `cells` is a fresh array on every poll tick, so a memoized map would
  // recompute every time anyway — this is already the cheap path.
  const cellByKey = new Map<string, BreakLabGridCell>();
  for (const cell of cells) cellByKey.set(`${cell.client}|${cell.server}`, cell);

  return (
    <div className="tab-grid">
      <Panel title={`Compatibility matrix: ${DEMO_SCENARIO.name}`}>
        <p className="muted">
          Every client×server pair evaluated exactly once — not a search sample — for one fixed certificate, network,
          and fallback slice ({DEMO_SCENARIO.dimensions.certificate[0]}, {DEMO_SCENARIO.dimensions.network[0]},
          fallback={String(DEMO_SCENARIO.dimensions.allowClassicalFallback[0])}).
        </p>
        <div className="run-row">
          <div>
            <label>Cell pace (ms)</label>
            <input type="number" min={0} value={paceMs} onChange={(event) => setPaceMs(Number(event.target.value))} />
          </div>
          <button
            className="primary" style={{ alignSelf: 'flex-end' }}
            onClick={() => run('breaklab-grid', { scenario: DEMO_SCENARIO, paceMs })}
            disabled={!client || running}
          >
            {running ? <Spinner /> : null} Run grid
          </button>
          {(running || result) && <span className="muted" style={{ alignSelf: 'flex-end' }}>{completed} / {total} resolved</span>}
        </div>
        {(running || result) && (
          <div className="progress-bar"><div className="progress-fill" style={{ width: `${total ? (completed / total) * 100 : 0}%` }} /></div>
        )}
        <ErrorNote message={error} />
      </Panel>

      {(running || result) && (
        <Panel title="Matrix">
          <div className="grid-table-wrap">
            <table className="grid-table">
              <thead>
                <tr>
                  <th></th>
                  {clients.map((clientName) => <th key={clientName} className="mono">{clientName}</th>)}
                </tr>
              </thead>
              <tbody>
                {servers.map((serverName) => (
                  <tr key={serverName}>
                    <th className="mono">{serverName}</th>
                    {clients.map((clientName) => {
                      const cell = cellByKey.get(`${clientName}|${serverName}`);
                      const cls = !cell ? 'grid-cell pending' : cell.pass ? 'grid-cell pass' : 'grid-cell fail';
                      const tip = !cell
                        ? 'not yet evaluated'
                        : `${cell.negotiatedGroup}\n${cell.findings.map((f) => f.message).join('\n') || 'no findings'}`;
                      return (
                        <td key={clientName}>
                          <Tip text={tip}><div className={cls}>{cell ? (cell.pass ? '✓' : cell.severity) : ''}</div></Tip>
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="grid-legend">
            <span><span className="swatch pending" />not yet evaluated</span>
            <span><span className="swatch pass" />clean</span>
            <span><span className="swatch fail" />failing (number = severity)</span>
          </div>
        </Panel>
      )}
    </div>
  );
}
