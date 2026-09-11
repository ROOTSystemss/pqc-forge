import { useState } from 'react';
import type { PqcForgeClient } from '../api';
import { useJobRunner } from '../useJobRunner';
import { DEMO_SCENARIO } from '../fixtures';
import type { BreakLabGridCell, BreakLabGridResult } from '../types';
import { ErrorNote, Panel, Spinner } from './common';
import { NetworkGrid } from './NetworkGrid';

/**
 * Renders the exhaustive client×server matrix live, cell by cell, as the
 * `breaklab-grid` job resolves them — this tab is the reason that job
 * exists (see the handler's own comment in src/api/jobs.js). Polling at
 * roughly the job's own cell pace makes each cell visibly resolve rather
 * than jumping from empty to complete between polls. Rendered as an
 * actual network diagram (NetworkGrid) rather than a table: a mesh of
 * threads settling into agreement or failure, not a spreadsheet.
 */
export function BreakLabGridTab({ client }: { client: PqcForgeClient | null }) {
  const [paceMs, setPaceMs] = useState(180);
  const { job, result, error, running, run } = useJobRunner<BreakLabGridResult>(client, 150);

  const clients = result?.dimensions.client ?? DEMO_SCENARIO.dimensions.client;
  const servers = result?.dimensions.server ?? DEMO_SCENARIO.dimensions.server;
  const cells: BreakLabGridCell[] = result?.cells ?? job?.progress?.cells ?? [];
  const total = job?.progress?.total ?? clients.length * servers.length;
  const completed = job?.progress?.completed ?? (result ? total : 0);

  return (
    <div className="tab-grid single">
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
        <Panel title="Compatibility diagram">
          <NetworkGrid clients={clients} servers={servers} cells={cells} total={total} />
        </Panel>
      )}
    </div>
  );
}
