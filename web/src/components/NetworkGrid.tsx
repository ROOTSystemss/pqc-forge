import type { BreakLabGridCell } from '../types';

const ROW_HEIGHT = 46;
const PAD_Y = 28;
const EDGE_SPAN = 340; // horizontal distance the curved edges themselves travel
const LABEL_GAP = 16; // gap between a node and the start of its label
const CHAR_WIDTH = 6.4; // approximate advance width of the mono label font at its size
const MIN_MARGIN = 90;

// Fixed pixel margins (the old approach) clip any label longer than that
// guess — a real scenario's dimension names aren't bounded in length, and
// the diagram sits inside a panel with `overflow: hidden`. Size each side
// from its own longest label instead, so the SVG's viewBox always has
// exactly enough room and nothing is ever cut off.
function measureMargin(labels: string[]) {
  const longest = labels.reduce((max, label) => Math.max(max, label.length), 0);
  return Math.max(MIN_MARGIN, longest * CHAR_WIDTH + LABEL_GAP + 14);
}

function columnY(index: number, count: number, maxCount: number) {
  const contentHeight = (maxCount - 1) * ROW_HEIGHT;
  const thisHeight = (count - 1) * ROW_HEIGHT;
  const offset = (contentHeight - thisHeight) / 2;
  return PAD_Y + offset + index * ROW_HEIGHT;
}

/**
 * The client×server compatibility matrix as an actual network diagram
 * instead of a table: two columns of nodes, one curved edge per pair,
 * drawing itself in — with a traveling pulse — the instant that pair's
 * cell resolves. A pending pair sits as a faint dashed thread until then,
 * so the whole picture reads as a mesh settling into agreement (or not)
 * rather than a spreadsheet filling in.
 *
 * SMIL (<animateMotion>/<animate>) drives the one-shot "draw in" and
 * particle travel entirely declaratively: React only decides *whether* a
 * given edge's resolved <g> exists yet (keyed by client|server), and the
 * animation plays once, automatically, the moment that node is created —
 * never replays on a later re-render of the same resolved cell.
 */
export function NetworkGrid({
  clients, servers, cells, total
}: { clients: string[]; servers: string[]; cells: BreakLabGridCell[]; total: number }) {
  const maxCount = Math.max(clients.length, servers.length);
  const height = PAD_Y * 2 + (maxCount - 1) * ROW_HEIGHT;
  const cellByKey = new Map<string, BreakLabGridCell>();
  for (const cell of cells) cellByKey.set(`${cell.client}|${cell.server}`, cell);

  const clientMargin = measureMargin(clients);
  const serverMargin = measureMargin(servers);
  const CLIENT_X = clientMargin;
  const WIDTH = clientMargin + EDGE_SPAN + serverMargin;
  const SERVER_X = WIDTH - serverMargin;
  const MID_X = WIDTH / 2;

  const clientPos = new Map(clients.map((name, i) => [name, columnY(i, clients.length, maxCount)]));
  const serverPos = new Map(servers.map((i2, i) => [i2, columnY(i, servers.length, maxCount)]));

  const resolvedCount = cells.length;

  return (
    <div className="network-grid">
      <svg viewBox={`0 0 ${WIDTH} ${height}`} className="network-svg" role="img" aria-label={`Compatibility diagram: ${resolvedCount} of ${total} pairs resolved`}>
        <defs>
          <linearGradient id="ng-pass" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stopColor="var(--pass)" stopOpacity="0.35" />
            <stop offset="100%" stopColor="var(--pass)" />
          </linearGradient>
          <linearGradient id="ng-fail" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stopColor="var(--fail)" stopOpacity="0.35" />
            <stop offset="100%" stopColor="var(--fail)" />
          </linearGradient>
        </defs>

        {/* Pending threads for every pair not yet resolved — drawn first, underneath. */}
        {clients.map((client) => servers.map((server) => {
          const key = `${client}|${server}`;
          if (cellByKey.has(key)) return null;
          const y1 = clientPos.get(client)!;
          const y2 = serverPos.get(server)!;
          return (
            <path
              key={key}
              d={`M ${CLIENT_X},${y1} C ${MID_X},${y1} ${MID_X},${y2} ${SERVER_X},${y2}`}
              className="edge pending"
            />
          );
        }))}

        {/* Resolved edges: each mounts exactly once, so its SMIL children play once. */}
        {cells.map((cell) => {
          const key = `${cell.client}|${cell.server}`;
          const y1 = clientPos.get(cell.client);
          const y2 = serverPos.get(cell.server);
          if (y1 === undefined || y2 === undefined) return null;
          const d = `M ${CLIENT_X},${y1} C ${MID_X},${y1} ${MID_X},${y2} ${SERVER_X},${y2}`;
          const pathId = `edge-${key}`.replace(/[^a-zA-Z0-9_-]/g, '_');
          return (
            <g key={key} className={`edge-group ${cell.pass ? 'pass' : 'fail'}`}>
              <title>
                {cell.client} × {cell.server}: {cell.negotiatedGroup}
                {cell.findings.length ? ` — ${cell.findings.map((f) => f.message).join(' ')}` : ' — clean'}
              </title>
              <path
                id={pathId} d={d} pathLength={1}
                className={`edge resolved ${cell.pass ? 'pass' : 'fail'}`}
                stroke={cell.pass ? 'url(#ng-pass)' : 'url(#ng-fail)'}
              >
                <animate attributeName="stroke-dashoffset" from="1" to="0" dur="0.7s" begin="0s" fill="freeze" calcMode="spline" keySplines="0.16 1 0.3 1" keyTimes="0;1" values="1;0" />
              </path>
              <circle r="4" className={`edge-particle ${cell.pass ? 'pass' : 'fail'}`}>
                <animateMotion dur="0.7s" begin="0s" fill="freeze" calcMode="spline" keySplines="0.16 1 0.3 1" keyTimes="0;1">
                  <mpath href={`#${pathId}`} />
                </animateMotion>
                <animate attributeName="opacity" values="0;1;1;0" keyTimes="0;0.05;0.75;1" dur="0.85s" begin="0s" fill="freeze" />
              </circle>
            </g>
          );
        })}

        {/* Nodes on top of every edge. */}
        {clients.map((client, i) => {
          const y = clientPos.get(client)!;
          const active = servers.some((s) => cellByKey.has(`${client}|${s}`));
          return (
            <g key={client} className={active ? 'node active' : 'node'} style={{ animationDelay: `${i * 40}ms` }}>
              <circle cx={CLIENT_X} cy={y} r={7} className="node-dot" />
              <text x={CLIENT_X - LABEL_GAP} y={y} textAnchor="end" dominantBaseline="middle" className="node-label">{client}</text>
            </g>
          );
        })}
        {servers.map((server, i) => {
          const y = serverPos.get(server)!;
          const active = clients.some((c) => cellByKey.has(`${c}|${server}`));
          return (
            <g key={server} className={active ? 'node active' : 'node'} style={{ animationDelay: `${i * 40}ms` }}>
              <circle cx={SERVER_X} cy={y} r={7} className="node-dot" />
              <text x={SERVER_X + LABEL_GAP} y={y} textAnchor="start" dominantBaseline="middle" className="node-label">{server}</text>
            </g>
          );
        })}
      </svg>

      <div className="network-legend">
        <span><span className="swatch pending" />pending</span>
        <span><span className="swatch pass" />clean</span>
        <span><span className="swatch fail" />failing — hover an edge for why</span>
      </div>
    </div>
  );
}
