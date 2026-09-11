# PQC Forge Dashboard

A single-page dashboard for the PQC Forge REST API (`src/api/*.js`, run via
`npm run api` at the repository root). It talks to the API entirely over
`fetch` — no server-side rendering, no build-time coupling to the API beyond
its documented HTTP contract.

## Run it

From the repository root:

```powershell
node ./bin/pqc-forge.js tenant-create --name "you" --out ./pqc-forge-api-data
npm run api
```

Then, in this directory:

```powershell
npm install
npm run dev
```

Open the printed local URL, paste in the API base URL (default
`http://localhost:8787`) and the API key `tenant-create` printed, and connect.

## One-origin deployment

`npm run build` here produces `dist/`. The API server
(`bin/pqc-forge-api.js`) serves that directory automatically at `/` when it
exists, so `npm run web:build` followed by `npm run api` from the repository
root serves the whole product — API and dashboard — from one process and one
origin, with no CORS configuration needed. The API also sends permissive CORS
headers regardless, so `npm run dev` here against a separately-running API
works too.

## What it covers

- **Scan** — paste or load an example Nginx/HAProxy/Apache config, run the
  scanner, see findings by severity.
- **Migrate** — dry-run or apply the hybrid-group migration, see proposed
  before/after changes, and the signed migration receipt's verification
  result.
- **Verify TLS** — observe a live TLS 1.3 handshake against a real endpoint
  and see whether a PQ key-exchange group was negotiated.
- **BreakLab** — run the compatibility-search comparison (random, pairwise,
  annealing, adaptive) against the bundled demo scenario and see the verdict,
  strategy comparison, and minimal counterexamples.
- **BreakLab Grid** — the same scenario's full client×server matrix,
  evaluated exhaustively and rendered as an actual network diagram
  (`NetworkGrid.tsx`): a curved edge per pair that draws itself in — with a
  traveling pulse — the instant that cell resolves, colored by pass/fail,
  rather than a table filling in.
- **Jobs** — this tenant's own job history, polled from `GET /v1/jobs`.
- **Verify Receipt** — paste any PQC Forge receipt JSON and check its
  signature and digest.

Job types that need a real target-like environment (`runtime-probe`,
`staging-gate`, `protocol-lab`, `validate-corpus`) are intentionally not
wired into the UI — they assume infrastructure (a staging container, Docker,
a real self-hosted runner) a generic dashboard cannot provide safely. Drive
those from the CLI or API directly, as documented in the root `README.md`.

## A known tradeoff: the API key lives in localStorage

The Connect screen persists the tenant API key in the browser's
`localStorage` (`api.ts`) so a return visit doesn't require re-entering it.
That is a deliberate convenience tradeoff, not an oversight: it means the
key is readable by any script that runs on this origin, which is why the
dashboard pulls in no runtime dependency beyond React itself and the bundled
fonts — there is no third-party script on the page that could exfiltrate it.
It is the same tradeoff most browser-based API-key tools make (a PAT pasted
into a dev tool, a webhook secret in a form). If that tradeoff doesn't fit
your deployment, don't rely on it: proxy the dashboard behind an
authentication layer of your own instead of handing tenant keys to browsers
at all.

## Design: "Lattice"

The visual identity is built around what the product actually protects:
Module-Lattice cryptography (ML-KEM, ML-DSA). `LatticeBackground.tsx` renders
a live mesh of points and edges behind every screen — points sit on a
jittered grid connected to their fixed lattice neighbors (not a nearest-
neighbor search, which is both the more accurate picture and O(n) per frame
instead of O(n²)) — with occasional pulses traveling along a random edge.
Panels are glass over that mesh; `index.css` carries the full light/dark
token set. It reads `prefers-reduced-motion` and goes fully static, and
pauses entirely when the tab isn't visible.

---

Built with Vite + React + TypeScript.
