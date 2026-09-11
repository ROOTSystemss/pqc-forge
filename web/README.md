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
  evaluated exhaustively and rendered live as each cell resolves.
- **Jobs** — this tenant's own job history, polled from `GET /v1/jobs`.
- **Verify Receipt** — paste any PQC Forge receipt JSON and check its
  signature and digest.

Job types that need a real target-like environment (`runtime-probe`,
`staging-gate`, `protocol-lab`, `validate-corpus`) are intentionally not
wired into the UI — they assume infrastructure (a staging container, Docker,
a real self-hosted runner) a generic dashboard cannot provide safely. Drive
those from the CLI or API directly, as documented in the root `README.md`.

---

Built with Vite + React + TypeScript.
