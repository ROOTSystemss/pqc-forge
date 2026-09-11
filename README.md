# PQC Forge v0.10

PQC Forge is a repository-to-proof migration tool. It finds quantum-vulnerable cryptography, proposes supported changes, captures what a TLS endpoint actually negotiated, and searches migration compatibility matrices for hidden failures.

It is deliberately not another readiness dashboard. The sellable promise is:

> Give us a repository or container. Receive an actionable migration patch and reproducible before/after evidence.

## Current v0.10 scope

- Static, file-and-line discovery for RSA, ECC, legacy TLS, weak RSA sizes, and classical-only Nginx, HAProxy, Apache, and Envoy groups.
- Dry-run or applied Nginx, HAProxy, Apache mod_ssl, and Envoy migration to `X25519MLKEM768` with classical fallbacks.
- Automatic backups for written changes.
- Live TLS 1.3 evidence: negotiated protocol, cipher, key-exchange group, certificate signature algorithm, and runtime.
- JSON schemas suitable for CI/CD, a composite GitHub Action, and a CycloneDX 1.6 CBOM export (`scan --cbom`) for SBOM/CBOM tooling.
- BreakLab searches silent downgrade, incompatibility, PQ signature, fragmentation, and latency failures.
- Fair equal-budget comparison of random, pairwise, simulated annealing, and adaptive distribution search.
- Minimal counterexamples plus ML-DSA-65 (FIPS 204) signed, tamper-evident JSON receipts for every command that emits evidence.
- Self-contained HTML evidence report and composite GitHub Action.
- One composite GitHub Action for SARIF/baseline repository gates or BreakLab compatibility gates.
- Twelve-case, SHA-256-pinned public Nginx/HAProxy/Apache validation corpus with three clean controls.
- End-to-end release gate covering tests, public configurations, BreakLab evidence, PR-pack integrity, package creation, and installed-CLI smoke testing.
- Target-runtime probe for OpenSSL 3.5+ (or BoringSSL for Envoy), actual TLS group availability, server build discovery, hybrid config digests, and read-only syntax checks.
- Agentless container runtime probes that bind a host-side patched artifact to native checks inside a named staging container.
- Per-artifact runtime receipt coverage in PR packs; unrelated, failing, partial, or tampered evidence cannot claim complete coverage.
- Tamper-evident endpoint observations and a fail-closed staging gate for performance, soak, rollback, monitoring, canary, and named-operator controls.
- A multi-tenant REST API (`npm run api`) that runs every CLI command as an isolated, queued job behind a per-tenant API key, plus a web dashboard (`web/`) for driving scan, migrate, live TLS verification, BreakLab, and receipt verification without the command line.

The Nginx change requires a TLS runtime that supports `X25519MLKEM768`, such as OpenSSL 3.5+. PQC Forge does not implement cryptographic primitives.

## Run

```powershell
npm.cmd test
node ./bin/pqc-forge.js scan ./test/fixtures/vulnerable
node ./bin/pqc-forge.js scan ./src --report ./pqc-forge-scan.json --sarif ./pqc-forge.sarif
node ./bin/pqc-forge.js scan ./src --baseline ./approved-scan.json --json
node ./bin/pqc-forge.js scan ./src --ignore ./.pqc-forge-ignore.json
node ./bin/pqc-forge.js migrate ./test/fixtures/vulnerable
node ./bin/pqc-forge.js migrate ./your-repository --write --accept-runtime-requirement --out ./migration-output
node ./bin/pqc-forge.js rollback ./migration-output/migration-receipt.json
node ./bin/pqc-forge.js rollback ./migration-output/migration-receipt.json --write
node ./bin/pqc-forge.js pr-pack ./your-repository --out ./pqc-forge-pr --protocol-receipt ./protocol-output/protocol-lab-receipt.json
node ./bin/pqc-forge.js verify staging.example.com:443 --out ./endpoint-output --json
node ./bin/pqc-forge.js breaklab ./scenarios/tls-migration-demo.json --budget 30 --seed 42 --out ./demo-output --no-fail
node ./bin/pqc-forge.js verify-receipt ./demo-output/breaklab-receipt.json
node ./bin/pqc-forge.js doctor
node ./bin/pqc-forge.js protocol-lab --out ./protocol-output
node ./bin/pqc-forge.js runtime-probe nginx --config ./staging/nginx.conf --out ./runtime-output --target staging-us-east
node ./bin/pqc-forge.js runtime-probe nginx --config ./staging/nginx.conf --container staging-nginx --container-config /etc/nginx/nginx.conf --docker docker --out ./runtime-output
node ./bin/pqc-forge.js staging-gate ./examples/staging-manifest.json --out ./staging-gate-output
node ./bin/pqc-forge.js validate-corpus ./validation/corpus.json --out ./validation-output
npm run release:check
npm run lab:protocol:windows
```

`scan` exits with code 2 when critical cryptographic debt is found. `verify` exits with code 3 when no PQ key exchange is observed, making both commands usable as release gates. Written changes require explicit confirmation that the deployment runtime supports `X25519MLKEM768`.

`scan --report <file>` writes the native JSON evidence used for history and future baselines. `--sarif <file>` emits SARIF 2.1.0 with stable fingerprints for code-scanning ingestion. With `--baseline <scan.json>`, exit code 2 is limited to newly introduced critical/high findings; accepted existing debt is reported but does not break the build.

Place `.pqc-forge-ignore.json` at the scan root (see the included example) for audited exceptions. Each suppression requires a rule, path glob, reason, and expiry date. Expired exceptions automatically stop suppressing findings; `--no-ignore` provides an uncompromised audit scan.

`migrate --out <directory>` writes a tamper-evident migration receipt containing SHA-256 before/after digests for every changed artifact. `verify-receipt` detects any later receipt modification.

Applied migration preflights every target before changing the first file. It refuses to overwrite an existing `.pqc-forge.bak`, creates backups exclusively, and aborts if a target changed between analysis and write preparation.

`rollback` first verifies the receipt, current migrated-file digest, and backup digest. It defaults to a dry-run and refuses to overwrite files changed after migration; `--write` performs the verified restoration while retaining the backup.

`pr-pack` is the non-destructive repository-to-PR workflow. It generates before/after JSON scans, post-migration SARIF, an apply-ready unified Git patch, migration and bundle receipts, rollback guidance, and a ready-to-post pull-request description. Supply `--protocol-receipt` to verify and embed reference-lab protocol evidence; this does not prove the target server or configuration. It refuses to overwrite a non-empty output directory.

`runtime-probe` must run against an already patched configuration in an isolated target-like environment. It checks OpenSSL 3.5+, confirms `X25519MLKEM768` appears in the runtime TLS 1.3 group list, records the server build, and invokes `nginx -t`, `haproxy -c`, or Apache `-t` without reloading the service. A failed check still produces a BLOCKED receipt and exits with code 8. Run syntax probes with least privilege because real configurations may reference certificates, includes, or log paths. For container targets, add `--container` and `--container-config`; PQC Forge hashes the host-side patched file and executes direct `docker exec` arguments against the corresponding path inside the running staging container.

Repeat `--runtime-receipt <file>` when building a PR pack to cover multiple migrated files. Each receipt must pass and its configuration digest must equal a generated after-migration artifact. Partial coverage remains explicitly blocked; even complete runtime coverage does not authorize production without staging traffic and canary validation.

`verify --out <directory>` records an endpoint observation as a tamper-evident TLS receipt. `staging-gate` consumes tamper-evident runtime and endpoint receipts plus measured load/soak metrics, rollback recovery, monitoring, rollback triggers, canary size, and a recorded named-operator approval. It exits with code 9 when any check fails. A pass means only `ready-for-authorized-canary`; it never authorizes broad production deployment. Start from `examples/staging-manifest.json` and replace every example value with measurements from the isolated target-like environment. SHA-256 receipts detect changes but do not authenticate the operator's identity; connect an organizational signing service before relying on identity provenance.

`validate-corpus` downloads only HTTPS sources pinned in `validation/corpus.json`, enforces a 1 MiB limit and exact SHA-256, creates PR packs in disposable repositories, verifies every receipt and listed artifact, applies and reverses each patch, and proves clean controls are untouched. The corpus contains five Nginx, four HAProxy, and three Apache configurations.

`npm run release:check` is the start-to-end software release gate. It creates `release-output/release-0.10.0/` with test logs, corpus evidence, BreakLab evidence, a release PR pack, the npm tarball, and a final tamper-evident release receipt. A software release PASS does not mean a customer configuration is production-ready. It refuses to overwrite an existing run. Use `-- --skip-public --out <directory>` only for offline CI; tagged and manual release workflows run the public corpus.

The bundled BreakLab demo intentionally fails its deployment policy. The release gate passes that step only when the detector reproduces the declared failing verdict and at least six distinct failure modes; an unexpectedly clean result fails the release gate.

## GitHub Action

```yaml
- uses: rootsystems/pqc-forge@v0.10.0
  with:
    mode: scan
    target: .
    report: pqc-forge-output/pqc-forge-scan.json
    sarif: pqc-forge-output/pqc-forge.sarif
    baseline: security/approved-pqc-scan.json
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: pqc-forge-output/pqc-forge.sarif
- uses: actions/upload-artifact@v4
  if: always()
  with:
    name: pqc-forge-evidence
    path: pqc-forge-output/
```

The optional upload step exports scan paths and excerpts to GitHub Actions storage. Use it only after approving that evidence destination; the bundled project workflows do not upload evidence automatically.

Set `mode: breaklab` plus `scenario`, `budget`, and `seed` to run the compatibility-search gate instead. Inputs are passed through environment variables rather than interpolated into shell commands.

Set `mode: runtime`, `runtime_server`, `runtime_config`, and `output` on a target-like self-hosted runner to execute the capability and syntax gate. The runner must contain the same server and OpenSSL build intended for deployment.

For an agentless container probe, also set `runtime_container` and `runtime_container_config`. The host artifact remains the digest source while all binary and syntax commands execute inside that container.

Set `mode: staging`, `staging_manifest`, and `output` after runtime, endpoint, and load tests have produced their evidence. The action validates receipt integrity and blocks unless every operational control passes.

`breaklab` exits with code 4 when the scenario's failure threshold is reached. Use `--no-fail` for demonstrations only. The adaptive strategy is classical, quantum-inspired search; the report never labels it quantum hardware or assumes it wins.

`protocol-lab` builds pinned OpenSSL 3.5.8 and Nginx 1.30.4 containers and executes five real TLS cases. It exits with code 6 when observed results differ from the positive and negative controls. Docker Compose is required.

On Windows, `npm run lab:protocol:windows` supplies explicit Docker Desktop and Node paths and captures the full run in `protocol-lab-run.log`, which makes elevated or first-run failures diagnosable.

Run `doctor` first for an automatic Docker/Compose/engine preflight. It discovers the standard Docker Desktop CLI location on Windows even when `PATH` is stale, provides a specific corrective action, and exits with code 7 while blocked. Set `PQC_FORGE_DOCKER` to override the Docker executable.

## REST API and web dashboard

`npm run api` starts a multi-tenant HTTP server (`bin/pqc-forge-api.js`, default port `8787`) that runs every CLI command above as a queued, tenant-isolated job instead of a one-shot process. Provision a tenant first — there is no self-serve signup endpoint by design:

```powershell
node ./bin/pqc-forge.js tenant-create --name "your-name" --out ./pqc-forge-api-data
npm run api
```

The printed API key is shown once; only its SHA-256 hash is persisted. Every request authenticates with `Authorization: Bearer <api key>`, and every filesystem path a job touches is resolved underneath that tenant's own directory — there is no code path from one tenant's request to another tenant's data (`src/api/tenants.js`, `src/api/workspace.js`).

Core routes: `POST /v1/workspaces` (upload an inline file list), `POST /v1/jobs` (submit `{ type, params }` for any job type — `scan`, `migrate`, `rollback`, `pr-pack`, `verify`, `runtime-probe`, `staging-gate`, `validate-corpus`, `breaklab`, `breaklab-grid`, `protocol-lab`), `GET /v1/jobs` (list this tenant's own job history), `GET /v1/jobs/:id` (poll status and live `progress`), `GET /v1/jobs/:id/result`, and `POST /v1/verify-receipt`. `GET /v1/health` is the only unauthenticated route.

The bundled dashboard (`web/`, Vite + React + TypeScript) drives scan, migrate, live TLS verification, BreakLab, an exhaustive client×server BreakLab compatibility grid, job history, and receipt verification against that API from the browser. Build it once and the API server serves it from the same origin automatically, so there is nothing else to run and no CORS setup needed:

```powershell
npm run web:build
npm run api
```

Then open `http://localhost:8787/` and connect with the tenant API key. See `web/README.md` for running the dashboard against a separately-hosted API (`npm run web:dev`) instead.

## Product path

1. Reproduce the prepared real protocol workflow on a clean GitHub-hosted runner.
2. Add safe patchers for Go, Java, Kubernetes ingress, and common container images (Envoy is done — scan, migrate, and runtime-probe already cover it).
3. Package as a GitHub App that opens migration pull requests and attaches tamper-evident evidence.
4. Add signing, licensing, checkout, and explicit opt-in evidence upload for private repositories.

This wedge remains useful when cloud and operating-system vendors add native PQC because it verifies and changes the application configurations spanning those vendors.
