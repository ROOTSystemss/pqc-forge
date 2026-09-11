# Changelog

## Unreleased

- Added ML-DSA-65 (FIPS 204) signing to every receipt type, replacing hash-only tamper evidence with real post-quantum signatures (`src/signing.js`).
- Added CycloneDX 1.6 CBOM export (`scan --cbom`) alongside SARIF and native JSON.
- Added an Envoy adapter: classical-curve/missing-policy scanning, migration, and a BoringSSL-aware runtime probe.
- Added a multi-tenant REST API (`npm run api`, `src/api/*.js`) that runs every CLI command as an isolated, queued job behind a per-tenant API key, with per-tenant and global concurrency caps, crash reconciliation, and a `breaklab-grid` job exposing BreakLab's exhaustive client×server matrix for live rendering.
- Added `GET /v1/jobs` to list a tenant's own job history, permissive CORS headers, and same-origin static serving of a built dashboard from the API server.
- Added a web dashboard (`web/`, Vite + React + TypeScript) covering scan, migrate, live TLS verification, BreakLab, the BreakLab compatibility grid, job history, and receipt verification.

## 0.10.0

- Added agentless container execution to `runtime-probe` through direct Docker CLI arguments without a shell.
- Bound the host-side patched artifact digest to a separately declared in-container configuration path.
- Added fail-closed CLI and composite-action validation for incomplete container arguments.
- Re-ran the real five-case OpenSSL 3.5.8/Nginx 1.30.4 protocol matrix and bound its fresh receipt into a verified PR pack.

## 0.9.0

- Added tamper-evident TLS endpoint receipts and a fail-closed staging acceptance gate.
- Combined runtime, endpoint, load/soak, rollback, monitoring, canary-size, and named-operator evidence into one verifiable receipt.
- Added explicit threshold failure reasons and tamper rejection for every input receipt.
- Limited a passing staging verdict to `ready-for-authorized-canary`; production authorization remains false.
- Added composite-action staging mode and an example staging manifest.

## 0.8.0

- Added `runtime-probe` for OpenSSL version, TLS 1.3 hybrid-group availability, server build, patched-config digest, and server-native syntax checks.
- Added tamper-evident passing and BLOCKED runtime receipts plus human-readable runtime reports.
- Bound runtime evidence to exact generated after-migration digests and tracked partial/complete multi-file coverage.
- Rejected failing, unrelated, duplicate, tampered, or artifact-mismatched runtime receipts.
- Added a composite-action runtime mode for target-like self-hosted staging runners.
- Added `DEPLOYMENT_SAFETY.md` to every PR pack and made production authorization explicitly false pending staging and canary validation.

## 0.7.0

- Added Apache mod_ssl scanning for explicit classical groups and missing policies per TLS virtual host.
- Added safe replacement/insertion through `SSLOpenSSLConfCmd Groups`, including multi-vhost inheritance awareness.
- Added Apache CRLF, comment, idempotence, false-positive, receipt, and rollback coverage.
- Expanded the immutable public corpus to twelve cases with the official Apache SSL template and two public classical-curve configurations.
- Added Apache to the mixed-server release PR pack so the release gate exercises all three adapters.
- Added all-files backup preflight and exclusive backup creation before applied migrations.
- Added corpus case/filename and PR-pack artifact path-containment checks against traversal.

## 0.6.0

- Added HAProxy scanning for classical bind/server curves, legacy minimum TLS, and missing hybrid bind policy.
- Added HAProxy migration for explicit curve policies, missing policies on TLS frontends, and TLS 1.0/1.1 minimums.
- Preserved comments, indentation, LF/CRLF line endings, idempotence, backups, receipts, PR packs, and verified rollback.
- Expanded the immutable public corpus from five Nginx cases to nine Nginx/HAProxy cases with three clean controls.
- Added offline HAProxy scanner, migrator, PR-pack, false-positive, and rollback tests.

## 0.5.0

- Added a five-case, immutable public Nginx corpus with HTTPS-only downloads, size limits, and SHA-256 source verification.
- Added end-to-end patch application and byte-exact reversal in disposable Git repositories.
- Added pack verification that checks both receipt envelopes and every artifact digest/size.
- Fixed CRLF-aware patch validation and a corrupt-patch bug caused by trimming trailing blank hunk context.
- Added a complete local release gate with tests, corpus validation, BreakLab, PR pack, npm package, installed-CLI smoke test, and release receipt.
- Added Node 20/22 CI, scheduled public-corpus validation, and tag/manual release gates without automatic evidence export.

## 0.4.0

- Added the non-destructive `pr-pack` repository-to-PR workflow.
- Added virtual after-migration rescanning without changing source files.
- Added apply-ready unified patches, SARIF, PR copy, rollback guidance, and pack-level receipts.
- Added overwrite protection and end-to-end `git apply --check` verification.

## 0.3.0

- Added Docker/Compose/engine preflight diagnostics and Windows Docker Desktop discovery.
- Added SARIF 2.1.0 export with stable finding fingerprints.
- Added native JSON report output and approved-baseline delta gating.
- Added audited, expiring rule/path suppressions plus uncompromised audit mode.
- Added SHA-256 before/after artifact digests and migration receipts.
- Added receipt-controlled, digest-verified dry-run and applied rollback.
- Fixed legacy TLS matching so TLS 1.2/1.3-only configurations remain untouched.
- Reduced generic RSA/ECC keyword noise by requiring configuration or API context.
- Expanded the composite GitHub Action into scan and BreakLab modes.

## 0.2.0

- Added deterministic BreakLab search comparison, minimized counterexamples, receipts, and HTML evidence.
- Added the pinned OpenSSL 3.5.8/Nginx 1.30.4 five-case Docker protocol lab and CI workflow.
