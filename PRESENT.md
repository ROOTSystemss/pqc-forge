# PQC Forge demonstration

## One-line pitch

PQC Forge changes quantum-vulnerable configurations, searches for the failures created by that migration, and produces reproducible proof.

## Demonstration flow

1. Run `pqc-forge scan` on the vulnerable fixture to show exact file-and-line findings.
2. Export JSON/SARIF and rerun against the JSON baseline to show that only new high/critical debt blocks CI.
3. Open the release gate's `pr-pack/PR_DESCRIPTION.md` and `migration.patch` to show the non-destructive repository-to-PR result.
4. Verify the migration, protocol, and pack receipts, then demonstrate the apply-ready patch and reverse-patch rollback.
5. Run `npm run demo:breaklab` to search 72 compatibility states with four equal-budget strategies.
6. Open `demo-output/breaklab-report.html` to present the measured winner and six minimal counterexamples.
7. Open `protocol-output/protocol-lab-report.html` for the passing five-case real OpenSSL/Nginx matrix.
8. Run `runtime-probe` on a patched staging configuration and show the exact capability/syntax receipt bound to its SHA-256.
9. Open `release-output/release-0.10.0/RELEASE_REPORT.md` for the software release verdict, then show why `DEPLOYMENT_SAFETY.md` still blocks unattended production.

## Honest current result

The included scenario fails with severity 100. All four strategies discovered all six failure modes under a 30-evaluation budget. Pairwise search ranked first for the recorded run; the adaptive distribution search did not win. This is expected and is the product principle: benchmark strategies and use the measured winner rather than forcing a quantum label.

## What is real now

- Repository scanning and file/line evidence.
- SARIF 2.1.0, native JSON history, stable fingerprints, and approved-baseline CI gating.
- Audited path/rule suppressions with mandatory reason and automatic expiry.
- Safe supported Nginx, HAProxy, and Apache edit generation, backup, and idempotence.
- Before/after artifact digests plus receipt-controlled rollback that refuses modified files or backups.
- A non-destructive PR pack with unified patch, virtual rescan, SARIF, PR copy, rollback guidance, and bound protocol evidence.
- Deterministic compatibility profile evaluation.
- Four search strategies under a shared budget.
- Failure-mode preservation and counterexample minimization.
- SHA-256 tamper-evident receipts.
- Static HTML evidence presentation.
- CI-compatible exit codes and a two-mode scan/BreakLab composite GitHub Action.
- Automatic Docker Desktop discovery and actionable protocol-lab preflight diagnostics.
- A pinned OpenSSL 3.5.8/Nginx 1.30.4 container lab, five-case real handshake matrix, evidence parser, receipt, report, and GitHub workflow.
- A twelve-case immutable public Nginx/HAProxy/Apache corpus with source hashes, patch apply/reverse checks, three clean controls, and validation receipt.
- A one-command release gate that builds and installs the final npm tarball before issuing a release receipt.
- A target-runtime gate that refuses to equate installed OpenSSL, unrelated configuration evidence, or partial coverage with deployment readiness.

## What remains before sale

- Reproduce the passing local protocol matrix on a clean GitHub-hosted runner.
- Validate certificate and handshake byte measurements from packet captures instead of declared profiles.
- Add a GitHub App installation and pull-request writer.
- Add checkout, licensing, update signing, and self-hosted runner packaging.
