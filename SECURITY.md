# Security policy

PQC Forge is a security tool. Reports about the tool's own vulnerabilities
get priority handling.

## Reporting a vulnerability

Email **saiuppu799@gmail.com** with:

- A description of the issue and its impact (e.g. patch injection, receipt
  forgery, path traversal, arbitrary command execution via `runtime-probe`
  or `protocol-lab` container arguments).
- Steps to reproduce, including the exact CLI invocation and a minimal
  fixture if possible.
- The version (`pqc-forge --version` / `package.json`) and OS.

Do not open a public GitHub issue for suspected vulnerabilities until a fix
is available.

## Scope

In scope:

- The `pqc-forge` CLI (`bin/`, `src/`) — scanning, migration, rollback,
  PR-pack generation, BreakLab, runtime-probe, staging-gate, validate-corpus.
- The composite GitHub Action (`action.yml`).
- The multi-tenant REST API (`bin/pqc-forge-api.js`, `src/api/`) — tenant
  isolation (one tenant reading, writing, or enumerating another tenant's
  workspaces, jobs, or results), API key handling, and any path escaping a
  tenant's own directory.
- Receipt tampering: any way to make a modified receipt, patch, or artifact
  verify as authentic.
- Signature/verification bypass in `src/signing.js` or `src/breaklab/receipt.js`.
- Command/argument injection in any code path that shells out (Docker,
  `git apply`, server syntax checks).

Out of scope:

- The target servers, TLS libraries, or OpenSSL builds PQC Forge scans or
  probes — report those to the respective upstream project.
- Findings in the bundled demo/fixture files, which are intentionally
  vulnerable for testing.

## Response targets

- Acknowledgment: within 5 business days.
- Triage and severity assessment: within 10 business days.
- Fix or mitigation timeline communicated once triaged.

## Disclosure

Coordinated disclosure is preferred. Please allow a reasonable remediation
window before any public write-up; we'll credit reporters who want credit
once a fix ships.
