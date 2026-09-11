# Sellable v0.11

## Customer promise

Connect a repository and receive a tested PQC migration pull request plus minimized compatibility failures, not another assessment PDF.

## Initial buyer

Engineering and product-security teams operating public-facing Nginx, HAProxy, or Apache TLS services. The product expands to Envoy, Kubernetes ingress, Go, Java, firmware signing, and HSM-backed pipelines only after each patcher has executable tests.

## Self-service path

1. Free CLI scans public or local repositories and emits JSON or SARIF evidence with stable finding fingerprints.
2. A GitHub Action blocks newly introduced critical/high cryptographic debt against an approved baseline or a classical-only TLS result.
3. Time-limited, reason-bearing suppressions make false-positive handling auditable instead of silently excluding paths.
4. A GitHub App opens migration pull requests and attaches before/after compatibility evidence.
5. A paid self-hosted runner handles private repositories and regulated environments.

BreakLab is the differentiating feature: it searches client, server, certificate, fallback, and network combinations; reports which search strategy actually won; and produces a tamper-evident receipt with minimal counterexamples.

No sales call is required for the CLI or GitHub tiers.

## Launch pricing hypothesis

- Community: free local scans and one public repository.
- Pro: $39 per repository per month for private scans, migration pull requests, and evidence history.
- Team: $249 per month for 20 repositories, policy gates, and shared evidence.
- Self-hosted: from $6,000 per year, including offline evidence export.

These are launch prices to test through checkout conversion, not claims about willingness to pay.

## Product proof required before charging

- At least five representative repositories for every supported patcher.
- A vulnerable baseline, generated edit, clean rescan, and successful compatibility test.
- An explicit runtime compatibility check before proposing a PQC group.
- Idempotence: a second migration run must produce zero changes.
- Rollback and backup tests.
- Receipt-controlled rollback that refuses modified targets or backups.
- No custom cryptographic implementation.

## Release boundary

Version 0.11 is a validated Nginx/HAProxy/Apache/Envoy-focused beta with a target-runtime staging gate, not universal migration: it scans common textual crypto indicators, produces non-destructive migration PR packs, records observable TLS negotiation, checks patched configuration syntax in target-like runtimes, and evaluates declared compatibility profiles. The BreakLab model remains a deterministic search adapter, not a substitute for browser, HSM, device, or production-network execution.

Runtime receipts are deliberately scoped. They prove a specific configuration digest passed capability and syntax checks in the named environment; they do not claim client compatibility, load tolerance, canary success, or production readiness. Every generated PR pack remains production-blocked until those operational gates are completed.

The pinned OpenSSL 3.5.8/Nginx 1.30.4 matrix has executed successfully on this machine: all five positive and negative controls matched, including X25519MLKEM768 key exchange and mldsa65 authentication. The receipt proves the captured run has not changed; broader platform compatibility still requires separate executable adapters.

The public source corpus passes twelve of twelve pinned cases: Nginx, HAProxy, and Apache migration candidates plus three clean controls. Every candidate patch applied and reversed, every artifact digest verified, and the controls produced no invented edits. This proves all three configuration adapters against representative public files; it does not yet prove other servers, application frameworks, or production traffic.

## Before selling outside the US/EU, especially into sanctioned or export-controlled markets

This is cryptographic software: it evaluates, migrates, and signs with TLS and post-quantum primitives (ML-DSA-65 via `@noble/post-quantum`). That commonly triggers export-control classification obligations (e.g. US EAR, typically ECCN 5D002 for software with cryptographic functionality) independent of who the buyer is, and separately, several jurisdictions carry country-specific sanctions or import restrictions that block or gate sales entirely regardless of classification.

This matters concretely for a BRICS-market push: Russia and Iran carry substantial, actively-enforced US/EU/UK sanctions on this category of software; China separately restricts commercial cryptography *import* under its own domestic regime (a different problem from export control on this end). None of this is resolved by translating the product — it is a legal/compliance question that needs an actual export-control or trade-compliance review before any transaction closes with a counterparty in an affected market. Nothing in this repository constitutes that review or substitutes for it.
