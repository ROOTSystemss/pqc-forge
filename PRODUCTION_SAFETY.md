# Production safety contract

PQC Forge v0.10 generates migration evidence; it does not authorize unattended production deployment.

## Required sequence

1. Scan the repository without writing changes.
2. Generate and review the non-destructive PR pack.
3. Apply the patch to an isolated staging copy.
4. Run `runtime-probe` for every migrated server configuration using the target server and OpenSSL build.
5. Regenerate or augment the PR pack with every passing runtime receipt and confirm coverage is complete.
6. Verify staging endpoints with PQ-capable and classical clients, including expected fallback and failure controls.
7. Measure handshake bytes, fragmentation, latency, throughput, error rates, CPU, and memory under load and soak conditions.
8. Prove patch reversal and service recovery in staging.
9. Deploy a small canary with explicit handshake-error and latency rollback thresholds.
10. Expand gradually only after an authorized operator reviews monitoring and compatibility evidence.

## What runtime-probe proves

- The invoked OpenSSL reports version 3.5 or newer.
- Its TLS 1.3 group list contains `X25519MLKEM768`.
- The selected server executable responds.
- The exact configuration digest contains the hybrid group.
- The server's native syntax command accepts that configuration in the named environment.

## What it does not prove

- That every process or container uses the same OpenSSL binary.
- That certificates, includes, secrets, network policy, or service permissions match production.
- That browsers, mobile applications, devices, SDKs, proxies, firewalls, or monitoring agents remain compatible.
- That larger handshakes meet latency, fragmentation, capacity, or availability requirements.
- That a rollout or rollback will succeed under live traffic.

Run probes only in staging or an isolated target-like container with least privilege. Nginx, HAProxy, and Apache syntax commands do not reload the service, but real configurations may read referenced files or attempt to access configured paths.
