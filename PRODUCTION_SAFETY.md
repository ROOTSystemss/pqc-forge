# Production safety contract

PQC Forge v0.11 generates migration evidence; it does not authorize unattended production deployment.

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

## REST API deployment

`bin/pqc-forge-api.js` binds `127.0.0.1` (loopback only) by default because it speaks plain HTTP and authenticates with a bearer API key in a header — anyone who can reach an unencrypted socket can read that key off the wire. Reaching it from another machine requires explicitly setting `PQC_FORGE_API_HOST`, which is then the operator's decision, not the default. Before doing that:

- Put a TLS-terminating reverse proxy in front of it. This server does not terminate TLS itself.
- Treat every job type as running with the API process's own privileges, and still run the API on a least-privilege host.

### Shared-host defaults (`src/api/hosted-safety.js`)

The API assumes its tenants are strangers to each other and to the operator:

- **`runtime-probe` and `protocol-lab` are off.** They start server binaries (`nginx -t`, `haproxy -c`, with executables the tenant names) or Docker on the API host. Set `PQC_FORGE_API_ALLOW_HOST_EXECUTION=1` only on a dedicated, target-like runner that serves one customer. Otherwise customers run them with the CLI or the GitHub Action on their own runner.
- **`verify` reaches public addresses only.** Loopback, private ranges, link-local (including `169.254.169.254` cloud metadata), carrier-grade NAT, multicast, IPv6 unique-local and NAT64 are refused. A name that resolves to any such address is refused as a whole, and the connection goes to the exact address that was checked, so the DNS answer cannot change in between. `PQC_FORGE_API_ALLOW_PRIVATE_TARGETS=1` lifts this for a single-customer, internal deployment.
- **`rollback` accepts only this server's own receipts, for the caller's own workspaces.** A migration receipt names the folder to restore. Anyone can sign a receipt with a key of their own, so the API checks that this server signed it and that its folder is inside the caller's workspaces. The CLI keeps its old behaviour (your own machine, your own receipts).

`test/hosted-safety.test.js` tries each of these through the HTTP API.
