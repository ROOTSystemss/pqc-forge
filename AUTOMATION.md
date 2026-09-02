# Automation and publication boundary

## One-command local release

Run from the project root:

```powershell
npm run release:check
```

The command refuses to overwrite an earlier run. It executes local tests, validates the twelve pinned public Nginx/HAProxy/Apache configurations, generates and verifies BreakLab and PR-pack receipts, builds the npm tarball, installs that tarball into a disposable directory, invokes the installed CLI, and writes a final release receipt under `release-output/release-0.10.0/`. The bundled BreakLab scenario is an intentional failure-detection fixture: the gate requires its declared failing verdict and at least six failure modes, so `BreakLab: FAIL` is an expected detector result rather than a release failure.

## Continuous automation

- `ci.yml` runs the offline release gate on Node 20 and 22 for pull requests and `main` pushes.
- `public-corpus.yml` runs the pinned public corpus weekly, manually, and whenever its engine or manifest changes.
- `real-pqc-lab.yml` runs the heavyweight OpenSSL/Nginx protocol matrix only when requested or relevant lab files change.
- `release.yml` runs the complete release gate for version tags and manual requests.
- Composite-action `runtime` mode runs capability and syntax checks on a target-like self-hosted staging runner; it exits nonzero and preserves a BLOCKED receipt when any requirement fails.
- Runtime mode can execute agentlessly inside a named staging container while binding the receipt to the exact host-side patched artifact.
- Composite-action `staging` mode verifies tamper-evident runtime and endpoint evidence plus load, rollback, monitoring, canary, and recorded named-approval controls; a pass permits only the approved canary.

## Deliberate external boundary

The project does not automatically push commits, publish to npm, create a GitHub repository, open pull requests, charge customers, or upload private repository evidence. Those operations need the owner's destination, credentials, and explicit authorization. The workflows keep generated evidence inside the runner unless an owner deliberately adds a reviewed upload or publication step, because scan reports may contain repository paths and code excerpts.

Before public launch, the owner must choose the repository and package destinations, add signing and release credentials, select a license, approve what evidence may leave customer environments, and configure checkout/legal terms. The release tarball and receipts produced here are the inputs to that controlled publication step.
