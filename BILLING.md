# PQC Forge subscriptions

Status: **self-serve subscription path is in code** on this branch. Hosted deploy + live Dodo products are still ROOT/operator steps (see `docs` ship checklist in the RootSystems agent store / `DEPLOY.md`).

## Plans (Stage 1 — Master Plan Appendix A)

| Plan | Price | Covers |
|---|---|---|
| Community | Free | Local CLI, one **public** repository in CI, dashboard scan & BreakLab, migrate |
| Pro | **$79** / month ($790 / year) | Up to 5 private repositories, CI gate, migration PRs, evidence history, all hosted job types |
| Team | **$399** / month ($3,990 / year) | Up to 25 repositories, policy gates, shared evidence |
| Business | **$999** / month, invoiced | Up to 100 repositories, company sign-in, priority support; set with `pqc-forge plan-set` |
| Self-hosted | from **$18,000** / year, invoiced | Set by an operator with `pqc-forge plan-set` |
| Readiness report | **$2,500** once | One credit for a signed readiness report the customer generates |
| Migration Pilot | from **$7,500**, invoiced | Fixed-scope staging pilot — not self-serve checkout |

Annual billing is ten months' price (two months free). Source of truth: `src/billing/plans.js`.

**Founding offer:** first 25 customers get 40% off list for 12 months (applied at payment / by RootSystems — not a public coupon code in-app).

## How it works

- **Self-serve signup**: `POST /v1/signup` with `{ name, email? }` creates a Community tenant and returns the API key **once**. The dashboard “Create free account” flow calls this.
- **Accounts** can still be provisioned by an operator (`tenant-create`); the API key is shown once, only its hash is stored.
- **Checkout**: `POST /v1/billing/checkout` with `{ plan: "pro"|"team", interval: "month"|"year", quantity }` or `{ item: "report" }` returns the provider's checkout URL. The account id travels in the checkout metadata. `returnUrl` may be `https://…` or local `http://localhost` / `http://127.0.0.1` for demo.
- **Webhook**: `POST /v1/billing/webhook/<provider>` verifies the signature (Standard Webhooks for Dodo), ignores repeated deliveries by event id, and ignores events older than the last one applied, so a late retry cannot undo a cancellation. `on_hold` keeps access while a renewal is retried.
- **Mock billing**: set `PQC_FORGE_BILLING_PROVIDER=mock` to apply Pro/Team/report entitlements immediately at checkout (no Dodo keys). For local demos and CI.
- **Gate**: the GitHub Action's "Check PQC Forge plan" step calls `POST /v1/gate/check`. Public repositories need no key. Private repositories need a Pro or Team key. Hosted API jobs also enforce plan: Community may `scan`, `migrate`, `breaklab`, and `breaklab-grid`; paid plans unlock PR packs, verify, runtime/staging/protocol jobs.
- **Data kept**: plan, status, quantity, period end, provider reference and the SHA-256 of each repository name. Never the repository name, never card or billing details.

## Payment providers

`src/billing/providers.js` puts every provider behind one interface (`configured`, `createCheckout`, `verifyWebhook`, `normalize`). Dodo Payments is the production provider; `mock` is for local demo. Adding another provider is one adapter plus `PQC_FORGE_BILLING_PROVIDER=<name>`; plans and entitlements do not change.

Environment for Dodo:

```
DODO_PAYMENTS_API_KEY=...
DODO_PAYMENTS_WEBHOOK_KEY=whsec_...
DODO_ENVIRONMENT=test_mode | live_mode
PQC_FORGE_DODO_PRODUCTS={"pro:month":"pdt_...","pro:year":"pdt_...","team:month":"pdt_...","team:year":"pdt_...","report":"pdt_..."}
PQC_FORGE_PUBLIC_URL=https://pqc-forge.onrender.com
PQC_FORGE_BILLING_PROVIDER=dodo
```

Checkout stays off (HTTP 503 with a plain message) until products + keys are set **or** mock mode is enabled.

## Before going live (ROOT blockers)

1. **Export control.** PQC Forge is cryptographic software. Get an export-classification review before selling outside the US and EU, and block sanctioned countries at checkout (see SELL.md).
2. **Dodo product type.** Confirm with Dodo that the $2,500 self-serve report counts as a digital product, not a service. Dodo does not allow services. Create products at Stage 1 prices.
3. **Hosting.** Deploy API + built dashboard (see `DEPLOY.md` / `render.yaml`). Bind beyond loopback only behind TLS. Set `PQC_FORGE_API_HOST`, `PQC_FORGE_PUBLIC_URL`, and secrets.
4. **Founding coupon.** Configure the 40% / 12-month offer in Dodo for the first 25 customers.

## Tests

`node --test test/billing.test.js` covers catalog prices, Community limits, signup, mock checkout, job entitlement gates, signed / wrongly signed / stale webhooks, duplicate and out-of-order events, on-hold and expiry, report credits, checkout payloads, the not-configured path, manual plans and the Action step.
