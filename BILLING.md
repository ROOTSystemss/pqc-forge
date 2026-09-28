# PQC Forge subscriptions

Status: built on branch `subscription`, **not deployed**. No live products exist yet.

## Plans

| Plan | Price | Covers |
|---|---|---|
| Community | Free | Local CLI, one **public** repository in CI, no key needed |
| Pro | $39 per repository / month ($390 / year) | Private repositories, CI gate, migration PRs, evidence history |
| Team | $249 / month ($2,490 / year) | 20 repositories, policy gates, shared evidence |
| Self-hosted | from $6,000 / year, invoiced | Set by an operator with `pqc-forge plan-set` |
| Readiness report | $499 once | One credit for a signed readiness report the customer generates |

Annual billing is ten months' price (two months free). Source of truth: `src/billing/plans.js`.

## How it works

- **Accounts** are the existing API tenants (`tenant-create`); the API key is shown once, only its hash is stored.
- **Checkout**: `POST /v1/billing/checkout` with `{ plan: "pro"|"team", interval: "month"|"year", quantity }` or `{ item: "report" }` returns the provider's checkout URL. The account id travels in the checkout metadata.
- **Webhook**: `POST /v1/billing/webhook/<provider>` verifies the signature (Standard Webhooks for Dodo), ignores repeated deliveries by event id, and ignores events older than the last one applied, so a late retry cannot undo a cancellation. `on_hold` keeps access while a renewal is retried.
- **Gate**: the GitHub Action's new "Check PQC Forge plan" step calls `POST /v1/gate/check`. Public repositories need no key. Private repositories need a Pro or Team key passed as `api_key` from a secret. A repository joins the plan the first time it runs; `POST /v1/gate/release` frees its place.
- **Data kept**: plan, status, quantity, period end, provider reference and the SHA-256 of each repository name. Never the repository name, never card or billing details.

## Payment providers

`src/billing/providers.js` puts every provider behind one interface (`configured`, `createCheckout`, `verifyWebhook`, `normalize`). Dodo Payments is the first one. Adding another provider is one adapter plus `PQC_FORGE_BILLING_PROVIDER=<name>`; plans and entitlements do not change, and existing subscribers keep working because each record remembers its provider.

Environment for Dodo:

```
DODO_PAYMENTS_API_KEY=...
DODO_PAYMENTS_WEBHOOK_KEY=whsec_...
DODO_ENVIRONMENT=test_mode | live_mode
PQC_FORGE_DODO_PRODUCTS={"pro:month":"pdt_...","pro:year":"pdt_...","team:month":"pdt_...","team:year":"pdt_...","report":"pdt_..."}
PQC_FORGE_PUBLIC_URL=https://...   # default return address after checkout
```

Checkout stays off (HTTP 503 with a plain message) until all five products and both keys are set.

## Before going live (blockers)

1. **Export control.** PQC Forge is cryptographic software. Get an export-classification review before selling outside the US and EU, and block sanctioned countries at checkout (see SELL.md).
2. **Dodo product type.** Confirm with Dodo that the $499 self-serve report counts as a digital product, not a service. Dodo does not allow services.
3. **Hosting.** The API binds to loopback by default and needs a TLS-terminating host before `api_url` can be published in the Action.

## Tests

`node --test test/billing.test.js` (15 tests) covers catalog prices, Community limits, key checks, signed / wrongly signed / stale webhooks, duplicate and out-of-order events, on-hold and expiry, report credits, checkout payloads, the not-configured path, manual plans and the Action step.
