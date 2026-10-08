# Deploy PQC Forge (hosted subscription)

Operator checklist for a public, self-serve instance (Render or equivalent).

## 1. Create the web service

- **Build:** `npm install && npm run web:build`
- **Start:** `npm run api` (or `node ./bin/pqc-forge-api.js`)
- **Node:** ≥ 20
- Suggested public URL: `https://pqc-forge.onrender.com` (match marketing CTAs)

A sample `render.yaml` is included in this repo.

## 2. Environment variables

| Variable | Required | Notes |
|---|---|---|
| `PQC_FORGE_API_HOST` | yes (hosted) | `0.0.0.0` behind Render’s TLS proxy |
| `PQC_FORGE_API_PORT` | usually set by host | Render sets `PORT` — map or read host port as needed |
| `PQC_FORGE_API_HOME` | yes | Persistent disk path for tenant data |
| `PQC_FORGE_PUBLIC_URL` | yes | `https://pqc-forge.onrender.com` — checkout return + marketing |
| `PQC_FORGE_BILLING_PROVIDER` | yes | `dodo` in production; `mock` only for demos |
| `DODO_PAYMENTS_API_KEY` | prod | From Dodo dashboard |
| `DODO_PAYMENTS_WEBHOOK_KEY` | prod | `whsec_…` |
| `DODO_ENVIRONMENT` | prod | `test_mode` then `live_mode` |
| `PQC_FORGE_DODO_PRODUCTS` | prod | JSON map of five product IDs (see BILLING.md) |
| `PQC_FORGE_SIGNING_KEY` | recommended | Persistent ML-DSA signing key path |
| `PQC_FORGE_WEB_DIST` | optional | Defaults to `web/dist` after build |

**Port note:** `bin/pqc-forge-api.js` reads `PQC_FORGE_API_PORT` (default 8787). On Render, set `PQC_FORGE_API_PORT` to `$PORT` or adjust the start command to export it.

## 3. Dodo products (Stage 1)

Create digital products (not services):

- Pro monthly / yearly — **$79** / **$790** per repo quantity
- Team monthly / yearly — **$599** / **$5,990**
- Readiness report once — **$1,500**

Webhook endpoint: `POST https://<public-host>/v1/billing/webhook/dodo`

Optional: founding coupon 40% off for 12 months (first 25 customers).

## 4. Smoke test after deploy

1. Open `/` → **Create free account** → land in dashboard on Community.
2. Run a **Scan** on the sample workspace.
3. Open **Billing** → with mock or test-mode Dodo, upgrade to Pro → confirm `GET /v1/subscription` shows `pro`.
4. Confirm private repo Action gate with a Pro key.
5. Cancel path: return URL with `?checkout=cancel` shows a clear message.

## 5. Marketing

Point rootsystems.app PQC CTAs at `PQC_FORGE_PUBLIC_URL` (signup / dashboard). Report one-time buy can use in-app Billing or `PQC_REPORT_CHECKOUT_URL` on the marketing site.
