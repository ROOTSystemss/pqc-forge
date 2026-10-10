import { useEffect, useState } from 'react';
import { ApiError, PqcForgeClient } from '../api';
import type { PlansResponse, SubscriptionResponse } from '../types';
import { EmptyState, ErrorNote, Panel, Spinner } from './common';

export function BillingTab({ client }: { client: PqcForgeClient }) {
  const [plans, setPlans] = useState<PlansResponse | null>(null);
  const [sub, setSub] = useState<SubscriptionResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [quantity, setQuantity] = useState(1);

  async function refresh() {
    setError(null);
    try {
      const [catalog, subscription] = await Promise.all([client.plans(), client.subscription()]);
      setPlans(catalog);
      setSub(subscription);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    }
  }

  useEffect(() => {
    void refresh();
    const params = new URLSearchParams(window.location.search);
    const checkout = params.get('checkout');
    if (checkout === 'success') {
      setNotice(params.get('mock') === '1'
        ? 'Mock checkout applied — your plan updated immediately.'
        : 'Checkout complete. If your plan has not updated yet, wait a moment for the payment webhook.');
      params.delete('checkout');
      params.delete('item');
      params.delete('quantity');
      params.delete('mock');
      const next = `${window.location.pathname}${params.toString() ? `?${params}` : ''}${window.location.hash}`;
      window.history.replaceState({}, '', next);
      const timer = setTimeout(() => { void refresh(); }, 800);
      return () => clearTimeout(timer);
    }
    if (checkout === 'cancelled' || checkout === 'cancel') {
      setNotice('Checkout cancelled — nothing was charged.');
      params.delete('checkout');
      const next = `${window.location.pathname}${params.toString() ? `?${params}` : ''}${window.location.hash}`;
      window.history.replaceState({}, '', next);
    }
  }, [client]);

  async function startCheckout(body: { plan?: string; interval?: string; quantity?: number; item?: string }) {
    const key = body.item ?? `${body.plan}:${body.interval}`;
    setBusy(key);
    setError(null);
    setNotice(null);
    try {
      const returnUrl = `${window.location.origin}${window.location.pathname}?tab=billing`;
      const { url } = await client.checkout({ ...body, returnUrl });
      window.location.assign(url);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
      setBusy(null);
    }
  }

  if (!plans && !error) {
    return (
      <div className="tab-grid single">
        <Panel title="Billing">
          <EmptyState icon="◌" message="Loading plans…" hint="Talking to the API." />
        </Panel>
      </div>
    );
  }

  const selfServe = (plans?.plans ?? []).filter((p) => p.selfServe);
  const report = plans?.oneTime?.[0];
  const slots = sub?.repoLimit == null ? 'unlimited' : `${sub.reposInUse} / ${sub.repoLimit}`;

  return (
    <div className="tab-grid">
      <Panel title="Your plan">
        {notice && <p className="billing-notice">{notice}</p>}
        <ErrorNote message={error} />
        {!sub ? (
          <EmptyState message="Could not load subscription." hint="Disconnect and reconnect, or check the API." />
        ) : (
          <>
            <div className="summary-row">
              <span className="badge pass">{sub.plan}</span>
              <span className="muted small">status: {sub.status}</span>
              {sub.interval && <span className="muted small">{sub.interval}ly</span>}
            </div>
            <p className="muted small">Repository slots in use: <strong>{slots}</strong></p>
            <p className="muted small">Readiness report credits: <strong>{sub.reportCredits}</strong></p>
            {sub.currentPeriodEnd && (
              <p className="muted small">Current period ends {new Date(sub.currentPeriodEnd).toLocaleDateString()}</p>
            )}
            <ul className="connect-features">
              {sub.features.map((feature) => <li key={feature}>{feature}</li>)}
            </ul>
            <button className="ghost" type="button" onClick={() => void refresh()}>Refresh status</button>
          </>
        )}
      </Panel>

      <Panel title="Upgrade">
        {!plans?.checkoutAvailable && (
          <EmptyState
            icon="◇"
            message="Self-serve checkout is not configured on this host."
            hint="Set Dodo product IDs and keys, or PQC_FORGE_BILLING_PROVIDER=mock for a local demo."
          />
        )}
        {plans?.checkoutAvailable && (
          <>
            {plans.billingProvider === 'mock' && (
              <p className="billing-notice">Mock billing is on — upgrades apply immediately without a real card charge.</p>
            )}
            {plans.foundingOffer && (
              <p className="muted small">{plans.foundingOffer.note}</p>
            )}
            {selfServe.some((plan) => plan.perRepo) && <div>
              <label htmlFor="pro-qty">Pro repositories</label>
              <input
                id="pro-qty"
                type="number"
                min={1}
                max={500}
                value={quantity}
                onChange={(event) => setQuantity(Math.min(500, Math.max(1, Number(event.target.value) || 1)))}
              />
            </div>}
            <div className="billing-plan-grid">
              {selfServe.map((plan) => (
                <div key={plan.id} className="billing-plan-card">
                  <h3>{plan.name}</h3>
                  <p className="billing-price">
                    ${plan.priceUsdMonthly}
                    <span className="muted small">{plan.perRepo ? ' / repo / mo' : ' / mo'}</span>
                  </p>
                  <p className="muted small">${plan.priceUsdYearly}{plan.perRepo ? ' / repo / yr' : ' / yr'} (annual)</p>
                  <div className="run-row">
                    <button
                      className="primary"
                      type="button"
                      disabled={Boolean(busy)}
                      onClick={() => void startCheckout({ plan: plan.id, interval: 'month', quantity: plan.perRepo ? quantity : 1 })}
                    >
                      {busy === `${plan.id}:month` ? <><Spinner /> Working…</> : 'Monthly'}
                    </button>
                    <button
                      className="ghost"
                      type="button"
                      disabled={Boolean(busy)}
                      onClick={() => void startCheckout({ plan: plan.id, interval: 'year', quantity: plan.perRepo ? quantity : 1 })}
                    >
                      {busy === `${plan.id}:year` ? <><Spinner /> Working…</> : 'Annual'}
                    </button>
                  </div>
                </div>
              ))}
            </div>
            {report && (
              <div className="billing-plan-card">
                <h3>{report.name}</h3>
                <p className="billing-price">${report.priceUsdOnce}<span className="muted small"> once</span></p>
                <button className="primary" type="button" disabled={Boolean(busy)} onClick={() => void startCheckout({ item: 'report' })}>
                  {busy === 'report' ? <><Spinner /> Working…</> : 'Buy report credit'}
                </button>
              </div>
            )}
            <p className="muted small">Business ($1,499/mo) and Self-hosted (from $18,000/yr) are invoiced — contact RootSystems.</p>
          </>
        )}
      </Panel>
    </div>
  );
}
