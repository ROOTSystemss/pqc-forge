// PQC Forge plans. Prices follow SELL.md; annual billing is ten months' price (two free).
// A plan says what an account may do; which payment provider sold it lives in the
// subscription record, so plans never depend on a provider.

export const PLANS = {
  community: {
    id: 'community',
    name: 'Community',
    priceUsdMonthly: 0,
    repoLimit: 1,
    privateRepos: false,
    features: ['Local CLI scans', 'One public repository in CI']
  },
  pro: {
    id: 'pro',
    name: 'Pro',
    priceUsdMonthly: 39,
    perRepo: true,
    repoLimit: null, // equals the quantity bought
    privateRepos: true,
    features: ['Private repositories', 'CI gate', 'Migration pull requests', 'Evidence history']
  },
  team: {
    id: 'team',
    name: 'Team',
    priceUsdMonthly: 249,
    repoLimit: 20,
    privateRepos: true,
    features: ['20 repositories', 'Policy gates', 'Shared evidence', 'Everything in Pro']
  },
  selfhosted: {
    id: 'selfhosted',
    name: 'Self-hosted',
    priceUsdYearly: 6000,
    invoiced: true,
    repoLimit: null, // set per contract
    privateRepos: true,
    features: ['Runs offline in your environment', 'Offline evidence export', 'Invoiced yearly']
  }
};

// One-time purchase: a signed readiness report the customer generates themselves.
export const REPORT = { id: 'report', name: 'Readiness report', priceUsdOnce: 499, credits: 1 };

export const INTERVALS = ['month', 'year'];
export const SELF_SERVE_PLANS = ['pro', 'team'];

export function annualPrice(planId) {
  const plan = PLANS[planId];
  if (!plan || !plan.priceUsdMonthly) return null;
  return plan.priceUsdMonthly * 10;
}

export function publicCatalog() {
  return {
    plans: Object.values(PLANS).map((p) => ({
      id: p.id,
      name: p.name,
      priceUsdMonthly: p.priceUsdMonthly ?? null,
      priceUsdYearly: p.priceUsdYearly ?? annualPrice(p.id),
      perRepo: Boolean(p.perRepo),
      repoLimit: p.repoLimit,
      privateRepos: p.privateRepos,
      invoiced: Boolean(p.invoiced),
      features: p.features
    })),
    oneTime: [{ ...REPORT }],
    annualNote: 'Annual billing is ten months’ price: two months free.'
  };
}
