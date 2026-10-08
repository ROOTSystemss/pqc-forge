// PQC Forge plans. Stage 1 prices (Master Plan Appendix A / Phase 0 locked).
// Annual billing is ten months' price (two free).
// A plan says what an account may do; which payment provider sold it lives in the
// subscription record, so plans never depend on a provider.

export const PLANS = {
  community: {
    id: 'community',
    name: 'Community',
    priceUsdMonthly: 0,
    repoLimit: 1,
    privateRepos: false,
    features: ['Local CLI scans', 'One public repository in CI', 'Dashboard scan & BreakLab']
  },
  pro: {
    id: 'pro',
    name: 'Pro',
    priceUsdMonthly: 79,
    perRepo: true,
    repoLimit: null, // equals the quantity bought
    privateRepos: true,
    features: ['Private repositories', 'CI gate', 'Migration pull requests', 'Evidence history']
  },
  team: {
    id: 'team',
    name: 'Team',
    priceUsdMonthly: 599,
    repoLimit: 20,
    privateRepos: true,
    features: ['20 repositories', 'Policy gates', 'Shared evidence', 'Everything in Pro']
  },
  business: {
    id: 'business',
    name: 'Business',
    priceUsdMonthly: 1499,
    invoiced: true,
    repoLimit: 75,
    privateRepos: true,
    features: ['75 repositories', 'Company sign-in', 'Priority support', 'Everything in Team']
  },
  selfhosted: {
    id: 'selfhosted',
    name: 'Self-hosted',
    priceUsdYearly: 18000,
    invoiced: true,
    repoLimit: null, // set per contract
    privateRepos: true,
    features: ['Runs offline in your environment', 'Offline evidence export', 'Invoiced yearly']
  }
};

// One-time purchase: a signed readiness report the customer generates themselves.
export const REPORT = { id: 'report', name: 'Readiness report', priceUsdOnce: 1500, credits: 1 };

/** Migration pilot remains invoiced (not self-serve checkout). */
export const MIGRATION_PILOT = { id: 'migration-pilot', name: 'Migration Pilot', priceUsdFrom: 7500, invoiced: true };

/** Founding offer (Phase 0): applied at payment processor / by RootSystems — not a public coupon code. */
export const FOUNDING_OFFER = {
  discountPercent: 40,
  months: 12,
  firstCustomers: 25,
  note: 'First 25 customers: 40% off list price for 12 months. Applied at checkout by RootSystems.'
};

export const INTERVALS = ['month', 'year'];
export const SELF_SERVE_PLANS = ['pro', 'team'];

/** Job types Community may run in the hosted API (paid unlocks PR packs / verify / runtime). */
export const COMMUNITY_JOB_TYPES = ['scan', 'migrate', 'breaklab', 'breaklab-grid'];

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
      selfServe: SELF_SERVE_PLANS.includes(p.id),
      features: p.features
    })),
    oneTime: [{ ...REPORT }],
    services: [{ ...MIGRATION_PILOT }],
    foundingOffer: { ...FOUNDING_OFFER },
    annualNote: 'Annual billing is ten months’ price: two months free.',
    selfServePlans: [...SELF_SERVE_PLANS]
  };
}
