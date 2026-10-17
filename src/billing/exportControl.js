// Export-control screen for self-serve sales. PQC Forge is cryptographic software (see SELL.md), so
// checkout refuses buyers in comprehensively sanctioned countries, and the webhook checks the billing
// country the payment provider reports, so a wrong answer at checkout does not unlock a plan.
// The country is checked and discarded; it is never stored.
//
// This is a screen, not a legal review: it cannot see regions (e.g. occupied regions of Ukraine) or
// restricted parties. An operator can replace the list with PQC_FORGE_BLOCKED_COUNTRIES="CU,IR,...".

export const DEFAULT_BLOCKED_COUNTRIES = ['BY', 'CU', 'IR', 'KP', 'RU', 'SY'];

export function blockedCountries(env = process.env) {
  const raw = env.PQC_FORGE_BLOCKED_COUNTRIES;
  if (typeof raw !== 'string' || !raw.trim()) return DEFAULT_BLOCKED_COUNTRIES;
  return raw.split(',').map((code) => code.trim().toUpperCase()).filter((code) => /^[A-Z]{2}$/.test(code));
}

/** A two-letter ISO 3166-1 country code, upper-cased, or null. */
export function normalizeCountry(value) {
  const code = String(value ?? '').trim().toUpperCase();
  return /^[A-Z]{2}$/.test(code) ? code : null;
}

export function isBlockedCountry(country, env = process.env) {
  const code = normalizeCountry(country);
  return code !== null && blockedCountries(env).includes(code);
}

/** True when the event would grant access (a credit or a live subscription), not take it away. */
export function grantsAccess(normalized) {
  if (normalized.kind === 'report') return true;
  return !['cancelled', 'expired', 'failed'].includes(normalized.status);
}
