// Post-quantum readiness report: the paid, self-serve deliverable. Built only from evidence PQC Forge
// gathered itself (a scan of the customer's code and configuration, a dry-run of the supported
// migrations, and live TLS observations of their endpoints), never from a questionnaire. Scored by fixed,
// published rules, signed with ML-DSA-65 like every other PQC Forge receipt, and rendered as one
// self-contained HTML page the customer can open, print to PDF and hand to an auditor or a customer.
import { createHash } from 'node:crypto';
import { scanToCbom } from './cbom.js';
import { signPayload } from './signing.js';
import { canonicalJson } from './canonical.js';
import { verifyReceipt } from './breaklab/receipt.js';

export const REPORT_SCHEMA = 'pqc-forge.readiness-report/v1';

// Paths in the report always use forward slashes, whatever system ran the scan.
const slash = (p) => String(p ?? '').replace(/\\/g, '/');

// Outside deadlines a reader plans against. Wording is deliberately cautious: these are the published
// positions at the time of writing; the report says to check the current text.
// E4c (2026-11-02): each deadline names its source document. Check the current text before relying on a date.
export const DEADLINES = [
  { body: 'NIST FIPS 203, 204, 205 (final, August 2024)', text: 'ML-KEM, ML-DSA and SLH-DSA are published standards: the algorithms to migrate to.', source: 'https://csrc.nist.gov/pubs/fips/203/final' },
  { body: 'NIST IR 8547 (initial public draft, November 2024)', text: 'RSA and elliptic-curve algorithms at 112-bit security deprecated after 2030 and disallowed after 2035.', source: 'https://csrc.nist.gov/pubs/ir/8547/ipd' },
  { body: 'NSA CNSA 2.0 (US national security systems)', text: 'Web servers, browsers and cloud services to support and prefer CNSA 2.0 algorithms now, and use them exclusively by 2033; the full transition by 2035.', source: 'https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF' },
  { body: 'US NSM-10 (May 2022) and OMB M-23-02 (November 2022)', text: 'US federal goal: mitigate quantum risk as much as feasible by 2035; agencies inventory quantum-vulnerable cryptography every year.', source: 'https://www.whitehouse.gov/wp-content/uploads/2022/11/M-23-02-M-Memo-on-Migrating-to-Post-Quantum-Cryptography.pdf' },
  { body: 'EU coordinated PQC roadmap (June 2025)', text: 'Member States and operators start the transition by end of 2026; high-risk use cases complete by 2030; as much as feasible by 2035.', source: 'https://digital-strategy.ec.europa.eu/en/library/coordinated-implementation-roadmap-transition-post-quantum-cryptography' },
];

// E4b: one plain status per finding and per endpoint.
export const STATUS = {
  vulnerable: 'Quantum-vulnerable', transitional: 'Transitional', deprecated: 'Deprecated (TLS 1.0-1.1)', unsafe: 'Unsafe (SSL)', safe: 'Quantum-safe',
};
const TRANSITIONAL_IDS = new Set(['QF-HAPROXY-MISSING-GROUP-POLICY', 'QF-APACHE-MISSING-GROUP-POLICY', 'QF-ENVOY-MISSING-GROUP-POLICY', 'QF-SSH-CLASSICAL-HOSTKEY']);
export function findingStatus(f) {
  if (f.id === 'QF-SSL-PROTOCOL') return STATUS.unsafe;
  if (f.category === 'protocol-baseline') return STATUS.deprecated;
  if (TRANSITIONAL_IDS.has(f.id) || /MISSING-GROUP-POLICY/.test(f.id)) return STATUS.transitional;
  return STATUS.vulnerable;
}
export function endpointStatus(e) {
  if (!e.ok) return 'Not reachable';
  if (/^SSL/i.test(e.evidence.protocol || '')) return STATUS.unsafe;
  if (/^TLSv1(\.[01])?$/i.test(e.evidence.protocol || '')) return STATUS.deprecated;
  if (e.evidence.verdict.pqKeyExchange) return e.evidence.verdict.pqAuthentication ? STATUS.safe : STATUS.safe + ' (key exchange); certificate still classical';
  return STATUS.vulnerable;
}

// Where a cryptographic inventory and migration plan is evidence.
export const MAPPINGS = [
  { framework: 'PCI DSS v4.0.1', control: '12.3.3', text: 'Cryptographic cipher suites and protocols in use are documented and reviewed at least once every 12 months, with a plan to respond to anticipated changes in cryptographic vulnerabilities.' },
  { framework: 'ISO/IEC 27001:2022', control: 'A.8.24', text: 'Rules for the effective use of cryptography, including key management, are defined and implemented.' },
  { framework: 'NIS2 Directive', control: 'Art. 21(2)(h)', text: 'Policies and procedures regarding the use of cryptography and, where appropriate, encryption.' },
  { framework: 'DORA (ICT risk-management RTS)', control: 'Encryption and cryptographic controls', text: 'Documented use of encryption and cryptographic controls, including key management, kept up to date with developments in cryptanalysis.' },
  { framework: 'US OMB M-23-02 / NSM-10', control: 'Cryptographic inventory', text: 'Inventory of quantum-vulnerable cryptography as the first step of migration planning (federal agencies; widely used as a reference).' },
];

const STAGES = [
  { id: 'urgent', label: 'Urgent: weak cryptography in use today', summary: 'Some keys are already too weak by classical standards. Fix these before any post-quantum work.' },
  { id: 'exposed', label: 'Exposed: classical cryptography only', summary: 'Quantum-vulnerable algorithms are in use and no endpoint negotiates post-quantum key exchange yet.' },
  { id: 'transition', label: 'In transition', summary: 'Some post-quantum protection is in place or ready to apply, but quantum-vulnerable cryptography remains.' },
  { id: 'ready', label: 'Ready for the deadlines', summary: 'No quantum-vulnerable findings remain in what was scanned, and the checked endpoints negotiate post-quantum key exchange.' },
];

// Fixed rules, written into the report itself (method). 100 = nothing found and every endpoint PQ-ready.
export function scoreReadiness(scan, endpoints) {
  const s = scan ? scan.summary : { critical: 0, high: 0, medium: 0, low: 0, automatable: 0, total: 0 };
  const classical = endpoints.filter((e) => e.ok && !e.evidence.verdict.pqKeyExchange).length;
  const unreachable = endpoints.filter((e) => !e.ok).length;
  const penalty = Math.min(45, s.critical * 15) + Math.min(35, s.high * 5) + Math.min(10, s.medium * 2) + Math.min(20, classical * 10) + Math.min(10, unreachable * 5);
  const score = Math.max(0, 100 - penalty);
  const pqEndpoints = endpoints.filter((e) => e.ok && e.evidence.verdict.pqKeyExchange).length;
  let stage = 'exposed';
  if (s.critical > 0) stage = 'urgent';
  else if (s.high === 0 && s.medium === 0 && (endpoints.length === 0 ? !!scan : classical === 0 && unreachable === 0)) stage = 'ready';
  else if (pqEndpoints > 0 || s.automatable > 0) stage = 'transition';
  return { score, stage: STAGES.find((x) => x.id === stage), classicalEndpoints: classical, pqEndpoints, unreachableEndpoints: unreachable };
}

// Fix-first plan: each step says what, where, and whether PQC Forge can generate the change.
export function roadmap(scan, migration, endpoints) {
  const steps = [];
  const findings = scan ? scan.findings : [];
  const by = (pred) => findings.filter(pred);
  const files = (list) => [...new Set(list.map((f) => slash(f.file)))];
  const weak = by((f) => f.id === 'QF-WEAK-RSA-SIZE');
  if (weak.length) steps.push({ priority: 'Now', title: 'Replace keys that are already too weak', detail: weak.length + ' place(s) use RSA keys of 1024 or 1536 bits. Replace them now; this does not wait for the post-quantum programme.', where: files(weak), automated: false });
  const legacy = by((f) => f.category === 'protocol-baseline');
  if (legacy.length) steps.push({ priority: 'Now', title: 'Remove TLS 1.0 and 1.1', detail: legacy.length + ' configuration line(s) still allow legacy TLS, which can never negotiate post-quantum key exchange.', where: files(legacy), automated: true });
  const kex = by((f) => f.category === 'key-establishment');
  if (kex.length || (migration && migration.changeCount)) steps.push({ priority: 'Next 3 months', title: 'Turn on hybrid post-quantum key exchange on your TLS servers', detail: (migration ? migration.changeCount : kex.length) + ' change(s) to Nginx, HAProxy, Apache or Envoy configuration add X25519MLKEM768 with classical fallbacks. PQC Forge generates these as a reviewed patch (PR pack); the servers need OpenSSL 3.5 or later.', where: files(kex), automated: true });
  const classical = endpoints.filter((e) => e.ok && !e.evidence.verdict.pqKeyExchange);
  if (classical.length) steps.push({ priority: 'Next 3 months', title: 'Make your live endpoints negotiate post-quantum key exchange', detail: classical.length + ' endpoint(s) negotiated only classical key exchange (' + [...new Set(classical.map((e) => e.evidence.ephemeralKey && (e.evidence.ephemeralKey.name || e.evidence.ephemeralKey.type) || 'unknown'))].join(', ') + '). Deploy the configuration change above, then re-check them with Verify TLS.', where: classical.map((e) => e.target), automated: false });
  const algos = by((f) => f.category === 'quantum-vulnerable-algorithm');
  if (algos.length) steps.push({ priority: 'Next 12 months', title: 'Plan the move of signatures and key exchange in your code', detail: algos.length + ' place(s) in code or configuration use RSA or elliptic-curve keys (for example JWT signing, key generation, certificate settings). Inventory each use, then move signatures to ML-DSA or SLH-DSA and key establishment to ML-KEM or a hybrid, as your libraries add support.', where: files(algos), automated: false });
  steps.push({ priority: 'Ongoing', title: 'Keep the inventory current', detail: 'Run the PQC Forge GitHub Action on every change with a baseline, so new quantum-vulnerable cryptography fails the build, and re-run this report at least once a year (PCI DSS 12.3.3 asks for a yearly review).', where: [], automated: false });
  return steps;
}

// endpoints: [{ target, ok, evidence?, error? }] from verifyTls. scan / migration may be null when only
// endpoints were checked. organization: the customer's name for the cover.
export function buildReadinessReport({ organization, scan, migration, endpoints = [], crossCheck = null, coverage = null, now = new Date() }) {
  const score = scoreReadiness(scan, endpoints);
  const s = scan ? scan.summary : null;
  const byCategory = {};
  for (const f of scan ? scan.findings : []) byCategory[f.category] = (byCategory[f.category] || 0) + 1;
  return {
    schema: REPORT_SCHEMA,
    generatedAt: new Date(now).toISOString(),
    organization: String(organization || 'Your organization').slice(0, 120),
    scope: {
      filesScanned: scan ? scan.filesScanned : 0,
      endpointsChecked: endpoints.length,
      note: 'This report covers only the files uploaded and the endpoints listed. Cryptography elsewhere (other repositories, devices, vendors, hardware security modules, managed cloud services) is not included.',
      // E4d: what the scanner reads, which languages, and what it does not cover.
      ...(coverage ? { languages: coverage.languages, configs: coverage.configs, notCovered: coverage.notCovered } : {}),
      endpoints: endpoints.map((e) => e.target),
    },
    readiness: { score: score.score, stage: score.stage.id, stageLabel: score.stage.label, stageSummary: score.stage.summary },
    summary: {
      findings: s ? s.total : 0, critical: s ? s.critical : 0, high: s ? s.high : 0, medium: s ? s.medium : 0, low: s ? s.low : 0,
      automatable: s ? s.automatable : 0, suppressed: s ? s.suppressed : 0, byCategory,
      migrationChangesReady: migration ? migration.changeCount : 0,
      endpointsPostQuantum: score.pqEndpoints, endpointsClassicalOnly: score.classicalEndpoints, endpointsUnreachable: score.unreachableEndpoints,
    },
    roadmap: roadmap(scan, migration, endpoints),
    endpoints: endpoints.map((e) => e.ok
      ? { target: e.target, status: endpointStatus(e), protocol: e.evidence.protocol, keyExchange: e.evidence.ephemeralKey && (e.evidence.ephemeralKey.name || e.evidence.ephemeralKey.type) || 'unknown', certificateSignature: e.evidence.peerSignatureAlgorithm, postQuantumKeyExchange: e.evidence.verdict.pqKeyExchange, postQuantumAuthentication: e.evidence.verdict.pqAuthentication, observedAt: e.evidence.generatedAt }
      : { target: e.target, status: endpointStatus(e), error: String(e.error || 'unreachable').slice(0, 200) }),
    findings: (scan ? scan.findings : []).slice(0, 500).map((f) => ({ id: f.id, status: findingStatus(f), ...(f.language ? { language: f.language } : {}), severity: f.severity, category: f.category, file: slash(f.file), line: f.line, excerpt: f.excerpt, reason: f.reason, remediation: f.remediation, standard: f.standard, automatable: f.automatable })),
    cbom: scan ? scanToCbom(scan) : null,
    deadlines: DEADLINES,
    mappings: MAPPINGS,
    ...(crossCheck ? { crossCheck } : {}),
    method: 'Score = 100 minus: 15 per critical finding (at most 45), 5 per high (at most 35), 2 per medium (at most 10), 10 per endpoint negotiating only classical key exchange (at most 20), 5 per endpoint that could not be reached (at most 10). Stage: Urgent when any critical finding exists; Ready when no critical, high or medium finding remains and every checked endpoint negotiates post-quantum key exchange; In transition when some post-quantum protection exists or supported changes are ready; otherwise Exposed. Findings come from static analysis of the uploaded files; endpoint results are live TLS 1.3 observations at the time shown.',
  };
}

// Same shape as every other PQC Forge receipt (receiptDigest + ML-DSA-65 signature over it), so the CLI's
// verify-receipt, POST /v1/verify-receipt and the dashboard's Verify Receipt page all check it unchanged.
export function signReport(report, signingKey) {
  const receiptDigest = `sha256:${createHash('sha256').update(canonicalJson(report)).digest('hex')}`;
  const withDigest = { ...report, receiptDigest };
  return { ...withDigest, signature: signPayload(withDigest, signingKey) };
}

export function verifyReport(doc, trustedPublicKeys = null) {
  if (!doc || doc.schema !== REPORT_SCHEMA) return { valid: false, errors: ['not a PQC Forge readiness report'] };
  return verifyReceipt(doc, { trustedPublicKeys });
}

// ---------- HTML ----------
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// E4e: the independent cross-check appendix (semgrep on code, sslyze on hosts), disagreements first.
function crossCheckHtml(c) {
  const tool = (t) => '<p><b>' + esc(t.tool) + '</b>: ' + (t.ran ? 'ran' + (t.version ? ' (' + esc(t.version) + ')' : '') + ', ' + esc(t.findings) + ' finding(s)' : '<b>not run</b>: ' + esc(t.reason)) + '</p>';
  const list = (items) => items.length ? '<table><tr><th>Where</th><th>What</th></tr>' + items.map((d) => '<tr><td><code>' + esc(d.where) + '</code></td><td>' + esc(d.note) + '</td></tr>').join('') + '</table>' : '<p class="muted">None.</p>';
  return '<h2>Appendix: independent cross-check</h2><p class="muted">' + esc(c.method) + '</p>' + c.tools.map(tool).join('')
    + '<h3>Found by the cross-check, not by PQC Forge (' + c.onlyCrossCheck.length + ')</h3>' + list(c.onlyCrossCheck)
    + '<h3>Found by PQC Forge, not by the cross-check (' + c.onlyForge.length + ')</h3>' + list(c.onlyForge)
    + '<p><b>Agreed:</b> ' + esc(c.agreed) + ' finding(s).</p>';
}

export function renderReportHtml(doc) {
  const r = doc;
  const stageColor = { urgent: '#b42318', exposed: '#c2410c', transition: '#a16207', ready: '#15803d' }[r.readiness.stage];
  const sev = (s) => '<span class="sev sev-' + esc(s) + '">' + esc(s) + '</span>';
  const rows = (list, cols) => list.map((x) => '<tr>' + cols.map((c) => '<td>' + c(x) + '</td>').join('') + '</tr>').join('');
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Post-quantum readiness report - ${esc(r.organization)}</title>
<style>
:root{--ink:#0b1f17;--muted:#4b5f56;--line:#d6e4dc;--panel:#f2f8f4;--green:#0f7a4a;--deep:#073b26}
*{box-sizing:border-box}body{margin:0;font:15px/1.55 -apple-system,"Segoe UI",Inter,Arial,sans-serif;color:var(--ink);background:#fff}
.wrap{max-width:920px;margin:0 auto;padding:40px 28px}
header{border-bottom:4px solid var(--green);padding-bottom:18px;margin-bottom:24px}
.brand{font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:var(--green);font-weight:700}
h1{font-size:30px;margin:6px 0 4px;color:var(--deep)}h2{font-size:19px;color:var(--deep);margin:34px 0 10px;border-left:4px solid var(--green);padding-left:10px}
.muted{color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px}.tile b{display:block;font-size:26px;color:var(--deep)}
.stage{border-radius:12px;padding:18px 20px;color:#fff;background:${stageColor};display:flex;gap:20px;align-items:center;flex-wrap:wrap}
.stage .score{font-size:48px;font-weight:800;line-height:1}.stage .lbl{font-size:18px;font-weight:700}
table{width:100%;border-collapse:collapse;font-size:13.5px}th,td{text-align:left;padding:8px 6px;border-bottom:1px solid var(--line);vertical-align:top}th{background:var(--panel);color:var(--deep)}
code{font:12.5px ui-monospace,Consolas,monospace;word-break:break-all}
.sev{display:inline-block;border-radius:999px;padding:1px 8px;font-size:12px;font-weight:700;color:#fff}.sev-critical{background:#b42318}.sev-high{background:#c2410c}.sev-medium{background:#a16207}.sev-low{background:#4b5f56}
.step{border:1px solid var(--line);border-left:5px solid var(--green);border-radius:8px;padding:12px 14px;margin:10px 0}.step .when{font-size:12px;font-weight:700;color:var(--green);text-transform:uppercase;letter-spacing:.06em}
.foot{margin-top:40px;font-size:12px;color:var(--muted);border-top:1px solid var(--line);padding-top:14px}
@media print{.wrap{padding:0}h2{break-after:avoid}.step,tr{break-inside:avoid}}
</style></head><body><div class="wrap">
<header><div class="brand">PQC Forge · RootSystems</div><h1>Post-quantum readiness report</h1>
<div class="muted">${esc(r.organization)} · generated ${esc(r.generatedAt.slice(0, 10))} · ${esc(r.scope.filesScanned)} files scanned · ${esc(r.scope.endpointsChecked)} endpoint(s) checked</div></header>
<div class="stage"><div class="score">${esc(r.readiness.score)}</div><div><div class="lbl">${esc(r.readiness.stageLabel)}</div><div>${esc(r.readiness.stageSummary)}</div></div></div>
<h2>At a glance</h2><div class="grid">
<div class="tile"><b>${esc(r.summary.critical)}</b>critical</div><div class="tile"><b>${esc(r.summary.high)}</b>high</div><div class="tile"><b>${esc(r.summary.medium)}</b>medium</div>
<div class="tile"><b>${esc(r.summary.migrationChangesReady)}</b>changes PQC Forge can generate</div><div class="tile"><b>${esc(r.summary.endpointsPostQuantum)}/${esc(r.scope.endpointsChecked)}</b>endpoints post-quantum</div></div>
<h2>What to do, in order</h2>${r.roadmap.map((st) => `<div class="step"><div class="when">${esc(st.priority)}${st.automated ? ' · PQC Forge can generate this' : ''}</div><b>${esc(st.title)}</b><div>${esc(st.detail)}</div>${st.where.length ? '<div class="muted" style="font-size:13px;margin-top:4px">Where: ' + st.where.slice(0, 12).map((w) => '<code>' + esc(w) + '</code>').join(', ') + (st.where.length > 12 ? ' and ' + (st.where.length - 12) + ' more' : '') + '</div>' : ''}</div>`).join('')}
<h2>Live endpoints</h2>${r.endpoints.length ? `<table><tr><th>Endpoint</th><th>Status</th><th>Key exchange</th><th>Certificate signature</th><th>Post-quantum</th></tr>${rows(r.endpoints, [(e) => '<code>' + esc(e.target) + '</code>', (e) => '<b>' + esc(e.status || '') + '</b>', (e) => e.error ? '<span class="muted">' + esc(e.error) + '</span>' : esc(e.keyExchange) + ' (' + esc(e.protocol) + ')', (e) => esc(e.certificateSignature || '-'), (e) => e.error ? 'not reached' : e.postQuantumKeyExchange ? 'yes (key exchange)' + (e.postQuantumAuthentication ? ' and signature' : '') : '<b>no</b>'])}</table>` : '<p class="muted">No endpoints were listed for this report.</p>'}
<h2>Findings (${esc(r.summary.findings)})</h2>${r.findings.length ? `<table><tr><th>Status</th><th>Severity</th><th>Where</th><th>What</th><th>Fix</th></tr>${rows(r.findings, [(f) => '<b>' + esc(f.status || '') + '</b>' + (f.language ? '<div class="muted">' + esc(f.language) + '</div>' : ''), (f) => sev(f.severity), (f) => '<code>' + esc(f.file) + ':' + esc(f.line) + '</code><div class="muted"><code>' + esc(f.excerpt) + '</code></div>', (f) => esc(f.reason) + ' <span class="muted">(' + esc(f.standard) + ')</span>', (f) => esc(f.remediation) + (f.automatable ? ' <b>PQC Forge can generate this change.</b>' : '')])}</table>` : '<p>No quantum-vulnerable cryptography was found in the scanned files.</p>'}
<h2>Deadlines to plan against</h2><table><tr><th>Source</th><th>Position</th></tr>${rows(r.deadlines, [(d) => esc(d.body) + (d.source ? '<div class="muted" style="font-size:12px"><code>' + esc(d.source) + '</code></div>' : ''), (d) => esc(d.text)])}</table><p class="muted" style="font-size:13px">Check the current text of each source; positions change as drafts are finalised.</p>
<h2>Where this report is evidence</h2><table><tr><th>Framework</th><th>Requirement</th><th>What it asks</th></tr>${rows(r.mappings, [(m) => esc(m.framework), (m) => esc(m.control), (m) => esc(m.text)])}</table>
<h2>Scope and method</h2><p>${esc(r.scope.note)}</p>${r.scope.languages ? '<p><b>Languages read:</b> ' + r.scope.languages.map(esc).join(', ') + '.<br><b>Configuration read:</b> ' + r.scope.configs.map(esc).join('; ') + '.</p><p><b>Not covered by this scan:</b></p><ul>' + r.scope.notCovered.map((x) => '<li>' + esc(x) + '</li>').join('') + '</ul>' : ''}<p class="muted">${esc(r.method)}</p><p class="muted">The full cryptographic bill of materials (CycloneDX 1.6 CBOM) is inside the signed JSON version of this report and in cbom.json.</p>
${r.crossCheck ? crossCheckHtml(r.crossCheck) : ''}
<div class="foot">Signed with ${esc(doc.signature ? doc.signature.algorithm : 'ML-DSA-65')} (FIPS 204), key <code>${esc(doc.signature ? doc.signature.keyId : '')}</code>. Anyone can check the JSON version has not been changed: <code>pqc-forge verify-receipt report.json</code> or the Verify Receipt page. PQC Forge does not implement cryptographic primitives and this report is not legal advice.</div>
</div></body></html>`;
}
