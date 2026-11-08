// E4e (live QA 2026-11-02): an independent cross-check for the paid report. Semgrep runs a separate,
// AST-based rule set (crosscheck/semgrep-crypto.yml) over the code; sslyze checks each endpoint's accepted
// protocols and key-exchange groups. Results are compared with PQC Forge's own findings, and every
// disagreement is listed. A tool that is not installed is reported as "not run", never silently skipped.
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const RULES = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'crosscheck', 'semgrep-crypto.yml');
// Files the semgrep rule set covers, and the PQC Forge findings comparable with it (key creation in code).
const SEMGREP_LANGS = /\.(?:py|go|java|js|mjs|cjs|ts|tsx|cs)$/i;
const COMPARABLE_FORGE = (f) => f.category === 'quantum-vulnerable-algorithm' && SEMGREP_LANGS.test(f.file) && !/import|^\s*"crypto\//i.test(f.excerpt || '');
const slash = (p) => String(p).replace(/\\/g, '/');

const SKIP = new Set(['.git', 'node_modules', 'dist', 'build', 'vendor', '.venv', 'coverage', '.next']);
async function codeFiles(root, dir = root, out = []) {
  const { promises: fs } = await import('node:fs');
  let stat;
  try { stat = await fs.stat(dir); } catch { return out; }
  if (stat.isFile()) { if (SEMGREP_LANGS.test(dir)) out.push(dir); return out; }
  for (const entry of await fs.readdir(dir, { withFileTypes: true })) {
    if (entry.isDirectory() && !SKIP.has(entry.name)) await codeFiles(root, path.join(dir, entry.name), out);
    else if (entry.isFile() && SEMGREP_LANGS.test(entry.name)) out.push(path.join(dir, entry.name));
  }
  return out;
}

function run(cmd, args, { timeoutMs = 300_000, env } = {}) {
  return new Promise((resolve) => {
    let out = '', err = '';
    let child;
    try { child = spawn(cmd, args, { env: { ...process.env, ...env }, windowsHide: true }); } catch (e) { resolve({ ok: false, error: e.message }); return; }
    const timer = setTimeout(() => { child.kill(); resolve({ ok: false, error: 'timed out' }); }, timeoutMs);
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('error', (e) => { clearTimeout(timer); resolve({ ok: false, error: e.code === 'ENOENT' ? 'not installed' : e.message }); });
    child.on('close', (code) => { clearTimeout(timer); resolve({ ok: true, code, out, err }); });
  });
}

export async function semgrepCrossCheck(repoRoot, forgeFindings, { semgrep = process.env.PQC_FORGE_SEMGREP || 'semgrep' } = {}) {
  const tool = { tool: 'Semgrep (independent AST rule set: crosscheck/semgrep-crypto.yml)', ran: false };
  const version = await run(semgrep, ['--version']);
  if (!version.ok || version.code !== 0) return { tool: { ...tool, reason: version.error || 'semgrep did not start' }, onlyCrossCheck: [], onlyForge: [], agreed: 0 };
  // Files are listed explicitly (in batches, for Windows' command-line limit): on a directory, Semgrep's
  // default ignores skip folders such as test/, which PQC Forge scans, and the two would disagree for that alone.
  const root = path.resolve(repoRoot);
  const files = await codeFiles(root);
  const results = [];
  for (let i = 0; i < files.length; i += 80) {
    const result = await run(semgrep, ['--config', RULES, '--json', '--metrics=off', '--disable-version-check', '--quiet', ...files.slice(i, i + 80)]);
    try { results.push(...(JSON.parse(result.out).results || [])); } catch { return { tool: { ...tool, reason: 'semgrep output could not be read' }, onlyCrossCheck: [], onlyForge: [], agreed: 0 }; }
  }
  const parsed = { results };
  const hits = (parsed.results || []).map((r) => ({ file: slash(path.relative(root, path.resolve(r.path))), line: r.start.line, rule: r.check_id.split('.').pop(), note: r.extra && r.extra.message }));
  const forge = forgeFindings.filter(COMPARABLE_FORGE).map((f) => ({ file: slash(f.file), line: f.line, id: f.id, note: f.reason }));
  const key = (x) => x.file + ':' + x.line;
  const forgeKeys = new Set(forge.map(key)), hitKeys = new Set(hits.map(key));
  return {
    tool: { ...tool, ran: true, version: String(version.out).trim().split(/\r?\n/).pop(), findings: hits.length },
    onlyCrossCheck: hits.filter((h) => !forgeKeys.has(key(h))).map((h) => ({ where: key(h), note: 'Semgrep ' + h.rule + ': ' + h.note + '. Not flagged by PQC Forge: review by hand.' })),
    onlyForge: forge.filter((f) => !hitKeys.has(key(f))).map((f) => ({ where: key(f), note: 'PQC Forge ' + f.id + ': not matched by the cross-check rule set (it covers key creation only). Review by hand.' })),
    agreed: forge.filter((f) => hitKeys.has(key(f))).length,
  };
}

// sslyze 6 JSON: accepted protocol versions and supported groups per endpoint, compared with PQC Forge's
// live observation (which sees only the negotiated TLS 1.3 handshake).
export async function sslyzeCrossCheck(endpoints, { sslyze = process.env.PQC_FORGE_SSLYZE || 'sslyze' } = {}) {
  const tool = { tool: 'sslyze (accepted protocols and groups per host)', ran: false };
  const targets = endpoints.filter((e) => e.ok).map((e) => e.target.replace(/^https?:\/\//, '').replace(/\/.*$/, '')).map((t) => (/:\d+$/.test(t) ? t : t + ':443'));
  if (!targets.length) return { tool: { ...tool, reason: 'no reachable endpoints in this report' }, onlyCrossCheck: [], onlyForge: [], agreed: 0 };
  const result = await run(sslyze, ['--json_out=-', '--tlsv1', '--tlsv1_1', '--sslv3', '--sslv2', '--tlsv1_3', '--elliptic_curves', ...targets], { timeoutMs: 240_000 });
  if (!result.ok) return { tool: { ...tool, reason: result.error }, onlyCrossCheck: [], onlyForge: [], agreed: 0 };
  let parsed;
  try { parsed = JSON.parse(result.out.slice(result.out.indexOf('{'))); } catch { return { tool: { ...tool, reason: 'sslyze output could not be read' }, onlyCrossCheck: [], onlyForge: [], agreed: 0 }; }
  const onlyCrossCheck = [], onlyForge = [];
  let agreed = 0;
  for (const s of parsed.server_scan_results || []) {
    const where = s.server_location.hostname + ':' + s.server_location.port;
    const r = s.scan_result || {};
    const accepted = (k) => !!(r[k] && r[k].result && (r[k].result.accepted_cipher_suites || []).length);
    const legacy = [['SSL 2.0', 'ssl_2_0_cipher_suites'], ['SSL 3.0', 'ssl_3_0_cipher_suites'], ['TLS 1.0', 'tls_1_0_cipher_suites'], ['TLS 1.1', 'tls_1_1_cipher_suites']].filter(([, k]) => accepted(k)).map(([n]) => n);
    const groups = ((r.elliptic_curves && r.elliptic_curves.result && r.elliptic_curves.result.supported_curves) || []).map((c) => c.name);
    const ep = endpoints.find((e) => e.ok && where.startsWith(e.target.replace(/^https?:\/\//, '').replace(/[:/].*$/, '')));
    const forgePq = !!(ep && ep.evidence.verdict.pqKeyExchange);
    const sslyzePq = groups.some((g) => /MLKEM|KYBER/i.test(g));
    if (legacy.length) onlyCrossCheck.push({ where, note: 'sslyze: the host also accepts ' + legacy.join(', ') + '. PQC Forge only sees the negotiated TLS 1.3 handshake: treat as Deprecated/Unsafe.' });
    if (forgePq && groups.length && !sslyzePq) onlyForge.push({ where, note: 'PQC Forge saw post-quantum key exchange; sslyze did not list a hybrid group (sslyze may not know the codepoint). Confirm with OpenSSL 3.5: openssl s_client -groups X25519MLKEM768.' });
    else if (!forgePq && sslyzePq) onlyCrossCheck.push({ where, note: 'sslyze lists a post-quantum hybrid group but PQC Forge did not negotiate one. Re-check the endpoint.' });
    else agreed += 1;
  }
  return { tool: { ...tool, ran: true, findings: (parsed.server_scan_results || []).length }, onlyCrossCheck, onlyForge, agreed };
}

export async function crossCheck({ repoRoot, scan, endpoints = [], semgrep, sslyze }) {
  const code = repoRoot && scan ? await semgrepCrossCheck(repoRoot, scan.findings, { semgrep }) : null;
  const hosts = endpoints.length ? await sslyzeCrossCheck(endpoints, { sslyze }) : null;
  const parts = [code, hosts].filter(Boolean);
  return {
    method: 'Two independent tools, run on the same inputs as PQC Forge: Semgrep with a separate AST-based rule set on the code, and sslyze on each live endpoint. Anything one side finds and the other does not is listed below for a human to review; agreement is counted, not listed.',
    tools: parts.map((p) => p.tool),
    onlyCrossCheck: parts.flatMap((p) => p.onlyCrossCheck),
    onlyForge: parts.flatMap((p) => p.onlyForge),
    agreed: parts.reduce((a, p) => a + p.agreed, 0),
  };
}
