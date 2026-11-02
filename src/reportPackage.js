// E4f (live QA 2026-11-02): one command produces the whole paid report package in one folder:
//   report.json      signed readiness report (ML-DSA-65), with CBOM, statuses, deadlines, scope, cross-check
//   report.html      the same, readable
//   report.pdf       printed from report.html with a local Chrome/Edge (headless); skipped with a note if none
//   cbom.json        CycloneDX 1.6 cryptographic bill of materials
//   crosscheck.json  the independent cross-check (Semgrep on code, sslyze on hosts) and every disagreement
//   MANIFEST.txt     SHA-256 of every file, and how to verify the signature
import { createHash } from 'node:crypto';
import { promises as fs, existsSync } from 'node:fs';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { scanRepository, SCAN_COVERAGE } from './scanner.js';
import { migrateRepository } from './migrator.js';
import { verifyTls } from './verifier.js';
import { buildReadinessReport, signReport, renderReportHtml } from './readinessReport.js';
import { crossCheck as runCrossCheck } from './crossCheck.js';

const BROWSERS = [
  process.env.PQC_FORGE_BROWSER,
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
  '/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
].filter(Boolean);

function printPdf(browser, htmlFile, pdfFile) {
  return new Promise((resolve) => {
    const child = spawn(browser, ['--headless=new', '--disable-gpu', '--no-sandbox', '--no-pdf-header-footer', `--print-to-pdf=${pdfFile}`, pathToFileURL(htmlFile).href], { windowsHide: true });
    const timer = setTimeout(() => { child.kill(); resolve(false); }, 120_000);
    child.on('error', () => { clearTimeout(timer); resolve(false); });
    child.on('close', () => { clearTimeout(timer); resolve(existsSync(pdfFile)); });
  });
}

export async function buildReportPackage({ repo, endpoints = [], organization, outDir, signingKey, crossCheck = true, semgrep, sslyze }) {
  if (!repo && !endpoints.length) throw new Error('Give a repository folder, at least one --endpoint, or both.');
  await fs.mkdir(outDir, { recursive: true });
  const scan = repo ? await scanRepository(repo) : null;
  const migration = repo ? await migrateRepository(repo, { write: false }) : null;
  const checked = [];
  for (const target of [...new Set(endpoints)]) {
    try { checked.push({ target, ok: true, evidence: await verifyTls(target) }); }
    catch (error) { checked.push({ target, ok: false, error: error.message }); }
  }
  const xc = crossCheck ? await runCrossCheck({ repoRoot: repo, scan, endpoints: checked, semgrep, sslyze }) : null;
  const report = buildReadinessReport({ organization, scan, migration, endpoints: checked, crossCheck: xc, coverage: SCAN_COVERAGE });
  if (scan) report.scope.root = path.basename(path.resolve(repo)); // never the full local path
  const signed = signReport(report, signingKey);

  const files = {};
  const write = async (name, text) => { const p = path.join(outDir, name); await fs.writeFile(p, text, 'utf8'); files[name] = p; };
  await write('report.json', JSON.stringify(signed, null, 2) + '\n');
  await write('report.html', renderReportHtml(signed));
  if (signed.cbom) await write('cbom.json', JSON.stringify(signed.cbom, null, 2) + '\n');
  if (xc) await write('crosscheck.json', JSON.stringify(xc, null, 2) + '\n');
  let pdfNote = 'report.pdf: not made (no Chrome or Edge found; set PQC_FORGE_BROWSER, or print report.html to PDF).';
  for (const browser of BROWSERS) {
    if (!existsSync(browser)) continue;
    const pdf = path.join(outDir, 'report.pdf');
    if (await printPdf(browser, files['report.html'], pdf)) { files['report.pdf'] = pdf; pdfNote = null; break; }
  }
  const lines = ['PQC Forge report package', 'Organization: ' + signed.organization, 'Generated: ' + signed.generatedAt, 'Receipt digest: ' + signed.receiptDigest, ''];
  for (const [name, p] of Object.entries(files)) lines.push(createHash('sha256').update(await fs.readFile(p)).digest('hex') + '  ' + name);
  if (pdfNote) lines.push('', pdfNote);
  lines.push('', 'Verify the signed report: pqc-forge verify-receipt report.json');
  await write('MANIFEST.txt', lines.join('\n') + '\n');
  return { outDir, files: Object.keys(files), receiptDigest: signed.receiptDigest, readiness: signed.readiness, crossCheck: xc && { agreed: xc.agreed, onlyCrossCheck: xc.onlyCrossCheck.length, onlyForge: xc.onlyForge.length, tools: xc.tools.map((t) => t.tool + (t.ran ? ': ran' : ': not run (' + t.reason + ')')) } };
}
