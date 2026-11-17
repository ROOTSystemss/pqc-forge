import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

// AD-072 (knock-out 2026-11-17): plain-English help under every field of the PQC Forge dashboard (web/src).
// Every visible <input>, <textarea> and <select> in the React sources has aria-describedby={hintId('<key>')}, the key
// has text in web/src/fieldHints.json, the same file renders <FieldHint k="<key>" />, no key is unused, the text is
// short plain text, and it never uses never-say words ("quantum-safe", "quantum-proof", "certified", "compliant"...).
const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const src = path.join(root, 'web', 'src');
const HINTS = JSON.parse(readFileSync(path.join(src, 'fieldHints.json'), 'utf8'));
const keys = Object.keys(HINTS).filter((k) => !k.startsWith('_'));
const NEVER = /\b(certified|compliant|guarantee[sd]?|quantum[- ]safe|quantum[- ]proof|unhackable|military[- ]grade)\b/i;

function files(dir) {
  return readdirSync(dir).flatMap((f) => { const p = path.join(dir, f); return statSync(p).isDirectory() ? files(p) : /\.tsx$/.test(f) ? [p] : []; });
}
function openingTags(s) { // JSX-aware: skips {...} expressions and quoted strings
  const out = []; const re = /<(input|textarea|select)\b/g; let m;
  while ((m = re.exec(s))) {
    let depth = 0, q = null, j = m.index + 1;
    for (; j < s.length; j++) {
      const c = s[j];
      if (q) { if (c === q && s[j - 1] !== '\\') q = null; continue; }
      if (c === '"' || c === "'" || c === '`') { q = c; continue; }
      if (c === '{') depth++; else if (c === '}') depth--; else if (depth === 0 && c === '>') break;
    }
    out.push(s.slice(m.index, j + 1));
  }
  return out;
}

test('every visible dashboard field has plain-English help linked with aria-describedby', () => {
  const used = new Set(); const problems = []; let fields = 0;
  for (const f of files(src)) {
    const s = readFileSync(f, 'utf8');
    for (const t of openingTags(s)) {
      if (/type="(hidden|submit|button|reset|image)"/.test(t)) continue;
      fields++;
      const k = (t.match(/aria-describedby=\{hintId\('([^']+)'\)\}/) || [])[1];
      if (!k) { problems.push(path.basename(f) + ': no hint on ' + t.slice(0, 70)); continue; }
      used.add(k);
      if (!HINTS[k]) problems.push(path.basename(f) + ': no hint text for ' + k);
      if (!s.includes(`<FieldHint k="${k}" />`)) problems.push(path.basename(f) + ': FieldHint ' + k + ' not rendered');
    }
  }
  assert.ok(fields >= 22, 'found ' + fields + ' fields');
  assert.deepEqual(problems, []);
  assert.deepEqual(keys.filter((k) => !used.has(k)), [], 'no hint text without a field');
});

test('hint text is short, plain, has no never-say words, and ids match the component', () => {
  for (const k of keys) {
    const h = HINTS[k];
    assert.ok(h.hint && h.hint.length <= 220, k + ' hint length');
    assert.ok(!/[<>]/.test(h.hint + (h.example || '')), k + ' plain text');
    assert.ok(!NEVER.test(h.hint + ' ' + (h.example || '')), k + ' never-say word');
  }
  const comp = readFileSync(path.join(src, 'components', 'FieldHint.tsx'), 'utf8');
  assert.match(comp, /'hint-' \+ key\.replace\(\/\[\^A-Za-z0-9\]\+\/g, '-'\)/, 'hintId rule');
  assert.match(comp, /id=\{hintId\(k\)\}/, 'the help element carries the id the field points at');
});

test('the readiness report form sends dataLifetimeYears (0-100) with its help', () => {
  const s = readFileSync(path.join(src, 'components', 'ReportTab.tsx'), 'utf8');
  assert.match(s, /dataLifetimeYears \}\);/);
  assert.match(s, /min=\{0\} max=\{100\}/);
  assert.ok(HINTS['ReportTab.dataLifetimeYears'].hint.includes('signatures are not affected'));
});
