// Live QA 2026-11-02 E1: the scanner found nothing in Python, Go, C#, OpenSSL command lines or sshd_config.
// A per-language corpus: every vulnerable file gives the expected rule at the exact line, with a reason and
// remediation; every clean file (hashing, randomness, commented-out code, a PQ-hybrid sshd_config) gives none.
import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanRepository, SCAN_COVERAGE } from '../src/scanner.js';

const corpus = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures', 'lang-corpus');
const EXPECTED = {
  'keys.py': [['QF-PY-RSA', 1], ['QF-PY-RSA', 5], ['QF-PY-ECC', 6], ['QF-PY-ECC', 7]],
  'keys.go': [['QF-GO-ECC', 4], ['QF-GO-ECC', 5], ['QF-GO-RSA', 7], ['QF-GO-RSA', 11], ['QF-GO-ECC', 12]],
  'Keys.cs': [['QF-CS-RSA', 7], ['QF-CS-ECC', 8]],
  'make-certs.sh': [['QF-OPENSSL-CLI-RSA', 3], ['QF-OPENSSL-CLI-ECC', 4], ['QF-OPENSSL-CLI-RSA', 5]],
  'sshd_config': [['QF-SSH-CLASSICAL-HOSTKEY', 2], ['QF-SSH-CLASSICAL-HOSTKEY', 3], ['QF-SSH-CLASSICAL-KEX', 4]],
};

test('each vulnerable file gives the expected rule at the exact line, with reason and remediation', async () => {
  const result = await scanRepository(path.join(corpus, 'vulnerable'), { ignoreFile: null });
  for (const [file, expected] of Object.entries(EXPECTED)) {
    const got = result.findings.filter((f) => path.basename(f.file) === file).map((f) => [f.id, f.line]);
    for (const pair of expected) assert.ok(got.some(([id, line]) => id === pair[0] && line === pair[1]), `${file}: expected ${pair[0]} at line ${pair[1]}, got ${JSON.stringify(got)}`);
  }
  for (const f of result.findings.filter((x) => x.language)) {
    assert.ok(f.reason && f.remediation && f.standard, `${f.id} has reason, remediation and standard`);
  }
});

test('sshd_config is read at all (it was not scanned before)', async () => {
  const result = await scanRepository(path.join(corpus, 'vulnerable', 'sshd_config'), { ignoreFile: null });
  assert.ok(result.filesScanned === 1 && result.findings.length >= 3);
});

test('clean files in every language give no findings', async () => {
  const result = await scanRepository(path.join(corpus, 'clean'), { ignoreFile: null });
  assert.equal(result.filesScanned, 5);
  assert.deepEqual(result.findings.map((f) => `${f.file}:${f.line} ${f.id}`), []);
});

test('a rule for one language never fires in another language', async () => {
  const result = await scanRepository(path.join(corpus, 'vulnerable'), { ignoreFile: null });
  for (const f of result.findings) {
    if (f.id.startsWith('QF-PY-')) assert.match(f.file, /\.py$/);
    if (f.id.startsWith('QF-GO-')) assert.match(f.file, /\.go$/);
    if (f.id.startsWith('QF-CS-')) assert.match(f.file, /\.cs$/);
  }
});

test('the scope statement lists the new languages and what is not covered', () => {
  for (const lang of ['Python', 'Go', 'C#']) assert.ok(SCAN_COVERAGE.languages.includes(lang));
  assert.ok(SCAN_COVERAGE.configs.some((c) => /OpenSSH/.test(c)) && SCAN_COVERAGE.notCovered.length >= 3);
});
