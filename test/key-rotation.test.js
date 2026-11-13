import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { createApiServer, provisionTenant } from '../src/api/server.js';
import { generateSigningKey } from '../src/signing.js';
import { createMigrationReceipt, verifyReceipt } from '../src/breaklab/receipt.js';
import { keyHistory, KEYRING_FORMAT } from '../src/keyHistory.js';

// Signing key rotation (key survival): a receipt signed with key A still verifies after the server
// rotates to key B (A published as retired in PQC_FORGE_KEY_HISTORY_JSON), a new receipt verifies with
// B, and a one-character change to either fails - over the API, in code and with the CLI.
const projectRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const A = generateSigningKey();
const B = generateSigningKey();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const migration = (name) => ({ root: '/workspaces/' + name, filesChanged: 1, changes: [{ file: 'src/tls.js', from: 'rsa-2048', to: 'ml-dsa-65' }] });
const entry = (k, status, validFrom, validUntil) => ({ keyId: k.keyId, algorithm: 'ML-DSA-65', publicKey: k.publicKey, status, validFrom, validUntil });
// One character changed inside the signed content (the receipt stays valid JSON).
const oneChar = (r) => ({ ...r, migration: { ...r.migration, root: r.migration.root.slice(0, -1) + (r.migration.root.endsWith('x') ? 'y' : 'x') } });

test('key rotation: old and new receipts both verify against the published history; one-character changes fail', async () => {
  const oldReceipt = createMigrationReceipt(migration('old'), A);
  await sleep(5);
  const retiredAt = new Date().toISOString();
  await sleep(5);
  const history = { format: KEYRING_FORMAT, keys: [entry(A, 'retired', A.createdAt, retiredAt), entry(B, 'active', retiredAt, null)] };

  const apiHome = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-rot-'));
  const keyFile = path.join(apiHome, 'signing-key.json');
  await fs.writeFile(keyFile, JSON.stringify(B));
  const before = process.env.PQC_FORGE_KEY_HISTORY_JSON;
  process.env.PQC_FORGE_KEY_HISTORY_JSON = JSON.stringify(history);
  const { server } = createApiServer({ apiHome, signingKeyPath: keyFile });
  await new Promise((resolve) => server.listen(0, resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const ring = await (await fetch(`${base}/.well-known/rootsystems-signing-keys.json`)).json();
    assert.equal(ring.format, KEYRING_FORMAT);
    assert.deepEqual(ring.keys.map((k) => [k.keyId, k.status, k.validUntil]), [[A.keyId, 'retired', retiredAt], [B.keyId, 'active', null]]);
    assert.ok(ring.keys.every((k) => !('secretKey' in k)), 'no secret key is ever published');
    assert.deepEqual(await (await fetch(`${base}/v1/signing-keys`)).json(), ring);

    const newReceipt = createMigrationReceipt(migration('new'), B);
    const { apiKey } = await provisionTenant(apiHome, 'Rotation Co');
    const check = async (receipt) => (await fetch(`${base}/v1/verify-receipt`, { method: 'POST', headers: { authorization: `Bearer ${apiKey}`, 'content-type': 'application/json' }, body: JSON.stringify({ receipt, trustedPublicKeys: ring.keys }) })).json();
    assert.equal((await check(oldReceipt)).valid, true, 'OLD receipt (key A, retired) verifies');
    assert.equal((await check(newReceipt)).valid, true, 'NEW receipt (key B, active) verifies');
    const oldTampered = await check(oneChar(oldReceipt));
    assert.equal(oldTampered.valid, false, 'OLD receipt with one character changed fails');
    assert.ok(oldTampered.errors.includes('digest-mismatch'));
    assert.equal((await check(oneChar(newReceipt))).valid, false, 'NEW receipt with one character changed fails');

    // Only the current key (no history) no longer accepts the old receipt: that is what rotation support fixes.
    assert.deepEqual(verifyReceipt(oldReceipt, { trustedPublicKeys: [B.publicKey] }).errors, ['signer-not-trusted']);
    // The server's own trust list (rollback) is the full history.
    assert.deepEqual(keyHistory(B).keys.map((k) => k.keyId), [A.keyId, B.keyId]);
    assert.equal(verifyReceipt(oldReceipt, { trustedPublicKeys: keyHistory(B).keys }).valid, true);

    // A retired key cannot vouch for a receipt generated after it was retired (a stolen old key is useless).
    const late = createMigrationReceipt(migration('late'), A);
    const lateResult = await check(late);
    assert.equal(lateResult.valid, false);
    assert.deepEqual(lateResult.errors, ['signed-after-key-retired']);

    // The CLI with the published history file.
    const ringFile = path.join(apiHome, 'keys.json');
    await fs.writeFile(ringFile, JSON.stringify(ring));
    const cli = async (receipt) => {
      const f = path.join(apiHome, `r-${Math.random().toString(16).slice(2)}.json`);
      await fs.writeFile(f, JSON.stringify(receipt));
      return spawnSync(process.execPath, [path.join(projectRoot, 'bin', 'pqc-forge.js'), 'verify-receipt', f, '--trusted-key', ringFile], { encoding: 'utf8', env: { ...process.env, PQC_FORGE_KEY_HISTORY_JSON: '' } });
    };
    assert.equal((await cli(oldReceipt)).status, 0, 'CLI: OLD receipt passes with the history');
    assert.equal((await cli(newReceipt)).status, 0, 'CLI: NEW receipt passes with the history');
    assert.equal((await cli(oneChar(oldReceipt))).status, 5, 'CLI: OLD receipt with one character changed fails');
    assert.equal((await cli(oneChar(newReceipt))).status, 5, 'CLI: NEW receipt with one character changed fails');
  } finally {
    await new Promise((resolve) => server.close(resolve));
    if (before === undefined) delete process.env.PQC_FORGE_KEY_HISTORY_JSON; else process.env.PQC_FORGE_KEY_HISTORY_JSON = before;
    await fs.rm(apiHome, { recursive: true, force: true });
  }
});

test('key history fails closed: a history whose active key is not the signing key is ignored', () => {
  const wrong = { format: KEYRING_FORMAT, keys: [entry(A, 'active', null, null), entry(B, 'retired', null, new Date().toISOString())] };
  assert.deepEqual(keyHistory(B, JSON.stringify(wrong)).keys.map((k) => [k.keyId, k.status]), [[B.keyId, 'active']]);
  const badId = { format: KEYRING_FORMAT, keys: [{ ...entry(A, 'retired', null, null), keyId: 'sha256:' + '0'.repeat(64) }, entry(B, 'active', null, null)] };
  assert.equal(keyHistory(B, JSON.stringify(badId)).keys.length, 1, 'a keyId that does not match its public key voids the history');
  assert.equal(keyHistory(B, 'not json').keys.length, 1);
  assert.equal(keyHistory(B, '').keys[0].keyId, B.keyId);
});
