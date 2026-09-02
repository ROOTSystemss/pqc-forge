import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { createPrPack } from '../src/pr-pack.js';
import { validateCorpus, verifyPackArtifacts } from '../src/validation.js';
import { canonicalJson, verifyReceipt } from '../src/breaklab/receipt.js';

const sha = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;

test('corpus validation verifies sources, patches, reversal, control, and receipt', async () => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-validation-'));
  const vulnerable = 'server {\n  ssl_protocols TLSv1 TLSv1.2;\n  ssl_ecdh_curve X25519;\n}\n';
  const clean = 'events {}\nhttp {}\n';
  const manifest = {
    schema: 'pqc-forge.public-corpus/v1',
    cases: [
      { id: 'vulnerable', source: 'test', revision: '1', url: 'https://example.test/vulnerable', filename: 'nginx.conf', sha256: sha(vulnerable), expect: { minFindings: 2, minChanges: 2, minResolved: 2, pack: true } },
      { id: 'control', source: 'test', revision: '1', url: 'https://example.test/control', filename: 'nginx.conf', sha256: sha(clean), expect: { minFindings: 0, minChanges: 0, pack: false } }
    ]
  };
  const manifestPath = path.join(base, 'manifest.json');
  await fs.writeFile(manifestPath, JSON.stringify(manifest));
  const fetchImpl = async (url) => new Response(url.endsWith('vulnerable') ? vulnerable : clean);
  const result = await validateCorpus(manifestPath, path.join(base, 'output'), { fetchImpl });
  assert.equal(result.run.totalCases, 2);
  assert.equal(result.run.cases.every((item) => item.pass), true);
  const receipt = JSON.parse(await fs.readFile(path.join(base, 'output', 'validation-receipt.json'), 'utf8'));
  assert.equal(verifyReceipt(receipt).valid, true);
});

test('PR-pack artifact verification rejects tampering even with a valid envelope receipt', async () => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-pack-integrity-'));
  const repository = path.join(base, 'repository');
  const output = path.join(base, 'output');
  await fs.mkdir(repository);
  await fs.writeFile(path.join(repository, 'nginx.conf'), 'ssl_ecdh_curve X25519;\n');
  await createPrPack(repository, output);
  await verifyPackArtifacts(output);
  await fs.appendFile(path.join(output, 'migration.patch'), '# tampered\n');
  await assert.rejects(() => verifyPackArtifacts(output), /artifact integrity failed/);
});

test('corpus and pack validation reject path traversal before file access', async () => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-path-safety-'));
  const manifestPath = path.join(base, 'manifest.json');
  await fs.writeFile(manifestPath, JSON.stringify({
    schema: 'pqc-forge.public-corpus/v1',
    cases: [{ id: '..', source: 'test', revision: '1', url: 'https://example.test/a', filename: '../escape.conf', sha256: sha('x'), expect: { pack: false } }]
  }));
  await assert.rejects(() => validateCorpus(manifestPath, path.join(base, 'output')), /unsafe/i);

  const repository = path.join(base, 'repository');
  const pack = path.join(base, 'pack');
  await fs.mkdir(repository);
  await fs.writeFile(path.join(repository, 'nginx.conf'), 'ssl_ecdh_curve X25519;\n');
  await createPrPack(repository, pack);
  const receiptPath = path.join(pack, 'pr-pack-receipt.json');
  const receipt = JSON.parse(await fs.readFile(receiptPath, 'utf8'));
  receipt.artifacts[0].file = '../outside';
  const { receiptDigest: ignored, ...payload } = receipt;
  receipt.receiptDigest = sha(canonicalJson(payload));
  await fs.writeFile(receiptPath, JSON.stringify(receipt));
  await assert.rejects(() => verifyPackArtifacts(pack), /Unsafe PR-pack artifact path/);
});
