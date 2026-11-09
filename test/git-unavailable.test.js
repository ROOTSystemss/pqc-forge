import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { createPrPack } from '../src/pr-pack.js';
import { GIT_UNAVAILABLE_MESSAGE } from '../src/git.js';
import { generateSigningKey } from '../src/signing.js';

// 2026-11-09: with no git binary a PR pack failed with "spawn git ENOENT"; the customer now sees a clear message.
test('PR pack without a git binary fails with a clear message, not "spawn git ENOENT"', async () => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-nogit-'));
  const repository = path.join(base, 'repository');
  await fs.mkdir(repository);
  await fs.writeFile(path.join(repository, 'nginx.conf'), 'server {\n  ssl_protocols TLSv1.2;\n  ssl_ecdh_curve secp384r1;\n}\n');
  const saved = process.env.PQC_FORGE_GIT;
  process.env.PQC_FORGE_GIT = path.join(base, 'no-such-git');
  try {
    await assert.rejects(() => createPrPack(repository, path.join(base, 'output'), { signingKey: generateSigningKey() }),
      (error) => error.message === GIT_UNAVAILABLE_MESSAGE && error.code === 'GIT_UNAVAILABLE' && !/ENOENT/.test(error.message));
  } finally {
    if (saved === undefined) delete process.env.PQC_FORGE_GIT; else process.env.PQC_FORGE_GIT = saved;
  }
});
