import assert from 'node:assert/strict';
import { test } from 'node:test';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

test('composite action exposes scan, BreakLab, runtime, and staging gates without shell interpolation', async () => {
  const action = await fs.readFile(path.join(root, 'action.yml'), 'utf8');
  assert.match(action, /default: scan/);
  assert.match(action, /inputs\.mode == 'scan'/);
  assert.match(action, /inputs\.mode == 'breaklab'/);
  assert.match(action, /inputs\.mode == 'runtime'/);
  assert.match(action, /inputs\.mode == 'staging'/);
  assert.match(action, /runtime-probe/);
  assert.match(action, /PQC_FORGE_RUNTIME_CONFIG/);
  assert.match(action, /PQC_FORGE_RUNTIME_CONTAINER_CONFIG/);
  assert.match(action, /--container/);
  assert.match(action, /PQC_FORGE_STAGING_MANIFEST/);
  assert.match(action, /staging-gate/);
  assert.match(action, /PQC_FORGE_BASELINE/);
  assert.match(action, /--sarif/);
  assert.match(action, /--report/);
  assert.doesNotMatch(action, /run:.*\$\{\{ inputs\./);
});
