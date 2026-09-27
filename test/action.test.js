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

test('composite action installs its own dependencies before any mode runs', async () => {
  // The CLI imports @noble/post-quantum at load time, so a consuming repository without this step
  // fails with ERR_MODULE_NOT_FOUND before scanning anything.
  const action = await fs.readFile(path.join(root, 'action.yml'), 'utf8');
  const install = action.indexOf('npm ci --omit=dev');
  assert.ok(install > 0, 'action must run npm ci for its own package');
  assert.match(action, /npm ci --omit=dev --ignore-scripts[^\n]*--prefix "\$GITHUB_ACTION_PATH"/);
  assert.ok(install < action.indexOf("inputs.mode == 'scan'"), 'install must precede the first mode step');
});
