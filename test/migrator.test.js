import assert from 'node:assert/strict';
import { test } from 'node:test';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { migrateRepository } from '../src/migrator.js';
import { scanRepository } from '../src/scanner.js';
import { createMigrationReceipt, verifyReceipt } from '../src/breaklab/receipt.js';
import { generateSigningKey } from '../src/signing.js';
import { rollbackMigration } from '../src/rollback.js';

const key = generateSigningKey();

test('migrator proposes and applies a hybrid TLS group with backup', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-'));
  const config = path.join(root, 'nginx.conf');
  await fs.writeFile(config, 'server {\n  ssl_protocols TLSv1 TLSv1.2 TLSv1.3;\n  ssl_ecdh_curve X25519;\n}\n');

  const dryRun = await migrateRepository(root);
  assert.equal(dryRun.mode, 'dry-run');
  assert.equal(dryRun.changeCount, 2);
  assert.equal(dryRun.artifacts.length, 1);
  assert.match(dryRun.artifacts[0].beforeDigest, /^sha256:[a-f0-9]{64}$/);
  assert.notEqual(dryRun.artifacts[0].beforeDigest, dryRun.artifacts[0].afterDigest);
  assert.equal(verifyReceipt(createMigrationReceipt(dryRun, key)).valid, true);
  assert.match(await fs.readFile(config, 'utf8'), /ssl_ecdh_curve X25519;/);

  await assert.rejects(() => migrateRepository(root, { write: true }), /Refusing to write/);

  const applied = await migrateRepository(root, { write: true, acknowledgeRuntime: true });
  assert.equal(applied.mode, 'applied');
  assert.match(await fs.readFile(config, 'utf8'), /X25519MLKEM768:X25519/);
  assert.match(await fs.readFile(`${config}.pqc-forge.bak`, 'utf8'), /TLSv1 TLSv1\.2/);

  const idempotent = await migrateRepository(root);
  assert.equal(idempotent.changeCount, 0);

  const appliedReceipt = createMigrationReceipt(applied, key);
  const rollbackPlan = await rollbackMigration(appliedReceipt);
  assert.equal(rollbackPlan.mode, 'dry-run');
  assert.match(await fs.readFile(config, 'utf8'), /X25519MLKEM768/);
  const rollback = await rollbackMigration(appliedReceipt, { write: true });
  assert.equal(rollback.restoredCount, 1);
  assert.match(await fs.readFile(config, 'utf8'), /ssl_ecdh_curve X25519;/);

  await fs.writeFile(config, 'changed after rollback\n');
  await assert.rejects(() => rollbackMigration(appliedReceipt), /changed after migration/);
  await fs.writeFile(config, await fs.readFile(`${config}.pqc-forge.bak`, 'utf8'));

  const secondRun = await migrateRepository(root);
  assert.equal(secondRun.changeCount, 2);
});

test('migrator leaves TLS 1.3-only configuration unchanged', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-modern-'));
  const config = path.join(root, 'nginx.conf');
  const modern = 'server {\n  ssl_protocols TLSv1.3;\n  ssl_ecdh_curve X25519MLKEM768:X25519;\n}\n';
  await fs.writeFile(config, modern);
  const report = await migrateRepository(root);
  assert.equal(report.changeCount, 0);
  assert.equal(await fs.readFile(config, 'utf8'), modern);
});

test('migrator updates HAProxy bind/server policies, legacy TLS, comments, and CRLF idempotently', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-haproxy-'));
  const config = path.join(root, 'haproxy.cfg');
  const original = [
    'global',
    '  ssl-default-bind-curves X25519:P-256 # frontend policy',
    '  ssl-default-server-curves X25519:secp384r1',
    '  ssl-default-bind-options no-tls-tickets ssl-min-ver TLSv1.1',
    'frontend https',
    '  bind *:443 ssl crt /cert.pem',
    ''
  ].join('\r\n');
  await fs.writeFile(config, original);
  const dryRun = await migrateRepository(root);
  assert.equal(dryRun.changeCount, 3);
  assert.equal(dryRun.artifacts.length, 1);
  const applied = await migrateRepository(root, { write: true, acknowledgeRuntime: true });
  const migrated = await fs.readFile(config, 'utf8');
  assert.match(migrated, /ssl-default-bind-curves X25519MLKEM768:SecP256r1MLKEM768:X25519:P-384:P-256 # frontend policy/);
  assert.match(migrated, /ssl-default-server-curves X25519MLKEM768/);
  assert.match(migrated, /ssl-min-ver TLSv1\.2/);
  assert.equal(migrated.includes('\r\n'), true);
  assert.equal((await migrateRepository(root)).changeCount, 0);
  const receipt = createMigrationReceipt(applied, key);
  await rollbackMigration(receipt, { write: true });
  assert.equal(await fs.readFile(config, 'utf8'), original);
});

test('migrator inserts a HAProxy hybrid bind policy only for an SSL frontend', async () => {
  const tlsRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-haproxy-add-'));
  await fs.writeFile(path.join(tlsRoot, 'haproxy.cfg'), 'global\n  daemon\nfrontend https\n  bind *:443 ssl crt /cert.pem\n');
  const tls = await migrateRepository(tlsRoot);
  assert.equal(tls.changeCount, 1);
  assert.equal(tls.changes[0].ruleId, 'QF-HAPROXY-ADD-HYBRID-GROUP');

  const clearRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-haproxy-clear-'));
  await fs.writeFile(path.join(clearRoot, 'haproxy.cfg'), 'global\n  daemon\nfrontend http\n  bind *:80\n');
  assert.equal((await migrateRepository(clearRoot)).changeCount, 0);
});

test('migrator updates and inserts Apache group policies per TLS virtual host', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-apache-'));
  const config = path.join(root, 'ssl.conf');
  const original = [
    '<VirtualHost *:443>',
    '  SSLEngine on',
    '  SSLOpenSSLConfCmd Curves X25519:prime256v1 # primary',
    '</VirtualHost>',
    '<VirtualHost *:8443>',
    '  SSLEngine on',
    '</VirtualHost>',
    ''
  ].join('\r\n');
  await fs.writeFile(config, original);
  const dryRun = await migrateRepository(root);
  assert.equal(dryRun.changeCount, 2);
  const applied = await migrateRepository(root, { write: true, acknowledgeRuntime: true });
  const migrated = await fs.readFile(config, 'utf8');
  assert.equal((migrated.match(/SSLOpenSSLConfCmd Groups X25519MLKEM768/g) ?? []).length, 2);
  assert.match(migrated, /secp384r1 # primary/);
  assert.equal(migrated.includes('\r\n'), true);
  assert.equal((await migrateRepository(root)).changeCount, 0);
  await rollbackMigration(createMigrationReceipt(applied, key), { write: true });
  assert.equal(await fs.readFile(config, 'utf8'), original);
});

test('migrator leaves non-TLS Apache configuration unchanged', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-apache-clear-'));
  await fs.writeFile(path.join(root, 'httpd.conf'), '<VirtualHost *:80>\n  DocumentRoot /var/www/html\n</VirtualHost>\n');
  assert.equal((await migrateRepository(root)).changeCount, 0);
});

test('migrator fixes classical Envoy curves, missing group policy, and legacy TLS minimum idempotently', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-envoy-'));
  const config = path.join(root, 'envoy.yaml');
  const original = [
    'static_resources:',
    '  listeners:',
    '  - filter_chains:',
    '    - transport_socket:',
    '        typed_config:',
    '          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext',
    '          common_tls_context:',
    '            tls_params:',
    '              tls_minimum_protocol_version: TLSv1_1',
    '              ecdh_curves:',
    '              - X25519',
    '              - P-256',
    '  clusters:',
    '  - transport_socket:',
    '      typed_config:',
    '        "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext',
    '        common_tls_context: {}',
    ''
  ].join('\n');
  await fs.writeFile(config, original);
  const dryRun = await migrateRepository(root);
  assert.equal(dryRun.changeCount, 3);
  assert.equal(dryRun.artifacts.length, 1);
  const applied = await migrateRepository(root, { write: true, acknowledgeRuntime: true });
  assert.equal(applied.mode, 'applied');
  const migrated = await fs.readFile(config, 'utf8');
  assert.match(migrated, /tls_minimum_protocol_version: TLSv1_2/);
  assert.match(migrated, /ecdh_curves:\n\s*- X25519MLKEM768\n\s*- X25519\n\s*- P-256/);
  assert.doesNotMatch(migrated, /common_tls_context:\s*\{\}/);
  assert.equal((await migrateRepository(root)).changeCount, 0);
  const rescan = await scanRepository(root);
  assert.equal(rescan.findings.some((finding) => finding.id.startsWith('QF-ENVOY-')), false);
  const receipt = createMigrationReceipt(applied, key);
  await rollbackMigration(receipt, { write: true });
  assert.equal(await fs.readFile(config, 'utf8'), original);
});

test('migrator leaves an Envoy config with an already-hybrid group policy unchanged', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-envoy-clean-'));
  await fs.writeFile(path.join(root, 'envoy.yaml'), [
    'static_resources:',
    '  listeners:',
    '  - filter_chains:',
    '    - transport_socket:',
    '        typed_config:',
    '          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext',
    '          common_tls_context:',
    '            tls_params:',
    '              tls_minimum_protocol_version: TLSv1_2',
    '              ecdh_curves:',
    '              - X25519MLKEM768',
    '              - X25519',
    ''
  ].join('\n'));
  assert.equal((await migrateRepository(root)).changeCount, 0);
});

test('migrator preflights every backup and refuses to overwrite an existing one', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-backup-preflight-'));
  const first = path.join(root, 'a.conf');
  const second = path.join(root, 'b.conf');
  const vulnerable = 'ssl_protocols TLSv1 TLSv1.2 TLSv1.3;\nssl_ecdh_curve X25519;\n';
  await fs.writeFile(first, vulnerable);
  await fs.writeFile(second, vulnerable);
  await fs.writeFile(`${second}.pqc-forge.bak`, 'existing recovery data\n');
  await assert.rejects(() => migrateRepository(root, { write: true, acknowledgeRuntime: true }), /Refusing to overwrite existing migration backup/);
  assert.equal(await fs.readFile(first, 'utf8'), vulnerable);
  assert.equal(await fs.readFile(second, 'utf8'), vulnerable);
  assert.equal(await fs.readFile(`${second}.pqc-forge.bak`, 'utf8'), 'existing recovery data\n');
  await assert.rejects(() => fs.stat(`${first}.pqc-forge.bak`), { code: 'ENOENT' });
});
