import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { verifyReceipt } from './breaklab/receipt.js';

const digest = (content) => `sha256:${createHash('sha256').update(content).digest('hex')}`;

function inside(root, relative) {
  const resolved = path.resolve(root, relative);
  const prefix = `${path.resolve(root)}${path.sep}`;
  if (resolved !== path.resolve(root) && !resolved.startsWith(prefix)) {
    throw new Error(`Unsafe rollback path outside migration root: ${relative}`);
  }
  return resolved;
}

export async function rollbackMigration(receipt, { write = false } = {}) {
  if (receipt?.schema !== 'pqc-forge.migration-receipt/v1') {
    throw new Error('Rollback requires a PQC Forge migration-receipt/v1 document.');
  }
  if (!verifyReceipt(receipt).valid) throw new Error('Refusing rollback: migration receipt digest is invalid.');
  if (receipt.migration.mode !== 'applied') throw new Error('Refusing rollback: receipt describes a dry-run, not applied changes.');
  const root = path.resolve(receipt.migration.root);
  const pending = [];
  for (const artifact of receipt.migration.artifacts) {
    if (!artifact.backup) throw new Error(`Refusing rollback: no backup recorded for ${artifact.file}.`);
    const target = inside(root, artifact.file);
    const backup = inside(root, artifact.backup);
    const [currentContent, backupContent] = await Promise.all([
      fs.readFile(target, 'utf8'), fs.readFile(backup, 'utf8')
    ]);
    if (digest(currentContent) !== artifact.afterDigest) {
      throw new Error(`Refusing rollback: ${artifact.file} changed after migration.`);
    }
    if (digest(backupContent) !== artifact.beforeDigest) {
      throw new Error(`Refusing rollback: backup digest mismatch for ${artifact.file}.`);
    }
    pending.push({ file: artifact.file, target, backup: artifact.backup, content: backupContent });
  }
  if (write) {
    for (const item of pending) await fs.writeFile(item.target, item.content, 'utf8');
  }
  return {
    schema: 'pqc-forge.rollback/v1', generatedAt: new Date().toISOString(), root,
    mode: write ? 'applied' : 'dry-run', restoredCount: pending.length,
    files: pending.map(({ file, backup }) => ({ file, backup }))
  };
}
