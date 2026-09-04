import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { scanRepository } from '../src/scanner.js';
import { compareScans } from '../src/baseline.js';
import { scanToCbom } from '../src/cbom.js';

const execute = promisify(execFile);
const projectRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const cli = path.join(projectRoot, 'bin', 'pqc-forge.js');
const fixtures = path.join(projectRoot, 'test', 'fixtures', 'vulnerable');

function componentIndex(cbom) {
  return new Map(cbom.components.map((component) => [component['bom-ref'], component]));
}

test('scanToCbom emits a structurally valid CycloneDX 1.6 document', async () => {
  const report = await scanRepository(fixtures);
  const cbom = scanToCbom(report);
  assert.equal(cbom.bomFormat, 'CycloneDX');
  assert.equal(cbom.specVersion, '1.6');
  assert.match(cbom.serialNumber, /^urn:uuid:[0-9a-f-]{36}$/);
  assert.equal(cbom.version, 1);
  assert.ok(cbom.metadata.timestamp);
  assert.equal(cbom.components.length, report.findings.length);
  assert.equal(cbom.vulnerabilities.length, report.findings.length);
  for (const component of cbom.components) {
    assert.equal(component.type, 'cryptographic-asset');
    assert.ok(component['bom-ref']);
    assert.ok(['algorithm', 'protocol'].includes(component.cryptoProperties.assetType));
    assert.equal(component.evidence.occurrences.length, 1);
    assert.ok(component.evidence.occurrences[0].location);
  }
  const components = componentIndex(cbom);
  for (const vulnerability of cbom.vulnerabilities) {
    assert.ok(vulnerability.id);
    assert.ok(['critical', 'high', 'medium', 'low', 'info', 'none', 'unknown'].includes(vulnerability.ratings[0].severity));
    assert.ok(vulnerability.recommendation);
    assert.equal(vulnerability.affects.length, 1);
    assert.ok(components.has(vulnerability.affects[0].ref), 'vulnerability must reference a real component');
    assert.equal(vulnerability.analysis, undefined, 'a fresh scan with no baseline has no migration-status analysis yet');
  }
});

test('scanToCbom marks resolved findings and still-open debt via analysis.state when a baseline delta is present', async () => {
  const report = await scanRepository(fixtures);
  const baseline = structuredClone(report);
  const extraFinding = { ...baseline.findings[0], line: 99999, excerpt: 'a finding that will not reproduce in the current scan' };
  baseline.findings = [...baseline.findings, extraFinding];
  report.delta = compareScans(report, baseline);

  const cbom = scanToCbom(report);
  const resolved = cbom.vulnerabilities.filter((v) => v.analysis?.state === 'resolved');
  assert.equal(resolved.length, 1);
  assert.equal(resolved[0].id, extraFinding.id);

  const stillOpen = cbom.vulnerabilities.filter((v) => v.analysis?.state === 'exploitable');
  assert.equal(stillOpen.length, report.findings.length);
  assert.equal(cbom.components.length, report.findings.length + 1);
  assert.equal(cbom.vulnerabilities.length, report.findings.length + 1);
});

test('scanToCbom carries suppressed findings with their audit reason and expiry', async () => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-cbom-suppress-'));
  await fs.writeFile(path.join(base, 'nginx.conf'), 'ssl_ecdh_curve X25519;\n');
  await fs.writeFile(path.join(base, '.pqc-forge-ignore.json'), JSON.stringify({
    schema: 'pqc-forge.ignore/v1',
    suppressions: [{ ruleId: 'QF-TLS-CLASSICAL-GROUPS', path: '**', reason: 'tracked in TICKET-1', expires: '2999-01-01' }]
  }));
  const report = await scanRepository(base);
  assert.equal(report.summary.suppressed, 1);
  const cbom = scanToCbom(report);
  const suppressed = cbom.vulnerabilities.find((v) => v.analysis?.detail?.includes('TICKET-1'));
  assert.ok(suppressed, 'expected a vulnerability entry carrying the suppression reason');
  assert.equal(suppressed.analysis.state, 'exploitable');
  assert.match(suppressed.analysis.detail, /2999-01-01/);
});

test('CLI scan --cbom writes a CycloneDX file alongside the JSON/SARIF report', async () => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-cbom-cli-'));
  const cbomPath = path.join(base, 'pqc-forge.cbom.json');
  await execute(process.execPath, [cli, 'scan', fixtures, '--cbom', cbomPath, '--no-ignore']).catch((error) => {
    // scan exits 2 on critical findings, which the fixture is expected to contain.
    if (error.code !== 2) throw error;
  });
  const cbom = JSON.parse(await fs.readFile(cbomPath, 'utf8'));
  assert.equal(cbom.bomFormat, 'CycloneDX');
  assert.ok(cbom.components.length > 0);
});
