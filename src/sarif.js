import { findingFingerprint } from './baseline.js';
import { VERSION } from './version.js';

const LEVELS = { critical: 'error', high: 'error', medium: 'warning', low: 'note' };

export function scanToSarif(report) {
  const rules = [...new Map(report.findings.map((finding) => [finding.id, {
    id: finding.id,
    name: finding.category,
    shortDescription: { text: finding.reason },
    fullDescription: { text: finding.remediation },
    help: { text: `${finding.remediation} Reference: ${finding.standard}.` },
    properties: { category: finding.category, standard: finding.standard, automatable: finding.automatable }
  }])).values()];
  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [{
      tool: { driver: { name: 'PQC Forge', semanticVersion: VERSION, informationUri: 'https://github.com/rootsystems/pqc-forge', rules } },
      automationDetails: { id: 'pqc-forge/quantum-risk-scan' },
      results: report.findings.map((finding) => ({
        ruleId: finding.id,
        level: LEVELS[finding.severity] ?? 'warning',
        message: { text: `${finding.reason} ${finding.remediation}` },
        locations: [{ physicalLocation: {
          artifactLocation: { uri: finding.file.replace(/\\/g, '/') },
          region: { startLine: finding.line }
        } }],
        partialFingerprints: { 'pqcForge/v1': findingFingerprint(finding) },
        properties: { severity: finding.severity, standard: finding.standard, automatable: finding.automatable }
      }))
    }]
  };
}
