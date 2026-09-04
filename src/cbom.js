import { randomUUID } from 'node:crypto';
import { findingFingerprint } from './baseline.js';
import { VERSION } from './version.js';

// Maps a PQC Forge scan rule to a CycloneDX 1.6 cryptographic-asset shape.
// Every branch produces a schema-valid `cryptoProperties` object; fields we
// are not confident about (e.g. exact parameter sizes not present in the
// excerpt) are simply omitted rather than guessed.
function cryptoProperties(finding) {
  switch (finding.id) {
    case 'QF-ALG-RSA':
    case 'QF-WEAK-RSA-SIZE': {
      const size = finding.excerpt.match(/\b(1024|1536|2048|3072|4096)\b/)?.[1];
      return {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: 'pke',
          parameterSetIdentifier: size ? `RSA-${size}` : 'RSA',
          executionEnvironment: 'software-plain-ram',
          implementationPlatform: 'generic',
          cryptoFunctions: ['keygen', 'encrypt', 'decrypt', 'sign', 'verify'],
          nistQuantumSecurityLevel: 0
        }
      };
    }
    case 'QF-ALG-ECC': {
      const curve = finding.excerpt.match(/\b(secp256r1|prime256v1|secp384r1|X25519)\b/i)?.[1];
      return {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: 'key-agree',
          parameterSetIdentifier: curve ?? 'ECC',
          executionEnvironment: 'software-plain-ram',
          implementationPlatform: 'generic',
          cryptoFunctions: ['keygen', 'keyderive'],
          nistQuantumSecurityLevel: 0
        }
      };
    }
    case 'QF-TLS-LEGACY':
    case 'QF-HAPROXY-LEGACY-TLS': {
      const version = finding.excerpt.match(/TLSv1(?:\.\d)?/i)?.[0];
      return {
        assetType: 'protocol',
        protocolProperties: {
          type: 'tls',
          version: version ?? 'TLSv1.0/1.1',
          cipherSuites: []
        }
      };
    }
    default:
      // QF-TLS-CLASSICAL-GROUPS, QF-HAPROXY-CLASSICAL-GROUPS,
      // QF-APACHE-CLASSICAL-GROUPS, QF-HAPROXY-MISSING-GROUP-POLICY,
      // QF-APACHE-MISSING-GROUP-POLICY: all describe a TLS key-establishment
      // group policy carrying no post-quantum group.
      return {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: 'key-agree',
          parameterSetIdentifier: 'classical-only-tls-groups',
          executionEnvironment: 'software-plain-ram',
          implementationPlatform: 'generic',
          cryptoFunctions: ['keygen', 'keyderive'],
          nistQuantumSecurityLevel: 0
        }
      };
  }
}

const SEVERITY = new Set(['critical', 'high', 'medium', 'low', 'info', 'none', 'unknown']);

function componentFor(finding, index) {
  const bomRef = `crypto-asset/${index}/${finding.id}`;
  return {
    'bom-ref': bomRef,
    type: 'cryptographic-asset',
    name: finding.id,
    description: finding.reason,
    cryptoProperties: cryptoProperties(finding),
    evidence: {
      occurrences: [{ location: finding.file.replace(/\\/g, '/'), line: finding.line, additionalContext: finding.excerpt }]
    }
  };
}

function vulnerabilityFor(finding, bomRef, { analysisState, analysisDetail } = {}) {
  const severity = SEVERITY.has(finding.severity) ? finding.severity : 'unknown';
  const vulnerability = {
    'bom-ref': `vuln/${bomRef}`,
    id: finding.id,
    source: { name: 'PQC Forge', url: 'https://github.com/rootsystems/pqc-forge' },
    ratings: [{ source: { name: 'PQC Forge' }, severity, method: 'other' }],
    description: finding.reason,
    recommendation: finding.remediation,
    affects: [{ ref: bomRef }],
    properties: [
      { name: 'pqc-forge:standard', value: finding.standard },
      { name: 'pqc-forge:automatable', value: String(Boolean(finding.automatable)) },
      { name: 'pqc-forge:category', value: finding.category }
    ]
  };
  if (analysisState) vulnerability.analysis = { state: analysisState, ...(analysisDetail ? { detail: analysisDetail } : {}) };
  return vulnerability;
}

/**
 * Render a PQC Forge scan report as a CycloneDX 1.6 Cryptographic Bill of
 * Materials. One cryptographic-asset component per finding occurrence, each
 * paired with a vulnerability entry carrying severity, remediation, and — via
 * `analysis.state` — migration status:
 *
 *  - no baseline:        every open finding is unanalyzed (state omitted).
 *  - with `report.delta`: new findings get no state (freshly introduced),
 *    unchanged findings get `exploitable` + `will_not_fix` is NOT implied —
 *    they are simply still-open debt — and prior findings that disappeared
 *    are included with `analysis.state: "resolved"`.
 *  - suppressed findings (active audited exceptions) get
 *    `analysis.state: "exploitable"` with the suppression reason and expiry
 *    recorded in `analysis.detail`, since an audited exception is a
 *    documented, time-boxed decision not to act yet — not a false positive.
 */
export function scanToCbom(report) {
  const components = [];
  const vulnerabilities = [];
  const delta = report.delta;
  const newFingerprints = new Set((delta?.newFindings ?? []).map(findingFingerprint));

  const addFinding = (finding, index, extra) => {
    const component = componentFor(finding, index);
    components.push(component);
    vulnerabilities.push(vulnerabilityFor(finding, component['bom-ref'], extra));
  };

  report.findings.forEach((finding, index) => {
    const fingerprint = findingFingerprint(finding);
    if (delta && !newFingerprints.has(fingerprint)) {
      addFinding(finding, index, { analysisState: 'exploitable', analysisDetail: 'Present in both the baseline and this scan; still open.' });
    } else {
      addFinding(finding, index, {});
    }
  });

  (report.suppressedFindings ?? []).forEach((finding, index) => {
    addFinding(finding, `suppressed-${index}`, {
      analysisState: 'exploitable',
      analysisDetail: `Audited exception: ${finding.suppression?.reason ?? 'no reason recorded'} (expires ${finding.suppression?.expires ?? 'unknown'}).`
    });
  });

  (delta?.resolvedFindings ?? []).forEach((finding, index) => {
    addFinding(finding, `resolved-${index}`, { analysisState: 'resolved', analysisDetail: 'No longer present in the current scan.' });
  });

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: report.generatedAt ?? new Date().toISOString(),
      tools: { components: [{ type: 'application', name: 'PQC Forge', version: VERSION, 'bom-ref': 'pqc-forge' }] },
      component: { type: 'application', name: 'scanned-repository', 'bom-ref': 'target' }
    },
    components,
    vulnerabilities
  };
}
