import { createHash } from 'node:crypto';

function normalize(value) {
  return String(value ?? '').replace(/\\/g, '/').replace(/\s+/g, ' ').trim().toLowerCase();
}

export function findingFingerprint(finding) {
  const identity = [finding.id, normalize(finding.file), normalize(finding.excerpt)].join('\u0000');
  return createHash('sha256').update(identity).digest('hex');
}

export function compareScans(current, baseline) {
  if (baseline?.schema !== 'pqc-forge.scan/v1' || !Array.isArray(baseline.findings)) {
    throw new Error('Baseline must be a PQC Forge scan/v1 JSON report.');
  }
  const previous = new Map(baseline.findings.map((finding) => [findingFingerprint(finding), finding]));
  const present = new Map(current.findings.map((finding) => [findingFingerprint(finding), finding]));
  const newFindings = current.findings.filter((finding) => !previous.has(findingFingerprint(finding)));
  const resolvedFindings = baseline.findings.filter((finding) => !present.has(findingFingerprint(finding)));
  const unchangedFindings = current.findings.filter((finding) => previous.has(findingFingerprint(finding)));
  const blockingNewFindings = newFindings.filter((finding) => ['critical', 'high'].includes(finding.severity));
  return {
    schema: 'pqc-forge.scan-delta/v1',
    baselineGeneratedAt: baseline.generatedAt ?? null,
    summary: {
      new: newFindings.length,
      newBlocking: blockingNewFindings.length,
      resolved: resolvedFindings.length,
      unchanged: unchangedFindings.length
    },
    newFindings,
    resolvedFindings,
    unchangedFindings,
    blockingNewFindings
  };
}
