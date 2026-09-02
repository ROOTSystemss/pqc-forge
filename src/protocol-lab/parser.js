const PQ_GROUP = /MLKEM|KYBER/i;
const PQ_SIGNATURE = /ML-?DSA|SLH-?DSA|DILITHIUM|SPHINCS/i;

function firstMatch(text, patterns) {
  for (const pattern of patterns) {
    const match = text.match(pattern);
    if (match) return match[1].trim();
  }
  return null;
}

export function parseOpenSslEvidence(output, exitCode, testCase) {
  const protocol = firstMatch(output, [/Protocol version:\s*([^\r\n]+)/i, /Protocol\s*:\s*([^\r\n]+)/i]);
  const group = firstMatch(output, [
    /Negotiated TLS1\.3 group:\s*([^\s\r\n]+)/i,
    /Peer Temp Key:\s*([^,\r\n]+)/i,
    /Server Temp Key:\s*([^,\r\n]+)/i
  ]);
  const signature = firstMatch(output, [/Peer signature type:\s*([^\r\n]+)/i, /Signature type:\s*([^\r\n]+)/i]);
  const findings = [];
  if (exitCode !== 0 || !/TLSv1\.3/i.test(protocol ?? '')) findings.push({ code: 'HANDSHAKE_FAILED', severity: 100, message: 'A TLS 1.3 handshake did not complete.' });
  if (exitCode === 0 && testCase.requirePqKeyExchange && !PQ_GROUP.test(group ?? '')) findings.push({ code: 'CLASSICAL_DOWNGRADE', severity: 95, message: `Expected PQ key exchange but observed ${group ?? 'unknown group'}.` });
  if (exitCode === 0 && testCase.requirePqAuthentication && !PQ_SIGNATURE.test(signature ?? '')) findings.push({ code: 'PQ_AUTH_NOT_OBSERVED', severity: 90, message: `Expected PQ authentication but observed ${signature ?? 'unknown signature'}.` });
  return {
    name: testCase.name, target: testCase.target, offeredGroups: testCase.groups, exitCode,
    handshakeSucceeded: exitCode === 0 && /TLSv1\.3/i.test(protocol ?? ''),
    protocol, negotiatedGroup: group, peerSignatureType: signature,
    pqKeyExchangeObserved: PQ_GROUP.test(group ?? ''), pqAuthenticationObserved: PQ_SIGNATURE.test(signature ?? ''),
    findings, severity: Math.max(0, ...findings.map((finding) => finding.severity)), rawOutput: output.trim().slice(0, 12000)
  };
}
