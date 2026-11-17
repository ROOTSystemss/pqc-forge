// AD-065 (knock-out Phase 5): passive TLS endpoint inventory. For each public endpoint the customer lists, one
// ordinary TLS 1.3 handshake (exactly what a browser does; no scanning, no probing of other ports or hosts) and a
// record of what was negotiated: protocol, key-exchange group, certificate signature algorithm, and whether the
// key exchange was post-quantum. Three states per endpoint: "post-quantum key exchange observed", "classical key
// exchange only", or "Not verified" (not reachable / no TLS 1.3 handshake) - an endpoint that did not answer is
// never counted as either. Signed like every other PQC Forge receipt.
import { signDoc, verifyDoc } from './signedDoc.js';

export const ENDPOINT_INVENTORY_SCHEMA = 'pqc-forge.endpoint-inventory/v1';

export function endpointRow(e) {
  if (!e.ok) return { target: e.target, state: 'not-verified', status: 'Not verified (not reachable or no TLS 1.3 handshake)', error: String(e.error || 'unreachable').slice(0, 200) };
  const ev = e.evidence;
  const keyExchange = (ev.ephemeralKey && (ev.ephemeralKey.name || ev.ephemeralKey.type)) || 'unknown';
  const pq = ev.verdict && ev.verdict.pqKeyExchange === true;
  return {
    target: e.target,
    state: pq ? 'pq-key-exchange' : 'classical-only',
    status: pq ? 'Post-quantum key exchange observed' : 'Classical key exchange only',
    protocol: ev.protocol || 'unknown',
    keyExchange,
    certificateSignature: ev.peerSignatureAlgorithm || 'unknown',
    postQuantumAuthentication: ev.verdict ? ev.verdict.pqAuthentication === true : false,
    certificateTrusted: ev.authorized === true,
    observedAt: ev.generatedAt,
  };
}

export function buildEndpointInventory({ label, endpoints, now = new Date() }) {
  if (!Array.isArray(endpoints) || !endpoints.length) throw new Error('List at least one public endpoint.');
  const rows = endpoints.map(endpointRow);
  const count = (s) => rows.filter((r) => r.state === s).length;
  return {
    schema: ENDPOINT_INVENTORY_SCHEMA,
    generatedAt: new Date(now).toISOString(),
    label: String(label || 'Endpoint inventory').slice(0, 120),
    scope: {
      endpointsListed: rows.length,
      method: 'Passive: one ordinary TLS 1.3 handshake per endpoint you listed (what any browser does). No port scanning, no probing of other hosts, no attack traffic.',
      note: 'Covers only the endpoints listed, at the moment shown. An endpoint that did not answer, or does not offer TLS 1.3, reads Not verified and is not counted as post-quantum or classical.',
    },
    summary: { postQuantumKeyExchange: count('pq-key-exchange'), classicalOnly: count('classical-only'), notVerified: count('not-verified') },
    endpoints: rows,
  };
}

export const signEndpointInventory = signDoc;
export const verifyEndpointInventory = (doc, keys = null) => verifyDoc(doc, ENDPOINT_INVENTORY_SCHEMA, 'endpoint inventory', keys);
