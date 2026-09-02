import tls from 'node:tls';

export function parseTarget(target) {
  const value = target.includes('://') ? new URL(target) : new URL(`tls://${target}`);
  return {
    host: value.hostname,
    port: Number(value.port || 443)
  };
}

export async function verifyTls(target, { insecure = false, timeoutMs = 10000 } = {}) {
  const { host, port } = parseTarget(target);
  const started = Date.now();

  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host,
      port,
      servername: host,
      minVersion: 'TLSv1.3',
      rejectUnauthorized: !insecure,
      timeout: timeoutMs
    });

    socket.once('secureConnect', () => {
      const ephemeral = socket.getEphemeralKeyInfo?.() ?? {};
      const certificate = socket.getPeerCertificate?.() ?? {};
      const group = ephemeral.name ?? ephemeral.type ?? 'unknown';
      const pqKeyExchange = /MLKEM|KYBER/i.test(group);
      const signatureAlgorithm = certificate.sigalg ?? 'unknown';
      const pqAuthentication = /ML-?DSA|SLH-?DSA|DILITHIUM|SPHINCS/i.test(signatureAlgorithm);
      const evidence = {
        schema: 'pqc-forge.tls-evidence/v1',
        generatedAt: new Date().toISOString(),
        target: `${host}:${port}`,
        elapsedMs: Date.now() - started,
        authorized: socket.authorized,
        authorizationError: socket.authorizationError ?? null,
        protocol: socket.getProtocol(),
        cipher: socket.getCipher(),
        ephemeralKey: ephemeral,
        peerSignatureAlgorithm: signatureAlgorithm,
        runtime: { node: process.version, openssl: process.versions.openssl },
        verdict: {
          pqKeyExchange,
          pqAuthentication,
          status: pqKeyExchange && pqAuthentication
            ? 'full-pq-observed'
            : pqKeyExchange
              ? 'pq-confidentiality-observed'
              : 'no-pq-negotiation-observed'
        }
      };
      socket.end();
      resolve(evidence);
    });

    socket.once('timeout', () => socket.destroy(new Error(`TLS verification timed out after ${timeoutMs}ms`)));
    socket.once('error', (error) => {
      const detail = error.message || error.code || error.errors?.map((item) => item.message).filter(Boolean).join('; ');
      reject(new Error(`TLS connection to ${host}:${port} failed${detail ? `: ${detail}` : ''}`));
    });
  });
}
