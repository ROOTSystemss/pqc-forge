import { promises as dns } from 'node:dns';
import net from 'node:net';
import { parseTarget } from '../verifier.js';

/**
 * Rules that only matter when strangers share one API host (the hosted
 * service). The CLI and the GitHub Action run on the user's own machine and
 * are unaffected.
 *
 * - Job types that run programs on the host (`runtime-probe` starts a server
 *   binary, `protocol-lab` runs Docker) are off unless the operator sets
 *   PQC_FORGE_API_ALLOW_HOST_EXECUTION=1 on a dedicated, least-privilege host.
 * - `verify` may only reach public addresses, so a caller cannot use the
 *   server to probe its private network or a cloud metadata endpoint. The
 *   operator can lift this with PQC_FORGE_API_ALLOW_PRIVATE_TARGETS=1.
 */
export const HOST_EXECUTION_JOB_TYPES = new Set(['runtime-probe', 'protocol-lab']);

export function safetyOptionsFromEnv(env = process.env) {
  return {
    allowHostExecution: env.PQC_FORGE_API_ALLOW_HOST_EXECUTION === '1',
    allowPrivateTargets: env.PQC_FORGE_API_ALLOW_PRIVATE_TARGETS === '1'
  };
}

function ipv4Private(address) {
  const [a, b] = address.split('.').map(Number);
  return a === 0 || a === 10 || a === 127 || a >= 224 // this network, private, loopback, multicast and reserved
    || (a === 100 && b >= 64 && b <= 127) // carrier-grade NAT
    || (a === 169 && b === 254) // link-local, including cloud metadata (169.254.169.254)
    || (a === 172 && b >= 16 && b <= 31)
    || (a === 192 && b === 168)
    || (a === 192 && b === 0 && address.split('.')[2] === '0') // IETF protocol assignments
    || (a === 198 && (b === 18 || b === 19)); // benchmarking
}

export function isPrivateAddress(address) {
  if (net.isIPv4(address)) return ipv4Private(address);
  if (!net.isIPv6(address)) return true; // not an IP at all: refuse rather than guess
  const lower = address.toLowerCase();
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(lower);
  if (mapped) return ipv4Private(mapped[1]);
  return lower === '::' || lower === '::1'
    || /^f[cd]/.test(lower) // unique local fc00::/7
    || /^fe[89ab]/.test(lower) // link-local fe80::/10
    || /^ff/.test(lower) // multicast
    || lower.startsWith('64:ff9b:'); // NAT64, which can reach private IPv4
}

/**
 * Resolves the target and returns the first address that is safe to connect
 * to. Throws if any resolved address is private: a name that resolves to both
 * a public and a private address is refused as a whole.
 */
export async function resolvePublicTarget(target, { allowPrivateTargets = false, lookup = dns.lookup } = {}) {
  let parsed;
  try {
    parsed = parseTarget(String(target ?? ''));
  } catch {
    throw new Error('verify requires a target such as example.com or example.com:443.');
  }
  if (!parsed.host) throw new Error('verify requires a target such as example.com or example.com:443.');
  if (!Number.isInteger(parsed.port) || parsed.port < 1 || parsed.port > 65535) throw new Error('verify target port must be between 1 and 65535.');
  const host = parsed.host.replace(/^\[|\]$/g, '');
  const addresses = net.isIP(host) ? [{ address: host }] : await lookup(host, { all: true, verbatim: true });
  if (!addresses.length) throw new Error(`Could not resolve ${host}.`);
  if (!allowPrivateTargets) {
    const blocked = addresses.find((entry) => isPrivateAddress(entry.address));
    if (blocked) throw new Error(`verify only reaches public addresses; ${host} resolves to a private or reserved address.`);
  }
  return { host, port: parsed.port, address: addresses[0].address };
}
