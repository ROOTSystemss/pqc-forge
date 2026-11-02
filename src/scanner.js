import { promises as fs } from 'node:fs';
import path from 'node:path';

const SKIP_DIRECTORIES = new Set([
  '.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.venv', 'vendor',
  '.npm-cache', 'demo-output', 'protocol-output', 'pqc-forge-output', 'release-output', 'validation-output'
]);

const TEXT_EXTENSIONS = new Set([
  '.c', '.cc', '.cfg', '.conf', '.config', '.cpp', '.cs', '.env', '.go', '.h', '.hpp',
  '.ini', '.java', '.js', '.json', '.jsx', '.kt', '.mjs', '.pem', '.properties',
  '.py', '.rb', '.rs', '.sh', '.toml', '.ts', '.tsx', '.xml', '.yaml', '.yml'
]);

const RULES = [
  {
    id: 'QF-ALG-RSA',
    severity: 'high',
    category: 'quantum-vulnerable-algorithm',
    pattern: /(?:\b(?:alg(?:orithm)?|certificate[_-]?algorithm|key[_-]?type|signature(?:[_-]?algorithm|\s+type)?)\b['"]?\s*[:=(]\s*['"]?\s*(?:RSA|RSA-PSS|RSAES|RSASSA|RS256|RS384|RS512|PS256|PS384|PS512)\b|\b(?:EVP_PKEY_RSA|RSA_generate_key|generateKeyPair(?:Sync)?\s*\(\s*['"]rsa|KeyPairGenerator\.getInstance\s*\(\s*['"]RSA))/i,
    reason: 'RSA public-key operations are vulnerable to a cryptographically relevant quantum computer.',
    remediation: 'Inventory the operation and migrate signing or key establishment to an approved PQC or hybrid construction.',
    standard: 'NIST FIPS 203/204',
    automatable: false
  },
  {
    id: 'QF-ALG-ECC',
    severity: 'high',
    category: 'quantum-vulnerable-algorithm',
    // Also covers how Node and JWT code names curves: namedCurve/crv P-256, JOSE alg ES256/EdDSA,
    // and crypto.generateKeyPair(Sync)('ec' | 'ed25519' | ...).
    pattern: /(?:(?:\b(?:alg(?:orithm)?|curve|named[_-]?curve|crv|ecdh[_-]?curve|group|key[_-]?type|signature[_-]?algorithm)|\bssl_ecdh_curve)\b['"]?\s*[:=(]?\s*['"]?\s*(?:ECDSA|ECDH|secp256r1|prime256v1|secp384r1|secp521r1|secp256k1|X25519|X448|P-256|P-384|P-521|ES256K?|ES384|ES512|EdDSA|Ed25519|Ed448)\b|\b(?:EVP_PKEY_EC|EC_KEY_new|createECDH\s*\(|X25519PrivateKey|generateKeyPair(?:Sync)?\s*\(\s*['"](?:ec|ed25519|ed448|x25519|x448)['"]))/i,
    ignore: /X25519MLKEM/i,
    reason: 'Classical elliptic-curve public-key operations are vulnerable to a cryptographically relevant quantum computer.',
    remediation: 'Use a standards-aligned hybrid key exchange during transition and plan ML-DSA or SLH-DSA for signatures.',
    standard: 'NIST FIPS 203/204/205',
    automatable: false
  },
  {
    id: 'QF-TLS-LEGACY',
    severity: 'medium',
    category: 'protocol-baseline',
    pattern: /ssl_protocols\s+([^;]*(?:\bTLSv1(?:\.0)?(?!\.\d)|\bTLSv1\.1\b)[^;]*);/i,
    reason: 'Legacy TLS is present in the migration surface and prevents a clean PQC-capable TLS 1.3 baseline.',
    remediation: 'Remove TLS 1.0/1.1 and retain TLS 1.2/1.3 according to compatibility requirements.',
    standard: 'TLS 1.3',
    automatable: true
  },
  {
    id: 'QF-TLS-CLASSICAL-GROUPS',
    severity: 'high',
    category: 'key-establishment',
    pattern: /ssl_ecdh_curve\s+([^;]*(?:X25519|prime256v1|secp256r1|secp384r1)[^;]*);/i,
    ignore: /MLKEM|KYBER/i,
    reason: 'The explicitly configured TLS groups contain no post-quantum or hybrid key exchange.',
    remediation: 'Prefer X25519MLKEM768 with X25519 fallback on a runtime that supports the standardized hybrid group.',
    standard: 'IETF TLS hybrid ML-KEM',
    automatable: true
  },
  {
    id: 'QF-HAPROXY-CLASSICAL-GROUPS',
    severity: 'high',
    category: 'key-establishment',
    pattern: /ssl-default-(?:bind|server)-curves\s+(?:[^#\s]*(?:X25519|X448|prime256v1|secp256r1|secp384r1|P-256|P-384)[^#\s]*)/i,
    ignore: /MLKEM|KYBER/i,
    reason: 'The HAProxy TLS group policy contains no post-quantum or hybrid key exchange.',
    remediation: 'Prepend X25519MLKEM768 and retain classical fallbacks on HAProxy linked to OpenSSL 3.5+.',
    standard: 'IETF TLS hybrid ML-KEM',
    automatable: true
  },
  {
    id: 'QF-HAPROXY-LEGACY-TLS',
    severity: 'medium',
    category: 'protocol-baseline',
    pattern: /(?:ssl-default-(?:bind|server)-options|\bbind\b.*\bssl\b).*\bssl-min-ver\s+(?:TLSv1(?:\.0)?(?!\.\d)|TLSv1\.1)\b/i,
    reason: 'The HAProxy TLS policy permits TLS 1.0/1.1, which cannot negotiate PQC-capable TLS 1.3.',
    remediation: 'Raise ssl-min-ver to TLSv1.2 while retaining TLS 1.3 support.',
    standard: 'TLS 1.3',
    automatable: true
  },
  {
    id: 'QF-APACHE-CLASSICAL-GROUPS',
    severity: 'high',
    category: 'key-establishment',
    pattern: /SSLOpenSSLConfCmd\s+(?:Groups|Curves)\s+[^#\s]*(?:X25519|X448|prime256v1|secp256r1|secp384r1|P-256|P-384)[^#\s]*/i,
    ignore: /MLKEM|KYBER/i,
    reason: 'The Apache mod_ssl group policy contains no post-quantum or hybrid key exchange.',
    remediation: 'Prefer X25519MLKEM768 with classical fallbacks through SSLOpenSSLConfCmd on OpenSSL 3.5+.',
    standard: 'IETF TLS hybrid ML-KEM',
    automatable: true
  },
  {
    id: 'QF-WEAK-RSA-SIZE',
    severity: 'critical',
    category: 'cryptographic-debt',
    pattern: /(?:rsa[_-]?(?:bits|key[_-]?size)|modulus[_-]?bits)\s*[:=]\s*(1024|1536)\b/i,
    reason: 'The configured RSA key size is already below modern classical-security expectations.',
    remediation: 'Replace immediately; do not wait for the PQC migration program.',
    standard: 'Current cryptographic hygiene',
    automatable: false
  }
];

// Live QA 2026-11-02 E1: nothing was found in Python, Go, C#, OpenSSL command lines or sshd_config. These
// rules apply only to their own file types (`files`), so a Go pattern never fires on Python, and each one
// names its language for the report's scope statement.
const PY = /\.py$/i, GO = /\.go$/i, CS = /\.cs$/i;
const SHELLISH = /(?:\.sh|\.bash|\.ps1|\.yml|\.yaml|\.mk|^dockerfile|^makefile|\.dockerfile)$/i;
const SSH_CONFIG = /^(?:sshd?_config|.*\.sshd?_config)$/i;
const LANGUAGE_RULES = [
  { id: 'QF-PY-RSA', language: 'Python', files: PY, severity: 'high', category: 'quantum-vulnerable-algorithm',
    pattern: /\brsa\.generate_private_key\s*\(|\bfrom\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+[^#\n]*\brsa\b|\bRSA\.(?:generate|import_key|importKey)\s*\(|\bPKCS1_(?:OAEP|v1_5)\.new\s*\(/,
    reason: 'Python RSA key generation or use (cryptography / PyCryptodome) is vulnerable to a cryptographically relevant quantum computer.',
    remediation: 'Inventory where the key signs or encrypts; plan ML-DSA (signatures) or ML-KEM / hybrid key exchange, for example via liboqs-python, behind an interface you can swap.',
    standard: 'NIST FIPS 203/204', automatable: false },
  { id: 'QF-PY-ECC', language: 'Python', files: PY, severity: 'high', category: 'quantum-vulnerable-algorithm',
    pattern: /\bec\.generate_private_key\s*\(|\bec\.(?:SECP256R1|SECP384R1|SECP521R1|SECP256K1)\s*\(|\b(?:Ed25519|Ed448|X25519|X448)PrivateKey\.generate\s*\(|\bECC\.generate\s*\(/,
    reason: 'Python elliptic-curve keys (ECDSA, ECDH, Ed25519, X25519) are vulnerable to a cryptographically relevant quantum computer.',
    remediation: 'Use a hybrid key exchange (X25519 + ML-KEM-768) during transition and plan ML-DSA or SLH-DSA for signatures.',
    standard: 'NIST FIPS 203/204/205', automatable: false },
  { id: 'QF-GO-RSA', language: 'Go', files: GO, severity: 'high', category: 'quantum-vulnerable-algorithm',
    pattern: /\brsa\.(?:GenerateKey|GenerateMultiPrimeKey|SignPKCS1v15|SignPSS|EncryptOAEP|EncryptPKCS1v15|DecryptOAEP)\s*\(|^\s*(?:import\s+)?"crypto\/rsa"/,
    reason: 'Go crypto/rsa key generation or use is vulnerable to a cryptographically relevant quantum computer.',
    remediation: 'Plan ML-DSA for signatures; for key exchange use crypto/mlkem (Go 1.24+) or a hybrid X25519MLKEM768 TLS group.',
    standard: 'NIST FIPS 203/204', automatable: false },
  { id: 'QF-GO-ECC', language: 'Go', files: GO, severity: 'high', category: 'quantum-vulnerable-algorithm',
    pattern: /\becdsa\.(?:GenerateKey|Sign|SignASN1)\s*\(|\belliptic\.P(?:224|256|384|521)\s*\(\s*\)|\becdh\.(?:P256|P384|P521|X25519)\s*\(\s*\)|\bed25519\.GenerateKey\s*\(|^\s*(?:import\s+)?"crypto\/(?:ecdsa|elliptic)"/,
    reason: 'Go elliptic-curve keys (crypto/ecdsa, crypto/elliptic, crypto/ecdh, ed25519) are vulnerable to a cryptographically relevant quantum computer.',
    remediation: 'Use X25519MLKEM768 in crypto/tls (default in Go 1.24+) and crypto/mlkem for key exchange; plan ML-DSA for signatures.',
    standard: 'NIST FIPS 203/204/205', automatable: false },
  { id: 'QF-CS-RSA', language: 'C#', files: CS, severity: 'high', category: 'quantum-vulnerable-algorithm',
    pattern: /\bRSA\.Create\s*\(|\bnew\s+RSA(?:CryptoServiceProvider|Cng|OpenSsl)\s*\(/,
    reason: '.NET RSA key creation is vulnerable to a cryptographically relevant quantum computer.',
    remediation: 'Plan ML-DSA / ML-KEM (System.Security.Cryptography.MLDsa and MLKem in .NET 10) behind an abstraction; keep RSA only where a dependency requires it.',
    standard: 'NIST FIPS 203/204', automatable: false },
  { id: 'QF-CS-ECC', language: 'C#', files: CS, severity: 'high', category: 'quantum-vulnerable-algorithm',
    pattern: /\bECDsa\.Create\s*\(|\bECDiffieHellman\.Create\s*\(|\bnew\s+ECDsa(?:Cng|OpenSsl)\s*\(|\bECCurve\.NamedCurves\.nistP(?:256|384|521)\b/,
    reason: '.NET elliptic-curve keys (ECDsa, ECDiffieHellman) are vulnerable to a cryptographically relevant quantum computer.',
    remediation: 'Use hybrid key exchange where the TLS stack supports it and plan ML-DSA / ML-KEM (.NET 10) for application keys.',
    standard: 'NIST FIPS 203/204', automatable: false },
  { id: 'QF-OPENSSL-CLI-RSA', language: 'OpenSSL CLI', files: SHELLISH, severity: 'high', category: 'quantum-vulnerable-algorithm',
    pattern: /\bopenssl\s+(?:genrsa\b|req\b[^#\n]*-newkey\s+rsa\b|genpkey\b[^#\n]*-algorithm\s+RSA\b)/i,
    reason: 'An OpenSSL command creates an RSA key, which is vulnerable to a cryptographically relevant quantum computer.',
    remediation: 'With OpenSSL 3.5+, generate ML-DSA keys (openssl genpkey -algorithm ML-DSA-65) where peers support them; otherwise record the key as transitional.',
    standard: 'NIST FIPS 204', automatable: false },
  { id: 'QF-OPENSSL-CLI-ECC', language: 'OpenSSL CLI', files: SHELLISH, severity: 'high', category: 'quantum-vulnerable-algorithm',
    pattern: /\bopenssl\s+(?:ecparam\b|genpkey\b[^#\n]*-algorithm\s+(?:EC|ED25519|ED448|X25519|X448)\b|req\b[^#\n]*-newkey\s+(?:ec|ed25519|ed448)\b)/i,
    reason: 'An OpenSSL command creates an elliptic-curve key, which is vulnerable to a cryptographically relevant quantum computer.',
    remediation: 'With OpenSSL 3.5+, use ML-DSA (signatures) or ML-KEM / X25519MLKEM768 (key exchange) where peers support them.',
    standard: 'NIST FIPS 203/204', automatable: false },
  { id: 'QF-SSH-CLASSICAL-KEX', language: 'OpenSSH config', files: SSH_CONFIG, severity: 'high', category: 'key-establishment',
    pattern: /^\s*KexAlgorithms\s+\S+/i, ignore: /mlkem768x25519|sntrup761x25519/i,
    reason: 'The SSH key exchange list has no post-quantum hybrid (mlkem768x25519-sha256 or sntrup761x25519-sha512).',
    remediation: 'Put mlkem768x25519-sha256 (OpenSSH 9.9+) and sntrup761x25519-sha512 first in KexAlgorithms, keeping a classical fallback.',
    standard: 'OpenSSH PQ hybrid key exchange', automatable: true },
  { id: 'QF-SSH-CLASSICAL-HOSTKEY', language: 'OpenSSH config', files: SSH_CONFIG, severity: 'medium', category: 'quantum-vulnerable-algorithm',
    pattern: /^\s*HostKey\s+\S*ssh_host_(?:rsa|ecdsa|ed25519|dsa)_key\b/i,
    reason: 'The SSH host key is a classical signature key; a quantum adversary could forge it in future (no PQ host key type is standard in OpenSSH yet).',
    remediation: 'Track: keep the host key inventory, prefer ed25519 over RSA now, and plan a PQ signature host key when OpenSSH ships one.',
    standard: 'NIST FIPS 204 (future SSH profile)', automatable: false },
];
RULES.push(...LANGUAGE_RULES);

// What this scanner reads, for the report's scope statement (E4d).
export const SCAN_COVERAGE = {
  languages: ['JavaScript/TypeScript (Node)', 'Java', 'Python', 'Go', 'C#', 'C/C++ (OpenSSL API names)'],
  configs: ['nginx', 'HAProxy', 'Apache mod_ssl', 'Envoy', 'OpenSSH (sshd_config, ssh_config)', 'OpenSSL command lines in shell scripts, Dockerfiles, Makefiles and CI YAML'],
  notCovered: [
    'Binaries, container images and installed packages (only source and config text is read)',
    'Cryptography inside third-party libraries the code calls (the call site is found, not the library internals)',
    'Kotlin, Rust, Ruby, PHP, Swift: only the generic RSA/ECC name rules apply, with no language-specific API rules',
    'Keys and certificates held in HSMs, cloud KMS or certificate stores',
    'Live TLS endpoints, unless a host cross-check (testssl.sh / sslyze) was run',
  ],
};

const HAPROXY_MISSING_GROUP_POLICY = {
  id: 'QF-HAPROXY-MISSING-GROUP-POLICY',
  severity: 'high',
  category: 'key-establishment',
  reason: 'HAProxy terminates TLS without an explicit hybrid-capable bind group policy.',
  remediation: 'Set ssl-default-bind-curves with X25519MLKEM768 and classical fallbacks on HAProxy linked to OpenSSL 3.5+.',
  standard: 'IETF TLS hybrid ML-KEM',
  automatable: true
};

const APACHE_MISSING_GROUP_POLICY = {
  id: 'QF-APACHE-MISSING-GROUP-POLICY',
  severity: 'high',
  category: 'key-establishment',
  reason: 'Apache mod_ssl enables TLS without an explicit hybrid-capable group policy.',
  remediation: 'Set SSLOpenSSLConfCmd Groups with X25519MLKEM768 and classical fallbacks on OpenSSL 3.5+.',
  standard: 'IETF TLS hybrid ML-KEM',
  automatable: true
};

const ENVOY_CLASSICAL_GROUPS = {
  id: 'QF-ENVOY-CLASSICAL-GROUPS',
  severity: 'high',
  category: 'key-establishment',
  reason: 'The Envoy TLS context declares an explicit ecdh_curves policy with no post-quantum or hybrid key exchange.',
  remediation: 'Prepend X25519MLKEM768 and retain classical fallbacks; requires Envoy linked against a BoringSSL build that advertises the hybrid group.',
  standard: 'IETF TLS hybrid ML-KEM',
  automatable: true
};

const ENVOY_MISSING_GROUP_POLICY = {
  id: 'QF-ENVOY-MISSING-GROUP-POLICY',
  severity: 'high',
  category: 'key-establishment',
  reason: 'The Envoy TLS context has no explicit ecdh_curves policy, so it relies on the linked BoringSSL build\'s default groups, which may not include a post-quantum hybrid.',
  remediation: 'Set tls_params.ecdh_curves to X25519MLKEM768 with classical fallbacks on an Envoy build with hybrid-capable BoringSSL.',
  standard: 'IETF TLS hybrid ML-KEM',
  automatable: true
};

const ENVOY_LEGACY_TLS = {
  id: 'QF-ENVOY-LEGACY-TLS',
  severity: 'medium',
  category: 'protocol-baseline',
  reason: 'The Envoy TLS context permits TLS 1.0/1.1, which cannot negotiate a PQC-capable TLS 1.3 handshake.',
  remediation: 'Raise tls_minimum_protocol_version to TLSv1_2 while retaining TLSv1_3 support.',
  standard: 'TLS 1.3',
  automatable: true
};

function isEnvoy(relativeFile, content) {
  return /envoy\.transport_sockets\.tls|(?:Downstream|Upstream)TlsContext/i.test(content)
    || /^envoy(?:\..*)?\.ya?ml$/i.test(path.basename(relativeFile));
}

// Envoy's bootstrap format is indentation-scoped YAML, not line-oriented like
// the other adapters' configs, so TLS contexts are located by indentation
// depth rather than a single-line regex. A "context" is the subtree rooted at
// a line naming Downstream/UpstreamTlsContext: it runs until indentation
// returns to at or below that line's own indentation.
function indentOf(line) {
  return line.match(/^[ \t]*/)[0].length;
}

function envoyTlsContexts(lines) {
  const contexts = [];
  for (let index = 0; index < lines.length; index += 1) {
    if (!/(?:Downstream|Upstream)TlsContext/i.test(lines[index])) continue;
    const markerIndent = indentOf(lines[index]);
    // The marker (typically an "@type" line) is one key among several
    // siblings under its parent (e.g. typed_config:), and the sibling that
    // actually carries tls_params/ecdh_curves is common_tls_context, not a
    // descendant of the marker itself. So the context's root is the marker's
    // *parent* indentation, found by walking back to the nearest strictly
    // shallower line; the context spans until indentation returns to or
    // below that root.
    let baseIndent = markerIndent;
    for (let cursor = index - 1; cursor >= 0; cursor -= 1) {
      if (lines[cursor].trim() === '') continue;
      const cursorIndent = indentOf(lines[cursor]);
      if (cursorIndent < markerIndent) { baseIndent = cursorIndent; break; }
    }
    let end = lines.length;
    for (let cursor = index + 1; cursor < lines.length; cursor += 1) {
      if (lines[cursor].trim() === '') continue;
      if (indentOf(lines[cursor]) <= baseIndent) { end = cursor; break; }
    }
    contexts.push({ start: index, end });
  }
  return contexts;
}

function envoyCurvesList(lines, curvesLineIndex) {
  const baseIndent = indentOf(lines[curvesLineIndex]);
  const curves = [];
  for (let cursor = curvesLineIndex + 1; cursor < lines.length; cursor += 1) {
    if (lines[cursor].trim() === '') continue;
    // YAML allows a block sequence's "- item" markers to sit at the same
    // indentation as their key (the common style) or deeper (also legal);
    // anything shallower than the key means the list has ended.
    if (indentOf(lines[cursor]) < baseIndent) break;
    const item = lines[cursor].match(/^\s*-\s*(\S+)/);
    if (item) curves.push(item[1]);
    else break;
  }
  return curves;
}

function envoyFindings(relativeFile, lines) {
  const findings = [];
  for (const context of envoyTlsContexts(lines)) {
    let curvesLine = -1;
    let minVersionLine = -1;
    for (let index = context.start; index < context.end; index += 1) {
      if (curvesLine === -1 && /^\s*ecdh_curves\s*:/.test(lines[index])) curvesLine = index;
      if (minVersionLine === -1 && /^\s*tls_minimum_protocol_version\s*:\s*TLSv1_[01]\b/.test(lines[index])) minVersionLine = index;
    }
    if (curvesLine >= 0) {
      const curves = envoyCurvesList(lines, curvesLine);
      if (curves.length > 0 && !curves.some((curve) => /MLKEM|KYBER/i.test(curve))) {
        findings.push(lineFinding(ENVOY_CLASSICAL_GROUPS, relativeFile, lines[curvesLine], curvesLine + 1));
      }
    } else {
      findings.push(lineFinding(ENVOY_MISSING_GROUP_POLICY, relativeFile, lines[context.start], context.start + 1));
    }
    if (minVersionLine >= 0) {
      findings.push(lineFinding(ENVOY_LEGACY_TLS, relativeFile, lines[minVersionLine], minVersionLine + 1));
    }
  }
  return findings;
}

function apacheMissingPolicyLines(lines) {
  let depth = 0;
  let globalPolicy = false;
  for (const line of lines) {
    if (/^\s*<VirtualHost\b/i.test(line)) depth += 1;
    if (depth === 0 && /^\s*SSLOpenSSLConfCmd\s+(?:Groups|Curves)\s+/i.test(line)) globalPolicy = true;
    if (/^\s*<\/VirtualHost\s*>/i.test(line)) depth = Math.max(0, depth - 1);
  }
  if (globalPolicy) return [];
  const missing = [];
  const seenContexts = new Set();
  for (let index = 0; index < lines.length; index += 1) {
    if (!/^\s*SSLEngine\s+on\b/i.test(lines[index])) continue;
    let start = 0;
    let open = -1;
    for (let cursor = 0; cursor <= index; cursor += 1) {
      if (/^\s*<VirtualHost\b/i.test(lines[cursor])) open = cursor;
      if (/^\s*<\/VirtualHost\s*>/i.test(lines[cursor])) open = -1;
    }
    if (open >= 0) start = open;
    let end = lines.length;
    if (open >= 0) {
      const closeOffset = lines.slice(index + 1).findIndex((line) => /^\s*<\/VirtualHost\s*>/i.test(line));
      if (closeOffset >= 0) end = index + 1 + closeOffset + 1;
    }
    const context = `${start}:${end}`;
    if (!seenContexts.has(context) && !lines.slice(start, end).some((line) => /^\s*SSLOpenSSLConfCmd\s+(?:Groups|Curves)\s+/i.test(line))) {
      missing.push(index);
      seenContexts.add(context);
    }
  }
  return missing;
}

async function walk(root, current = root, output = []) {
  const entries = await fs.readdir(current, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isDirectory() && SKIP_DIRECTORIES.has(entry.name)) continue;
    const absolute = path.join(current, entry.name);
    if (entry.isDirectory()) await walk(root, absolute, output);
    else if (entry.isFile() && !entry.name.startsWith('.pqc-forge-ignore') && isTextFile(entry.name)) output.push(absolute);
  }
  return output;
}

function isTextFile(name) {
  const lower = name.toLowerCase();
  return TEXT_EXTENSIONS.has(path.extname(lower)) || [
    'dockerfile', 'makefile', 'nginx.conf', 'haproxy.cfg', 'caddyfile', 'sshd_config', 'ssh_config'
  ].includes(lower) || /\.sshd?_config$|\.ps1$|\.bash$|\.mk$|\.dockerfile$/.test(lower);
}

function lineFinding(rule, relativeFile, line, lineNumber) {
  return {
    id: rule.id,
    ...(rule.language ? { language: rule.language } : {}),
    severity: rule.severity,
    category: rule.category,
    file: relativeFile,
    line: lineNumber,
    excerpt: line.trim().slice(0, 240),
    reason: rule.reason,
    remediation: rule.remediation,
    standard: rule.standard,
    automatable: rule.automatable
  };
}

function globRegex(pattern) {
  const source = String(pattern).replace(/\\/g, '/');
  let regex = '^';
  for (let index = 0; index < source.length; index += 1) {
    const char = source[index];
    if (char === '*' && source[index + 1] === '*') { regex += '.*'; index += 1; }
    else if (char === '*') regex += '[^/]*';
    else if (char === '?') regex += '[^/]';
    else regex += /[.\^$+{}()|[\]\\]/.test(char) ? `\\${char}` : char;
  }
  return new RegExp(`${regex}$`, 'i');
}

async function readSuppressions(root, ignoreFile) {
  if (ignoreFile === null) return { source: null, suppressions: [] };
  const source = ignoreFile ? path.resolve(ignoreFile) : path.join(root, '.pqc-forge-ignore.json');
  try {
    const document = JSON.parse(await fs.readFile(source, 'utf8'));
    if (document.schema !== 'pqc-forge.ignore/v1' || !Array.isArray(document.suppressions)) {
      throw new Error('expected schema pqc-forge.ignore/v1 and a suppressions array');
    }
    for (const item of document.suppressions) {
      if (!item.ruleId || !item.path || !item.reason || !item.expires) {
        throw new Error('each suppression requires ruleId, path, reason, and expires');
      }
      if (Number.isNaN(Date.parse(item.expires))) throw new Error(`invalid expiry: ${item.expires}`);
    }
    return { source, suppressions: document.suppressions };
  } catch (error) {
    if (!ignoreFile && error.code === 'ENOENT') return { source: null, suppressions: [] };
    throw new Error(`Invalid PQC Forge ignore file ${source}: ${error.message}`);
  }
}

function applicableSuppression(finding, suppressions, now) {
  return suppressions.find((item) =>
    (item.ruleId === '*' || item.ruleId === finding.id)
    && globRegex(item.path).test(finding.file.replace(/\\/g, '/'))
    && Date.parse(item.expires) >= now.getTime());
}

export async function scanRepository(rootPath, { ignoreFile, now = new Date(), overrides = new Map() } = {}) {
  const root = path.resolve(rootPath);
  const stat = await fs.stat(root);
  const suppressionRoot = stat.isDirectory() ? root : path.dirname(root);
  const suppressionConfig = await readSuppressions(suppressionRoot, ignoreFile);
  const files = stat.isDirectory() ? await walk(root) : [root];
  const findings = [];
  const suppressedFindings = [];

  for (const file of files) {
    let content;
    try {
      const relativeFile = stat.isDirectory() ? path.relative(root, file) : path.basename(file);
      content = overrides.has(relativeFile) ? overrides.get(relativeFile) : await fs.readFile(file, 'utf8');
    } catch {
      continue;
    }
    const relativeFile = stat.isDirectory() ? path.relative(root, file) : path.basename(file);
    const lines = content.split(/\r?\n/);
    const baseName = path.basename(relativeFile);
    const rules = RULES.filter((rule) => !rule.files || rule.files.test(baseName));
    // A commented-out line in Python, Go, C# or a shell script is not live code (configs keep their own handling).
    const skipComments = /\.(?:py|go|cs|sh|bash|ps1)$/i.test(baseName);
    for (let index = 0; index < lines.length; index += 1) {
      if (skipComments && /^\s*(?:#|\/\/)/.test(lines[index])) continue;
      for (const rule of rules) {
        if (rule.pattern.test(lines[index]) && !(rule.ignore?.test(lines[index]))) {
          const finding = lineFinding(rule, relativeFile, lines[index], index + 1);
          const suppression = applicableSuppression(finding, suppressionConfig.suppressions, now);
          if (suppression) suppressedFindings.push({ ...finding, suppression: { reason: suppression.reason, expires: suppression.expires } });
          else findings.push(finding);
        }
      }
    }
    const haproxyShape = path.basename(relativeFile).toLowerCase() === 'haproxy.cfg'
      || (/^\s*global\s*$/im.test(content) && /^\s*(?:frontend|listen)\s+\S+/im.test(content));
    const tlsBindIndex = lines.findIndex((line) => /^\s*bind\s+[^#]*\bssl\b/i.test(line));
    const hasBindGroupPolicy = lines.some((line) => /^\s*ssl-default-bind-curves\s+/i.test(line))
      || lines.filter((line) => /^\s*bind\s+[^#]*\bssl\b/i.test(line)).every((line) => /\bcurves\s+[^#\s]*(?:MLKEM|KYBER)/i.test(line));
    if (haproxyShape && tlsBindIndex >= 0 && !hasBindGroupPolicy) {
      const finding = lineFinding(HAPROXY_MISSING_GROUP_POLICY, relativeFile, lines[tlsBindIndex], tlsBindIndex + 1);
      const suppression = applicableSuppression(finding, suppressionConfig.suppressions, now);
      if (suppression) suppressedFindings.push({ ...finding, suppression: { reason: suppression.reason, expires: suppression.expires } });
      else findings.push(finding);
    }
    for (const lineIndex of apacheMissingPolicyLines(lines)) {
      const finding = lineFinding(APACHE_MISSING_GROUP_POLICY, relativeFile, lines[lineIndex], lineIndex + 1);
      const suppression = applicableSuppression(finding, suppressionConfig.suppressions, now);
      if (suppression) suppressedFindings.push({ ...finding, suppression: { reason: suppression.reason, expires: suppression.expires } });
      else findings.push(finding);
    }
    if (isEnvoy(relativeFile, content)) {
      for (const finding of envoyFindings(relativeFile, lines)) {
        const suppression = applicableSuppression(finding, suppressionConfig.suppressions, now);
        if (suppression) suppressedFindings.push({ ...finding, suppression: { reason: suppression.reason, expires: suppression.expires } });
        else findings.push(finding);
      }
    }
  }

  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]
    || a.file.localeCompare(b.file) || a.line - b.line);

  return {
    schema: 'pqc-forge.scan/v1',
    generatedAt: new Date().toISOString(),
    root,
    filesScanned: files.length,
    summary: findings.reduce((result, finding) => {
      result.total += 1;
      result[finding.severity] += 1;
      if (finding.automatable) result.automatable += 1;
      return result;
    }, { total: 0, critical: 0, high: 0, medium: 0, low: 0, automatable: 0, suppressed: suppressedFindings.length }),
    suppressionFile: suppressionConfig.source,
    findings,
    suppressedFindings
  };
}
