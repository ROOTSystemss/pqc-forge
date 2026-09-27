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
    'dockerfile', 'makefile', 'nginx.conf', 'haproxy.cfg', 'caddyfile'
  ].includes(lower);
}

function lineFinding(rule, relativeFile, line, lineNumber) {
  return {
    id: rule.id,
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
    for (let index = 0; index < lines.length; index += 1) {
      for (const rule of RULES) {
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
