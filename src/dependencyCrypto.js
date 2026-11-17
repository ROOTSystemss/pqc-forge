// AD-070 (knock-out Phase 5): which declared libraries bring in public-key cryptography (RSA/ECC) and which are
// post-quantum capable. Reads dependency manifests only (package.json, requirements*.txt, pyproject.toml, go.mod,
// pom.xml, Cargo.toml, *.csproj, Gemfile, composer.json); DECLARED dependencies, not the resolved transitive tree,
// and only libraries in the fixed table below (anything else is not listed - it is not claimed to be crypto-free).
import { promises as fs } from 'node:fs';
import path from 'node:path';

const C = 'classical public-key (RSA/ECC)', P = 'post-quantum capable', S = 'symmetric / hashing only', B = 'classical public-key, post-quantum capable';
// [ecosystem, name (lowercase), class, what it provides]
const TABLE = [
  ['npm', 'node-forge', C, 'RSA, X.509, TLS'], ['npm', 'jsonwebtoken', C, 'RS*/ES* JWT signatures'], ['npm', 'jose', C, 'RSA/ECDSA/EdDSA JOSE'],
  ['npm', 'elliptic', C, 'ECDSA/ECDH'], ['npm', 'node-rsa', C, 'RSA'], ['npm', '@noble/curves', C, 'ECDSA/EdDSA/ECDH'], ['npm', 'tweetnacl', C, 'Ed25519/X25519'],
  ['npm', 'openpgp', C, 'RSA/ECC OpenPGP'], ['npm', 'ssh2', C, 'SSH RSA/ECDSA/Ed25519'], ['npm', '@peculiar/x509', C, 'X.509 RSA/ECDSA'],
  ['npm', '@noble/post-quantum', P, 'ML-KEM, ML-DSA, SLH-DSA'], ['npm', 'crypto-js', S, 'AES, SHA'], ['npm', 'bcrypt', S, 'password hashing'], ['npm', 'bcryptjs', S, 'password hashing'],
  ['pypi', 'cryptography', C, 'RSA/ECC, X.509, AES'], ['pypi', 'pycryptodome', C, 'RSA/ECC, AES'], ['pypi', 'pycryptodomex', C, 'RSA/ECC, AES'], ['pypi', 'pyjwt', C, 'RS*/ES* JWT'],
  ['pypi', 'paramiko', C, 'SSH RSA/ECDSA'], ['pypi', 'rsa', C, 'RSA'], ['pypi', 'ecdsa', C, 'ECDSA'], ['pypi', 'pynacl', C, 'Ed25519/X25519'], ['pypi', 'pyopenssl', C, 'RSA/ECC, TLS'],
  ['pypi', 'liboqs-python', P, 'liboqs ML-KEM/ML-DSA'], ['pypi', 'oqs', P, 'liboqs ML-KEM/ML-DSA'], ['pypi', 'pqcrypto', P, 'PQ KEM/signatures'], ['pypi', 'bcrypt', S, 'password hashing'],
  ['go', 'golang.org/x/crypto', C, 'SSH, ECDH, Ed25519'], ['go', 'github.com/golang-jwt/jwt', C, 'RS*/ES* JWT'], ['go', 'github.com/golang-jwt/jwt/v5', C, 'RS*/ES* JWT'],
  ['go', 'github.com/cloudflare/circl', B, 'ECC + ML-KEM/ML-DSA'], ['go', 'github.com/open-quantum-safe/liboqs-go', P, 'liboqs'],
  ['maven', 'org.bouncycastle:bcprov-jdk18on', B, 'RSA/ECC + ML-KEM/ML-DSA'], ['maven', 'org.bouncycastle:bcprov-jdk15on', C, 'RSA/ECC (older line)'],
  ['maven', 'com.nimbusds:nimbus-jose-jwt', C, 'RSA/ECDSA JOSE'], ['maven', 'io.jsonwebtoken:jjwt', C, 'RS*/ES* JWT'], ['maven', 'io.jsonwebtoken:jjwt-api', C, 'RS*/ES* JWT'],
  ['cargo', 'rsa', C, 'RSA'], ['cargo', 'ring', C, 'RSA/ECDSA/Ed25519'], ['cargo', 'p256', C, 'ECDSA P-256'], ['cargo', 'ed25519-dalek', C, 'Ed25519'], ['cargo', 'x25519-dalek', C, 'X25519'],
  ['cargo', 'pqcrypto', P, 'PQ KEM/signatures'], ['cargo', 'oqs', P, 'liboqs'], ['cargo', 'ml-kem', P, 'ML-KEM'], ['cargo', 'ml-dsa', P, 'ML-DSA'],
  ['nuget', 'bouncycastle.cryptography', B, 'RSA/ECC + ML-KEM/ML-DSA'], ['nuget', 'portable.bouncycastle', C, 'RSA/ECC (older line)'], ['nuget', 'system.identitymodel.tokens.jwt', C, 'RS*/ES* JWT'],
  ['gem', 'jwt', C, 'RS*/ES* JWT'], ['gem', 'rbnacl', C, 'Ed25519/X25519'], ['gem', 'net-ssh', C, 'SSH RSA/ECDSA'],
  ['composer', 'firebase/php-jwt', C, 'RS*/ES* JWT'], ['composer', 'phpseclib/phpseclib', C, 'RSA/ECC, SSH'],
];
const LOOKUP = new Map(TABLE.map(([eco, name, cls, provides]) => [`${eco}:${name}`, { cls, provides }]));

const parsers = {
  'package.json': (t) => { const j = JSON.parse(t); return Object.entries({ ...(j.dependencies || {}), ...(j.devDependencies || {}), ...(j.optionalDependencies || {}) }).map(([n, v]) => ['npm', n, String(v)]); },
  'composer.json': (t) => { const j = JSON.parse(t); return Object.entries({ ...(j.require || {}), ...(j['require-dev'] || {}) }).map(([n, v]) => ['composer', n, String(v)]); },
  'go.mod': (t) => [...t.matchAll(/^\s*(?:require\s+)?([a-z0-9.\-]+\.[a-z]{2,}\/[^\s]+)\s+(v[^\s]+)/gim)].map((m) => ['go', m[1], m[2]]),
  'Cargo.toml': (t) => { const sec = (t.split(/^\[(?:dev-)?dependencies\]\s*$/m).slice(1).join('\n').split(/^\[/m)[0]) || ''; return [...sec.matchAll(/^\s*([A-Za-z0-9_\-]+)\s*=\s*(?:"([^"]+)"|\{[^}]*version\s*=\s*"([^"]+)")/gm)].map((m) => ['cargo', m[1], m[2] || m[3] || '']); },
  'pom.xml': (t) => [...t.matchAll(/<dependency>[\s\S]*?<groupId>([^<]+)<\/groupId>[\s\S]*?<artifactId>([^<]+)<\/artifactId>(?:[\s\S]*?<version>([^<]+)<\/version>)?[\s\S]*?<\/dependency>/g)].map((m) => ['maven', `${m[1].trim()}:${m[2].trim()}`, (m[3] || '').trim()]),
  'Gemfile': (t) => [...t.matchAll(/^\s*gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?/gm)].map((m) => ['gem', m[1], m[2] || '']),
  'pyproject.toml': (t) => { const deps = (t.match(/dependencies\s*=\s*\[([\s\S]*?)\]/) || [])[1] || ''; return [...deps.matchAll(/"([A-Za-z0-9_.\-]+)\s*([^"]*)"/g)].map((m) => ['pypi', m[1], m[2].trim()]); },
};
const reqTxt = (t) => t.split(/\r?\n/).map((l) => l.replace(/#.*/, '').trim()).filter((l) => l && !l.startsWith('-')).map((l) => { const m = l.match(/^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(.*)$/); return m ? ['pypi', m[1], m[2]] : null; }).filter(Boolean);
const csproj = (t) => [...t.matchAll(/<PackageReference\s+Include="([^"]+)"(?:\s+Version="([^"]+)")?/g)].map((m) => ['nuget', m[1], m[2] || '']);

function parserFor(name) {
  if (parsers[name]) return parsers[name];
  if (/^requirements.*\.txt$/i.test(name)) return reqTxt;
  if (/\.csproj$/i.test(name)) return csproj;
  return null;
}

export async function scanDependencies(root, { maxFiles = 200 } = {}) {
  const rows = [], manifests = [], unreadable = [];
  const walk = async (dir) => {
    let entries = [];
    try { entries = await fs.readdir(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (manifests.length + unreadable.length >= maxFiles) return;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) { if (!['node_modules', '.git', 'vendor', 'target', 'dist', '.venv'].includes(e.name)) await walk(full); continue; }
      const parse = parserFor(e.name);
      if (!parse) continue;
      const rel = path.relative(root, full).split(path.sep).join('/');
      try {
        const deps = parse(await fs.readFile(full, 'utf8'));
        manifests.push(rel);
        for (const [eco, name, version] of deps) {
          const hit = LOOKUP.get(`${eco}:${String(name).toLowerCase()}`);
          if (hit) rows.push({ file: rel, ecosystem: eco, name, version: String(version || '').slice(0, 40), class: hit.cls, provides: hit.provides });
        }
      } catch { unreadable.push(rel); }
    }
  };
  await walk(root);
  const n = (c) => rows.filter((r) => r.class === c).length;
  return {
    method: 'Declared dependencies in manifest files only (not the resolved transitive tree), matched against a fixed list of known cryptography libraries. Libraries not on the list are not shown; that does not mean they contain no cryptography. Manifests that could not be parsed are listed and were not checked.',
    manifests, unreadableManifests: unreadable,
    summary: { libraries: rows.length, classicalPublicKey: n(C) + n(B), postQuantumCapable: n(P) + n(B), symmetricOnly: n(S) },
    libraries: rows,
  };
}
