// SAMPLE CODE for the public PQC Readiness Report sample (made up; not anyone's real code).
const crypto = require('crypto');

// Session tokens signed with ECDSA P-256 (classical).
function sessionKeys() {
  return crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
}

// Data at rest: AES-256-GCM (symmetric; fine against quantum attacks at this key size).
function seal(key, plaintext) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const out = Buffer.concat([c.update(plaintext), c.final()]);
  return { iv, out, tag: c.getAuthTag() };
}

module.exports = { sessionKeys, seal };
