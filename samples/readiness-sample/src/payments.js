// SAMPLE CODE for the public PQC Readiness Report sample (made up; not anyone's real code).
// Deliberately uses classical cryptography so the sample report has findings to show.
const crypto = require('crypto');

// Signs payment instructions with RSA-2048 (classical; not post-quantum).
function makeSigningKeys() {
  return crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
}

function signInstruction(privateKey, instruction) {
  return crypto.sign('sha256', Buffer.from(JSON.stringify(instruction)), privateKey);
}

// Key agreement with a partner bank over ECDH P-256 (classical).
function bankKeyAgreement() {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  return ecdh;
}

// Legacy checksum kept for an old partner (SHA-1).
function legacyChecksum(data) {
  return crypto.createHash('sha1').update(data).digest('hex');
}

module.exports = { makeSigningKeys, signInstruction, bankKeyAgreement, legacyChecksum };
