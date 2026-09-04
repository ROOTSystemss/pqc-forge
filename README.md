# pqc-forge

A small CLI/library for signing and verifying files with **ML-DSA-65**
(NIST FIPS 204, formerly CRYSTALS-Dilithium), a post-quantum digital
signature algorithm. Built on [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum),
an audited, pure-JS/TS implementation.

## Install

```sh
npm install
npm run build
```

## Usage

```sh
# Generate a keypair (defaults to ~/.pqc-forge/signing-key.json)
node dist/cli.js keygen

# Sign a file -> writes <file>.sig.json next to it
node dist/cli.js sign ./release.tar.gz

# Verify a file against its signature
node dist/cli.js verify ./release.tar.gz
```

Pass `-k <path>` to use a different key file, `-o <path>` to control
output locations, and `-s <path>` to point `verify` at a signature file
that isn't named `<file>.sig.json`.

## File formats

**Key file** (`pqc-forge.signing-key/v1`):

```json
{
  "schema": "pqc-forge.signing-key/v1",
  "algorithm": "ML-DSA-65",
  "keyId": "sha256:<hex>",
  "createdAt": "<ISO 8601>",
  "publicKey": "<base64>",
  "secretKey": "<base64>"
}
```

`keyId` is `sha256` of the base64-encoded public key string, and is
recomputed and checked whenever a key file is loaded.

**Signature file** (`pqc-forge.signature/v1`):

```json
{
  "schema": "pqc-forge.signature/v1",
  "algorithm": "ML-DSA-65",
  "keyId": "sha256:<hex>",
  "createdAt": "<ISO 8601>",
  "digestAlgorithm": "sha256",
  "digest": "<hex sha256 of the signed bytes>",
  "signature": "<base64>"
}
```

## Security notes

- Secret keys are written with mode `0600`, but Windows filesystems
  don't enforce POSIX permission bits the way this expects — treat the
  key file itself as the trust boundary and restrict folder ACLs if
  needed.
- `keygen` refuses to overwrite an existing key file unless `--force`
  is passed.
- `verify` checks, in order: algorithm match, keyId match, message
  digest match, then the ML-DSA-65 cryptographic signature itself.

## Status

Early scaffold: keygen / sign / verify for ML-DSA-65 only. Not yet
published or hardened for production use.
