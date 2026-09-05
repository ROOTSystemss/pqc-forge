# pqc-forge

A small CLI/library for post-quantum file **signing** (ML-DSA-65) and
**encryption** (ML-KEM-768 + AES-256-GCM), built on
[`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum),
an audited, pure-JS/TS implementation of the NIST FIPS 203/204 standards
(formerly CRYSTALS-Kyber/Dilithium).

## Install

```sh
npm install
npm run build
npm link   # optional: puts `pqc-forge` on your PATH globally
```

## Usage

### Signing (ML-DSA-65)

```sh
# Generate a signing keypair (defaults to ~/.pqc-forge/signing-key.json)
pqc-forge keygen

# Sign a file -> writes <file>.sig.json next to it
pqc-forge sign ./release.tar.gz

# Verify a file against its signature (see "Sharing keys" below for
# why this normally uses a public-only export, not your full key file)
pqc-forge verify ./release.tar.gz
```

### Encryption (ML-KEM-768 + AES-256-GCM)

```sh
# Generate a KEM keypair (defaults to ~/.pqc-forge/kem-key.json)
pqc-forge kem-keygen

# Encrypt a file for the holder of a KEM public key -> <file>.enc.json
pqc-forge encrypt ./message.txt -k recipient-kem-key.json

# Decrypt it with the matching secret key
pqc-forge decrypt ./message.txt.enc.json -k recipient-kem-key.json -o message.txt
```

Encryption is hybrid: an ML-KEM-768 encapsulation establishes a shared
secret per file, HKDF-SHA256 derives a one-time AES-256-GCM key from it,
and that key encrypts the file content. A fresh KEM encapsulation and IV
are used every time, even for the same plaintext and recipient.

Pass `-k <path>` to use a different key file, `-o <path>` to control
output locations, and (for `verify`) `-s <path>` to point at a signature
file that isn't named `<file>.sig.json`.

### Sharing keys with someone else

`keygen`/`kem-keygen` write a file containing **both** halves of the
keypair. That's fine for your own use, but the whole point of public-key
crypto is that other people only ever need your *public* key — to give
someone the ability to verify your signatures or encrypt files to you
without also handing them the power to sign as you or read everything
encrypted to you, strip the secret key first:

```sh
pqc-forge export-pubkey ./signing-key.json -o alice-signing.pub.json
pqc-forge export-pubkey ./kem-key.json     -o alice-kem.pub.json
```

The resulting file has the same `keyId` and schema, just no `secretKey`
field. `verify` and `encrypt` both work fine against a public-only file;
`sign` and `decrypt` fail with a clear error if you point them at one
("this key file has no secret key...").

## Web app

A local web UI for everything above — no CLI needed — lives alongside
the library as two workspaces:

- `server/` — a small Express API (binds to `127.0.0.1` only) that
  calls the same library functions the CLI uses.
- `web/` — a React + Vite frontend with a tab per operation (Keys,
  Sign, Verify, Encrypt, Decrypt), talking to the API through Vite's
  dev proxy.

```sh
npm install     # once, from the repo root — installs all workspaces
npm run dev     # builds the lib in watch mode, and runs server + web together
```

Then open the URL Vite prints (`http://127.0.0.1:5173`). Keys/files
never leave your machine — the server is local-only and doesn't
persist anything; generated keys and results download straight to your
browser's downloads folder.

## File formats

**Signing key file** (`pqc-forge.signing-key/v1`):

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

**KEM key file** (`pqc-forge.kem-key/v1`) has the same shape with
`algorithm: "ML-KEM-768"`.

`secretKey` is omitted entirely from a public-only export produced by
`export-pubkey` (see "Sharing keys" above) — everything else about the
file is unchanged.

For both, `keyId` is `sha256` of the base64-encoded public key *string*
(not the raw public key bytes), and is recomputed and checked whenever a
key file is loaded.

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

**Encrypted file** (`pqc-forge.encrypted/v1`):

```json
{
  "schema": "pqc-forge.encrypted/v1",
  "kemAlgorithm": "ML-KEM-768",
  "cipherAlgorithm": "AES-256-GCM",
  "keyId": "sha256:<hex>",
  "createdAt": "<ISO 8601>",
  "kemCiphertext": "<base64>",
  "iv": "<base64>",
  "authTag": "<base64>",
  "ciphertext": "<base64>"
}
```

## Security notes

- Secret keys are written with mode `0600`, but Windows filesystems
  don't enforce POSIX permission bits the way this expects — treat the
  key file itself as the trust boundary and restrict folder ACLs if
  needed.
- `keygen` / `kem-keygen` refuse to overwrite an existing key file
  unless `--force` is passed.
- `verify` checks, in order: algorithm match, keyId match, message
  digest match, then the ML-DSA-65 cryptographic signature itself.
- `decrypt` checks schema/algorithm/keyId, then relies on AES-256-GCM's
  authentication tag to reject any tampered ciphertext or wrong key —
  both surface as a generic "decryption failed" error by design (no
  detail that would help an attacker distinguish the two).

## Testing & CI

```sh
npm test
```

Runs the `node:test`-based suite: unit tests for the key/sign/KEM/
encrypt library functions (sizing, determinism, tamper detection, public-
key export, wrong-key and tampered-ciphertext rejection) plus integration
tests that spawn the real compiled CLI end-to-end. GitHub Actions
(`.github/workflows/ci.yml`) runs the same on Node 20.x/22.x across
Linux and Windows on every push/PR once this repo has a remote.

## Status

Signing (ML-DSA-65) and encryption (ML-KEM-768 + AES-256-GCM) are
implemented and tested, including public-key-only export/sharing;
`pqc-forge` can be `npm link`ed as a global command. A local web app
(`server/` + `web/`, see above) wraps all of it in a UI. CI runs on
push/PR against the GitHub remote. Not yet: an npm publish.
