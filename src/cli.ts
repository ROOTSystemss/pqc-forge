#!/usr/bin/env node
import { Command } from "commander";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import {
  generateKeyPair,
  toKeyFile,
  toPublicKeyFile,
  parseKeyFile,
  keyFileToPair,
  keyFileToPublicKey,
  KEY_SCHEMA,
  type SigningKeyFile,
} from "./keys.js";
import { buildSignatureFile, verifySignatureFile, type SignatureFile } from "./sign.js";
import {
  generateKemKeyPair,
  toKemKeyFile,
  toKemPublicKeyFile,
  parseKemKeyFile,
  kemKeyFileToPair,
  kemKeyFileToPublicKey,
  KEM_KEY_SCHEMA,
  type KemKeyFile,
} from "./kem.js";
import { encryptForRecipient, decryptWithKey, type EncryptedFile } from "./encrypt.js";

const DEFAULT_KEY_PATH = join(homedir(), ".pqc-forge", "signing-key.json");
const DEFAULT_KEM_KEY_PATH = join(homedir(), ".pqc-forge", "kem-key.json");

function loadKeyFile(path: string): SigningKeyFile {
  if (!existsSync(path)) {
    throw new Error(`no key found at ${path} (run "pqc-forge keygen" first)`);
  }
  return parseKeyFile(readFileSync(path, "utf8"));
}

function loadKemKeyFile(path: string): KemKeyFile {
  if (!existsSync(path)) {
    throw new Error(`no KEM key found at ${path} (run "pqc-forge kem-keygen" first)`);
  }
  return parseKemKeyFile(readFileSync(path, "utf8"));
}

function writeKeyFileSafely(path: string, contents: string, force: boolean): boolean {
  if (existsSync(path) && !force) {
    console.error(`refusing to overwrite existing key at ${path} (pass --force to replace it)`);
    process.exitCode = 1;
    return false;
  }
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, contents, { mode: 0o600 });
  return true;
}

function readInputFile(path: string): Buffer {
  if (!existsSync(path)) {
    throw new Error(`input file not found: ${path}`);
  }
  return readFileSync(path);
}

function readJsonFile<T>(path: string, kind: string): T {
  if (!existsSync(path)) {
    throw new Error(`${kind} not found: ${path}`);
  }
  const raw = readFileSync(path, "utf8");
  try {
    return JSON.parse(raw) as T;
  } catch {
    throw new Error(`${kind} at ${path} is not valid JSON (corrupt or truncated file?)`);
  }
}

/** Wraps a command action so thrown Errors become a clean "Error: ..." line + exit 1 instead of a raw stack trace. */
function action<Args extends unknown[]>(fn: (...args: Args) => void): (...args: Args) => void {
  return (...args: Args) => {
    try {
      fn(...args);
    } catch (err) {
      console.error(`Error: ${(err as Error).message}`);
      process.exitCode = 1;
    }
  };
}

const program = new Command();

program
  .name("pqc-forge")
  .description("Post-quantum file signing (ML-DSA-65) and encryption (ML-KEM-768 + AES-256-GCM)")
  .version("0.1.0");

program
  .command("keygen")
  .description("Generate a new ML-DSA-65 signing keypair")
  .option("-o, --out <path>", "path to write the key file", DEFAULT_KEY_PATH)
  .option("-f, --force", "overwrite an existing key file", false)
  .action(
    action((opts: { out: string; force: boolean }) => {
      const keyFile = toKeyFile(generateKeyPair());
      if (writeKeyFileSafely(opts.out, JSON.stringify(keyFile, null, 2) + "\n", opts.force)) {
        console.log(`wrote ${keyFile.algorithm} key ${keyFile.keyId} to ${opts.out}`);
      }
    }),
  );

program
  .command("kem-keygen")
  .description("Generate a new ML-KEM-768 key-encapsulation keypair")
  .option("-o, --out <path>", "path to write the key file", DEFAULT_KEM_KEY_PATH)
  .option("-f, --force", "overwrite an existing key file", false)
  .action(
    action((opts: { out: string; force: boolean }) => {
      const keyFile = toKemKeyFile(generateKemKeyPair());
      if (writeKeyFileSafely(opts.out, JSON.stringify(keyFile, null, 2) + "\n", opts.force)) {
        console.log(`wrote ${keyFile.algorithm} key ${keyFile.keyId} to ${opts.out}`);
      }
    }),
  );

program
  .command("export-pubkey")
  .description("Strip the secret key from a signing or KEM key file, producing a file safe to share")
  .argument("<key-file>", "path to a full pqc-forge signing-key or kem-key file")
  .option("-o, --out <path>", "path to write the public-only key file (default: <key-file> with .pub.json before the extension)")
  .action(
    action((keyFilePath: string, opts: { out?: string }) => {
      const raw = readJsonFile<{ schema?: string }>(keyFilePath, "key file");
      let publicOnly: SigningKeyFile | KemKeyFile;
      if (raw.schema === KEY_SCHEMA) {
        publicOnly = toPublicKeyFile(parseKeyFile(readFileSync(keyFilePath, "utf8")));
      } else if (raw.schema === KEM_KEY_SCHEMA) {
        publicOnly = toKemPublicKeyFile(parseKemKeyFile(readFileSync(keyFilePath, "utf8")));
      } else {
        throw new Error(
          `unrecognized key schema: ${raw.schema} (expected "${KEY_SCHEMA}" or "${KEM_KEY_SCHEMA}")`,
        );
      }
      const outPath = opts.out ?? keyFilePath.replace(/(\.json)?$/, ".pub.json");
      writeFileSync(outPath, JSON.stringify(publicOnly, null, 2) + "\n");
      console.log(`wrote public-only ${publicOnly.algorithm} key ${publicOnly.keyId} to ${outPath}`);
    }),
  );

program
  .command("sign")
  .description("Sign a file")
  .argument("<file>", "path to the file to sign")
  .option("-k, --key <path>", "path to the signing key file", DEFAULT_KEY_PATH)
  .option("-o, --out <path>", "path to write the .sig.json file (default: <file>.sig.json)")
  .action(
    action((file: string, opts: { key: string; out?: string }) => {
      const keyFile = loadKeyFile(opts.key);
      const pair = keyFileToPair(keyFile);
      const message = readInputFile(file);
      const sigFile = buildSignatureFile(pair, keyFile.keyId, message);
      const outPath = opts.out ?? `${file}.sig.json`;
      writeFileSync(outPath, JSON.stringify(sigFile, null, 2) + "\n");
      console.log(`signed ${file} with key ${keyFile.keyId} -> ${outPath}`);
    }),
  );

program
  .command("verify")
  .description("Verify a file against a signature")
  .argument("<file>", "path to the file that was signed")
  .option("-s, --sig <path>", "path to the .sig.json file (default: <file>.sig.json)")
  .option("-k, --key <path>", "path to the signing key file (for the public key)", DEFAULT_KEY_PATH)
  .action(
    action((file: string, opts: { sig?: string; key: string }) => {
      const keyFile = loadKeyFile(opts.key);
      const sigPath = opts.sig ?? `${file}.sig.json`;
      const sigFile = readJsonFile<SignatureFile>(sigPath, "signature file");
      const message = readInputFile(file);
      const result = verifySignatureFile(keyFileToPublicKey(keyFile), keyFile.keyId, message, sigFile);
      if (result.ok) {
        console.log(`OK: ${file} matches signature from key ${keyFile.keyId}`);
      } else {
        console.error(`FAILED: ${result.reason}`);
        process.exitCode = 1;
      }
    }),
  );

program
  .command("encrypt")
  .description("Encrypt a file for a recipient's ML-KEM-768 public key (hybrid ML-KEM + AES-256-GCM)")
  .argument("<file>", "path to the file to encrypt")
  .option("-k, --key <path>", "path to the recipient's KEM key file (public key)", DEFAULT_KEM_KEY_PATH)
  .option("-o, --out <path>", "path to write the .enc.json file (default: <file>.enc.json)")
  .action(
    action((file: string, opts: { key: string; out?: string }) => {
      const recipient = loadKemKeyFile(opts.key);
      const plaintext = readInputFile(file);
      const encrypted = encryptForRecipient(kemKeyFileToPublicKey(recipient), recipient.keyId, plaintext);
      const outPath = opts.out ?? `${file}.enc.json`;
      writeFileSync(outPath, JSON.stringify(encrypted, null, 2) + "\n");
      console.log(`encrypted ${file} for key ${recipient.keyId} -> ${outPath}`);
    }),
  );

program
  .command("decrypt")
  .description("Decrypt a file produced by 'encrypt' using your ML-KEM-768 secret key")
  .argument("<file>", "path to the .enc.json file to decrypt")
  .option("-k, --key <path>", "path to your KEM key file (secret key)", DEFAULT_KEM_KEY_PATH)
  .option("-o, --out <path>", "path to write the decrypted plaintext (default: <file> with .enc.json stripped)")
  .action(
    action((file: string, opts: { key: string; out?: string }) => {
      const own = loadKemKeyFile(opts.key);
      const encrypted = readJsonFile<EncryptedFile>(file, "encrypted file");
      const result = decryptWithKey(kemKeyFileToPair(own), own.keyId, encrypted);
      if (!result.ok) {
        console.error(`FAILED: ${result.reason}`);
        process.exitCode = 1;
        return;
      }
      const outPath = opts.out ?? file.replace(/\.enc\.json$/, "");
      if (outPath === file) {
        console.error(`refusing to write decrypted output over the input file; pass -o <path>`);
        process.exitCode = 1;
        return;
      }
      writeFileSync(outPath, result.plaintext);
      console.log(`decrypted ${file} -> ${outPath}`);
    }),
  );

program.parse();
