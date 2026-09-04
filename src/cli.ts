#!/usr/bin/env node
import { Command } from "commander";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import {
  generateKeyPair,
  toKeyFile,
  parseKeyFile,
  keyFileToPair,
  type SigningKeyFile,
} from "./keys.js";
import { buildSignatureFile, verifySignatureFile, type SignatureFile } from "./sign.js";

const DEFAULT_KEY_PATH = join(homedir(), ".pqc-forge", "signing-key.json");

function loadKeyFile(path: string): SigningKeyFile {
  if (!existsSync(path)) {
    throw new Error(`no key found at ${path} (run "pqc-forge keygen" first)`);
  }
  return parseKeyFile(readFileSync(path, "utf8"));
}

const program = new Command();

program
  .name("pqc-forge")
  .description("Post-quantum (ML-DSA-65) file signing")
  .version("0.1.0");

program
  .command("keygen")
  .description("Generate a new ML-DSA-65 signing keypair")
  .option("-o, --out <path>", "path to write the key file", DEFAULT_KEY_PATH)
  .option("-f, --force", "overwrite an existing key file", false)
  .action((opts: { out: string; force: boolean }) => {
    if (existsSync(opts.out) && !opts.force) {
      console.error(`refusing to overwrite existing key at ${opts.out} (pass --force to replace it)`);
      process.exitCode = 1;
      return;
    }
    const pair = generateKeyPair();
    const keyFile = toKeyFile(pair);
    mkdirSync(dirname(opts.out), { recursive: true });
    writeFileSync(opts.out, JSON.stringify(keyFile, null, 2) + "\n", { mode: 0o600 });
    console.log(`wrote ${keyFile.algorithm} key ${keyFile.keyId} to ${opts.out}`);
  });

program
  .command("sign")
  .description("Sign a file")
  .argument("<file>", "path to the file to sign")
  .option("-k, --key <path>", "path to the signing key file", DEFAULT_KEY_PATH)
  .option("-o, --out <path>", "path to write the .sig.json file (default: <file>.sig.json)")
  .action((file: string, opts: { key: string; out?: string }) => {
    const keyFile = loadKeyFile(opts.key);
    const pair = keyFileToPair(keyFile);
    const message = readFileSync(file);
    const sigFile = buildSignatureFile(pair, keyFile.keyId, message);
    const outPath = opts.out ?? `${file}.sig.json`;
    writeFileSync(outPath, JSON.stringify(sigFile, null, 2) + "\n");
    console.log(`signed ${file} with key ${keyFile.keyId} -> ${outPath}`);
  });

program
  .command("verify")
  .description("Verify a file against a signature")
  .argument("<file>", "path to the file that was signed")
  .option("-s, --sig <path>", "path to the .sig.json file (default: <file>.sig.json)")
  .option("-k, --key <path>", "path to the signing key file (for the public key)", DEFAULT_KEY_PATH)
  .action((file: string, opts: { sig?: string; key: string }) => {
    const keyFile = loadKeyFile(opts.key);
    const sigPath = opts.sig ?? `${file}.sig.json`;
    if (!existsSync(sigPath)) {
      console.error(`no signature found at ${sigPath}`);
      process.exitCode = 1;
      return;
    }
    const sigFile = JSON.parse(readFileSync(sigPath, "utf8")) as SignatureFile;
    const message = readFileSync(file);
    const result = verifySignatureFile(keyFileToPair(keyFile).publicKey, keyFile.keyId, message, sigFile);
    if (result.ok) {
      console.log(`OK: ${file} matches signature from key ${keyFile.keyId}`);
    } else {
      console.error(`FAILED: ${result.reason}`);
      process.exitCode = 1;
    }
  });

program.parse();
