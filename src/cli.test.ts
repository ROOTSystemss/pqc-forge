import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const CLI_PATH = fileURLToPath(new URL("./cli.js", import.meta.url));

function run(args: string[], cwd: string) {
  const result = spawnSync(process.execPath, [CLI_PATH, ...args], { cwd, encoding: "utf8" });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

function withTempDir(fn: (dir: string) => void) {
  const dir = mkdtempSync(join(tmpdir(), "pqc-forge-cli-test-"));
  try {
    fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("keygen + sign + verify round-trip via the CLI", () => {
  withTempDir((dir) => {
    const keyPath = join(dir, "key.json");
    const filePath = join(dir, "message.txt");
    writeFileSync(filePath, "hello from the CLI test suite");

    const keygen = run(["keygen", "-o", keyPath], dir);
    assert.equal(keygen.status, 0, keygen.stderr);
    assert.match(keygen.stdout, /wrote ML-DSA-65 key/);

    const sign = run(["sign", filePath, "-k", keyPath], dir);
    assert.equal(sign.status, 0, sign.stderr);
    assert.ok(existsSync(`${filePath}.sig.json`));

    const verify = run(["verify", filePath, "-k", keyPath], dir);
    assert.equal(verify.status, 0, verify.stderr);
    assert.match(verify.stdout, /^OK:/);
  });
});

test("verify fails with a clear message when the file is tampered", () => {
  withTempDir((dir) => {
    const keyPath = join(dir, "key.json");
    const filePath = join(dir, "message.txt");
    writeFileSync(filePath, "original content");
    run(["keygen", "-o", keyPath], dir);
    run(["sign", filePath, "-k", keyPath], dir);

    writeFileSync(filePath, "tampered content");
    const verify = run(["verify", filePath, "-k", keyPath], dir);
    assert.equal(verify.status, 1);
    assert.match(verify.stderr, /FAILED: message digest does not match/);
  });
});

test("keygen refuses to overwrite an existing key without --force", () => {
  withTempDir((dir) => {
    const keyPath = join(dir, "key.json");
    const first = run(["keygen", "-o", keyPath], dir);
    assert.equal(first.status, 0);
    const original = readFileSync(keyPath, "utf8");

    const second = run(["keygen", "-o", keyPath], dir);
    assert.equal(second.status, 1);
    assert.match(second.stderr, /refusing to overwrite/);
    assert.equal(readFileSync(keyPath, "utf8"), original);

    const forced = run(["keygen", "-o", keyPath, "--force"], dir);
    assert.equal(forced.status, 0);
    assert.notEqual(readFileSync(keyPath, "utf8"), original);
  });
});

test("sign reports a clean error for a missing input file", () => {
  withTempDir((dir) => {
    const keyPath = join(dir, "key.json");
    run(["keygen", "-o", keyPath], dir);

    const sign = run(["sign", join(dir, "does-not-exist.txt"), "-k", keyPath], dir);
    assert.equal(sign.status, 1);
    assert.match(sign.stderr, /Error: input file not found/);
    // No raw Node stack trace should leak to the user.
    assert.doesNotMatch(sign.stderr, /at Object\.<anonymous>/);
  });
});

test("verify reports a clean error for a missing key file", () => {
  withTempDir((dir) => {
    const filePath = join(dir, "message.txt");
    writeFileSync(filePath, "content");
    const verify = run(["verify", filePath, "-k", join(dir, "nope.json")], dir);
    assert.equal(verify.status, 1);
    assert.match(verify.stderr, /Error: no key found at/);
  });
});

test("verify reports a clean error for a corrupt signature file", () => {
  withTempDir((dir) => {
    const keyPath = join(dir, "key.json");
    const filePath = join(dir, "message.txt");
    writeFileSync(filePath, "content");
    run(["keygen", "-o", keyPath], dir);
    writeFileSync(`${filePath}.sig.json`, "{ not valid json");

    const verify = run(["verify", filePath, "-k", keyPath], dir);
    assert.equal(verify.status, 1);
    assert.match(verify.stderr, /Error: signature file at .* is not valid JSON/);
  });
});

test("kem-keygen + encrypt + decrypt round-trip via the CLI", () => {
  withTempDir((dir) => {
    const keyPath = join(dir, "kem-key.json");
    const filePath = join(dir, "secret.txt");
    const decryptedPath = join(dir, "secret.out.txt");
    writeFileSync(filePath, "top secret hybrid-encrypted payload");

    const keygen = run(["kem-keygen", "-o", keyPath], dir);
    assert.equal(keygen.status, 0, keygen.stderr);
    assert.match(keygen.stdout, /wrote ML-KEM-768 key/);

    const encrypt = run(["encrypt", filePath, "-k", keyPath], dir);
    assert.equal(encrypt.status, 0, encrypt.stderr);
    assert.ok(existsSync(`${filePath}.enc.json`));

    const decrypt = run(["decrypt", `${filePath}.enc.json`, "-k", keyPath, "-o", decryptedPath], dir);
    assert.equal(decrypt.status, 0, decrypt.stderr);
    assert.equal(readFileSync(decryptedPath, "utf8"), "top secret hybrid-encrypted payload");
  });
});

test("decrypt refuses to write over the input file when -o is omitted and names collide", () => {
  withTempDir((dir) => {
    const keyPath = join(dir, "kem-key.json");
    // Deliberately name the plaintext so its ciphertext path equals itself
    // once ".enc.json" is stripped back off.
    const filePath = join(dir, "payload");
    writeFileSync(filePath, "data");
    run(["kem-keygen", "-o", keyPath], dir);
    run(["encrypt", filePath, "-k", keyPath, "-o", filePath], dir);

    const decrypt = run(["decrypt", filePath, "-k", keyPath], dir);
    assert.equal(decrypt.status, 1);
    assert.match(decrypt.stderr, /refusing to write decrypted output over the input file/);
  });
});

test("export-pubkey + verify with the public-only signing key file", () => {
  withTempDir((dir) => {
    const keyPath = join(dir, "signer.json");
    const pubPath = join(dir, "signer.pub.json");
    const filePath = join(dir, "release.txt");
    writeFileSync(filePath, "release contents");

    run(["keygen", "-o", keyPath], dir);
    const exportResult = run(["export-pubkey", keyPath, "-o", pubPath], dir);
    assert.equal(exportResult.status, 0, exportResult.stderr);
    assert.equal(JSON.parse(readFileSync(pubPath, "utf8")).secretKey, undefined);

    run(["sign", filePath, "-k", keyPath], dir);
    const verify = run(["verify", filePath, "-k", pubPath], dir);
    assert.equal(verify.status, 0, verify.stderr);

    const signWithPubOnly = run(["sign", filePath, "-k", pubPath], dir);
    assert.equal(signWithPubOnly.status, 1);
    assert.match(signWithPubOnly.stderr, /has no secret key/);
  });
});

test("export-pubkey + encrypt with the public-only KEM key file", () => {
  withTempDir((dir) => {
    const keyPath = join(dir, "recipient.json");
    const pubPath = join(dir, "recipient.pub.json");
    const filePath = join(dir, "msg.txt");
    const outPath = join(dir, "msg.out.txt");
    writeFileSync(filePath, "secret payload");

    run(["kem-keygen", "-o", keyPath], dir);
    run(["export-pubkey", keyPath, "-o", pubPath], dir);

    const encrypt = run(["encrypt", filePath, "-k", pubPath], dir);
    assert.equal(encrypt.status, 0, encrypt.stderr);

    const decrypt = run(["decrypt", `${filePath}.enc.json`, "-k", keyPath, "-o", outPath], dir);
    assert.equal(decrypt.status, 0, decrypt.stderr);
    assert.equal(readFileSync(outPath, "utf8"), "secret payload");

    const decryptWithPubOnly = run(["decrypt", `${filePath}.enc.json`, "-k", pubPath, "-o", outPath], dir);
    assert.equal(decryptWithPubOnly.status, 1);
    assert.match(decryptWithPubOnly.stderr, /has no secret key/);
  });
});

test("export-pubkey rejects a file with an unrecognized schema", () => {
  withTempDir((dir) => {
    const badPath = join(dir, "not-a-key.json");
    writeFileSync(badPath, JSON.stringify({ schema: "something-else/v1" }));
    const result = run(["export-pubkey", badPath], dir);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /unrecognized key schema/);
  });
});

test("decrypt fails cleanly with the wrong KEM key", () => {
  withTempDir((dir) => {
    const keyPathA = join(dir, "a.json");
    const keyPathB = join(dir, "b.json");
    const filePath = join(dir, "secret.txt");
    writeFileSync(filePath, "for A's eyes only");

    run(["kem-keygen", "-o", keyPathA], dir);
    run(["kem-keygen", "-o", keyPathB], dir);
    run(["encrypt", filePath, "-k", keyPathA], dir);

    const decrypt = run(["decrypt", `${filePath}.enc.json`, "-k", keyPathB, "-o", join(dir, "out.txt")], dir);
    assert.equal(decrypt.status, 1);
    assert.match(decrypt.stderr, /FAILED: keyId mismatch/);
  });
});
