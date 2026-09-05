// Thin client for the local pqc-forge server (see ../../server/src/index.ts).
// Every function throws a plain Error with the server's message on failure.

async function asJson<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(body.error ?? `request failed (${res.status})`);
  }
  return res.json() as Promise<T>;
}

export interface SigningKeyFile {
  schema: "pqc-forge.signing-key/v1";
  algorithm: "ML-DSA-65";
  keyId: string;
  createdAt: string;
  publicKey: string;
  secretKey?: string;
}

export interface KemKeyFile {
  schema: "pqc-forge.kem-key/v1";
  algorithm: "ML-KEM-768";
  keyId: string;
  createdAt: string;
  publicKey: string;
  secretKey?: string;
}

export interface SignatureFile {
  schema: "pqc-forge.signature/v1";
  algorithm: "ML-DSA-65";
  keyId: string;
  createdAt: string;
  digestAlgorithm: "sha256";
  digest: string;
  signature: string;
}

export interface EncryptedFile {
  schema: "pqc-forge.encrypted/v1";
  kemAlgorithm: "ML-KEM-768";
  cipherAlgorithm: "AES-256-GCM";
  keyId: string;
  createdAt: string;
  kemCiphertext: string;
  iv: string;
  authTag: string;
  ciphertext: string;
}

export interface VerifyResult {
  ok: boolean;
  reason?: string;
}

export async function generateSigningKey(): Promise<SigningKeyFile> {
  return asJson(await fetch("/api/keys/signing", { method: "POST" }));
}

export async function generateKemKey(): Promise<KemKeyFile> {
  return asJson(await fetch("/api/keys/kem", { method: "POST" }));
}

export async function exportPublicKey(keyFile: unknown): Promise<SigningKeyFile | KemKeyFile> {
  return asJson(
    await fetch("/api/keys/export-pubkey", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ keyFile }),
    }),
  );
}

export async function signFile(file: File, keyFile: unknown): Promise<SignatureFile> {
  const form = new FormData();
  form.append("file", file);
  form.append("keyFile", JSON.stringify(keyFile));
  return asJson(await fetch("/api/sign", { method: "POST", body: form }));
}

export async function verifyFile(file: File, signatureFile: unknown, keyFile: unknown): Promise<VerifyResult> {
  const form = new FormData();
  form.append("file", file);
  form.append("signatureFile", JSON.stringify(signatureFile));
  form.append("keyFile", JSON.stringify(keyFile));
  return asJson(await fetch("/api/verify", { method: "POST", body: form }));
}

export async function encryptFile(file: File, keyFile: unknown): Promise<EncryptedFile> {
  const form = new FormData();
  form.append("file", file);
  form.append("keyFile", JSON.stringify(keyFile));
  return asJson(await fetch("/api/encrypt", { method: "POST", body: form }));
}

export async function decryptFile(encryptedFile: unknown, keyFile: unknown): Promise<Blob> {
  const res = await fetch("/api/decrypt", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ encryptedFile, keyFile }),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(body.error ?? `request failed (${res.status})`);
  }
  return res.blob();
}

/** Triggers a browser download of `data` (pretty-printed) as `filename`. */
export function downloadJson(filename: string, data: unknown): void {
  downloadBlob(filename, new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
}

export function downloadBlob(filename: string, blob: Blob): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

/** Reads a File (e.g. a chosen .json key/signature file) as text and parses it. */
export async function readJsonFile(file: File): Promise<unknown> {
  return JSON.parse(await file.text());
}
