import { useState } from "react";
import { Card, FilePicker, JsonFilePicker, Button, ErrorBox } from "../components";
import { encryptFile, downloadJson } from "../api";

export function EncryptTab() {
  const [file, setFile] = useState<File | null>(null);
  const [keyFile, setKeyFile] = useState<unknown | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run() {
    if (!file || !keyFile) return;
    setBusy(true);
    setError(null);
    try {
      const encrypted = await encryptFile(file, keyFile);
      downloadJson(`${file.name}.pqc-enc.json`, encrypted);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card title="Encrypt a file">
      <p className="hint">
        Hybrid-encrypts a file for a recipient's ML-KEM-768 public key (ML-KEM encapsulation + AES-256-GCM). You only
        need their public key — not their secret key.
      </p>
      <FilePicker label="File to encrypt" onFile={setFile} />
      <JsonFilePicker label="Recipient's KEM key file (public or full)" onData={setKeyFile} />
      <div className="row">
        <Button onClick={run} disabled={busy || !file || !keyFile}>
          Encrypt
        </Button>
      </div>
      <ErrorBox message={error} />
    </Card>
  );
}
