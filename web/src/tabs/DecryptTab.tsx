import { useState } from "react";
import { Card, JsonFilePicker, Button, ErrorBox } from "../components";
import { decryptFile, downloadBlob } from "../api";

export function DecryptTab() {
  const [encryptedFile, setEncryptedFile] = useState<unknown | null>(null);
  const [keyFile, setKeyFile] = useState<unknown | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  async function run() {
    if (!encryptedFile || !keyFile) return;
    setBusy(true);
    setError(null);
    setDone(false);
    try {
      const blob = await decryptFile(encryptedFile, keyFile);
      downloadBlob("decrypted.bin", blob);
      setDone(true);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card title="Decrypt a file">
      <p className="hint">
        Needs your ML-KEM-768 secret key — the one matching the public key the file was encrypted for. The
        decrypted file downloads as <code>decrypted.bin</code> (original filename/type aren't stored in the
        encrypted format, so rename it back as needed).
      </p>
      <JsonFilePicker label="Encrypted file (.pqc-enc.json)" onData={setEncryptedFile} />
      <JsonFilePicker label="Your KEM key file (needs secret key)" onData={setKeyFile} />
      <div className="row">
        <Button onClick={run} disabled={busy || !encryptedFile || !keyFile}>
          Decrypt
        </Button>
      </div>
      {done && <div className="result-ok">✓ Decrypted — check your downloads for decrypted.bin</div>}
      <ErrorBox message={error} />
    </Card>
  );
}
