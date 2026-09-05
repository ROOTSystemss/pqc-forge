import { useState } from "react";
import { Card, FilePicker, JsonFilePicker, Button, ErrorBox } from "../components";
import { signFile, downloadJson } from "../api";

export function SignTab() {
  const [file, setFile] = useState<File | null>(null);
  const [keyFile, setKeyFile] = useState<unknown | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run() {
    if (!file || !keyFile) return;
    setBusy(true);
    setError(null);
    try {
      const sig = await signFile(file, keyFile);
      downloadJson(`${file.name}.pqc-sig.json`, sig);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card title="Sign a file">
      <p className="hint">Signs a file with an ML-DSA-65 secret key and downloads the resulting signature file.</p>
      <FilePicker label="File to sign" onFile={setFile} />
      <JsonFilePicker label="Signing key file (needs secret key)" onData={setKeyFile} />
      <div className="row">
        <Button onClick={run} disabled={busy || !file || !keyFile}>
          Sign
        </Button>
      </div>
      <ErrorBox message={error} />
    </Card>
  );
}
