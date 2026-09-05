import { useState } from "react";
import { Card, FilePicker, JsonFilePicker, Button, ErrorBox } from "../components";
import { verifyFile, type VerifyResult } from "../api";

export function VerifyTab() {
  const [file, setFile] = useState<File | null>(null);
  const [signatureFile, setSignatureFile] = useState<unknown | null>(null);
  const [keyFile, setKeyFile] = useState<unknown | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<VerifyResult | null>(null);

  async function run() {
    if (!file || !signatureFile || !keyFile) return;
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await verifyFile(file, signatureFile, keyFile));
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card title="Verify a signature">
      <p className="hint">Checks a file against a signature file and a public (or full) signing key.</p>
      <FilePicker label="Original file" onFile={setFile} />
      <JsonFilePicker label="Signature file (.pqc-sig.json)" onData={setSignatureFile} />
      <JsonFilePicker label="Signing key file (public or full)" onData={setKeyFile} />
      <div className="row">
        <Button onClick={run} disabled={busy || !file || !signatureFile || !keyFile}>
          Verify
        </Button>
      </div>
      {result && (
        <div className={result.ok ? "result-ok" : "result-fail"}>
          {result.ok ? "✓ Signature is valid" : `✗ Invalid: ${result.reason}`}
        </div>
      )}
      <ErrorBox message={error} />
    </Card>
  );
}
