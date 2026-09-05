import { useState } from "react";
import { Card, JsonFilePicker, Button, ErrorBox } from "../components";
import { generateSigningKey, generateKemKey, exportPublicKey, downloadJson } from "../api";

export function KeysTab() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [existingKey, setExistingKey] = useState<unknown | null>(null);

  async function generate(kind: "signing" | "kem") {
    setBusy(true);
    setError(null);
    try {
      const key = kind === "signing" ? await generateSigningKey() : await generateKemKey();
      downloadJson(`pqc-forge-${kind}-key.json`, key);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function exportPublic() {
    if (!existingKey) return;
    setBusy(true);
    setError(null);
    try {
      const pub = await exportPublicKey(existingKey);
      downloadJson("public-key.json", pub);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <Card title="Generate a new keypair">
        <p className="hint">
          Downloads a JSON key file containing both the public and secret key. Keep it safe — anyone with it can
          sign (or decrypt) as you.
        </p>
        <div className="row">
          <Button onClick={() => generate("signing")} disabled={busy}>
            Generate ML-DSA-65 signing key
          </Button>
          <Button onClick={() => generate("kem")} disabled={busy}>
            Generate ML-KEM-768 encryption key
          </Button>
        </div>
      </Card>

      <Card title="Export a public-only key">
        <p className="hint">
          Strips the secret key from an existing key file, so you can hand it to someone else — they'll be able to
          verify your signatures (or encrypt to you) but not act as you.
        </p>
        <JsonFilePicker label="Key file (signing or encryption)" onData={setExistingKey} />
        <div className="row">
          <Button onClick={exportPublic} disabled={busy || !existingKey}>
            Export public-only key
          </Button>
        </div>
      </Card>

      <ErrorBox message={error} />
    </>
  );
}
