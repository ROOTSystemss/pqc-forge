import express from "express";
import cors from "cors";
import multer from "multer";
import {
  generateKeyPair,
  toKeyFile,
  toPublicKeyFile,
  parseKeyFile,
  keyFileToPublicKey,
  keyFileToPair,
  KEY_SCHEMA,
  buildSignatureFile,
  verifySignatureFile,
  type SignatureFile,
  generateKemKeyPair,
  toKemKeyFile,
  toKemPublicKeyFile,
  parseKemKeyFile,
  kemKeyFileToPublicKey,
  kemKeyFileToPair,
  KEM_KEY_SCHEMA,
  encryptForRecipient,
  decryptWithKey,
  type EncryptedFile,
} from "pqc-forge";

const PORT = Number(process.env.PORT ?? 8787);
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 200 * 1024 * 1024 } });

const app = express();
app.use(cors());
app.use(express.json({ limit: "5mb" }));

/** Wraps a route handler so any thrown error becomes a clean 400 JSON response instead of an unhandled crash. */
function route(handler: (req: express.Request, res: express.Response) => void) {
  return (req: express.Request, res: express.Response) => {
    try {
      handler(req, res);
    } catch (err) {
      res.status(400).json({ error: (err as Error).message });
    }
  };
}

app.get("/api/health", (_req, res) => res.json({ ok: true }));

app.post(
  "/api/keys/signing",
  route((_req, res) => {
    const pair = generateKeyPair();
    res.json(toKeyFile(pair));
  }),
);

app.post(
  "/api/keys/kem",
  route((_req, res) => {
    const pair = generateKemKeyPair();
    res.json(toKemKeyFile(pair));
  }),
);

app.post(
  "/api/keys/export-pubkey",
  route((req, res) => {
    const raw = JSON.stringify(req.body?.keyFile);
    const schema = req.body?.keyFile?.schema;
    if (schema === KEY_SCHEMA) {
      res.json(toPublicKeyFile(parseKeyFile(raw)));
    } else if (schema === KEM_KEY_SCHEMA) {
      res.json(toKemPublicKeyFile(parseKemKeyFile(raw)));
    } else {
      res.status(400).json({ error: `unrecognized key file schema: ${schema}` });
    }
  }),
);

app.post(
  "/api/sign",
  upload.single("file"),
  route((req, res) => {
    if (!req.file) throw new Error("missing file to sign");
    const key = parseKeyFile(req.body.keyFile);
    const pair = keyFileToPair(key);
    res.json(buildSignatureFile(pair, key.keyId, req.file.buffer));
  }),
);

app.post(
  "/api/verify",
  upload.single("file"),
  route((req, res) => {
    if (!req.file) throw new Error("missing file to verify");
    const key = parseKeyFile(req.body.keyFile);
    const sig = JSON.parse(req.body.signatureFile) as SignatureFile;
    const publicKey = keyFileToPublicKey(key);
    res.json(verifySignatureFile(publicKey, key.keyId, req.file.buffer, sig));
  }),
);

app.post(
  "/api/encrypt",
  upload.single("file"),
  route((req, res) => {
    if (!req.file) throw new Error("missing file to encrypt");
    const key = parseKemKeyFile(req.body.keyFile);
    const publicKey = kemKeyFileToPublicKey(key);
    res.json(encryptForRecipient(publicKey, key.keyId, req.file.buffer));
  }),
);

app.post(
  "/api/decrypt",
  route((req, res) => {
    const key = parseKemKeyFile(JSON.stringify(req.body.keyFile));
    const pair = kemKeyFileToPair(key);
    const encrypted = req.body.encryptedFile as EncryptedFile;
    const result = decryptWithKey(pair, key.keyId, encrypted);
    if (!result.ok) {
      res.status(400).json({ error: result.reason });
      return;
    }
    res.setHeader("Content-Type", "application/octet-stream");
    res.setHeader("Content-Disposition", 'attachment; filename="decrypted.bin"');
    res.send(result.plaintext);
  }),
);

app.listen(PORT, "127.0.0.1", () => {
  console.log(`pqc-forge server listening on http://127.0.0.1:${PORT}`);
});
