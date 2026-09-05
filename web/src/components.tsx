import { useId, useState } from "react";
import type { ReactNode } from "react";
import { readJsonFile } from "./api";

export function Card({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="card">
      <h2>{title}</h2>
      {children}
    </section>
  );
}

export function ErrorBox({ message }: { message: string | null }) {
  if (!message) return null;
  return <div className="error-box">{message}</div>;
}

export function FilePicker({
  label,
  onFile,
}: {
  label: string;
  onFile: (file: File | null) => void;
}) {
  const id = useId();
  const [name, setName] = useState<string | null>(null);
  return (
    <label className="field" htmlFor={id}>
      <span>{label}</span>
      <input
        id={id}
        type="file"
        onChange={(e) => {
          const file = e.target.files?.[0] ?? null;
          setName(file?.name ?? null);
          onFile(file);
        }}
      />
      {name && <span className="filename">{name}</span>}
    </label>
  );
}

interface KeyLike {
  schema?: string;
  algorithm?: string;
  keyId?: string;
  secretKey?: string;
}

/** Picks a .json file, parses it, and shows a summary line (schema/algorithm/keyId/whether it has a secret). */
export function JsonFilePicker({
  label,
  onData,
}: {
  label: string;
  onData: (data: unknown | null) => void;
}) {
  const id = useId();
  const [name, setName] = useState<string | null>(null);
  const [summary, setSummary] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  return (
    <label className="field" htmlFor={id}>
      <span>{label}</span>
      <input
        id={id}
        type="file"
        accept="application/json,.json"
        onChange={async (e) => {
          const file = e.target.files?.[0] ?? null;
          setName(file?.name ?? null);
          setError(null);
          setSummary(null);
          if (!file) {
            onData(null);
            return;
          }
          try {
            const data = (await readJsonFile(file)) as KeyLike;
            onData(data);
            const bits: string[] = [];
            if (data.algorithm) bits.push(data.algorithm);
            if (data.keyId) bits.push(data.keyId.slice(0, 22) + "…");
            if (data.secretKey !== undefined) bits.push(data.secretKey ? "has secret" : "public-only");
            setSummary(bits.join(" · "));
          } catch (err) {
            setError((err as Error).message);
            onData(null);
          }
        }}
      />
      {name && <span className="filename">{name}</span>}
      {summary && <span className="summary">{summary}</span>}
      {error && <span className="error-inline">{error}</span>}
    </label>
  );
}

export function Button({
  children,
  onClick,
  disabled,
  variant = "primary",
}: {
  children: ReactNode;
  onClick: () => void;
  disabled?: boolean;
  variant?: "primary" | "secondary";
}) {
  return (
    <button type="button" className={`btn btn-${variant}`} onClick={onClick} disabled={disabled}>
      {children}
    </button>
  );
}
