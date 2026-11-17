// AD-072 (knock-out 2026-11-17): plain-English help under every form field. Text lives in ../fieldHints.json.
import HINTS from '../fieldHints.json';

type Hint = { hint: string; example?: string };
const table = HINTS as unknown as Record<string, Hint | string>;

export const hintId = (key: string): string => 'hint-' + key.replace(/[^A-Za-z0-9]+/g, '-');

export function FieldHint({ k }: { k: string }) {
  const h = table[k];
  if (!h || typeof h === 'string') return null;
  return (
    <small className="field-hint" id={hintId(k)}>
      {h.hint}
      {h.example ? <> <span className="field-hint-example">Example: {h.example}</span></> : null}
    </small>
  );
}
