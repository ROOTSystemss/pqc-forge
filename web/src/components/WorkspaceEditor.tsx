import { useState } from 'react';
import type { WorkspaceFile } from '../types';
import { EXAMPLE_WORKSPACES } from '../fixtures';

/**
 * Edits the in-browser file list that becomes a workspace upload
 * (POST /v1/workspaces). Shared by the Scan and Migrate tabs since both
 * act on "a small set of pasted config files" rather than a real
 * repository checkout — the API's workspace model (see workspace.js) is
 * an inline file list for exactly this reason.
 */
export function WorkspaceEditor({ files, onChange }: { files: WorkspaceFile[]; onChange: (files: WorkspaceFile[]) => void }) {
  const [active, setActive] = useState(0);

  function updateFile(index: number, patch: Partial<WorkspaceFile>) {
    onChange(files.map((file, i) => (i === index ? { ...file, ...patch } : file)));
  }

  function addFile() {
    onChange([...files, { path: `file-${files.length + 1}.conf`, content: '' }]);
    setActive(files.length);
  }

  function removeFile(index: number) {
    const next = files.filter((_, i) => i !== index);
    onChange(next);
    setActive(Math.max(0, Math.min(active, next.length - 1)));
  }

  const current = files[active];

  return (
    <div className="workspace-editor">
      <div className="workspace-toolbar">
        <div className="file-tabs">
          {files.map((file, index) => (
            <button
              key={index}
              className={index === active ? 'file-tab active' : 'file-tab'}
              onClick={() => setActive(index)}
            >
              {file.path || '(untitled)'}
            </button>
          ))}
          <button className="ghost" onClick={addFile} title="Add file">+ file</button>
        </div>
        <select
          defaultValue=""
          onChange={(event) => {
            const key = event.target.value;
            if (key && EXAMPLE_WORKSPACES[key]) { onChange(EXAMPLE_WORKSPACES[key]); setActive(0); }
            event.target.value = '';
          }}
        >
          <option value="" disabled>Load example…</option>
          {Object.keys(EXAMPLE_WORKSPACES).map((key) => <option key={key} value={key}>{key}</option>)}
        </select>
      </div>

      {current && (
        <div className="file-editor">
          <div className="file-editor-chrome">
            <span className="traffic" /><span className="traffic" /><span className="traffic" />
            <div className="file-editor-row">
              <input
                type="text" value={current.path}
                onChange={(event) => updateFile(active, { path: event.target.value })}
                placeholder="relative/path.conf"
              />
            </div>
            <button className="ghost" onClick={() => removeFile(active)} disabled={files.length <= 1}>remove</button>
          </div>
          <textarea
            rows={12} value={current.content} spellCheck={false}
            onChange={(event) => updateFile(active, { content: event.target.value })}
            placeholder="Paste configuration content here…"
          />
        </div>
      )}
    </div>
  );
}
