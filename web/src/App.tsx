import { useState } from "react";
import { KeysTab } from "./tabs/KeysTab";
import { SignTab } from "./tabs/SignTab";
import { VerifyTab } from "./tabs/VerifyTab";
import { EncryptTab } from "./tabs/EncryptTab";
import { DecryptTab } from "./tabs/DecryptTab";

const TABS = [
  { id: "keys", label: "Keys", Component: KeysTab },
  { id: "sign", label: "Sign", Component: SignTab },
  { id: "verify", label: "Verify", Component: VerifyTab },
  { id: "encrypt", label: "Encrypt", Component: EncryptTab },
  { id: "decrypt", label: "Decrypt", Component: DecryptTab },
] as const;

function App() {
  const [active, setActive] = useState<(typeof TABS)[number]["id"]>("keys");
  const Active = TABS.find((t) => t.id === active)?.Component ?? KeysTab;

  return (
    <div className="app">
      <header className="app-header">
        <h1>pqc-forge</h1>
        <p>Post-quantum signing (ML-DSA-65) and encryption (ML-KEM-768) — runs entirely on your machine.</p>
      </header>
      <nav className="tabs">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            type="button"
            className={tab.id === active ? "tab tab-active" : "tab"}
            onClick={() => setActive(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </nav>
      <main className="content">
        <Active />
      </main>
    </div>
  );
}

export default App;
