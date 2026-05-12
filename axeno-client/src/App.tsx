import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import Sidebar from "./components/Sidebar/Sidebar";
import ChatView from "./components/ChatView/ChatView";
import Settings from "./components/Settings/Settings";
import ChatSettings from "./components/ChatSettings/ChatSettings";
import AddContact from "./components/AddContact/AddContact";
import Onboarding from "./components/Onboarding/Onboarding";
import VerifyIdentity from "./components/VerifyIdentity/VerifyIdentity";
import { Contact, AppSettings, ServerChoice, defaultSettings } from "./types";
import { mockContacts, mockMessages } from "./mockData";
import "./App.css";
import "./components/Onboarding/Onboarding.css"; 

interface UnlockResponse {
  fingerprint: string;
  display_name: string;
}

function computeInitials(name: string): string {
  return name.trim().split(/\s+/).map(w => w[0]).join("").slice(0, 2).toUpperCase() || "?";
}

export default function App() {
  const [appState, setAppState] = useState<"loading" | "onboarding" | "login" | "chat">("loading");
  const [torStatus, setTorStatus] = useState<"connecting" | "connected" | "failed">("connecting");
  
  const [displayName, setDisplayName] = useState("My User");
  const [activePassword, setActivePassword] = useState("");
  
  const [loginPassword, setLoginPassword] = useState("");
  const [loginError, setLoginError] = useState("");
  const [isUnlocking, setIsUnlocking] = useState(false);

  const [contacts, setContacts] = useState<Contact[]>(mockContacts);
  const [activeContactId, setActiveContactId] = useState("ax7f2c");
  const [settings, setSettings] = useState<AppSettings>(defaultSettings);

  const [showSettings, setShowSettings]     = useState(false);
  const [showAddContact, setShowAddContact] = useState(false);
  const [showChatSettings, setShowChatSettings] = useState(false);
  const [showVerify, setShowVerify]         = useState(false);

  useEffect(() => {
    // Listen for Tor background events emitted from Rust
    const unlisten = listen<"connecting" | "connected" | "failed">("tor-status", (event) => {
      setTorStatus(event.payload);
    });

    const init = async () => {
      try {
        const exists = await invoke<boolean>("has_identity");
        setAppState(exists ? "login" : "onboarding");
        
        // Spawn Tor bootstrap in background
        await invoke("bootstrap_tor");
      } catch (err) {
        setAppState("onboarding");
      }
    };
    init();

    return () => { unlisten.then(f => f()); };
  }, []);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoginError("");
    setIsUnlocking(true);
    try {
      const res = await invoke<UnlockResponse>("unlock_identity", { passphrase: loginPassword });
      setDisplayName(res.display_name);
      setActivePassword(loginPassword); // Cache session password so we can re-encrypt settings changes later
      setAppState("chat");
    } catch (err) {
      setLoginError("Incorrect password.");
    } finally {
      setIsUnlocking(false);
    }
  };

  const active = contacts.find(c => c.id === activeContactId)!;

  const updateContactServer = (id: string, server: ServerChoice) => {
    setContacts(prev => prev.map(c => (c.id === id ? { ...c, serverChoice: server } : c)));
  };

  if (appState === "loading") {
    return (
      <div className="app-root" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <div className="onboarding-spinner" style={{ borderColor: 'var(--border)', borderTopColor: 'var(--brand)' }} />
      </div>
    );
  }

  if (appState === "onboarding") {
    return <Onboarding onComplete={(name, password) => { 
      setDisplayName(name); 
      setActivePassword(password);
      setAppState("chat"); 
    }} />;
  }

  if (appState === "login") {
    return (
      <div className="onboarding-root">
        <div className="onboarding-card">
          <h1 className="onboarding-title">Welcome Back</h1>
          <form onSubmit={handleLogin} style={{ width: '100%' }}>
            <input
              type="password"
              className="onboarding-key-input"
              placeholder="Password"
              value={loginPassword}
              onChange={(e) => { setLoginPassword(e.target.value); setLoginError(""); }}
              autoFocus
            />
            {loginError && <div className="onboarding-error">{loginError}</div>}
            <button type="submit" className="btn btn-primary onboarding-btn" disabled={isUnlocking || !loginPassword}>
              {isUnlocking ? "Unlocking..." : "Unlock"}
            </button>
          </form>
        </div>
      </div>
    );
  }

  return (
    <div className="app-root">
      <Sidebar
        contacts={contacts}
        allMessages={mockMessages}
        activeContactId={activeContactId}
        onSelectContact={setActiveContactId}
        onOpenAddContact={() => setShowAddContact(true)}
        onOpenSettings={() => setShowSettings(true)}
        myInitials={computeInitials(displayName)}
        myDisplayName={displayName}
        torStatus={torStatus}
      />

      <ChatView
        contact={active}
        messages={mockMessages[active.id] || []}
        onOpenChatSettings={() => setShowChatSettings(true)}
      />

      {showSettings && (
        <Settings
          settings={settings}
          onChange={setSettings}
          displayName={displayName}
          onChangeName={setDisplayName}
          onClose={() => setShowSettings(false)}
          activePassword={activePassword}
        />
      )}

      {showAddContact && <AddContact onClose={() => setShowAddContact(false)} />}

      {showChatSettings && (
        <ChatSettings
          contact={active}
          settings={settings}
          onClose={() => setShowChatSettings(false)}
          onOpenVerify={() => { setShowChatSettings(false); setShowVerify(true); }}
          onUpdateContactServer={updateContactServer}
        />
      )}

      {showVerify && <VerifyIdentity contact={active} onClose={() => setShowVerify(false)} />}
    </div>
  );
}