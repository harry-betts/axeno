import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import Sidebar from "./components/Sidebar/Sidebar";
import ChatView from "./components/ChatView/ChatView";
import Settings from "./components/Settings/Settings";
import ChatSettings from "./components/ChatSettings/ChatSettings";
import AddContact from "./components/AddContact/AddContact";
import Onboarding from "./components/Onboarding/Onboarding";
import VerifyIdentity from "./components/VerifyIdentity/VerifyIdentity";
import {
  Contact, Message, AppSettings, defaultSettings,
  MessagingSnapshot, BackendMessage, BackendContact, contactFromBackend, messageFromBackend,
} from "./types";
import "./App.css";
import "./components/Onboarding/Onboarding.css";

interface UnlockResponse { fingerprint: string; display_name: string; }
type TorStatus = "connecting" | "connected" | "failed";
interface TorStatusEvent { status: TorStatus; reason?: string; }
interface IncomingEnvelopeEvent { server_id: string; envelope: { id: string; to: string; envelope_type: string; ciphertext: string; }; }
interface IncomingMessageEvent { contact_id: string; message: BackendMessage; }
interface SendMessageResponse { message: BackendMessage; }

function sanitizeSettingsForStorage(settings: AppSettings): AppSettings {
  return {
    ...settings,
    // Connection codes contain delivery tokens and mailbox routing metadata.
    // They live only in the encrypted Rust-side message store, never localStorage.
    inviteCodes: [],
  };
}

function parseStoredSettings(raw: string | null): AppSettings {
  if (!raw) return defaultSettings;
  const parsed = JSON.parse(raw) as Partial<AppSettings>;
  return { ...defaultSettings, ...parsed, inviteCodes: [] };
}

function computeInitials(name: string): string {
  return name.trim().split(/\s+/).map(w => w[0]).join("").slice(0, 2).toUpperCase() || "?";
}

function groupMessages(snapshot: MessagingSnapshot): Record<string, Message[]> {
  const result: Record<string, Message[]> = {};
  Object.entries(snapshot.messages).forEach(([contactId, msgs]) => {
    result[contactId] = msgs.map(messageFromBackend);
  });
  return result;
}

export default function App() {
  const [appState, setAppState] = useState<"loading" | "onboarding" | "login" | "chat">("loading");
  const [torStatus, setTorStatus] = useState<TorStatus>("connecting");
  const [torError, setTorError] = useState<string>("");

  const [displayName, setDisplayName] = useState("");

  const [loginPassword, setLoginPassword] = useState("");
  const [loginError, setLoginError] = useState("");
  const [isUnlocking, setIsUnlocking] = useState(false);

  const [contacts, setContacts] = useState<Contact[]>([]);
  const [messages, setMessages] = useState<Record<string, Message[]>>({});
  const [activeContactId, setActiveContactId] = useState("");
  const [settings, setSettings] = useState<AppSettings>(() => {
    try {
      return parseStoredSettings(localStorage.getItem("axeno.settings.v1"));
    } catch {
      return defaultSettings;
    }
  });

  const [showSettings, setShowSettings] = useState(false);
  const [showAddContact, setShowAddContact] = useState(false);
  const [showChatSettings, setShowChatSettings] = useState(false);
  const [showVerify, setShowVerify] = useState(false);

  useEffect(() => {
    try { localStorage.setItem("axeno.settings.v1", JSON.stringify(sanitizeSettingsForStorage(settings))); } catch {}
  }, [settings]);

  const loadMessaging = useCallback(async () => {
    const snap = await invoke<MessagingSnapshot>("messaging_snapshot");
    const nextContacts = snap.contacts.map(contactFromBackend);
    setContacts(nextContacts);
    setMessages(groupMessages(snap));
    setActiveContactId(prev => prev || nextContacts[0]?.id || "");
    await invoke("messaging_connect_all").catch(() => {});
  }, []);

  useEffect(() => {
    const unlistenTor = listen<TorStatusEvent>("tor-status", (event) => {
      setTorStatus(event.payload.status);
      setTorError(event.payload.reason ?? "");
      if (event.payload.status === "connected") invoke("messaging_connect_all").catch(() => {});
    });

    const unlistenEnvelope = listen<IncomingEnvelopeEvent>("axeno-envelope", async (event) => {
      try {
        await invoke("messaging_handle_incoming_envelope", {
          serverId: event.payload.server_id,
          envelope: event.payload.envelope,
        });
      } catch {
        // Leave it queued if decryption failed; this avoids deleting data we cannot read.
      }
    });

    const unlistenMessage = listen<IncomingMessageEvent>("axeno-message", (event) => {
      const msg = messageFromBackend(event.payload.message);
      setContacts(prev => prev.some(c => c.id === event.payload.contact_id) ? prev : prev);
      setMessages(prev => {
        const existing = prev[event.payload.contact_id] ?? [];
        if (existing.some(m => m.id === msg.id)) return prev;
        return { ...prev, [event.payload.contact_id]: [...existing, msg] };
      });
      setActiveContactId(prev => prev || event.payload.contact_id);
      loadMessaging().catch(() => {});
    });

    const init = async () => {
      try {
        const exists = await invoke<boolean>("has_identity");
        setAppState(exists ? "login" : "onboarding");
        await invoke("bootstrap_tor");
      } catch {
        setAppState("onboarding");
      }
    };
    init();

    return () => {
      unlistenTor.then(f => f());
      unlistenEnvelope.then(f => f());
      unlistenMessage.then(f => f());
    };
  }, [loadMessaging]);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoginError("");
    setIsUnlocking(true);
    try {
      const res = await invoke<UnlockResponse>("unlock_identity", { passphrase: loginPassword });
      setDisplayName(res.display_name);
      setLoginPassword("");
      await loadMessaging();
      setAppState("chat");
    } catch {
      setLoginError("Incorrect password.");
    } finally {
      setIsUnlocking(false);
    }
  };

  const handleOnboardingComplete = async (name: string) => {
    setDisplayName(name);
    await loadMessaging().catch(() => {});
    setAppState("chat");
  };

  const handleAddedContact = async (contact: BackendContact) => {
    const c = contactFromBackend(contact);
    setContacts(prev => prev.some(x => x.id === c.id) ? prev : [...prev, c]);
    setActiveContactId(c.id);
    await invoke("messaging_connect_all").catch(() => {});
  };

  const sendMessage = async (contactId: string, text: string) => {
    const res = await invoke<SendMessageResponse>("messaging_send_text_message", { contactId, text });
    const msg = messageFromBackend(res.message);
    setMessages(prev => ({ ...prev, [contactId]: [...(prev[contactId] ?? []), msg] }));
  };

  const selectContact = async (id: string) => {
    setActiveContactId(id);
    setContacts(prev => prev.map(c => c.id === id ? { ...c, lastReadAt: Date.now() } : c));
    await invoke("messaging_mark_contact_read", { contactId: id }).catch(() => {});
  };

  const active = contacts.find(c => c.id === activeContactId) || contacts[0];


  if (appState === "loading") {
    return <div className="app-root" style={{ display: "flex", alignItems: "center", justifyContent: "center" }}><div className="onboarding-spinner" style={{ borderColor: "var(--border)", borderTopColor: "var(--brand)" }} /></div>;
  }

  if (appState === "onboarding") return <Onboarding onComplete={handleOnboardingComplete} />;

  if (appState === "login") {
    return (
      <div className="onboarding-root">
        <div className="onboarding-card">
          <h1 className="onboarding-title">Welcome back</h1>
          <form onSubmit={handleLogin} style={{ width: "100%" }}>
            <input type="password" className="onboarding-key-input" placeholder="Password" value={loginPassword} onChange={(e) => { setLoginPassword(e.target.value); setLoginError(""); }} autoFocus />
            {loginError && <div className="onboarding-error">{loginError}</div>}
            <button type="submit" className="btn btn-primary onboarding-btn" disabled={isUnlocking || !loginPassword}>{isUnlocking ? "Unlocking..." : "Unlock"}</button>
          </form>
        </div>
      </div>
    );
  }

  return (
    <div className="app-root">
      <Sidebar contacts={contacts} allMessages={messages} activeContactId={active?.id ?? ""} onSelectContact={selectContact} onOpenAddContact={() => setShowAddContact(true)} onOpenSettings={() => setShowSettings(true)} myInitials={computeInitials(displayName)} myDisplayName={displayName || "Me"} torStatus={torStatus} />

      {active ? (
        <ChatView contact={active} messages={messages[active.id] || []} onOpenChatSettings={() => setShowChatSettings(true)} onSendMessage={(text) => sendMessage(active.id, text)} sendOnEnter={settings.sendOnEnter} messageTextSize={settings.messageTextSize} />
      ) : (
        <main className="chat-view" style={{ display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-muted)" }}>Generate a connection code or add a contact to start messaging.</main>
      )}

      {showSettings && <Settings settings={settings} onChange={setSettings} displayName={displayName} onChangeName={setDisplayName} onClose={() => setShowSettings(false)} torStatus={torStatus} torError={torError} />}
      {showAddContact && <AddContact onClose={() => setShowAddContact(false)} onAdded={handleAddedContact} />}
      {showChatSettings && active && <ChatSettings contact={active} onClose={() => setShowChatSettings(false)} onOpenVerify={() => { setShowChatSettings(false); setShowVerify(true); }} />}
      {showVerify && active && <VerifyIdentity contact={active} onClose={() => setShowVerify(false)} />}
    </div>
  );
}
