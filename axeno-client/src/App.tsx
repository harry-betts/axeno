import { useState, useEffect, useCallback, useRef } from "react";
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
interface IncomingMessageEvent { contact_id: string; message: BackendMessage; }
interface SendMessageResponse { message: BackendMessage; }
interface SendReceiptEvent { server_id: string; id: string; queued: boolean; client_ref?: string | null; }
interface SendFailedEvent { server_id: string; client_ref?: string | null; code: string; message: string; }
interface ServerStatusEvent { server_id: string; status: string; reason?: string | null; }
interface BackendPrivateServerSettings { private_servers: { id: string; name: string; onion: string }[]; default_server_url?: string | null; }

function sanitizeSettingsForStorage(settings: AppSettings): AppSettings {
  return {
    ...settings,
    // Connection codes and private relay selections contain routing metadata.
    // They live only in the encrypted Rust-side message store, never localStorage.
    inviteCodes: [],
    privateServers: [],
    defaultServer: { kind: "official" },
  };
}

function parseStoredSettings(raw: string | null): AppSettings {
  if (!raw) return defaultSettings;
  const parsed = JSON.parse(raw) as Partial<AppSettings>;
  return { ...defaultSettings, ...parsed, inviteCodes: [], privateServers: [], defaultServer: { kind: "official" } };
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

  const loginPasswordRef = useRef<HTMLInputElement>(null);
  const [loginPasswordReady, setLoginPasswordReady] = useState(false);
  const [loginError, setLoginError] = useState("");
  const [isUnlocking, setIsUnlocking] = useState(false);

  const [contacts, setContacts] = useState<Contact[]>([]);
  const [messages, setMessages] = useState<Record<string, Message[]>>({});
  const [activeContactId, setActiveContactId] = useState("");
  const activeContactIdRef = useRef("");
  const reconnectTimersRef = useRef<Record<string, number>>({});
  const [settings, setSettings] = useState<AppSettings>(() => {
    try {
      return parseStoredSettings(localStorage.getItem("axeno.settings.v1"));
    } catch {
      return defaultSettings;
    }
  });

  const [serverSettingsLoaded, setServerSettingsLoaded] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [showAddContact, setShowAddContact] = useState(false);
  const [showChatSettings, setShowChatSettings] = useState(false);
  const [showVerify, setShowVerify] = useState(false);

  useEffect(() => {
    try { localStorage.setItem("axeno.settings.v1", JSON.stringify(sanitizeSettingsForStorage(settings))); } catch {}
  }, [settings]);

  useEffect(() => {
    if (appState !== "chat" || !serverSettingsLoaded) return;
    const defaultServerUrl = settings.defaultServer.kind === "private"
      ? settings.privateServers.find(s => s.id === (settings.defaultServer as { kind: "private"; serverId: string }).serverId)?.onion ?? null
      : null;
    invoke("messaging_save_private_server_settings", {
      settings: {
        private_servers: settings.privateServers,
        default_server_url: defaultServerUrl,
      },
    }).catch(() => {});
  }, [settings.privateServers, settings.defaultServer, appState, serverSettingsLoaded]);

  const loadMessaging = useCallback(async () => {
    const snap = await invoke<MessagingSnapshot>("messaging_snapshot");
    const nextContacts = snap.contacts.map(contactFromBackend);
    setContacts(nextContacts);
    setMessages(groupMessages(snap));
    setActiveContactId(prev => prev || nextContacts[0]?.id || "");
    invoke("messaging_connect_all").catch(() => {});
  }, []);

  const loadPrivateServerSettings = useCallback(async () => {
    const persisted = await invoke<BackendPrivateServerSettings>("messaging_load_private_server_settings");
    setSettings(prev => {
      const privateServers = persisted.private_servers.map(s => ({ id: s.id, name: s.name, onion: s.onion }));
      const matching = persisted.default_server_url
        ? privateServers.find(s => s.onion === persisted.default_server_url)
        : undefined;
      return {
        ...prev,
        privateServers,
        defaultServer: matching ? { kind: "private", serverId: matching.id } : { kind: "official" },
      };
    });
    setServerSettingsLoaded(true);
  }, []);

  const markContactRead = useCallback(async (contactId: string) => {
    if (!contactId) return;

    // Clear instantly in the UI, then replace with the exact persisted backend value.
    const optimisticReadAt = Date.now();
    setContacts(prev => prev.map(c => c.id === contactId ? { ...c, lastReadAt: optimisticReadAt } : c));

    const updated = await invoke<BackendContact>("messaging_mark_contact_read", { contactId });
    const next = contactFromBackend(updated);
    setContacts(prev => prev.map(c => c.id === contactId ? next : c));
  }, []);

  const activeContactIdForUi = activeContactId || contacts[0]?.id || "";

  useEffect(() => {
    activeContactIdRef.current = activeContactIdForUi;
  }, [activeContactIdForUi]);

  useEffect(() => {
    if (appState !== "chat" || !activeContactIdForUi) return;
    markContactRead(activeContactIdForUi).catch(() => {});
  }, [appState, activeContactIdForUi, markContactRead]);


  useEffect(() => {
    const unlistenTor = listen<TorStatusEvent>("tor-status", (event) => {
      setTorStatus(event.payload.status);
      setTorError(event.payload.reason ?? "");
      if (event.payload.status === "connected") invoke("messaging_connect_all").catch(() => {});
    });

    const unlistenServerStatus = listen<ServerStatusEvent>("axeno-server-status", (event) => {
      const { server_id: serverId, status } = event.payload;
      if (status === "ready" || status === "connected" || status === "connecting") {
        const existing = reconnectTimersRef.current[serverId];
        if (existing) {
          window.clearTimeout(existing);
          delete reconnectTimersRef.current[serverId];
        }
        return;
      }
      if (status !== "failed" && status !== "disconnected") return;
      if (reconnectTimersRef.current[serverId]) return;
      reconnectTimersRef.current[serverId] = window.setTimeout(() => {
        delete reconnectTimersRef.current[serverId];
        invoke("messaging_connect_all").catch(() => {});
      }, 1500);
    });


    const unlistenSendReceipt = listen<SendReceiptEvent>("axeno-send-receipt", async (event) => {
      const messageId = event.payload.client_ref;
      if (!messageId) return;
      try {
        const updated = await invoke<BackendMessage | null>("messaging_mark_message_relay_received", {
          messageId,
          queued: event.payload.queued,
        });
        if (!updated) return;
        const msg = messageFromBackend(updated);
        setMessages(prev => {
          const contactId = updated.contact_id;
          const existing = prev[contactId] ?? [];
          return { ...prev, [contactId]: existing.map(m => m.id === msg.id ? msg : m) };
        });
      } catch {}
    });

    const unlistenSendFailed = listen<SendFailedEvent>("axeno-send-failed", async (event) => {
      const messageId = event.payload.client_ref;
      if (!messageId) return;
      try {
        const updated = await invoke<BackendMessage | null>("messaging_mark_message_send_failed", { messageId });
        if (!updated) return;
        const msg = messageFromBackend(updated);
        setMessages(prev => {
          const contactId = updated.contact_id;
          const existing = prev[contactId] ?? [];
          return { ...prev, [contactId]: existing.map(m => m.id === msg.id ? msg : m) };
        });
      } catch {}
    });

    const unlistenMessage = listen<IncomingMessageEvent>("axeno-message", (event) => {
      const contactId = event.payload.contact_id;
      const msg = messageFromBackend(event.payload.message);
      setMessages(prev => {
        const existing = prev[contactId] ?? [];
        if (existing.some(m => m.id === msg.id)) return prev;
        return { ...prev, [contactId]: [...existing, msg] };
      });

      const activeNow = activeContactIdRef.current;
      const isOpenChat = !activeNow || activeNow === contactId;
      if (!activeNow) {
        activeContactIdRef.current = contactId;
        setActiveContactId(contactId);
      }

      const refreshAfterRead = async () => {
        if (isOpenChat) await markContactRead(contactId).catch(() => {});
        await loadMessaging().catch(() => {});
      };
      void refreshAfterRead();
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
      unlistenServerStatus.then(f => f());
      unlistenSendReceipt.then(f => f());
      unlistenSendFailed.then(f => f());
      unlistenMessage.then(f => f());
      Object.values(reconnectTimersRef.current).forEach(timer => window.clearTimeout(timer));
      reconnectTimersRef.current = {};
    };
  }, [loadMessaging, loadPrivateServerSettings, markContactRead]);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoginError("");
    setIsUnlocking(true);
    try {
      const passphrase = loginPasswordRef.current?.value ?? "";
      const res = await invoke<UnlockResponse>("unlock_identity", { passphrase });
      if (loginPasswordRef.current) loginPasswordRef.current.value = "";
      setLoginPasswordReady(false);
      setDisplayName(res.display_name);
      await loadMessaging();
      await loadPrivateServerSettings().catch(() => setServerSettingsLoaded(true));
      setAppState("chat");
    } catch {
      setLoginError("Incorrect password.");
    } finally {
      if (loginPasswordRef.current) loginPasswordRef.current.value = "";
      setLoginPasswordReady(false);
      setIsUnlocking(false);
    }
  };

  const handleOnboardingComplete = async (name: string) => {
    setDisplayName(name);
    await loadMessaging().catch(() => {});
    await loadPrivateServerSettings().catch(() => setServerSettingsLoaded(true));
    setAppState("chat");
  };

  const handleAddedContact = async (contact: BackendContact) => {
    const c = contactFromBackend(contact);
    setContacts(prev => prev.some(x => x.id === c.id) ? prev : [...prev, c]);
    setActiveContactId(c.id);
    invoke("messaging_connect_all").catch(() => {});
  };

  const sendMessage = async (contactId: string, text: string) => {
    // Optimistic: show bubble immediately with "sending" status
    const optimisticId = `pending_${Date.now()}_${Math.random().toString(36).slice(2)}`;
    const optimisticMsg: Message = {
      id: optimisticId,
      text,
      mine: true,
      timestamp: Date.now(),
      status: "relay_pending",
    };
    setMessages(prev => ({ ...prev, [contactId]: [...(prev[contactId] ?? []), optimisticMsg] }));

    try {
      const res = await invoke<SendMessageResponse>("messaging_send_text_message", { contactId, text });
      const msg = messageFromBackend(res.message);
      // Replace optimistic message with real one from backend
      setMessages(prev => {
        const existing = prev[contactId] ?? [];
        return { ...prev, [contactId]: existing.map(m => m.id === optimisticId ? msg : m) };
      });
    } catch (e) {
      // Mark optimistic message as failed
      setMessages(prev => {
        const existing = prev[contactId] ?? [];
        return { ...prev, [contactId]: existing.map(m => m.id === optimisticId ? { ...m, status: "send_failed" } : m) };
      });
      throw e;
    }
  };

  const migrateContactRelay = async (contactId: string, code: string) => {
    const updated = await invoke<BackendContact>("messaging_migrate_contact_with_code", { contactId, code });
    const next = contactFromBackend(updated);
    setContacts(prev => prev.map(c => c.id === contactId ? next : c));
    invoke("messaging_connect_all").catch(() => {});
    await loadMessaging().catch(() => {});
  };

  const selectContact = async (id: string) => {
    setActiveContactId(id);
    activeContactIdRef.current = id;
    await markContactRead(id).catch(() => {});
  };

  const active = contacts.find(c => c.id === activeContactIdForUi) || contacts[0];


  if (appState === "loading") {
    return <div className="app-root app-centered"><div className="onboarding-spinner app-loading-spinner" /></div>;
  }

  if (appState === "onboarding") return <Onboarding onComplete={handleOnboardingComplete} />;

  if (appState === "login") {
    return (
      <div className="onboarding-root">
        <div className="onboarding-card">
          <h1 className="onboarding-title">Welcome back</h1>
          <form onSubmit={handleLogin} className="login-form">
            <input type="password" className="onboarding-key-input" placeholder="Password" ref={loginPasswordRef} onChange={(e) => { setLoginPasswordReady(e.currentTarget.value.length > 0); setLoginError(""); }} autoFocus />
            {loginError && <div className="onboarding-error">{loginError}</div>}
            <button type="submit" className="btn btn-primary onboarding-btn" disabled={isUnlocking || !loginPasswordReady}>{isUnlocking ? "Unlocking..." : "Unlock"}</button>
          </form>
        </div>
      </div>
    );
  }

  return (
    <div className="app-root">
      <Sidebar contacts={contacts} allMessages={messages} activeContactId={activeContactIdForUi} onSelectContact={selectContact} onOpenAddContact={() => setShowAddContact(true)} onOpenSettings={() => setShowSettings(true)} myInitials={computeInitials(displayName)} myDisplayName={displayName || "Me"} torStatus={torStatus} />

      {active ? (
        <ChatView contact={active} messages={messages[active.id] || []} onOpenChatSettings={() => setShowChatSettings(true)} onSendMessage={(text) => sendMessage(active.id, text)} sendOnEnter={settings.sendOnEnter} messageTextSize={settings.messageTextSize} />
      ) : (
        <main className="chat-view empty-chat">Generate a connection code or add a contact to start messaging.</main>
      )}

      {showSettings && <Settings settings={settings} onChange={setSettings} displayName={displayName} onChangeName={setDisplayName} onClose={() => setShowSettings(false)} torStatus={torStatus} torError={torError} />}
      {showAddContact && <AddContact onClose={() => setShowAddContact(false)} onAdded={handleAddedContact} />}
      {showChatSettings && active && <ChatSettings contact={active} onClose={() => setShowChatSettings(false)} onOpenVerify={() => { setShowChatSettings(false); setShowVerify(true); }} onMigrateRelay={(code) => migrateContactRelay(active.id, code)} />}
      {showVerify && active && <VerifyIdentity contact={active} onClose={() => setShowVerify(false)} onContactUpdated={(updated) => setContacts(prev => prev.map(c => c.id === updated.id ? updated : c))} />}
    </div>
  );
}
