import { useEffect, useState } from "react";
import { AppSettings, InviteCode, PrivateServer, ServerChoice } from "../../types";
import {
  IconArrowLeft, IconKey, IconServer, IconEye,
  IconInfo, IconCopy, IconPlus, IconTrash, IconCheck, IconChevronDown, IconEdit,
} from "../icons";
import { invoke } from "@tauri-apps/api/core";
import "./Settings.css";

type Section = "identity" | "servers" | "appearance" | "about";

interface Props {
  settings: AppSettings;
  onChange: (settings: AppSettings) => void;
  onClose: () => void;
  displayName: string;
  onChangeName: (name: string) => void;
  torStatus: "connecting" | "connected" | "failed";
  torError?: string;
}

export default function Settings({
  settings, onChange, onClose, displayName, onChangeName, torStatus, torError,
}: Props) {
  const [section, setSection] = useState<Section>("identity");

  return (
    <div className="settings-root">
      <header className="settings-topbar">
        <button className="settings-back" onClick={onClose} aria-label="Close settings">
          <IconArrowLeft />
        </button>
        <div className="settings-title">Settings</div>
      </header>

      <div className="settings-layout">
        <nav className="settings-nav">
          <NavItem icon={<IconKey />} label="Identity" active={section === "identity"} onClick={() => setSection("identity")} />
          <NavItem icon={<IconServer />} label="Servers" active={section === "servers"} onClick={() => setSection("servers")} />
          <NavItem icon={<IconEye />} label="Appearance" active={section === "appearance"} onClick={() => setSection("appearance")} />
          <NavItem icon={<IconInfo />} label="About" active={section === "about"} onClick={() => setSection("about")} />
        </nav>

        <main className="settings-content">
          {section === "identity" && <IdentitySection displayName={displayName} onChangeName={onChangeName} inviteCodes={settings.inviteCodes} onChangeInviteCodes={(inviteCodes) => onChange({ ...settings, inviteCodes })} defaultServerUrl={defaultServerUrl(settings)} />}
          {section === "servers" && <ServersSection settings={settings} onChange={onChange} />}
          {section === "appearance" && <AppearanceSection settings={settings} onChange={onChange} />}
          {section === "about" && <AboutSection torStatus={torStatus} torError={torError} />}
        </main>
      </div>
    </div>
  );
}

function NavItem({ icon, label, active, onClick }: { icon: React.ReactNode; label: string; active: boolean; onClick: () => void }) {
  return (
    <button className={`settings-nav-item ${active ? "active" : ""}`} onClick={onClick}>
      <span className="settings-nav-icon">{icon}</span>
      <span>{label}</span>
    </button>
  );
}

function Section({ title, description, children }: { title: string; description?: string; children: React.ReactNode }) {
  return (
    <section className="settings-section">
      <div className="settings-section-header">
        <h2 className="settings-section-title">{title}</h2>
        {description && <p className="settings-section-desc">{description}</p>}
      </div>
      <div className="settings-section-body">{children}</div>
    </section>
  );
}

function Row({ label, description, control }: { label: string; description?: string; control: React.ReactNode }) {
  return (
    <div className="settings-row">
      <div className="settings-row-text">
        <div className="settings-row-label">{label}</div>
        {description && <div className="settings-row-desc">{description}</div>}
      </div>
      <div className="settings-row-control">{control}</div>
    </div>
  );
}

function Toggle({ on, onChange }: { on: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      className={`toggle ${on ? "on" : ""}`}
      onClick={() => onChange(!on)}
      role="switch"
      aria-checked={on}
    >
      <span className="toggle-knob" />
    </button>
  );
}

function Select<T extends string>({ value, options, onChange }: { value: T; options: { value: T; label: string }[]; onChange: (v: T) => void }) {
  return (
    <div className="select-wrap">
      <select className="select" value={value} onChange={e => onChange(e.target.value as T)}>
        {options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
      <span className="select-chevron"><IconChevronDown /></span>
    </div>
  );
}

// ---------- Sections ----------

function computeInitials(name: string): string {
  return name.trim().split(/\s+/).map(w => w[0]).join("").slice(0, 2).toUpperCase() || "?";
}

function compactConnectionCode(code: string): string {
  if (code.length <= 34) return code;
  return `${code.slice(0, 18)}…${code.slice(-10)}`;
}

function defaultServerUrl(settings: AppSettings): string {
  const choice = settings.defaultServer;
  if (choice.kind === "private") {
    const server = settings.privateServers.find(s => s.id === choice.serverId);
    if (server) return server.onion;
  }
  return "ws://127.0.0.1:8787/ws";
}

function IdentitySection({ displayName, onChangeName, inviteCodes, onChangeInviteCodes, defaultServerUrl }: {
  displayName: string;
  onChangeName: (name: string) => void;
  inviteCodes: InviteCode[];
  onChangeInviteCodes: (inviteCodes: InviteCode[]) => void;
  defaultServerUrl: string;
}) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(displayName);
  const [copied, setCopied] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string>("");

  // Change-password modal state
  const [showPwModal, setShowPwModal] = useState(false);
  const [newPw, setNewPw] = useState("");
  const [confirmPw, setConfirmPw] = useState("");
  const [pwError, setPwError] = useState("");
  const [pwBusy, setPwBusy] = useState(false);

  const saveName = async () => {
    const trimmed = draft.trim();
    if (!trimmed) { setEditing(false); return; }
    setSaveError("");
    try {
      // The backend operates on the unlocked session. No passphrase passed
      // from the frontend — the KEK lives in Rust memory.
      await invoke("update_display_name", { newName: trimmed });
      onChangeName(trimmed);
      setEditing(false);
    } catch (e) {
      setSaveError(typeof e === "string" ? e : "Could not save name");
    }
  };

  const cancelEdit = () => {
    setDraft(displayName);
    setSaveError("");
    setEditing(false);
  };

  useEffect(() => {
    invoke<Array<{ id: string; code: string; created_at: number; server_url: string }>>("messaging_list_connection_codes")
      .then(codes => onChangeInviteCodes(codes.map(c => ({ id: c.id, code: c.code, createdAt: c.created_at, serverUrl: c.server_url }))))
      .catch(() => {});
  }, []);

  const addCode = async () => {
    try {
      const next = await invoke<{ id: string; code: string; created_at: number; server_url: string }>("messaging_generate_connection_code", {
        serverUrl: defaultServerUrl,
      });
      onChangeInviteCodes([...inviteCodes, { id: next.id, code: next.code, createdAt: next.created_at, serverUrl: next.server_url }]);
      await invoke("messaging_connect_all").catch(() => {});
    } catch (e) {
      setSaveError(typeof e === "string" ? e : "Could not generate connection code");
    }
  };

  const removeCode = async (id: string) => {
    await invoke("messaging_delete_connection_code", { id }).catch(() => {});
    onChangeInviteCodes(inviteCodes.filter(c => c.id !== id));
  };

  const copyCode = (id: string, code: string) => {
    navigator.clipboard.writeText(code);
    setCopied(id);
    setTimeout(() => setCopied(null), 1500);
  };

  const submitNewPassword = async () => {
    if (newPw.length < 8) { setPwError("Password must be at least 8 characters."); return; }
    if (newPw !== confirmPw) { setPwError("Passwords do not match."); return; }
    setPwError("");
    setPwBusy(true);
    try {
      await invoke("change_password", { newPassphrase: newPw });
      setShowPwModal(false);
      setNewPw("");
      setConfirmPw("");
    } catch (e) {
      setPwError(typeof e === "string" ? e : "Failed to change password.");
    } finally {
      setPwBusy(false);
    }
  };

  return (
    <Section
      title="Identity"
      description="Your identity is a cryptographic keypair generated on this device. It is never shared with the server and never recoverable if lost."
    >
      <div className="identity-card">
        <div className="identity-avatar">{computeInitials(displayName)}</div>
        <div className="identity-info">
          {editing ? (
            <div className="identity-name-edit">
              <input
                className="text-input identity-name-input"
                value={draft}
                onChange={e => setDraft(e.target.value)}
                onKeyDown={e => { if (e.key === "Enter") saveName(); if (e.key === "Escape") cancelEdit(); }}
                autoFocus
                maxLength={40}
              />
              <div className="identity-name-edit-actions">
                <button className="btn btn-primary" onClick={saveName} disabled={!draft.trim()}>Save</button>
                <button className="btn btn-secondary" onClick={cancelEdit}>Cancel</button>
              </div>
              {saveError && <div className="onboarding-error" style={{ marginTop: 8 }}>{saveError}</div>}
            </div>
          ) : (
            <div className="identity-name-row">
              <span className="identity-name">{displayName}</span>
              <button className="identity-edit-btn" onClick={() => { setDraft(displayName); setEditing(true); }} title="Change name">
                <IconEdit />
              </button>
            </div>
          )}
        </div>
      </div>

      <div className="inviteCodes-block">
        <div className="inviteCodes-block-header">
          {/* This header will now be styled as a bold sub-section */}
          <div className="inviteCodes-block-title">Connection Codes</div>
          <div className="inviteCodes-block-desc">
            Share a code with someone so they can start a conversation with you.
            Each code gets its own routing mailbox and expires after 24 hours; deleting it disables your local receive route. Codes are stored only in the encrypted backend store, not browser storage.
          </div>
        </div>

        <div className="code-list">
          {inviteCodes.length === 0 && (
            <div className="code-empty">No connection codes. Generate one below.</div>
          )}
          {inviteCodes.map(c => (
            <div className="code-item" key={c.id}>
              <div className="code-main">
                <span className="code-string" title={c.code}>{compactConnectionCode(c.code)}</span>
                <span className="code-server" title={c.serverUrl}>Relay: {c.serverUrl || "unknown"}</span>
              </div>
              <div className="code-actions">
                <button
                  className="code-action-btn"
                  onClick={() => copyCode(c.id, c.code)}
                  title="Copy code"
                >
                  {copied === c.id ? <IconCheck /> : <IconCopy />}
                </button>
                <button
                  className="code-action-btn danger"
                  onClick={() => removeCode(c.id)}
                  title="Delete code"
                >
                  <IconTrash />
                </button>
              </div>
            </div>
          ))}
        </div>

        <button className="btn btn-secondary inviteCodes-generate-btn" onClick={addCode}>
          <IconPlus /> Generate new code
        </button>
      </div>

      <Row
        label="Change password"
        description="Set a new password for encrypting your vault. Your private keys are re-encrypted with the new password."
        control={<button className="btn btn-secondary" onClick={() => setShowPwModal(true)}>Change…</button>}
      />

      {showPwModal && (
        <div className="settings-modal-backdrop" onClick={() => !pwBusy && setShowPwModal(false)}>
          <div className="settings-modal" onClick={(e) => e.stopPropagation()}>
            <h3 className="settings-modal-title">Change password</h3>
            <p className="settings-modal-desc">
              Your vault will be re-encrypted with the new password. You will need this
              password to unlock Axeno next time.
            </p>
            <input
              type="password"
              className="text-input"
              placeholder="New password"
              value={newPw}
              onChange={(e) => { setNewPw(e.target.value); setPwError(""); }}
              autoFocus
            />
            <input
              type="password"
              className="text-input"
              placeholder="Confirm new password"
              value={confirmPw}
              onChange={(e) => { setConfirmPw(e.target.value); setPwError(""); }}
            />
            {pwError && <div className="onboarding-error">{pwError}</div>}
            <div className="button-row">
              <button className="btn btn-primary" onClick={submitNewPassword} disabled={pwBusy || !newPw || !confirmPw}>
                {pwBusy ? "Saving…" : "Save"}
              </button>
              <button className="btn btn-secondary" onClick={() => setShowPwModal(false)} disabled={pwBusy}>Cancel</button>
            </div>
          </div>
        </div>
      )}
    </Section>
  );
}

function ServersSection({ settings, onChange }: { settings: AppSettings; onChange: (s: AppSettings) => void }) {
  const [showAdd, setShowAdd] = useState(false);
  const [newName, setNewName] = useState("");
  const [newOnion, setNewOnion] = useState("");

  const addServer = () => {
    if (!newName.trim() || !newOnion.trim()) return;
    const server: PrivateServer = {
      id: `srv_${Date.now()}`,
      name: newName.trim(),
      onion: newOnion.trim(),
    };
    onChange({ ...settings, privateServers: [...settings.privateServers, server] });
    setNewName(""); setNewOnion(""); setShowAdd(false);
  };

  const removeServer = (id: string) => {
    const updated = settings.privateServers.filter(s => s.id !== id);
    let defaultServer = settings.defaultServer;
    if (defaultServer.kind === "private" && defaultServer.serverId === id) {
      defaultServer = { kind: "official" };
    }
    onChange({ ...settings, privateServers: updated, defaultServer });
  };

  const setDefault = (choice: ServerChoice) => {
    onChange({ ...settings, defaultServer: choice });
  };

  return (
    <Section
      title="Select default server"
      description="Choose where messages addressed to you are stored. This dev build has no real official relay configured; the built-in option is localhost only. For real use, add a self-hosted .onion WebSocket relay. Selecting a default server here only applies to new connection codes."
    >
      <div className="server-list">
        <ServerOption
          name="Local dev relay"
          description="localhost only · not anonymous · development/testing"
          selected={settings.defaultServer.kind === "official"}
          onClick={() => setDefault({ kind: "official" })}
        />
        {settings.privateServers.map(s => (
          <ServerOption
            key={s.id}
            name={s.name}
            description={s.onion}
            selected={settings.defaultServer.kind === "private" && settings.defaultServer.serverId === s.id}
            onClick={() => setDefault({ kind: "private", serverId: s.id })}
            onDelete={() => removeServer(s.id)}
          />
        ))}
      </div>

      {!showAdd ? (
        <button className="btn btn-secondary add-server-btn" onClick={() => setShowAdd(true)}>
          <IconPlus /> Add self-hosted server
        </button>
      ) : (
        <div className="add-server-form">
          <div className="add-server-title">Add self-hosted server</div>
          <input
            type="text"
            className="text-input"
            placeholder="Display name (e.g. My VPS)"
            value={newName}
            onChange={e => setNewName(e.target.value)}
          />
          <input
            type="text"
            className="text-input mono"
            placeholder="ws://abc123...xyz.onion/ws"
            value={newOnion}
            onChange={e => setNewOnion(e.target.value)}
          />
          <div className="button-row">
            <button className="btn btn-primary" onClick={addServer}>Add</button>
            <button className="btn btn-secondary" onClick={() => { setShowAdd(false); setNewName(""); setNewOnion(""); }}>Cancel</button>
          </div>
        </div>
      )}
    </Section>
  );
}

function ServerOption({ name, description, selected, onClick, onDelete }: { name: string; description: string; selected: boolean; onClick: () => void; onDelete?: () => void }) {
  return (
    <div className={`server-option ${selected ? "selected" : ""}`} onClick={onClick}>
      <div className="server-radio">
        {selected && <div className="server-radio-dot" />}
      </div>
      <div className="server-info">
        <div className="server-name">{name}</div>
        <div className="server-onion">{description}</div>
      </div>
      {onDelete && (
        <button
          className="server-delete"
          onClick={(e) => { e.stopPropagation(); onDelete(); }}
          aria-label={`Delete ${name}`}
        >
          <IconTrash />
        </button>
      )}
    </div>
  );
}

function AppearanceSection({ settings, onChange }: { settings: AppSettings; onChange: (s: AppSettings) => void }) {
  return (
    <Section title="Appearance">
      <Row
        label="Message text size"
        control={
          <Select
            value={settings.messageTextSize}
            options={[
              { value: "small", label: "Small" },
              { value: "medium", label: "Medium" },
              { value: "large", label: "Large" },
            ]}
            onChange={(v) => onChange({ ...settings, messageTextSize: v })}
          />
        }
      />
      <Row
        label="Send with Enter"
        description="When off, only Ctrl+Enter sends."
        control={<Toggle on={settings.sendOnEnter} onChange={(v) => onChange({ ...settings, sendOnEnter: v })} />}
      />
    </Section>
  );
}


function AboutSection({ torStatus, torError }: { torStatus: "connecting" | "connected" | "failed"; torError?: string }) {
  const torLabel =
    torStatus === "connected" ? "Connected" :
      torStatus === "connecting" ? "Bootstrapping…" :
        `Failed${torError ? `: ${torError}` : ""}`;

  return (
    <Section title="About">
      <div className="about-block">
        <div className="about-row"><span>Version</span><span className="mono">0.1.0-dev</span></div>
        <div className="about-row"><span>Protocol</span><span>1:1 text uses libsignal-protocol sessions and libsignal Sealed Sender envelopes. Sender certificates are route-scoped so the relay does not receive your long-term Signal identity key.</span></div>
        <div className="about-row"><span>Relay metadata</span><span>The relay sees destination mailboxes, delivery-token proof, ciphertext size/timing, and the authenticated receive mailbox for the socket used to submit a send. Axeno now uses per-contact return mailboxes to reduce cross-contact linking, but it is not mixnet-level anonymous.</span></div>
        <div className="about-row"><span>Transport</span><span>Local WebSocket for development; .onion WebSocket through Tor for real relay use.</span></div>
        <div className="about-row"><span>Tor status</span><span>{torLabel}</span></div>
      </div>
    </Section>
  );
}
