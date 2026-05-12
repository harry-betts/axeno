import { useState } from "react";
import { AppSettings, PrivateServer, ServerChoice } from "../../types";
import { mockMyIdentity } from "../../mockData";
import {
  IconArrowLeft, IconKey, IconServer, IconShield, IconBell, IconEye,
  IconInfo, IconCopy, IconPlus, IconTrash, IconCheck, IconChevronDown,
} from "../icons";
import "./Settings.css";

type Section = "identity" | "servers" | "privacy" | "notifications" | "appearance" | "advanced" | "about";

interface Props {
  settings: AppSettings;
  onChange: (settings: AppSettings) => void;
  onClose: () => void;
}

export default function Settings({ settings, onChange, onClose }: Props) {
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
          <NavItem icon={<IconKey />}    label="Identity"      active={section === "identity"}      onClick={() => setSection("identity")} />
          <NavItem icon={<IconServer />} label="Servers"       active={section === "servers"}       onClick={() => setSection("servers")} />
          <NavItem icon={<IconShield />} label="Privacy"       active={section === "privacy"}       onClick={() => setSection("privacy")} />
          <NavItem icon={<IconBell />}   label="Notifications" active={section === "notifications"} onClick={() => setSection("notifications")} />
          <NavItem icon={<IconEye />}    label="Appearance"    active={section === "appearance"}    onClick={() => setSection("appearance")} />
          <NavItem icon={<IconShield />} label="Advanced"      active={section === "advanced"}      onClick={() => setSection("advanced")} />
          <NavItem icon={<IconInfo />}   label="About"         active={section === "about"}         onClick={() => setSection("about")} />
        </nav>

        <main className="settings-content">
          {section === "identity"      && <IdentitySection />}
          {section === "servers"       && <ServersSection settings={settings} onChange={onChange} />}
          {section === "privacy"       && <PrivacySection settings={settings} onChange={onChange} />}
          {section === "notifications" && <NotificationsSection settings={settings} onChange={onChange} />}
          {section === "appearance"    && <AppearanceSection settings={settings} onChange={onChange} />}
          {section === "advanced"      && <AdvancedSection settings={settings} onChange={onChange} />}
          {section === "about"         && <AboutSection />}
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

function IdentitySection() {
  return (
    <Section
      title="Identity"
      description="Your identity is a cryptographic keypair generated on this device. It is never shared with the server and never recoverable if lost."
    >
      <div className="identity-card">
        <div className="identity-avatar">{mockMyIdentity.initials}</div>
        <div className="identity-fingerprint-block">
          <div className="identity-label">Public key fingerprint</div>
          <div className="identity-fingerprint">{mockMyIdentity.fingerprint}</div>
        </div>
      </div>

      <div className="button-row">
        <button className="btn btn-secondary"><IconCopy /> Copy contact link</button>
        <button className="btn btn-secondary"><IconCopy /> Copy fingerprint</button>
      </div>

      <div className="danger-zone">
        <div className="danger-zone-label">Danger zone</div>
        <Row
          label="Regenerate identity"
          description="Creates a new keypair. All existing contacts will need to verify you again. This cannot be undone."
          control={<button className="btn btn-danger">Regenerate</button>}
        />
      </div>
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
      title="Servers"
      description="Choose where messages addressed to you are stored. The official servers are operated by the Axeno project and route everything through Tor. Self-hosted servers give you full sovereignty over your message queues."
    >
      <div className="server-list">
        <ServerOption
          name="Official servers"
          description="Operated by the Axeno project · routed via Tor"
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
            placeholder="abc123...xyz.onion"
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

function PrivacySection({ settings, onChange }: { settings: AppSettings; onChange: (s: AppSettings) => void }) {
  return (
    <Section title="Privacy">
      <Row
        label="Read receipts"
        description="Let contacts see when you have read their messages."
        control={<Toggle on={settings.readReceipts} onChange={(v) => onChange({ ...settings, readReceipts: v })} />}
      />
      <Row
        label="Default disappearing messages"
        description="Set how long new conversations keep messages by default. Can be overridden per chat."
        control={
          <Select
            value={String(settings.defaultDisappearingMessages) as any}
            options={[
              { value: "0",      label: "Off" },
              { value: "3600",   label: "1 hour" },
              { value: "86400",  label: "1 day" },
              { value: "604800", label: "7 days" },
              { value: "2592000", label: "30 days" },
            ]}
            onChange={(v) => onChange({ ...settings, defaultDisappearingMessages: parseInt(v) })}
          />
        }
      />
    </Section>
  );
}

function NotificationsSection({ settings, onChange }: { settings: AppSettings; onChange: (s: AppSettings) => void }) {
  return (
    <Section
      title="Notifications"
      description="Notifications are generated locally. They never include the server in the loop."
    >
      <Row
        label="Enable notifications"
        control={<Toggle on={settings.notificationsEnabled} onChange={(v) => onChange({ ...settings, notificationsEnabled: v })} />}
      />
      <Row
        label="Show message preview"
        description="Include the message text in the notification."
        control={<Toggle on={settings.notificationShowPreview} onChange={(v) => onChange({ ...settings, notificationShowPreview: v })} />}
      />
      <Row
        label="Show sender"
        description="Include the contact identifier in the notification."
        control={<Toggle on={settings.notificationShowSender} onChange={(v) => onChange({ ...settings, notificationShowSender: v })} />}
      />
    </Section>
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
              { value: "small",  label: "Small" },
              { value: "medium", label: "Medium" },
              { value: "large",  label: "Large" },
            ]}
            onChange={(v) => onChange({ ...settings, messageTextSize: v })}
          />
        }
      />
      <Row
        label="Send with Enter"
        description="When off, Enter inserts a new line and you send with Ctrl+Enter."
        control={<Toggle on={settings.sendOnEnter} onChange={(v) => onChange({ ...settings, sendOnEnter: v })} />}
      />
    </Section>
  );
}

function AdvancedSection({ settings, onChange }: { settings: AppSettings; onChange: (s: AppSettings) => void }) {
  return (
    <Section title="Advanced">
      <Row
        label="Local message retention"
        description="How long undelivered messages are kept on the relay before being dropped."
        control={
          <Select
            value={String(settings.messageRetentionDays) as any}
            options={[
              { value: "7",  label: "7 days" },
              { value: "14", label: "14 days" },
              { value: "30", label: "30 days" },
              { value: "60", label: "60 days" },
            ]}
            onChange={(v) => onChange({ ...settings, messageRetentionDays: parseInt(v) })}
          />
        }
      />
      <div className="danger-zone">
        <div className="danger-zone-label">Danger zone</div>
        <Row
          label="Export identity backup"
          description="Encrypted with a passphrase you choose. Required to migrate this identity to another device."
          control={<button className="btn btn-secondary">Export</button>}
        />
        <Row
          label="Clear local data"
          description="Removes all local message history. Does not affect undelivered messages on relays."
          control={<button className="btn btn-danger">Clear</button>}
        />
      </div>
    </Section>
  );
}

function AboutSection() {
  return (
    <Section title="About">
      <div className="about-block">
        <div className="about-row"><span>Version</span><span className="mono">0.1.0-dev</span></div>
        <div className="about-row"><span>Build</span><span className="mono">7f3c9a2</span></div>
        <div className="about-row"><span>Protocol</span><span>Signal Protocol with PQXDH</span></div>
        <div className="about-row"><span>Transport</span><span>Tor (arti embedded)</span></div>
      </div>
      <div className="button-row">
        <button className="btn btn-secondary">View source</button>
        <button className="btn btn-secondary">Architecture spec</button>
        <button className="btn btn-secondary">Warrant canary</button>
      </div>
    </Section>
  );
}
