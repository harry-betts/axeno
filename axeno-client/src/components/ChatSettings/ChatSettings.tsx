import { useState } from "react";
import { Contact } from "../../types";
import { contactDisplayName, contactInitials } from "../../utils";
import {
  IconX, IconShield, IconChevronRight, IconServer,
} from "../icons";
import "./ChatSettings.css";

interface Props {
  contact: Contact;
  onClose: () => void;
  onOpenVerify: () => void;
  onMigrateRelay: (code: string) => Promise<void>;
}

export default function ChatSettings({ contact, onClose, onOpenVerify, onMigrateRelay }: Props) {
  const verifyStatusText = contact.trustState === "verified"
    ? "Verified"
    : contact.trustState === "identity_changed_blocked"
      ? "Key changed"
      : "Not verified";
  const verifyStatusClass = contact.trustState === "verified"
    ? "verified"
    : contact.trustState === "identity_changed_blocked"
      ? "blocked"
      : "unverified";

  const [showMigration, setShowMigration] = useState(false);
  const [migrationCode, setMigrationCode] = useState("");
  const [migrationError, setMigrationError] = useState("");
  const [migrationBusy, setMigrationBusy] = useState(false);

  const submitMigration = async () => {
    const code = migrationCode.trim();
    if (!code) return;
    setMigrationError("");
    setMigrationBusy(true);
    try {
      await onMigrateRelay(code);
      setMigrationCode("");
      setShowMigration(false);
    } catch (err) {
      setMigrationError(err instanceof Error ? err.message : String(err));
    } finally {
      setMigrationBusy(false);
    }
  };

  return (
    <>
      <div className="chat-settings-backdrop" onClick={onClose} />
      <aside className="chat-settings-drawer">
        <header className="chat-settings-header">
          <div className="chat-settings-title">Conversation</div>
          <button className="chat-settings-close" onClick={onClose} aria-label="Close">
            <IconX />
          </button>
        </header>

        <div className="chat-settings-body">
          <div className="chat-settings-identity">
            <div className="chat-settings-avatar">{contactInitials(contact)}</div>
            <div className="chat-settings-contact-id">{contactDisplayName(contact)}</div>
          </div>

          <div className="chat-settings-action-list">
            <button className="chat-settings-action" onClick={onOpenVerify}>
              <span className="chat-settings-action-icon"><IconShield /></span>
              <span className="chat-settings-action-label">Verify identity</span>
              <span className={`chat-settings-action-status ${verifyStatusClass}`}>{verifyStatusText}</span>
              <span className="chat-settings-action-chevron"><IconChevronRight /></span>
            </button>
            <button className="chat-settings-action" onClick={() => setShowMigration(v => !v)}>
              <span className="chat-settings-action-icon"><IconServer /></span>
              <span className="chat-settings-action-label">Migrate relay</span>
              <span className="chat-settings-action-status">Fresh code required</span>
              <span className="chat-settings-action-chevron"><IconChevronRight /></span>
            </button>
          </div>

          <section className="chat-settings-section">
            <div className="chat-settings-section-title">Server</div>
            <div className="chat-settings-section-desc">
              Current relay: <span className="chat-settings-mono">{contact.serverUrl || "unknown"}</span>
            </div>
            <div className="chat-settings-section-desc">
              Relay migration needs a fresh connection code from this same contact. Axeno refuses the move if the code has a different identity key.
            </div>
          </section>

          {showMigration && (
            <section className="chat-settings-section chat-settings-migration">
              <div className="chat-settings-section-title">Fresh relay code</div>
              <textarea
                className="chat-settings-code-input"
                placeholder="Paste their new connection code here"
                value={migrationCode}
                onChange={(e) => { setMigrationCode(e.target.value); setMigrationError(""); }}
              />
              {migrationError && <div className="chat-settings-error">{migrationError}</div>}
              <div className="chat-settings-button-row">
                <button className="btn btn-primary" onClick={submitMigration} disabled={migrationBusy || !migrationCode.trim()}>
                  {migrationBusy ? "Migrating…" : "Accept migration"}
                </button>
                <button className="btn btn-secondary" onClick={() => { setShowMigration(false); setMigrationCode(""); setMigrationError(""); }} disabled={migrationBusy}>Cancel</button>
              </div>
            </section>
          )}
        </div>
      </aside>
    </>
  );
}
