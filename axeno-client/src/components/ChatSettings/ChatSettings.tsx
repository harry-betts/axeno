import { Contact, AppSettings, ServerChoice } from "../../types";
import { contactDisplayName, contactInitials } from "../../utils";
import {
  IconX, IconShield, IconChevronRight, IconChevronDown,
} from "../icons";
import "./ChatSettings.css";

interface Props {
  contact: Contact;
  settings: AppSettings;
  onClose: () => void;
  onOpenVerify: () => void;
  onUpdateContactServer: (id: string, server: ServerChoice) => void | Promise<void>;
}

export default function ChatSettings({ contact, settings, onClose, onOpenVerify, onUpdateContactServer }: Props) {
  const currentChoice: ServerChoice = contact.serverChoice ?? settings.defaultServer;

  const onChangeServer = (val: string) => {
    if (val === "official") {
      onUpdateContactServer(contact.id, { kind: "official" });
    } else if (val.startsWith("private:")) {
      const serverId = val.slice("private:".length);
      onUpdateContactServer(contact.id, { kind: "private", serverId });
    }
  };

  const selectValue =
    currentChoice.kind === "official"
      ? "official"
      : `private:${currentChoice.serverId}`;

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
              <span className="chat-settings-action-status">{contact.trustState === "verified" ? "Verified" : contact.trustState === "identity_changed_blocked" ? "Key changed" : "Not verified"}</span>
              <span className="chat-settings-action-chevron"><IconChevronRight /></span>
            </button>
          </div>

          <section className="chat-settings-section">
            <div className="chat-settings-section-title">Server</div>
            <div className="chat-settings-section-desc">
              Where your messages to this contact are deposited. Defaults to your global setting.
            </div>
            <div className="select-wrap chat-settings-select-wrap">
              <select
                className="select chat-settings-select"
                value={selectValue}
                onChange={(e) => onChangeServer(e.target.value)}
              >
                <option value="official">Local dev relay</option>
                {settings.privateServers.map(s => (
                  <option key={s.id} value={`private:${s.id}`}>{s.name}</option>
                ))}
              </select>
              <span className="select-chevron"><IconChevronDown /></span>
            </div>
          </section>
        </div>
      </aside>
    </>
  );
}
