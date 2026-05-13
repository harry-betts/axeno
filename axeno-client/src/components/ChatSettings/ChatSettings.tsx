import { Contact } from "../../types";
import { contactDisplayName, contactInitials } from "../../utils";
import {
  IconX, IconShield, IconChevronRight,
} from "../icons";
import "./ChatSettings.css";

interface Props {
  contact: Contact;
  onClose: () => void;
  onOpenVerify: () => void;
}

export default function ChatSettings({ contact, onClose, onOpenVerify }: Props) {
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
              This contact's relay and mailbox come from their connection code. Changing it safely requires a fresh code from that contact.
            </div>
          </section>
        </div>
      </aside>
    </>
  );
}
