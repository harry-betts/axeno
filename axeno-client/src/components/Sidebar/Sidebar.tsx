import { Contact } from "../../types";
import { IconSearch, IconPlus, IconSettings } from "../icons";
import "./Sidebar.css";

interface Props {
  contacts: Contact[];
  activeContactId: string;
  onSelectContact: (id: string) => void;
  onOpenAddContact: () => void;
  onOpenSettings: () => void;
  myInitials: string;
  myDisplayName: string;
}

export default function Sidebar({
  contacts, activeContactId, onSelectContact,
  onOpenAddContact, onOpenSettings,
  myInitials, myDisplayName,
}: Props) {
  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        <div className="brand">Axeno</div>
      </div>

      <div className="sidebar-search">
        <span className="sidebar-search-icon"><IconSearch /></span>
        <input type="text" placeholder="Search" className="sidebar-search-input" />
      </div>

      <div className="sidebar-list">
        {contacts.map((c) => {
          const isActive = c.id === activeContactId;
          return (
            <div
              key={c.id}
              onClick={() => onSelectContact(c.id)}
              className={`contact-row ${isActive ? "active" : ""}`}
            >
              <div className="avatar">{c.initials}</div>
              <div className="contact-info">
                <div className="contact-id">{c.id}</div>
                <div className="contact-preview">{c.preview}</div>
              </div>
              <div className="contact-meta">
                <span className="contact-time">{c.time}</span>
                {c.unread > 0 && <div className="unread-badge">{c.unread}</div>}
              </div>
            </div>
          );
        })}
      </div>

      <div className="sidebar-footer">
        <div className="me-avatar">{myInitials}</div>
        <span className="me-name">{myDisplayName}</span>
        <button className="icon-button" onClick={onOpenAddContact} aria-label="Add contact">
          <IconPlus />
        </button>
        <button className="icon-button" onClick={onOpenSettings} aria-label="Settings">
          <IconSettings />
        </button>
      </div>
    </aside>
  );
}
