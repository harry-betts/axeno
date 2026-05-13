import { useMemo, useState } from "react";
import { Contact, Message } from "../../types";
import { contactDisplayName, contactInitials, formatMessageTime, lastMessage, unreadCount } from "../../utils";
import { IconSearch, IconPlus, IconSettings } from "../icons";
import "./Sidebar.css";

interface Props {
  contacts: Contact[];
  allMessages: Record<string, Message[]>;
  activeContactId: string;
  onSelectContact: (id: string) => void;
  onOpenAddContact: () => void;
  onOpenSettings: () => void;
  myInitials: string;
  myDisplayName: string;
  torStatus: "connecting" | "connected" | "failed"; // NEW
}

export default function Sidebar({
  contacts, allMessages, activeContactId, onSelectContact,
  onOpenAddContact, onOpenSettings,
  myInitials, myDisplayName, torStatus
}: Props) {
  const [query, setQuery] = useState("");
  const visibleContacts = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return contacts;
    return contacts.filter(c => {
      const msgs = allMessages[c.id] ?? [];
      const last = lastMessage(msgs)?.text ?? "";
      return [contactDisplayName(c), c.recipientId ?? "", last].some(v => v.toLowerCase().includes(q));
    });
  }, [contacts, allMessages, query]);

  return (
    <aside className="sidebar">
      <div className="sidebar-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div className="brand">Axeno</div>
        
        {/* NEW TOR INDICATOR */}
        <div className="sidebar-tor-status" title={`Tor: ${torStatus}`}>
          <span className={`tor-dot ${torStatus}`} />
          <span className="tor-text">Tor</span>
        </div>
      </div>

      <div className="sidebar-search">
        <span className="sidebar-search-icon"><IconSearch /></span>
        <input type="text" placeholder="Search" className="sidebar-search-input" value={query} onChange={e => setQuery(e.target.value)} />
      </div>

      <div className="sidebar-list">
        {visibleContacts.map((c) => {
          const isActive = c.id === activeContactId;
          const msgs = allMessages[c.id] ?? [];
          const last = lastMessage(msgs);
          const preview = last?.text ?? "";
          const time = last ? formatMessageTime(last.timestamp) : "";
          const unread = unreadCount(msgs, c.lastReadAt);
          return (
            <div
              key={c.id}
              onClick={() => onSelectContact(c.id)}
              className={`contact-row ${isActive ? "active" : ""}`}
            >
              <div className="avatar">{contactInitials(c)}</div>
              <div className="contact-info">
                <div className="contact-id">{contactDisplayName(c)}</div>
                <div className="contact-preview">{preview}</div>
              </div>
              <div className="contact-meta">
                <span className="contact-time">{time}</span>
                {unread > 0 && <div className="unread-badge">{unread}</div>}
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