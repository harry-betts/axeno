import { useState } from "react";
import "./App.css";

const contacts = [
  { id: "ax7f2c", initials: "AX", preview: "sounds good to me",       time: "now",   unread: 0 },
  { id: "kp9a1d", initials: "KP", preview: "did you get my message",  time: "14:02", unread: 2 },
  { id: "r3mx8b", initials: "R3", preview: "ok",                      time: "09:41", unread: 0 },
  { id: "fn4e9c", initials: "FN", preview: "meeting at 6?",           time: "Mon",   unread: 0 },
  { id: "zq1b7f", initials: "ZQ", preview: "encrypted file attached", time: "Sun",   unread: 0 },
];

const messages = [
  { id: 1, mine: false, text: "hey, did you get the updated keys I sent over?",                    time: "13:41" },
  { id: 2, mine: false, text: "want to make sure the ratchet state is synced before we proceed",   time: "13:41" },
  { id: 3, mine: true,  text: "yeah got them, verified the fingerprint too",                        time: "13:44" },
  { id: 4, mine: true,  text: "sounds good to me",                                                  time: "13:44" },
];

function IconSearch() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
    </svg>
  );
}

function IconPlus() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
    </svg>
  );
}

function IconSettings() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="3"/>
      <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
    </svg>
  );
}

function IconDots() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="5" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="12" cy="19" r="1"/>
    </svg>
  );
}

function IconPaperclip() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/>
    </svg>
  );
}

function IconArrowUp() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <line x1="12" y1="19" x2="12" y2="5"/><polyline points="5 12 12 5 19 12"/>
    </svg>
  );
}

export default function App() {
  const [activeContact, setActiveContact] = useState("ax7f2c");
  const [input, setInput] = useState("");
  const active = contacts.find(c => c.id === activeContact)!;

  return (
    <div style={{
      display: "flex",
      height: "100vh",
      width: "100vw",
      background: "var(--bg-base)",
      overflow: "hidden",
      color: "var(--text-primary)",
    }}>

      {/* Sidebar */}
      <div style={{
        width: "var(--sidebar-width)",
        minWidth: "var(--sidebar-width)",
        background: "var(--bg-base)",
        borderRight: "1px solid var(--border-subtle)",
        display: "flex",
        flexDirection: "column",
        height: "100%",
      }}>

        {/* Sidebar header */}
        <div style={{
          padding: "20px 18px 14px",
          flexShrink: 0,
        }}>
          <div style={{
            fontSize: 16,
            fontWeight: 600,
            color: "var(--text-primary)",
            letterSpacing: "-0.015em",
          }}>
            Axeno
          </div>
        </div>

        {/* Search */}
        <div style={{ padding: "0 14px 14px", flexShrink: 0 }}>
          <div style={{ position: "relative" }}>
            <span style={{
              position: "absolute",
              left: 10,
              top: "50%",
              transform: "translateY(-50%)",
              color: "var(--text-muted)",
              display: "flex",
              alignItems: "center",
              pointerEvents: "none",
            }}>
              <IconSearch />
            </span>
            <input
              type="text"
              placeholder="Search"
              style={{
                width: "100%",
                background: "var(--bg-elevated)",
                border: "1px solid transparent",
                borderRadius: 6,
                padding: "7px 10px 7px 30px",
                color: "var(--text-primary)",
                fontSize: 12.5,
                outline: "none",
              }}
            />
          </div>
        </div>

        {/* Contact list */}
        <div style={{ flex: 1, overflowY: "auto", padding: "0 8px" }}>
          {contacts.map((c) => {
            const isActive = activeContact === c.id;
            return (
              <div
                key={c.id}
                onClick={() => setActiveContact(c.id)}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 11,
                  padding: "9px 10px",
                  borderRadius: 6,
                  cursor: "pointer",
                  background: isActive ? "var(--bg-active)" : "transparent",
                  marginBottom: 1,
                }}
              >
                <div style={{
                  width: 32,
                  height: 32,
                  borderRadius: "var(--radius-full)",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  fontSize: 10.5,
                  fontWeight: 500,
                  flexShrink: 0,
                  background: "var(--bg-avatar)",
                  color: "var(--text-secondary)",
                  fontFamily: "var(--font-mono)",
                  letterSpacing: "0.02em",
                }}>
                  {c.initials}
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{
                    fontSize: 13,
                    fontWeight: 500,
                    color: "var(--text-primary)",
                    whiteSpace: "nowrap",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    fontFamily: "var(--font-mono)",
                    letterSpacing: "-0.01em",
                  }}>
                    {c.id}
                  </div>
                  <div style={{
                    fontSize: 12,
                    color: "var(--text-muted)",
                    whiteSpace: "nowrap",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    marginTop: 2,
                  }}>
                    {c.preview}
                  </div>
                </div>
                <div style={{
                  display: "flex",
                  flexDirection: "column",
                  alignItems: "flex-end",
                  gap: 5,
                  flexShrink: 0,
                }}>
                  <span style={{
                    fontSize: 10.5,
                    color: "var(--text-faint)",
                    fontVariantNumeric: "tabular-nums",
                  }}>
                    {c.time}
                  </span>
                  {c.unread > 0 && (
                    <div style={{
                      minWidth: 16,
                      height: 16,
                      padding: "0 5px",
                      borderRadius: "var(--radius-full)",
                      background: "var(--text-secondary)",
                      color: "var(--bg-base)",
                      fontSize: 10,
                      fontWeight: 600,
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                    }}>
                      {c.unread}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>

        {/* Footer */}
        <div style={{
          padding: "12px 14px",
          borderTop: "1px solid var(--border-subtle)",
          display: "flex",
          alignItems: "center",
          gap: 10,
          flexShrink: 0,
        }}>
          <div style={{
            width: 26,
            height: 26,
            borderRadius: "var(--radius-full)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontSize: 9.5,
            fontWeight: 500,
            flexShrink: 0,
            background: "var(--bg-avatar)",
            color: "var(--text-secondary)",
            fontFamily: "var(--font-mono)",
          }}>
            HB
          </div>
          <span style={{
            fontFamily: "var(--font-mono)",
            fontSize: 11,
            color: "var(--text-muted)",
            whiteSpace: "nowrap",
            overflow: "hidden",
            textOverflow: "ellipsis",
            flex: 1,
            letterSpacing: "-0.01em",
          }}>
            hb3f9...a2c1
          </span>
          <button style={iconButtonStyle} aria-label="Add contact">
            <IconPlus />
          </button>
          <button style={iconButtonStyle} aria-label="Settings">
            <IconSettings />
          </button>
        </div>
      </div>

      {/* Chat area */}
      <div style={{
        flex: 1,
        display: "flex",
        flexDirection: "column",
        background: "var(--bg-surface)",
        minWidth: 0,
        height: "100%",
      }}>

        {/* Chat header */}
        <div style={{
          padding: "16px 24px",
          borderBottom: "1px solid var(--border-subtle)",
          display: "flex",
          alignItems: "center",
          gap: 12,
          flexShrink: 0,
        }}>
          <div style={{
            width: 30,
            height: 30,
            borderRadius: "var(--radius-full)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontSize: 10,
            fontWeight: 500,
            flexShrink: 0,
            background: "var(--bg-avatar)",
            color: "var(--text-secondary)",
            fontFamily: "var(--font-mono)",
          }}>
            {active.initials}
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{
              fontSize: 13.5,
              fontWeight: 500,
              color: "var(--text-primary)",
              fontFamily: "var(--font-mono)",
              letterSpacing: "-0.01em",
            }}>
              {active.id}4e9b
            </div>
          </div>
          <button style={iconButtonStyle} aria-label="More options">
            <IconDots />
          </button>
        </div>

        {/* Messages */}
        <div style={{
          flex: 1,
          overflowY: "auto",
          padding: "24px 24px 8px",
          display: "flex",
          flexDirection: "column",
          gap: 2,
        }}>
          <div style={{
            display: "flex",
            alignItems: "center",
            gap: 12,
            margin: "0 auto 18px",
            color: "var(--text-faint)",
            fontSize: 10.5,
            letterSpacing: "0.06em",
            textTransform: "uppercase",
            fontWeight: 500,
          }}>
            <div style={{ width: 60, height: 1, background: "var(--border-subtle)" }} />
            Today
            <div style={{ width: 60, height: 1, background: "var(--border-subtle)" }} />
          </div>

          {messages.map((msg, i) => {
            const prev = messages[i - 1];
            const isSequenceStart = !prev || prev.mine !== msg.mine;
            return (
              <div
                key={msg.id}
                style={{
                  display: "flex",
                  flexDirection: "column",
                  alignItems: msg.mine ? "flex-end" : "flex-start",
                  alignSelf: msg.mine ? "flex-end" : "flex-start",
                  maxWidth: "68%",
                  marginTop: isSequenceStart && prev ? 10 : 0,
                }}
              >
                <div style={{
                  padding: "8px 13px",
                  borderRadius: 14,
                  fontSize: 13,
                  lineHeight: 1.5,
                  wordBreak: "break-word",
                  background: msg.mine ? "var(--bubble-mine)" : "var(--bubble-theirs)",
                  color: msg.mine ? "var(--bubble-mine-text)" : "var(--text-primary)",
                }}>
                  {msg.text}
                </div>
                <div style={{
                  fontSize: 10,
                  color: "var(--text-faint)",
                  marginTop: 4,
                  padding: "0 4px",
                  fontVariantNumeric: "tabular-nums",
                }}>
                  {msg.time}
                </div>
              </div>
            );
          })}
        </div>

        {/* Input area */}
        <div style={{
          padding: "12px 24px 18px",
          flexShrink: 0,
        }}>
          <div style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            background: "var(--bg-elevated)",
            border: "1px solid var(--border-subtle)",
            borderRadius: 10,
            padding: "4px 4px 4px 12px",
          }}>
            <button aria-label="Attach file" style={{
              background: "none",
              border: "none",
              color: "var(--text-muted)",
              padding: 4,
              display: "flex",
              alignItems: "center",
              cursor: "pointer",
              flexShrink: 0,
            }}>
              <IconPaperclip />
            </button>
            <input
              type="text"
              value={input}
              onChange={e => setInput(e.target.value)}
              placeholder="Message"
              style={{
                flex: 1,
                background: "none",
                border: "none",
                outline: "none",
                color: "var(--text-primary)",
                fontSize: 13,
                padding: "8px 0",
              }}
            />
            <button aria-label="Send message" style={{
              width: 28,
              height: 28,
              borderRadius: 7,
              background: input.length > 0 ? "var(--accent)" : "var(--bg-elevated-2)",
              border: "none",
              color: input.length > 0 ? "var(--bg-base)" : "var(--text-muted)",
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              flexShrink: 0,
              transition: "background 0.12s, color 0.12s",
            }}>
              <IconArrowUp />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

const iconButtonStyle: React.CSSProperties = {
  background: "none",
  border: "none",
  color: "var(--text-muted)",
  padding: 5,
  borderRadius: 5,
  display: "flex",
  alignItems: "center",
  cursor: "pointer",
};