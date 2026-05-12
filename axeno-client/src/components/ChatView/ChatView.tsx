import { useState } from "react";
import { Contact, Message } from "../../types";
import { contactInitials, formatMessageTime } from "../../utils";
import { IconDots, IconPaperclip, IconArrowUp } from "../icons";
import "./ChatView.css";

interface Props {
  contact: Contact;
  messages: Message[];
  onOpenChatSettings: () => void;
}

export default function ChatView({ contact, messages, onOpenChatSettings }: Props) {
  const [input, setInput] = useState("");

  return (
    <main className="chat-view">
      <header className="chat-header">
        <div className="chat-avatar">{contactInitials(contact)}</div>
        <div className="chat-header-info">
          <div className="chat-contact-id">{contact.id}4e9b</div>
        </div>
        <button className="chat-icon-button" onClick={onOpenChatSettings} aria-label="Chat settings">
          <IconDots />
        </button>
      </header>

      <div className="chat-messages">
        <div className="date-divider">
          <span className="date-line"></span>
          <span className="date-label">Today</span>
          <span className="date-line"></span>
        </div>

        {messages.map((msg, i) => {
          const prev = messages[i - 1];
          const isSequenceStart = !prev || prev.mine !== msg.mine;
          return (
            <div
              key={msg.id}
              className={`message-row ${msg.mine ? "mine" : "theirs"}`}
              style={{ marginTop: isSequenceStart && prev ? 10 : 0 }}
            >
              <div className={`bubble ${msg.mine ? "bubble-mine" : "bubble-theirs"}`}>
                {msg.text}
              </div>
              <div className="message-time">{formatMessageTime(msg.timestamp)}</div>
            </div>
          );
        })}
      </div>

      <div className="chat-input-wrap">
        <div className="chat-input-row">
          <button className="chat-input-attach" aria-label="Attach file">
            <IconPaperclip />
          </button>
          <input
            type="text"
            value={input}
            onChange={e => setInput(e.target.value)}
            placeholder="Message"
            className="chat-input"
          />
          <button
            className={`chat-send ${input.length > 0 ? "active" : ""}`}
            aria-label="Send message"
          >
            <IconArrowUp />
          </button>
        </div>
      </div>
    </main>
  );
}
