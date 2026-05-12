import { useState } from "react";
import { IconX } from "../icons";
import "./AddContact.css";

interface Props {
  onClose: () => void;
}

export default function AddContact({ onClose }: Props) {
  const [code, setCode] = useState("");

  return (
    <>
      <div className="modal-backdrop" onClick={onClose} />
      <div className="modal add-contact-modal">
        <header className="modal-header">
          <div className="modal-title">Add contact</div>
          <button className="modal-close" onClick={onClose} aria-label="Close">
            <IconX />
          </button>
        </header>

        <div className="modal-body">
          <p className="add-contact-desc">
            Enter the connection code you received from someone to start a conversation.
          </p>

          <input
            type="text"
            className="text-input mono add-contact-input"
            placeholder="axn-xxxx-xxxx-xxxx"
            value={code}
            onChange={e => setCode(e.target.value)}
            autoFocus
            spellCheck={false}
          />

          <div className="add-contact-actions">
            <button className="btn btn-primary" disabled={!code.trim()}>
              Add contact
            </button>
          </div>
        </div>
      </div>
    </>
  );
}
