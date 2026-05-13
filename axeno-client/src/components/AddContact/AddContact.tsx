import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { IconX } from "../icons";
import { BackendContact } from "../../types";
import "./AddContact.css";

interface Props {
  onClose: () => void;
  onAdded: (contact: BackendContact) => void | Promise<void>;
}

export default function AddContact({ onClose, onAdded }: Props) {
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const add = async () => {
    const trimmed = code.trim();
    if (!trimmed || busy) return;
    setBusy(true);
    setError("");
    try {
      const contact = await invoke<BackendContact>("messaging_add_contact_from_code", {
        code: trimmed,
      });
      await onAdded(contact);
      onClose();
    } catch (e) {
      setError(typeof e === "string" ? e : "Could not add contact");
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <div className="modal-backdrop" onClick={onClose} />
      <div className="modal add-contact-modal">
        <header className="modal-header">
          <div className="modal-title">Add contact</div>
          <button className="modal-close" onClick={onClose} aria-label="Close"><IconX /></button>
        </header>

        <div className="modal-body">
          <p className="add-contact-desc">Enter the connection code you received from someone to start an encrypted text conversation.</p>

          <input type="text" className="text-input mono add-contact-input" placeholder="axn1_..." value={code} onChange={e => { setCode(e.target.value); setError(""); }} autoFocus spellCheck={false} />

          {error && <div className="onboarding-error">{error}</div>}

          <div className="add-contact-actions">
            <button className="btn btn-primary" disabled={!code.trim() || busy} onClick={add}>{busy ? "Adding…" : "Add contact"}</button>
          </div>
        </div>
      </div>
    </>
  );
}
