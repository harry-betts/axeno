import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Contact } from "../../types";
import { IconArrowLeft, IconQR, IconCheck } from "../icons";
import { contactDisplayName } from "../../utils";
import "./VerifyIdentity.css";

interface Props {
  contact: Contact;
  onClose: () => void;
}

function safetyGroups(value?: string): string[] {
  const raw = (value || "pending-first-contact").replace(/[^a-fA-F0-9]/g, "").toUpperCase();
  const groups = raw.match(/.{1,4}/g) || ["PENDING"];
  return groups.slice(0, 12);
}

export default function VerifyIdentity({ contact, onClose }: Props) {
  const [verified, setVerified] = useState(contact.trustState === "verified");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const toggleVerified = async () => {
    if (busy) return;
    const next = !verified;
    setBusy(true);
    setError("");
    try {
      await invoke("messaging_mark_contact_verified", { contactId: contact.id, verified: next });
      setVerified(next);
    } catch (e) {
      setError(typeof e === "string" ? e : "Could not update verification state");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="verify-root">
      <header className="verify-topbar">
        <button className="verify-back" onClick={onClose} aria-label="Back">
          <IconArrowLeft />
        </button>
        <div className="verify-topbar-title">Verify identity</div>
      </header>

      <div className="verify-content">
        <div className="verify-header">
          <h1 className="verify-title">Verify {contactDisplayName(contact)}</h1>
          <p className="verify-desc">
            Compare these numbers with your contact in person, over a video call, or any
            other channel you trust. If they match on both sides, your conversation is
            confirmed end-to-end with the right person.
          </p>
        </div>

        <div className="verify-qr-panel">
          <div className="verify-qr-placeholder">
            <IconQR />
          </div>
          <div className="verify-qr-caption">
            They can scan this code with their Axeno app to verify automatically.
          </div>
        </div>

        <div className="verify-divider">
          <span>or compare numbers manually</span>
        </div>

        <div className="verify-safety-number">
          {Array.from({ length: 4 }).map((_, rowIdx) => (
            <div key={rowIdx} className="verify-safety-row">
              {safetyGroups(contact.safetyNumber).slice(rowIdx * 3, rowIdx * 3 + 3).map((g, i) => (
                <span key={i} className="verify-safety-group">{g}</span>
              ))}
            </div>
          ))}
        </div>

        <div className="verify-actions">
          <button
            className={`btn ${verified ? "btn-success" : "btn-primary"}`}
            onClick={toggleVerified}
            disabled={busy}
          >
            {verified ? <><IconCheck /> Marked as verified</> : "Mark as verified"}
          </button>
          {error && <div className="onboarding-error">{error}</div>}
          <p className="verify-fineprint">
            If their key changes in the future, this verified state is cleared and sending is blocked until you re-check it.
          </p>
        </div>
      </div>
    </div>
  );
}
