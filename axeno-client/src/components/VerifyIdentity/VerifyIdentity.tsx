import { useState } from "react";
import { Contact } from "../../types";
import { IconArrowLeft, IconQR, IconCheck } from "../icons";
import "./VerifyIdentity.css";

interface Props {
  contact: Contact;
  onClose: () => void;
}

// 60 digits in 12 groups of 5
const mockSafetyNumber = [
  "39472", "10384", "82910", "47291",
  "63782", "29047", "10583", "73920",
  "48291", "10472", "92831", "47102",
];

export default function VerifyIdentity({ contact, onClose }: Props) {
  const [verified, setVerified] = useState(false);

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
          <h1 className="verify-title">Verify {contact.id}</h1>
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
              {mockSafetyNumber.slice(rowIdx * 3, rowIdx * 3 + 3).map((g, i) => (
                <span key={i} className="verify-safety-group">{g}</span>
              ))}
            </div>
          ))}
        </div>

        <div className="verify-actions">
          <button
            className={`btn ${verified ? "btn-success" : "btn-primary"}`}
            onClick={() => setVerified(!verified)}
          >
            {verified ? <><IconCheck /> Marked as verified</> : "Mark as verified"}
          </button>
          <p className="verify-fineprint">
            If their key changes in the future, you will be prompted to verify again.
          </p>
        </div>
      </div>
    </div>
  );
}
