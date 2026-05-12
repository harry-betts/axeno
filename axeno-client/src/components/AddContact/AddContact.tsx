import { useState } from "react";
import { mockMyIdentity } from "../../mockData";
import { IconX, IconCopy, IconQR, IconLink, IconCheck } from "../icons";
import "./AddContact.css";

interface Props {
  onClose: () => void;
}

type Tab = "share" | "add";

export default function AddContact({ onClose }: Props) {
  const [tab, setTab] = useState<Tab>("share");
  const [inviteLink, setInviteLink] = useState("");
  const [copied, setCopied] = useState(false);

  const myInviteLink = `axeno://contact/${mockMyIdentity.fingerprint.slice(0, 32)}`;

  const handleCopy = () => {
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

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

        <div className="add-contact-tabs">
          <button
            className={`add-contact-tab ${tab === "share" ? "active" : ""}`}
            onClick={() => setTab("share")}
          >
            Share your invite
          </button>
          <button
            className={`add-contact-tab ${tab === "add" ? "active" : ""}`}
            onClick={() => setTab("add")}
          >
            Add from invite
          </button>
        </div>

        <div className="modal-body">
          {tab === "share" ? (
            <>
              <p className="add-contact-desc">
                Share this invite link with someone you want to talk to. Send it over a channel you trust.
              </p>

              <div className="qr-placeholder">
                <IconQR />
                <span>QR code preview</span>
              </div>

              <div className="invite-link-wrap">
                <div className="invite-link">{myInviteLink}</div>
                <button className="btn btn-secondary" onClick={handleCopy}>
                  {copied ? <><IconCheck /> Copied</> : <><IconCopy /> Copy</>}
                </button>
              </div>
            </>
          ) : (
            <>
              <p className="add-contact-desc">
                Paste an invite link you received, or scan a QR code.
              </p>

              <div className="invite-input-wrap">
                <span className="invite-input-icon"><IconLink /></span>
                <input
                  type="text"
                  className="text-input mono invite-input"
                  placeholder="axeno://contact/..."
                  value={inviteLink}
                  onChange={(e) => setInviteLink(e.target.value)}
                />
              </div>

              <div className="add-contact-or">or</div>

              <button className="btn btn-secondary full">
                <IconQR /> Scan QR code
              </button>

              <div className="add-contact-actions">
                <button className="btn btn-primary" disabled={!inviteLink.trim()}>
                  Add contact
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </>
  );
}
