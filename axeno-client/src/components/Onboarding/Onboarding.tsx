import { useState } from "react";
import {
  IconCheck, IconKey, IconShield,
  IconLock, IconEye, IconEyeOff, IconSmartphone, IconUser,
} from "../icons";
import "./Onboarding.css";
import { invoke } from "@tauri-apps/api/core";

interface Props {
  onComplete: (displayName: string) => void;
}

type Step =
  | "welcome"
  | "choice"
  | "generating"
  | "set-password"
  | "set-profile"
  | "transfer-show"
  | "transfer-code"
  | "done";

type GeneratingFor = "new" | "transfer";

// Static QR Pattern for the "Transfer" placeholder
const QR_PATTERN = [
  [1,1,1,1,1,1,1,0,1,0,1,0,1,0,1,1,1,1,1,1,1],
  [1,0,0,0,0,0,1,0,1,1,0,1,0,0,1,0,0,0,0,0,1],
  [1,0,1,1,1,0,1,0,0,0,1,1,1,0,1,0,1,1,1,0,1],
  [1,0,1,1,1,0,1,0,1,0,0,1,0,0,1,0,1,1,1,0,1],
  [1,0,1,1,1,0,1,0,0,1,1,0,1,0,1,0,1,1,1,0,1],
  [1,0,0,0,0,0,1,0,1,0,1,1,0,0,1,0,0,0,0,0,1],
  [1,1,1,1,1,1,1,0,1,0,1,0,1,0,1,1,1,1,1,1,1],
  [0,0,0,0,0,0,0,0,0,1,0,1,0,0,0,0,0,0,0,0,0],
  [1,1,0,1,0,1,1,1,0,0,1,0,0,1,0,1,0,0,1,0,1],
  [0,1,0,0,1,0,0,1,1,0,0,1,0,1,0,0,1,0,0,1,0],
  [1,0,1,1,0,1,1,0,0,1,1,0,1,0,1,0,0,1,1,0,1],
  [0,1,0,1,1,0,0,1,1,0,0,1,0,1,0,1,0,0,1,0,0],
  [1,0,0,0,1,1,1,0,0,1,0,0,1,0,0,0,1,1,0,1,0],
  [0,0,0,0,0,0,0,0,1,0,1,1,0,1,1,0,0,1,0,0,1],
  [1,1,1,1,1,1,1,0,1,0,0,1,0,0,0,1,0,1,1,0,1],
  [1,0,0,0,0,0,1,0,0,1,1,0,1,0,1,0,1,0,0,1,0],
  [1,0,1,1,1,0,1,0,1,0,0,1,0,0,0,1,0,1,0,0,1],
  [1,0,1,1,1,0,1,0,0,1,1,0,1,0,1,0,0,0,1,1,0],
  [1,0,1,1,1,0,1,0,1,0,0,1,0,0,0,1,1,0,0,0,1],
  [1,0,0,0,0,0,1,0,0,1,0,0,1,0,1,0,0,1,0,1,0],
  [1,1,1,1,1,1,1,0,1,0,1,1,0,1,0,1,0,0,1,0,1],
];

function FakeQRCode() {
  const cell = 9;
  const size = 21 * cell;
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} style={{ display: "block" }}>
      {QR_PATTERN.map((row, r) =>
        row.map((on, c) =>
          on ? (
            <rect
              key={`${r}-${c}`}
              x={c * cell}
              y={r * cell}
              width={cell - 1}
              height={cell - 1}
              fill="var(--text-bright)"
              rx={0.5}
            />
          ) : null
        )
      )}
    </svg>
  );
}

export default function Onboarding({ onComplete }: Props) {
  const [step, setStep] = useState<Step>("welcome");
  const [generatingFor, setGeneratingFor] = useState<GeneratingFor>("new");
  const [transferKey, setTransferKey] = useState("");
  const [transferKeyError, setTransferKeyError] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [passwordError, setPasswordError] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [displayName, setDisplayName] = useState("");

  const startNewIdentity = () => {
    setGeneratingFor("new");
    setStep("set-password"); // Move to password first; keys need password to be encrypted
  };

  const submitTransferKey = () => {
    if (transferKey.trim().length < 10) {
      setTransferKeyError("Code too short. Make sure you copied the full transfer code.");
      return;
    }
    setTransferKeyError("");
    setGeneratingFor("transfer");
    setStep("set-password");
  };

  const submitPassword = async () => {
    // 1. Client-side validation
    if (password.length < 8) {
      setPasswordError("Password must be at least 8 characters.");
      return;
    }
    if (password !== confirmPassword) {
      setPasswordError("Passwords do not match.");
      return;
    }

    setPasswordError("");
    setStep("generating"); // Trigger the loading state

    try {
      // 2. Call the Rust Backend
      // This will take ~1-2 seconds because of Argon2id cost.
      // The CSS spinner will continue to animate because this is an async call.
      const fingerprint = await invoke<string>("create_identity", { 
        passphrase: password 
      });
      
      console.log("Successfully generated identity:", fingerprint);

      // 3. Proceed to final steps
      setStep(generatingFor === "new" ? "set-profile" : "done");
    } catch (err) {
      console.error("Failed to generate identity:", err);
      setPasswordError("Encryption failed. Please try a different password.");
      setStep("set-password");
    }
  };

  const loadingText =
    generatingFor === "new"
      ? { main: "Generating keys", sub: "This happens once and only on this device." }
      : { main: "Receiving identity", sub: "Decrypting and importing your keypair." };

  return (
    <div className="onboarding-root">
      <div className="onboarding-card">

        {/* ── Welcome ── */}
        {step === "welcome" && (
          <>
            <h1 className="onboarding-title">Private by design</h1>
            <p className="onboarding-text">
              Your identity lives only on your device. No accounts, no servers,
              no recovery codes held by anyone but you.
            </p>

            <div className="onboarding-points">
              <div className="onboarding-point">
                <span className="onboarding-point-icon"><IconKey /></span>
                <div>
                  <div className="onboarding-point-title">Cryptographic identity</div>
                  <div className="onboarding-point-desc">A keypair generated locally on your device.</div>
                </div>
              </div>
              <div className="onboarding-point">
                <span className="onboarding-point-icon"><IconShield /></span>
                <div>
                  <div className="onboarding-point-title">Tor by default</div>
                  <div className="onboarding-point-desc">All traffic routes through the Tor network.</div>
                </div>
              </div>
              <div className="onboarding-point">
                <span className="onboarding-point-icon"><IconLock /></span>
                <div>
                  <div className="onboarding-point-title">Password protected</div>
                  <div className="onboarding-point-desc">Your keys are encrypted with a password only you know.</div>
                </div>
              </div>
            </div>

            <button className="btn btn-primary onboarding-btn" onClick={() => setStep("choice")}>
              Get started
            </button>
          </>
        )}

        {/* ── Choice ── */}
        {step === "choice" && (
          <>
            <h1 className="onboarding-title">New or existing identity?</h1>
            <p className="onboarding-text">
              Create a fresh identity on this device, or bring one over from another device.
            </p>

            <div className="onboarding-choices">
              <button className="onboarding-choice" onClick={startNewIdentity}>
                <span className="onboarding-choice-icon"><IconKey /></span>
                <div className="onboarding-choice-body">
                  <div className="onboarding-choice-title">Create new identity</div>
                  <div className="onboarding-choice-desc">Generate a fresh keypair on your device.</div>
                </div>
                <span className="onboarding-choice-arrow">›</span>
              </button>

              <button className="onboarding-choice" onClick={() => setStep("transfer-show")}>
                <span className="onboarding-choice-icon"><IconSmartphone /></span>
                <div className="onboarding-choice-body">
                  <div className="onboarding-choice-title">Transfer from device</div>
                  <div className="onboarding-choice-desc">Bring your identity over from another device.</div>
                </div>
                <span className="onboarding-choice-arrow">›</span>
              </button>
            </div>
          </>
        )}

        {/* ── Transfer: show QR ── */}
        {step === "transfer-show" && (
          <>
            <button className="onboarding-back" onClick={() => setStep("choice")}>
              ← Back
            </button>
            <h1 className="onboarding-title">Scan this code</h1>
            <p className="onboarding-text">
              On your other device, scan the code to transfer your identity.
            </p>
            <div className="qr-code-container">
              <FakeQRCode />
            </div>
            <button className="btn btn-primary onboarding-btn" onClick={() => setStep("transfer-code")}>
              Enter a code instead
            </button>
          </>
        )}

        {/* ── Transfer: manual code ── */}
        {step === "transfer-code" && (
          <>
            <button className="onboarding-back" onClick={() => setStep("transfer-show")}>
              ← Back
            </button>
            <h1 className="onboarding-title">Enter transfer code</h1>
            <textarea
              className="onboarding-key-input"
              placeholder="Paste transfer code here…"
              value={transferKey}
              onChange={e => { setTransferKey(e.target.value); setTransferKeyError(""); }}
              rows={3}
            />
            {transferKeyError && <div className="onboarding-error">{transferKeyError}</div>}
            <button className="btn btn-primary onboarding-btn" onClick={submitTransferKey} disabled={!transferKey.trim()}>
              Import identity
            </button>
          </>
        )}

        {/* ── Generating / importing (Visible during invoke) ── */}
        {step === "generating" && (
          <div className="onboarding-loading">
            <div className="onboarding-spinner" />
            <div className="onboarding-loading-text">{loadingText.main}</div>
            <div className="onboarding-loading-sub">{loadingText.sub}</div>
          </div>
        )}

        {/* ── Set password ── */}
        {step === "set-password" && (
          <>
            <div className="onboarding-step-icon"><IconLock /></div>
            <h1 className="onboarding-title">Protect your keys</h1>
            <p className="onboarding-text">
              Set a password to encrypt your private keys.
            </p>

            <div className="onboarding-password-group">
              <input
                type={showPassword ? "text" : "password"}
                className="onboarding-key-input"
                placeholder="Password"
                value={password}
                onChange={e => { setPassword(e.target.value); setPasswordError(""); }}
                autoFocus
              />
              <button type="button" className="onboarding-eye-btn" onClick={() => setShowPassword(!showPassword)}>
                {showPassword ? <IconEyeOff /> : <IconEye />}
              </button>
            </div>

            <input
              type={showPassword ? "text" : "password"}
              className="onboarding-key-input"
              placeholder="Confirm password"
              value={confirmPassword}
              onChange={e => { setConfirmPassword(e.target.value); setPasswordError(""); }}
            />

            {passwordError && <div className="onboarding-error">{passwordError}</div>}

            <button className="btn btn-primary onboarding-btn" onClick={submitPassword} disabled={!password || !confirmPassword}>
              Set password
            </button>
          </>
        )}

        {/* ── Set profile ── */}
        {step === "set-profile" && (
          <>
            <div className="onboarding-step-icon"><IconUser /></div>
            <h1 className="onboarding-title">Your display name</h1>
            <input
              type="text"
              className="onboarding-name-input"
              placeholder="e.g. Alice"
              value={displayName}
              onChange={e => setDisplayName(e.target.value)}
              autoFocus
            />
            <button className="btn btn-primary onboarding-btn" onClick={() => setStep("done")} disabled={!displayName.trim()}>
              Continue
            </button>
          </>
        )}

        {/* ── Done ── */}
        {step === "done" && (
          <>
            <div className="onboarding-done-icon"><IconCheck /></div>
            <h1 className="onboarding-title">You're ready</h1>
            <button className="btn btn-primary onboarding-btn" onClick={() => onComplete(displayName)}>
              Open Axeno
            </button>
          </>
        )}

      </div>
    </div>
  );
}