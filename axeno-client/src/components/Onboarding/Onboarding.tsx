import { useRef, useState } from "react";
import {
  IconCheck, IconKey, IconShield,
  IconLock, IconEye, IconEyeOff, IconUser,
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
  | "done";

export default function Onboarding({ onComplete }: Props) {
  const [step, setStep] = useState<Step>("welcome");
  const passwordRef = useRef<HTMLInputElement>(null);
  const confirmPasswordRef = useRef<HTMLInputElement>(null);
  const [passwordReady, setPasswordReady] = useState(false);
  const [passwordError, setPasswordError] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [displayName, setDisplayName] = useState("");

  const startNewIdentity = () => {
    setStep("set-profile");
  };

  const submitPassword = async () => {
    const password = passwordRef.current?.value ?? "";
    const confirmPassword = confirmPasswordRef.current?.value ?? "";
    if (password.length < 12) {
      setPasswordError("Password must be at least 12 characters. A 4-5 word passphrase is better.");
      return;
    }
    if (password !== confirmPassword) {
      setPasswordError("Passwords do not match.");
      return;
    }
    setPasswordError("");
    setStep("generating");

    try {
      await invoke<string>("create_identity", {
        passphrase: password,
        displayName,
      });
      // The backend now holds the unlocked session in Rust memory.
      // Wipe DOM copies of the password immediately after IPC returns.
      if (passwordRef.current) passwordRef.current.value = "";
      if (confirmPasswordRef.current) confirmPasswordRef.current.value = "";
      setPasswordReady(false);
      setStep("done");
    } catch (err) {
      if (passwordRef.current) passwordRef.current.value = "";
      if (confirmPasswordRef.current) confirmPasswordRef.current.value = "";
      setPasswordReady(false);
      console.error("Failed to generate identity:", err);
      setPasswordError(
        typeof err === "string" ? err : "Encryption failed. Please try a different password."
      );
      setStep("set-password");
    }
  };

  const loadingText = { main: "Generating keys", sub: "This happens once and only on this device." };

  return (
    <div className="onboarding-root">
      <div className="onboarding-card">

        {step === "welcome" && (
          <>
            <h1 className="onboarding-title">Private by design</h1>
            <p className="onboarding-text">
              Your identity keys live only on your device. Relays can move encrypted messages,
              but they should never receive your private keys, passphrase, contacts, or plaintext.
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
                  <div className="onboarding-point-title">Tor/onion relay support</div>
                  <div className="onboarding-point-desc">Localhost is for development; .onion relays are routed through Tor.</div>
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

        {step === "choice" && (
          <>
            <h1 className="onboarding-title">Create your identity</h1>
            <p className="onboarding-text">
              This build supports fresh local identities only. Device transfer is hidden until the protocol is genuinely implemented.
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
            </div>
          </>
        )}

        {step === "set-profile" && (
          <>
            <div className="onboarding-step-icon"><IconUser /></div>
            <h1 className="onboarding-title">Your display name</h1>
            <p className="onboarding-text">
              This is the name other people will see when you contact them.
            </p>
            <input
              type="text"
              className="onboarding-name-input"
              placeholder="e.g. Alice"
              value={displayName}
              onChange={e => setDisplayName(e.target.value)}
              autoFocus
            />
            <button className="btn btn-primary onboarding-btn" onClick={() => setStep("set-password")} disabled={!displayName.trim()}>
              Continue
            </button>
          </>
        )}

        {step === "set-password" && (
          <>
            <div className="onboarding-step-icon"><IconLock /></div>
            <h1 className="onboarding-title">Protect your keys</h1>
            <p className="onboarding-text">
              Set a password to encrypt your private keys and profile.
            </p>

            <div className="onboarding-password-group">
              <input
                type={showPassword ? "text" : "password"}
                className="onboarding-key-input"
                placeholder="Password"
                ref={passwordRef}
                onChange={e => { setPasswordReady(e.currentTarget.value.length > 0 && (confirmPasswordRef.current?.value.length ?? 0) > 0); setPasswordError(""); }}
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
              ref={confirmPasswordRef}
              onChange={e => { setPasswordReady(e.currentTarget.value.length > 0 && (passwordRef.current?.value.length ?? 0) > 0); setPasswordError(""); }}
            />

            {passwordError && <div className="onboarding-error">{passwordError}</div>}

            <button className="btn btn-primary onboarding-btn" onClick={submitPassword} disabled={!passwordReady}>
              Set password
            </button>
          </>
        )}

        {step === "generating" && (
          <div className="onboarding-loading">
            <div className="onboarding-spinner" />
            <div className="onboarding-loading-text">{loadingText.main}</div>
            <div className="onboarding-loading-sub">{loadingText.sub}</div>
          </div>
        )}

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
