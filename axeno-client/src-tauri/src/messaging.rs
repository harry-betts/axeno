//! Axeno messaging layer.
//!
//! This file is deliberately Signal-first. The previous development-only pairing-secret
//! encryption path has been removed from normal messaging because it was not Signal Protocol.
//! The implemented pieces are:
//! - real backend-owned contact/message store, encrypted at rest with the unlocked vault key;
//! - connection codes carrying Signal public identity + signed-prekey + one-time-prekey material;
//! - WebSocket relay integration using opaque `axeno_signal_v1` envelopes;
//! - safe failure instead of falling back to non-Signal encryption when the Signal session engine
//!   cannot be compiled/linked in the local environment.
//!
//! The actual Signal send/decrypt calls are isolated behind `signal_protocol_engine`. This keeps
//! the app from accidentally shipping fake security while still lining up the exact flow the app
//! needs: PreKeyBundle -> Session -> CiphertextMessage -> relay -> PreKeySignalMessage/SignalMessage
//! decrypt -> persisted plaintext.

use std::{collections::{HashMap, HashSet}, fs, io::Write, path::PathBuf, sync::Arc, time::{SystemTime, UNIX_EPOCH}};

use base64::{engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD}, Engine as _};
use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use libsignal_protocol::{KeyPair, PrivateKey, PublicKey};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use tauri::{AppHandle, Emitter, Manager};
use tokio::sync::Mutex;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::{identity::{fingerprint, remove_consumed_opks_and_replenish, reseal_vault, rotate_signed_prekey_if_due, EncryptedIdentity, OpkSecret, SignedPreKeySecret}, load_vault, read_unified_message_store, save_vault, transport, update_unified_message_store, AppSessionState};

const INVITE_PREFIX: &str = "axn1_";
const STORE_FILE: &str = "messages.store";
const DEFAULT_DEV_SERVER: &str = "ws://127.0.0.1:8787/ws";
const PROTOCOL_SIGNAL: &str = "axeno_signal_v1";
const ENVELOPE_TYPE_SIGNAL: &str = "axeno_signal_v1";
const ENVELOPE_TYPE_SEALED_SIGNAL: &str = "axeno_sealed_signal_v1";
const DEVICE_ID: u32 = 1;
const CONNECTION_CODE_TTL_MS: u64 = 24 * 60 * 60 * 1000;
const VERIFY_PREFIX: &str = "axv1_";
const VERIFY_CODE_TTL_MS: u64 = 10 * 60 * 1000;
const SIGNED_PREKEY_ROTATION_MS: u64 = 7 * 24 * 60 * 60 * 1000;
const KYBER_PREKEY_ROTATION_MS: u64 = 30 * 24 * 60 * 60 * 1000;
const MAX_FAILED_ENVELOPES: usize = 4096;
const FAILED_ENVELOPE_TTL_MS: u64 = 60 * 60 * 1000;
/// Maximum messages retained per contact. Oldest messages are pruned when this
/// limit is exceeded. Keeping a finite window limits the blast radius of device
/// compromise and prevents the encrypted store from growing without bound.
const MAX_MESSAGES_PER_CONTACT: usize = 10_000;

#[derive(Clone, Default)]
pub struct MessagingRuntimeState {
    seen_envelopes: Arc<Mutex<HashMap<String, u64>>>,
    failed_envelopes: Arc<Mutex<HashMap<String, FailedEnvelopeEntry>>>,
}

#[derive(Debug, Clone, Copy)]
struct FailedEnvelopeEntry { count: u32, last_seen_ms: u64 }

impl MessagingRuntimeState { pub fn new() -> Self { Self::default() } }

const SEEN_ENVELOPE_TTL_MS: u64 = 24 * 60 * 60 * 1000;
const MAX_SEEN_ENVELOPES: usize = 4096;
const MAX_FAILED_DECRYPTS_PER_ENVELOPE: u32 = 5;
const DELIVERY_TOKEN_FALLBACK_TTL_MS: u64 = 7 * 24 * 60 * 60 * 1000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredContact {
    pub id: String,
    /// Human display name learned from connection code or encrypted profile payload.
    pub display_name: Option<String>,
    /// Server-side mailbox/routing token. This is random and must never be shown as a user identity.
    pub recipient_id: String,
    pub server_url: String,
    pub server_id: String,
    pub identity_public_b64: String,
    pub registration_id: u32,
    pub device_id: u32,
    pub signed_prekey_id: u32,
    pub signed_prekey_public_b64: String,
    pub signed_prekey_signature_b64: String,
    pub opk_id: Option<u32>,
    pub opk_public_b64: Option<String>,
    #[serde(default)]
    pub kyber_prekey_id: Option<u32>,
    #[serde(default)]
    pub kyber_prekey_public_b64: Option<String>,
    #[serde(default)]
    pub kyber_prekey_signature_b64: Option<String>,
    #[serde(default)]
    pub delivery_token: String,
    #[serde(default = "default_token_epoch")]
    pub delivery_token_epoch: u64,
    pub safety_number: String,
    #[serde(default = "default_trust_state")]
    pub trust_state: String,
    #[serde(default)]
    pub verified_at_ms: Option<u64>,
    #[serde(default)]
    pub local_route_id: Option<String>,
    #[serde(default)]
    pub peer_sender_mailbox_id: Option<String>,
    pub created_at_ms: u64,
    pub last_read_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredMessage {
    pub id: String,
    pub contact_id: String,
    pub mine: bool,
    pub text: String,
    pub timestamp: u64,
    #[serde(default)]
    pub received_at_ms: Option<u64>,
    pub status: String,
}

fn default_store_version() -> u16 { 1 }

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MessagingStore {
    #[serde(default = "default_store_version")] pub version: u16,
    #[serde(default)] pub contacts: Vec<StoredContact>,
    #[serde(default)] pub messages: Vec<StoredMessage>,
    #[serde(default)] pub pending_invites: Vec<PendingInvite>,
    #[serde(default)] pub signal_sessions: HashMap<String, SignalSessionBlob>,
    #[serde(default)] pub local_kyber_prekey: Option<KyberPreKeyBlob>,
    #[serde(default)] pub previous_kyber_prekeys: Vec<KyberPreKeyBlob>,
    #[serde(default)] pub local_profile: Option<LocalProfile>,
    #[serde(default)] pub local_routes: Vec<LocalRoute>,
    #[serde(default)] pub pending_relay_retires: Vec<LocalRoute>,
    #[serde(default)] pub used_opk_ids: Vec<u32>,
    #[serde(default)] pub server_trust_roots: HashMap<String, String>,
    #[serde(default)] pub private_servers: Vec<PrivateServerSetting>,
    #[serde(default)] pub default_server_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateServerSetting {
    pub id: String,
    pub name: String,
    pub onion: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PrivateServerSettings {
    #[serde(default)] pub private_servers: Vec<PrivateServerSetting>,
    #[serde(default)] pub default_server_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalProfile {
    pub mailbox_id: String,
    pub receive_auth_token: String,
    #[serde(default)]
    pub delivery_token: String,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetiredDeliveryToken {
    pub token: String,
    pub epoch: u64,
    pub retire_after_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalRoute {
    pub id: String,
    pub mailbox_id: String,
    pub receive_auth_token: String,
    pub delivery_token: String,
    #[serde(default = "default_token_epoch")]
    pub delivery_token_epoch: u64,
    #[serde(default)]
    pub retired_delivery_tokens: Vec<String>,
    #[serde(default)]
    pub pending_token_retirements: Vec<RetiredDeliveryToken>,
    pub server_url: String,
    pub server_id: String,
    /// Per-route libsignal SenderCertificate public key. This is intentionally
    /// NOT the long-term Signal identity key; the relay may see this key when
    /// issuing a sealed-sender certificate, so it must be route-scoped and
    /// unlinkable across contacts.
    #[serde(default)]
    pub sealed_sender_cert_public_b64: String,
    /// Private half of the per-route sealed-sender certificate keypair. Stored
    /// only in the encrypted local message store and used only for the outer
    /// sealed-sender envelope. It must never be sent to the relay.
    #[serde(default)]
    pub sealed_sender_cert_private_b64: String,
    pub scope: String,
    #[serde(default)]
    pub replacement_route_id: Option<String>,
    #[serde(default = "default_true")]
    pub active: bool,
    pub created_at_ms: u64,
    #[serde(default)]
    pub expires_at_ms: Option<u64>,
}

fn default_true() -> bool { true }
fn default_token_epoch() -> u64 { 1 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalSessionBlob {
    /// Serialized libsignal SessionRecord data for this recipient/device.
    /// Kept in the encrypted local message store, not on the relay.
    pub address_name: String,
    pub device_id: u32,
    pub session_b64: String,
    pub remote_identity_b64: String,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KyberPreKeyBlob {
    pub id: u32,
    pub public_b64: String,
    pub signature_b64: String,
    pub record_b64: String,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedVerificationPayload {
    payload: VerificationPayload,
    signature_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedStoreFile { #[serde(default = "default_store_version")] version: u16, nonce: [u8; 12], ciphertext: Vec<u8> }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingInvite {
    pub id: String,
    pub code: String,
    pub mailbox_id: String,
    pub server_url: String,
    #[serde(default)]
    pub server_name: Option<String>,
    pub route_id: Option<String>,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    #[serde(default)]
    pub reusable: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnectionCodeResponse {
    pub id: String,
    pub code: String,
    pub created_at: u64,
    pub server_url: String,
    pub server_name: String,
    pub reusable: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerificationCodeResponse { pub code: String, pub safety_number: String, pub created_at: u64 }

#[derive(Debug, Clone, Serialize)]
pub struct MessagingSnapshot {
    pub my_recipient_id: String,
    pub my_recipient_ids: Vec<String>,
    pub contacts: Vec<StoredContact>,
    pub messages: HashMap<String, Vec<StoredMessage>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SendMessageResponse { pub message: StoredMessage }

#[derive(Debug, Clone, Serialize)]
pub struct IncomingMessageEvent { pub contact_id: String, pub message: StoredMessage }

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InvitePayload {
    v: u16,
    protocol: String,
    display_name: String,
    mailbox_id: String,
    delivery_token: String,
    server_url: String,
    device_id: u32,
    identity_public_b64: String,
    registration_id: u32,
    signed_prekey_id: u32,
    signed_prekey_public_b64: String,
    signed_prekey_signature_b64: String,
    opk_id: Option<u32>,
    opk_public_b64: Option<String>,
    kyber_prekey_id: Option<u32>,
    kyber_prekey_public_b64: Option<String>,
    kyber_prekey_signature_b64: Option<String>,
    created_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HostedInviteCode {
    v: u16,
    kind: String,
    server_url: String,
    bundle_id: String,
    bundle_key_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HostedInviteBundle {
    v: u16,
    payload: InvitePayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HostedInviteCiphertext {
    v: u16,
    nonce_b64: String,
    ciphertext_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VerificationPayload {
    v: u16,
    kind: String,
    local_identity_public_b64: String,
    remote_identity_public_b64: String,
    safety_number: String,
    created_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SealedSignalWireMessage {
    /// Official libsignal sealed-sender message bytes. The relay sees this opaque
    /// blob only; sender certificate, sender identity, inner Signal message type,
    /// and message ciphertext are inside the libsignal sealed envelope.
    v: u16,
    sealed_sender_b64: String,
}

/// Pad raw ciphertext to fixed bucket sizes so the relay cannot infer message
/// length from the wire size. Buckets: 512, 1024, 2048, 4096, 8192, 16384, 32768.
/// Padding bytes are random noise appended after a 4-byte big-endian length prefix.
fn pad_ciphertext(raw: &[u8]) -> Result<Vec<u8>, String> {
    const BUCKETS: &[usize] = &[512, 1024, 2048, 4096, 8192, 16384, 32768, 65536];
    let total_needed = 4 + raw.len(); // 4-byte length prefix + payload
    let bucket = BUCKETS.iter().copied().find(|&b| b >= total_needed).unwrap_or(total_needed);
    let mut out = Vec::with_capacity(bucket);
    out.extend_from_slice(&(raw.len() as u32).to_be_bytes());
    out.extend_from_slice(raw);
    let padding_len = bucket - out.len();
    if padding_len > 0 {
        let mut pad = vec![0u8; padding_len];
        fill_random(&mut pad)?;
        out.extend_from_slice(&pad);
    }
    Ok(out)
}

/// Remove padding added by pad_ciphertext, returning the original ciphertext.
fn unpad_ciphertext(padded: &[u8]) -> Result<Vec<u8>, String> {
    if padded.len() < 4 {
        return Err("padded ciphertext too short".into());
    }
    let len = u32::from_be_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;
    if 4 + len > padded.len() {
        return Err("padded ciphertext length prefix exceeds data".into());
    }
    Ok(padded[4..4 + len].to_vec())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AxenoSignalPlaintext {
    v: u16,
    kind: String,
    message_id: String,
    sent_at_ms: u64,
    body: String,
    #[serde(default)]
    sender_display_name: Option<String>,
    #[serde(default)]
    sender_mailbox_id: Option<String>,
    #[serde(default)]
    sender_delivery_token: Option<String>,
    #[serde(default)]
    sender_delivery_token_epoch: Option<u64>,
    #[serde(default)]
    return_mailbox_id: Option<String>,
    #[serde(default)]
    return_delivery_token: Option<String>,
    #[serde(default)]
    return_delivery_token_epoch: Option<u64>,
    #[serde(default)]
    return_server_url: Option<String>,
    #[serde(default)]
    acked_peer_delivery_token_epoch: Option<u64>,
    #[serde(default)]
    acked_peer_sender_mailbox_id: Option<String>,
    #[serde(default)]
    sender_server_url: Option<String>,
    #[serde(default)]
    sender_device_id: Option<u32>,
    #[serde(default)]
    sender_identity_public_b64: Option<String>,
    #[serde(default)]
    sender_registration_id: Option<u32>,
    #[serde(default)]
    sender_signed_prekey_id: Option<u32>,
    #[serde(default)]
    sender_signed_prekey_public_b64: Option<String>,
    #[serde(default)]
    sender_signed_prekey_signature_b64: Option<String>,
    #[serde(default)]
    sender_kyber_prekey_id: Option<u32>,
    #[serde(default)]
    sender_kyber_prekey_public_b64: Option<String>,
    #[serde(default)]
    sender_kyber_prekey_signature_b64: Option<String>,
}

#[derive(Debug, Clone)]
struct DecryptedSignalText {
    kind: String,
    message_id: String,
    sent_at_ms: u64,
    body: String,
    sender_display_name: Option<String>,
    sender_mailbox_id: Option<String>,
    sender_delivery_token: Option<String>,
    sender_delivery_token_epoch: Option<u64>,
    return_mailbox_id: Option<String>,
    return_delivery_token: Option<String>,
    return_delivery_token_epoch: Option<u64>,
    return_server_url: Option<String>,
    acked_peer_delivery_token_epoch: Option<u64>,
    acked_peer_sender_mailbox_id: Option<String>,
    sender_server_url: Option<String>,
    sender_device_id: Option<u32>,
    sender_identity_public_b64: Option<String>,
    sender_registration_id: Option<u32>,
    sender_signed_prekey_id: Option<u32>,
    sender_signed_prekey_public_b64: Option<String>,
    sender_signed_prekey_signature_b64: Option<String>,
    sender_kyber_prekey_id: Option<u32>,
    sender_kyber_prekey_public_b64: Option<String>,
    sender_kyber_prekey_signature_b64: Option<String>,
}

fn encode_signal_plaintext(
    kind: &str,
    body: &str,
    sender_display_name: &str,
    message_id: &str,
    sent_at_ms: u64,
    sender_route: &LocalRoute,
    return_route: &LocalRoute,
    local_identity_public_b64: &str,
    local_registration_id: u32,
    local_signed_prekey_id: u32,
    local_signed_prekey_public_b64: String,
    local_signed_prekey_signature_b64: String,
    local_kyber_prekey_id: u32,
    local_kyber_prekey_public_b64: String,
    local_kyber_prekey_signature_b64: String,
    acked_peer_delivery_token_epoch: u64,
    acked_peer_sender_mailbox_id: Option<String>,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&AxenoSignalPlaintext {
        v: 1,
        kind: kind.to_string(),
        message_id: message_id.to_string(),
        sent_at_ms,
        body: body.to_string(),
        sender_display_name: Some(sender_display_name.trim().to_string()).filter(|s| !s.is_empty()),
        sender_mailbox_id: Some(sender_route.mailbox_id.clone()),
        sender_delivery_token: Some(sender_route.delivery_token.clone()),
        sender_delivery_token_epoch: Some(sender_route.delivery_token_epoch),
        return_mailbox_id: Some(return_route.mailbox_id.clone()),
        return_delivery_token: Some(return_route.delivery_token.clone()),
        return_delivery_token_epoch: Some(return_route.delivery_token_epoch),
        acked_peer_delivery_token_epoch: Some(acked_peer_delivery_token_epoch),
        acked_peer_sender_mailbox_id,
        sender_server_url: Some(sender_route.server_url.clone()),
        return_server_url: Some(return_route.server_url.clone()),
        sender_device_id: Some(DEVICE_ID),
        sender_identity_public_b64: Some(local_identity_public_b64.to_string()),
        sender_registration_id: Some(local_registration_id),
        sender_signed_prekey_id: Some(local_signed_prekey_id),
        sender_signed_prekey_public_b64: Some(local_signed_prekey_public_b64),
        sender_signed_prekey_signature_b64: Some(local_signed_prekey_signature_b64),
        sender_kyber_prekey_id: Some(local_kyber_prekey_id),
        sender_kyber_prekey_public_b64: Some(local_kyber_prekey_public_b64),
        sender_kyber_prekey_signature_b64: Some(local_kyber_prekey_signature_b64),
    }).map_err(|e| format!("could not serialize encrypted message payload: {e}"))
}

fn decode_signal_plaintext(raw: Vec<u8>) -> Result<DecryptedSignalText, String> {
    if let Ok(payload) = serde_json::from_slice::<AxenoSignalPlaintext>(&raw) {
        if payload.v != 1 || !matches!(payload.kind.as_str(), "text" | "route_sync" | "route_sync_ack") {
            return Err("unsupported encrypted Axeno message payload".into());
        }
        return Ok(DecryptedSignalText {
            kind: payload.kind,
            message_id: payload.message_id,
            sent_at_ms: payload.sent_at_ms,
            body: payload.body,
            sender_display_name: payload.sender_display_name.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
            sender_mailbox_id: payload.sender_mailbox_id.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
            sender_delivery_token: payload.sender_delivery_token.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
            sender_delivery_token_epoch: payload.sender_delivery_token_epoch.filter(|epoch| *epoch > 0),
            return_mailbox_id: payload.return_mailbox_id.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
            return_delivery_token: payload.return_delivery_token.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
            return_delivery_token_epoch: payload.return_delivery_token_epoch.filter(|epoch| *epoch > 0),
            return_server_url: payload.return_server_url.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
            acked_peer_delivery_token_epoch: payload.acked_peer_delivery_token_epoch.filter(|epoch| *epoch > 0),
            acked_peer_sender_mailbox_id: payload.acked_peer_sender_mailbox_id.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
            sender_server_url: payload.sender_server_url.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
            sender_device_id: payload.sender_device_id,
            sender_identity_public_b64: payload.sender_identity_public_b64.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
            sender_registration_id: payload.sender_registration_id.filter(|id| *id > 0),
            sender_signed_prekey_id: payload.sender_signed_prekey_id.filter(|id| *id > 0),
            sender_signed_prekey_public_b64: payload.sender_signed_prekey_public_b64.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
            sender_signed_prekey_signature_b64: payload.sender_signed_prekey_signature_b64.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
            sender_kyber_prekey_id: payload.sender_kyber_prekey_id.filter(|id| *id > 0),
            sender_kyber_prekey_public_b64: payload.sender_kyber_prekey_public_b64.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
            sender_kyber_prekey_signature_b64: payload.sender_kyber_prekey_signature_b64.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
        });
    }

    // Backward-compatible fallback for any already-created dev messages before the
    // encrypted plaintext envelope existed.
    let body = String::from_utf8(raw).map_err(|_| "decrypted Signal plaintext was not valid UTF-8".to_string())?;
    Ok(DecryptedSignalText {
        kind: "text".to_string(),
        message_id: Uuid::new_v4().to_string(),
        sent_at_ms: now_ms(),
        body,
        sender_display_name: None,
        sender_mailbox_id: None,
        sender_delivery_token: None,
        sender_delivery_token_epoch: None,
        return_mailbox_id: None,
        return_delivery_token: None,
        return_delivery_token_epoch: None,
        return_server_url: None,
        acked_peer_delivery_token_epoch: None,
        acked_peer_sender_mailbox_id: None,
        sender_server_url: None,
        sender_device_id: None,
        sender_identity_public_b64: None,
        sender_registration_id: None,
        sender_signed_prekey_id: None,
        sender_signed_prekey_public_b64: None,
        sender_signed_prekey_signature_b64: None,
        sender_kyber_prekey_id: None,
        sender_kyber_prekey_public_b64: None,
        sender_kyber_prekey_signature_b64: None,
    })
}

fn store_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_data_dir().map_err(|_| "could not resolve app data dir".to_string())?;
    fs::create_dir_all(&dir).map_err(|e| format!("could not create app data dir: {e}"))?;
    Ok(dir.join(STORE_FILE))
}

async fn store_keys(session: &AppSessionState) -> Result<([u8; 32], [u8; 32]), String> {
    let guard = session.session.lock().await;
    let Some(unlocked) = guard.as_ref() else { return Err("identity is locked".into()); };
    let legacy = unlocked.key.expose_for_rekey();
    let current = derive_domain_key(&legacy, b"message-store");
    Ok((current, legacy))
}

#[derive(Debug, Clone)]
struct PrivateSignalMaterial {
    identity_priv: Vec<u8>,
    spk_priv: Vec<u8>,
    previous_spks_secret: Vec<SignedPreKeySecret>,
    opks_secret: Vec<OpkSecret>,
    display_name: String,
}

impl Drop for PrivateSignalMaterial {
    fn drop(&mut self) {
        self.identity_priv.zeroize();
        self.spk_priv.zeroize();
        for previous in self.previous_spks_secret.iter_mut() {
            previous.private_key.zeroize();
        }
        for opk in self.opks_secret.iter_mut() {
            opk.private_key.zeroize();
        }
    }
}

async fn signal_material(session: &AppSessionState) -> Result<PrivateSignalMaterial, String> {
    let guard = session.session.lock().await;
    let Some(unlocked) = guard.as_ref() else { return Err("identity is locked".into()); };
    Ok(PrivateSignalMaterial {
        identity_priv: unlocked.secrets.identity_priv.clone(),
        spk_priv: unlocked.secrets.spk_priv.clone(),
        previous_spks_secret: unlocked.secrets.previous_spks_secret.clone(),
        opks_secret: unlocked.secrets.opks_secret.clone(),
        display_name: unlocked.secrets.display_name.clone(),
    })
}

fn decode_store_file(path: &PathBuf, data: &[u8]) -> Result<EncryptedStoreFile, String> {
    match serde_json::from_slice::<EncryptedStoreFile>(data) {
        Ok(file) => return Ok(file),
        Err(first_err) => {
            // Recovery path for stores created during early dev builds or concurrent test runs.
            // serde_json::from_slice rejects valid JSON followed by trailing bytes/another JSON value
            // with "trailing characters". Parse the first complete value so the next successful
            // save can rewrite the file cleanly instead of bricking the profile.
            let mut stream = serde_json::Deserializer::from_slice(data).into_iter::<EncryptedStoreFile>();
            if let Some(Ok(file)) = stream.next() {
                let backup_name = format!(
                    "{}.corrupted.{}.bak",
                    path.file_name().and_then(|n| n.to_str()).unwrap_or(STORE_FILE),
                    now_ms()
                );
                let backup = path.with_file_name(backup_name);
                let _ = fs::write(&backup, data);
                eprintln!("warning: recovered message store with trailing garbage; backed up original to {}", backup.display());
                return Ok(file);
            }
            Err(format!("message store header is corrupted: {first_err}"))
        }
    }
}

fn try_load_store_with_key(app: &AppHandle, key_bytes: &[u8; 32]) -> Result<MessagingStore, String> {
    let path = store_path(app)?;
    let data = if path.exists() {
        fs::read(&path).map_err(|e| format!("read encrypted message store failed: {e}"))?
    } else if let Some(raw) = read_unified_message_store(app)? {
        raw
    } else {
        return Ok(MessagingStore::default());
    };
    let file = decode_store_file(&path, &data)?;
    if file.version > 1 { return Err("message store was written by a newer Axeno client".to_string()); }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key_bytes));
    let mut plaintext = cipher.decrypt(Nonce::from_slice(&file.nonce), file.ciphertext.as_ref())
        .map_err(|_| "message store could not be decrypted with this key".to_string())?;
    let parsed = serde_json::from_slice(&plaintext).map_err(|e| format!("message store plaintext is corrupted: {e}"));
    plaintext.zeroize();
    parsed
}

fn load_store_with_keys(app: &AppHandle, current_key: &[u8; 32], legacy_key: &[u8; 32]) -> Result<MessagingStore, String> {
    match try_load_store_with_key(app, current_key) {
        Ok(store) => Ok(store),
        Err(current_err) => {
            if current_key == legacy_key {
                return Err(format!("message store could not be decrypted; identity/password mismatch or corrupted store: {current_err}"));
            }
            match try_load_store_with_key(app, legacy_key) {
                Ok(store) => {
                    // One-time legacy migration: if an old raw-KEK store is readable,
                    // immediately rewrite it under the domain-separated store key so the
                    // legacy decrypt path is not exercised forever.
                    save_store_with_key(app, &store, current_key)?;
                    Ok(store)
                }
                Err(_) => Err("message store could not be decrypted; identity/password mismatch or corrupted store".to_string()),
            }
        }
    }
}

fn save_store_with_key(app: &AppHandle, store: &MessagingStore, key_bytes: &[u8; 32]) -> Result<(), String> {
    let path = store_path(app)?;
    // Never reuse one fixed tmp path. During local two-instance testing, overlapping writes to the
    // same messages.store.tmp can leave concatenated/trailing JSON and trigger Serde's
    // "trailing characters" error. A unique tmp file plus atomic rename avoids that class of bug.
    let tmp = path.with_file_name(format!(
        "{}.{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or(STORE_FILE),
        Uuid::new_v4()
    ));
    let mut json = serde_json::to_vec(store).map_err(|e| format!("serialize message store failed: {e}"))?;
    let mut nonce = [0u8; 12]; fill_random(&mut nonce)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key_bytes));
    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), json.as_ref()).map_err(|_| "message store encryption failed".to_string())?;
    json.zeroize();
    let encoded = serde_json::to_vec(&EncryptedStoreFile { version: 1, nonce, ciphertext }).map_err(|e| format!("serialize encrypted message store failed: {e}"))?;
    #[cfg(unix)] {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)
            .map_err(|e| format!("open message store tmp failed: {e}"))?;
        f.write_all(&encoded).map_err(|e| format!("write message store failed: {e}"))?;
        f.sync_all().map_err(|e| format!("fsync message store failed: {e}"))?;
    }
    #[cfg(not(unix))] {
        let mut f = fs::OpenOptions::new().write(true).create_new(true).open(&tmp)
            .map_err(|e| format!("open message store tmp failed: {e}"))?;
        f.write_all(&encoded).map_err(|e| format!("write message store failed: {e}"))?;
        f.sync_all().map_err(|e| format!("fsync message store failed: {e}"))?;
    }
    if let Err(e) = fs::rename(&tmp, &path) {
        let _ = fs::remove_file(&tmp);
        return Err(format!("rename message store failed: {e}"));
    }
    #[cfg(unix)]
    {
        if let Some(parent) = path.parent() {
            if let Ok(dir) = fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
    }
    update_unified_message_store(app, encoded)?;
    Ok(())
}


pub fn derive_store_key_from_root(root_key: &[u8; 32]) -> [u8; 32] {
    derive_domain_key(root_key, b"message-store")
}

pub fn reencrypt_message_store(app: &AppHandle, old_root_key: &[u8; 32], new_root_key: &[u8; 32]) -> Result<(), String> {
    let old_store_key = derive_store_key_from_root(old_root_key);
    let legacy_old_key = *old_root_key;
    let store = load_store_with_keys(app, &old_store_key, &legacy_old_key)?;
    let new_store_key = derive_store_key_from_root(new_root_key);
    save_store_with_key(app, &store, &new_store_key)
}

fn now_ms() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64 }
fn fill_random(buf: &mut [u8]) -> Result<(), String> { getrandom::getrandom(buf).map_err(|e| format!("OS randomness unavailable: {e}")) }

fn fresh_signal_rng() -> Result<ChaCha20Rng, String> {
    let mut seed = [0u8; 32];
    fill_random(&mut seed)?;
    Ok(ChaCha20Rng::from_seed(seed))
}

fn generate_route_cert_keypair_b64() -> Result<(String, String), String> {
    let mut rng = fresh_signal_rng()?;
    let pair = KeyPair::generate(&mut rng);
    Ok((
        STANDARD_NO_PAD.encode(pair.public_key.serialize()),
        STANDARD_NO_PAD.encode(pair.private_key.serialize()),
    ))
}

fn ensure_route_cert_key(route: &mut LocalRoute) -> Result<(), String> {
    if route.sealed_sender_cert_public_b64.trim().is_empty()
        || route.sealed_sender_cert_private_b64.trim().is_empty()
    {
        let (public_b64, private_b64) = generate_route_cert_keypair_b64()?;
        route.sealed_sender_cert_public_b64 = public_b64;
        route.sealed_sender_cert_private_b64 = private_b64;
    }
    Ok(())
}

fn derive_domain_key(root_key: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"axeno-domain-separated-key-v1");
    hasher.update(label);
    hasher.update(root_key);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

pub fn legacy_identity_routing_id(blob: &EncryptedIdentity) -> String { fingerprint(blob).replace(':', "").replace(' ', "") }

fn random_token(prefix: &str, bytes: usize) -> Result<String, String> {
    let mut raw = vec![0u8; bytes];
    fill_random(&mut raw)?;
    Ok(format!("{}{}", prefix, URL_SAFE_NO_PAD.encode(raw)))
}

#[allow(dead_code)]
fn ensure_local_profile(store: &mut MessagingStore) -> Result<LocalProfile, String> {
    if let Some(profile) = store.local_profile.clone() { return Ok(profile); }
    let profile = LocalProfile {
        mailbox_id: random_token("mbx_", 24)?,
        receive_auth_token: random_token("rx_", 32)?,
        delivery_token: random_token("dt_", 32)?,
        created_at_ms: now_ms(),
    };
    store.local_profile = Some(profile.clone());
    Ok(profile)
}

fn new_local_route(server_url: String, scope: String, expires_at_ms: Option<u64>) -> Result<LocalRoute, String> {
    let normalized = normalize_server_url(Some(server_url));
    let (cert_public_b64, cert_private_b64) = generate_route_cert_keypair_b64()?;
    Ok(LocalRoute {
        id: random_token("rt_", 18)?,
        mailbox_id: random_token("mbx_", 24)?,
        receive_auth_token: random_token("rx_", 32)?,
        delivery_token: random_token("dt_", 32)?,
        delivery_token_epoch: 1,
        retired_delivery_tokens: Vec::new(),
        pending_token_retirements: Vec::new(),
        server_id: server_id_for_url(&normalized),
        server_url: normalized,
        sealed_sender_cert_public_b64: cert_public_b64,
        sealed_sender_cert_private_b64: cert_private_b64,
        scope,
        replacement_route_id: None,
        active: true,
        created_at_ms: now_ms(),
        expires_at_ms,
    })
}

fn route_connection_id(route: &LocalRoute) -> String {
    format!("{}__{}", route.server_id, route.mailbox_id)
}

fn queue_relay_retire(store: &mut MessagingStore, route: LocalRoute) {
    if !route.mailbox_id.starts_with("mbx_") { return; }
    if store.pending_relay_retires.iter().any(|r| r.server_url == route.server_url && r.mailbox_id == route.mailbox_id) { return; }
    store.pending_relay_retires.push(route);
}

fn cleanup_expired_routes(store: &mut MessagingStore) {
    let now = now_ms();
    store.pending_invites.retain(|p| p.expires_at_ms > now);

    let mut keep = Vec::with_capacity(store.local_routes.len());
    let routes = std::mem::take(&mut store.local_routes);
    for route in routes {
        let expired = route.expires_at_ms.map(|exp| exp <= now).unwrap_or(false);
        if route.active && !expired {
            keep.push(route);
        } else {
            queue_relay_retire(store, route);
        }
    }
    store.local_routes = keep;

    prune_old_messages(store);
}

/// Enforce per-contact message retention cap. Messages are sorted by timestamp
/// and the oldest are dropped when a contact exceeds MAX_MESSAGES_PER_CONTACT.
fn prune_old_messages(store: &mut MessagingStore) {
    // Group message counts by contact_id
    let mut counts: HashMap<String, usize> = HashMap::new();
    for msg in &store.messages {
        *counts.entry(msg.contact_id.clone()).or_insert(0) += 1;
    }
    // Check if any contact exceeds the limit
    let any_over = counts.values().any(|&c| c > MAX_MESSAGES_PER_CONTACT);
    if !any_over { return; }

    // Sort by (contact_id, timestamp) so we can keep the newest per contact
    store.messages.sort_by(|a, b| {
        a.contact_id.cmp(&b.contact_id)
            .then(a.timestamp.cmp(&b.timestamp))
            .then(a.received_at_ms.unwrap_or(a.timestamp).cmp(&b.received_at_ms.unwrap_or(b.timestamp)))
    });

    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut kept = Vec::with_capacity(store.messages.len());
    // Walk from newest to oldest (reverse)
    for msg in store.messages.drain(..).rev() {
        let count = seen.entry(msg.contact_id.clone()).or_insert(0);
        if *count < MAX_MESSAGES_PER_CONTACT {
            *count += 1;
            kept.push(msg);
        }
    }
    kept.reverse();
    store.messages = kept;
}

fn ensure_route_for_contact(store: &mut MessagingStore, contact_id: &str, server_url: &str) -> Result<LocalRoute, String> {
    cleanup_expired_routes(store);
    let normalized = normalize_server_url(Some(server_url.to_string()));
    if let Some(existing_route_id) = store.contacts.iter().find(|c| c.id == contact_id).and_then(|c| c.local_route_id.clone()) {
        if let Some(route) = store.local_routes.iter_mut().find(|r| r.id == existing_route_id) {
            if route.server_url == normalized && route.active {
                route.expires_at_ms = None;
                ensure_route_cert_key(route)?;
                return Ok(route.clone());
            }
        }
    }
    rotate_local_route_for_contact(store, contact_id, &normalized)
}

fn rotate_local_route_for_contact(store: &mut MessagingStore, contact_id: &str, server_url: &str) -> Result<LocalRoute, String> {
    let old_route_id = store.contacts.iter().find(|c| c.id == contact_id).and_then(|c| c.local_route_id.clone());
    let mut route_to_retire = None;
    if let Some(old_id) = old_route_id.as_ref() {
        if let Some(old_route) = store.local_routes.iter_mut().find(|r| &r.id == old_id) {
            old_route.active = false;
            old_route.expires_at_ms = Some(now_ms());
            route_to_retire = Some(old_route.clone());
        }
    }
    if let Some(route) = route_to_retire {
        queue_relay_retire(store, route);
    }
    let route = new_local_route(server_url.to_string(), format!("contact:{contact_id}"), None)?;
    let route_id = route.id.clone();
    store.local_routes.push(route.clone());
    if let Some(contact) = store.contacts.iter_mut().find(|c| c.id == contact_id) {
        contact.local_route_id = Some(route_id);
    }
    Ok(route)
}

fn route_for_mailbox(store: &MessagingStore, mailbox_id: &str) -> Option<LocalRoute> {
    store.local_routes.iter().find(|r| r.active && r.mailbox_id == mailbox_id).cloned()
}


fn route_is_sender_hold(route: &LocalRoute, contact_id: &str) -> bool {
    route.active && route.scope == format!("sender:{contact_id}")
}

fn route_is_retiring_invite_for_contact(route: &LocalRoute, contact_id: &str) -> bool {
    route.active && route.scope == format!("retiring_invite:{contact_id}")
}

fn sender_route_for_contact(store: &MessagingStore, contact_id: &str, fallback: &LocalRoute) -> LocalRoute {
    let contact = store.contacts.iter().find(|c| c.id == contact_id);
    let has_reusable_prekey = contact.map(contact_has_reusable_prekey_material).unwrap_or(false);

    // Only move the sender side onto the fresh per-contact route once we can
    // safely establish a clean PreKey session for that peer. Otherwise keep
    // using the old invite/session route, because a normal Signal message sent
    // from a new sealed-sender mailbox but encrypted with the old ratchet is
    // undecryptable by the peer under route-scoped sessions.
    if has_reusable_prekey {
        if let Some(route_id) = contact.and_then(|c| c.local_route_id.clone()) {
            if let Some(route) = store.local_routes.iter().find(|r| r.active && r.id == route_id && r.server_url == fallback.server_url) {
                return route.clone();
            }
        }
    }

    if let Some(route) = store.local_routes
        .iter()
        .find(|r| route_is_sender_hold(r, contact_id) && r.server_url == fallback.server_url)
    {
        return route.clone();
    }

    if let Some(route) = store.local_routes
        .iter()
        .find(|r| route_is_retiring_invite_for_contact(r, contact_id) && r.server_url == fallback.server_url)
    {
        return route.clone();
    }

    contact
        .and_then(|c| c.local_route_id.clone())
        .and_then(|route_id| store.local_routes.iter().find(|r| r.active && r.id == route_id && r.server_url == fallback.server_url).cloned())
        .unwrap_or_else(|| fallback.clone())
}

fn route_is_retiring_invite(route: &LocalRoute) -> bool {
    route.scope.starts_with("retiring_invite:")
}

fn pin_server_trust_root(store: &mut MessagingStore, server_id: &str, trust_root_b64: &str) -> Result<bool, String> {
    if trust_root_b64.trim().is_empty() { return Err("relay trust root was empty".into()); }
    if let Some(pinned) = store.server_trust_roots.get(server_id) {
        if pinned != trust_root_b64 {
            return Err("server trust root changed for this relay; refusing to continue until manually reviewed".into());
        }
        Ok(false)
    } else {
        store.server_trust_roots.insert(server_id.to_string(), trust_root_b64.to_string());
        Ok(true)
    }
}

fn contact_has_reusable_prekey_material(contact: &StoredContact) -> bool {
    !contact.identity_public_b64.trim().is_empty()
        && !contact.signed_prekey_public_b64.trim().is_empty()
        && contact.kyber_prekey_public_b64.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false)
}

fn legacy_route_from_profile(profile: LocalProfile, server_id: String, server_url: String) -> Result<LocalRoute, String> {
    let (cert_public_b64, cert_private_b64) = generate_route_cert_keypair_b64()?;
    Ok(LocalRoute {
        id: "legacy_local_profile".to_string(),
        mailbox_id: profile.mailbox_id,
        receive_auth_token: profile.receive_auth_token,
        delivery_token: profile.delivery_token,
        delivery_token_epoch: 1,
        retired_delivery_tokens: Vec::new(),
        pending_token_retirements: Vec::new(),
        server_url: normalize_server_url(Some(server_url)),
        server_id,
        sealed_sender_cert_public_b64: cert_public_b64,
        sealed_sender_cert_private_b64: cert_private_b64,
        scope: "legacy".to_string(),
        replacement_route_id: None,
        active: true,
        created_at_ms: profile.created_at_ms,
        expires_at_ms: None,
    })
}

fn route_delivery_allowlist(route: &LocalRoute) -> Vec<String> {
    let mut out = vec![route.delivery_token.clone()];
    for token in &route.retired_delivery_tokens {
        if !out.iter().any(|existing| existing == token) { out.push(token.clone()); }
    }
    for retired in &route.pending_token_retirements {
        if !out.iter().any(|existing| existing == &retired.token) { out.push(retired.token.clone()); }
    }
    out
}

fn normalize_legacy_retired_tokens(route: &mut LocalRoute) {
    let now = now_ms();
    let mut converted = Vec::new();
    for token in std::mem::take(&mut route.retired_delivery_tokens) {
        if token != route.delivery_token && !converted.iter().any(|r: &RetiredDeliveryToken| r.token == token) {
            converted.push(RetiredDeliveryToken {
                token,
                epoch: route.delivery_token_epoch.saturating_sub(1).max(1),
                retire_after_ms: now.saturating_add(DELIVERY_TOKEN_FALLBACK_TTL_MS),
            });
        }
    }
    route.pending_token_retirements.extend(converted);
}

fn prune_expired_token_retirements(route: &mut LocalRoute) -> bool {
    normalize_legacy_retired_tokens(route);
    let now = now_ms();
    let before = route.pending_token_retirements.len();
    route.pending_token_retirements.retain(|retired| retired.retire_after_ms > now);
    before != route.pending_token_retirements.len()
}

#[allow(dead_code)]
async fn rotate_route_delivery_token_after_confirmed(
    transport_state: &transport::TransportState,
    route: &mut LocalRoute,
) -> Result<bool, String> {
    normalize_legacy_retired_tokens(route);
    let old_token = route.delivery_token.clone();
    let new_token = random_token("dt_", 32)?;
    let new_epoch = route.delivery_token_epoch.saturating_add(1).max(2);
    let mut allowlist = vec![new_token.clone(), old_token.clone()];
    for retired in &route.pending_token_retirements {
        if !allowlist.iter().any(|token| token == &retired.token) { allowlist.push(retired.token.clone()); }
    }
    transport::set_delivery_tokens_confirmed(
        transport_state,
        route_connection_id(route),
        allowlist,
    ).await?;
    route.delivery_token = new_token;
    route.delivery_token_epoch = new_epoch;
    route.pending_token_retirements.push(RetiredDeliveryToken {
        token: old_token,
        epoch: new_epoch.saturating_sub(1).max(1),
        retire_after_ms: now_ms().saturating_add(DELIVERY_TOKEN_FALLBACK_TTL_MS),
    });
    Ok(true)
}

#[allow(dead_code)]
async fn retire_acknowledged_route_tokens(
    transport_state: &transport::TransportState,
    route: &mut LocalRoute,
    acked_epoch: Option<u64>,
) -> Result<bool, String> {
    normalize_legacy_retired_tokens(route);
    let mut changed = prune_expired_token_retirements(route);
    let before = route.pending_token_retirements.len();
    if let Some(acked) = acked_epoch {
        if acked >= route.delivery_token_epoch {
            route.pending_token_retirements.clear();
        }
    }
    if before != route.pending_token_retirements.len() { changed = true; }
    if changed {
        transport::set_delivery_tokens_confirmed(
            transport_state,
            route_connection_id(route),
            route_delivery_allowlist(route),
        ).await?;
    }
    Ok(changed)
}

#[allow(dead_code)]
fn token_hash(token: &str) -> String { hex::encode(Sha256::digest(token.as_bytes())) }

fn pairwise_safety_number(local_identity_public: &[u8], remote_identity_public: &[u8]) -> String {
    let (first, second) = if local_identity_public <= remote_identity_public {
        (local_identity_public, remote_identity_public)
    } else {
        (remote_identity_public, local_identity_public)
    };
    let mut hasher = Sha256::new();
    hasher.update(b"axeno-safety-number-v1");
    hasher.update(first);
    hasher.update(second);
    hex::encode(&hasher.finalize()[..16])
}

fn default_trust_state() -> String { "unverified".to_string() }

enum DecodedInviteCode {
    Direct(InvitePayload),
    Hosted(HostedInviteCode),
}

fn decode_invite_code(code: &str) -> Result<DecodedInviteCode, String> {
    let encoded = code.trim().strip_prefix(INVITE_PREFIX).ok_or_else(|| "connection code must start with axn1_".to_string())?;
    let bytes = URL_SAFE_NO_PAD.decode(encoded.as_bytes()).map_err(|_| "connection code base64 is invalid".to_string())?;
    if let Ok(hosted) = serde_json::from_slice::<HostedInviteCode>(&bytes) {
        if hosted.v == 1 && hosted.kind == "axeno_hosted_invite_v1" {
            return Ok(DecodedInviteCode::Hosted(hosted));
        }
    }
    serde_json::from_slice::<InvitePayload>(&bytes)
        .map(DecodedInviteCode::Direct)
        .map_err(|e| format!("connection code payload is invalid: {e}"))
}

#[allow(dead_code)]
fn payload_to_code(payload: &InvitePayload) -> Result<String, String> {
    Ok(format!("{}{}", INVITE_PREFIX, URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).map_err(|e| e.to_string())?)))
}

fn hosted_code_to_code(payload: &HostedInviteCode) -> Result<String, String> {
    Ok(format!("{}{}", INVITE_PREFIX, URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).map_err(|e| e.to_string())?)))
}

fn encrypt_hosted_invite_payload(payload: InvitePayload, server_url: &str) -> Result<(String, String, String), String> {
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    fill_random(&mut key)?;
    fill_random(&mut nonce)?;
    let bundle_id = random_token("bun_", 24)?;
    let bundle = HostedInviteBundle { v: 1, payload };
    let mut plaintext = serde_json::to_vec(&bundle).map_err(|e| format!("could not serialize hosted invite bundle: {e}"))?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
        .map_err(|_| "hosted invite bundle encryption failed".to_string())?;
    plaintext.zeroize();
    let wrapped = HostedInviteCiphertext {
        v: 1,
        nonce_b64: URL_SAFE_NO_PAD.encode(nonce),
        ciphertext_b64: URL_SAFE_NO_PAD.encode(ciphertext),
    };
    let hosted = HostedInviteCode {
        v: 1,
        kind: "axeno_hosted_invite_v1".to_string(),
        server_url: normalize_server_url(Some(server_url.to_string())),
        bundle_id: bundle_id.clone(),
        bundle_key_b64: URL_SAFE_NO_PAD.encode(key),
    };
    let code = hosted_code_to_code(&hosted)?;
    let relay_blob = serde_json::to_string(&wrapped).map_err(|e| format!("could not serialize hosted invite ciphertext: {e}"))?;
    Ok((code, bundle_id, relay_blob))
}

fn decrypt_hosted_invite_payload(hosted: HostedInviteCode, relay_blob: String) -> Result<InvitePayload, String> {
    if hosted.v != 1 || hosted.kind != "axeno_hosted_invite_v1" {
        return Err("unsupported hosted connection code".into());
    }
    let key = URL_SAFE_NO_PAD.decode(hosted.bundle_key_b64.as_bytes()).map_err(|_| "hosted invite key is invalid".to_string())?;
    if key.len() != 32 { return Err("hosted invite key has wrong length".into()); }
    let wrapped: HostedInviteCiphertext = serde_json::from_str(&relay_blob).map_err(|e| format!("hosted invite bundle is corrupted: {e}"))?;
    if wrapped.v != 1 { return Err("unsupported hosted invite bundle version".into()); }
    let nonce = URL_SAFE_NO_PAD.decode(wrapped.nonce_b64.as_bytes()).map_err(|_| "hosted invite nonce is invalid".to_string())?;
    if nonce.len() != 12 { return Err("hosted invite nonce has wrong length".into()); }
    let ciphertext = URL_SAFE_NO_PAD.decode(wrapped.ciphertext_b64.as_bytes()).map_err(|_| "hosted invite ciphertext is invalid".to_string())?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let mut plaintext = cipher.decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| "hosted invite bundle could not be decrypted".to_string())?;
    let bundle: HostedInviteBundle = serde_json::from_slice(&plaintext).map_err(|e| format!("hosted invite plaintext is invalid: {e}"))?;
    plaintext.zeroize();
    if bundle.v != 1 { return Err("unsupported hosted invite plaintext version".into()); }
    Ok(bundle.payload)
}

async fn resolve_invite_payload(
    code: &str,
    tor_client: Arc<Mutex<Option<arti_client::TorClient<tor_rtcompat::PreferredRuntime>>>>,
) -> Result<InvitePayload, String> {
    match decode_invite_code(code)? {
        DecodedInviteCode::Direct(payload) => Ok(payload),
        DecodedInviteCode::Hosted(hosted) => {
            let relay_blob = transport::fetch_invite_bundle(tor_client, hosted.server_url.clone(), hosted.bundle_id.clone()).await?;
            decrypt_hosted_invite_payload(hosted, relay_blob)
        }
    }
}

fn verification_payload_to_code(payload: &SignedVerificationPayload) -> Result<String, String> {
    Ok(format!("{}{}", VERIFY_PREFIX, URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).map_err(|e| e.to_string())?)))
}

fn code_to_verification_payload(code: &str) -> Result<SignedVerificationPayload, String> {
    let encoded = code.trim().strip_prefix(VERIFY_PREFIX).ok_or_else(|| "verification code must start with axv1_".to_string())?;
    let bytes = URL_SAFE_NO_PAD.decode(encoded.as_bytes()).map_err(|_| "verification code base64 is invalid".to_string())?;
    serde_json::from_slice::<SignedVerificationPayload>(&bytes).map_err(|e| format!("verification code payload is invalid: {e}"))
}

fn normalize_server_url(url: Option<String>) -> String {
    let raw = url.unwrap_or_else(|| DEFAULT_DEV_SERVER.to_string()).trim().to_string();
    if raw.is_empty() { return DEFAULT_DEV_SERVER.to_string(); }
    if raw.ends_with("/ws") { raw }
    else if raw.starts_with("ws://") || raw.starts_with("wss://") { format!("{}/ws", raw.trim_end_matches('/')) }
    else if raw.ends_with(".onion") { format!("ws://{raw}/ws") }
    else { raw }
}

fn ws_url_host(url: &str) -> Option<String> {
    let rest = url.strip_prefix("ws://").or_else(|| url.strip_prefix("wss://"))?;
    let authority = rest.split('/').next()?.trim();
    if authority.is_empty() || authority.contains('@') || authority.starts_with('[') { return None; }
    let host = authority
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(authority)
        .trim()
        .to_ascii_lowercase();
    if host.is_empty() { None } else { Some(host) }
}

fn is_private_onion_ws_url(url: &str) -> bool {
    let normalized = normalize_server_url(Some(url.to_string()));
    normalized.starts_with("ws://")
        && ws_url_host(&normalized).map(|host| host.ends_with(".onion")).unwrap_or(false)
}
pub fn server_id_for_url(url: &str) -> String { format!("srv_{}", hex::encode(&Sha256::digest(url.as_bytes())[..8])) }

fn relay_display_name_for_url(store: &MessagingStore, server_url: &str) -> String {
    let normalized = normalize_server_url(Some(server_url.to_string()));
    if let Some(server) = store.private_servers.iter().find(|s| normalize_server_url(Some(s.onion.clone())) == normalized) {
        return server.name.clone();
    }
    if normalized == DEFAULT_DEV_SERVER {
        return "Local dev relay".to_string();
    }
    "Unknown relay".to_string()
}

fn clean_relay_display_name(input: Option<String>) -> Option<String> {
    let name = input?.trim().to_string();
    if name.is_empty() { return None; }
    Some(name.chars().take(80).collect())
}

fn connection_code_response(store: &MessagingStore, pending: &PendingInvite) -> ConnectionCodeResponse {
    let current_name = relay_display_name_for_url(store, &pending.server_url);
    let server_name = if current_name == "Unknown relay" {
        pending.server_name.clone().unwrap_or(current_name)
    } else {
        current_name
    };

    ConnectionCodeResponse {
        id: pending.id.clone(),
        code: pending.code.clone(),
        created_at: pending.created_at_ms,
        server_url: pending.server_url.clone(),
        server_name,
        reusable: pending.reusable,
    }
}

fn prune_failed_envelopes(map: &mut HashMap<String, FailedEnvelopeEntry>, now: u64) {
    map.retain(|_, entry| now.saturating_sub(entry.last_seen_ms) <= FAILED_ENVELOPE_TTL_MS);
    if map.len() <= MAX_FAILED_ENVELOPES { return; }
    let mut entries: Vec<(String, u64)> = map.iter().map(|(k, v)| (k.clone(), v.last_seen_ms)).collect();
    entries.sort_by_key(|(_, ts)| *ts);
    let remove_count = map.len().saturating_sub(MAX_FAILED_ENVELOPES);
    for (key, _) in entries.into_iter().take(remove_count) { map.remove(&key); }
}

fn sign_verification_payload(material: &PrivateSignalMaterial, payload: &VerificationPayload) -> Result<String, String> {
    let private = PrivateKey::deserialize(&material.identity_priv).map_err(|e| format!("local identity private key is invalid: {e}"))?;
    let mut rng = fresh_signal_rng()?;
    let bytes = serde_json::to_vec(payload).map_err(|e| format!("could not serialize verification payload: {e}"))?;
    let sig = private.calculate_signature(&bytes, &mut rng).map_err(|e| format!("could not sign verification code: {e}"))?;
    Ok(STANDARD_NO_PAD.encode(sig))
}

fn verify_verification_payload_signature(payload: &VerificationPayload, signature_b64: &str) -> Result<(), String> {
    let remote_public = PublicKey::deserialize(&decode_b64(&payload.local_identity_public_b64, "verification signer identity public key")?)
        .map_err(|e| format!("verification signer public key is invalid: {e}"))?;
    let sig = decode_b64(signature_b64, "verification signature")?;
    let bytes = serde_json::to_vec(payload).map_err(|e| format!("could not serialize verification payload: {e}"))?;
    let ok = remote_public.verify_signature(&bytes, &sig);
    if !ok { return Err("verification code signature did not match the claimed identity".to_string()); }
    Ok(())
}

fn decode_b64(s: &str, label: &str) -> Result<Vec<u8>, String> {
    STANDARD_NO_PAD.decode(s.as_bytes()).map_err(|_| format!("bad base64 for {label}"))
}

fn contact_from_payload(payload: InvitePayload, local_identity_public: &[u8]) -> Result<StoredContact, String> {
    if payload.v != 1 || payload.protocol != PROTOCOL_SIGNAL { return Err("unsupported connection code protocol".into()); }
    let now = now_ms();
    // Reject codes claiming to be created far in the future — prevents a
    // malicious generator from bypassing the 24-hour TTL by setting
    // created_at_ms to a future timestamp.
    const MAX_CLOCK_DRIFT_MS: u64 = 5 * 60 * 1000;
    if payload.created_at_ms > now.saturating_add(MAX_CLOCK_DRIFT_MS) {
        return Err("connection code claims to be from the future; check your clock or request a fresh code".into());
    }
    if payload.created_at_ms.saturating_add(CONNECTION_CODE_TTL_MS) < now {
        return Err("connection code has expired; ask for a fresh code".into());
    }
    let server_url = normalize_server_url(Some(payload.server_url.clone()));
    let identity_public = STANDARD_NO_PAD.decode(payload.identity_public_b64.as_bytes()).map_err(|_| "bad identity public key in code".to_string())?;
    if identity_public == local_identity_public {
        return Err("this connection code belongs to your own identity".into());
    }
    Ok(StoredContact {
        id: payload.mailbox_id.clone(),
        display_name: Some(payload.display_name.clone()).filter(|s| !s.trim().is_empty()),
        recipient_id: payload.mailbox_id.clone(),
        server_url: server_url.clone(),
        server_id: server_id_for_url(&server_url),
        identity_public_b64: payload.identity_public_b64,
        registration_id: payload.registration_id,
        device_id: payload.device_id,
        signed_prekey_id: payload.signed_prekey_id,
        signed_prekey_public_b64: payload.signed_prekey_public_b64,
        signed_prekey_signature_b64: payload.signed_prekey_signature_b64,
        opk_id: payload.opk_id,
        opk_public_b64: payload.opk_public_b64,
        kyber_prekey_id: payload.kyber_prekey_id,
        kyber_prekey_public_b64: payload.kyber_prekey_public_b64,
        kyber_prekey_signature_b64: payload.kyber_prekey_signature_b64,
        delivery_token: payload.delivery_token,
        delivery_token_epoch: 1,
        safety_number: pairwise_safety_number(local_identity_public, &identity_public),
        trust_state: "unverified".to_string(),
        verified_at_ms: None,
        local_route_id: None,
        peer_sender_mailbox_id: None,
        created_at_ms: now_ms(),
        last_read_at: None,
    })
}


pub async fn load_private_server_settings(app: AppHandle, session: &AppSessionState) -> Result<PrivateServerSettings, String> {
    let (store_key, legacy_store_key) = store_keys(session).await?;
    let store = load_store_with_keys(&app, &store_key, &legacy_store_key)?;
    Ok(PrivateServerSettings {
        private_servers: store.private_servers.clone(),
        default_server_url: store.default_server_url.clone(),
    })
}

pub async fn save_private_server_settings(app: AppHandle, session: &AppSessionState, settings: PrivateServerSettings) -> Result<PrivateServerSettings, String> {
    let _store_guard = session.messaging_store_lock.lock().await;
    let (store_key, legacy_store_key) = store_keys(session).await?;
    let mut store = load_store_with_keys(&app, &store_key, &legacy_store_key)?;
    let mut private_servers = Vec::new();
    let mut seen = HashSet::new();
    for server in settings.private_servers.into_iter().take(32) {
        let id = server.id.trim().to_string();
        let name = server.name.trim().to_string();
        let onion = normalize_server_url(Some(server.onion.trim().to_string()));
        if id.is_empty() || name.is_empty() || !seen.insert(id.clone()) { continue; }
        if !is_private_onion_ws_url(&onion) {
            return Err("private servers must be ws:// .onion WebSocket URLs".to_string());
        }
        private_servers.push(PrivateServerSetting { id, name, onion });
    }
    let default_server_url = settings.default_server_url
        .map(|url| normalize_server_url(Some(url)))
        .filter(|url| private_servers.iter().any(|s| s.onion == *url));
    store.private_servers = private_servers;
    store.default_server_url = default_server_url;
    let out = PrivateServerSettings { private_servers: store.private_servers.clone(), default_server_url: store.default_server_url.clone() };
    save_store_with_key(&app, &store, &store_key)?;
    Ok(out)
}

pub async fn generate_connection_code(
    app: AppHandle,
    session: &AppSessionState,
    transport_state: &transport::TransportState,
    tor_client: Arc<Mutex<Option<arti_client::TorClient<tor_rtcompat::PreferredRuntime>>>>,
    server_url: Option<String>,
    server_name: Option<String>,
    reusable: bool,
) -> Result<ConnectionCodeResponse, String> {
    let (store_key, legacy_store_key) = store_keys(session).await?;
    let (response, route_for_connect, bundle_id, hosted_ciphertext, expires) = {
        let _store_guard = session.messaging_store_lock.lock().await;
        let mut blob = load_vault(&app)?;
        let mut store = load_store_with_keys(&app, &store_key, &legacy_store_key)?;
        cleanup_expired_routes(&mut store);
        let material = {
            let mut guard = session.session.lock().await;
            let unlocked = guard.as_mut().ok_or_else(|| "identity is locked".to_string())?;
            let mut changed = false;
            let low_opk_pool = blob.opks_public.len() < 20 || unlocked.secrets.opks_secret.len() < 20;
            changed |= rotate_signed_prekey_if_due(&mut blob, &mut unlocked.secrets, SIGNED_PREKEY_ROTATION_MS).map_err(|e| e.to_string())?;
            remove_consumed_opks_and_replenish(&mut blob, &mut unlocked.secrets, &[]).map_err(|e| e.to_string())?;
            if changed || low_opk_pool {
                reseal_vault(&mut blob, &unlocked.key, &unlocked.secrets).map_err(|e| e.to_string())?;
                save_vault(&app, &blob)?;
            }
            PrivateSignalMaterial {
                identity_priv: unlocked.secrets.identity_priv.clone(),
                spk_priv: unlocked.secrets.spk_priv.clone(),
                previous_spks_secret: unlocked.secrets.previous_spks_secret.clone(),
                opks_secret: unlocked.secrets.opks_secret.clone(),
                display_name: unlocked.secrets.display_name.clone(),
            }
        };

        // Reserve a fresh one-time prekey per generated invite if it is single-use.
        let opk = if reusable {
            None
        } else {
            let opk = blob.opks_public
                .iter()
                .find(|o| !store.used_opk_ids.contains(&o.id))
                .cloned()
                .ok_or_else(|| "no fresh one-time prekeys are available; restart Axeno or unlock again to replenish the pool".to_string())?;
            store.used_opk_ids.push(opk.id);
            Some(opk)
        };

        let created = now_ms();
        let expires = created.saturating_add(CONNECTION_CODE_TTL_MS);
        let route = new_local_route(
            normalize_server_url(server_url),
            "pending_invite".to_string(),
            Some(expires),
        )?;
        let kyber = signal_protocol_engine::ensure_local_kyber_prekey(&blob, &material, &mut store)?;
        let payload = InvitePayload {
            v: 1,
            protocol: PROTOCOL_SIGNAL.to_string(),
            display_name: material.display_name.trim().to_string(),
            mailbox_id: route.mailbox_id.clone(),
            delivery_token: route.delivery_token.clone(),
            server_url: route.server_url.clone(),
            device_id: DEVICE_ID,
            identity_public_b64: STANDARD_NO_PAD.encode(&blob.public_key),
            registration_id: blob.registration_id as u32,
            signed_prekey_id: blob.signed_prekey_id,
            signed_prekey_public_b64: STANDARD_NO_PAD.encode(&blob.signed_prekey_public),
            signed_prekey_signature_b64: STANDARD_NO_PAD.encode(&blob.signed_prekey_signature),
            opk_id: opk.as_ref().map(|o| o.id),
            opk_public_b64: opk.as_ref().map(|o| STANDARD_NO_PAD.encode(&o.public_key)),
            kyber_prekey_id: Some(kyber.id),
            kyber_prekey_public_b64: Some(kyber.public_b64.clone()),
            kyber_prekey_signature_b64: Some(kyber.signature_b64.clone()),
            created_at_ms: created,
        };
        let (code, bundle_id, hosted_ciphertext) = encrypt_hosted_invite_payload(payload, &route.server_url)?;
        let inferred_server_name = relay_display_name_for_url(&store, &route.server_url);
        let pending = PendingInvite {
            id: Uuid::new_v4().to_string(),
            code: code.clone(),
            mailbox_id: route.mailbox_id.clone(),
            server_url: route.server_url.clone(),
            server_name: clean_relay_display_name(server_name).or_else(|| {
                if inferred_server_name == "Unknown relay" { None } else { Some(inferred_server_name) }
            }),
            route_id: Some(route.id.clone()),
            created_at_ms: created,
            expires_at_ms: expires,
            reusable,
        };
        let route_for_connect = route.clone();
        store.local_routes.push(route);
        store.pending_invites.push(pending.clone());
        let response = connection_code_response(&store, &pending);
        save_store_with_key(&app, &store, &store_key)?;
        (response, route_for_connect, bundle_id, hosted_ciphertext, expires)
    };

    // Register the invite mailbox immediately and upload only the encrypted
    // prekey bundle to the relay. The shareable code contains a random bundle
    // handle + symmetric key, not the full Signal/PQ prekey material. This is
    // intentionally done after releasing the local store lock so a slow relay
    // cannot freeze unrelated message-store operations.
    transport::connect_server(
        app.clone(),
        transport_state,
        tor_client.clone(),
        route_connection_id(&route_for_connect),
        route_for_connect.server_url.clone(),
        route_for_connect.mailbox_id.clone(),
        route_for_connect.receive_auth_token.clone(),
        route_for_connect.delivery_token.clone(),
    ).await?;
    transport::upload_invite_bundle(
        tor_client,
        route_for_connect.server_url.clone(),
        bundle_id,
        hosted_ciphertext,
        expires,
    ).await?;

    Ok(response)
}

pub async fn list_connection_codes(app: AppHandle, session: &AppSessionState) -> Result<Vec<ConnectionCodeResponse>, String> {
    let _store_guard = session.messaging_store_lock.lock().await;
    let (store_key, legacy_store_key) = store_keys(session).await?;
    let mut store = load_store_with_keys(&app, &store_key, &legacy_store_key)?;
    cleanup_expired_routes(&mut store);
    let out = store.pending_invites.iter().map(|p| connection_code_response(&store, p)).collect();
    save_store_with_key(&app, &store, &store_key)?;
    Ok(out)
}

pub async fn delete_connection_code(app: AppHandle, session: &AppSessionState, id: String) -> Result<Vec<String>, String> {
    let _store_guard = session.messaging_store_lock.lock().await;
    let (store_key, legacy_store_key) = store_keys(session).await?;
    let mut store = load_store_with_keys(&app, &store_key, &legacy_store_key)?;
    let route_ids: Vec<String> = store.pending_invites
        .iter()
        .filter(|p| p.id == id)
        .filter_map(|p| p.route_id.clone())
        .collect();
    let connection_ids: Vec<String> = store.local_routes
        .iter()
        .filter(|r| route_ids.iter().any(|rid| rid == &r.id))
        .map(route_connection_id)
        .collect();
    store.pending_invites.retain(|p| p.id != id);
    for route in &mut store.local_routes {
        if route_ids.iter().any(|rid| rid == &route.id) {
            route.active = false;
            route.expires_at_ms = Some(now_ms());
        }
    }
    cleanup_expired_routes(&mut store);
    save_store_with_key(&app, &store, &store_key)?;
    Ok(connection_ids)
}

pub async fn add_contact_from_code(
    app: AppHandle,
    session: &AppSessionState,
    tor_client: Arc<Mutex<Option<arti_client::TorClient<tor_rtcompat::PreferredRuntime>>>>,
    code: String,
) -> Result<StoredContact, String> {
    let (store_key, legacy_store_key) = store_keys(session).await?;
    let blob = load_vault(&app)?;
    let payload = resolve_invite_payload(&code, tor_client).await?;
    let contact = contact_from_payload(payload, &blob.public_key)?;

    let _store_guard = session.messaging_store_lock.lock().await;
    let mut store = load_store_with_keys(&app, &store_key, &legacy_store_key)?;
    cleanup_expired_routes(&mut store);

    if let Some(pos) = store.contacts.iter().position(|c| c.recipient_id == contact.recipient_id) {
        if store.contacts[pos].identity_public_b64 != contact.identity_public_b64 && !store.contacts[pos].identity_public_b64.is_empty() {
            store.contacts[pos].trust_state = "identity_changed_blocked".to_string();
            store.contacts[pos].verified_at_ms = None;
            save_store_with_key(&app, &store, &store_key)?;
            return Err("contact identity key changed; refusing to replace it automatically. Verify out-of-band before re-adding.".into());
        }
        let contact_id = store.contacts[pos].id.clone();
        let route = ensure_route_for_contact(&mut store, &contact_id, &contact.server_url)?;
        let existing = &mut store.contacts[pos];
        existing.display_name = contact.display_name.clone().or_else(|| existing.display_name.clone());
        existing.server_url = contact.server_url.clone();
        existing.server_id = contact.server_id.clone();
        existing.identity_public_b64 = contact.identity_public_b64.clone();
        existing.registration_id = contact.registration_id;
        existing.device_id = contact.device_id;
        existing.signed_prekey_id = contact.signed_prekey_id;
        existing.signed_prekey_public_b64 = contact.signed_prekey_public_b64.clone();
        existing.signed_prekey_signature_b64 = contact.signed_prekey_signature_b64.clone();
        existing.opk_id = contact.opk_id;
        existing.opk_public_b64 = contact.opk_public_b64.clone();
        existing.kyber_prekey_id = contact.kyber_prekey_id;
        existing.kyber_prekey_public_b64 = contact.kyber_prekey_public_b64.clone();
        existing.kyber_prekey_signature_b64 = contact.kyber_prekey_signature_b64.clone();
        existing.delivery_token = contact.delivery_token.clone();
        existing.delivery_token_epoch = contact.delivery_token_epoch.max(existing.delivery_token_epoch);
        existing.safety_number = contact.safety_number.clone();
        existing.local_route_id = Some(route.id.clone());
        let updated = existing.clone();
        save_store_with_key(&app, &store, &store_key)?;
        return Ok(updated);
    }

    store.contacts.push(contact.clone());
    let route = ensure_route_for_contact(&mut store, &contact.id, &contact.server_url)?;
    if let Some(stored) = store.contacts.iter_mut().find(|c| c.id == contact.id) {
        stored.local_route_id = Some(route.id.clone());
    }
    let stored = store.contacts.iter().find(|c| c.id == contact.id).cloned().unwrap_or(contact);
    save_store_with_key(&app, &store, &store_key)?;
    Ok(stored)
}

pub async fn snapshot(app: AppHandle, session: &AppSessionState) -> Result<MessagingSnapshot, String> {
    let _store_guard = session.messaging_store_lock.lock().await;
    let (store_key, legacy_store_key) = store_keys(session).await?;
    let mut store = load_store_with_keys(&app, &store_key, &legacy_store_key)?;
    cleanup_expired_routes(&mut store);
    let mut grouped: HashMap<String, Vec<StoredMessage>> = HashMap::new();
    for msg in store.messages.clone() { grouped.entry(msg.contact_id.clone()).or_default().push(msg); }
    for msgs in grouped.values_mut() { msgs.sort_by_key(|m| (m.timestamp, m.received_at_ms.unwrap_or(m.timestamp))); }
    let my_recipient_ids: Vec<String> = store.local_routes.iter().filter(|r| r.active).map(|r| r.mailbox_id.clone()).collect();
    let my_recipient_id = my_recipient_ids.first().cloned().or_else(|| store.local_profile.as_ref().map(|p| p.mailbox_id.clone())).unwrap_or_default();
    save_store_with_key(&app, &store, &store_key)?;
    Ok(MessagingSnapshot { my_recipient_id, my_recipient_ids, contacts: store.contacts, messages: grouped })
}

pub async fn connect_all(app: AppHandle, session: &AppSessionState, transport_state: &transport::TransportState, tor_client: Arc<Mutex<Option<arti_client::TorClient<tor_rtcompat::PreferredRuntime>>>>) -> Result<(), String> {
    let (store_key, legacy_store_key) = store_keys(session).await?;
    let (routes, retire_routes) = {
        let _store_guard = session.messaging_store_lock.lock().await;
        let mut store = load_store_with_keys(&app, &store_key, &legacy_store_key)?;
        cleanup_expired_routes(&mut store);

        // Make sure every imported contact has a private return mailbox on that
        // contact's relay. This avoids one global mailbox linking all contacts.
        let contact_routes: Vec<(String, String)> = store.contacts.iter().map(|c| (c.id.clone(), c.server_url.clone())).collect();
        for (contact_id, server_url) in contact_routes {
            let _ = ensure_route_for_contact(&mut store, &contact_id, &server_url)?;
        }

        for route in &mut store.local_routes {
            prune_expired_token_retirements(route);
        }
        let routes: Vec<LocalRoute> = store.local_routes.iter().filter(|r| r.active).cloned().collect();
        let retire_routes = store.pending_relay_retires.clone();
        save_store_with_key(&app, &store, &store_key)?;
        (routes, retire_routes)
    };

    if !retire_routes.is_empty() {
        let mut still_pending = Vec::new();
        for route in retire_routes {
            let retired = transport::retire_mailbox_once(
                tor_client.clone(),
                route.server_url.clone(),
                route.mailbox_id.clone(),
                route.receive_auth_token.clone(),
                route.delivery_token.clone(),
            ).await.is_ok();
            if !retired { still_pending.push(route); }
        }
        let _store_guard = session.messaging_store_lock.lock().await;
        let mut store = load_store_with_keys(&app, &store_key, &legacy_store_key)?;
        store.pending_relay_retires = still_pending;
        save_store_with_key(&app, &store, &store_key)?;
    }

    let mut tasks = Vec::new();
    for route in routes {
        let app_clone = app.clone();
        let transport_state_clone = transport_state.clone();
        let tor_client_clone = tor_client.clone();
        
        tasks.push(tokio::spawn(async move {
            let connection_id = route_connection_id(&route);
            let _ = transport::connect_server(
                app_clone,
                &transport_state_clone,
                tor_client_clone,
                connection_id.clone(),
                route.server_url.clone(),
                route.mailbox_id.clone(),
                route.receive_auth_token.clone(),
                route.delivery_token.clone(),
            ).await;
            let allowlist = route_delivery_allowlist(&route);
            if allowlist.len() > 1 {
                let _ = transport::set_delivery_tokens_confirmed(&transport_state_clone, connection_id, allowlist).await;
            }
        }));
    }
    for task in tasks {
        let _ = task.await;
    }
    Ok(())
}

async fn send_signal_payload_internal(
    app: AppHandle,
    session: &AppSessionState,
    transport_state: &transport::TransportState,
    tor_client: Arc<Mutex<Option<arti_client::TorClient<tor_rtcompat::PreferredRuntime>>>>,
    contact_id: String,
    payload_kind: &str,
    text: String,
    visible: bool,
    force_prekey: bool,
) -> Result<Option<StoredMessage>, String> {
    let (store_key, legacy_store_key) = store_keys(session).await?;
    let trimmed = if payload_kind == "text" { text.trim().to_string() } else { text };
    if payload_kind == "text" && trimmed.is_empty() { return Err("message is empty".into()); }
    if trimmed.len() > 16 * 1024 { return Err("message too large for text MVP".into()); }
    let blob = load_vault(&app)?;
    let material = signal_material(session).await?;

    let (contact_for_cert, sender_route_for_cert) = {
        let _store_guard = session.messaging_store_lock.lock().await;
        let mut store = load_store_with_keys(&app, &store_key, &legacy_store_key)?;
        cleanup_expired_routes(&mut store);
        let contact = store.contacts.iter().find(|c| c.id == contact_id).cloned().ok_or_else(|| "contact not found".to_string())?;
        if contact.trust_state == "identity_changed_blocked" { return Err("contact identity changed; verify before sending".into()); }
        let return_route = ensure_route_for_contact(&mut store, &contact.id, &contact.server_url)?;
        let sender_route = sender_route_for_contact(&store, &contact.id, &return_route);
        save_store_with_key(&app, &store, &store_key)?;
        (contact, sender_route)
    };

    let connection_id_for_cert = route_connection_id(&sender_route_for_cert);
    let cert = match transport::request_sender_certificate(
        transport_state,
        connection_id_for_cert.clone(),
        sender_route_for_cert.mailbox_id.clone(),
        DEVICE_ID,
        sender_route_for_cert.sealed_sender_cert_public_b64.clone(),
    ).await {
        Ok(cert) => cert,
        Err(primary_err) => {
            // Route migration can create a valid route in the encrypted store
            // before the long-lived receive socket is present in TransportState.
            // Do not fail user sends with "server not connected"; get the
            // certificate over a short-lived authenticated socket, then force a
            // reconnect of the long-lived route so inbound delivery still works.
            let cert = transport::request_sender_certificate_once(
                tor_client.clone(),
                sender_route_for_cert.server_url.clone(),
                sender_route_for_cert.mailbox_id.clone(),
                sender_route_for_cert.receive_auth_token.clone(),
                sender_route_for_cert.delivery_token.clone(),
                DEVICE_ID,
                sender_route_for_cert.sealed_sender_cert_public_b64.clone(),
            ).await.map_err(|fallback_err| format!("sender certificate failed ({primary_err}); fallback also failed: {fallback_err}"))?;
            let _ = transport::disconnect_server(transport_state, connection_id_for_cert.clone()).await;
            let _ = transport::connect_server(
                app.clone(),
                transport_state,
                tor_client.clone(),
                connection_id_for_cert,
                sender_route_for_cert.server_url.clone(),
                sender_route_for_cert.mailbox_id.clone(),
                sender_route_for_cert.receive_auth_token.clone(),
                sender_route_for_cert.delivery_token.clone(),
            ).await;
            cert
        }
    };

    let message_id = Uuid::new_v4().to_string();
    let sent_at = now_ms();
    let (send_server_url, send_to, send_delivery_token, wire_json, mut maybe_msg) = {
        let _store_guard = session.messaging_store_lock.lock().await;
        let mut store = load_store_with_keys(&app, &store_key, &legacy_store_key)?;
        cleanup_expired_routes(&mut store);
        pin_server_trust_root(&mut store, &sender_route_for_cert.server_id, &cert.trust_root_b64)?;

        let contact = store.contacts.iter().find(|c| c.id == contact_for_cert.id).cloned().ok_or_else(|| "contact not found".to_string())?;
        if contact.trust_state == "identity_changed_blocked" { return Err("contact identity changed; verify before sending".into()); }
        let return_route = ensure_route_for_contact(&mut store, &contact.id, &contact.server_url)?;
        let sender_route = sender_route_for_contact(&store, &contact.id, &return_route);
        if sender_route.id != sender_route_for_cert.id {
            return Err("sender route changed while preparing message; retry send".into());
        }

        let encrypted = signal_protocol_engine::encrypt_for_contact(
            &blob,
            &material,
            &contact,
            &sender_route,
            &return_route,
            &mut store,
            payload_kind,
            &trimmed,
            &message_id,
            sent_at,
            &cert,
            force_prekey,
            contact.peer_sender_mailbox_id.clone(),
        ).await?;
        let padded = pad_ciphertext(&encrypted.sealed_sender)?;
        let wire = SealedSignalWireMessage { v: 1, sealed_sender_b64: STANDARD_NO_PAD.encode(padded) };
        let maybe_msg = if visible {
            let msg = StoredMessage {
                id: message_id.clone(),
                contact_id: contact.id.clone(),
                mine: true,
                text: trimmed.clone(),
                timestamp: sent_at,
                received_at_ms: None,
                status: "relay_pending".to_string(),
            };
            store.messages.push(msg.clone());
            Some(msg)
        } else {
            None
        };
        save_store_with_key(&app, &store, &store_key)?;
        (
            contact.server_url.clone(),
            contact.recipient_id.clone(),
            contact.delivery_token.clone(),
            serde_json::to_string(&wire).map_err(|e| e.to_string())?,
            maybe_msg,
        )
    };

    let send_result = transport::send_envelope_once(
        tor_client,
        send_server_url,
        send_to,
        send_delivery_token,
        ENVELOPE_TYPE_SEALED_SIGNAL.to_string(),
        wire_json,
        Some(message_id.clone()),
    ).await;

    if visible {
        let _store_guard = session.messaging_store_lock.lock().await;
        let mut store = load_store_with_keys(&app, &store_key, &legacy_store_key)?;
        let mut msg = maybe_msg.take().ok_or_else(|| "visible message missing local state".to_string())?;
        match send_result {
            Ok(ack) => {
                if let Some(stored) = store.messages.iter_mut().find(|m| m.id == message_id && m.mine) {
                    stored.status = if ack.queued { "relay_queued".to_string() } else { "relay_received".to_string() };
                    msg = stored.clone();
                } else {
                    msg.status = if ack.queued { "relay_queued".to_string() } else { "relay_received".to_string() };
                    store.messages.push(msg.clone());
                }
            }
            Err(_e) => {
                if let Some(stored) = store.messages.iter_mut().find(|m| m.id == message_id && m.mine) {
                    stored.status = "send_failed".to_string();
                    msg = stored.clone();
                } else {
                    msg.status = "send_failed".to_string();
                    store.messages.push(msg.clone());
                }
            }
        }
        save_store_with_key(&app, &store, &store_key)?;
        Ok(Some(msg))
    } else {
        send_result.map(|_| None)
    }
}

async fn send_route_control(
    app: AppHandle,
    session: &AppSessionState,
    transport_state: &transport::TransportState,
    tor_client: Arc<Mutex<Option<arti_client::TorClient<tor_rtcompat::PreferredRuntime>>>>,
    contact_id: String,
    kind: &str,
) -> Result<(), String> {
    let _ = send_signal_payload_internal(app, session, transport_state, tor_client, contact_id, kind, String::new(), false, true).await?;
    Ok(())
}

pub async fn send_text_message(
    app: AppHandle,
    session: &AppSessionState,
    transport_state: &transport::TransportState,
    tor_client: Arc<Mutex<Option<arti_client::TorClient<tor_rtcompat::PreferredRuntime>>>>,
    contact_id: String,
    text: String,
) -> Result<SendMessageResponse, String> {
    let message = send_signal_payload_internal(
        app,
        session,
        transport_state,
        tor_client,
        contact_id,
        "text",
        text,
        true,
        false,
    ).await?
    .ok_or_else(|| "message send did not produce a local message".to_string())?;
    Ok(SendMessageResponse { message })
}

pub async fn handle_incoming_envelope(
    app: AppHandle,
    session: &AppSessionState,
    runtime: &MessagingRuntimeState,
    transport_state: &transport::TransportState,
    tor_client: Arc<Mutex<Option<arti_client::TorClient<tor_rtcompat::PreferredRuntime>>>>,
    server_id: String,
    envelope: transport::StoredEnvelope,
) -> Result<(), String> {
    let (store_key, legacy_store_key) = store_keys(session).await?;
    if envelope.envelope_type != ENVELOPE_TYPE_SEALED_SIGNAL && envelope.envelope_type != ENVELOPE_TYPE_SIGNAL { return Ok(()); }

    let envelope_key = envelope.id.to_string();
    let already_seen = {
        let mut seen = runtime.seen_envelopes.lock().await;
        let now = now_ms();
        seen.retain(|_, ts| now.saturating_sub(*ts) <= SEEN_ENVELOPE_TTL_MS);
        if seen.len() > MAX_SEEN_ENVELOPES {
            let mut by_age: Vec<(String, u64)> = seen.iter().map(|(id, ts)| (id.clone(), *ts)).collect();
            by_age.sort_by_key(|(_, ts)| *ts);
            for (id, _) in by_age.into_iter().take(seen.len().saturating_sub(MAX_SEEN_ENVELOPES)) {
                seen.remove(&id);
            }
        }
        seen.contains_key(&envelope_key)
    };
    if already_seen {
        let _ = transport::ack_envelopes(transport_state, server_id.clone(), vec![envelope.id]).await;
        return Ok(());
    }
    let drop_poisoned_envelope = {
        let mut failed = runtime.failed_envelopes.lock().await;
        let now = now_ms();
        prune_failed_envelopes(&mut failed, now);
        failed.get(&envelope_key).map(|e| e.count).unwrap_or(0) >= MAX_FAILED_DECRYPTS_PER_ENVELOPE
    };
    if drop_poisoned_envelope {
        let _ = transport::ack_envelopes(transport_state, server_id.clone(), vec![envelope.id]).await;
        return Ok(());
    }

    let _store_guard = session.messaging_store_lock.lock().await;
    let mut blob = load_vault(&app)?;
    let material = signal_material(session).await?;
    let mut store = load_store_with_keys(&app, &store_key, &legacy_store_key)?;
    cleanup_expired_routes(&mut store);
    let local_route = match route_for_mailbox(&store, &envelope.to) {
        Some(route) => route,
        None => match store.local_profile.clone() {
            Some(profile) => legacy_route_from_profile(profile, server_id.clone(), DEFAULT_DEV_SERVER.to_string())?,
            None => return Err("incoming envelope was not addressed to a known local mailbox".to_string()),
        },
    };
    let trust_root_b64 = transport::get_server_trust_root(transport_state, server_id.clone())
        .await?
        .ok_or_else(|| "server trust root unavailable; reconnect to the relay before decrypting sealed-sender messages".to_string())?;
    pin_server_trust_root(&mut store, &local_route.server_id, &trust_root_b64)?;
    let wire: SealedSignalWireMessage = serde_json::from_str(&envelope.ciphertext).map_err(|e| format!("bad sealed Signal envelope: {e}"))?;
    if wire.v != 1 { return Err("unsupported sealed Signal envelope version".into()); }
    let raw_decoded = STANDARD_NO_PAD.decode(wire.sealed_sender_b64.as_bytes()).map_err(|_| "bad sealed sender ciphertext encoding".to_string())?;
    // Try to unpad; if the data was sent before padding was enabled, use as-is.
    let ciphertext = unpad_ciphertext(&raw_decoded).unwrap_or(raw_decoded);

    let decrypted_result = signal_protocol_engine::decrypt_sealed_sender_message(
        &blob,
        &material,
        &mut store,
        &local_route,
        &server_id,
        &trust_root_b64,
        &ciphertext,
    ).await;

    let decrypted = match decrypted_result {
        Ok(value) => value,
        Err(e) => {
            // Persist any defensive state changes made before the decrypt path returned,
            // such as trust-root pinning or identity_changed_blocked. Without this, a
            // malicious changed-key envelope could trigger a warning only in memory and
            // then disappear on restart.
            let _ = save_store_with_key(&app, &store, &store_key);
            let should_drop_poisoned_envelope = {
                let mut failed = runtime.failed_envelopes.lock().await;
                let now = now_ms();
                prune_failed_envelopes(&mut failed, now);
                let entry = failed.entry(envelope_key.clone()).or_insert(FailedEnvelopeEntry { count: 0, last_seen_ms: now });
                entry.count = entry.count.saturating_add(1);
                entry.last_seen_ms = now;
                entry.count >= MAX_FAILED_DECRYPTS_PER_ENVELOPE
            };
            if should_drop_poisoned_envelope {
                drop(store);
                drop(_store_guard);
                let _ = transport::ack_envelopes(transport_state, server_id.clone(), vec![envelope.id]).await;
                let mut failed = runtime.failed_envelopes.lock().await;
                failed.remove(&envelope_key);
                return Ok(());
            }
            return Err(e);
        }
    };

    if !decrypted.consumed_opk_ids.is_empty() {
        let mut guard = session.session.lock().await;
        let unlocked = guard.as_mut().ok_or_else(|| "identity is locked".to_string())?;
        remove_consumed_opks_and_replenish(&mut blob, &mut unlocked.secrets, &decrypted.consumed_opk_ids).map_err(|e| e.to_string())?;
        for id in &decrypted.consumed_opk_ids {
            if !store.used_opk_ids.contains(id) { store.used_opk_ids.push(*id); }
        }
        reseal_vault(&mut blob, &unlocked.key, &unlocked.secrets).map_err(|e| e.to_string())?;
        save_vault(&app, &blob)?;
    }

    let contact_id = decrypted.contact.id.clone();
    if store.messages.iter().any(|m| m.id == decrypted.message.message_id) {
        save_store_with_key(&app, &store, &store_key)?;
        drop(store);
        drop(_store_guard);
        let _ = transport::ack_envelopes(transport_state, server_id.clone(), vec![envelope.id]).await;
        runtime.seen_envelopes.lock().await.insert(envelope_key, now_ms());
        return Ok(());
    }

    let received_at = now_ms();
    let mut route_to_connect_after_save: Option<LocalRoute> = None;
    let mut token_allowlist_update_after_save: Option<(String, Vec<String>)> = None;
    let mut route_sync_contact_after_save: Option<String> = None;
    let mut route_sync_ack_contact_after_save: Option<String> = None;
    let acked_peer_delivery_token_epoch = decrypted.message.acked_peer_delivery_token_epoch;
    let msg = if decrypted.message.kind == "text" {
        let msg = StoredMessage {
            id: decrypted.message.message_id.clone(),
            contact_id: contact_id.clone(),
            mine: false,
            text: decrypted.message.body.clone(),
            timestamp: decrypted.message.sent_at_ms,
            received_at_ms: Some(received_at),
            status: "received".to_string(),
        };
        store.messages.push(msg.clone());
        Some(msg)
    } else {
        None
    };

    if let Some(acked_sender_mailbox) = decrypted.message.acked_peer_sender_mailbox_id.clone() {
        let routes_to_retire: Vec<String> = store.local_routes.iter()
            .filter(|route| route_is_retiring_invite(route))
            .filter_map(|route| {
                let replacement_id = route.replacement_route_id.clone()?;
                let replacement_mailbox_matches = store.local_routes.iter()
                    .find(|candidate| candidate.id == replacement_id)
                    .map(|candidate| candidate.mailbox_id == acked_sender_mailbox)
                    .unwrap_or(false);
                if replacement_mailbox_matches { Some(route.id.clone()) } else { None }
            })
            .collect();
        for route in store.local_routes.iter_mut() {
            if routes_to_retire.iter().any(|id| *id == route.id) {
                route.active = false;
                route.expires_at_ms = Some(received_at);
            }
        }
    }

    // Retire old local delivery tokens only after the peer proves, inside an
    // encrypted Signal payload, that it has learned the current token epoch.
    // This gives us reliable overlap without keeping invite tokens alive
    // forever. Expired fallback tokens are pruned as a safety net.
    if let Some(idx) = store.local_routes.iter().position(|r| r.id == local_route.id) {
        let mut route = store.local_routes[idx].clone();
        normalize_legacy_retired_tokens(&mut route);
        let mut changed = prune_expired_token_retirements(&mut route);
        let before = route.pending_token_retirements.len();
        if let Some(acked) = acked_peer_delivery_token_epoch {
            if acked >= route.delivery_token_epoch {
                route.pending_token_retirements.clear();
            }
        }
        if before != route.pending_token_retirements.len() { changed = true; }
        if changed {
            token_allowlist_update_after_save = Some((route_connection_id(&route), route_delivery_allowlist(&route)));
            store.local_routes[idx] = route;
        }
    }

    // If this was a one-off invite mailbox, do not let that public invite route
    // become the permanent route. Keep it only as a temporary fallback until
    // the peer acknowledges our fresh private route, then retire it.
    if let Some(idx) = store.local_routes.iter().position(|r| r.id == local_route.id) {
        if store.local_routes[idx].scope == "pending_invite" {
            let server_url = store.local_routes[idx].server_url.clone();
            let fresh_route = new_local_route(server_url, format!("contact:{contact_id}"), None)?;
            store.local_routes[idx].scope = format!("retiring_invite:{contact_id}");
            store.local_routes[idx].replacement_route_id = Some(fresh_route.id.clone());
            store.local_routes[idx].expires_at_ms = None;
            if let Some(contact) = store.contacts.iter_mut().find(|c| c.id == contact_id) {
                contact.local_route_id = Some(fresh_route.id.clone());
            }
            route_to_connect_after_save = Some(fresh_route.clone());
            route_sync_contact_after_save = Some(contact_id.clone());
            store.local_routes.push(fresh_route);
        } else if !route_is_sender_hold(&store.local_routes[idx], &contact_id) && !route_is_retiring_invite(&store.local_routes[idx]) {
            store.local_routes[idx].scope = format!("contact:{contact_id}");
            store.local_routes[idx].expires_at_ms = None;
        }
    }
    if decrypted.message.kind == "route_sync" {
        route_sync_ack_contact_after_save = Some(contact_id.clone());
    }

    for invite in &mut store.pending_invites {
        if invite.mailbox_id == local_route.mailbox_id { invite.expires_at_ms = received_at; }
    }
    cleanup_expired_routes(&mut store);

    save_store_with_key(&app, &store, &store_key)?;
    drop(store);
    drop(_store_guard);

    if let Some(route) = route_to_connect_after_save {
        let _ = transport::connect_server(
            app.clone(),
            transport_state,
            tor_client.clone(),
            route_connection_id(&route),
            route.server_url.clone(),
            route.mailbox_id.clone(),
            route.receive_auth_token.clone(),
            route.delivery_token.clone(),
        ).await;
    }
    if let Some((connection_id, allowlist)) = token_allowlist_update_after_save {
        let _ = transport::set_delivery_tokens_confirmed(transport_state, connection_id, allowlist).await;
    }
    let _ = transport::ack_envelopes(transport_state, server_id.clone(), vec![envelope.id]).await;
    runtime.seen_envelopes.lock().await.insert(envelope_key.clone(), now_ms());
    runtime.failed_envelopes.lock().await.remove(&envelope_key);
    if let Some(contact_id) = route_sync_contact_after_save {
        let _ = send_route_control(app.clone(), session, transport_state, tor_client.clone(), contact_id, "route_sync").await;
    }
    if let Some(contact_id) = route_sync_ack_contact_after_save {
        let _ = send_route_control(app.clone(), session, transport_state, tor_client.clone(), contact_id, "route_sync_ack").await;
    }
    if let Some(msg) = msg {
        let _ = app.emit("axeno-message", IncomingMessageEvent { contact_id, message: msg });
    }
    Ok(())
}


pub async fn mark_message_relay_received(app: AppHandle, session: &AppSessionState, message_id: String, queued: bool) -> Result<Option<StoredMessage>, String> {
    let _store_guard = session.messaging_store_lock.lock().await;
    let (store_key, legacy_store_key) = store_keys(session).await?;
    let mut store = load_store_with_keys(&app, &store_key, &legacy_store_key)?;
    let Some(msg) = store.messages.iter_mut().find(|m| m.id == message_id && m.mine) else { return Ok(None); };
    msg.status = if queued { "relay_queued".to_string() } else { "relay_received".to_string() };
    let out = msg.clone();
    save_store_with_key(&app, &store, &store_key)?;
    Ok(Some(out))
}

pub async fn mark_message_send_failed(app: AppHandle, session: &AppSessionState, message_id: String) -> Result<Option<StoredMessage>, String> {
    let _store_guard = session.messaging_store_lock.lock().await;
    let (store_key, legacy_store_key) = store_keys(session).await?;
    let mut store = load_store_with_keys(&app, &store_key, &legacy_store_key)?;
    let Some(msg) = store.messages.iter_mut().find(|m| m.id == message_id && m.mine) else { return Ok(None); };
    msg.status = "send_failed".to_string();
    let out = msg.clone();
    save_store_with_key(&app, &store, &store_key)?;
    Ok(Some(out))
}

pub async fn mark_contact_verified(app: AppHandle, session: &AppSessionState, contact_id: String, verified: bool) -> Result<StoredContact, String> {
    let _store_guard = session.messaging_store_lock.lock().await;
    let (store_key, legacy_store_key) = store_keys(session).await?;
    let mut store = load_store_with_keys(&app, &store_key, &legacy_store_key)?;
    let contact = store.contacts.iter_mut().find(|c| c.id == contact_id).ok_or_else(|| "contact not found".to_string())?;
    if contact.trust_state == "identity_changed_blocked" && verified {
        return Err("contact identity changed; re-add using a fresh code before verifying".into());
    }
    if verified && (contact.identity_public_b64.trim().is_empty() || contact.safety_number.trim().is_empty()) {
        return Err("contact does not have enough identity material to verify yet".into());
    }
    contact.trust_state = if verified { "verified" } else { "unverified" }.to_string();
    contact.verified_at_ms = if verified { Some(now_ms()) } else { None };
    let out = contact.clone();
    save_store_with_key(&app, &store, &store_key)?;
    Ok(out)
}

pub async fn verification_code_for_contact(app: AppHandle, session: &AppSessionState, contact_id: String) -> Result<VerificationCodeResponse, String> {
    let _store_guard = session.messaging_store_lock.lock().await;
    let (store_key, legacy_store_key) = store_keys(session).await?;
    let blob = load_vault(&app)?;
    let material = signal_material(session).await?;
    let store = load_store_with_keys(&app, &store_key, &legacy_store_key)?;
    let contact = store.contacts.iter().find(|c| c.id == contact_id).ok_or_else(|| "contact not found".to_string())?;
    if contact.identity_public_b64.trim().is_empty() || contact.safety_number.trim().is_empty() {
        return Err("contact identity is not established yet; exchange at least one valid Signal message first".into());
    }
    let identity_public = STANDARD_NO_PAD.encode(&blob.public_key);
    let created_at = now_ms();
    let payload = VerificationPayload {
        v: 1,
        kind: "axeno_verify_v1".to_string(),
        local_identity_public_b64: identity_public,
        remote_identity_public_b64: contact.identity_public_b64.clone(),
        safety_number: contact.safety_number.clone(),
        created_at_ms: created_at,
    };
    let signed = SignedVerificationPayload {
        signature_b64: sign_verification_payload(&material, &payload)?,
        payload,
    };
    let code = verification_payload_to_code(&signed)?;
    Ok(VerificationCodeResponse { code, safety_number: contact.safety_number.clone(), created_at })
}

pub async fn verify_contact_with_code(app: AppHandle, session: &AppSessionState, contact_id: String, code: String) -> Result<StoredContact, String> {
    let trimmed = code.trim().to_string();
    if trimmed.is_empty() { return Err("verification code is empty".into()); }
    let signed = code_to_verification_payload(&trimmed)?;
    let payload = signed.payload;
    if payload.v != 1 || payload.kind != "axeno_verify_v1" {
        return Err("unsupported verification code".into());
    }
    if payload.created_at_ms.saturating_add(VERIFY_CODE_TTL_MS) < now_ms() {
        return Err("verification code has expired; ask them to generate a fresh one".into());
    }
    verify_verification_payload_signature(&payload, &signed.signature_b64)?;

    let _store_guard = session.messaging_store_lock.lock().await;
    let (store_key, legacy_store_key) = store_keys(session).await?;
    let blob = load_vault(&app)?;
    let mut store = load_store_with_keys(&app, &store_key, &legacy_store_key)?;
    let contact = store.contacts.iter_mut().find(|c| c.id == contact_id).ok_or_else(|| "contact not found".to_string())?;
    if contact.trust_state == "identity_changed_blocked" {
        return Err("contact identity changed; re-add using a fresh code before verifying".into());
    }
    if contact.identity_public_b64.trim().is_empty() || contact.safety_number.trim().is_empty() {
        return Err("contact identity is not established yet; exchange at least one valid Signal message first".into());
    }
    let my_identity_b64 = STANDARD_NO_PAD.encode(&blob.public_key);
    if payload.local_identity_public_b64 != contact.identity_public_b64 {
        return Err("verification code was not generated by this contact identity".into());
    }
    if payload.remote_identity_public_b64 != my_identity_b64 {
        return Err("verification code was generated for a different recipient identity".into());
    }
    if payload.safety_number != contact.safety_number {
        return Err("verification code safety number does not match this conversation".into());
    }
    contact.trust_state = "verified".to_string();
    contact.verified_at_ms = Some(now_ms());
    let out = contact.clone();
    save_store_with_key(&app, &store, &store_key)?;
    Ok(out)
}

pub async fn mark_contact_read(app: AppHandle, session: &AppSessionState, contact_id: String) -> Result<StoredContact, String> {
    let _store_guard = session.messaging_store_lock.lock().await;
    let (store_key, legacy_store_key) = store_keys(session).await?;
    let mut store = load_store_with_keys(&app, &store_key, &legacy_store_key)?;
    let contact = store.contacts.iter_mut().find(|c| c.id == contact_id).ok_or_else(|| "contact not found".to_string())?;
    contact.last_read_at = Some(now_ms());
    let out = contact.clone();
    save_store_with_key(&app, &store, &store_key)?;
    Ok(out)
}

pub async fn migrate_contact_with_code(
    app: AppHandle,
    session: &AppSessionState,
    transport_state: &transport::TransportState,
    tor_client: Arc<Mutex<Option<arti_client::TorClient<tor_rtcompat::PreferredRuntime>>>>,
    contact_id: String,
    code: String,
) -> Result<StoredContact, String> {
    let trimmed = code.trim().to_string();
    if trimmed.is_empty() { return Err("migration code is empty".into()); }

    let (store_key, legacy_store_key) = store_keys(session).await?;
    let blob = load_vault(&app)?;
    let payload = resolve_invite_payload(&trimmed, tor_client.clone()).await?;
    let incoming = contact_from_payload(payload, &blob.public_key)?;

    let _store_guard = session.messaging_store_lock.lock().await;
    let mut store = load_store_with_keys(&app, &store_key, &legacy_store_key)?;
    cleanup_expired_routes(&mut store);

    let pos = store.contacts.iter().position(|c| c.id == contact_id)
        .ok_or_else(|| "contact not found".to_string())?;
    let previous = store.contacts[pos].clone();
    if previous.identity_public_b64.trim().is_empty() {
        return Err("cannot migrate a contact without a pinned identity key".into());
    }

    // A relay migration is only safe if the fresh code belongs to the same
    // Signal identity. A different identity is a new contact or an attack, not
    // a server move.
    if previous.identity_public_b64 != incoming.identity_public_b64 {
        store.contacts[pos].trust_state = "identity_changed_blocked".to_string();
        store.contacts[pos].verified_at_ms = None;
        save_store_with_key(&app, &store, &store_key)?;
        return Err("fresh code has a different identity key; refusing relay migration".into());
    }
    if previous.device_id != incoming.device_id {
        return Err("fresh code uses a different device id; create a new contact or verify out-of-band first".into());
    }

    let old_session_key = format!("{}:{}", previous.recipient_id, previous.device_id);
    store.signal_sessions.remove(&old_session_key);

    let route = rotate_local_route_for_contact(&mut store, &contact_id, &incoming.server_url)?;

    let contact = &mut store.contacts[pos];
    contact.display_name = incoming.display_name.clone().or_else(|| contact.display_name.clone());
    contact.recipient_id = incoming.recipient_id.clone();
    contact.server_url = incoming.server_url.clone();
    contact.server_id = incoming.server_id.clone();
    contact.registration_id = incoming.registration_id;
    contact.device_id = incoming.device_id;
    contact.signed_prekey_id = incoming.signed_prekey_id;
    contact.signed_prekey_public_b64 = incoming.signed_prekey_public_b64.clone();
    contact.signed_prekey_signature_b64 = incoming.signed_prekey_signature_b64.clone();
    contact.opk_id = incoming.opk_id;
    contact.opk_public_b64 = incoming.opk_public_b64.clone();
    contact.kyber_prekey_id = incoming.kyber_prekey_id;
    contact.kyber_prekey_public_b64 = incoming.kyber_prekey_public_b64.clone();
    contact.kyber_prekey_signature_b64 = incoming.kyber_prekey_signature_b64.clone();
    contact.delivery_token = incoming.delivery_token.clone();
    contact.safety_number = incoming.safety_number.clone();
    contact.local_route_id = Some(route.id.clone());
    contact.trust_state = if previous.trust_state == "verified" { "verified".to_string() } else { "unverified".to_string() };
    contact.verified_at_ms = previous.verified_at_ms;
    let out = contact.clone();

    let route_to_connect = route.clone();
    save_store_with_key(&app, &store, &store_key)?;
    drop(store);
    drop(_store_guard);

    let _ = transport::connect_server(
        app.clone(),
        transport_state,
        tor_client.clone(),
        route_connection_id(&route_to_connect),
        route_to_connect.server_url.clone(),
        route_to_connect.mailbox_id.clone(),
        route_to_connect.receive_auth_token.clone(),
        route_to_connect.delivery_token.clone(),
    ).await;
    Ok(out)
}

pub async fn update_contact_server(_app: AppHandle, _session: &AppSessionState, _contact_id: String, _server_url: String) -> Result<StoredContact, String> {
    Err("changing a contact relay without a fresh connection code is unsafe; use relay migration with a fresh code".into())
}

mod signal_protocol_engine {
    //! Real Signal Protocol integration.
    //!
    //! This module wires Axeno's encrypted local message store into libsignal-protocol's
    //! X3DH/PreKey session setup and Double Ratchet message encryption. The relay still only
    //! sees opaque serialized libsignal ciphertext messages.
    //!
    //! Current scope: one device per Axeno identity, direct 1:1 text messaging only.

    use super::*;
    use libsignal_protocol::{
        kem, message_decrypt_prekey, message_decrypt_signal, message_encrypt, process_prekey_bundle,
        sealed_sender_decrypt_to_usmc, sealed_sender_encrypt_from_usmc,
        CiphertextMessageType, ContentHint, GenericSignedPreKey, IdentityKey,
        IdentityKeyPair, IdentityKeyStore, InMemSignalProtocolStore, KeyPair, KyberPreKeyId,
        KyberPreKeyRecord, KyberPreKeyStore, PreKeyBundle, PreKeyId, PreKeyRecord,
        PreKeySignalMessage, PreKeyStore, PrivateKey, ProtocolAddress, PublicKey,
        SenderCertificate, SessionRecord, SessionStore, SignalMessage, SignedPreKeyId, SignedPreKeyRecord,
        SignedPreKeyStore, Timestamp, UnidentifiedSenderMessageContent,
    };
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    pub struct EncryptedForRelay { pub sealed_sender: Vec<u8> }

    const KYBER_PREKEY_ID: u32 = 1;

    fn fresh_signal_rng() -> Result<ChaCha20Rng, String> {
        let mut seed = [0u8; 32];
        super::fill_random(&mut seed)?;
        Ok(ChaCha20Rng::from_seed(seed))
    }

    fn local_address(address_name: &str) -> Result<ProtocolAddress, String> {
        let device_id = DEVICE_ID.try_into().map_err(|_| "invalid local device id".to_string())?;
        Ok(ProtocolAddress::new(address_name.to_string(), device_id))
    }

    fn signal_err<E: std::fmt::Display>(context: &str, err: E) -> String {
        format!("{context}: {err}")
    }

    fn remote_address(contact: &StoredContact) -> Result<ProtocolAddress, String> {
        let device_id = contact.device_id.try_into().map_err(|_| "invalid remote device id".to_string())?;
        Ok(ProtocolAddress::new(contact.recipient_id.clone(), device_id))
    }

    fn local_identity(me: &EncryptedIdentity, material: &PrivateSignalMaterial) -> Result<IdentityKeyPair, String> {
        let public = PublicKey::deserialize(&me.public_key).map_err(|e| signal_err("local identity public key is invalid", e))?;
        let private = PrivateKey::deserialize(&material.identity_priv).map_err(|e| signal_err("local identity private key is invalid", e))?;
        Ok(IdentityKeyPair::new(IdentityKey::from(public), private))
    }

    fn route_sealed_sender_identity(local_route: &LocalRoute) -> Result<IdentityKeyPair, String> {
        let public_raw = decode_b64(&local_route.sealed_sender_cert_public_b64, "route sealed-sender certificate public key")?;
        let private_raw = decode_b64(&local_route.sealed_sender_cert_private_b64, "route sealed-sender certificate private key")?;
        let public = PublicKey::deserialize(&public_raw)
            .map_err(|e| signal_err("route sealed-sender certificate public key is invalid", e))?;
        let private = PrivateKey::deserialize(&private_raw)
            .map_err(|e| signal_err("route sealed-sender certificate private key is invalid", e))?;
        Ok(IdentityKeyPair::new(IdentityKey::from(public), private))
    }

    fn key_pair(public: &[u8], private: &[u8], label: &str) -> Result<KeyPair, String> {
        KeyPair::from_public_and_private(public, private).map_err(|e| signal_err(label, e))
    }

    fn decode_b64(s: &str, label: &str) -> Result<Vec<u8>, String> {
        STANDARD_NO_PAD.decode(s.as_bytes()).map_err(|_| format!("bad base64 for {label}"))
    }

    fn prekey_bundle_from_contact(contact: &StoredContact) -> Result<PreKeyBundle, String> {
        let device_id = contact.device_id.try_into().map_err(|_| "invalid contact device id".to_string())?;
        let identity_pub = PublicKey::deserialize(&decode_b64(&contact.identity_public_b64, "identity public key")?)
            .map_err(|e| signal_err("bad contact identity key", e))?;
        let signed_pub = PublicKey::deserialize(&decode_b64(&contact.signed_prekey_public_b64, "signed prekey public key")?)
            .map_err(|e| signal_err("bad contact signed prekey", e))?;
        let signed_sig = decode_b64(&contact.signed_prekey_signature_b64, "signed prekey signature")?;
        let opk = match (contact.opk_id, contact.opk_public_b64.as_ref()) {
            (Some(id), Some(public_b64)) => {
                let pk = PublicKey::deserialize(&decode_b64(public_b64, "one-time prekey public key")?)
                    .map_err(|e| signal_err("bad contact one-time prekey", e))?;
                Some((PreKeyId::from(id), pk))
            }
            _ => None,
        };

        let kyber_id = contact.kyber_prekey_id.ok_or_else(|| {
            "contact connection code is missing the required PQXDH Kyber prekey; generate/import a fresh code".to_string()
        })?;
        let kyber_public_b64 = contact.kyber_prekey_public_b64.as_ref().ok_or_else(|| {
            "contact connection code is missing the required PQXDH Kyber public key".to_string()
        })?;
        let kyber_sig_b64 = contact.kyber_prekey_signature_b64.as_ref().ok_or_else(|| {
            "contact connection code is missing the required PQXDH Kyber signature".to_string()
        })?;
        let kyber_public = kem::PublicKey::deserialize(&decode_b64(kyber_public_b64, "Kyber prekey public key")?)
            .map_err(|e| signal_err("bad contact Kyber prekey", e))?;
        let kyber_sig = decode_b64(kyber_sig_b64, "Kyber prekey signature")?;

        PreKeyBundle::new(
            contact.registration_id,
            device_id,
            opk,
            SignedPreKeyId::from(contact.signed_prekey_id),
            signed_pub,
            signed_sig,
            KyberPreKeyId::from(kyber_id),
            kyber_public,
            kyber_sig,
            IdentityKey::from(identity_pub),
        ).map_err(|e| signal_err("could not build remote PreKeyBundle", e))
    }

    pub fn ensure_local_kyber_prekey(
        _me: &EncryptedIdentity,
        material: &PrivateSignalMaterial,
        axeno_store: &mut MessagingStore,
    ) -> Result<KyberPreKeyBlob, String> {
        let now = now_ms();
        if let Some(existing) = axeno_store.local_kyber_prekey.clone() {
            if now.saturating_sub(existing.created_at_ms) < KYBER_PREKEY_ROTATION_MS {
                return Ok(existing);
            }
            axeno_store.previous_kyber_prekeys.push(existing);
        }
        axeno_store.previous_kyber_prekeys.retain(|k| now.saturating_sub(k.created_at_ms) <= KYBER_PREKEY_ROTATION_MS.saturating_mul(2));

        let signing_key = PrivateKey::deserialize(&material.identity_priv)
            .map_err(|e| signal_err("local identity private key is invalid", e))?;
        let next_id = axeno_store.previous_kyber_prekeys
            .iter()
            .map(|k| k.id)
            .chain(axeno_store.local_kyber_prekey.as_ref().map(|k| k.id))
            .max()
            .unwrap_or(KYBER_PREKEY_ID.saturating_sub(1))
            .saturating_add(1);
        let record = KyberPreKeyRecord::generate(
            kem::KeyType::Kyber1024,
            KyberPreKeyId::from(next_id),
            &signing_key,
        ).map_err(|e| signal_err("could not generate local Kyber prekey", e))?;

        let public = record.public_key()
            .map_err(|e| signal_err("could not read generated Kyber public key", e))?;
        let signature = record.signature()
            .map_err(|e| signal_err("could not read generated Kyber signature", e))?;
        let serialized = record.serialize()
            .map_err(|e| signal_err("could not serialize generated Kyber prekey", e))?;

        let blob = KyberPreKeyBlob {
            id: next_id,
            public_b64: STANDARD_NO_PAD.encode(public.serialize()),
            signature_b64: STANDARD_NO_PAD.encode(signature),
            record_b64: STANDARD_NO_PAD.encode(serialized),
            created_at_ms: now,
        };
        axeno_store.local_kyber_prekey = Some(blob.clone());
        Ok(blob)
    }

    async fn protocol_store_for(
        me: &EncryptedIdentity,
        material: &PrivateSignalMaterial,
        axeno_store: &MessagingStore,
    ) -> Result<InMemSignalProtocolStore, String> {
        let identity = local_identity(me, material)?;
        let mut protocol_store = InMemSignalProtocolStore::new(identity, me.registration_id as u32)
            .map_err(|e| signal_err("could not create libsignal protocol store", e))?;

        // Signed prekey private material from the encrypted vault.
        let spk_pair = key_pair(&me.signed_prekey_public, &material.spk_priv, "bad local signed prekey")?;
        let spk_record = SignedPreKeyRecord::new(
            SignedPreKeyId::from(me.signed_prekey_id),
            Timestamp::from_epoch_millis(now_ms()),
            &spk_pair,
            &me.signed_prekey_signature,
        );
        protocol_store.save_signed_pre_key(SignedPreKeyId::from(me.signed_prekey_id), &spk_record)
            .await
            .map_err(|e| signal_err("could not save signed prekey into libsignal store", e))?;

        for previous in &me.previous_signed_prekeys {
            if let Some(secret) = material.previous_spks_secret.iter().find(|s| s.id == previous.id) {
                let kp = key_pair(&previous.public_key, &secret.private_key, "bad previous local signed prekey")?;
                let record = SignedPreKeyRecord::new(
                    SignedPreKeyId::from(previous.id),
                    Timestamp::from_epoch_millis(previous.created_at_ms),
                    &kp,
                    &previous.signature,
                );
                protocol_store.save_signed_pre_key(SignedPreKeyId::from(previous.id), &record)
                    .await
                    .map_err(|e| signal_err("could not save previous signed prekey into libsignal store", e))?;
            }
        }

        // One-time prekeys from the encrypted vault.
        for public in &me.opks_public {
            if let Some(secret) = material.opks_secret.iter().find(|s| s.id == public.id) {
                let kp = key_pair(&public.public_key, &secret.private_key, "bad local one-time prekey")?;
                let record = PreKeyRecord::new(PreKeyId::from(public.id), &kp);
                protocol_store.save_pre_key(PreKeyId::from(public.id), &record)
                    .await
                    .map_err(|e| signal_err("could not save one-time prekey into libsignal store", e))?;
            }
        }

        // PQXDH Kyber prekey from the encrypted local message store.
        for kyber in axeno_store.previous_kyber_prekeys.iter().chain(axeno_store.local_kyber_prekey.as_ref()) {
            let raw = decode_b64(&kyber.record_b64, "local Kyber prekey record")?;
            let record = KyberPreKeyRecord::deserialize(&raw)
                .map_err(|e| signal_err("bad local Kyber prekey record", e))?;
            protocol_store.save_kyber_pre_key(KyberPreKeyId::from(kyber.id), &record)
                .await
                .map_err(|e| signal_err("could not save Kyber prekey into libsignal store", e))?;
        }

        // Restore durable ratchet session records.
        for blob in axeno_store.signal_sessions.values() {
            let device_id = blob.device_id.try_into().map_err(|_| "invalid saved session device id".to_string())?;
            let address = ProtocolAddress::new(blob.address_name.clone(), device_id);
            let raw = decode_b64(&blob.session_b64, "stored Signal session")?;
            let record = SessionRecord::deserialize(&raw).map_err(|e| signal_err("bad stored Signal session", e))?;
            protocol_store.store_session(&address, &record)
                .await
                .map_err(|e| signal_err("could not restore Signal session", e))?;
        }

        Ok(protocol_store)
    }

    async fn sealed_sender_outer_store_for(
        local_route: &LocalRoute,
        contact: &StoredContact,
        registration_id: u32,
    ) -> Result<InMemSignalProtocolStore, String> {
        let identity = route_sealed_sender_identity(local_route)?;
        let mut outer_store = InMemSignalProtocolStore::new(identity, registration_id)
            .map_err(|e| signal_err("could not create route sealed-sender identity store", e))?;

        // sealed_sender_encrypt_from_usmc needs the recipient's identity key in
        // the store because the outer sealed-sender KEM derives keys from the
        // recipient identity. Keep this separate from the inner Signal ratchet
        // store so the relay-certified sender key is the route pseudonym, not
        // the stable Axeno Signal identity.
        let remote_identity = PublicKey::deserialize(&decode_b64(&contact.identity_public_b64, "contact identity public key")?)
            .map_err(|e| signal_err("bad contact identity key", e))?;
        let remote = remote_address(contact)?;
        let _ = outer_store.identity_store
            .save_identity(&remote, &IdentityKey::from(remote_identity))
            .await
            .map_err(|e| signal_err("could not seed route sealed-sender identity store", e))?;
        Ok(outer_store)
    }

    async fn persist_session(
        protocol_store: &InMemSignalProtocolStore,
        axeno_store: &mut MessagingStore,
        contact: &StoredContact,
    ) -> Result<(), String> {
        let address = remote_address(contact)?;
        if let Some(record) = protocol_store.load_session(&address).await.map_err(|e| signal_err("could not load libsignal session", e))? {
            let raw = record.serialize().map_err(|e| signal_err("could not serialize Signal session", e))?;
            let key = format!("{}:{}", contact.recipient_id, contact.device_id);
            let now = now_ms();
            let created = axeno_store.signal_sessions.get(&key).map(|s| s.created_at_ms).unwrap_or(now);
            axeno_store.signal_sessions.insert(key, SignalSessionBlob {
                address_name: contact.recipient_id.clone(),
                device_id: contact.device_id,
                session_b64: STANDARD_NO_PAD.encode(raw),
                remote_identity_b64: contact.identity_public_b64.clone(),
                created_at_ms: created,
                updated_at_ms: now,
            });
        }
        Ok(())
    }

    fn ciphertext_type_name(message_type: CiphertextMessageType) -> Result<&'static str, String> {
        match message_type {
            CiphertextMessageType::PreKey => Ok("prekey_signal"),
            CiphertextMessageType::Whisper => Ok("signal"),
            CiphertextMessageType::SenderKey => Err("group SenderKey messages are not enabled in the text MVP".into()),
            CiphertextMessageType::Plaintext => Err("plaintext libsignal messages are not allowed".into()),
        }
    }

    pub async fn encrypt_for_contact(
        me: &EncryptedIdentity,
        material: &PrivateSignalMaterial,
        contact: &StoredContact,
        local_route: &LocalRoute,
        return_route: &LocalRoute,
        axeno_store: &mut MessagingStore,
        kind: &str,
        plaintext: &str,
        message_id: &str,
        sent_at_ms: u64,
        sender_certificate: &transport::SenderCertificateResponse,
        force_prekey: bool,
        acked_peer_sender_mailbox_id: Option<String>,
    ) -> Result<EncryptedForRelay, String> {
        let local_kyber = ensure_local_kyber_prekey(me, material, axeno_store)?;
        // A fresh route should start a clean PreKey session when we actually
        // have the peer's reusable prekey bundle from a connection code. When
        // the peer was learned only from an inbound PreKey message, we may know
        // their identity and return route but not their signed/kyber prekeys. In
        // that case, keep the existing Signal session instead of breaking route
        // sync with a "no usable prekey bundle" failure.
        if force_prekey && contact_has_reusable_prekey_material(contact) {
            let session_key = format!("{}:{}", contact.recipient_id, contact.device_id);
            axeno_store.signal_sessions.remove(&session_key);
        }
        let mut protocol_store = protocol_store_for(me, material, axeno_store).await?;
        let remote = remote_address(contact)?;
        let local = local_address(&local_route.mailbox_id)?;

        let has_existing_session = protocol_store.session_store
            .load_session(&remote)
            .await
            .map_err(|e| signal_err("could not check Signal session", e))?
            .is_some();

        if !has_existing_session {
            if contact.identity_public_b64.is_empty() || contact.signed_prekey_public_b64.is_empty() {
                return Err("contact does not have a usable Signal prekey bundle yet, and no established session exists; exchange connection codes first".into());
            }
            let bundle = prekey_bundle_from_contact(contact)?;
            let mut rng = fresh_signal_rng()?;
            process_prekey_bundle(
                &remote,
                &local,
                &mut protocol_store.session_store,
                &mut protocol_store.identity_store,
                &bundle,
                SystemTime::now(),
                &mut rng,
            )
                .await
                .map_err(|e| signal_err("Signal PreKeyBundle processing failed", e))?;
            if let Some(stored) = axeno_store.contacts.iter_mut().find(|c| c.id == contact.id) {
                // Do not reuse a one-time prekey from an imported connection code
                // if a later route migration forces a fresh prekey session.
                stored.opk_id = None;
                stored.opk_public_b64 = None;
            }
        }

        let local_identity_public_b64 = STANDARD_NO_PAD.encode(&me.public_key);
        let plaintext_payload = encode_signal_plaintext(
            kind,
            plaintext,
            &material.display_name,
            message_id,
            sent_at_ms,
            local_route,
            return_route,
            &local_identity_public_b64,
            me.registration_id as u32,
            me.signed_prekey_id,
            STANDARD_NO_PAD.encode(&me.signed_prekey_public),
            STANDARD_NO_PAD.encode(&me.signed_prekey_signature),
            local_kyber.id,
            local_kyber.public_b64.clone(),
            local_kyber.signature_b64.clone(),
            contact.delivery_token_epoch,
            acked_peer_sender_mailbox_id,
        )?;
        let mut rng = fresh_signal_rng()?;
        let cipher = message_encrypt(
            plaintext_payload.as_slice(),
            &remote,
            &local,
            &mut protocol_store.session_store,
            &mut protocol_store.identity_store,
            SystemTime::now(),
            &mut rng,
        )
            .await
            .map_err(|e| signal_err("Signal message encryption failed", e))?;
        persist_session(&protocol_store, axeno_store, contact).await?;

        let sender_cert_raw = decode_b64(&sender_certificate.certificate_b64, "sender certificate")?;
        let sender_cert = SenderCertificate::deserialize(&sender_cert_raw)
            .map_err(|e| signal_err("bad sender certificate from relay", e))?;
        let usmc = UnidentifiedSenderMessageContent::new(
            cipher.message_type(),
            sender_cert,
            cipher.serialize().to_vec(),
            ContentHint::Default,
            None,
        ).map_err(|e| signal_err("could not create libsignal sealed-sender content", e))?;
        let outer_store = sealed_sender_outer_store_for(local_route, contact, me.registration_id as u32).await?;
        let mut rng = fresh_signal_rng()?;
        let sealed = sealed_sender_encrypt_from_usmc(
            &remote,
            &usmc,
            &outer_store.identity_store,
            &mut rng,
        )
            .await
            .map_err(|e| signal_err("libsignal Sealed Sender encryption failed", e))?;
        Ok(EncryptedForRelay { sealed_sender: sealed })
    }

    pub struct DecryptedEnvelope {
        pub contact: StoredContact,
        pub message: DecryptedSignalText,
        pub consumed_opk_ids: Vec<u32>,
    }

    pub async fn decrypt_sealed_sender_message(
        me: &EncryptedIdentity,
        material: &PrivateSignalMaterial,
        axeno_store: &mut MessagingStore,
        local_route: &LocalRoute,
        _server_id: &str,
        trust_root_b64: &str,
        sealed_sender: &[u8],
    ) -> Result<DecryptedEnvelope, String> {
        ensure_local_kyber_prekey(me, material, axeno_store)?;
        let mut protocol_store = protocol_store_for(me, material, axeno_store).await?;
        let mut consumed_opk_ids: Vec<u32> = Vec::new();
        let local = local_address(&local_route.mailbox_id)?;

        let trust_root_raw = decode_b64(trust_root_b64, "server trust root")?;
        let trust_root = PublicKey::deserialize(&trust_root_raw).map_err(|e| signal_err("bad server trust root", e))?;
        let usmc = sealed_sender_decrypt_to_usmc(sealed_sender, &protocol_store.identity_store)
            .await
            .map_err(|e| signal_err("libsignal Sealed Sender envelope decryption failed", e))?;
        let sender_cert = usmc.sender().map_err(|e| signal_err("sealed sender certificate missing", e))?;
        let cert_ok = sender_cert
            .validate(&trust_root, Timestamp::from_epoch_millis(now_ms()))
            .map_err(|e| signal_err("sender certificate validation failed", e))?;
        if !cert_ok { return Err("sender certificate was not trusted by this server root".into()); }

        let cert_sender_uuid = sender_cert.sender_uuid().map_err(|e| signal_err("sender certificate has no sender uuid", e))?.to_string();
        let cert_sender_device_raw = sender_cert.sender_device_id().map_err(|e| signal_err("sender certificate has no device id", e))?;
        let cert_sender_device: u32 = cert_sender_device_raw.into();
        let _route_cert_key = sender_cert.key().map_err(|e| signal_err("sender certificate has no route certificate key", e))?;

        // Privacy boundary: Axeno sender certificates are bound to the sender's
        // per-contact route/mailbox certificate key, not to the sender's long-term
        // Signal identity key. The relay may therefore certify that a mailbox is
        // allowed to send without learning the stable identity. The real Signal
        // identity is learned only after decrypting the inner Signal message.
        let mut contact = if let Some(existing) = axeno_store.contacts.iter().find(|c| c.recipient_id == cert_sender_uuid).cloned() {
            existing
        } else {
            StoredContact {
                id: cert_sender_uuid.clone(),
                display_name: None,
                recipient_id: cert_sender_uuid.clone(),
                server_url: String::new(),
                server_id: local_route.server_id.clone(),
                identity_public_b64: String::new(),
                registration_id: 0,
                device_id: cert_sender_device,
                signed_prekey_id: 0,
                signed_prekey_public_b64: String::new(),
                signed_prekey_signature_b64: String::new(),
                opk_id: None,
                opk_public_b64: None,
                kyber_prekey_id: None,
                kyber_prekey_public_b64: None,
                kyber_prekey_signature_b64: None,
                delivery_token: String::new(),
                delivery_token_epoch: 1,
                safety_number: String::new(),
                trust_state: "unverified".to_string(),
                verified_at_ms: None,
                local_route_id: Some(local_route.id.clone()),
                peer_sender_mailbox_id: Some(cert_sender_uuid.clone()),
                created_at_ms: now_ms(),
                last_read_at: None,
            }
        };

        contact.device_id = cert_sender_device;
        contact.server_id = local_route.server_id.clone();

        let remote = remote_address(&contact)?;
        let message_type = usmc.msg_type().map_err(|e| signal_err("sealed sender content has no message type", e))?;
        let inner = usmc.contents().map_err(|e| signal_err("sealed sender content has no inner ciphertext", e))?;
        let plaintext = match ciphertext_type_name(message_type)? {
            "prekey_signal" => {
                let prekey_msg = PreKeySignalMessage::try_from(inner.as_ref())
                    .map_err(|e| signal_err("bad PreKeySignalMessage", e))?;
                let consumed_opk_id = prekey_msg.pre_key_id().map(u32::from);
                let identity_b64 = STANDARD_NO_PAD.encode(prekey_msg.identity_key().serialize());
                if contact.identity_public_b64.is_empty() {
                    contact.identity_public_b64 = identity_b64.clone();
                    contact.safety_number = pairwise_safety_number(&me.public_key, &prekey_msg.identity_key().serialize());
                } else if contact.identity_public_b64 != identity_b64 {
                    if let Some(c) = axeno_store.contacts.iter_mut().find(|c| c.recipient_id == cert_sender_uuid) {
                        c.trust_state = "identity_changed_blocked".to_string();
                        c.verified_at_ms = None;
                    }
                    return Err("Signal prekey identity did not match stored contact identity".into());
                }
                let mut rng = fresh_signal_rng()?;
                let decrypted = message_decrypt_prekey(
                    &prekey_msg,
                    &remote,
                    &local,
                    &mut protocol_store.session_store,
                    &mut protocol_store.identity_store,
                    &mut protocol_store.pre_key_store,
                    &protocol_store.signed_pre_key_store,
                    &mut protocol_store.kyber_pre_key_store,
                    &mut rng,
                )
                    .await
                    .map_err(|e| signal_err("Signal PreKey message decryption failed", e))?;
                if let Some(id) = consumed_opk_id { consumed_opk_ids.push(id); }
                decrypted
            }
            "signal" => {
                if contact.identity_public_b64.is_empty() {
                    return Err("received a normal Signal message from an unknown sealed-sender route; exchange a prekey message first".into());
                }
                let sig_msg = SignalMessage::try_from(inner.as_ref())
                    .map_err(|e| signal_err("bad SignalMessage", e))?;
                let mut rng = fresh_signal_rng()?;
                message_decrypt_signal(
                    &sig_msg,
                    &remote,
                    &local,
                    &mut protocol_store.session_store,
                    &mut protocol_store.identity_store,
                    &mut rng,
                )
                    .await
                    .map_err(|e| signal_err("Signal message decryption failed", e))?
            }
            other => return Err(format!("unsupported Signal ciphertext type: {other}")),
        };

        let decoded = decode_signal_plaintext(plaintext)?;
        if let Some(name) = decoded.sender_display_name.clone() { contact.display_name = Some(name); }
        contact.peer_sender_mailbox_id = Some(cert_sender_uuid.clone());
        if let Some(mailbox) = decoded.sender_mailbox_id.clone() {
            if mailbox != cert_sender_uuid {
                return Err("encrypted sender profile did not match sealed sender certificate".into());
            }
        }

        // Always learn the sender-certified route first. This route is the one
        // whose Signal session just decrypted successfully, so it is the safest
        // immediate reply path for contacts discovered by inbound messages. The
        // previous route-migration build skipped this whenever a dedicated
        // return route was present, leaving inbound-created contacts with an
        // empty server_url and causing replies to fail with "server URL must
        // start with ws:// or wss://".
        if let Some(token) = decoded.sender_delivery_token.clone() {
            let epoch = decoded.sender_delivery_token_epoch.unwrap_or(contact.delivery_token_epoch.max(1));
            if epoch >= contact.delivery_token_epoch || contact.delivery_token.is_empty() {
                contact.delivery_token = token;
                contact.delivery_token_epoch = epoch.max(1);
            }
        }
        if let Some(url) = decoded.sender_server_url.clone() {
            contact.server_url = normalize_server_url(Some(url));
            contact.server_id = server_id_for_url(&contact.server_url);
        }

        // Backward compatibility: older encrypted payloads used the sender
        // certificate mailbox as the return route. Newer payloads may advertise
        // a separate return mailbox. Only switch the durable contact destination
        // to that separate mailbox when we have reusable prekey material from a
        // real connection-code contact. Inbound-only contacts keep replying to
        // the sender-certified route until a proper encrypted migration has
        // completed, which preserves functionality and avoids empty routing.
        let has_dedicated_return_route = decoded.return_mailbox_id.is_some();
        if has_dedicated_return_route && contact_has_reusable_prekey_material(&contact) {
            if let Some(mailbox) = decoded.return_mailbox_id.clone() {
                contact.recipient_id = mailbox;
            }
            if let Some(token) = decoded.return_delivery_token.clone() {
                let epoch = decoded.return_delivery_token_epoch.unwrap_or(contact.delivery_token_epoch.max(1));
                if epoch >= contact.delivery_token_epoch || contact.delivery_token.is_empty() {
                    contact.delivery_token = token;
                    contact.delivery_token_epoch = epoch.max(1);
                }
            }
            if let Some(url) = decoded.return_server_url.clone().or_else(|| decoded.sender_server_url.clone()) {
                contact.server_url = normalize_server_url(Some(url));
                contact.server_id = server_id_for_url(&contact.server_url);
            }
            // If a route migration makes the peer start a new Signal session to
            // the advertised return mailbox, do not make it reuse an old OPK from
            // the original connection code.
            contact.opk_id = None;
            contact.opk_public_b64 = None;
        }
        if let Some(dev) = decoded.sender_device_id { contact.device_id = dev; }
        if let Some(identity) = decoded.sender_identity_public_b64.clone() {
            if contact.identity_public_b64.is_empty() {
                contact.identity_public_b64 = identity.clone();
                if let Ok(identity_raw) = decode_b64(&identity, "sender identity public key") {
                    contact.safety_number = pairwise_safety_number(&me.public_key, &identity_raw);
                }
            } else if identity != contact.identity_public_b64 {
                if let Some(c) = axeno_store.contacts.iter_mut().find(|c| c.recipient_id == contact.recipient_id) {
                    c.trust_state = "identity_changed_blocked".to_string();
                    c.verified_at_ms = None;
                }
                return Err("encrypted sender profile identity did not match the Signal session identity".into());
            }
        }
        if contact.identity_public_b64.is_empty() {
            return Err("decrypted sender profile did not contain a stable Signal identity".into());
        }

        // Every encrypted payload now carries the sender's reusable PreKey
        // bundle. That lets an inbound-only peer establish a clean session when
        // a later route migration moves the sender onto a fresh mailbox. Without
        // this, replies could be accepted by the relay but dropped locally
        // because the recipient had no session/prekey material for the fresh
        // sealed-sender route.
        if let Some(id) = decoded.sender_registration_id { contact.registration_id = id; }
        if let Some(id) = decoded.sender_signed_prekey_id { contact.signed_prekey_id = id; }
        if let Some(value) = decoded.sender_signed_prekey_public_b64.clone() { contact.signed_prekey_public_b64 = value; }
        if let Some(value) = decoded.sender_signed_prekey_signature_b64.clone() { contact.signed_prekey_signature_b64 = value; }
        if let Some(id) = decoded.sender_kyber_prekey_id { contact.kyber_prekey_id = Some(id); }
        if let Some(value) = decoded.sender_kyber_prekey_public_b64.clone() { contact.kyber_prekey_public_b64 = Some(value); }
        if let Some(value) = decoded.sender_kyber_prekey_signature_b64.clone() { contact.kyber_prekey_signature_b64 = Some(value); }

        let existing_pos = axeno_store.contacts
            .iter()
            .position(|c| c.recipient_id == contact.recipient_id)
            .or_else(|| {
                // Route-scoped sealed sender deliberately means the certificate
                // sender UUID is the sender's current private return mailbox,
                // not necessarily the mailbox from the original connection code.
                // If we already know this stable Signal identity under an older
                // invite mailbox, merge the route update into that existing UI
                // contact instead of creating a duplicate contact and fragmenting
                // the session/message history.
                if contact.identity_public_b64.is_empty() { return None; }
                axeno_store.contacts
                    .iter()
                    .position(|c| !c.identity_public_b64.is_empty() && c.identity_public_b64 == contact.identity_public_b64)
            });

        if let Some(pos) = existing_pos {
            let existing = &mut axeno_store.contacts[pos];
            existing.display_name = contact.display_name.clone().or_else(|| existing.display_name.clone());
            existing.recipient_id = contact.recipient_id.clone();
            existing.server_url = if contact.server_url.is_empty() { existing.server_url.clone() } else { contact.server_url.clone() };
            existing.server_id = if contact.server_id.is_empty() { existing.server_id.clone() } else { contact.server_id.clone() };
            existing.identity_public_b64 = contact.identity_public_b64.clone();
            existing.device_id = contact.device_id;
            if contact.registration_id > 0 { existing.registration_id = contact.registration_id; }
            if contact.signed_prekey_id > 0 { existing.signed_prekey_id = contact.signed_prekey_id; }
            if !contact.signed_prekey_public_b64.is_empty() { existing.signed_prekey_public_b64 = contact.signed_prekey_public_b64.clone(); }
            if !contact.signed_prekey_signature_b64.is_empty() { existing.signed_prekey_signature_b64 = contact.signed_prekey_signature_b64.clone(); }
            if contact.kyber_prekey_id.is_some() { existing.kyber_prekey_id = contact.kyber_prekey_id; }
            if contact.kyber_prekey_public_b64.as_ref().map(|s| !s.is_empty()).unwrap_or(false) { existing.kyber_prekey_public_b64 = contact.kyber_prekey_public_b64.clone(); }
            if contact.kyber_prekey_signature_b64.as_ref().map(|s| !s.is_empty()).unwrap_or(false) { existing.kyber_prekey_signature_b64 = contact.kyber_prekey_signature_b64.clone(); }
            if !contact.delivery_token.is_empty() { existing.delivery_token = contact.delivery_token.clone(); }
            existing.delivery_token_epoch = existing.delivery_token_epoch.max(contact.delivery_token_epoch);
            existing.peer_sender_mailbox_id = contact.peer_sender_mailbox_id.clone().or_else(|| existing.peer_sender_mailbox_id.clone());
            if existing.safety_number.is_empty() { existing.safety_number = contact.safety_number.clone(); }
            if !route_is_retiring_invite(local_route) && !route_is_sender_hold(local_route, &existing.id) {
                existing.local_route_id = Some(local_route.id.clone());
            }
            if contact.opk_id.is_none() {
                existing.opk_id = None;
                existing.opk_public_b64 = None;
            }
            contact = existing.clone();
        } else {
            if !route_is_retiring_invite(local_route) && !route_is_sender_hold(local_route, &contact.id) {
                contact.local_route_id = Some(local_route.id.clone());
            }
            axeno_store.contacts.push(contact.clone());
        }

        let mut session_contact = contact.clone();
        session_contact.recipient_id = cert_sender_uuid.clone();
        session_contact.device_id = cert_sender_device;
        persist_session(&protocol_store, axeno_store, &session_contact).await?;
        Ok(DecryptedEnvelope { contact, message: decoded, consumed_opk_ids })
    }

}
