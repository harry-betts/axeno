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

use std::{collections::HashMap, fs, io::Write, path::PathBuf, sync::Arc, time::{SystemTime, UNIX_EPOCH}};

use base64::{engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD}, Engine as _};
use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::Mutex;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::{identity::{fingerprint, EncryptedIdentity, OpkSecret}, load_vault, transport, AppSessionState};

const INVITE_PREFIX: &str = "axn1_";
const STORE_FILE: &str = "messages.store";
const DEFAULT_DEV_SERVER: &str = "ws://127.0.0.1:8787/ws";
const PROTOCOL_SIGNAL: &str = "axeno_signal_v1";
const ENVELOPE_TYPE_SIGNAL: &str = "axeno_signal_v1";
const ENVELOPE_TYPE_SEALED_SIGNAL: &str = "axeno_sealed_signal_v1";
const DEVICE_ID: u32 = 1;
const CONNECTION_CODE_TTL_MS: u64 = 24 * 60 * 60 * 1000;

#[derive(Default)]
pub struct MessagingRuntimeState {
    seen_envelopes: Arc<Mutex<HashMap<String, ()>>>,
}

impl MessagingRuntimeState { pub fn new() -> Self { Self::default() } }

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
    pub safety_number: String,
    #[serde(default = "default_trust_state")]
    pub trust_state: String,
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
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MessagingStore {
    #[serde(default)] pub contacts: Vec<StoredContact>,
    #[serde(default)] pub messages: Vec<StoredMessage>,
    #[serde(default)] pub pending_invites: Vec<PendingInvite>,
    #[serde(default)] pub signal_sessions: HashMap<String, SignalSessionBlob>,
    #[serde(default)] pub local_kyber_prekey: Option<KyberPreKeyBlob>,
    #[serde(default)] pub local_profile: Option<LocalProfile>,
    #[serde(default)] pub used_opk_ids: Vec<u32>,
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
struct EncryptedStoreFile { nonce: [u8; 12], ciphertext: Vec<u8> }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingInvite {
    pub id: String,
    pub code: String,
    pub mailbox_id: String,
    pub server_url: String,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnectionCodeResponse { pub id: String, pub code: String, pub created_at: u64 }

#[derive(Debug, Clone, Serialize)]
pub struct MessagingSnapshot {
    pub my_recipient_id: String,
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
struct SealedSignalWireMessage {
    /// Official libsignal sealed-sender message bytes. The relay sees this opaque
    /// blob only; sender certificate, sender identity, inner Signal message type,
    /// and message ciphertext are inside the libsignal sealed envelope.
    v: u16,
    sealed_sender_b64: String,
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
    sender_server_url: Option<String>,
    #[serde(default)]
    sender_device_id: Option<u32>,
    #[serde(default)]
    sender_identity_public_b64: Option<String>,
}

#[derive(Debug, Clone)]
struct DecryptedSignalText {
    message_id: String,
    sent_at_ms: u64,
    body: String,
    sender_display_name: Option<String>,
    sender_mailbox_id: Option<String>,
    sender_delivery_token: Option<String>,
    sender_server_url: Option<String>,
    sender_device_id: Option<u32>,
    sender_identity_public_b64: Option<String>,
}

fn encode_signal_plaintext(
    body: &str,
    sender_display_name: &str,
    message_id: &str,
    sent_at_ms: u64,
    local_profile: &LocalProfile,
    local_identity_public_b64: &str,
    server_url: &str,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&AxenoSignalPlaintext {
        v: 1,
        kind: "text".to_string(),
        message_id: message_id.to_string(),
        sent_at_ms,
        body: body.to_string(),
        sender_display_name: Some(sender_display_name.trim().to_string()).filter(|s| !s.is_empty()),
        sender_mailbox_id: Some(local_profile.mailbox_id.clone()),
        sender_delivery_token: Some(local_profile.delivery_token.clone()),
        sender_server_url: Some(server_url.to_string()),
        sender_device_id: Some(DEVICE_ID),
        sender_identity_public_b64: Some(local_identity_public_b64.to_string()),
    }).map_err(|e| format!("could not serialize encrypted message payload: {e}"))
}

fn decode_signal_plaintext(raw: Vec<u8>) -> Result<DecryptedSignalText, String> {
    if let Ok(payload) = serde_json::from_slice::<AxenoSignalPlaintext>(&raw) {
        if payload.v != 1 || payload.kind != "text" {
            return Err("unsupported encrypted Axeno message payload".into());
        }
        return Ok(DecryptedSignalText {
            message_id: payload.message_id,
            sent_at_ms: payload.sent_at_ms,
            body: payload.body,
            sender_display_name: payload.sender_display_name.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
            sender_mailbox_id: payload.sender_mailbox_id.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
            sender_delivery_token: payload.sender_delivery_token.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
            sender_server_url: payload.sender_server_url.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
            sender_device_id: payload.sender_device_id,
            sender_identity_public_b64: payload.sender_identity_public_b64.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
        });
    }

    // Backward-compatible fallback for any already-created dev messages before the
    // encrypted plaintext envelope existed.
    let body = String::from_utf8(raw).map_err(|_| "decrypted Signal plaintext was not valid UTF-8".to_string())?;
    Ok(DecryptedSignalText {
        message_id: Uuid::new_v4().to_string(),
        sent_at_ms: now_ms(),
        body,
        sender_display_name: None,
        sender_mailbox_id: None,
        sender_delivery_token: None,
        sender_server_url: None,
        sender_device_id: None,
        sender_identity_public_b64: None,
    })
}

fn store_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_data_dir().map_err(|_| "could not resolve app data dir".to_string())?;
    fs::create_dir_all(&dir).map_err(|e| format!("could not create app data dir: {e}"))?;
    Ok(dir.join(STORE_FILE))
}

async fn store_key(session: &AppSessionState) -> Result<[u8; 32], String> {
    let guard = session.session.lock().await;
    let Some(unlocked) = guard.as_ref() else { return Err("identity is locked".into()); };
    Ok(unlocked.key.0)
}

#[derive(Debug, Clone)]
struct PrivateSignalMaterial {
    identity_priv: Vec<u8>,
    spk_priv: Vec<u8>,
    opks_secret: Vec<OpkSecret>,
    display_name: String,
}

impl Drop for PrivateSignalMaterial {
    fn drop(&mut self) {
        self.identity_priv.zeroize();
        self.spk_priv.zeroize();
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
        opks_secret: unlocked.secrets.opks_secret.clone(),
        display_name: unlocked.secrets.display_name.clone(),
    })
}

fn decode_store_file(data: &[u8]) -> Result<EncryptedStoreFile, String> {
    match serde_json::from_slice::<EncryptedStoreFile>(data) {
        Ok(file) => return Ok(file),
        Err(first_err) => {
            // Recovery path for stores created during early dev builds or concurrent test runs.
            // serde_json::from_slice rejects valid JSON followed by trailing bytes/another JSON value
            // with "trailing characters". Parse the first complete value so the next successful
            // save can rewrite the file cleanly instead of bricking the profile.
            let mut stream = serde_json::Deserializer::from_slice(data).into_iter::<EncryptedStoreFile>();
            if let Some(Ok(file)) = stream.next() {
                return Ok(file);
            }
            Err(format!("message store header is corrupted: {first_err}"))
        }
    }
}

fn load_store_with_key(app: &AppHandle, key_bytes: &[u8; 32]) -> Result<MessagingStore, String> {
    let path = store_path(app)?;
    if !path.exists() { return Ok(MessagingStore::default()); }
    let data = fs::read(path).map_err(|e| format!("read encrypted message store failed: {e}"))?;
    let file = decode_store_file(&data)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key_bytes));
    let plaintext = cipher.decrypt(Nonce::from_slice(&file.nonce), file.ciphertext.as_ref())
        .map_err(|_| "message store could not be decrypted; identity/password mismatch or corrupted store".to_string())?;
    serde_json::from_slice(&plaintext).map_err(|e| format!("message store plaintext is corrupted: {e}"))
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
    let json = serde_json::to_vec(store).map_err(|e| format!("serialize message store failed: {e}"))?;
    let mut nonce = [0u8; 12]; fill_random(&mut nonce)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key_bytes));
    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), json.as_ref()).map_err(|_| "message store encryption failed".to_string())?;
    let encoded = serde_json::to_vec(&EncryptedStoreFile { nonce, ciphertext }).map_err(|e| format!("serialize encrypted message store failed: {e}"))?;
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
    Ok(())
}

fn now_ms() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64 }
fn fill_random(buf: &mut [u8]) -> Result<(), String> { getrandom::getrandom(buf).map_err(|e| format!("OS randomness unavailable: {e}")) }

pub fn legacy_identity_routing_id(blob: &EncryptedIdentity) -> String { fingerprint(blob).replace(':', "").replace(' ', "") }

fn random_token(prefix: &str, bytes: usize) -> Result<String, String> {
    let mut raw = vec![0u8; bytes];
    fill_random(&mut raw)?;
    Ok(format!("{}{}", prefix, URL_SAFE_NO_PAD.encode(raw)))
}

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

fn token_hash(token: &str) -> String { hex::encode(Sha256::digest(token.as_bytes())) }

fn safety_number(identity_public: &[u8]) -> String { hex::encode(&Sha256::digest(identity_public)[..16]) }

fn default_trust_state() -> String { "unverified".to_string() }

fn code_to_payload(code: &str) -> Result<InvitePayload, String> {
    let encoded = code.trim().strip_prefix(INVITE_PREFIX).ok_or_else(|| "connection code must start with axn1_".to_string())?;
    let bytes = URL_SAFE_NO_PAD.decode(encoded.as_bytes()).map_err(|_| "connection code base64 is invalid".to_string())?;
    serde_json::from_slice::<InvitePayload>(&bytes).map_err(|e| format!("connection code payload is invalid: {e}"))
}
fn payload_to_code(payload: &InvitePayload) -> Result<String, String> {
    Ok(format!("{}{}", INVITE_PREFIX, URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).map_err(|e| e.to_string())?)))
}
fn normalize_server_url(url: Option<String>) -> String {
    let raw = url.unwrap_or_else(|| DEFAULT_DEV_SERVER.to_string()).trim().to_string();
    if raw.ends_with("/ws") { raw }
    else if raw.starts_with("ws://") || raw.starts_with("wss://") { format!("{}/ws", raw.trim_end_matches('/')) }
    else if raw.ends_with(".onion") { format!("ws://{raw}/ws") }
    else { raw }
}
pub fn server_id_for_url(url: &str) -> String { format!("srv_{}", hex::encode(&Sha256::digest(url.as_bytes())[..8])) }

fn contact_from_payload(payload: InvitePayload) -> Result<StoredContact, String> {
    if payload.v != 1 || payload.protocol != PROTOCOL_SIGNAL { return Err("unsupported connection code protocol".into()); }
    let identity_public = STANDARD_NO_PAD.decode(payload.identity_public_b64.as_bytes()).map_err(|_| "bad identity public key in code".to_string())?;
    Ok(StoredContact {
        id: payload.mailbox_id.clone(),
        display_name: Some(payload.display_name.clone()).filter(|s| !s.trim().is_empty()),
        recipient_id: payload.mailbox_id.clone(),
        server_url: payload.server_url.clone(),
        server_id: server_id_for_url(&payload.server_url),
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
        safety_number: safety_number(&identity_public),
        trust_state: "unverified".to_string(),
        created_at_ms: now_ms(),
        last_read_at: None,
    })
}

pub async fn generate_connection_code(app: AppHandle, session: &AppSessionState, server_url: Option<String>) -> Result<ConnectionCodeResponse, String> {
    let store_key = store_key(session).await?;
    let blob = load_vault(&app)?;
    let material = signal_material(session).await?;
    let mut store = load_store_with_key(&app, &store_key)?;
    let profile = ensure_local_profile(&mut store)?;

    // Reserve a fresh one-time prekey per generated invite where possible.
    let opk = blob.opks_public
        .iter()
        .find(|o| !store.used_opk_ids.contains(&o.id))
        .cloned()
        .or_else(|| blob.opks_public.first().cloned());
    if let Some(ref opk) = opk {
        if !store.used_opk_ids.contains(&opk.id) { store.used_opk_ids.push(opk.id); }
    }

    let kyber = signal_protocol_engine::ensure_local_kyber_prekey(&blob, &material, &mut store)?;
    let created = now_ms();
    let payload = InvitePayload {
        v: 1,
        protocol: PROTOCOL_SIGNAL.to_string(),
        display_name: material.display_name.trim().to_string(),
        mailbox_id: profile.mailbox_id.clone(),
        delivery_token: profile.delivery_token.clone(),
        server_url: normalize_server_url(server_url),
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
    let code = payload_to_code(&payload)?;
    let pending = PendingInvite { id: Uuid::new_v4().to_string(), code: code.clone(), mailbox_id: payload.mailbox_id.clone(), server_url: payload.server_url.clone(), created_at_ms: payload.created_at_ms, expires_at_ms: payload.created_at_ms + CONNECTION_CODE_TTL_MS };
    store.pending_invites.retain(|p| p.expires_at_ms > created);
    store.pending_invites.push(pending.clone());
    save_store_with_key(&app, &store, &store_key)?;
    Ok(ConnectionCodeResponse { id: pending.id, code, created_at: pending.created_at_ms })
}

pub async fn list_connection_codes(app: AppHandle, session: &AppSessionState) -> Result<Vec<ConnectionCodeResponse>, String> {
    let store_key = store_key(session).await?;
    let mut store = load_store_with_key(&app, &store_key)?;
    let now = now_ms();
    store.pending_invites.retain(|p| p.expires_at_ms > now);
    let out = store.pending_invites.iter().cloned().map(|p| ConnectionCodeResponse { id: p.id, code: p.code, created_at: p.created_at_ms }).collect();
    save_store_with_key(&app, &store, &store_key)?;
    Ok(out)
}

pub async fn delete_connection_code(app: AppHandle, session: &AppSessionState, id: String) -> Result<(), String> {
    let store_key = store_key(session).await?;
    let mut store = load_store_with_key(&app, &store_key)?;
    store.pending_invites.retain(|p| p.id != id);
    save_store_with_key(&app, &store, &store_key)
}

pub async fn add_contact_from_code(app: AppHandle, session: &AppSessionState, code: String) -> Result<StoredContact, String> {
    let store_key = store_key(session).await?;
    let contact = contact_from_payload(code_to_payload(&code)?)?;
    let mut store = load_store_with_key(&app, &store_key)?;
    if let Some(existing) = store.contacts.iter_mut().find(|c| c.recipient_id == contact.recipient_id) {
        if existing.identity_public_b64 != contact.identity_public_b64 && !existing.identity_public_b64.is_empty() {
            existing.trust_state = "identity_changed_blocked".to_string();
            save_store_with_key(&app, &store, &store_key)?;
            return Err("contact identity key changed; refusing to replace it automatically. Verify out-of-band before re-adding.".into());
        }
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
        existing.safety_number = contact.safety_number.clone();
        let updated = existing.clone();
        save_store_with_key(&app, &store, &store_key)?;
        return Ok(updated);
    }
    store.contacts.push(contact.clone());
    save_store_with_key(&app, &store, &store_key)?;
    Ok(contact)
}

pub async fn snapshot(app: AppHandle, session: &AppSessionState) -> Result<MessagingSnapshot, String> {
    let store_key = store_key(session).await?;
    let mut store = load_store_with_key(&app, &store_key)?;
    let profile = ensure_local_profile(&mut store)?;
    let mut grouped: HashMap<String, Vec<StoredMessage>> = HashMap::new();
    for msg in store.messages.clone() { grouped.entry(msg.contact_id.clone()).or_default().push(msg); }
    for msgs in grouped.values_mut() { msgs.sort_by_key(|m| m.timestamp); }
    save_store_with_key(&app, &store, &store_key)?;
    Ok(MessagingSnapshot { my_recipient_id: profile.mailbox_id, contacts: store.contacts, messages: grouped })
}

pub async fn connect_all(app: AppHandle, session: &AppSessionState, transport_state: State<'_, transport::TransportState>, tor_client: Arc<Mutex<Option<arti_client::TorClient<tor_rtcompat::PreferredRuntime>>>>) -> Result<(), String> {
    let store_key = store_key(session).await?;
    let mut store = load_store_with_key(&app, &store_key)?;
    let profile = ensure_local_profile(&mut store)?;
    let mut urls: Vec<String> = store.contacts.iter().map(|c| c.server_url.clone()).collect();
    urls.extend(store.pending_invites.iter().filter(|p| p.expires_at_ms > now_ms()).map(|p| p.server_url.clone()));
    if urls.is_empty() { urls.push(DEFAULT_DEV_SERVER.to_string()); }
    urls.sort(); urls.dedup();
    save_store_with_key(&app, &store, &store_key)?;
    for url in urls {
        let server_id = server_id_for_url(&url);
        let _ = transport::connect_server(
            app.clone(),
            transport_state.clone(),
            tor_client.clone(),
            server_id,
            url,
            profile.mailbox_id.clone(),
            profile.receive_auth_token.clone(),
            profile.delivery_token.clone(),
        ).await;
    }
    Ok(())
}

pub async fn send_text_message(app: AppHandle, session: &AppSessionState, transport_state: State<'_, transport::TransportState>, contact_id: String, text: String) -> Result<SendMessageResponse, String> {
    let store_key = store_key(session).await?;
    let trimmed = text.trim().to_string();
    if trimmed.is_empty() { return Err("message is empty".into()); }
    if trimmed.len() > 16 * 1024 { return Err("message too large for text MVP".into()); }
    let blob = load_vault(&app)?;
    let material = signal_material(session).await?;
    let mut store = load_store_with_key(&app, &store_key)?;
    ensure_local_profile(&mut store)?;
    let contact = store.contacts.iter().find(|c| c.id == contact_id).cloned().ok_or_else(|| "contact not found".to_string())?;
    if contact.trust_state == "identity_changed_blocked" { return Err("contact identity changed; verify before sending".into()); }

    let message_id = Uuid::new_v4().to_string();
    let sent_at = now_ms();
    let cert = transport::request_sender_certificate(
        transport_state.clone(),
        contact.server_id.clone(),
        ensure_local_profile(&mut store)?.mailbox_id.clone(),
        DEVICE_ID,
        STANDARD_NO_PAD.encode(&blob.public_key),
    ).await?;
    let encrypted = signal_protocol_engine::encrypt_for_contact(&blob, &material, &contact, &mut store, &trimmed, &message_id, sent_at, &cert).await?;
    let wire = SealedSignalWireMessage { v: 1, sealed_sender_b64: STANDARD_NO_PAD.encode(encrypted.sealed_sender) };
    transport::send_envelope(transport_state, contact.server_id.clone(), contact.recipient_id.clone(), contact.delivery_token.clone(), ENVELOPE_TYPE_SEALED_SIGNAL.to_string(), serde_json::to_string(&wire).map_err(|e| e.to_string())?).await?;

    let msg = StoredMessage { id: message_id, contact_id: contact.id, mine: true, text: trimmed, timestamp: sent_at, status: "sent".to_string() };
    store.messages.push(msg.clone());
    save_store_with_key(&app, &store, &store_key)?;
    Ok(SendMessageResponse { message: msg })
}

pub async fn handle_incoming_envelope(app: AppHandle, session: &AppSessionState, runtime: State<'_, MessagingRuntimeState>, transport_state: State<'_, transport::TransportState>, server_id: String, envelope: transport::StoredEnvelope) -> Result<(), String> {
    let store_key = store_key(session).await?;
    if envelope.envelope_type != ENVELOPE_TYPE_SEALED_SIGNAL && envelope.envelope_type != ENVELOPE_TYPE_SIGNAL { return Ok(()); }
    {
        let seen = runtime.seen_envelopes.lock().await;
        if seen.contains_key(&envelope.id.to_string()) { return Ok(()); }
    }

    let blob = load_vault(&app)?;
    let material = signal_material(session).await?;
    let mut store = load_store_with_key(&app, &store_key)?;
    let trust_root_b64 = transport::get_server_trust_root(transport_state, server_id.clone())
        .await?
        .ok_or_else(|| "server trust root unavailable; reconnect to the relay before decrypting sealed-sender messages".to_string())?;
    let wire: SealedSignalWireMessage = serde_json::from_str(&envelope.ciphertext).map_err(|e| format!("bad sealed Signal envelope: {e}"))?;
    if wire.v != 1 { return Err("unsupported sealed Signal envelope version".into()); }
    let ciphertext = STANDARD_NO_PAD.decode(wire.sealed_sender_b64.as_bytes()).map_err(|_| "bad sealed sender ciphertext encoding".to_string())?;

    let decrypted = signal_protocol_engine::decrypt_sealed_sender_message(
        &blob,
        &material,
        &mut store,
        &server_id,
        &trust_root_b64,
        &ciphertext,
    ).await?;

    let contact_id = decrypted.contact.id.clone();
    if store.messages.iter().any(|m| m.id == decrypted.message.message_id) {
        save_store_with_key(&app, &store, &store_key)?;
        runtime.seen_envelopes.lock().await.insert(envelope.id.to_string(), ());
        return Ok(());
    }

    let msg = StoredMessage {
        id: decrypted.message.message_id,
        contact_id: contact_id.clone(),
        mine: false,
        text: decrypted.message.body,
        timestamp: decrypted.message.sent_at_ms,
        status: "received".to_string(),
    };
    store.messages.push(msg.clone());
    save_store_with_key(&app, &store, &store_key)?;
    runtime.seen_envelopes.lock().await.insert(envelope.id.to_string(), ());
    let _ = app.emit("axeno-message", IncomingMessageEvent { contact_id, message: msg });
    Ok(())
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
        IdentityKeyPair, InMemSignalProtocolStore, KeyPair, KyberPreKeyId,
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
        if let Some(existing) = axeno_store.local_kyber_prekey.clone() {
            return Ok(existing);
        }

        let signing_key = PrivateKey::deserialize(&material.identity_priv)
            .map_err(|e| signal_err("local identity private key is invalid", e))?;
        let record = KyberPreKeyRecord::generate(
            kem::KeyType::Kyber1024,
            KyberPreKeyId::from(KYBER_PREKEY_ID),
            &signing_key,
        ).map_err(|e| signal_err("could not generate local Kyber prekey", e))?;

        let public = record.public_key()
            .map_err(|e| signal_err("could not read generated Kyber public key", e))?;
        let signature = record.signature()
            .map_err(|e| signal_err("could not read generated Kyber signature", e))?;
        let serialized = record.serialize()
            .map_err(|e| signal_err("could not serialize generated Kyber prekey", e))?;

        let blob = KyberPreKeyBlob {
            id: KYBER_PREKEY_ID,
            public_b64: STANDARD_NO_PAD.encode(public.serialize()),
            signature_b64: STANDARD_NO_PAD.encode(signature),
            record_b64: STANDARD_NO_PAD.encode(serialized),
            created_at_ms: now_ms(),
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
        if let Some(kyber) = axeno_store.local_kyber_prekey.as_ref() {
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
        axeno_store: &mut MessagingStore,
        plaintext: &str,
        message_id: &str,
        sent_at_ms: u64,
        sender_certificate: &transport::SenderCertificateResponse,
    ) -> Result<EncryptedForRelay, String> {
        ensure_local_kyber_prekey(me, material, axeno_store)?;
        let mut protocol_store = protocol_store_for(me, material, axeno_store).await?;
        let remote = remote_address(contact)?;
        let local_profile = ensure_local_profile(axeno_store)?;
        let local = local_address(&local_profile.mailbox_id)?;

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
        }

        let local_profile_for_payload = ensure_local_profile(axeno_store)?;
        let local_identity_public_b64 = STANDARD_NO_PAD.encode(&me.public_key);
        let plaintext_payload = encode_signal_plaintext(
            plaintext,
            &material.display_name,
            message_id,
            sent_at_ms,
            &local_profile_for_payload,
            &local_identity_public_b64,
            &contact.server_url,
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
        let mut rng = fresh_signal_rng()?;
        let sealed = sealed_sender_encrypt_from_usmc(
            &remote,
            &usmc,
            &protocol_store.identity_store,
            &mut rng,
        )
            .await
            .map_err(|e| signal_err("libsignal Sealed Sender encryption failed", e))?;
        Ok(EncryptedForRelay { sealed_sender: sealed })
    }

    pub struct DecryptedEnvelope {
        pub contact: StoredContact,
        pub message: DecryptedSignalText,
    }

    pub async fn decrypt_sealed_sender_message(
        me: &EncryptedIdentity,
        material: &PrivateSignalMaterial,
        axeno_store: &mut MessagingStore,
        server_id: &str,
        trust_root_b64: &str,
        sealed_sender: &[u8],
    ) -> Result<DecryptedEnvelope, String> {
        ensure_local_kyber_prekey(me, material, axeno_store)?;
        let mut protocol_store = protocol_store_for(me, material, axeno_store).await?;
        let local_profile = ensure_local_profile(axeno_store)?;
        let local = local_address(&local_profile.mailbox_id)?;

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
        let cert_key = sender_cert.key().map_err(|e| signal_err("sender certificate has no identity key", e))?;
        let cert_key_b64 = STANDARD_NO_PAD.encode(cert_key.serialize());

        // With official sealed sender, the sender is deliberately not visible to
        // the relay. The receiver learns the sender from the encrypted sealed
        // envelope's SenderCertificate, so we must be able to create/update a
        // provisional contact here even if the receiver has not manually imported
        // the sender's connection code yet.
        let mut contact = if let Some(existing) = axeno_store.contacts.iter().find(|c| c.recipient_id == cert_sender_uuid).cloned() {
            existing
        } else {
            StoredContact {
                id: cert_sender_uuid.clone(),
                display_name: None,
                recipient_id: cert_sender_uuid.clone(),
                server_url: String::new(),
                server_id: server_id.to_string(),
                identity_public_b64: cert_key_b64.clone(),
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
                safety_number: safety_number(&cert_key.serialize()),
                trust_state: "unverified".to_string(),
                created_at_ms: now_ms(),
                last_read_at: None,
            }
        };

        if !contact.identity_public_b64.is_empty() && contact.identity_public_b64 != cert_key_b64 {
            if let Some(c) = axeno_store.contacts.iter_mut().find(|c| c.recipient_id == cert_sender_uuid) {
                c.trust_state = "identity_changed_blocked".to_string();
            }
            return Err("sealed sender certificate identity did not match stored contact identity".into());
        }
        contact.identity_public_b64 = cert_key_b64.clone();
        contact.device_id = cert_sender_device;
        contact.server_id = server_id.to_string();
        if contact.safety_number.is_empty() {
            contact.safety_number = safety_number(&cert_key.serialize());
        }

        let remote = remote_address(&contact)?;
        let message_type = usmc.msg_type().map_err(|e| signal_err("sealed sender content has no message type", e))?;
        let inner = usmc.contents().map_err(|e| signal_err("sealed sender content has no inner ciphertext", e))?;
        let plaintext = match ciphertext_type_name(message_type)? {
            "prekey_signal" => {
                let prekey_msg = PreKeySignalMessage::try_from(inner.as_ref())
                    .map_err(|e| signal_err("bad PreKeySignalMessage", e))?;
                let identity_b64 = STANDARD_NO_PAD.encode(prekey_msg.identity_key().serialize());
                if contact.identity_public_b64.is_empty() {
                    contact.identity_public_b64 = identity_b64.clone();
                    contact.safety_number = safety_number(&prekey_msg.identity_key().serialize());
                }
                let mut rng = fresh_signal_rng()?;
                message_decrypt_prekey(
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
                    .map_err(|e| signal_err("Signal PreKey message decryption failed", e))?
            }
            "signal" => {
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
        if let Some(mailbox) = decoded.sender_mailbox_id.clone() {
            if mailbox != contact.recipient_id {
                return Err("encrypted sender profile did not match sealed sender certificate".into());
            }
        }
        if let Some(token) = decoded.sender_delivery_token.clone() { contact.delivery_token = token; }
        if let Some(url) = decoded.sender_server_url.clone() {
            contact.server_url = normalize_server_url(Some(url));
            contact.server_id = server_id_for_url(&contact.server_url);
        }
        if let Some(dev) = decoded.sender_device_id { contact.device_id = dev; }
        if let Some(identity) = decoded.sender_identity_public_b64.clone() {
            if identity != cert_key_b64 {
                return Err("encrypted sender profile identity did not match sealed sender certificate".into());
            }
        }

        if let Some(existing) = axeno_store.contacts.iter_mut().find(|c| c.recipient_id == contact.recipient_id) {
            existing.display_name = contact.display_name.clone().or_else(|| existing.display_name.clone());
            existing.server_url = if contact.server_url.is_empty() { existing.server_url.clone() } else { contact.server_url.clone() };
            existing.server_id = if contact.server_id.is_empty() { existing.server_id.clone() } else { contact.server_id.clone() };
            existing.identity_public_b64 = contact.identity_public_b64.clone();
            existing.device_id = contact.device_id;
            if !contact.delivery_token.is_empty() { existing.delivery_token = contact.delivery_token.clone(); }
            if existing.safety_number.is_empty() { existing.safety_number = contact.safety_number.clone(); }
            contact = existing.clone();
        } else {
            axeno_store.contacts.push(contact.clone());
        }

        persist_session(&protocol_store, axeno_store, &contact).await?;
        Ok(DecryptedEnvelope { contact, message: decoded })
    }

}
