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

use std::{collections::{HashMap, VecDeque}, fs, io::Write, path::PathBuf, sync::Arc, time::{SystemTime, UNIX_EPOCH}};

use base64::{engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD}, Engine as _};
use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use libsignal_protocol::KeyPair;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
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
    seen_envelopes: Arc<Mutex<VecDeque<(String, u64)>>>,
    failed_envelopes: Arc<Mutex<HashMap<String, u32>>>,
}

impl MessagingRuntimeState { pub fn new() -> Self { Self::default() } }

const SEEN_ENVELOPE_TTL_MS: u64 = 24 * 60 * 60 * 1000;
const MAX_SEEN_ENVELOPES: usize = 4096;
const MAX_FAILED_DECRYPTS_PER_ENVELOPE: u32 = 5;

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
    #[serde(default)]
    pub verified_at_ms: Option<u64>,
    #[serde(default)]
    pub local_route_id: Option<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MessagingStore {
    #[serde(default)] pub contacts: Vec<StoredContact>,
    #[serde(default)] pub messages: Vec<StoredMessage>,
    #[serde(default)] pub pending_invites: Vec<PendingInvite>,
    #[serde(default)] pub signal_sessions: HashMap<String, SignalSessionBlob>,
    #[serde(default)] pub local_kyber_prekey: Option<KyberPreKeyBlob>,
    #[serde(default)] pub local_profile: Option<LocalProfile>,
    #[serde(default)] pub local_routes: Vec<LocalRoute>,
    #[serde(default)] pub used_opk_ids: Vec<u32>,
    #[serde(default)] pub server_trust_roots: HashMap<String, String>,
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
pub struct LocalRoute {
    pub id: String,
    pub mailbox_id: String,
    pub receive_auth_token: String,
    pub delivery_token: String,
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
    #[serde(default = "default_true")]
    pub active: bool,
    pub created_at_ms: u64,
    #[serde(default)]
    pub expires_at_ms: Option<u64>,
}

fn default_true() -> bool { true }

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
    #[serde(default)]
    pub route_id: Option<String>,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnectionCodeResponse { pub id: String, pub code: String, pub created_at: u64 }

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
    local_route: &LocalRoute,
    local_identity_public_b64: &str,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&AxenoSignalPlaintext {
        v: 1,
        kind: "text".to_string(),
        message_id: message_id.to_string(),
        sent_at_ms,
        body: body.to_string(),
        sender_display_name: Some(sender_display_name.trim().to_string()).filter(|s| !s.is_empty()),
        sender_mailbox_id: Some(local_route.mailbox_id.clone()),
        sender_delivery_token: Some(local_route.delivery_token.clone()),
        sender_server_url: Some(local_route.server_url.clone()),
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

async fn store_keys(session: &AppSessionState) -> Result<([u8; 32], [u8; 32]), String> {
    let guard = session.session.lock().await;
    let Some(unlocked) = guard.as_ref() else { return Err("identity is locked".into()); };
    let legacy = unlocked.key.0;
    let current = derive_domain_key(&legacy, b"message-store");
    Ok((current, legacy))
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

fn try_load_store_with_key(app: &AppHandle, key_bytes: &[u8; 32]) -> Result<MessagingStore, String> {
    let path = store_path(app)?;
    if !path.exists() { return Ok(MessagingStore::default()); }
    let data = fs::read(path).map_err(|e| format!("read encrypted message store failed: {e}"))?;
    let file = decode_store_file(&data)?;
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
            try_load_store_with_key(app, legacy_key).map_err(|_| {
                "message store could not be decrypted; identity/password mismatch or corrupted store".to_string()
            })
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
        server_id: server_id_for_url(&normalized),
        server_url: normalized,
        sealed_sender_cert_public_b64: cert_public_b64,
        sealed_sender_cert_private_b64: cert_private_b64,
        scope,
        active: true,
        created_at_ms: now_ms(),
        expires_at_ms,
    })
}

fn route_connection_id(route: &LocalRoute) -> String {
    format!("{}__{}", route.server_id, route.mailbox_id)
}

fn cleanup_expired_routes(store: &mut MessagingStore) {
    let now = now_ms();
    store.pending_invites.retain(|p| p.expires_at_ms > now);
    store.local_routes.retain(|r| r.active && r.expires_at_ms.map(|exp| exp > now).unwrap_or(true));
}

fn ensure_route_for_contact(store: &mut MessagingStore, contact_id: &str, server_url: &str) -> Result<LocalRoute, String> {
    cleanup_expired_routes(store);
    if let Some(existing_route_id) = store.contacts.iter().find(|c| c.id == contact_id).and_then(|c| c.local_route_id.clone()) {
        if let Some(route) = store.local_routes.iter_mut().find(|r| r.id == existing_route_id) {
            route.server_url = normalize_server_url(Some(server_url.to_string()));
            route.server_id = server_id_for_url(&route.server_url);
            route.expires_at_ms = None;
            route.active = true;
            ensure_route_cert_key(route)?;
            return Ok(route.clone());
        }
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

fn legacy_route_from_profile(profile: LocalProfile, server_id: String, server_url: String) -> LocalRoute {
    LocalRoute {
        id: "legacy_local_profile".to_string(),
        mailbox_id: profile.mailbox_id,
        receive_auth_token: profile.receive_auth_token,
        delivery_token: profile.delivery_token,
        server_url: normalize_server_url(Some(server_url)),
        server_id,
        sealed_sender_cert_public_b64: String::new(),
        sealed_sender_cert_private_b64: String::new(),
        scope: "legacy".to_string(),
        active: true,
        created_at_ms: profile.created_at_ms,
        expires_at_ms: None,
    }
}

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

fn contact_from_payload(payload: InvitePayload, local_identity_public: &[u8]) -> Result<StoredContact, String> {
    if payload.v != 1 || payload.protocol != PROTOCOL_SIGNAL { return Err("unsupported connection code protocol".into()); }
    let now = now_ms();
    if payload.created_at_ms.saturating_add(CONNECTION_CODE_TTL_MS) < now {
        return Err("connection code has expired; ask for a fresh code".into());
    }
    let server_url = normalize_server_url(Some(payload.server_url.clone()));
    let identity_public = STANDARD_NO_PAD.decode(payload.identity_public_b64.as_bytes()).map_err(|_| "bad identity public key in code".to_string())?;
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
        safety_number: pairwise_safety_number(local_identity_public, &identity_public),
        trust_state: "unverified".to_string(),
        verified_at_ms: None,
        local_route_id: None,
        created_at_ms: now_ms(),
        last_read_at: None,
    })
}

pub async fn generate_connection_code(app: AppHandle, session: &AppSessionState, server_url: Option<String>) -> Result<ConnectionCodeResponse, String> {
    let (store_key, legacy_store_key) = store_keys(session).await?;
    let blob = load_vault(&app)?;
    let material = signal_material(session).await?;
    let mut store = load_store_with_keys(&app, &store_key, &legacy_store_key)?;
    cleanup_expired_routes(&mut store);

    // Reserve a fresh one-time prekey per generated invite. Do not silently fall
    // back to reusing OPKs: that breaks the one-time property and makes stale
    // connection codes much more dangerous.
    let opk = blob.opks_public
        .iter()
        .find(|o| !store.used_opk_ids.contains(&o.id))
        .cloned();
    if let Some(opk) = opk.as_ref() {
        store.used_opk_ids.push(opk.id);
    }

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
    let code = payload_to_code(&payload)?;
    let pending = PendingInvite {
        id: Uuid::new_v4().to_string(),
        code: code.clone(),
        mailbox_id: route.mailbox_id.clone(),
        server_url: route.server_url.clone(),
        route_id: Some(route.id.clone()),
        created_at_ms: payload.created_at_ms,
        expires_at_ms: expires,
    };
    store.local_routes.push(route);
    store.pending_invites.push(pending.clone());
    save_store_with_key(&app, &store, &store_key)?;
    Ok(ConnectionCodeResponse { id: pending.id, code, created_at: pending.created_at_ms })
}

pub async fn list_connection_codes(app: AppHandle, session: &AppSessionState) -> Result<Vec<ConnectionCodeResponse>, String> {
    let (store_key, legacy_store_key) = store_keys(session).await?;
    let mut store = load_store_with_keys(&app, &store_key, &legacy_store_key)?;
    cleanup_expired_routes(&mut store);
    let out = store.pending_invites.iter().cloned().map(|p| ConnectionCodeResponse { id: p.id, code: p.code, created_at: p.created_at_ms }).collect();
    save_store_with_key(&app, &store, &store_key)?;
    Ok(out)
}

pub async fn delete_connection_code(app: AppHandle, session: &AppSessionState, id: String) -> Result<Vec<String>, String> {
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

pub async fn add_contact_from_code(app: AppHandle, session: &AppSessionState, code: String) -> Result<StoredContact, String> {
    let (store_key, legacy_store_key) = store_keys(session).await?;
    let blob = load_vault(&app)?;
    let contact = contact_from_payload(code_to_payload(&code)?, &blob.public_key)?;
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

pub async fn connect_all(app: AppHandle, session: &AppSessionState, transport_state: State<'_, transport::TransportState>, tor_client: Arc<Mutex<Option<arti_client::TorClient<tor_rtcompat::PreferredRuntime>>>>) -> Result<(), String> {
    let (store_key, legacy_store_key) = store_keys(session).await?;
    let mut store = load_store_with_keys(&app, &store_key, &legacy_store_key)?;
    cleanup_expired_routes(&mut store);

    // Make sure every imported contact has a private return mailbox on that
    // contact's relay. This avoids one global mailbox linking all contacts.
    let contact_routes: Vec<(String, String)> = store.contacts.iter().map(|c| (c.id.clone(), c.server_url.clone())).collect();
    for (contact_id, server_url) in contact_routes {
        let _ = ensure_route_for_contact(&mut store, &contact_id, &server_url)?;
    }

    let routes: Vec<LocalRoute> = store.local_routes.iter().filter(|r| r.active).cloned().collect();
    save_store_with_key(&app, &store, &store_key)?;
    for route in routes {
        let _ = transport::connect_server(
            app.clone(),
            transport_state.clone(),
            tor_client.clone(),
            route_connection_id(&route),
            route.server_url.clone(),
            route.mailbox_id.clone(),
            route.receive_auth_token.clone(),
            route.delivery_token.clone(),
        ).await;
    }
    Ok(())
}

pub async fn send_text_message(app: AppHandle, session: &AppSessionState, transport_state: State<'_, transport::TransportState>, contact_id: String, text: String) -> Result<SendMessageResponse, String> {
    let (store_key, legacy_store_key) = store_keys(session).await?;
    let trimmed = text.trim().to_string();
    if trimmed.is_empty() { return Err("message is empty".into()); }
    if trimmed.len() > 16 * 1024 { return Err("message too large for text MVP".into()); }
    let blob = load_vault(&app)?;
    let material = signal_material(session).await?;
    let mut store = load_store_with_keys(&app, &store_key, &legacy_store_key)?;
    cleanup_expired_routes(&mut store);
    let contact = store.contacts.iter().find(|c| c.id == contact_id).cloned().ok_or_else(|| "contact not found".to_string())?;
    if contact.trust_state == "identity_changed_blocked" { return Err("contact identity changed; verify before sending".into()); }
    let route = ensure_route_for_contact(&mut store, &contact.id, &contact.server_url)?;

    let message_id = Uuid::new_v4().to_string();
    let sent_at = now_ms();
    let cert = transport::request_sender_certificate(
        transport_state.clone(),
        route_connection_id(&route),
        route.mailbox_id.clone(),
        DEVICE_ID,
        route.sealed_sender_cert_public_b64.clone(),
    ).await?;
    let encrypted = signal_protocol_engine::encrypt_for_contact(&blob, &material, &contact, &route, &mut store, &trimmed, &message_id, sent_at, &cert).await?;
    let wire = SealedSignalWireMessage { v: 1, sealed_sender_b64: STANDARD_NO_PAD.encode(encrypted.sealed_sender) };
    transport::send_envelope(transport_state, route_connection_id(&route), contact.recipient_id.clone(), contact.delivery_token.clone(), ENVELOPE_TYPE_SEALED_SIGNAL.to_string(), serde_json::to_string(&wire).map_err(|e| e.to_string())?).await?;

    let msg = StoredMessage { id: message_id, contact_id: contact.id, mine: true, text: trimmed, timestamp: sent_at, received_at_ms: None, status: "relay_pending".to_string() };
    store.messages.push(msg.clone());
    save_store_with_key(&app, &store, &store_key)?;
    Ok(SendMessageResponse { message: msg })
}

pub async fn handle_incoming_envelope(app: AppHandle, session: &AppSessionState, runtime: State<'_, MessagingRuntimeState>, transport_state: State<'_, transport::TransportState>, server_id: String, envelope: transport::StoredEnvelope) -> Result<(), String> {
    let (store_key, legacy_store_key) = store_keys(session).await?;
    if envelope.envelope_type != ENVELOPE_TYPE_SEALED_SIGNAL && envelope.envelope_type != ENVELOPE_TYPE_SIGNAL { return Ok(()); }

    let envelope_key = envelope.id.to_string();
    let already_seen = {
        let mut seen = runtime.seen_envelopes.lock().await;
        let now = now_ms();
        while let Some((_, ts)) = seen.front() {
            if seen.len() <= MAX_SEEN_ENVELOPES && now.saturating_sub(*ts) <= SEEN_ENVELOPE_TTL_MS { break; }
            seen.pop_front();
        }
        seen.iter().any(|(id, _)| id == &envelope_key)
    };
    if already_seen {
        let _ = transport::ack_envelopes(transport_state.clone(), server_id.clone(), vec![envelope.id]).await;
        return Ok(());
    }
    {
        let failed = runtime.failed_envelopes.lock().await;
        if failed.get(&envelope_key).copied().unwrap_or(0) >= MAX_FAILED_DECRYPTS_PER_ENVELOPE {
            return Ok(());
        }
    }

    let blob = load_vault(&app)?;
    let material = signal_material(session).await?;
    let mut store = load_store_with_keys(&app, &store_key, &legacy_store_key)?;
    cleanup_expired_routes(&mut store);
    let local_route = route_for_mailbox(&store, &envelope.to)
        .or_else(|| store.local_profile.clone().map(|p| legacy_route_from_profile(p, server_id.clone(), DEFAULT_DEV_SERVER.to_string())))
        .ok_or_else(|| "incoming envelope was not addressed to a known local mailbox".to_string())?;
    let trust_root_b64 = transport::get_server_trust_root(transport_state.clone(), server_id.clone())
        .await?
        .ok_or_else(|| "server trust root unavailable; reconnect to the relay before decrypting sealed-sender messages".to_string())?;
    if let Some(pinned) = store.server_trust_roots.get(&local_route.server_id) {
        if pinned != &trust_root_b64 {
            return Err("server trust root changed for this relay; refusing to decrypt until manually reviewed".into());
        }
    } else {
        store.server_trust_roots.insert(local_route.server_id.clone(), trust_root_b64.clone());
    }
    let wire: SealedSignalWireMessage = serde_json::from_str(&envelope.ciphertext).map_err(|e| format!("bad sealed Signal envelope: {e}"))?;
    if wire.v != 1 { return Err("unsupported sealed Signal envelope version".into()); }
    let ciphertext = STANDARD_NO_PAD.decode(wire.sealed_sender_b64.as_bytes()).map_err(|_| "bad sealed sender ciphertext encoding".to_string())?;

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
            let mut failed = runtime.failed_envelopes.lock().await;
            let count = failed.entry(envelope_key.clone()).or_insert(0);
            *count = count.saturating_add(1);
            return Err(e);
        }
    };

    let contact_id = decrypted.contact.id.clone();
    if store.messages.iter().any(|m| m.id == decrypted.message.message_id) {
        save_store_with_key(&app, &store, &store_key)?;
        let _ = transport::ack_envelopes(transport_state.clone(), server_id.clone(), vec![envelope.id]).await;
        runtime.seen_envelopes.lock().await.push_back((envelope_key, now_ms()));
        return Ok(());
    }

    let received_at = now_ms();
    let msg = StoredMessage {
        id: decrypted.message.message_id,
        contact_id: contact_id.clone(),
        mine: false,
        text: decrypted.message.body,
        timestamp: decrypted.message.sent_at_ms,
        received_at_ms: Some(received_at),
        status: "received".to_string(),
    };
    store.messages.push(msg.clone());

    // If this was a one-off invite mailbox, promote it to a contact route once
    // the first valid message lands, rather than keeping it as a reusable invite.
    if let Some(route) = store.local_routes.iter_mut().find(|r| r.id == local_route.id) {
        route.scope = format!("contact:{contact_id}");
        route.expires_at_ms = None;
    }
    for invite in &mut store.pending_invites {
        if invite.mailbox_id == local_route.mailbox_id { invite.expires_at_ms = received_at; }
    }
    cleanup_expired_routes(&mut store);

    save_store_with_key(&app, &store, &store_key)?;
    let _ = transport::ack_envelopes(transport_state.clone(), server_id.clone(), vec![envelope.id]).await;
    runtime.seen_envelopes.lock().await.push_back((envelope_key.clone(), now_ms()));
    runtime.failed_envelopes.lock().await.remove(&envelope_key);
    let _ = app.emit("axeno-message", IncomingMessageEvent { contact_id, message: msg });
    Ok(())
}

pub async fn mark_contact_verified(app: AppHandle, session: &AppSessionState, contact_id: String, verified: bool) -> Result<StoredContact, String> {
    let (store_key, legacy_store_key) = store_keys(session).await?;
    let mut store = load_store_with_keys(&app, &store_key, &legacy_store_key)?;
    let contact = store.contacts.iter_mut().find(|c| c.id == contact_id).ok_or_else(|| "contact not found".to_string())?;
    if contact.trust_state == "identity_changed_blocked" && verified {
        return Err("contact identity changed; re-add using a fresh code before verifying".into());
    }
    contact.trust_state = if verified { "verified" } else { "unverified" }.to_string();
    contact.verified_at_ms = if verified { Some(now_ms()) } else { None };
    let out = contact.clone();
    save_store_with_key(&app, &store, &store_key)?;
    Ok(out)
}

pub async fn mark_contact_read(app: AppHandle, session: &AppSessionState, contact_id: String) -> Result<StoredContact, String> {
    let (store_key, legacy_store_key) = store_keys(session).await?;
    let mut store = load_store_with_keys(&app, &store_key, &legacy_store_key)?;
    let contact = store.contacts.iter_mut().find(|c| c.id == contact_id).ok_or_else(|| "contact not found".to_string())?;
    contact.last_read_at = Some(now_ms());
    let out = contact.clone();
    save_store_with_key(&app, &store, &store_key)?;
    Ok(out)
}

pub async fn update_contact_server(_app: AppHandle, _session: &AppSessionState, _contact_id: String, _server_url: String) -> Result<StoredContact, String> {
    Err("changing a contact relay without a fresh connection code is unsafe; ask the contact for a new code".into())
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
        axeno_store: &mut MessagingStore,
        plaintext: &str,
        message_id: &str,
        sent_at_ms: u64,
        sender_certificate: &transport::SenderCertificateResponse,
    ) -> Result<EncryptedForRelay, String> {
        ensure_local_kyber_prekey(me, material, axeno_store)?;
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
        }

        let local_identity_public_b64 = STANDARD_NO_PAD.encode(&me.public_key);
        let plaintext_payload = encode_signal_plaintext(
            plaintext,
            &material.display_name,
            message_id,
            sent_at_ms,
            local_route,
            &local_identity_public_b64,
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
        let mut outer_store = sealed_sender_outer_store_for(local_route, contact, me.registration_id as u32).await?;
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
                safety_number: String::new(),
                trust_state: "unverified".to_string(),
                verified_at_ms: None,
                local_route_id: Some(local_route.id.clone()),
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

        if let Some(existing) = axeno_store.contacts.iter_mut().find(|c| c.recipient_id == contact.recipient_id) {
            existing.display_name = contact.display_name.clone().or_else(|| existing.display_name.clone());
            existing.server_url = if contact.server_url.is_empty() { existing.server_url.clone() } else { contact.server_url.clone() };
            existing.server_id = if contact.server_id.is_empty() { existing.server_id.clone() } else { contact.server_id.clone() };
            existing.identity_public_b64 = contact.identity_public_b64.clone();
            existing.device_id = contact.device_id;
            if !contact.delivery_token.is_empty() { existing.delivery_token = contact.delivery_token.clone(); }
            if existing.safety_number.is_empty() { existing.safety_number = contact.safety_number.clone(); }
            existing.local_route_id = Some(local_route.id.clone());
            contact = existing.clone();
        } else {
            contact.local_route_id = Some(local_route.id.clone());
            axeno_store.contacts.push(contact.clone());
        }

        persist_session(&protocol_store, axeno_store, &contact).await?;
        Ok(DecryptedEnvelope { contact, message: decoded })
    }

}
