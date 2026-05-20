#![forbid(unsafe_code)]
//! Axeno relay server.
//!
//! Relay duties:
//! - authenticate mailbox collection;
//! - delivery-token gate sending, with multiple per-mailbox tokens so clients can rotate/revoke per contact;
//! - issue short-lived libsignal SenderCertificate objects for per-route pseudonymous certificate keys;
//! - accept token-gated SendEnvelope frames even on unauthenticated sockets so clients can send over
//!   fresh/isolated WebSockets instead of linking sends to their receive mailbox socket;
//! - host opaque encrypted invite/prekey bundles under random handles;
//! - persist offline queues across relay restarts.
//!
//! The relay never receives plaintext. It can still observe transport metadata:
//! authenticated receive mailbox for the socket, destination mailbox, ciphertext
//! size, and timing. Clients should use per-contact mailboxes and Tor to reduce
//! cross-contact correlation; this relay is not a mixnet.

use std::{collections::VecDeque, fs, net::SocketAddr, path::PathBuf, sync::{Arc, atomic::{AtomicUsize, AtomicBool, Ordering}}, time::{SystemTime, UNIX_EPOCH}};

use axum::{
    extract::{ws::{Message, WebSocket, WebSocketUpgrade}, State},
    response::IntoResponse,
    routing::get,
    Router,
};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use dashmap::{mapref::entry::Entry, DashMap};
use futures_util::{SinkExt, StreamExt};
use libsignal_protocol::{KeyPair, PrivateKey, PublicKey, SenderCertificate, ServerCertificate, Timestamp};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{io::{AsyncBufReadExt, BufReader}, sync::mpsc};
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

const MAX_QUEUE_PER_RECIPIENT: usize = 200;
const MAX_FRAME_BYTES: usize = 512 * 1024;
const MAX_TOTAL_QUEUED_BYTES: usize = 64 * 1024 * 1024;
const PROTOCOL_MIN_SUPPORTED: u16 = 4;
const PROTOCOL_VERSION: u16 = 5;
const SENDER_CERT_TTL_MS: u64 = 24 * 60 * 60 * 1000;
const RATE_WINDOW_MS: u64 = 60 * 1000;
const MAX_FRAMES_PER_WINDOW: u32 = 600;
const MAX_MAILBOXES: usize = 50_000;
const MAX_DELIVERY_TOKENS_PER_MAILBOX: usize = 64;
const MAX_BUNDLES: usize = 50_000;
const MAX_BUNDLE_BYTES: usize = 16 * 1024;
const MAX_BUNDLE_TTL_MS: u64 = 48 * 60 * 60 * 1000;
const OUTBOUND_QUEUE_CAPACITY: usize = 256;
const MAX_SENDS_PER_DEST_PER_WINDOW: u32 = 30;

type RecipientId = String;
type ClientTx = mpsc::Sender<ServerFrame>;

#[derive(Clone)]
struct AppState {
    queues: Arc<DashMap<RecipientId, VecDeque<StoredEnvelope>>>,
    online: Arc<DashMap<RecipientId, ClientTx>>,
    mailbox_auth: Arc<DashMap<RecipientId, MailboxAuth>>,
    mailbox_count: Arc<AtomicUsize>,
    bundles: Arc<DashMap<String, HostedBundle>>,
    total_queued_bytes: Arc<AtomicUsize>,
    crypto: Arc<ServerCrypto>,
    /// Original disk crypto key material, cached at startup for snapshot_disk_state.
    disk_crypto: Arc<DiskCrypto>,
    data_dir: Arc<PathBuf>,
    dirty: Arc<AtomicBool>,
}

struct ServerCrypto {
    trust_root_public_b64: String,
    server_certificate: ServerCertificate,
    server_signing_private: PrivateKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MailboxAuth {
    receive_auth_hash: String,
    #[serde(default)]
    delivery_token_hash: String,
    #[serde(default)]
    delivery_token_hashes: Vec<String>,
}

impl MailboxAuth {
    fn new(receive_auth_hash: String, delivery_hash: String) -> Self {
        Self {
            receive_auth_hash,
            delivery_token_hash: delivery_hash.clone(),
            delivery_token_hashes: vec![delivery_hash],
        }
    }

    fn accepts_delivery_hash(&self, hash: &str) -> bool {
        self.delivery_token_hash == hash || self.delivery_token_hashes.iter().any(|h| h == hash)
    }

    fn ensure_delivery_hash(&mut self, hash: String) -> bool {
        if self.delivery_token_hash.is_empty() {
            self.delivery_token_hash = hash.clone();
        }
        if self.delivery_token_hashes.iter().any(|h| h == &hash) {
            return false;
        }
        if self.delivery_token_hashes.len() >= MAX_DELIVERY_TOKENS_PER_MAILBOX {
            self.delivery_token_hashes.remove(0);
        }
        self.delivery_token_hashes.push(hash);
        true
    }

    fn replace_delivery_hashes(&mut self, hashes: Vec<String>) {
        let mut out = Vec::new();
        for hash in hashes.into_iter().take(MAX_DELIVERY_TOKENS_PER_MAILBOX) {
            if !out.iter().any(|h| h == &hash) { out.push(hash); }
        }
        self.delivery_token_hash = out.first().cloned().unwrap_or_default();
        self.delivery_token_hashes = out;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HostedBundle {
    id: String,
    ciphertext: String,
    created_at_ms: u64,
    expires_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct DiskState {
    /// Plaintext crypto keys (legacy / when AXENO_KEY is not set).
    crypto: Option<DiskCrypto>,
    /// Encrypted crypto keys (when AXENO_KEY is set). Contains a JSON-serialized
    /// DiskCrypto encrypted with ChaCha20Poly1305 using a key derived from
    /// AXENO_KEY via Argon2id.
    #[serde(default)]
    encrypted_crypto: Option<EncryptedCryptoBlob>,
    mailbox_auth: Vec<(RecipientId, MailboxAuth)>,
    #[serde(default)]
    queues: Vec<(RecipientId, Vec<StoredEnvelope>)>,
    #[serde(default)]
    bundles: Vec<HostedBundle>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedCryptoBlob {
    /// Argon2id salt (16 bytes, hex-encoded).
    salt: String,
    /// ChaCha20Poly1305 nonce (12 bytes, hex-encoded).
    nonce: String,
    /// Encrypted DiskCrypto JSON (hex-encoded).
    ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DiskCrypto {
    trust_root_public: Vec<u8>,
    trust_root_private: Vec<u8>,
    server_signing_public: Vec<u8>,
    server_signing_private: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredEnvelope {
    id: Uuid,
    to: RecipientId,
    envelope_type: String,
    ciphertext: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientFrame {
    Hello {
        recipient_id: RecipientId,
        auth_token: String,
        delivery_token: String,
        #[serde(default)] protocol_min: Option<u16>,
        #[serde(default)] protocol_max: Option<u16>,
        #[serde(default)] protocol_version: Option<u16>,
        #[serde(default)] pow: Option<String>,
        #[serde(default)] cert_only: bool,
    },
    SetDeliveryTokens { request_id: String, tokens: Vec<String> },
    IssueSenderCertificate { request_id: String, sender_uuid: String, sender_device_id: u32, sender_cert_public_b64: String },
    SendEnvelope { #[serde(default)] client_ref: Option<String>, to: RecipientId, delivery_token: String, envelope_type: String, ciphertext: String },
    UploadBundle { request_id: String, bundle_id: String, ciphertext: String, expires_at_ms: u64 },
    FetchBundle { request_id: String, bundle_id: String },
    Ack { ids: Vec<Uuid> },
    RetireMailbox,
    Ping,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerFrame {
    HelloOk { protocol_version: u16, min_supported: u16, current_protocol: u16, server_time_ms: u64, trust_root_b64: String },
    SenderCertificate { request_id: String, certificate_b64: String, trust_root_b64: String, expires_at_ms: u64 },
    BundleUploaded { request_id: String, bundle_id: String, expires_at_ms: u64 },
    Bundle { request_id: String, bundle_id: String, ciphertext: String, expires_at_ms: u64 },
    Envelope { envelope: StoredEnvelope },
    SendOk { id: Uuid, queued: bool, client_ref: Option<String> },
    SendError { client_ref: Option<String>, code: String, message: String },
    DeliveryTokensSet { request_id: String, active_count: usize },
    AckOk { removed: usize },
    Pong { server_time_ms: u64 },
    Error { code: String, message: String },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env().add_directive("axeno_server=debug".parse()?))
        .init();

    let bind = std::env::var("AXENO_BIND").unwrap_or_else(|_| "127.0.0.1:8787".to_string());
    let addr: SocketAddr = bind.parse()?;
    let data_dir = PathBuf::from(std::env::var("AXENO_DATA_DIR").unwrap_or_else(|_| "axeno-relay-data".to_string()));
    fs::create_dir_all(&data_dir)?;
    let mut disk = load_disk_state(&data_dir)?;
    let crypto = init_server_crypto(&mut disk)?;
    prune_disk_state(&mut disk);
    save_disk_state(&data_dir, &disk)?;

    let mailbox_auth = Arc::new(DashMap::new());
    for (rid, auth) in disk.mailbox_auth.iter().cloned() {
        mailbox_auth.insert(rid, auth);
    }

    let queues = Arc::new(DashMap::new());
    let mut queued_bytes = 0usize;
    for (rid, queue) in disk.queues.iter().cloned() {
        let queue: VecDeque<StoredEnvelope> = queue.into_iter().collect();
        queued_bytes = queued_bytes.saturating_add(queue.iter().map(|e| e.ciphertext.len()).sum::<usize>());
        queues.insert(rid, queue);
    }

    let bundles = Arc::new(DashMap::new());
    for bundle in disk.bundles.iter().cloned() {
        bundles.insert(bundle.id.clone(), bundle);
    }

    let disk_crypto_cached = disk.crypto.clone().expect("crypto must be initialized before building AppState");
    let dirty = Arc::new(AtomicBool::new(false));
    let state = AppState {
        queues,
        online: Arc::new(DashMap::new()),
        mailbox_count: Arc::new(AtomicUsize::new(mailbox_auth.len())),
        mailbox_auth,
        bundles,
        total_queued_bytes: Arc::new(AtomicUsize::new(queued_bytes)),
        crypto: Arc::new(crypto),
        disk_crypto: Arc::new(disk_crypto_cached),
        data_dir: Arc::new(data_dir.clone()),
        dirty: dirty.clone(),
    };

    let state_for_bg = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            interval.tick().await;
            if state_for_bg.dirty.swap(false, Ordering::Relaxed) {
                if let Ok(disk) = snapshot_disk_state(&state_for_bg) {
                    let data_dir = state_for_bg.data_dir.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        let _ = save_disk_state(&data_dir, &disk);
                    }).await;
                }
            }
        }
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/ws", get(ws_handler))
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(%addr, "Axeno relay listening");

    if addr.ip().is_loopback() {
        if let Err(e) = start_tor_hidden_service(addr.port(), &data_dir).await {
            warn!("Failed to start automatic Tor hidden service: {}", e);
        }
    } else {
        info!("Server is bound to public IP; skipping automatic Tor hidden service creation.");
    }

    axum::serve(listener, app).await?;
    Ok(())
}

async fn start_tor_hidden_service(port: u16, data_dir: &std::path::Path) -> anyhow::Result<()> {
    if tokio::process::Command::new("tor").arg("--version").output().await.is_err() {
        warn!("Tor is not installed or not in PATH. Skipping automatic Hidden Service creation.");
        warn!("To run over Tor, please install tor (e.g. `apt install tor`) and restart the server.");
        return Ok(());
    }

    let tor_dir = data_dir.join("tor");
    let hs_dir = tor_dir.join("hs");
    let torrc_path = tor_dir.join("torrc");

    fs::create_dir_all(&hs_dir)?;
    
    // Set strict permissions on the hidden service directory (Tor requires 0700)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&hs_dir, fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(&tor_dir, fs::Permissions::from_mode(0o700))?;
    }

    let torrc_content = format!(
        "DataDirectory {data_dir}\n\
         HiddenServiceDir {hs_dir}\n\
         HiddenServiceVersion 3\n\
         HiddenServicePort 80 127.0.0.1:{port}\n\
         SocksPort 0\n\
         Log notice stdout\n",
        data_dir = tor_dir.display(),
        hs_dir = hs_dir.display(),
        port = port
    );
    fs::write(&torrc_path, torrc_content)?;

    info!("Starting Tor daemon for automatic Hidden Service...");
    
    let pid = std::process::id();
    let mut child = tokio::process::Command::new("tor")
        .arg("-f")
        .arg(&torrc_path)
        .arg("__OwningControllerProcess")
        .arg(pid.to_string())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;

    let hs_dir_clone = hs_dir.clone();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    tokio::spawn(async move {
        let Some(stdout) = stdout else { return; };
        let mut lines = BufReader::new(stdout).lines();
        let mut announced = false;
        while let Ok(Some(line)) = lines.next_line().await {
            info!("tor: {}", line);
            if announced || !line.contains("Bootstrapped 100%") {
                continue;
            }

            let hostname_path = hs_dir_clone.join("hostname");
            for _ in 0..30 {
                if let Ok(hostname) = fs::read_to_string(&hostname_path) {
                    info!("==================================================");
                    info!("Tor Hidden Service bootstrapped.");
                    info!("Your relay onion address is: ws://{}/ws", hostname.trim());
                    info!("==================================================");
                    if let Ok(pwd) = std::env::current_dir() {
                        let _ = fs::write(pwd.join("onion_address.txt"), format!("ws://{}/ws", hostname.trim()));
                    }
                    announced = true;
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
            }
            if !announced {
                warn!("Tor bootstrapped, but the hidden service hostname file was not available in time.");
            }
        }
    });

    tokio::spawn(async move {
        let Some(stderr) = stderr else { return; };
        let mut lines = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            warn!("tor: {}", line);
        }
    });

    tokio::spawn(async move {
        let _ = child.wait().await;
        warn!("Tor daemon process exited.");
    });

    Ok(())
}

fn init_server_crypto(disk: &mut DiskState) -> anyhow::Result<ServerCrypto> {
    let mut rng = fresh_rng()?;
    let (trust_root, server_signing) = if let Some(saved) = disk.crypto.as_ref() {
        (
            KeyPair::from_public_and_private(&saved.trust_root_public, &saved.trust_root_private)?,
            KeyPair::from_public_and_private(&saved.server_signing_public, &saved.server_signing_private)?,
        )
    } else {
        let trust_root = KeyPair::generate(&mut rng);
        let server_signing = KeyPair::generate(&mut rng);
        disk.crypto = Some(DiskCrypto {
            trust_root_public: trust_root.public_key.serialize().to_vec(),
            trust_root_private: trust_root.private_key.serialize().to_vec(),
            server_signing_public: server_signing.public_key.serialize().to_vec(),
            server_signing_private: server_signing.private_key.serialize().to_vec(),
        });
        (trust_root, server_signing)
    };
    let server_certificate = ServerCertificate::new(1, server_signing.public_key, &trust_root.private_key, &mut rng)?;
    Ok(ServerCrypto {
        trust_root_public_b64: STANDARD_NO_PAD.encode(trust_root.public_key.serialize()),
        server_certificate,
        server_signing_private: server_signing.private_key,
    })
}

fn disk_state_path(data_dir: &PathBuf) -> PathBuf { data_dir.join("relay-state.json") }

/// Derive a 32-byte encryption key from the AXENO_KEY env var using Argon2id.
fn derive_key_from_env(env_key: &str, salt: &[u8]) -> anyhow::Result<[u8; 32]> {
    use argon2::Argon2;
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(env_key.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow::anyhow!("Argon2id derivation failed: {e}"))?;
    Ok(key)
}

/// Encrypt a DiskCrypto struct with the given passphrase.
fn encrypt_disk_crypto(crypto: &DiskCrypto, env_key: &str) -> anyhow::Result<EncryptedCryptoBlob> {
    use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Key, Nonce};

    let mut salt = [0u8; 16];
    getrandom::getrandom(&mut salt)?;
    let key_bytes = derive_key_from_env(env_key, &salt)?;
    let key = Key::from_slice(&key_bytes);
    let cipher = ChaCha20Poly1305::new(key);

    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes)?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = serde_json::to_vec(crypto)?;
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())
        .map_err(|e| anyhow::anyhow!("ChaCha20Poly1305 encrypt failed: {e}"))?;

    Ok(EncryptedCryptoBlob {
        salt: hex::encode(salt),
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(ciphertext),
    })
}

/// Decrypt an EncryptedCryptoBlob with the given passphrase.
fn decrypt_disk_crypto(blob: &EncryptedCryptoBlob, env_key: &str) -> anyhow::Result<DiskCrypto> {
    use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Key, Nonce};

    let salt = hex::decode(&blob.salt)?;
    let key_bytes = derive_key_from_env(env_key, &salt)?;
    let key = Key::from_slice(&key_bytes);
    let cipher = ChaCha20Poly1305::new(key);

    let nonce_bytes = hex::decode(&blob.nonce)?;
    if nonce_bytes.len() != 12 { return Err(anyhow::anyhow!("invalid nonce length")); }
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = hex::decode(&blob.ciphertext)?;
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| anyhow::anyhow!("failed to decrypt relay keys — is AXENO_KEY correct?"))?;

    Ok(serde_json::from_slice(&plaintext)?)
}

/// Read the optional AXENO_KEY env var for at-rest key encryption.
fn relay_encryption_key() -> Option<String> {
    std::env::var("AXENO_KEY").ok().filter(|k| !k.is_empty())
}

fn load_disk_state(data_dir: &PathBuf) -> anyhow::Result<DiskState> {
    let path = disk_state_path(data_dir);
    if !path.exists() { return Ok(DiskState::default()); }
    let raw = fs::read(path)?;
    let mut state: DiskState = serde_json::from_slice(&raw)?;

    // If we have encrypted crypto and an AXENO_KEY, decrypt it into the
    // plaintext crypto field for use by init_server_crypto.
    if let (Some(blob), Some(env_key)) = (&state.encrypted_crypto, relay_encryption_key()) {
        let crypto = decrypt_disk_crypto(blob, &env_key)?;
        state.crypto = Some(crypto);
        info!("relay private keys decrypted from encrypted_crypto");
    } else if state.encrypted_crypto.is_some() && relay_encryption_key().is_none() {
        return Err(anyhow::anyhow!(
            "relay-state.json contains encrypted keys but AXENO_KEY is not set. \
             Set AXENO_KEY to the same value used when the keys were encrypted."
        ));
    }

    // Migration: if we have plaintext crypto and AXENO_KEY is set, warn that
    // keys will be encrypted on next save.
    if state.crypto.is_some() && state.encrypted_crypto.is_none() && relay_encryption_key().is_some() {
        warn!("plaintext relay keys will be encrypted on next save (AXENO_KEY migration)");
    }

    Ok(state)
}

fn save_disk_state(data_dir: &PathBuf, state: &DiskState) -> anyhow::Result<()> {
    let path = disk_state_path(data_dir);
    let tmp = path.with_file_name(format!(
        "{}.{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("relay-state.json"),
        Uuid::new_v4()
    ));
    let raw = serde_json::to_vec_pretty(state)?;

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(&raw)?;
        file.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        file.write_all(&raw)?;
        file.sync_all()?;
    }

    if let Err(e) = fs::rename(&tmp, &path) {
        let _ = fs::remove_file(&tmp);
        return Err(e.into());
    }
    #[cfg(unix)]
    {
        if let Ok(dir) = fs::File::open(data_dir) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

fn prune_disk_state(disk: &mut DiskState) {
    let now = now_ms();
    disk.bundles.retain(|b| b.expires_at_ms > now);
    for (_, auth) in &mut disk.mailbox_auth {
        if auth.delivery_token_hashes.is_empty() && !auth.delivery_token_hash.is_empty() {
            auth.delivery_token_hashes.push(auth.delivery_token_hash.clone());
        }
    }
}

fn snapshot_disk_state(state: &AppState) -> anyhow::Result<DiskState> {
    // Build entirely from in-memory state. The crypto key material is cached
    // at startup in state.disk_crypto and never mutated, so we do not need to
    // re-read the disk file. Re-reading could silently introduce corrupted or
    // externally modified key material while overwriting the auth/queue data.
    let disk_crypto = (*state.disk_crypto).clone();
    let mut disk = DiskState {
        crypto: None,
        encrypted_crypto: None,
        mailbox_auth: state.mailbox_auth.iter().map(|entry| (entry.key().clone(), entry.value().clone())).collect(),
        queues: state.queues.iter().map(|entry| (entry.key().clone(), entry.value().iter().cloned().collect())).collect(),
        bundles: state.bundles.iter().map(|entry| entry.value().clone()).collect(),
    };

    // When AXENO_KEY is set, encrypt the private keys before writing to disk.
    // The plaintext crypto field is left empty so private keys never hit disk
    // in the clear.
    if let Some(env_key) = relay_encryption_key() {
        disk.encrypted_crypto = Some(encrypt_disk_crypto(&disk_crypto, &env_key)?);
        // Deliberately leave disk.crypto = None so plaintext keys are not written.
    } else {
        disk.crypto = Some(disk_crypto);
    }

    prune_disk_state(&mut disk);
    Ok(disk)
}

fn persist_runtime_state(state: &AppState) {
    state.dirty.store(true, Ordering::Relaxed);
}

fn fresh_rng() -> anyhow::Result<ChaCha20Rng> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed)?;
    Ok(ChaCha20Rng::from_seed(seed))
}

fn try_reserve_mailbox_slot(state: &AppState) -> bool {
    loop {
        let current = state.mailbox_count.load(Ordering::Relaxed);
        if current >= MAX_MAILBOXES { return false; }
        if state.mailbox_count.compare_exchange(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ).is_ok() {
            return true;
        }
    }
}

async fn health() -> &'static str { "ok" }

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.max_message_size(MAX_FRAME_BYTES).on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: AppState) {
    let (mut sender, mut receiver) = socket.split();
    let (tx, mut rx) = mpsc::channel::<ServerFrame>(OUTBOUND_QUEUE_CAPACITY);

    let writer = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            match serde_json::to_string(&frame) {
                Ok(text) => { if sender.send(Message::Text(text.into())).await.is_err() { break; } }
                Err(e) => error!(?e, "failed to serialize server frame"),
            }
        }
    });

    let mut recipient_id: Option<RecipientId> = None;
    let mut window_start_ms = now_ms();
    let mut frame_count: u32 = 0;
    // Per-destination send rate limiting for this socket. Keyed by destination
    // mailbox, counts sends in the current window to prevent mailbox flooding.
    let mut dest_send_counts: std::collections::HashMap<String, u32> = std::collections::HashMap::new();

    while let Some(incoming) = receiver.next().await {
        let Ok(msg) = incoming else { break; };
        let Message::Text(text) = msg else { continue; };
        let now = now_ms();
        if now.saturating_sub(window_start_ms) > RATE_WINDOW_MS {
            window_start_ms = now;
            frame_count = 0;
            dest_send_counts.clear();
        }
        frame_count = frame_count.saturating_add(1);
        if frame_count > MAX_FRAMES_PER_WINDOW { let _ = tx.try_send(err("rate_limited", "too many frames on this socket")); continue; }
        if text.len() > MAX_FRAME_BYTES { let _ = tx.try_send(err("too_large", "frame too large")); continue; }

        let frame = match serde_json::from_str::<ClientFrame>(&text) {
            Ok(frame) => frame,
            Err(e) => { let _ = tx.try_send(err("bad_json", &e.to_string())); continue; }
        };

        match frame {
            ClientFrame::Hello { recipient_id: rid, auth_token, delivery_token, protocol_min, protocol_max, protocol_version, pow, cert_only } => {
                let client_min = protocol_min.unwrap_or(protocol_version.unwrap_or(PROTOCOL_VERSION));
                let client_max = protocol_max.unwrap_or(protocol_version.unwrap_or(PROTOCOL_VERSION));
                let selected = PROTOCOL_VERSION.min(client_max);
                if selected < PROTOCOL_MIN_SUPPORTED || selected < client_min {
                    let _ = tx.try_send(err("protocol_mismatch", "no common relay protocol version"));
                    continue;
                }
                if !valid_recipient_id(&rid) || !valid_token(&auth_token) || !valid_token(&delivery_token) {
                    let _ = tx.try_send(err("bad_hello", "invalid mailbox or token"));
                    continue;
                }
                let auth_hash = token_hash(&auth_token);
                let delivery_hash = token_hash(&delivery_token);
                let changed = match state.mailbox_auth.entry(rid.clone()) {
                    Entry::Occupied(mut existing) => {
                        if existing.get().receive_auth_hash != auth_hash {
                            let _ = tx.try_send(err("auth_failed", "mailbox auth failed"));
                            continue;
                        }
                        existing.get_mut().ensure_delivery_hash(delivery_hash)
                    }
                    Entry::Vacant(vacant) => {
                        let valid_pow = pow.as_deref().map(|n| verify_pow(&rid, n)).unwrap_or(false);
                        if !valid_pow {
                            let _ = tx.try_send(err("bad_pow", "invalid proof of work for new mailbox"));
                            continue;
                        }
                        if !try_reserve_mailbox_slot(&state) {
                            let _ = tx.try_send(err("relay_full", "relay mailbox limit reached"));
                            continue;
                        }
                        vacant.insert(MailboxAuth::new(auth_hash, delivery_hash));
                        true
                    }
                };
                if changed { persist_runtime_state(&state); }
                recipient_id = Some(rid.clone());
                let _ = tx.try_send(ServerFrame::HelloOk {
                    protocol_version: selected,
                    min_supported: PROTOCOL_MIN_SUPPORTED,
                    current_protocol: PROTOCOL_VERSION,
                    server_time_ms: now_ms(),
                    trust_root_b64: state.crypto.trust_root_public_b64.clone(),
                });
                if !cert_only {
                    state.online.insert(rid.clone(), tx.clone());
                    flush_queue(&state, &rid, &tx);
                }
            }
            ClientFrame::SetDeliveryTokens { request_id, tokens } => {
                let Some(rid) = recipient_id.as_ref() else { let _ = tx.try_send(err("not_registered", "send hello first")); continue; };
                if tokens.is_empty() || tokens.len() > MAX_DELIVERY_TOKENS_PER_MAILBOX || !tokens.iter().all(|t| valid_token(t)) {
                    let _ = tx.try_send(err("bad_tokens", "invalid delivery-token allowlist"));
                    continue;
                }
                if let Some(mut auth) = state.mailbox_auth.get_mut(rid) {
                    auth.replace_delivery_hashes(tokens.iter().map(|t| token_hash(t)).collect());
                    let active_count = auth.delivery_token_hashes.len();
                    drop(auth);
                    persist_runtime_state(&state);
                    let _ = tx.try_send(ServerFrame::DeliveryTokensSet { request_id, active_count });
                } else {
                    let _ = tx.try_send(err("not_registered", "mailbox auth missing"));
                }
            }
            ClientFrame::IssueSenderCertificate { request_id, sender_uuid, sender_device_id, sender_cert_public_b64 } => {
                let Some(registered_rid) = recipient_id.as_ref() else {
                    let _ = tx.try_send(err("not_registered", "send hello first"));
                    continue;
                };
                if &sender_uuid != registered_rid {
                    let _ = tx.try_send(err("cert_denied", "sender certificate can only be issued for your authenticated mailbox"));
                    continue;
                }
                match issue_sender_certificate(&state, request_id, sender_uuid, sender_device_id, sender_cert_public_b64) {
                    Ok(frame) => { let _ = tx.try_send(frame); }
                    Err(e) => { let _ = tx.try_send(err("cert_failed", &e)); }
                }
            }
            ClientFrame::SendEnvelope { client_ref, to, delivery_token, envelope_type, ciphertext } => {
                if !valid_recipient_id(&to) || !valid_token(&delivery_token) {
                    let _ = tx.try_send(send_err(client_ref, "bad_send", "invalid destination or delivery token"));
                    continue;
                }
                // Per-destination send rate limit to mitigate mailbox flooding
                // by holders of a known delivery token.
                let dest_count = dest_send_counts.entry(to.clone()).or_insert(0);
                *dest_count = dest_count.saturating_add(1);
                if *dest_count > MAX_SENDS_PER_DEST_PER_WINDOW {
                    let _ = tx.try_send(send_err(client_ref, "rate_limited", "too many sends to this destination"));
                    continue;
                }
                if envelope_type.len() > 32 || ciphertext.len() > MAX_FRAME_BYTES {
                    let _ = tx.try_send(send_err(client_ref, "bad_envelope", "envelope rejected by size/type limits"));
                    continue;
                }
                let Some(auth) = state.mailbox_auth.get(&to) else {
                    let _ = tx.try_send(send_err(client_ref, "delivery_denied", "delivery token rejected"));
                    continue;
                };
                if !auth.accepts_delivery_hash(&token_hash(&delivery_token)) {
                    let _ = tx.try_send(send_err(client_ref, "delivery_denied", "delivery token rejected"));
                    continue;
                }
                drop(auth);
                if state.total_queued_bytes.load(Ordering::Relaxed).saturating_add(ciphertext.len()) > MAX_TOTAL_QUEUED_BYTES {
                    let _ = tx.try_send(send_err(client_ref, "relay_full", "relay queue memory limit reached"));
                    continue;
                }

                let env = StoredEnvelope { id: Uuid::new_v4(), to: to.clone(), envelope_type, ciphertext };
                let delivered_live = if let Some(live) = state.online.get(&to) {
                    let sent = live.try_send(ServerFrame::Envelope { envelope: env.clone() }).is_ok();
                    drop(live);
                    if !sent {
                        // The relay had a stale socket registered for this mailbox. Do not
                        // pretend live delivery happened; remove it so the next connection
                        // can become the live route and keep the envelope queued.
                        state.online.remove(&to);
                    }
                    sent
                } else {
                    false
                };

                {
                    let mut queue = state.queues.entry(to).or_default();
                    while queue.len() >= MAX_QUEUE_PER_RECIPIENT {
                        if let Some(old) = queue.pop_front() {
                            state.total_queued_bytes.fetch_sub(old.ciphertext.len(), Ordering::Relaxed);
                        }
                    }
                    state.total_queued_bytes.fetch_add(env.ciphertext.len(), Ordering::Relaxed);
                    queue.push_back(env.clone());
                }

                // Important: do not call persist_runtime_state while holding the
                // DashMap queue entry guard above. snapshot_disk_state iterates the
                // same DashMap; holding an entry/ref guard and then re-entering the
                // map can self-deadlock the relay before SendOk is emitted. On
                // localhost this presents exactly as messages sitting at "sending"
                // forever and the recipient never seeing queued envelopes.
                persist_runtime_state(&state);
                let _ = tx.try_send(ServerFrame::SendOk { id: env.id, queued: !delivered_live, client_ref });
            }
            ClientFrame::UploadBundle { request_id, bundle_id, ciphertext, expires_at_ms } => {
                if !valid_bundle_id(&bundle_id) || ciphertext.len() > MAX_BUNDLE_BYTES {
                    let _ = tx.try_send(err("bad_bundle", "invalid invite bundle"));
                    continue;
                }
                if state.bundles.len() >= MAX_BUNDLES {
                    let _ = tx.try_send(err("relay_full", "relay invite bundle limit reached"));
                    continue;
                }
                let now = now_ms();
                let max_expires = now.saturating_add(MAX_BUNDLE_TTL_MS);
                let expires = expires_at_ms.min(max_expires).max(now.saturating_add(60_000));
                prune_expired_bundles(&state);
                let bundle = HostedBundle { id: bundle_id.clone(), ciphertext, created_at_ms: now, expires_at_ms: expires };
                state.bundles.insert(bundle_id.clone(), bundle);
                persist_runtime_state(&state);
                let _ = tx.try_send(ServerFrame::BundleUploaded { request_id, bundle_id, expires_at_ms: expires });
            }
            ClientFrame::FetchBundle { request_id, bundle_id } => {
                prune_expired_bundles(&state);
                match state.bundles.get(&bundle_id) {
                    Some(bundle) => {
                        let _ = tx.try_send(ServerFrame::Bundle { request_id, bundle_id: bundle.id.clone(), ciphertext: bundle.ciphertext.clone(), expires_at_ms: bundle.expires_at_ms });
                    }
                    None => { let _ = tx.try_send(err("bundle_not_found", "invite bundle was not found or has expired")); }
                }
            }
            ClientFrame::Ack { ids } => {
                let Some(rid) = recipient_id.as_ref() else { let _ = tx.try_send(err("not_registered", "send hello first")); continue; };
                let removed = remove_acked(&state, rid, &ids);
                if removed > 0 { persist_runtime_state(&state); }
                let _ = tx.try_send(ServerFrame::AckOk { removed });
            }
            ClientFrame::RetireMailbox => {
                let Some(rid) = recipient_id.as_ref() else { let _ = tx.try_send(err("not_registered", "send hello first")); continue; };
                if state.mailbox_auth.remove(rid).is_some() {
                    state.mailbox_count.fetch_sub(1, Ordering::Relaxed);
                }
                if let Some((_, queue)) = state.queues.remove(rid) {
                    let freed: usize = queue.iter().map(|e| e.ciphertext.len()).sum();
                    state.total_queued_bytes.fetch_sub(freed, Ordering::Relaxed);
                }
                state.online.remove(rid);
                persist_runtime_state(&state);
                let _ = tx.try_send(ServerFrame::AckOk { removed: 0 });
                break;
            }
            ClientFrame::Ping => { let _ = tx.try_send(ServerFrame::Pong { server_time_ms: now_ms() }); }
        }
    }

    if let Some(rid) = recipient_id {
        // Only remove the online entry if it still points at this socket. A fast
        // reconnect can install a newer sender before the old socket finishes
        // unwinding; unconditional remove would make the relay think the mailbox
        // is offline and messages would sit queued until another reconnect.
        let remove_this_socket = state
            .online
            .get(&rid)
            .map(|live| live.same_channel(&tx))
            .unwrap_or(false);
        if remove_this_socket {
            state.online.remove(&rid);
        }
    }
    writer.abort();
    debug!("websocket disconnected");
}

fn issue_sender_certificate(state: &AppState, request_id: String, sender_uuid: String, sender_device_id: u32, sender_cert_public_b64: String) -> Result<ServerFrame, String> {
    if !valid_recipient_id(&sender_uuid) || sender_device_id == 0 || sender_device_id > 127 {
        return Err("invalid sender certificate request".into());
    }
    if sender_cert_public_b64.len() > 64 {
        return Err("sender certificate public key is too large".into());
    }
    let cert_key_bytes = STANDARD_NO_PAD.decode(sender_cert_public_b64.as_bytes()).map_err(|_| "bad sender certificate public key encoding".to_string())?;
    let sender_public = PublicKey::deserialize(&cert_key_bytes).map_err(|e| format!("bad sender certificate public key: {e}"))?;
    let mut rng = fresh_rng().map_err(|e| e.to_string())?;
    let expires_at_ms = now_ms().saturating_add(SENDER_CERT_TTL_MS);
    let sender_device = sender_device_id.try_into().map_err(|_| "bad device id".to_string())?;
    let cert = SenderCertificate::new(
        sender_uuid,
        None,
        sender_public,
        sender_device,
        Timestamp::from_epoch_millis(expires_at_ms),
        state.crypto.server_certificate.clone(),
        &state.crypto.server_signing_private,
        &mut rng,
    ).map_err(|e| format!("sender certificate signing failed: {e}"))?;
    let cert_b64 = STANDARD_NO_PAD.encode(cert.serialized().map_err(|e| format!("could not serialize sender certificate: {e}"))?);
    Ok(ServerFrame::SenderCertificate { request_id, certificate_b64: cert_b64, trust_root_b64: state.crypto.trust_root_public_b64.clone(), expires_at_ms })
}

fn err(code: &str, message: &str) -> ServerFrame { ServerFrame::Error { code: code.into(), message: message.into() } }
fn send_err(client_ref: Option<String>, code: &str, message: &str) -> ServerFrame {
    ServerFrame::SendError { client_ref, code: code.into(), message: message.into() }
}

fn flush_queue(state: &AppState, rid: &str, tx: &ClientTx) {
    if let Some(queue) = state.queues.get(rid) {
        for env in queue.iter() {
            if tx.try_send(ServerFrame::Envelope { envelope: env.clone() }).is_err() { break; }
        }
    }
}

fn remove_acked(state: &AppState, rid: &str, ids: &[Uuid]) -> usize {
    let Some(mut queue) = state.queues.get_mut(rid) else { return 0; };
    let before = queue.len();
    let mut freed = 0usize;
    let ids_set: std::collections::HashSet<_> = ids.iter().collect();
    queue.retain(|env| {
        let remove = ids_set.contains(&env.id);
        if remove { freed += env.ciphertext.len(); }
        !remove
    });
    state.total_queued_bytes.fetch_sub(freed, Ordering::Relaxed);
    before - queue.len()
}

fn prune_expired_bundles(state: &AppState) {
    let now = now_ms();
    let expired: Vec<String> = state.bundles.iter()
        .filter(|entry| entry.value().expires_at_ms <= now)
        .map(|entry| entry.key().clone())
        .collect();
    if !expired.is_empty() {
        for id in expired { state.bundles.remove(&id); }
        persist_runtime_state(state);
    }
}

fn valid_recipient_id(id: &str) -> bool {
    id.starts_with("mbx_")
        && (36..=128).contains(&id.len())
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

fn valid_bundle_id(id: &str) -> bool {
    (16..=128).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

fn valid_token(token: &str) -> bool {
    (16..=128).contains(&token.len()) && token.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

fn verify_pow(recipient_id: &str, nonce: &str) -> bool {
    use std::time::{SystemTime, UNIX_EPOCH};
    let current_window = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() / 600;

    // Accept time-bound format: "ts_window:nonce"
    if let Some((ts_str, nonce_part)) = nonce.split_once(':') {
        if let Ok(ts_window) = ts_str.parse::<u64>() {
            // Accept current window and previous window (20 minutes total validity)
            if ts_window != current_window && ts_window != current_window.saturating_sub(1) {
                return false;
            }
            let input = format!("{recipient_id}:{ts_window}:{nonce_part}");
            let hash = Sha256::digest(input.as_bytes());
            return hash[0] == 0 && hash[1] == 0;
        }
    }

    false
}

fn token_hash(token: &str) -> String { hex::encode(Sha256::digest(token.as_bytes())) }
fn now_ms() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64 }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_defaults_to_live_receive_socket() {
        let frame = serde_json::from_str::<ClientFrame>(r#"{
            "type":"hello",
            "recipient_id":"mbx_receiver_1234567890",
            "auth_token":"auth_token_123456",
            "delivery_token":"delivery_token_123456"
        }"#).unwrap();

        match frame {
            ClientFrame::Hello { cert_only, .. } => assert!(!cert_only),
            _ => panic!("expected hello frame"),
        }
    }

    #[test]
    fn hello_can_be_certificate_only() {
        let frame = serde_json::from_str::<ClientFrame>(r#"{
            "type":"hello",
            "recipient_id":"mbx_receiver_1234567890",
            "auth_token":"auth_token_123456",
            "delivery_token":"delivery_token_123456",
            "cert_only":true
        }"#).unwrap();

        match frame {
            ClientFrame::Hello { cert_only, .. } => assert!(cert_only),
            _ => panic!("expected hello frame"),
        }
    }
}
