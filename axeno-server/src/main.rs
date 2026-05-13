//! Axeno relay server.
//!
//! Relay duties:
//! - authenticate mailbox collection;
//! - delivery-token gate sending;
//! - issue short-lived libsignal SenderCertificate objects;
//! - store/forward sealed-sender ciphertext only.
//!
//! The relay must not receive sender identity during message delivery. Sender
//! identity is only visible when a client explicitly requests a sender
//! certificate for its authenticated mailbox.

use std::{collections::VecDeque, net::SocketAddr, sync::{Arc, atomic::{AtomicUsize, Ordering}}, time::{SystemTime, UNIX_EPOCH}};

use axum::{
    extract::{ws::{Message, WebSocket, WebSocketUpgrade}, State},
    response::IntoResponse,
    routing::get,
    Router,
};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use libsignal_protocol::{KeyPair, PrivateKey, PublicKey, SenderCertificate, ServerCertificate, Timestamp};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info};
use uuid::Uuid;

const MAX_QUEUE_PER_RECIPIENT: usize = 200;
// Official libsignal sealed-sender envelopes can be substantially larger
// than the old raw Signal ciphertext wrapper because they carry the
// sender certificate and sealed outer envelope. Keep the text MVP
// plaintext limit small on the client, but allow enough transport room
// so tungstenite/axum does not close the WebSocket during send.
const MAX_FRAME_BYTES: usize = 512 * 1024;
const MAX_TOTAL_QUEUED_BYTES: usize = 64 * 1024 * 1024;
const PROTOCOL_VERSION: u16 = 3;
const SENDER_CERT_TTL_MS: u64 = 24 * 60 * 60 * 1000;

type RecipientId = String;
type ClientTx = mpsc::UnboundedSender<ServerFrame>;

#[derive(Clone)]
struct AppState {
    queues: Arc<DashMap<RecipientId, VecDeque<StoredEnvelope>>>,
    online: Arc<DashMap<RecipientId, ClientTx>>,
    mailbox_auth: Arc<DashMap<RecipientId, MailboxAuth>>,
    total_queued_bytes: Arc<AtomicUsize>,
    crypto: Arc<ServerCrypto>,
}

struct ServerCrypto {
    trust_root_public_b64: String,
    server_certificate: ServerCertificate,
    server_signing_private: PrivateKey,
}

#[derive(Debug, Clone)]
struct MailboxAuth {
    receive_auth_hash: String,
    delivery_token_hash: String,
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
    Hello { recipient_id: RecipientId, auth_token: String, delivery_token: String },
    IssueSenderCertificate { request_id: String, sender_uuid: String, sender_device_id: u32, identity_public_b64: String },
    SendEnvelope { to: RecipientId, delivery_token: String, envelope_type: String, ciphertext: String },
    Poll,
    Ack { ids: Vec<Uuid> },
    Ping,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerFrame {
    HelloOk { protocol_version: u16, server_time_ms: u64, trust_root_b64: String },
    SenderCertificate { request_id: String, certificate_b64: String, trust_root_b64: String, expires_at_ms: u64 },
    Envelope { envelope: StoredEnvelope },
    SendOk { id: Uuid, queued: bool },
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

    let state = AppState {
        queues: Arc::new(DashMap::new()),
        online: Arc::new(DashMap::new()),
        mailbox_auth: Arc::new(DashMap::new()),
        total_queued_bytes: Arc::new(AtomicUsize::new(0)),
        crypto: Arc::new(init_server_crypto()?),
    };
    let app = Router::new()
        .route("/health", get(health))
        .route("/ws", get(ws_handler))
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(%addr, "Axeno relay listening");
    axum::serve(listener, app).await?;
    Ok(())
}

fn init_server_crypto() -> anyhow::Result<ServerCrypto> {
    let mut rng = fresh_rng()?;
    let trust_root = KeyPair::generate(&mut rng);
    let server_signing = KeyPair::generate(&mut rng);
    let server_certificate = ServerCertificate::new(1, server_signing.public_key, &trust_root.private_key, &mut rng)?;
    Ok(ServerCrypto {
        trust_root_public_b64: STANDARD_NO_PAD.encode(trust_root.public_key.serialize()),
        server_certificate,
        server_signing_private: server_signing.private_key,
    })
}

fn fresh_rng() -> anyhow::Result<ChaCha20Rng> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed)?;
    Ok(ChaCha20Rng::from_seed(seed))
}

async fn health() -> &'static str { "ok" }

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.max_message_size(MAX_FRAME_BYTES).on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: AppState) {
    let (mut sender, mut receiver) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<ServerFrame>();

    let writer = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            match serde_json::to_string(&frame) {
                Ok(text) => { if sender.send(Message::Text(text.into())).await.is_err() { break; } }
                Err(e) => error!(?e, "failed to serialize server frame"),
            }
        }
    });

    let mut recipient_id: Option<RecipientId> = None;

    while let Some(incoming) = receiver.next().await {
        let Ok(msg) = incoming else { break; };
        let Message::Text(text) = msg else { continue; };
        if text.len() > MAX_FRAME_BYTES { let _ = tx.send(err("too_large", "frame too large")); continue; }

        let frame = match serde_json::from_str::<ClientFrame>(&text) {
            Ok(frame) => frame,
            Err(e) => { let _ = tx.send(err("bad_json", &e.to_string())); continue; }
        };

        match frame {
            ClientFrame::Hello { recipient_id: rid, auth_token, delivery_token } => {
                if !valid_recipient_id(&rid) || !valid_token(&auth_token) || !valid_token(&delivery_token) {
                    let _ = tx.send(err("bad_hello", "invalid mailbox or token"));
                    continue;
                }
                let auth_hash = token_hash(&auth_token);
                let delivery_hash = token_hash(&delivery_token);
                if let Some(existing) = state.mailbox_auth.get(&rid) {
                    if existing.receive_auth_hash != auth_hash {
                        let _ = tx.send(err("auth_failed", "mailbox auth failed"));
                        continue;
                    }
                } else {
                    state.mailbox_auth.insert(rid.clone(), MailboxAuth { receive_auth_hash: auth_hash, delivery_token_hash: delivery_hash });
                }
                recipient_id = Some(rid.clone());
                state.online.insert(rid.clone(), tx.clone());
                let _ = tx.send(ServerFrame::HelloOk { protocol_version: PROTOCOL_VERSION, server_time_ms: now_ms(), trust_root_b64: state.crypto.trust_root_public_b64.clone() });
                flush_queue(&state, &rid, &tx);
            }
            ClientFrame::IssueSenderCertificate { request_id, sender_uuid, sender_device_id, identity_public_b64 } => {
                let Some(registered_rid) = recipient_id.as_ref() else {
                    let _ = tx.send(err("not_registered", "send hello first"));
                    continue;
                };
                if &sender_uuid != registered_rid {
                    let _ = tx.send(err("cert_denied", "sender certificate can only be issued for your authenticated mailbox"));
                    continue;
                }
                match issue_sender_certificate(&state, request_id, sender_uuid, sender_device_id, identity_public_b64) {
                    Ok(frame) => { let _ = tx.send(frame); }
                    Err(e) => { let _ = tx.send(err("cert_failed", &e)); }
                }
            }
            ClientFrame::SendEnvelope { to, delivery_token, envelope_type, ciphertext } => {
                if !valid_recipient_id(&to) || !valid_token(&delivery_token) {
                    let _ = tx.send(err("bad_send", "invalid destination or delivery token"));
                    continue;
                }
                if envelope_type.len() > 32 || ciphertext.len() > MAX_FRAME_BYTES {
                    let _ = tx.send(err("bad_envelope", "envelope rejected by size/type limits"));
                    continue;
                }
                let Some(auth) = state.mailbox_auth.get(&to) else {
                    let _ = tx.send(err("unknown_mailbox", "recipient mailbox is not registered on this relay yet"));
                    continue;
                };
                if auth.delivery_token_hash != token_hash(&delivery_token) {
                    let _ = tx.send(err("delivery_denied", "delivery token rejected"));
                    continue;
                }
                drop(auth);
                if state.total_queued_bytes.load(Ordering::Relaxed).saturating_add(ciphertext.len()) > MAX_TOTAL_QUEUED_BYTES {
                    let _ = tx.send(err("relay_full", "relay queue memory limit reached"));
                    continue;
                }

                let env = StoredEnvelope { id: Uuid::new_v4(), to: to.clone(), envelope_type, ciphertext };
                let delivered_live = state.online.get(&to).and_then(|live| live.send(ServerFrame::Envelope { envelope: env.clone() }).ok()).is_some();

                let mut queue = state.queues.entry(to).or_default();
                while queue.len() >= MAX_QUEUE_PER_RECIPIENT {
                    if let Some(old) = queue.pop_front() { state.total_queued_bytes.fetch_sub(old.ciphertext.len(), Ordering::Relaxed); }
                }
                state.total_queued_bytes.fetch_add(env.ciphertext.len(), Ordering::Relaxed);
                queue.push_back(env.clone());
                let _ = tx.send(ServerFrame::SendOk { id: env.id, queued: !delivered_live });
            }
            ClientFrame::Poll => {
                if let Some(rid) = recipient_id.as_ref() { flush_queue(&state, rid, &tx); }
                else { let _ = tx.send(err("not_registered", "send hello first")); }
            }
            ClientFrame::Ack { ids } => {
                let Some(rid) = recipient_id.as_ref() else { let _ = tx.send(err("not_registered", "send hello first")); continue; };
                let removed = remove_acked(&state, rid, &ids);
                let _ = tx.send(ServerFrame::AckOk { removed });
            }
            ClientFrame::Ping => { let _ = tx.send(ServerFrame::Pong { server_time_ms: now_ms() }); }
        }
    }

    if let Some(rid) = recipient_id { state.online.remove(&rid); }
    writer.abort();
    debug!("websocket disconnected");
}

fn issue_sender_certificate(state: &AppState, request_id: String, sender_uuid: String, sender_device_id: u32, identity_public_b64: String) -> Result<ServerFrame, String> {
    if !valid_recipient_id(&sender_uuid) || sender_device_id == 0 || sender_device_id > 127 {
        return Err("invalid sender certificate request".into());
    }
    let identity_bytes = STANDARD_NO_PAD.decode(identity_public_b64.as_bytes()).map_err(|_| "bad identity public key encoding".to_string())?;
    let sender_public = PublicKey::deserialize(&identity_bytes).map_err(|e| format!("bad identity public key: {e}"))?;
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

fn flush_queue(state: &AppState, rid: &str, tx: &ClientTx) {
    if let Some(queue) = state.queues.get(rid) {
        for env in queue.iter() {
            if tx.send(ServerFrame::Envelope { envelope: env.clone() }).is_err() { break; }
        }
    }
}

fn remove_acked(state: &AppState, rid: &str, ids: &[Uuid]) -> usize {
    let Some(mut queue) = state.queues.get_mut(rid) else { return 0; };
    let before = queue.len();
    let mut freed = 0usize;
    queue.retain(|env| {
        let remove = ids.contains(&env.id);
        if remove { freed += env.ciphertext.len(); }
        !remove
    });
    state.total_queued_bytes.fetch_sub(freed, Ordering::Relaxed);
    before - queue.len()
}

fn valid_recipient_id(id: &str) -> bool {
    (16..=128).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

fn valid_token(token: &str) -> bool {
    (16..=96).contains(&token.len()) && token.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

fn token_hash(token: &str) -> String { hex::encode(Sha256::digest(token.as_bytes())) }
fn now_ms() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64 }
