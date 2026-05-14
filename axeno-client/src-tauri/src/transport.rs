//! WebSocket transport for Axeno.
//!
//! This module implements one live WebSocket connection per route/mailbox plus
//! short-lived standalone relay requests for opaque invite-bundle upload/fetch.
//! It only moves opaque envelopes and opaque encrypted bundles.

use std::{collections::HashMap, sync::Arc, time::{SystemTime, UNIX_EPOCH}};

use arti_client::TorClient;
use futures_util::{Sink, SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager};
use tokio::{io::{AsyncRead, AsyncWrite}, sync::{mpsc, oneshot, Mutex}, time::{timeout, Duration}};
use tokio_tungstenite::{connect_async, client_async, tungstenite::{client::IntoClientRequest, Message}, WebSocketStream};
use tor_rtcompat::PreferredRuntime;
use uuid::Uuid;

const PROTOCOL_MIN_SUPPORTED: u16 = 4;
const PROTOCOL_VERSION: u16 = 5;
const OUTBOUND_QUEUE_CAPACITY: usize = 256;

#[derive(Clone, Default)]
pub struct TransportState {
    connections: Arc<Mutex<HashMap<String, ServerConnection>>>,
    pending_sender_certs: Arc<Mutex<HashMap<String, oneshot::Sender<SenderCertificateResponse>>>>,
    sender_cert_cache: Arc<Mutex<HashMap<String, SenderCertificateResponse>>>,
    pending_token_updates: Arc<Mutex<HashMap<String, oneshot::Sender<()>>>>,
    pending_sends: Arc<Mutex<HashMap<String, oneshot::Sender<Result<SendEnvelopeAck, String>>>>>,
    server_trust_roots: Arc<Mutex<HashMap<String, String>>>,
}

impl TransportState {
    pub fn new() -> Self { Self::default() }
}

struct ServerConnection {
    url: String,
    recipient_id: String,
    outbound: mpsc::Sender<ClientFrame>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEnvelope {
    pub id: Uuid,
    pub to: String,
    pub envelope_type: String,
    pub ciphertext: String,
}

async fn generate_pow(recipient_id: &str) -> String {
    let rid = recipient_id.to_string();
    tokio::task::spawn_blocking(move || {
        use sha2::{Sha256, Digest};
        use std::time::{SystemTime, UNIX_EPOCH};
        let mut nonce = 0u64;
        // Include a coarse timestamp (10-minute window) so the PoW nonce
        // cannot be replayed outside a narrow time window.
        let ts_window = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() / 600;
        let prefix = format!("{rid}:{ts_window}:");
        loop {
            let input = format!("{prefix}{nonce}");
            let hash = Sha256::digest(input.as_bytes());
            if hash[0] == 0 && hash[1] == 0 {
                return format!("{ts_window}:{nonce}");
            }
            nonce += 1;
        }
    }).await.unwrap_or_else(|_| "0:0".to_string())
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[allow(dead_code)]
enum ClientFrame {
    Hello { recipient_id: String, auth_token: String, delivery_token: String, protocol_min: u16, protocol_max: u16, pow: Option<String> },
    SetDeliveryTokens { request_id: String, tokens: Vec<String> },
    IssueSenderCertificate { request_id: String, sender_uuid: String, sender_device_id: u32, sender_cert_public_b64: String },
    SendEnvelope {
        client_ref: Option<String>,
        to: String,
        delivery_token: String,
        envelope_type: String,
        ciphertext: String,
    },
    UploadBundle { request_id: String, bundle_id: String, ciphertext: String, expires_at_ms: u64 },
    FetchBundle { request_id: String, bundle_id: String },
    Ack { ids: Vec<Uuid> },
    RetireMailbox,
    Ping,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[allow(dead_code)]
enum ServerFrame {
    HelloOk { protocol_version: u16, server_time_ms: u64, trust_root_b64: String, #[serde(default)] min_supported: Option<u16>, #[serde(default)] current_protocol: Option<u16> },
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

#[derive(Debug, Clone, Serialize)]
pub struct TransportStatusEvent {
    pub server_id: String,
    pub status: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IncomingEnvelopeEvent {
    pub server_id: String,
    pub envelope: StoredEnvelope,
}

#[derive(Debug, Clone, Serialize)]
pub struct SendReceipt {
    pub server_id: String,
    pub id: Uuid,
    pub queued: bool,
    pub client_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SendFailure {
    pub server_id: String,
    pub client_ref: Option<String>,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderCertificateResponse {
    pub certificate_b64: String,
    pub trust_root_b64: String,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendEnvelopeAck {
    pub id: Uuid,
    pub queued: bool,
    pub client_ref: Option<String>,
}

pub async fn connect_server(
    app: AppHandle,
    state: &TransportState,
    tor_client: Arc<Mutex<Option<TorClient<PreferredRuntime>>>>,
    server_id: String,
    url: String,
    recipient_id: String,
    auth_token: String,
    delivery_token: String,
) -> Result<(), String> {
    validate_ws_url(&url)?;
    validate_recipient_id(&recipient_id)?;
    validate_token(&auth_token, "auth token")?;
    validate_token(&delivery_token, "delivery token")?;

    let mut guard = state.connections.lock().await;
    if let Some(existing) = guard.get(&server_id) {
        if existing.url == url && existing.recipient_id == recipient_id && !existing.outbound.is_closed() {
            return Ok(());
        }
        guard.remove(&server_id);
    }

    let (tx, rx) = mpsc::channel::<ClientFrame>(OUTBOUND_QUEUE_CAPACITY);
    guard.insert(server_id.clone(), ServerConnection { url: url.clone(), recipient_id: recipient_id.clone(), outbound: tx.clone() });
    drop(guard);

    let (ready_tx, ready_rx) = oneshot::channel::<Result<(), String>>();
    let app_for_task = app.clone();
    let pending_certs = state.pending_sender_certs.clone();
    let pending_token_updates = state.pending_token_updates.clone();
    let pending_sends = state.pending_sends.clone();
    let trust_roots = state.server_trust_roots.clone();
    let connections = state.connections.clone();
    let task_server_id = server_id.clone();
    tokio::spawn(async move {
        let _ = emit_status(&app_for_task, &task_server_id, "connecting", None);
        let result = run_connection(app_for_task.clone(), tor_client, pending_certs, pending_token_updates, pending_sends, trust_roots, task_server_id.clone(), url, recipient_id, auth_token, delivery_token, rx, Some(ready_tx)).await;
        connections.lock().await.remove(&task_server_id);
        match result {
            Ok(()) => { let _ = emit_status(&app_for_task, &task_server_id, "disconnected", None); }
            Err(e) => { let _ = emit_status(&app_for_task, &task_server_id, "failed", Some(e)); }
        }
    });

    match timeout(Duration::from_secs(10), ready_rx).await {
        Ok(Ok(Ok(()))) => Ok(()),
        Ok(Ok(Err(e))) => { state.connections.lock().await.remove(&server_id); Err(e) }
        Ok(Err(_)) => { state.connections.lock().await.remove(&server_id); Err("relay connection closed before registration completed".to_string()) }
        Err(_) => { state.connections.lock().await.remove(&server_id); Err("timed out waiting for relay registration".to_string()) }
    }
}

pub async fn disconnect_server(
    state: &TransportState,
    server_id: String,
) -> Result<(), String> {
    state.connections.lock().await.remove(&server_id);
    Ok(())
}

pub async fn set_delivery_tokens(
    state: &TransportState,
    server_id: String,
    tokens: Vec<String>,
) -> Result<(), String> {
    if tokens.is_empty() { return Err("delivery-token allowlist may not be empty".into()); }
    for token in &tokens { validate_token(token, "delivery token")?; }
    let request_id = Uuid::new_v4().to_string();
    let guard = state.connections.lock().await;
    let conn = guard.get(&server_id).ok_or_else(|| "server is not connected".to_string())?;
    conn.outbound.try_send(ClientFrame::SetDeliveryTokens { request_id, tokens })
        .map_err(|e| format!("server connection is not accepting frames; reconnect and try again: {e}"))
}

pub async fn set_delivery_tokens_confirmed(
    state: &TransportState,
    server_id: String,
    tokens: Vec<String>,
) -> Result<(), String> {
    if tokens.is_empty() { return Err("delivery-token allowlist may not be empty".into()); }
    for token in &tokens { validate_token(token, "delivery token")?; }
    let request_id = Uuid::new_v4().to_string();
    let (tx, rx) = oneshot::channel();
    state.pending_token_updates.lock().await.insert(request_id.clone(), tx);

    let send_result = {
        let guard = state.connections.lock().await;
        match guard.get(&server_id) {
            Some(conn) => conn.outbound.try_send(ClientFrame::SetDeliveryTokens { request_id: request_id.clone(), tokens })
                .map_err(|e| format!("server connection is not accepting frames; reconnect and try again: {e}")),
            None => Err("server is not connected".to_string()),
        }
    };

    if let Err(e) = send_result {
        state.pending_token_updates.lock().await.remove(&request_id);
        return Err(e);
    }

    match timeout(Duration::from_secs(10), rx).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => {
            state.pending_token_updates.lock().await.remove(&request_id);
            Err("delivery-token update response channel closed".to_string())
        }
        Err(_) => {
            state.pending_token_updates.lock().await.remove(&request_id);
            Err("timed out waiting for delivery-token update confirmation".to_string())
        }
    }
}

pub async fn send_envelope(
    state: &TransportState,
    server_id: String,
    to: String,
    delivery_token: String,
    envelope_type: String,
    ciphertext: String,
    client_ref: Option<String>,
) -> Result<SendEnvelopeAck, String> {
    validate_recipient_id(&to)?;
    validate_token(&delivery_token, "delivery token")?;
    if envelope_type.len() > 32 { return Err("envelope_type is too long".into()); }
    if ciphertext.len() > 512 * 1024 { return Err("ciphertext exceeds 512 KiB frame limit".into()); }

    // Wait for the relay's SendOk/SendError here, but only from the Rust async
    // worker path. The UI freeze came from calling this through a synchronous
    // Tauri block_on; the command now runs off the UI thread, while this ACK wait
    // gives the caller a real truth signal instead of leaving messages stuck at
    // relay_pending forever when the relay rejects or wedges.
    let client_ref = client_ref.unwrap_or_else(|| Uuid::new_v4().to_string());
    let (tx, rx) = oneshot::channel();
    state.pending_sends.lock().await.insert(client_ref.clone(), tx);

    let send_result = {
        let guard = state.connections.lock().await;
        match guard.get(&server_id) {
            Some(conn) => conn.outbound.try_send(ClientFrame::SendEnvelope {
                client_ref: Some(client_ref.clone()),
                to,
                delivery_token,
                envelope_type,
                ciphertext,
            }).map_err(|e| format!("server connection is not accepting frames; reconnect and try again: {e}")),
            None => Err("server is not connected".to_string()),
        }
    };

    if let Err(e) = send_result {
        state.pending_sends.lock().await.remove(&client_ref);
        return Err(e);
    }

    match timeout(Duration::from_secs(15), rx).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => {
            state.pending_sends.lock().await.remove(&client_ref);
            Err("send acknowledgement channel closed".to_string())
        }
        Err(_) => {
            state.pending_sends.lock().await.remove(&client_ref);
            Err("timed out waiting for relay send acknowledgement".to_string())
        }
    }
}

/// Send one opaque envelope over a fresh unauthenticated WebSocket.
///
/// This deliberately does not reuse the authenticated receive mailbox socket.
/// The relay still validates the destination delivery token, but it does not get
/// a socket-level sender mailbox for the send itself. Sender authenticity remains
/// inside the sealed-sender/Signal envelope; the relay only sees ciphertext,
/// destination mailbox, timing, and size.
pub async fn send_envelope_once(
    tor_client: Arc<Mutex<Option<TorClient<PreferredRuntime>>>>,
    url: String,
    to: String,
    delivery_token: String,
    envelope_type: String,
    ciphertext: String,
    client_ref: Option<String>,
) -> Result<SendEnvelopeAck, String> {
    validate_ws_url(&url)?;
    validate_recipient_id(&to)?;
    validate_token(&delivery_token, "delivery token")?;
    if envelope_type.len() > 32 { return Err("envelope_type is too long".into()); }
    if ciphertext.len() > 512 * 1024 { return Err("ciphertext exceeds 512 KiB frame limit".into()); }

    let client_ref = client_ref.unwrap_or_else(|| Uuid::new_v4().to_string());
    let frame = ClientFrame::SendEnvelope {
        client_ref: Some(client_ref.clone()),
        to,
        delivery_token,
        envelope_type,
        ciphertext,
    };
    let parsed = parse_ws_url(&url)?;
    if parsed.host.ends_with(".onion") {
        let client = tor_client.lock().await.clone().ok_or_else(|| "Tor is not bootstrapped yet; call bootstrap_tor first".to_string())?;
        let isolated = client.isolated_client();
        let stream = isolated.connect((parsed.host.as_str(), parsed.port)).await.map_err(|e| format!("Tor connect failed: {e}"))?;
        let request = url.clone().into_client_request().map_err(|e| e.to_string())?;
        let (ws, _) = client_async(request, stream).await.map_err(|e| format!("onion websocket handshake failed: {e}"))?;
        run_send_envelope_ws(ws, frame, client_ref).await
    } else {
        if !parsed.is_local_dev_host() { return Err("direct WebSocket is only allowed for localhost development. Use a .onion server URL for real transport.".into()); }
        let (ws, _) = connect_async(&url).await.map_err(|e| format!("websocket connect failed: {e}"))?;
        run_send_envelope_ws(ws, frame, client_ref).await
    }
}

async fn run_send_envelope_ws<S>(
    mut ws: WebSocketStream<S>,
    frame: ClientFrame,
    client_ref: String,
) -> Result<SendEnvelopeAck, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    send_frame(&mut ws, frame).await?;
    let response = timeout(Duration::from_secs(15), ws.next()).await.map_err(|_| "timed out waiting for relay send acknowledgement".to_string())?;
    let Some(response) = response else { return Err("relay closed before send acknowledgement".to_string()); };
    let msg = response.map_err(|e| format!("websocket read failed: {e}"))?;
    let Message::Text(text) = msg else { return Err("unexpected non-text relay response to send".to_string()); };
    match serde_json::from_str::<ServerFrame>(&text).map_err(|e| format!("bad relay send response: {e}"))? {
        ServerFrame::SendOk { id, queued, client_ref: response_ref } => {
            if response_ref.as_deref() != Some(client_ref.as_str()) {
                return Err("relay send acknowledgement did not match request".to_string());
            }
            Ok(SendEnvelopeAck { id, queued, client_ref: response_ref })
        }
        ServerFrame::SendError { code, message, .. } => Err(format!("{code}: {message}")),
        ServerFrame::Error { code, message } => Err(format!("{code}: {message}")),
        _ => Err("unexpected relay response to send".to_string()),
    }
}

pub async fn request_sender_certificate(
    state: &TransportState,
    server_id: String,
    sender_uuid: String,
    sender_device_id: u32,
    sender_cert_public_b64: String,
) -> Result<SenderCertificateResponse, String> {
    validate_recipient_id(&sender_uuid)?;
    if sender_device_id == 0 || sender_device_id > 127 { return Err("invalid sender device id".into()); }
    if sender_cert_public_b64.len() > 64 { return Err("sender certificate public key is too large".into()); }
    let cache_key = format!("{}|{}|{}|{}", server_id, sender_uuid, sender_device_id, sender_cert_public_b64);
    if let Some(cached) = state.sender_cert_cache.lock().await.get(&cache_key).cloned() {
        if cached.expires_at_ms > now_ms().saturating_add(60 * 60 * 1000) {
            return Ok(cached);
        }
    }
    let request_id = Uuid::new_v4().to_string();
    let (tx, rx) = oneshot::channel();
    state.pending_sender_certs.lock().await.insert(request_id.clone(), tx);

    let send_result = {
        let guard = state.connections.lock().await;
        match guard.get(&server_id) {
            Some(conn) => conn.outbound.try_send(ClientFrame::IssueSenderCertificate { request_id: request_id.clone(), sender_uuid, sender_device_id, sender_cert_public_b64 })
                .map_err(|e| format!("server connection is not accepting certificate requests: {e}")),
            None => Err("server is not connected".to_string()),
        }
    };

    if let Err(e) = send_result {
        state.pending_sender_certs.lock().await.remove(&request_id);
        return Err(e);
    }

    match timeout(Duration::from_secs(10), rx).await {
        Ok(Ok(response)) => {
            let mut cache = state.sender_cert_cache.lock().await;
            // Evict expired certificates and cap cache size to prevent
            // unbounded growth from route rotations.
            let now = now_ms();
            cache.retain(|_, cert| cert.expires_at_ms > now);
            const MAX_CERT_CACHE: usize = 256;
            if cache.len() >= MAX_CERT_CACHE {
                // Remove oldest by expiry
                if let Some(oldest_key) = cache.iter()
                    .min_by_key(|(_, v)| v.expires_at_ms)
                    .map(|(k, _)| k.clone())
                {
                    cache.remove(&oldest_key);
                }
            }
            cache.insert(cache_key, response.clone());
            Ok(response)
        },
        Ok(Err(_)) => {
            state.pending_sender_certs.lock().await.remove(&request_id);
            Err("sender certificate response channel closed".to_string())
        }
        Err(_) => {
            state.pending_sender_certs.lock().await.remove(&request_id);
            Err("timed out waiting for sender certificate".to_string())
        }
    }
}


pub async fn request_sender_certificate_once(
    tor_client: Arc<Mutex<Option<TorClient<PreferredRuntime>>>>,
    url: String,
    sender_uuid: String,
    auth_token: String,
    delivery_token: String,
    sender_device_id: u32,
    sender_cert_public_b64: String,
) -> Result<SenderCertificateResponse, String> {
    validate_ws_url(&url)?;
    validate_recipient_id(&sender_uuid)?;
    validate_token(&auth_token, "auth token")?;
    validate_token(&delivery_token, "delivery token")?;
    if sender_device_id == 0 || sender_device_id > 127 { return Err("invalid sender device id".into()); }
    if sender_cert_public_b64.len() > 64 { return Err("sender certificate public key is too large".into()); }

    let parsed = parse_ws_url(&url)?;
    if parsed.host.ends_with(".onion") {
        let client = tor_client.lock().await.clone().ok_or_else(|| "Tor is not bootstrapped yet; call bootstrap_tor first".to_string())?;
        let isolated = client.isolated_client();
        let stream = isolated.connect((parsed.host.as_str(), parsed.port)).await.map_err(|e| format!("Tor connect failed: {e}"))?;
        let request = url.clone().into_client_request().map_err(|e| e.to_string())?;
        let (ws, _) = client_async(request, stream).await.map_err(|e| format!("onion websocket handshake failed: {e}"))?;
        run_sender_certificate_once_ws(ws, sender_uuid, auth_token, delivery_token, sender_device_id, sender_cert_public_b64).await
    } else {
        if !parsed.is_local_dev_host() { return Err("direct WebSocket is only allowed for localhost development. Use a .onion server URL for real transport.".into()); }
        let (ws, _) = connect_async(&url).await.map_err(|e| format!("websocket connect failed: {e}"))?;
        run_sender_certificate_once_ws(ws, sender_uuid, auth_token, delivery_token, sender_device_id, sender_cert_public_b64).await
    }
}

async fn run_sender_certificate_once_ws<S>(
    mut ws: WebSocketStream<S>,
    sender_uuid: String,
    auth_token: String,
    delivery_token: String,
    sender_device_id: u32,
    sender_cert_public_b64: String,
) -> Result<SenderCertificateResponse, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    send_frame(&mut ws, ClientFrame::Hello {
        recipient_id: sender_uuid.clone(),
        auth_token,
        delivery_token,
        protocol_min: PROTOCOL_MIN_SUPPORTED,
        protocol_max: PROTOCOL_VERSION,
        pow: Some(generate_pow(&sender_uuid).await),
    }).await?;

    let response = timeout(Duration::from_secs(15), ws.next()).await.map_err(|_| "timed out waiting for sender-certificate hello".to_string())?;
    let Some(response) = response else { return Err("relay closed before sender-certificate hello".to_string()); };
    let message = response.map_err(|e| format!("websocket read failed: {e}"))?;
    let Message::Text(text) = message else { return Err("unexpected non-text relay response".to_string()); };
    match serde_json::from_str::<ServerFrame>(&text).map_err(|e| format!("bad server frame: {e}"))? {
        ServerFrame::HelloOk { .. } => {}
        ServerFrame::Error { code, message } => return Err(format!("{code}: {message}")),
        _ => return Err("unexpected relay response to sender-certificate hello".to_string()),
    }

    let request_id = Uuid::new_v4().to_string();
    send_frame(&mut ws, ClientFrame::IssueSenderCertificate {
        request_id: request_id.clone(),
        sender_uuid,
        sender_device_id,
        sender_cert_public_b64,
    }).await?;

    let response = timeout(Duration::from_secs(15), ws.next()).await.map_err(|_| "timed out waiting for sender certificate".to_string())?;
    let Some(response) = response else { return Err("relay closed before sender certificate".to_string()); };
    let message = response.map_err(|e| format!("websocket read failed: {e}"))?;
    let Message::Text(text) = message else { return Err("unexpected non-text relay response".to_string()); };
    match serde_json::from_str::<ServerFrame>(&text).map_err(|e| format!("bad server frame: {e}"))? {
        ServerFrame::SenderCertificate { request_id: got_request, certificate_b64, trust_root_b64, expires_at_ms } if got_request == request_id => {
            Ok(SenderCertificateResponse { certificate_b64, trust_root_b64, expires_at_ms })
        }
        ServerFrame::Error { code, message } => Err(format!("{code}: {message}")),
        _ => Err("unexpected relay response to sender-certificate request".to_string()),
    }
}

pub async fn upload_invite_bundle(
    tor_client: Arc<Mutex<Option<TorClient<PreferredRuntime>>>>,
    url: String,
    bundle_id: String,
    ciphertext: String,
    expires_at_ms: u64,
) -> Result<(), String> {
    validate_ws_url(&url)?;
    validate_bundle_id(&bundle_id)?;
    if ciphertext.len() > 16 * 1024 { return Err("invite bundle exceeds relay limit".into()); }
    let request_id = Uuid::new_v4().to_string();
    let frame = ClientFrame::UploadBundle { request_id: request_id.clone(), bundle_id: bundle_id.clone(), ciphertext, expires_at_ms };
    let parsed = parse_ws_url(&url)?;
    if parsed.host.ends_with(".onion") {
        let client = tor_client.lock().await.clone().ok_or_else(|| "Tor is not bootstrapped yet; call bootstrap_tor first".to_string())?;
        let isolated = client.isolated_client();
        let stream = isolated.connect((parsed.host.as_str(), parsed.port)).await.map_err(|e| format!("Tor connect failed: {e}"))?;
        let request = url.clone().into_client_request().map_err(|e| e.to_string())?;
        let (ws, _) = client_async(request, stream).await.map_err(|e| format!("onion websocket handshake failed: {e}"))?;
        run_upload_bundle_ws(ws, frame, request_id, bundle_id).await
    } else {
        if !parsed.is_local_dev_host() { return Err("direct WebSocket is only allowed for localhost development. Use a .onion server URL for real transport.".into()); }
        let (ws, _) = connect_async(&url).await.map_err(|e| format!("websocket connect failed: {e}"))?;
        run_upload_bundle_ws(ws, frame, request_id, bundle_id).await
    }
}

pub async fn fetch_invite_bundle(
    tor_client: Arc<Mutex<Option<TorClient<PreferredRuntime>>>>,
    url: String,
    bundle_id: String,
) -> Result<String, String> {
    validate_ws_url(&url)?;
    validate_bundle_id(&bundle_id)?;
    let request_id = Uuid::new_v4().to_string();
    let frame = ClientFrame::FetchBundle { request_id: request_id.clone(), bundle_id: bundle_id.clone() };
    let parsed = parse_ws_url(&url)?;
    if parsed.host.ends_with(".onion") {
        let client = tor_client.lock().await.clone().ok_or_else(|| "Tor is not bootstrapped yet; call bootstrap_tor first".to_string())?;
        let isolated = client.isolated_client();
        let stream = isolated.connect((parsed.host.as_str(), parsed.port)).await.map_err(|e| format!("Tor connect failed: {e}"))?;
        let request = url.clone().into_client_request().map_err(|e| e.to_string())?;
        let (ws, _) = client_async(request, stream).await.map_err(|e| format!("onion websocket handshake failed: {e}"))?;
        run_fetch_bundle_ws(ws, frame, request_id, bundle_id).await
    } else {
        if !parsed.is_local_dev_host() { return Err("direct WebSocket is only allowed for localhost development. Use a .onion server URL for real transport.".into()); }
        let (ws, _) = connect_async(&url).await.map_err(|e| format!("websocket connect failed: {e}"))?;
        run_fetch_bundle_ws(ws, frame, request_id, bundle_id).await
    }
}

pub async fn retire_mailbox_once(
    tor_client: Arc<Mutex<Option<TorClient<PreferredRuntime>>>>,
    url: String,
    recipient_id: String,
    auth_token: String,
    delivery_token: String,
) -> Result<(), String> {
    validate_ws_url(&url)?;
    validate_recipient_id(&recipient_id)?;
    validate_token(&auth_token, "auth token")?;
    validate_token(&delivery_token, "delivery token")?;
    let parsed = parse_ws_url(&url)?;
    if parsed.host.ends_with(".onion") {
        let client = tor_client.lock().await.clone().ok_or_else(|| "Tor is not bootstrapped yet; call bootstrap_tor first".to_string())?;
        let isolated = client.isolated_client();
        let stream = isolated.connect((parsed.host.as_str(), parsed.port)).await.map_err(|e| format!("Tor connect failed: {e}"))?;
        let request = url.clone().into_client_request().map_err(|e| e.to_string())?;
        let (ws, _) = client_async(request, stream).await.map_err(|e| format!("onion websocket handshake failed: {e}"))?;
        run_retire_mailbox_ws(ws, recipient_id, auth_token, delivery_token).await
    } else {
        if !parsed.is_local_dev_host() { return Err("direct WebSocket is only allowed for localhost development. Use a .onion server URL for real transport.".into()); }
        let (ws, _) = connect_async(&url).await.map_err(|e| format!("websocket connect failed: {e}"))?;
        run_retire_mailbox_ws(ws, recipient_id, auth_token, delivery_token).await
    }
}

async fn run_upload_bundle_ws<S>(
    mut ws: WebSocketStream<S>,
    frame: ClientFrame,
    request_id: String,
    bundle_id: String,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    send_frame(&mut ws, frame).await?;
    let response = timeout(Duration::from_secs(15), ws.next()).await.map_err(|_| "timed out waiting for invite bundle upload ack".to_string())?;
    let Some(response) = response else { return Err("relay closed before invite bundle upload ack".to_string()); };
    let message = response.map_err(|e| format!("websocket read failed: {e}"))?;
    let Message::Text(text) = message else { return Err("unexpected non-text relay response".to_string()); };
    match serde_json::from_str::<ServerFrame>(&text).map_err(|e| format!("bad server frame: {e}"))? {
        ServerFrame::BundleUploaded { request_id: got_request, bundle_id: got_bundle, .. } if got_request == request_id && got_bundle == bundle_id => Ok(()),
        ServerFrame::Error { code, message } => Err(format!("{code}: {message}")),
        _ => Err("unexpected relay response to invite bundle upload".to_string()),
    }
}

async fn run_fetch_bundle_ws<S>(
    mut ws: WebSocketStream<S>,
    frame: ClientFrame,
    request_id: String,
    bundle_id: String,
) -> Result<String, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    send_frame(&mut ws, frame).await?;
    let response = timeout(Duration::from_secs(15), ws.next()).await.map_err(|_| "timed out waiting for invite bundle".to_string())?;
    let Some(response) = response else { return Err("relay closed before returning invite bundle".to_string()); };
    let message = response.map_err(|e| format!("websocket read failed: {e}"))?;
    let Message::Text(text) = message else { return Err("unexpected non-text relay response".to_string()); };
    match serde_json::from_str::<ServerFrame>(&text).map_err(|e| format!("bad server frame: {e}"))? {
        ServerFrame::Bundle { request_id: got_request, bundle_id: got_bundle, ciphertext, .. } if got_request == request_id && got_bundle == bundle_id => Ok(ciphertext),
        ServerFrame::Error { code, message } => Err(format!("{code}: {message}")),
        _ => Err("unexpected relay response to invite bundle fetch".to_string()),
    }
}

async fn run_retire_mailbox_ws<S>(
    mut ws: WebSocketStream<S>,
    recipient_id: String,
    auth_token: String,
    delivery_token: String,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    send_frame(&mut ws, ClientFrame::Hello {
        recipient_id: recipient_id.clone(),
        auth_token,
        delivery_token,
        protocol_min: PROTOCOL_MIN_SUPPORTED,
        protocol_max: PROTOCOL_VERSION,
        pow: Some(generate_pow(&recipient_id).await),
    }).await?;

    let response = timeout(Duration::from_secs(15), ws.next()).await.map_err(|_| "timed out waiting for mailbox-retire hello".to_string())?;
    let Some(response) = response else { return Err("relay closed before mailbox-retire hello".to_string()); };
    let message = response.map_err(|e| format!("websocket read failed: {e}"))?;
    let Message::Text(text) = message else { return Err("unexpected non-text relay response".to_string()); };
    match serde_json::from_str::<ServerFrame>(&text).map_err(|e| format!("bad server frame: {e}"))? {
        ServerFrame::HelloOk { .. } => {}
        ServerFrame::Error { code, message } => return Err(format!("{code}: {message}")),
        _ => return Err("unexpected relay response to mailbox-retire hello".to_string()),
    }

    send_frame(&mut ws, ClientFrame::RetireMailbox).await?;
    let response = timeout(Duration::from_secs(15), ws.next()).await.map_err(|_| "timed out waiting for mailbox-retire ack".to_string())?;
    let Some(response) = response else { return Err("relay closed before mailbox-retire ack".to_string()); };
    let message = response.map_err(|e| format!("websocket read failed: {e}"))?;
    let Message::Text(text) = message else { return Err("unexpected non-text relay response".to_string()); };
    match serde_json::from_str::<ServerFrame>(&text).map_err(|e| format!("bad server frame: {e}"))? {
        ServerFrame::AckOk { .. } => Ok(()),
        ServerFrame::Error { code, message } => Err(format!("{code}: {message}")),
        _ => Err("unexpected relay response to mailbox-retire".to_string()),
    }
}

pub async fn get_server_trust_root(
    state: &TransportState,
    server_id: String,
) -> Result<Option<String>, String> {
    Ok(state.server_trust_roots.lock().await.get(&server_id).cloned())
}

pub async fn ack_envelopes(
    state: &TransportState,
    server_id: String,
    ids: Vec<Uuid>,
) -> Result<(), String> {
    let guard = state.connections.lock().await;
    let conn = guard.get(&server_id).ok_or_else(|| "server is not connected".to_string())?;
    conn.outbound.try_send(ClientFrame::Ack { ids }).map_err(|e| format!("server connection is not accepting ACKs; reconnect and try again: {e}"))
}

pub async fn retire_mailbox(
    state: &TransportState,
    server_id: String,
) -> Result<(), String> {
    let conn = {
        let guard = state.connections.lock().await;
        guard.get(&server_id).map(|c| c.outbound.clone())
    };
    if let Some(outbound) = conn {
        let _ = outbound.try_send(ClientFrame::RetireMailbox);
    }
    state.connections.lock().await.remove(&server_id);
    Ok(())
}

pub async fn list_connections(state: &TransportState) -> Result<Vec<(String, String, String)>, String> {
    let guard = state.connections.lock().await;
    Ok(guard.iter().map(|(id, c)| (id.clone(), c.url.clone(), c.recipient_id.clone())).collect())
}

async fn run_connection(
    app: AppHandle,
    tor_client: Arc<Mutex<Option<TorClient<PreferredRuntime>>>>,
    pending_certs: Arc<Mutex<HashMap<String, oneshot::Sender<SenderCertificateResponse>>>>,
    pending_token_updates: Arc<Mutex<HashMap<String, oneshot::Sender<()>>>>,
    pending_sends: Arc<Mutex<HashMap<String, oneshot::Sender<Result<SendEnvelopeAck, String>>>>>,
    server_trust_roots: Arc<Mutex<HashMap<String, String>>>,
    server_id: String,
    url: String,
    recipient_id: String,
    auth_token: String,
    delivery_token: String,
    outbound_rx: mpsc::Receiver<ClientFrame>,
    ready_tx: Option<oneshot::Sender<Result<(), String>>>,
) -> Result<(), String> {
    let parsed = parse_ws_url(&url)?;

    if parsed.host.ends_with(".onion") {
        if parsed.scheme != "ws" {
            return Err("onion WebSocket URLs must use ws:// because Tor already provides the transport privacy; wss:// onion TLS is not implemented yet".into());
        }
        let client = tor_client
            .lock()
            .await
            .clone()
            .ok_or_else(|| "Tor is not bootstrapped yet; call bootstrap_tor first".to_string())?;
        let isolated = client.isolated_client();
        let stream = isolated
            .connect((parsed.host.as_str(), parsed.port))
            .await
            .map_err(|e| format!("Tor connect failed: {e}"))?;
        let request = url.clone().into_client_request().map_err(|e| e.to_string())?;
        let (ws, _) = client_async(request, stream)
            .await
            .map_err(|e| format!("onion websocket handshake failed: {e}"))?;
        run_websocket(app, pending_certs, pending_token_updates, pending_sends, server_trust_roots, server_id, recipient_id, auth_token, delivery_token, outbound_rx, ws, ready_tx).await
    } else {
        if !parsed.is_local_dev_host() {
            return Err("direct WebSocket is only allowed for localhost development. Use a .onion server URL for real transport.".into());
        }
        let (ws, _) = connect_async(&url).await.map_err(|e| format!("websocket connect failed: {e}"))?;
        run_websocket(app, pending_certs, pending_token_updates, pending_sends, server_trust_roots, server_id, recipient_id, auth_token, delivery_token, outbound_rx, ws, ready_tx).await
    }
}

async fn run_websocket<S>(
    app: AppHandle,
    pending_certs: Arc<Mutex<HashMap<String, oneshot::Sender<SenderCertificateResponse>>>>,
    pending_token_updates: Arc<Mutex<HashMap<String, oneshot::Sender<()>>>>,
    pending_sends: Arc<Mutex<HashMap<String, oneshot::Sender<Result<SendEnvelopeAck, String>>>>>,
    server_trust_roots: Arc<Mutex<HashMap<String, String>>>,
    server_id: String,
    recipient_id: String,
    auth_token: String,
    delivery_token: String,
    mut outbound_rx: mpsc::Receiver<ClientFrame>,
    ws: WebSocketStream<S>,
    mut ready_tx: Option<oneshot::Sender<Result<(), String>>>,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut write, mut read) = ws.split();

    send_frame(&mut write, ClientFrame::Hello {
        recipient_id: recipient_id.clone(),
        auth_token,
        delivery_token,
        protocol_min: PROTOCOL_MIN_SUPPORTED,
        protocol_max: PROTOCOL_VERSION,
        pow: Some(generate_pow(&recipient_id).await),
    }).await?;
    let _ = emit_status(&app, &server_id, "connected", None);

    let writer_server_id = server_id.clone();
    let writer_app = app.clone();
    let writer = tokio::spawn(async move {
        while let Some(frame) = outbound_rx.recv().await {
            let send_ref = match &frame {
                ClientFrame::SendEnvelope { client_ref, .. } => client_ref.clone(),
                _ => None,
            };
            if let Err(e) = send_frame(&mut write, frame).await {
                if send_ref.is_some() {
                    let _ = writer_app.emit("axeno-send-failed", SendFailure {
                        server_id: writer_server_id.clone(),
                        client_ref: send_ref,
                        code: "websocket_write_failed".to_string(),
                        message: e.clone(),
                    });
                }
                let _ = emit_status(&writer_app, &writer_server_id, "failed", Some(e));
                break;
            }
        }
    });

    while let Some(message) = read.next().await {
        let message = message.map_err(|e| format!("websocket read failed: {e}"))?;
        let Message::Text(text) = message else { continue; };
        let frame: ServerFrame = serde_json::from_str(&text).map_err(|e| format!("bad server frame: {e}"))?;
        match frame {
            ServerFrame::HelloOk { protocol_version, trust_root_b64, server_time_ms, min_supported, current_protocol } => {
                let local_time = now_ms();
                let skew = if server_time_ms > local_time { server_time_ms - local_time } else { local_time - server_time_ms };
                if skew > 5 * 60 * 1000 {
                    let minutes = skew / 60_000;
                    let _ = emit_status(&app, &server_id, "clock_skew", Some(format!("local clock differs from relay by about {minutes} minutes")));
                }
                let server_min = min_supported.unwrap_or(protocol_version);
                let server_max = current_protocol.unwrap_or(protocol_version);
                if protocol_version < PROTOCOL_MIN_SUPPORTED || protocol_version > PROTOCOL_VERSION || protocol_version < server_min || protocol_version > server_max {
                    return Err(format!("relay protocol mismatch: client supports {PROTOCOL_MIN_SUPPORTED}-{PROTOCOL_VERSION}, relay selected {protocol_version}"));
                }
                let mut roots = server_trust_roots.lock().await;
                if let Some(existing) = roots.get(&server_id) {
                    if existing != &trust_root_b64 {
                        return Err("relay trust root changed during this session".to_string());
                    }
                }
                roots.insert(server_id.clone(), trust_root_b64);
                drop(roots);
                if let Some(tx) = ready_tx.take() { let _ = tx.send(Ok(())); }
                let _ = emit_status(&app, &server_id, "ready", None);
            }
            ServerFrame::SenderCertificate { request_id, certificate_b64, trust_root_b64, expires_at_ms } => {
                let mut roots = server_trust_roots.lock().await;
                if let Some(existing) = roots.get(&server_id) {
                    if existing != &trust_root_b64 {
                        return Err("relay trust root changed during sender-certificate issuance".to_string());
                    }
                }
                roots.insert(server_id.clone(), trust_root_b64.clone());
                drop(roots);
                if let Some(tx) = pending_certs.lock().await.remove(&request_id) {
                    let _ = tx.send(SenderCertificateResponse { certificate_b64, trust_root_b64, expires_at_ms });
                }
            }
            ServerFrame::Envelope { envelope } => {
                // Process the envelope directly in the Rust backend instead of
                // round-tripping through the webview. This eliminates the attack
                // surface where a compromised webview could inject fake envelopes
                // via the Tauri invoke handler.
                //
                // Note: handle_incoming_envelope uses non-Send libsignal futures,
                // so we isolate it on a blocking thread with its own runtime,
                // matching the pattern used by the Tauri command handler.
                let app_clone = app.clone();
                let server_id_clone = server_id.clone();
                tokio::task::spawn_blocking(move || {
                    let session = app_clone.state::<crate::AppSessionState>();
                    let runtime = app_clone.state::<crate::messaging::MessagingRuntimeState>();
                    let ts = app_clone.state::<TransportState>();
                    let tor_state = app_clone.state::<crate::AppTorState>();
                    let result = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|e| format!("envelope worker runtime failed: {e}"))
                        .and_then(|rt| {
                            rt.block_on(crate::messaging::handle_incoming_envelope(
                                app_clone.clone(),
                                &session,
                                &runtime,
                                &ts,
                                tor_state.client.clone(),
                                server_id_clone.clone(),
                                envelope.clone(),
                            ))
                        });
                    if let Err(e) = result {
                        eprintln!("[axeno] failed to handle incoming envelope on {}: {}", server_id_clone, e);
                    }
                });
            }
            ServerFrame::SendOk { id, queued, client_ref } => {
                if let Some(ref reference) = client_ref {
                    if let Some(tx) = pending_sends.lock().await.remove(reference) {
                        let _ = tx.send(Ok(SendEnvelopeAck { id, queued, client_ref: client_ref.clone() }));
                    }
                }
                let _ = app.emit("axeno-send-receipt", SendReceipt { server_id: server_id.clone(), id, queued, client_ref });
            }
            ServerFrame::SendError { client_ref, code, message } => {
                if let Some(ref reference) = client_ref {
                    if let Some(tx) = pending_sends.lock().await.remove(reference) {
                        let _ = tx.send(Err(format!("{code}: {message}")));
                    }
                }
                let _ = app.emit("axeno-send-failed", SendFailure {
                    server_id: server_id.clone(),
                    client_ref: client_ref.clone(),
                    code: code.clone(),
                    message: message.clone(),
                });
                let _ = emit_status(&app, &server_id, "send_error", Some(format!("{code}: {message}")));
            }
            ServerFrame::DeliveryTokensSet { request_id, .. } => {
                if let Some(tx) = pending_token_updates.lock().await.remove(&request_id) {
                    let _ = tx.send(());
                }
            }
            ServerFrame::AckOk { .. } => {}
            ServerFrame::Pong { .. } => {}
            ServerFrame::BundleUploaded { .. } | ServerFrame::Bundle { .. } => {}
            ServerFrame::Error { code, message } => {
                if let Some(tx) = ready_tx.take() { let _ = tx.send(Err(format!("{code}: {message}"))); }
                let _ = emit_status(&app, &server_id, "server_error", Some(format!("{code}: {message}")));
            }
        }
    }

    if let Some(tx) = ready_tx.take() { let _ = tx.send(Err("relay connection ended before registration completed".to_string())); }
    writer.abort();
    Ok(())
}

async fn send_frame<S>(write: &mut S, frame: ClientFrame) -> Result<(), String>
where
    S: Sink<Message> + Unpin,
    S::Error: std::fmt::Display,
{
    let text = serde_json::to_string(&frame).map_err(|e| e.to_string())?;
    write.send(Message::Text(text.into())).await.map_err(|e| e.to_string())
}

fn emit_status(app: &AppHandle, server_id: &str, status: &str, reason: Option<String>) -> Result<(), tauri::Error> {
    app.emit("axeno-server-status", TransportStatusEvent { server_id: server_id.to_string(), status: status.to_string(), reason })
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

#[derive(Debug)]
struct ParsedWsUrl {
    scheme: String,
    host: String,
    port: u16,
}

impl ParsedWsUrl {
    fn is_local_dev_host(&self) -> bool {
        matches!(self.host.as_str(), "127.0.0.1" | "localhost" | "[::1]" | "::1")
    }
}

fn parse_ws_url(url: &str) -> Result<ParsedWsUrl, String> {
    let (scheme, rest) = if let Some(rest) = url.strip_prefix("ws://") {
        ("ws", rest)
    } else if let Some(rest) = url.strip_prefix("wss://") {
        ("wss", rest)
    } else {
        return Err("server URL must start with ws:// or wss://".into());
    };

    let authority = rest.split('/').next().unwrap_or_default();
    if authority.is_empty() { return Err("server URL is missing a host".into()); }

    let (host, port) = if authority.starts_with('[') {
        let end = authority.find(']').ok_or_else(|| "invalid IPv6 host".to_string())?;
        let host = authority[..=end].to_string();
        let port = authority[end + 1..]
            .strip_prefix(':')
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(if scheme == "wss" { 443 } else { 80 });
        (host, port)
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        (host.to_string(), port.parse::<u16>().map_err(|_| "invalid server port".to_string())?)
    } else {
        (authority.to_string(), if scheme == "wss" { 443 } else { 80 })
    };

    Ok(ParsedWsUrl { scheme: scheme.to_string(), host, port })
}

fn validate_ws_url(url: &str) -> Result<(), String> {
    if url.starts_with("ws://") || url.starts_with("wss://") { Ok(()) } else { Err("server URL must start with ws:// or wss://".into()) }
}

fn validate_token(token: &str, label: &str) -> Result<(), String> {
    if (16..=128).contains(&token.len()) && token.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')) {
        Ok(())
    } else {
        Err(format!("{label} must be 16-128 URL-safe characters"))
    }
}

fn validate_recipient_id(id: &str) -> Result<(), String> {
    if id.starts_with("mbx_")
        && (16..=128).contains(&id.len())
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        Ok(())
    } else {
        Err("recipient id must start with mbx_ and be 16-128 URL-safe characters".into())
    }
}

fn validate_bundle_id(id: &str) -> Result<(), String> {
    if (16..=128).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')) {
        Ok(())
    } else {
        Err("invite bundle id must be 16-128 URL-safe characters".into())
    }
}
