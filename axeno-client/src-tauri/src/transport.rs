//! WebSocket transport for Axeno.
//!
//! This module implements one live WebSocket connection per configured server.
//! It only moves opaque envelopes. The normal chat UI should not claim E2EE
//! until the Signal session layer encrypts/decrypts these envelopes.

use std::{collections::HashMap, sync::Arc, time::{SystemTime, UNIX_EPOCH}};

use arti_client::TorClient;
use futures_util::{Sink, SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};
use tokio::{io::{AsyncRead, AsyncWrite}, sync::{mpsc, oneshot, Mutex}, time::{timeout, Duration}};
use tokio_tungstenite::{connect_async, client_async, tungstenite::{client::IntoClientRequest, Message}, WebSocketStream};
use tor_rtcompat::PreferredRuntime;
use uuid::Uuid;

#[derive(Default)]
pub struct TransportState {
    connections: Arc<Mutex<HashMap<String, ServerConnection>>>,
    pending_sender_certs: Arc<Mutex<HashMap<String, oneshot::Sender<SenderCertificateResponse>>>>,
    server_trust_roots: Arc<Mutex<HashMap<String, String>>>,
}

impl TransportState {
    pub fn new() -> Self { Self::default() }
}

struct ServerConnection {
    url: String,
    recipient_id: String,
    outbound: mpsc::UnboundedSender<ClientFrame>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEnvelope {
    pub id: Uuid,
    pub to: String,
    pub envelope_type: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientFrame {
    Hello { recipient_id: String, auth_token: String, delivery_token: String },
    IssueSenderCertificate { request_id: String, sender_uuid: String, sender_device_id: u32, identity_public_b64: String },
    SendEnvelope {
        to: String,
        delivery_token: String,
        envelope_type: String,
        ciphertext: String,
    },
    Poll,
    Ack { ids: Vec<Uuid> },
    Ping,
}

#[derive(Debug, Clone, Deserialize)]
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderCertificateResponse {
    pub certificate_b64: String,
    pub trust_root_b64: String,
    pub expires_at_ms: u64,
}

pub async fn connect_server(
    app: AppHandle,
    state: tauri::State<'_, TransportState>,
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
        if existing.url == url && existing.recipient_id == recipient_id {
            return Ok(());
        }
    }

    let (tx, rx) = mpsc::unbounded_channel::<ClientFrame>();
    guard.insert(server_id.clone(), ServerConnection { url: url.clone(), recipient_id: recipient_id.clone(), outbound: tx.clone() });
    drop(guard);

    let app_for_task = app.clone();
    let pending_certs = state.pending_sender_certs.clone();
    let trust_roots = state.server_trust_roots.clone();
    tokio::spawn(async move {
        let _ = emit_status(&app_for_task, &server_id, "connecting", None);
        if let Err(e) = run_connection(app_for_task.clone(), tor_client, pending_certs, trust_roots, server_id.clone(), url, recipient_id, auth_token, delivery_token, rx).await {
            let _ = emit_status(&app_for_task, &server_id, "failed", Some(e));
        }
    });

    Ok(())
}

pub async fn disconnect_server(
    state: tauri::State<'_, TransportState>,
    server_id: String,
) -> Result<(), String> {
    state.connections.lock().await.remove(&server_id);
    Ok(())
}

pub async fn send_envelope(
    state: tauri::State<'_, TransportState>,
    server_id: String,
    to: String,
    delivery_token: String,
    envelope_type: String,
    ciphertext: String,
) -> Result<(), String> {
    validate_recipient_id(&to)?;
    validate_token(&delivery_token, "delivery token")?;
    if envelope_type.len() > 32 { return Err("envelope_type is too long".into()); }
    if ciphertext.len() > 64 * 1024 { return Err("ciphertext exceeds 64 KiB frame limit".into()); }

    let guard = state.connections.lock().await;
    let conn = guard.get(&server_id).ok_or_else(|| "server is not connected".to_string())?;
    conn.outbound.send(ClientFrame::SendEnvelope { to, delivery_token, envelope_type, ciphertext })
        .map_err(|_| "server connection is closed".to_string())
}

pub async fn request_sender_certificate(
    state: tauri::State<'_, TransportState>,
    server_id: String,
    sender_uuid: String,
    sender_device_id: u32,
    identity_public_b64: String,
) -> Result<SenderCertificateResponse, String> {
    validate_recipient_id(&sender_uuid)?;
    if sender_device_id == 0 || sender_device_id > 127 { return Err("invalid sender device id".into()); }
    if identity_public_b64.len() > 256 { return Err("identity public key is too large".into()); }
    let request_id = Uuid::new_v4().to_string();
    let (tx, rx) = oneshot::channel();
    state.pending_sender_certs.lock().await.insert(request_id.clone(), tx);

    let send_result = {
        let guard = state.connections.lock().await;
        let conn = guard.get(&server_id).ok_or_else(|| "server is not connected".to_string())?;
        conn.outbound.send(ClientFrame::IssueSenderCertificate { request_id: request_id.clone(), sender_uuid, sender_device_id, identity_public_b64 })
            .map_err(|_| "server connection is closed".to_string())
    };

    if let Err(e) = send_result {
        state.pending_sender_certs.lock().await.remove(&request_id);
        return Err(e);
    }

    timeout(Duration::from_secs(10), rx)
        .await
        .map_err(|_| "timed out waiting for sender certificate".to_string())?
        .map_err(|_| "sender certificate response channel closed".to_string())
}

pub async fn get_server_trust_root(
    state: tauri::State<'_, TransportState>,
    server_id: String,
) -> Result<Option<String>, String> {
    Ok(state.server_trust_roots.lock().await.get(&server_id).cloned())
}

pub async fn poll_server(
    state: tauri::State<'_, TransportState>,
    server_id: String,
) -> Result<(), String> {
    let guard = state.connections.lock().await;
    let conn = guard.get(&server_id).ok_or_else(|| "server is not connected".to_string())?;
    conn.outbound.send(ClientFrame::Poll).map_err(|_| "server connection is closed".to_string())
}

pub async fn ack_envelopes(
    state: tauri::State<'_, TransportState>,
    server_id: String,
    ids: Vec<Uuid>,
) -> Result<(), String> {
    let guard = state.connections.lock().await;
    let conn = guard.get(&server_id).ok_or_else(|| "server is not connected".to_string())?;
    conn.outbound.send(ClientFrame::Ack { ids }).map_err(|_| "server connection is closed".to_string())
}

pub async fn list_connections(state: tauri::State<'_, TransportState>) -> Result<Vec<(String, String, String)>, String> {
    let guard = state.connections.lock().await;
    Ok(guard.iter().map(|(id, c)| (id.clone(), c.url.clone(), c.recipient_id.clone())).collect())
}

async fn run_connection(
    app: AppHandle,
    tor_client: Arc<Mutex<Option<TorClient<PreferredRuntime>>>>,
    pending_certs: Arc<Mutex<HashMap<String, oneshot::Sender<SenderCertificateResponse>>>>,
    server_trust_roots: Arc<Mutex<HashMap<String, String>>>,
    server_id: String,
    url: String,
    recipient_id: String,
    auth_token: String,
    delivery_token: String,
    outbound_rx: mpsc::UnboundedReceiver<ClientFrame>,
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
        let stream = client
            .connect((parsed.host.as_str(), parsed.port))
            .await
            .map_err(|e| format!("Tor connect failed: {e}"))?;
        let request = url.clone().into_client_request().map_err(|e| e.to_string())?;
        let (ws, _) = client_async(request, stream)
            .await
            .map_err(|e| format!("onion websocket handshake failed: {e}"))?;
        run_websocket(app, pending_certs, server_trust_roots, server_id, recipient_id, auth_token, delivery_token, outbound_rx, ws).await
    } else {
        if !parsed.is_local_dev_host() {
            return Err("direct WebSocket is only allowed for localhost development. Use a .onion server URL for real transport.".into());
        }
        let (ws, _) = connect_async(&url).await.map_err(|e| format!("websocket connect failed: {e}"))?;
        run_websocket(app, pending_certs, server_trust_roots, server_id, recipient_id, auth_token, delivery_token, outbound_rx, ws).await
    }
}

async fn run_websocket<S>(
    app: AppHandle,
    pending_certs: Arc<Mutex<HashMap<String, oneshot::Sender<SenderCertificateResponse>>>>,
    server_trust_roots: Arc<Mutex<HashMap<String, String>>>,
    server_id: String,
    recipient_id: String,
    auth_token: String,
    delivery_token: String,
    mut outbound_rx: mpsc::UnboundedReceiver<ClientFrame>,
    ws: WebSocketStream<S>,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut write, mut read) = ws.split();

    send_frame(&mut write, ClientFrame::Hello { recipient_id, auth_token, delivery_token }).await?;
    let _ = emit_status(&app, &server_id, "connected", None);

    let writer_server_id = server_id.clone();
    let writer_app = app.clone();
    let writer = tokio::spawn(async move {
        while let Some(frame) = outbound_rx.recv().await {
            if let Err(e) = send_frame(&mut write, frame).await {
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
            ServerFrame::HelloOk { trust_root_b64, .. } => {
                server_trust_roots.lock().await.insert(server_id.clone(), trust_root_b64);
                let _ = emit_status(&app, &server_id, "ready", None);
            }
            ServerFrame::SenderCertificate { request_id, certificate_b64, trust_root_b64, expires_at_ms } => {
                server_trust_roots.lock().await.insert(server_id.clone(), trust_root_b64.clone());
                if let Some(tx) = pending_certs.lock().await.remove(&request_id) {
                    let _ = tx.send(SenderCertificateResponse { certificate_b64, trust_root_b64, expires_at_ms });
                }
            }
            ServerFrame::Envelope { envelope } => {
                let _ = app.emit("axeno-envelope", IncomingEnvelopeEvent { server_id: server_id.clone(), envelope });
            }
            ServerFrame::SendOk { id, queued } => {
                let _ = app.emit("axeno-send-receipt", SendReceipt { server_id: server_id.clone(), id, queued });
            }
            ServerFrame::AckOk { .. } => {}
            ServerFrame::Pong { .. } => {}
            ServerFrame::Error { code, message } => {
                let _ = emit_status(&app, &server_id, "server_error", Some(format!("{code}: {message}")));
            }
        }
    }

    writer.abort();
    let _ = emit_status(&app, &server_id, "disconnected", None);
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
    if (16..=96).contains(&token.len()) && token.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')) {
        Ok(())
    } else {
        Err(format!("{label} must be 16-96 URL-safe characters"))
    }
}

fn validate_recipient_id(id: &str) -> Result<(), String> {
    if (16..=128).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')) {
        Ok(())
    } else {
        Err("recipient id must be 16-128 URL-safe characters".into())
    }
}

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}
