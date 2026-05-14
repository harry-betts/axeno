#![forbid(unsafe_code)]
//! Axeno backend library: identity, vault, and Tor bootstrap.
//!
//! Security architecture summary:
//! - The passphrase is supplied to `create_identity` or `unlock_identity` and
//!   is immediately dropped after the KEK is derived.
//! - The KEK and the decrypted vault live in Rust memory inside `UnlockedSession`,
//!   wrapped in a `Mutex` behind Tauri managed state.
//! - The frontend never sees the passphrase again after unlock.
//! - All mutations to vault contents go through commands that operate on the
//!   in-memory secrets and then call `reseal_vault` (fresh nonce every time).
//! - The on-disk file is saved atomically via tmp+rename. On Unix, the tmp file
//!   is opened with mode 0o600 from the start.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use arti_client::{TorClient, TorClientConfig};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::Mutex;
use tor_rtcompat::PreferredRuntime;

pub mod identity;
pub mod messaging;
pub mod transport;

use identity::{
    change_passphrase, create_identity as id_create, fingerprint, reseal_vault,
    unlock_identity as id_unlock, DerivedKey, EncryptedIdentity, VaultSecrets,
};

// --------------------------------------------------------------------------
// Application state
// --------------------------------------------------------------------------

/// The Tor client. Lazily bootstrapped in the background.
pub struct AppTorState {
    pub client: Arc<Mutex<Option<TorClient<PreferredRuntime>>>>,
}

/// The unlocked session: in-memory secrets + KEK. Both wiped on drop.
/// `None` when the app is locked (i.e. before login or after explicit lock).
pub struct UnlockedSession {
    pub secrets: VaultSecrets,
    pub key: DerivedKey,
}

#[derive(Clone, Default)]
pub struct AppSessionState {
    pub session: Arc<Mutex<Option<UnlockedSession>>>,
    pub messaging_store_lock: Arc<Mutex<()>>,
}

#[derive(Serialize, Deserialize, Default)]
struct UnifiedAppStateFile {
    version: u16,
    identity: Option<EncryptedIdentity>,
    messages_store_json: Option<Vec<u8>>,
}

fn unified_state_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|_| "could not resolve app data dir".to_string())?;
    fs::create_dir_all(&dir).map_err(|e| format!("could not create app data dir: {e}"))?;
    Ok(dir.join("axeno.state"))
}

fn load_unified_state(app: &AppHandle) -> Result<UnifiedAppStateFile, String> {
    let path = unified_state_path(app)?;
    if !path.exists() { return Ok(UnifiedAppStateFile { version: 1, ..Default::default() }); }
    let raw = fs::read(&path).map_err(|e| format!("read unified state failed: {e}"))?;
    let state: UnifiedAppStateFile = serde_json::from_slice(&raw).map_err(|e| format!("corrupted unified state: {e}"))?;
    if state.version > 1 { return Err("unified state was written by a newer Axeno client".to_string()); }
    Ok(state)
}

fn save_unified_state(app: &AppHandle, state: &UnifiedAppStateFile) -> Result<(), String> {
    let path = unified_state_path(app)?;
    let tmp = path.with_file_name(format!(
        "{}.{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("axeno.state"),
        uuid::Uuid::new_v4()
    ));
    let json = serde_json::to_vec(state).map_err(|e| format!("serialize unified state failed: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| format!("open unified state tmp failed: {e}"))?;
        f.write_all(&json).map_err(|e| format!("write unified state failed: {e}"))?;
        f.sync_all().map_err(|e| format!("fsync unified state failed: {e}"))?;
    }
    #[cfg(not(unix))]
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|e| format!("open unified state tmp failed: {e}"))?;
        f.write_all(&json).map_err(|e| format!("write unified state failed: {e}"))?;
        f.sync_all().map_err(|e| format!("fsync unified state failed: {e}"))?;
    }
    if let Err(e) = fs::rename(&tmp, &path) {
        let _ = fs::remove_file(&tmp);
        return Err(format!("rename unified state failed: {e}"));
    }
    #[cfg(unix)]
    {
        if let Some(parent) = path.parent() {
            if let Ok(dir) = fs::File::open(parent) { let _ = dir.sync_all(); }
        }
    }
    Ok(())
}

pub(crate) fn update_unified_message_store(app: &AppHandle, store_json: Vec<u8>) -> Result<(), String> {
    let mut unified = load_unified_state(app).unwrap_or_else(|_| UnifiedAppStateFile { version: 1, ..Default::default() });
    unified.version = 1;
    unified.messages_store_json = Some(store_json);
    save_unified_state(app, &unified)
}

pub(crate) fn read_unified_message_store(app: &AppHandle) -> Result<Option<Vec<u8>>, String> {
    Ok(load_unified_state(app)?.messages_store_json)
}

// --------------------------------------------------------------------------
// Vault file I/O
// --------------------------------------------------------------------------

fn vault_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|_| "could not resolve app data dir".to_string())?;
    fs::create_dir_all(&dir).map_err(|e| format!("could not create app data dir: {e}"))?;
    Ok(dir.join("identity.vault"))
}

/// Atomically write a vault file with restrictive permissions.
///
/// On Unix, the tmp file is opened with 0o600 from the start, so there is no
/// window during which the file exists with default permissions. The tmp file
/// uses a unique UUID name and create_new to prevent symlink attacks.
pub(crate) fn save_vault(app: &AppHandle, blob: &EncryptedIdentity) -> Result<(), String> {
    let path = vault_path(app)?;
    let tmp = path.with_file_name(format!(
        "{}.{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("identity.vault"),
        uuid::Uuid::new_v4()
    ));

    let json = serde_json::to_vec(blob).map_err(|e| format!("serialize error: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| format!("open tmp failed: {e}"))?;
        f.write_all(&json)
            .map_err(|e| format!("write tmp failed: {e}"))?;
        f.sync_all().map_err(|e| format!("fsync failed: {e}"))?;
    }
    #[cfg(not(unix))]
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|e| format!("open tmp failed: {e}"))?;
        f.write_all(&json)
            .map_err(|e| format!("write tmp failed: {e}"))?;
        f.sync_all().map_err(|e| format!("fsync failed: {e}"))?;
    }

    if let Err(e) = fs::rename(&tmp, &path) {
        let _ = fs::remove_file(&tmp);
        return Err(format!("atomic rename failed: {e}"));
    }
    #[cfg(unix)]
    {
        if let Some(parent) = path.parent() {
            if let Ok(dir) = fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
    }
    let mut unified = load_unified_state(app).unwrap_or_else(|_| UnifiedAppStateFile { version: 1, ..Default::default() });
    unified.version = 1;
    unified.identity = Some(blob.clone());
    save_unified_state(app, &unified)?;
    Ok(())
}

pub(crate) fn load_vault(app: &AppHandle) -> Result<EncryptedIdentity, String> {
    if let Ok(unified) = load_unified_state(app) {
        if let Some(identity) = unified.identity { return Ok(identity); }
    }
    let path = vault_path(app)?;
    let data = fs::read(&path).map_err(|_| "vault file not found".to_string())?;
    let blob: EncryptedIdentity = serde_json::from_slice(&data).map_err(|_| "corrupted vault".to_string())?;
    let mut unified = load_unified_state(app).unwrap_or_else(|_| UnifiedAppStateFile { version: 1, ..Default::default() });
    unified.version = 1;
    unified.identity = Some(blob.clone());
    let _ = save_unified_state(app, &unified);
    Ok(blob)
}

// --------------------------------------------------------------------------
// API response types
// --------------------------------------------------------------------------

#[derive(Serialize)]
pub struct UnlockResponse {
    pub fingerprint: String,
    pub display_name: String,
}

#[derive(Serialize)]
pub struct PublicIdentityResponse {
    pub fingerprint: String,
    pub public_key_hex: String,
    pub registration_id: u16,
}

// --------------------------------------------------------------------------
// Commands
// --------------------------------------------------------------------------

#[tauri::command]
async fn has_identity(app: AppHandle) -> Result<bool, String> {
    if vault_path(&app)?.exists() { return Ok(true); }
    Ok(load_unified_state(&app)
        .map(|state| state.identity.is_some())
        .unwrap_or(false))
}

/// Create a new identity. Persists the encrypted vault and caches the unlocked
/// session in memory. The passphrase is dropped after this returns.
#[tauri::command]
async fn create_identity(
    app: AppHandle,
    session: State<'_, AppSessionState>,
    passphrase: String,
    display_name: String,
) -> Result<UnlockResponse, String> {
    let created = id_create(&passphrase, &display_name).map_err(|e| e.to_string())?;
    drop(passphrase); // explicit drop for clarity; the String allocator may still hold it briefly

    save_vault(&app, &created.blob)?;

    let response = UnlockResponse {
        fingerprint: fingerprint(&created.blob),
        display_name: created.secrets.display_name.clone(),
    };

    *session.session.lock().await = Some(UnlockedSession {
        secrets: created.secrets,
        key: created.key,
    });

    Ok(response)
}

/// Unlock an existing identity. On success the decrypted vault and the KEK are
/// cached in memory; the passphrase is dropped.
#[tauri::command]
async fn unlock_identity(
    app: AppHandle,
    session: State<'_, AppSessionState>,
    passphrase: String,
) -> Result<UnlockResponse, String> {
    let blob = load_vault(&app)?;
    let unlocked = id_unlock(&blob, &passphrase).map_err(|_| "incorrect password".to_string())?;
    drop(passphrase);

    let response = UnlockResponse {
        fingerprint: fingerprint(&blob),
        display_name: unlocked.secrets.display_name.clone(),
    };

    *session.session.lock().await = Some(UnlockedSession {
        secrets: unlocked.secrets,
        key: unlocked.key,
    });

    Ok(response)
}


/// Return public identity material only. Does not require decrypting private keys.
#[tauri::command]
async fn current_identity_public(app: AppHandle) -> Result<PublicIdentityResponse, String> {
    let blob = load_vault(&app)?;
    Ok(PublicIdentityResponse {
        fingerprint: fingerprint(&blob),
        public_key_hex: hex::encode(&blob.public_key),
        registration_id: blob.registration_id,
    })
}

/// Explicitly drop the in-memory session.
#[tauri::command]
async fn lock_identity(session: State<'_, AppSessionState>) -> Result<(), String> {
    *session.session.lock().await = None;
    Ok(())
}

/// Whether the session is currently unlocked.
#[tauri::command]
async fn is_unlocked(session: State<'_, AppSessionState>) -> Result<bool, String> {
    Ok(session.session.lock().await.is_some())
}

/// Update the display name. Mutates the in-memory secrets, reseals with a
/// fresh nonce, and writes the new blob to disk. Requires an unlocked session.
#[tauri::command]
async fn update_display_name(
    app: AppHandle,
    session: State<'_, AppSessionState>,
    new_name: String,
) -> Result<(), String> {
    let mut blob = load_vault(&app)?;
    let mut guard = session.session.lock().await;
    let unlocked = guard.as_mut().ok_or_else(|| "vault is locked".to_string())?;

    unlocked.secrets.display_name = new_name;
    reseal_vault(&mut blob, &unlocked.key, &unlocked.secrets).map_err(|e| e.to_string())?;
    save_vault(&app, &blob)?;
    Ok(())
}

/// Change the passphrase. Requires an unlocked session. Generates a fresh salt,
/// derives a new KEK, re-encrypts the vault, and replaces the cached KEK.
#[tauri::command]
async fn change_password(
    app: AppHandle,
    session: State<'_, AppSessionState>,
    new_passphrase: String,
) -> Result<(), String> {
    let _store_guard = session.messaging_store_lock.lock().await;
    let mut blob = load_vault(&app)?;
    let mut guard = session.session.lock().await;
    let unlocked = guard.as_mut().ok_or_else(|| "vault is locked".to_string())?;

    let old_key = unlocked.key.expose_for_rekey();
    let new_key =
        change_passphrase(&mut blob, &unlocked.secrets, &new_passphrase).map_err(|e| e.to_string())?;
    drop(new_passphrase);
    let new_key_bytes = new_key.expose_for_rekey();

    // Re-encrypt the message/contact store before committing the vault key change.
    // Otherwise the vault unlocks with the new password but messages.store remains
    // encrypted under the old derived store key.
    messaging::reencrypt_message_store(&app, &old_key, &new_key_bytes)?;

    save_vault(&app, &blob)?;
    unlocked.key = new_key;
    Ok(())
}

/// Bootstrap Tor in the background. Returns immediately; status updates are
/// emitted via the `tor-status` event.
///
/// Event payloads:
/// - `"connecting"` — bootstrap in progress
/// - `"connected"` — circuits available
/// - `{"status": "failed", "reason": "..."}` — bootstrap failed with details
#[tauri::command]
async fn bootstrap_tor(app: AppHandle, state: State<'_, AppTorState>) -> Result<(), String> {
    let client_arc = state.client.clone();
    tauri::async_runtime::spawn(async move {
        let _ = app.emit("tor-status", serde_json::json!({ "status": "connecting" }));

        let mut guard = client_arc.lock().await;
        if guard.is_some() {
            let _ = app.emit("tor-status", serde_json::json!({ "status": "connected" }));
            return;
        }

        let config = TorClientConfig::default();
        match TorClient::create_bootstrapped(config).await {
            Ok(client) => {
                *guard = Some(client);
                let _ = app.emit("tor-status", serde_json::json!({ "status": "connected" }));
            }
            Err(e) => {
                let _ = app.emit(
                    "tor-status",
                    serde_json::json!({ "status": "failed", "reason": e.to_string() }),
                );
            }
        }
    });
    Ok(())
}


// --------------------------------------------------------------------------
// WebSocket transport commands
// --------------------------------------------------------------------------

#[tauri::command]
async fn transport_connect_server(
    app: AppHandle,
    state: State<'_, transport::TransportState>,
    tor: State<'_, AppTorState>,
    server_id: String,
    url: String,
    recipient_id: String,
    auth_token: String,
    delivery_token: String,
) -> Result<(), String> {
    transport::connect_server(app, state.inner(), tor.client.clone(), server_id, url, recipient_id, auth_token, delivery_token).await
}

#[tauri::command]
async fn transport_disconnect_server(
    state: State<'_, transport::TransportState>,
    server_id: String,
) -> Result<(), String> {
    transport::disconnect_server(state.inner(), server_id).await
}

#[tauri::command]
async fn transport_ack_envelopes(
    state: State<'_, transport::TransportState>,
    server_id: String,
    ids: Vec<uuid::Uuid>,
) -> Result<(), String> {
    transport::ack_envelopes(state.inner(), server_id, ids).await
}

#[tauri::command]
async fn transport_list_connections(
    state: State<'_, transport::TransportState>,
) -> Result<Vec<(String, String, String)>, String> {
    transport::list_connections(state.inner()).await
}



#[tauri::command]
async fn messaging_load_private_server_settings(
    app: AppHandle,
    session: State<'_, AppSessionState>,
) -> Result<messaging::PrivateServerSettings, String> {
    messaging::load_private_server_settings(app, &session).await
}

#[tauri::command]
async fn messaging_save_private_server_settings(
    app: AppHandle,
    session: State<'_, AppSessionState>,
    settings: messaging::PrivateServerSettings,
) -> Result<messaging::PrivateServerSettings, String> {
    messaging::save_private_server_settings(app, &session, settings).await
}

#[tauri::command]
async fn messaging_generate_connection_code(
    app: AppHandle,
    session: State<'_, AppSessionState>,
    transport_state: State<'_, transport::TransportState>,
    tor_state: State<'_, AppTorState>,
    server_url: Option<String>,
    server_name: Option<String>,
    reusable: bool,
) -> Result<messaging::ConnectionCodeResponse, String> {
    messaging::generate_connection_code(app, &session, transport_state.inner(), tor_state.client.clone(), server_url, server_name, reusable).await
}

#[tauri::command]
async fn messaging_list_connection_codes(
    app: AppHandle,
    session: State<'_, AppSessionState>,
) -> Result<Vec<messaging::ConnectionCodeResponse>, String> {
    messaging::list_connection_codes(app, &session).await
}

#[tauri::command]
async fn messaging_delete_connection_code(
    app: AppHandle,
    session: State<'_, AppSessionState>,
    transport_state: State<'_, transport::TransportState>,
    id: String,
) -> Result<(), String> {
    let connection_ids = messaging::delete_connection_code(app, &session, id).await?;
    for connection_id in connection_ids {
        let _ = transport::retire_mailbox(transport_state.inner(), connection_id).await;
    }
    Ok(())
}

#[tauri::command]
async fn messaging_add_contact_from_code(
    app: AppHandle,
    session: State<'_, AppSessionState>,
    tor_state: State<'_, AppTorState>,
    code: String,
) -> Result<messaging::StoredContact, String> {
    messaging::add_contact_from_code(app, &session, tor_state.client.clone(), code).await
}

#[tauri::command]
async fn messaging_snapshot(
    app: AppHandle,
    session: State<'_, AppSessionState>,
) -> Result<messaging::MessagingSnapshot, String> {
    messaging::snapshot(app, &session).await
}

#[tauri::command]
async fn messaging_connect_all(
    app: AppHandle,
    session: State<'_, AppSessionState>,
    transport_state: State<'_, transport::TransportState>,
    tor_state: State<'_, AppTorState>,
) -> Result<(), String> {
    messaging::connect_all(app, &session, transport_state.inner(), tor_state.client.clone()).await
}

#[tauri::command]
async fn messaging_send_text_message(
    app: AppHandle,
    session: State<'_, AppSessionState>,
    transport_state: State<'_, transport::TransportState>,
    tor_state: State<'_, AppTorState>,
    contact_id: String,
    text: String,
) -> Result<messaging::SendMessageResponse, String> {
    // libsignal's current Rust store futures are not Send. Do not block the
    // Tauri/UI command thread with block_on; run the non-Send future on a
    // dedicated current-thread runtime inside a blocking worker instead.
    let session = session.inner().clone();
    let transport_state = transport_state.inner().clone();
    let tor_client = tor_state.client.clone();
    tauri::async_runtime::spawn_blocking(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("could not start message worker runtime: {e}"))?
            .block_on(messaging::send_text_message(
                app,
                &session,
                &transport_state,
                tor_client,
                contact_id,
                text,
            ))
    })
    .await
    .map_err(|e| format!("message worker panicked or was cancelled: {e}"))?
}


#[tauri::command]
async fn messaging_mark_message_relay_received(
    app: AppHandle,
    session: State<'_, AppSessionState>,
    message_id: String,
    queued: bool,
) -> Result<Option<messaging::StoredMessage>, String> {
    messaging::mark_message_relay_received(app, &session, message_id, queued).await
}

#[tauri::command]
async fn messaging_mark_message_send_failed(
    app: AppHandle,
    session: State<'_, AppSessionState>,
    message_id: String,
) -> Result<Option<messaging::StoredMessage>, String> {
    messaging::mark_message_send_failed(app, &session, message_id).await
}

#[tauri::command]
async fn messaging_mark_contact_verified(
    app: AppHandle,
    session: State<'_, AppSessionState>,
    contact_id: String,
    verified: bool,
) -> Result<messaging::StoredContact, String> {
    messaging::mark_contact_verified(app, &session, contact_id, verified).await
}

#[tauri::command]
async fn messaging_verification_code_for_contact(
    app: AppHandle,
    session: State<'_, AppSessionState>,
    contact_id: String,
) -> Result<messaging::VerificationCodeResponse, String> {
    messaging::verification_code_for_contact(app, &session, contact_id).await
}

#[tauri::command]
async fn messaging_verify_contact_with_code(
    app: AppHandle,
    session: State<'_, AppSessionState>,
    contact_id: String,
    code: String,
) -> Result<messaging::StoredContact, String> {
    messaging::verify_contact_with_code(app, &session, contact_id, code).await
}

#[tauri::command]
async fn messaging_mark_contact_read(
    app: AppHandle,
    session: State<'_, AppSessionState>,
    contact_id: String,
) -> Result<messaging::StoredContact, String> {
    messaging::mark_contact_read(app, &session, contact_id).await
}


#[tauri::command]
async fn messaging_migrate_contact_with_code(
    app: AppHandle,
    session: State<'_, AppSessionState>,
    transport_state: State<'_, transport::TransportState>,
    tor_state: State<'_, AppTorState>,
    contact_id: String,
    code: String,
) -> Result<messaging::StoredContact, String> {
    messaging::migrate_contact_with_code(app, &session, transport_state.inner(), tor_state.client.clone(), contact_id, code).await
}

#[tauri::command]
async fn messaging_update_contact_server(
    app: AppHandle,
    session: State<'_, AppSessionState>,
    contact_id: String,
    server_url: String,
) -> Result<messaging::StoredContact, String> {
    messaging::update_contact_server(app, &session, contact_id, server_url).await
}

// This handler is no longer exposed as a Tauri command — envelope processing
// now happens directly in the Rust transport layer (M2 security fix). Kept as
// an internal helper for potential debugging use.
#[allow(dead_code)]
async fn messaging_handle_incoming_envelope(
    app: AppHandle,
    session: State<'_, AppSessionState>,
    runtime: State<'_, messaging::MessagingRuntimeState>,
    transport_state: State<'_, transport::TransportState>,
    tor_state: State<'_, AppTorState>,
    server_id: String,
    envelope: transport::StoredEnvelope,
) -> Result<(), String> {
    // Same deal as send: sealed-sender decrypt uses non-Send libsignal futures,
    // so isolate it on a worker thread instead of freezing the command loop.
    let session = session.inner().clone();
    let runtime = runtime.inner().clone();
    let transport_state = transport_state.inner().clone();
    let tor_client = tor_state.client.clone();
    tauri::async_runtime::spawn_blocking(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("could not start message worker runtime: {e}"))?
            .block_on(messaging::handle_incoming_envelope(
                app,
                &session,
                &runtime,
                &transport_state,
                tor_client,
                server_id,
                envelope,
            ))
    })
    .await
    .map_err(|e| format!("message worker panicked or was cancelled: {e}"))?
}

// --------------------------------------------------------------------------
// Entry point
// --------------------------------------------------------------------------

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(AppTorState {
            client: Arc::new(Mutex::new(None)),
        })
        .manage(AppSessionState::default())
        .manage(messaging::MessagingRuntimeState::new())
        .manage(transport::TransportState::new())
        .invoke_handler(tauri::generate_handler![
            has_identity,
            create_identity,
            unlock_identity,
            lock_identity,
            is_unlocked,
            current_identity_public,
            update_display_name,
            change_password,
            bootstrap_tor,
            messaging_load_private_server_settings,
            messaging_save_private_server_settings,
            messaging_generate_connection_code,
            messaging_list_connection_codes,
            messaging_delete_connection_code,
            messaging_add_contact_from_code,
            messaging_snapshot,
            messaging_connect_all,
            messaging_send_text_message,
            messaging_mark_message_relay_received,
            messaging_mark_message_send_failed,
            messaging_mark_contact_verified,
            messaging_verification_code_for_contact,
            messaging_verify_contact_with_code,
            messaging_mark_contact_read,
            messaging_migrate_contact_with_code,
            messaging_update_contact_server,
            transport_connect_server,
            transport_disconnect_server,
            transport_ack_envelopes,
            transport_list_connections,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}