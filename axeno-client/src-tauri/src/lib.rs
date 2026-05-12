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
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::Mutex;
use tor_rtcompat::PreferredRuntime;

pub mod identity;

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

#[derive(Default)]
pub struct AppSessionState {
    pub session: Arc<Mutex<Option<UnlockedSession>>>,
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
/// window during which the file exists with default permissions.
fn save_vault(app: &AppHandle, blob: &EncryptedIdentity) -> Result<(), String> {
    let path = vault_path(app)?;
    let tmp = path.with_extension("vault.tmp");

    let json = serde_json::to_vec(blob).map_err(|e| format!("serialize error: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
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
            .create(true)
            .truncate(true)
            .open(&tmp)
            .map_err(|e| format!("open tmp failed: {e}"))?;
        f.write_all(&json)
            .map_err(|e| format!("write tmp failed: {e}"))?;
        f.sync_all().map_err(|e| format!("fsync failed: {e}"))?;
    }

    fs::rename(&tmp, &path).map_err(|e| format!("atomic rename failed: {e}"))?;
    Ok(())
}

fn load_vault(app: &AppHandle) -> Result<EncryptedIdentity, String> {
    let path = vault_path(app)?;
    let data = fs::read(&path).map_err(|_| "vault file not found".to_string())?;
    serde_json::from_slice(&data).map_err(|_| "corrupted vault".to_string())
}

// --------------------------------------------------------------------------
// API response types
// --------------------------------------------------------------------------

#[derive(Serialize)]
pub struct UnlockResponse {
    pub fingerprint: String,
    pub display_name: String,
}

// --------------------------------------------------------------------------
// Commands
// --------------------------------------------------------------------------

#[tauri::command]
async fn has_identity(app: AppHandle) -> Result<bool, String> {
    Ok(vault_path(&app)?.exists())
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
    let mut blob = load_vault(&app)?;
    let mut guard = session.session.lock().await;
    let unlocked = guard.as_mut().ok_or_else(|| "vault is locked".to_string())?;

    let new_key =
        change_passphrase(&mut blob, &unlocked.secrets, &new_passphrase).map_err(|e| e.to_string())?;
    drop(new_passphrase);

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
        .invoke_handler(tauri::generate_handler![
            has_identity,
            create_identity,
            unlock_identity,
            lock_identity,
            is_unlocked,
            update_display_name,
            change_password,
            bootstrap_tor,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}