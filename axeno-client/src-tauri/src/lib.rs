use tauri::{AppHandle, Manager, State, Emitter};
use std::fs;
use std::sync::Arc;
use tokio::sync::Mutex;
use arti_client::{TorClient, TorClientConfig};
use tor_rtcompat::PreferredRuntime;

pub mod identity;

pub struct AppTorState {
    pub client: Arc<Mutex<Option<TorClient<PreferredRuntime>>>>,
}

fn get_vault_path(app: &AppHandle) -> Result<std::path::PathBuf, String> {
    let mut path = app.path().app_data_dir().map_err(|_| "AppData dir error")?;
    fs::create_dir_all(&path).map_err(|_| "Folder creation error")?;
    path.push("identity.vault");
    Ok(path)
}

// ATOMIC SAVE: Writes to a .tmp file first, locks permissions, then renames. 
// This prevents corruption if the app crashes mid-save.
fn save_vault(app: &AppHandle, identity: &crate::identity::EncryptedIdentity) -> Result<(), String> {
    let vault_path = get_vault_path(app)?;
    let tmp_path = vault_path.with_extension("tmp");
    
    let json = serde_json::to_string(identity).map_err(|_| "Serialization error")?;
    fs::write(&tmp_path, json).map_err(|_| "Write error")?;

    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(mut perms) = fs::metadata(&tmp_path).map(|m| m.permissions()) {
            perms.set_mode(0o600);
            let _ = fs::set_permissions(&tmp_path, perms);
        }
    }
    
    // Atomic rename overwrites the old file instantly
    fs::rename(tmp_path, vault_path).map_err(|_| "Atomic rename failed")?;
    Ok(())
}

#[derive(serde::Serialize)]
struct UnlockResponse {
    fingerprint: String,
    display_name: String,
}

#[tauri::command]
async fn create_identity(app: AppHandle, passphrase: String, display_name: String) -> Result<UnlockResponse, String> {
    let blob = crate::identity::create_encrypted_identity(&passphrase, &display_name).map_err(|e| e.to_string())?;
    save_vault(&app, &blob)?;
    Ok(UnlockResponse { 
        fingerprint: crate::identity::fingerprint(&blob), 
        display_name 
    })
}

#[tauri::command]
async fn has_identity(app: AppHandle) -> Result<bool, String> {
    Ok(get_vault_path(&app)?.exists())
}

#[tauri::command]
async fn unlock_identity(app: AppHandle, passphrase: String) -> Result<UnlockResponse, String> {
    let path = get_vault_path(&app)?;
    let file_data = fs::read_to_string(&path).map_err(|_| "Vault file not found")?;
    let encrypted: crate::identity::EncryptedIdentity = serde_json::from_str(&file_data).map_err(|_| "Corrupted vault")?;
    
    let (fingerprint, display_name) = crate::identity::unlock_identity(&encrypted, &passphrase)
        .map_err(|_| "Incorrect password")?;
        
    Ok(UnlockResponse { fingerprint, display_name })
}

#[tauri::command]
async fn update_display_name(app: AppHandle, passphrase: String, new_name: String) -> Result<(), String> {
    let path = get_vault_path(&app)?;
    let file_data = fs::read_to_string(&path).map_err(|_| "Vault file not found")?;
    let mut encrypted: crate::identity::EncryptedIdentity = serde_json::from_str(&file_data).map_err(|_| "Corrupted vault")?;
    
    crate::identity::update_display_name(&mut encrypted, &passphrase, &new_name)
        .map_err(|_| "Decryption failed or invalid password")?;
        
    save_vault(&app, &encrypted)?;
    Ok(())
}

// NON-BLOCKING TOR: Spawns in background and emits events to the UI
#[tauri::command]
async fn bootstrap_tor(app: AppHandle, state: State<'_, AppTorState>) -> Result<(), String> {
    let client_arc = state.client.clone();
    
    tauri::async_runtime::spawn(async move {
        let _ = app.emit("tor-status", "connecting");
        
        let mut client_lock = client_arc.lock().await;
        if client_lock.is_some() {
            let _ = app.emit("tor-status", "connected");
            return;
        }

        let config = TorClientConfig::default();
        match TorClient::create_bootstrapped(config).await {
            Ok(client) => {
                *client_lock = Some(client);
                let _ = app.emit("tor-status", "connected");
            }
            Err(e) => {
                eprintln!("Tor Bootstrap failed: {}", e);
                let _ = app.emit("tor-status", "failed");
            }
        }
    });

    Ok(()) // Returns to frontend immediately
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(AppTorState { client: Arc::new(Mutex::new(None)) })
        .invoke_handler(tauri::generate_handler![
            create_identity, has_identity, unlock_identity, bootstrap_tor, update_display_name
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}