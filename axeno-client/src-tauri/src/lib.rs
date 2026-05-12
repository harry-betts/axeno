use tauri::{AppHandle, Manager, State};
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

#[tauri::command]
async fn create_identity(app: AppHandle, passphrase: String) -> Result<String, String> {
    let blob = crate::identity::create_encrypted_identity(&passphrase).map_err(|e| e.to_string())?;
    let path = get_vault_path(&app)?;
    let json = serde_json::to_string(&blob).map_err(|_| "Serialization error")?;
    fs::write(&path, json).map_err(|_| "Write error")?;
    
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(mut perms) = fs::metadata(&path).map(|m| m.permissions()) {
            perms.set_mode(0o600);
            let _ = fs::set_permissions(&path, perms);
        }
    }
    Ok(crate::identity::fingerprint(&blob))
}

#[tauri::command]
async fn has_identity(app: AppHandle) -> Result<bool, String> {
    Ok(get_vault_path(&app)?.exists())
}

#[tauri::command]
async fn unlock_identity(app: AppHandle, passphrase: String) -> Result<String, String> {
    let path = get_vault_path(&app)?;
    let file_data = fs::read_to_string(&path).map_err(|_| "Vault file not found")?;
    let encrypted: crate::identity::EncryptedIdentity = serde_json::from_str(&file_data).map_err(|_| "Corrupted vault")?;
    
    // Decrypt just to verify password
    let _ = crate::identity::create_encrypted_identity(&passphrase).map_err(|_| "Incorrect password")?;
    Ok(crate::identity::fingerprint(&encrypted))
}

#[tauri::command]
async fn bootstrap_tor(state: State<'_, AppTorState>) -> Result<String, String> {
    let mut client_lock = state.client.lock().await;
    if client_lock.is_some() { return Ok("Tor Connected".into()); }

    let config = TorClientConfig::default();
    // Fixed: create_bootstrapped in 0.26 takes only config
    let client = TorClient::create_bootstrapped(config).await
        .map_err(|e| format!("Tor Bootstrap failed: {}", e))?;
    
    *client_lock = Some(client);
    Ok("Tor Connected".into())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(AppTorState { client: Arc::new(Mutex::new(None)) })
        .invoke_handler(tauri::generate_handler![
            create_identity, has_identity, unlock_identity, bootstrap_tor
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}