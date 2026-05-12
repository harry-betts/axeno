use std::fs;
use std::path::PathBuf;
use tauri::Manager;
use crate::identity::{create_encrypted_identity, decrypt_identity, fingerprint, EncryptedIdentity};

fn identity_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app.path()
        .app_data_dir()
        .map_err(|e| e.to_string())?;
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join("identity.json"))
}

#[tauri::command]
pub async fn identity_exists(app: tauri::AppHandle) -> Result<bool, String> {
    Ok(identity_path(&app)?.exists())
}

#[tauri::command]
pub async fn create_identity(
    app: tauri::AppHandle,
    passphrase: String,
) -> Result<String, String> {
    let path = identity_path(&app)?;
    if path.exists() {
        return Err("identity already exists".into());
    }

    let blob = create_encrypted_identity(&passphrase)
        .map_err(|e| e.to_string())?;

    let json = serde_json::to_string(&blob).map_err(|e| e.to_string())?;
    fs::write(&path, json).map_err(|e| e.to_string())?;

    Ok(fingerprint(&blob))
}

#[tauri::command]
pub async fn unlock_identity(
    app: tauri::AppHandle,
    passphrase: String,
) -> Result<String, String> {
    let path = identity_path(&app)?;
    let json = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let blob: EncryptedIdentity = serde_json::from_str(&json).map_err(|e| e.to_string())?;

    // Verify the passphrase by attempting decryption; discard result.
    decrypt_identity(&blob, &passphrase).map_err(|e| e.to_string())?;

    Ok(fingerprint(&blob))
}