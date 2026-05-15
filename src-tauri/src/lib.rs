//! # lib.rs — Blacksite Node Tauri Command Surface

mod crypto;
mod security;
mod state;

use state::{AppState, Session, VaultState, VaultStatus};
use crate::crypto::{
    create_duress_blob, decrypt_vault, derive_key, encrypt_vault, generate_diceware_passphrase,
    generate_salt, generate_secure_password, read_duress_blob, read_vault_salt,
    try_decrypt_duress, vault_exists, wipe_vault, CredentialEntry, VaultData,
};
use tauri::{Manager, State};
use tokio::sync::Mutex;
use std::time::SystemTime;

// ---------------------------------------------------------------------------
// setup_vault
// ---------------------------------------------------------------------------

/// Initializes a new vault from a frontend-provided master + canary passphrase.
///
/// The frontend generates both passphrases via `generate_passphrase()` and
/// presents them to the user before calling this command. This ensures the user
/// has recorded their passphrases BEFORE the vault is committed to disk.
///
/// Returns `Ok(())`. Both passphrases are caller-provided and never stored.
#[tauri::command]
async fn setup_vault(
    passphrase: String,
    canary_passphrase: String,
    state: State<'_, VaultState>,
) -> Result<(), String> {
    let mut app_state = state.lock().await;

    if vault_exists(&app_state.vault_path) {
        return Err("Vault already exists. Use unlock_vault to access it.".to_string());
    }

    let master_salt = generate_salt();
    let canary_salt = generate_salt();

    let passphrase_clone = passphrase.clone();
    let canary_clone = canary_passphrase.clone();
    let key_result = tokio::task::spawn_blocking(move || -> Result<_, String> {
        let master_key = derive_key(&passphrase_clone, &master_salt)?;
        let duress_blob = create_duress_blob(&canary_clone, &canary_salt)?;
        Ok((master_key, master_salt, duress_blob))
    })
    .await
    .map_err(|e| format!("KDF task error: {e}"))?;

    let (master_key, master_salt, duress_blob) = key_result?;

    let vault_data = VaultData { version: 1, entries: Vec::new() };
    encrypt_vault(&vault_data, &master_key, &app_state.vault_path, &master_salt, Some(&duress_blob))?;

    app_state.duress_blob = Some(duress_blob);
    app_state.session = Some(Session { master_key, vault_data, is_duress: false });

    Ok(())
}

// ---------------------------------------------------------------------------
// get_vault_status
// ---------------------------------------------------------------------------

#[tauri::command]
async fn get_vault_status(state: State<'_, VaultState>) -> Result<VaultStatus, String> {
    let app_state = state.lock().await;
    Ok(VaultStatus {
        vault_exists: vault_exists(&app_state.vault_path),
        is_unlocked: app_state.is_unlocked(),
        failed_attempts: app_state.rate_limiter.failed_count(),
        lockout_remaining_secs: app_state.rate_limiter.remaining_lockout_secs(),
    })
}

// ---------------------------------------------------------------------------
// unlock_vault
// ---------------------------------------------------------------------------

/// Attempts to unlock the vault.
///
/// ## Duress Protocol
/// If the entered passphrase is the canary key (not the master key), the backend:
/// 1. Overwrites the vault file with zeros and deletes it.
/// 2. Opens an in-memory empty session flagged as `is_duress = true`.
/// 3. Returns `Ok(())` — identical to a successful normal unlock.
///
/// The frontend sees no difference. Subsequent reads return zero credentials;
/// writes are silently discarded. On next launch the vault appears uninitialized.
#[tauri::command]
async fn unlock_vault(
    passphrase: String,
    state: State<'_, VaultState>,
) -> Result<(), String> {
    // Check lockout before doing any crypto work
    {
        let app_state = state.lock().await;
        if let Err(remaining) = app_state.rate_limiter.check_lockout() {
            return Err(format!("LOCKED:{remaining}"));
        }
        if !vault_exists(&app_state.vault_path) {
            return Err("No vault found. Run setup first.".to_string());
        }
    }

    let vault_path = {
        let app_state = state.lock().await;
        app_state.vault_path.clone()
    };

    let salt = read_vault_salt(&vault_path)?;

    // Attempt to derive a key and decrypt with the master ciphertext
    let passphrase_for_master = passphrase.clone();
    let salt_clone = salt.clone();
    let master_key_result = tokio::task::spawn_blocking(move || {
        derive_key(&passphrase_for_master, &salt_clone)
    })
    .await
    .map_err(|e| format!("KDF task error: {e}"))?;

    match master_key_result {
        Ok(master_key) => {
            match decrypt_vault(&master_key, &vault_path) {
                Ok(vault_data) => {
                    // Master key success — read duress blob and open real session
                    let duress_blob = read_duress_blob(&vault_path);
                    let mut app_state = state.lock().await;
                    app_state.rate_limiter.record_success();
                    app_state.duress_blob = duress_blob;
                    app_state.session = Some(Session { master_key, vault_data, is_duress: false });
                    Ok(())
                }
                Err(_) => {
                    // Master decrypt failed. Try the duress path before recording failure.
                    let vp = vault_path.clone();
                    let p2 = passphrase.clone();
                    let duress_check = tokio::task::spawn_blocking(move || {
                        try_decrypt_duress(&p2, &vp)
                    })
                    .await
                    .map_err(|e| format!("Duress check error: {e}"))?;

                    match duress_check {
                        Ok(true) => {
                            // Canary key confirmed — wipe vault and open ghost session
                            wipe_vault(&vault_path)?;
                            let mut app_state = state.lock().await;
                            app_state.rate_limiter.record_success();
                            app_state.duress_blob = None;
                            app_state.session = Some(Session {
                                master_key,
                                vault_data: VaultData { version: 1, entries: Vec::new() },
                                is_duress: true,
                            });
                            Ok(())
                        }
                        _ => {
                            // Neither master nor canary — genuine wrong passphrase
                            let mut app_state = state.lock().await;
                            app_state.rate_limiter.record_failure();
                            let remaining = app_state.rate_limiter.remaining_lockout_secs();
                            if remaining > 0 {
                                Err(format!("LOCKED:{remaining}"))
                            } else {
                                Err("WRONG_PASSPHRASE".to_string())
                            }
                        }
                    }
                }
            }
        }
        Err(e) => Err(format!("Key derivation error: {e}")),
    }
}

// ---------------------------------------------------------------------------
// lock_vault
// ---------------------------------------------------------------------------

#[tauri::command]
async fn lock_vault(state: State<'_, VaultState>) -> Result<(), String> {
    let mut app_state = state.lock().await;
    app_state.lock();
    Ok(())
}

// ---------------------------------------------------------------------------
// get_credentials
// ---------------------------------------------------------------------------

#[tauri::command]
async fn get_credentials(state: State<'_, VaultState>) -> Result<Vec<CredentialEntry>, String> {
    let app_state = state.lock().await;
    match &app_state.session {
        Some(session) => Ok(session.vault_data.entries.clone()),
        None => Err("Vault is locked.".to_string()),
    }
}

// ---------------------------------------------------------------------------
// add_credential
// ---------------------------------------------------------------------------

#[tauri::command]
async fn add_credential(
    service: String,
    username: String,
    password: String,
    notes: String,
    state: State<'_, VaultState>,
) -> Result<String, String> {
    let mut app_state = state.lock().await;

    let session = app_state.session.as_mut().ok_or("Vault is locked.")?;

    // In a duress session the vault file is gone — silently succeed
    if session.is_duress {
        let id = format!("{:x}", service.len() as u64 * 31);
        return Ok(id);
    }

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let id = format!("{:x}", now ^ (service.len() as u64 * 31));

    let entry = CredentialEntry {
        id: id.clone(),
        service,
        username,
        password,
        notes,
        created_at: now,
        updated_at: now,
    };

    session.vault_data.entries.push(entry);

    let salt_bytes = read_vault_salt(&app_state.vault_path)?;
    let mut salt_arr = [0u8; 16];
    let copy_len = salt_bytes.len().min(16);
    salt_arr[..copy_len].copy_from_slice(&salt_bytes[..copy_len]);

    let duress_blob = app_state.duress_blob.clone();
    let session = app_state.session.as_ref().ok_or("Vault is locked.")?;
    encrypt_vault(
        &session.vault_data,
        &session.master_key,
        &app_state.vault_path,
        &salt_arr,
        duress_blob.as_ref(),
    )?;

    Ok(id)
}

// ---------------------------------------------------------------------------
// delete_credential
// ---------------------------------------------------------------------------

#[tauri::command]
async fn delete_credential(id: String, state: State<'_, VaultState>) -> Result<(), String> {
    let mut app_state = state.lock().await;

    let session = app_state.session.as_mut().ok_or("Vault is locked.")?;

    if session.is_duress {
        return Ok(());
    }

    let before = session.vault_data.entries.len();
    session.vault_data.entries.retain(|e| e.id != id);
    if session.vault_data.entries.len() == before {
        return Err("Entry not found.".to_string());
    }

    let salt_bytes = read_vault_salt(&app_state.vault_path)?;
    let mut salt_arr = [0u8; 16];
    let copy_len = salt_bytes.len().min(16);
    salt_arr[..copy_len].copy_from_slice(&salt_bytes[..copy_len]);

    let duress_blob = app_state.duress_blob.clone();
    let session = app_state.session.as_ref().ok_or("Vault is locked.")?;
    encrypt_vault(
        &session.vault_data,
        &session.master_key,
        &app_state.vault_path,
        &salt_arr,
        duress_blob.as_ref(),
    )?;

    Ok(())
}

// ---------------------------------------------------------------------------
// generate_passphrase
// ---------------------------------------------------------------------------

#[tauri::command]
async fn generate_passphrase() -> Result<String, String> {
    Ok(generate_diceware_passphrase())
}

// ---------------------------------------------------------------------------
// cmd_generate_secure_password
// ---------------------------------------------------------------------------

#[tauri::command]
async fn cmd_generate_secure_password(length: Option<usize>) -> Result<String, String> {
    let len = length.unwrap_or(24).clamp(12, 128);
    Ok(generate_secure_password(len))
}

// ---------------------------------------------------------------------------
// Tauri application entry point
// ---------------------------------------------------------------------------

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let data_dir = app
                .path()
                .app_data_dir()
                .expect("Failed to resolve app data directory");

            std::fs::create_dir_all(&data_dir)
                .expect("Failed to create app data directory");

            let vault_path = data_dir.join("vault.blacksite");

            app.manage(Mutex::new(AppState::new(vault_path)));

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            setup_vault,
            get_vault_status,
            unlock_vault,
            lock_vault,
            get_credentials,
            add_credential,
            delete_credential,
            generate_passphrase,
            cmd_generate_secure_password,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
