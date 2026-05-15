//! # state.rs — Blacksite Node Session State Manager
//!
//! ## Zero-Knowledge Session Architecture
//!
//! The master key NEVER touches persistent storage. This module manages the
//! lifecycle of the decrypted session state — the window between a successful
//! `unlock_vault()` and the next `lock_vault()` or process termination.
//!
//! ## Session State Machine
//!
//! ```
//! [Locked / No Vault]
//!       │
//!       ├─── setup_vault() ──────────────► [Locked + Vault Exists]
//!       │                                        │
//!       └─── vault_exists() == false             │
//!                                        unlock_vault(passphrase)
//!                                                │
//!                                                ▼
//!                                          [Unlocked]
//!                                         MasterKey in RAM
//!                                         VaultData in RAM
//!                                                │
//!                                         lock_vault() / close
//!                                                │
//!                                                ▼
//!                                          [Locked]
//!                                         Key zeroized
//!                                         VaultData dropped
//! ```
//!
//! ## Memory Safety
//! - `MasterKey` uses `ZeroizeOnDrop` — when dropped, bytes are overwritten.
//! - `VaultData` is dropped normally when `AppState.session` is set to `None`.
//! - The `tokio::sync::Mutex` prevents concurrent access to session state,
//!   eliminating race conditions where a lock operation races with an add operation.

use crate::crypto::{DuressBlob, MasterKey, VaultData};
use crate::security::RateLimiter;
use std::path::PathBuf;
use tokio::sync::Mutex;

/// The complete runtime state of a Blacksite Node session.
/// Wrapped in `tokio::sync::Mutex` and registered as a Tauri managed state,
/// enabling safe concurrent access from multiple Tauri commands.
pub struct AppState {
    /// Decrypted session. `None` when the vault is locked.
    /// Contains the master key and cached vault data when unlocked.
    pub session: Option<Session>,
    /// Rate limiter for failed authentication attempts.
    pub rate_limiter: RateLimiter,
    /// Absolute path to the vault file. Determined at startup.
    pub vault_path: PathBuf,
    /// Cached duress blob from the on-disk vault. Carried in memory so
    /// encrypt_vault can re-embed it without re-reading the full file.
    /// Cleared when the vault is locked.
    pub duress_blob: Option<DuressBlob>,
}

/// Active session data — exists only while the vault is unlocked.
pub struct Session {
    /// Derived 256-bit key. Zeroized on drop.
    pub master_key: MasterKey,
    /// Cached decrypted vault contents. Dropped (not zeroized) on lock.
    pub vault_data: VaultData,
    /// True when this session was opened via the duress/canary key.
    /// In a duress session the vault is already wiped; writes are silently
    /// discarded to maintain the illusion of a functioning empty vault.
    pub is_duress: bool,
}

impl AppState {
    pub fn new(vault_path: PathBuf) -> Self {
        Self {
            session: None,
            rate_limiter: RateLimiter::new(),
            vault_path,
            duress_blob: None,
        }
    }

    /// Returns `true` if there is an active unlocked session.
    pub fn is_unlocked(&self) -> bool {
        self.session.is_some()
    }

    /// Locks the vault by dropping the session. The `MasterKey` inside
    /// `Session` is zeroized via its `ZeroizeOnDrop` impl at this point.
    pub fn lock(&mut self) {
        self.session = None;
        self.duress_blob = None;
        // MasterKey::bytes are zeroed here by ZeroizeOnDrop
    }
}

/// Type alias for the Tauri-managed state handle.
/// All Tauri commands access session state via `tauri::State<'_, VaultState>`.
pub type VaultState = Mutex<AppState>;

/// Serializable credential entry for frontend consumption.
/// Identical to `CredentialEntry` but included here for explicit API surface control.
#[allow(unused)]
pub use crate::crypto::CredentialEntry as Credential;

/// Serializable summary of session status for the frontend.
#[derive(serde::Serialize)]
pub struct VaultStatus {
    pub vault_exists: bool,
    pub is_unlocked: bool,
    pub failed_attempts: u32,
    pub lockout_remaining_secs: u64,
}
