//! # security.rs — Blacksite Node Active Defense Engine
//!
//! ## Threat Model
//! This module protects against **online brute-force attacks** — a scenario where
//! an adversary has access to the running application (e.g., physical access to an
//! unlocked machine) and attempts to guess the master passphrase by submitting
//! repeated unlock requests.
//!
//! ## Mitigations Implemented
//!
//! ### Exponential Backoff Rate Limiter
//! After each failed authentication attempt, the next unlock call is blocked for
//! an exponentially growing lockout duration:
//! - Attempt 1: immediate (no lockout after first fail — show warning)
//! - Attempt 2: 1 second lockout
//! - Attempt 3: 3 seconds lockout
//! - Attempt 4: 10 seconds lockout
//! - Attempt 5: 30 seconds lockout
//! - Attempt 6+: 60 seconds lockout (sustained maximum)
//!
//! This is not a substitute for the Argon2id KDF latency — it is a *complementary*
//! layer. Together they reduce brute-force throughput from ~3 attempts/second
//! (Argon2id alone) to ~1 attempt/minute at attempt 5+.
//!
//! ### In-Memory State Only
//! Attempt counts and lockout deadlines are stored in RAM via `tokio::sync::Mutex`.
//! There is no persistence to disk — a process restart resets the counter. This is
//! intentional: persistent lockout counters on disk could be used as a side-channel
//! to confirm the vault exists and has been attacked. The Argon2id KDF provides the
//! durable defense against offline attacks.

use std::time::{Duration, Instant};

/// Tracks the brute-force attempt state for a single vault session.
pub struct RateLimiter {
    /// Number of consecutive failed authentication attempts since last success.
    failed_attempts: u32,
    /// The earliest `Instant` at which the next unlock attempt is permitted.
    /// `None` means no lockout is active.
    lockout_until: Option<Instant>,
}

impl RateLimiter {
    /// Creates a fresh rate limiter with zero failed attempts.
    pub fn new() -> Self {
        Self {
            failed_attempts: 0,
            lockout_until: None,
        }
    }

    /// Returns `Ok(())` if an unlock attempt is currently allowed, or
    /// `Err(remaining_seconds)` with the number of seconds the caller must wait.
    ///
    /// The check is non-blocking — it reads the system clock once and returns
    /// immediately. The Tauri command layer is responsible for propagating the
    /// lockout duration to the frontend.
    pub fn check_lockout(&self) -> Result<(), u64> {
        if let Some(deadline) = self.lockout_until {
            let now = Instant::now();
            if now < deadline {
                let remaining = deadline.duration_since(now);
                return Err(remaining.as_secs() + 1); // +1 to round up to whole seconds
            }
        }
        Ok(())
    }

    /// Records a failed authentication attempt and sets the next lockout deadline.
    ///
    /// The lockout schedule uses a piecewise exponential function:
    ///
    /// | Attempts failed | Lockout duration |
    /// |-----------------|------------------|
    /// | 1               | 0 s (warning only) |
    /// | 2               | 1 s              |
    /// | 3               | 3 s              |
    /// | 4               | 10 s             |
    /// | 5               | 30 s             |
    /// | 6+              | 60 s             |
    pub fn record_failure(&mut self) {
        self.failed_attempts = self.failed_attempts.saturating_add(1);
        let lockout_secs: u64 = match self.failed_attempts {
            0 | 1 => 0,   // First failure: show warning, no lockout
            2 => 1,
            3 => 3,
            4 => 10,
            5 => 30,
            _ => 60,      // Sustained maximum — one attempt per minute
        };

        if lockout_secs > 0 {
            self.lockout_until = Some(Instant::now() + Duration::from_secs(lockout_secs));
        }
    }

    /// Resets the rate limiter after a successful authentication.
    /// Called by `unlock_vault` on success to allow future legitimate unlocks.
    pub fn record_success(&mut self) {
        self.failed_attempts = 0;
        self.lockout_until = None;
    }

    /// Returns the number of consecutive failed attempts for UI display.
    pub fn failed_count(&self) -> u32 {
        self.failed_attempts
    }

    /// Returns how many seconds remain in the current lockout, or 0 if none.
    pub fn remaining_lockout_secs(&self) -> u64 {
        if let Some(deadline) = self.lockout_until {
            let now = Instant::now();
            if now < deadline {
                return deadline.duration_since(now).as_secs() + 1;
            }
        }
        0
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}
