/**
 * App.tsx — Root application shell and view router.
 *
 * View state machine:
 *   loading → (vault absent) → setup
 *           → (vault present, locked) → locked
 *           → (vault present, unlocked) → vault
 *
 * ## Lock-on-hide security guarantee
 * The Page Visibility API is used to detect when the window is hidden or
 * minimized. On hide, `lock_vault()` is called in Rust (zeroizes the master key)
 * and the view returns to the lock screen. This ensures the key is never left
 * alive in RAM when the user switches away or closes the window.
 */
import { useEffect, useState, useCallback } from "react";
import "./index.css";
import { getVaultStatus, lockVault } from "./lib/tauri";
import { SetupView } from "./components/SetupView";
import { LockScreen } from "./components/LockScreen";
import { VaultView } from "./components/VaultView";

type AppView = "loading" | "setup" | "locked" | "vault";

interface LockState {
  failedAttempts: number;
  lockoutSecs: number;
}

export default function App() {
  const [view, setView] = useState<AppView>("loading");
  const [lockState, setLockState] = useState<LockState>({
    failedAttempts: 0,
    lockoutSecs: 0,
  });

  const initializeView = useCallback(async () => {
    try {
      const status = await getVaultStatus();
      if (!status.vault_exists) {
        setView("setup");
      } else if (status.is_unlocked) {
        setView("vault");
      } else {
        setLockState({
          failedAttempts: status.failed_attempts,
          lockoutSecs: status.lockout_remaining_secs,
        });
        setView("locked");
      }
    } catch {
      setView("locked");
    }
  }, []);

  useEffect(() => {
    initializeView();
  }, [initializeView]);

  // Lock vault when the window is hidden (minimized, switched away, or closed).
  useEffect(() => {
    const handleVisibilityChange = async () => {
      if (document.visibilityState === "hidden") {
        try {
          await lockVault();
        } catch { /* already locked or no vault */ }
        setView((current) => (current === "vault" ? "locked" : current));
      }
    };
    document.addEventListener("visibilitychange", handleVisibilityChange);
    return () => {
      document.removeEventListener("visibilitychange", handleVisibilityChange);
    };
  }, []);

  const handleSetupComplete = useCallback(async () => {
    await initializeView();
  }, [initializeView]);

  const handleUnlock = useCallback(() => {
    setView("vault");
  }, []);

  const handleLock = useCallback(() => {
    setLockState({ failedAttempts: 0, lockoutSecs: 0 });
    setView("locked");
  }, []);

  if (view === "loading") {
    return (
      <div className="flex items-center justify-center h-screen bg-gunmetal-900 text-slate-label font-mono text-xs uppercase tracking-widest">
        <span className="animate-pulse">INITIALIZING...</span>
      </div>
    );
  }

  if (view === "setup") {
    return <SetupView onSetupComplete={handleSetupComplete} />;
  }

  if (view === "locked") {
    return (
      <LockScreen
        onUnlock={handleUnlock}
        initialFailedAttempts={lockState.failedAttempts}
        initialLockoutSecs={lockState.lockoutSecs}
      />
    );
  }

  return <VaultView onLock={handleLock} />;
}
