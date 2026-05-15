import React, { useState, useEffect, useRef, useCallback } from "react";
import { Lock, AlertTriangle, Eye, EyeOff } from "lucide-react";
import { unlockVault, getVaultStatus } from "../lib/tauri";

interface LockScreenProps {
  onUnlock: () => void;
  initialFailedAttempts?: number;
  initialLockoutSecs?: number;
}

export const LockScreen: React.FC<LockScreenProps> = ({
  onUnlock,
  initialFailedAttempts = 0,
  initialLockoutSecs = 0,
}) => {
  const [passphrase, setPassphrase] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>("");
  const [failedAttempts, setFailedAttempts] = useState(initialFailedAttempts);
  const [lockoutSecs, setLockoutSecs] = useState(initialLockoutSecs);
  const [isRevealed, setIsRevealed] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (lockoutSecs > 0) {
      timerRef.current = setInterval(() => {
        setLockoutSecs((s) => {
          if (s <= 1) {
            if (timerRef.current) clearInterval(timerRef.current);
            return 0;
          }
          return s - 1;
        });
      }, 1000);
    }
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [lockoutSecs]);

  const handleUnlock = useCallback(async () => {
    if (loading || lockoutSecs > 0 || !passphrase.trim()) return;

    setLoading(true);
    setError("");

    try {
      await unlockVault(passphrase.trim());
      onUnlock();
    } catch (raw) {
      const msg = String(raw);
      if (msg.startsWith("LOCKED:")) {
        const secs = parseInt(msg.split(":")[1], 10);
        setLockoutSecs(secs);
        const status = await getVaultStatus().catch(() => null);
        if (status) setFailedAttempts(status.failed_attempts);
        setError(`Lockout active. Wait ${secs}s before next attempt.`);
      } else if (msg === "WRONG_PASSPHRASE") {
        const status = await getVaultStatus().catch(() => null);
        if (status) {
          setFailedAttempts(status.failed_attempts);
          setLockoutSecs(status.lockout_remaining_secs);
        }
        setError("Authentication failed. Incorrect passphrase.");
      } else {
        setError(msg);
      }
      setPassphrase("");
      inputRef.current?.focus();
    } finally {
      setLoading(false);
    }
  }, [loading, lockoutSecs, passphrase, onUnlock]);

  const isLocked = lockoutSecs > 0;

  return (
    <div className="flex flex-col h-full bg-gunmetal-900 text-slate-text font-mono">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-3 bg-gunmetal-800 border-b border-ops-700">
        <div className="flex items-center gap-3">
          <img src="/app_logo.png" alt="Blacksite Node" className="h-6 w-auto object-contain" />
          <span className="text-xs uppercase tracking-widest text-slate-dim">
            BLACKSITE NODE — AUTHENTICATION REQUIRED
          </span>
        </div>
        <div className={`text-xs uppercase ${isLocked ? "text-amber-warn" : "text-slate-label"}`}>
          {isLocked ? `LOCKED — ${lockoutSecs}s` : "VAULT SECURED"}
        </div>
      </div>

      <div className="flex flex-col items-center justify-center flex-1 px-8 max-w-xl mx-auto w-full">
        {/* Lock icon */}
        <div className="mb-8">
          <Lock
            size={48}
            className={`${isLocked ? "text-amber-warn" : "text-slate-dim"} transition-colors`}
          />
        </div>

        {/* Terminal prompt + hold-to-reveal input */}
        <div className="w-full mb-2">
          <div className="label-ops mb-2">MASTER PASSPHRASE</div>
          <div className="flex items-center gap-2 bg-gunmetal-800 border border-ops-600 focus-within:border-blue-ops px-3 py-2">
            <span className="text-blue-active text-sm select-none">▶</span>
            <input
              ref={inputRef}
              type={isRevealed ? "text" : "password"}
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleUnlock()}
              placeholder="word1-word2-word3-word4-word5"
              className="flex-1 bg-transparent outline-none text-slate-text text-sm font-mono placeholder:text-slate-label"
              disabled={loading || isLocked}
              autoFocus
              autoComplete="off"
              spellCheck={false}
            />
            {loading && (
              <span className="text-xs text-slate-label animate-pulse">DERIVING KEY...</span>
            )}
            {/* Hold-to-reveal button — text visible only while mousedown */}
            <button
              className={`select-none p-1 transition-colors ${
                isRevealed ? "text-blue-active" : "text-slate-label hover:text-slate-dim"
              }`}
              onMouseDown={() => setIsRevealed(true)}
              onMouseUp={() => setIsRevealed(false)}
              onMouseLeave={() => setIsRevealed(false)}
              title="Hold to reveal passphrase"
              tabIndex={-1}
              disabled={loading || isLocked}
            >
              {isRevealed ? <Eye size={14} /> : <EyeOff size={14} />}
            </button>
          </div>
        </div>

        {/* Error / lockout display */}
        {(error || failedAttempts > 0) && (
          <div className="w-full mb-4">
            {error && (
              <div
                className={`flex items-start gap-2 text-xs mb-2 ${
                  isLocked ? "text-amber-warn" : "text-red-critical"
                }`}
              >
                <AlertTriangle size={12} className="mt-0.5 shrink-0" />
                <span>{error}</span>
              </div>
            )}

            {failedAttempts > 0 && (
              <div className="flex items-center gap-2 text-xs text-slate-dim">
                <div className="flex gap-1">
                  {Array.from({ length: Math.min(failedAttempts, 6) }).map((_, i) => (
                    <div
                      key={i}
                      className={`w-2 h-2 ${
                        i < failedAttempts ? "bg-red-critical" : "bg-ops-600"
                      } ${isLocked ? "animate-pulse-slow" : ""}`}
                    />
                  ))}
                  {failedAttempts > 6 && (
                    <span className="text-red-critical">+{failedAttempts - 6}</span>
                  )}
                </div>
                <span className="text-slate-label">
                  {failedAttempts} failed attempt{failedAttempts !== 1 ? "s" : ""}
                </span>
              </div>
            )}

            {isLocked && (
              <div className="mt-3 w-full">
                <div className="h-1 bg-ops-700 w-full">
                  <div
                    className="h-1 bg-amber-warn transition-all duration-1000"
                    style={{
                      width: `${Math.max(
                        0,
                        (lockoutSecs / getLockoutMax(failedAttempts)) * 100
                      )}%`,
                    }}
                  />
                </div>
                <div className="text-xs text-amber-warn mt-1 text-right">
                  LOCKOUT: {lockoutSecs}s remaining
                </div>
              </div>
            )}
          </div>
        )}

        <button
          onClick={handleUnlock}
          disabled={loading || isLocked || !passphrase.trim()}
          className="btn-primary w-full"
        >
          {loading
            ? "AUTHENTICATING..."
            : isLocked
            ? `LOCKED — ${lockoutSecs}s`
            : "UNLOCK VAULT"}
        </button>

        <div className="mt-6 text-xs text-slate-label text-center leading-relaxed">
          Argon2id · ChaCha20-Poly1305 · CSPRNG · Zero-knowledge
        </div>
      </div>
    </div>
  );
};

function getLockoutMax(attempts: number): number {
  if (attempts <= 2) return 1;
  if (attempts === 3) return 3;
  if (attempts === 4) return 10;
  if (attempts === 5) return 30;
  return 60;
}
