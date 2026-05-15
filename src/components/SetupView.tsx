import React, { useState, useEffect, useCallback } from "react";
import { RefreshCw, ShieldCheck, AlertTriangle, Copy, Check, Skull } from "lucide-react";
import { generatePassphrase, setupVault } from "../lib/tauri";

interface SetupViewProps {
  onSetupComplete: () => void;
}

type Phase = "generate" | "confirm" | "confirming" | "done";

export const SetupView: React.FC<SetupViewProps> = ({ onSetupComplete }) => {
  const [masterPassphrase, setMasterPassphrase] = useState<string>("");
  const [canaryPassphrase, setCanaryPassphrase] = useState<string>("");
  const [confirmInput, setConfirmInput] = useState<string>("");
  const [phase, setPhase] = useState<Phase>("generate");
  const [error, setError] = useState<string>("");
  const [loading, setLoading] = useState(false);
  const [copiedMaster, setCopiedMaster] = useState(false);
  const [copiedCanary, setCopiedCanary] = useState(false);

  const loadPassphrases = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [master, canary] = await Promise.all([
        generatePassphrase(),
        generatePassphrase(),
      ]);
      setMasterPassphrase(master);
      setCanaryPassphrase(canary);
      setConfirmInput("");
      setPhase("generate");
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadPassphrases();
  }, [loadPassphrases]);

  const handleCopy = async (text: string, setter: (v: boolean) => void) => {
    try {
      await navigator.clipboard.writeText(text);
      setter(true);
      setTimeout(() => setter(false), 2000);
    } catch {
      setError("Clipboard access denied.");
    }
  };

  const handleConfirmSetup = async () => {
    if (confirmInput.trim() !== masterPassphrase.trim()) {
      setError("Passphrase mismatch. Re-check your written copy and try again.");
      return;
    }
    setPhase("confirming");
    setError("");
    setLoading(true);
    try {
      await setupVault(masterPassphrase, canaryPassphrase);
      setPhase("done");
      setTimeout(onSetupComplete, 1400);
    } catch (e) {
      setError(String(e));
      setPhase("confirm");
    } finally {
      setLoading(false);
    }
  };

  const WordTiles = ({
    phrase,
    dimColor = false,
  }: {
    phrase: string;
    dimColor?: boolean;
  }) => (
    <div
      className={`panel-ops p-4 ${dimColor ? "border-amber-warn/40" : ""}`}
    >
      <div className="flex flex-wrap gap-2 justify-center">
        {phrase.split("-").map((word, i) => (
          <div
            key={i}
            className={`border px-3 py-2 text-sm font-mono ${
              dimColor
                ? "bg-gunmetal-800 border-amber-warn/30 text-amber-warn"
                : "bg-gunmetal-800 border-ops-600 text-slate-text"
            }`}
          >
            <span
              className={`text-xs mr-2 ${dimColor ? "text-amber-warn/50" : "text-slate-label"}`}
            >
              {i + 1}
            </span>
            {word}
          </div>
        ))}
      </div>
      <div
        className={`mt-3 text-center text-xs ${
          dimColor ? "text-amber-warn/60" : "text-slate-label"
        }`}
      >
        {phrase}
      </div>
    </div>
  );

  return (
    <div className="flex flex-col h-full bg-gunmetal-900 text-slate-text font-mono">
      {/* Header bar */}
      <div className="flex items-center justify-between px-6 py-3 bg-gunmetal-800 border-b border-ops-700">
        <div className="flex items-center gap-3">
          <img src="/app_logo.png" alt="Blacksite Node" className="h-6 w-auto object-contain" />
          <span className="text-xs uppercase tracking-widest text-slate-dim">
            BLACKSITE NODE — VAULT INITIALIZATION
          </span>
        </div>
        <div className="text-xs text-slate-label">FIRST RUN DETECTED</div>
      </div>

      <div className="flex flex-col items-center justify-center flex-1 px-8 max-w-2xl mx-auto w-full overflow-y-auto py-4">

        {/* Status heading */}
        <div className="w-full mb-5">
          <div className="label-ops mb-2">SYSTEM STATUS</div>
          <div className="h-px bg-ops-700 mb-4" />
          <p className="text-slate-dim text-sm leading-relaxed">
            No vault detected. Two sovereign passphrases will be generated:{" "}
            <span className="text-blue-active">Master Key</span> (opens the vault) and{" "}
            <span className="text-amber-warn">Canary Passphrase</span> (silent wipe + decoy).{" "}
            <span className="text-amber-warn">Record both. They are shown once.</span>
          </p>
        </div>

        {/* Passphrases — only shown before done */}
        {masterPassphrase && phase !== "done" && (
          <>
            {/* Master Passphrase */}
            <div className="w-full mb-4">
              <div className="flex items-center justify-between mb-2">
                <div className="label-ops text-blue-active">MASTER PASSPHRASE</div>
                <div className="flex gap-2">
                  <button
                    onClick={() => handleCopy(masterPassphrase, setCopiedMaster)}
                    className="btn-ghost flex items-center gap-1 py-1 px-2 text-xs"
                  >
                    {copiedMaster ? (
                      <Check size={12} className="text-blue-active" />
                    ) : (
                      <Copy size={12} />
                    )}
                    {copiedMaster ? "COPIED" : "COPY"}
                  </button>
                  <button
                    onClick={loadPassphrases}
                    disabled={loading || phase === "confirm"}
                    className="btn-ghost flex items-center gap-1 py-1 px-2 text-xs"
                    title="Regenerate both passphrases"
                  >
                    <RefreshCw size={12} className={loading ? "animate-spin" : ""} />
                    REGEN
                  </button>
                </div>
              </div>
              <WordTiles phrase={masterPassphrase} dimColor={false} />
            </div>

            {/* Canary / Duress Passphrase */}
            <div className="w-full mb-5">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <Skull size={12} className="text-amber-warn" />
                  <div className="label-ops text-amber-warn">CANARY PASSPHRASE</div>
                </div>
                <button
                  onClick={() => handleCopy(canaryPassphrase, setCopiedCanary)}
                  className="btn-ghost flex items-center gap-1 py-1 px-2 text-xs"
                >
                  {copiedCanary ? (
                    <Check size={12} className="text-blue-active" />
                  ) : (
                    <Copy size={12} />
                  )}
                  {copiedCanary ? "COPIED" : "COPY"}
                </button>
              </div>
              <WordTiles phrase={canaryPassphrase} dimColor={true} />
              <div className="mt-2 flex items-start gap-2 text-xs text-amber-warn/80">
                <AlertTriangle size={12} className="mt-0.5 shrink-0" />
                <span>
                  Duress Key — entering this at the lock screen triggers an immediate silent wipe
                  of the vault and opens a decoy empty session. Store separately from your Master Key.
                </span>
              </div>
            </div>
          </>
        )}

        {/* Confirmation input */}
        {(phase === "generate" || phase === "confirm" || phase === "confirming") && masterPassphrase && (
          <div className="w-full">
            <div className="label-ops mb-2">CONFIRM MASTER PASSPHRASE TO ACTIVATE VAULT</div>
            <input
              type="text"
              value={confirmInput}
              onChange={(e) => setConfirmInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && !loading && handleConfirmSetup()}
              placeholder="word1-word2-word3-word4-word5"
              className="input-ops mb-3"
              disabled={loading || phase === "confirming"}
              autoFocus
              spellCheck={false}
              autoComplete="off"
            />

            {error && (
              <div className="flex items-center gap-2 text-red-critical text-xs mb-3">
                <AlertTriangle size={12} className="shrink-0" />
                {error}
              </div>
            )}

            <button
              onClick={handleConfirmSetup}
              disabled={loading || !confirmInput || phase === "confirming"}
              className="btn-primary w-full"
            >
              {loading || phase === "confirming" ? "INITIALIZING VAULT..." : "ACTIVATE VAULT"}
            </button>
          </div>
        )}

        {/* Done */}
        {phase === "done" && (
          <div className="flex flex-col items-center gap-3 text-blue-active">
            <ShieldCheck size={32} />
            <span className="text-sm uppercase tracking-widest">VAULT ACTIVATED</span>
          </div>
        )}
      </div>
    </div>
  );
};
