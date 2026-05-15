/**
 * GeneratorModal — High-entropy password generator interface.
 *
 * Calls the Rust CSPRNG backend to generate a password for a specific service.
 * The generated password is never stored locally — it is either copied to
 * clipboard or discarded. The user decides whether to save it as a credential.
 */
import React, { useState, useEffect, useCallback } from "react";
import { X, RefreshCw, Copy, Check, Zap } from "lucide-react";
import { generateSecurePassword } from "../lib/tauri";

interface GeneratorModalProps {
  onClose: () => void;
  onUsePassword?: (password: string) => void;
}

export const GeneratorModal: React.FC<GeneratorModalProps> = ({
  onClose,
  onUsePassword,
}) => {
  const [password, setPassword] = useState("");
  const [length, setLength] = useState(24);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState("");

  const generate = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const pw = await generateSecurePassword(length);
      setPassword(pw);
      setCopied(false);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, [length]);

  useEffect(() => {
    generate();
  }, []);

  const handleCopy = async () => {
    if (!password) return;
    try {
      await navigator.clipboard.writeText(password);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setError("Clipboard access denied.");
    }
  };

  // Calculate rough entropy display
  const entropyBits = Math.floor(length * Math.log2(88));

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center"
      style={{ backgroundColor: "rgba(13, 15, 18, 0.85)" }}
    >
      <div className="panel-ops w-full max-w-lg mx-4">
        {/* Modal header */}
        <div className="flex items-center justify-between px-5 py-3 border-b border-ops-700">
          <div className="flex items-center gap-2">
            <Zap size={14} className="text-blue-active" />
            <span className="text-xs uppercase tracking-widest text-slate-dim">
              SECURE PASSWORD GENERATOR
            </span>
          </div>
          <button
            onClick={onClose}
            className="text-slate-label hover:text-slate-text transition-colors"
            aria-label="Close"
          >
            <X size={16} />
          </button>
        </div>

        <div className="p-5">
          {/* Generated password display */}
          <div className="label-ops mb-2">GENERATED PASSWORD</div>
          <div className="bg-gunmetal-800 border border-ops-600 p-3 mb-2 min-h-[48px] flex items-center">
            {loading ? (
              <span className="text-slate-label text-sm animate-pulse">GENERATING...</span>
            ) : (
              <span
                className="text-slate-text text-sm break-all font-mono select-all"
                data-selectable
              >
                {password}
              </span>
            )}
          </div>

          {/* Entropy indicator */}
          <div className="flex items-center justify-between text-xs text-slate-label mb-4">
            <span>ENTROPY: ~{entropyBits} bits</span>
            <span>CHARSET: 88 symbols</span>
            <span>LENGTH: {length}</span>
          </div>

          {/* Length slider */}
          <div className="mb-5">
            <div className="flex items-center justify-between mb-2">
              <div className="label-ops">LENGTH</div>
              <span className="text-xs text-slate-text font-mono">{length}</span>
            </div>
            <input
              type="range"
              min={12}
              max={64}
              value={length}
              onChange={(e) => setLength(Number(e.target.value))}
              className="w-full accent-blue-ops bg-ops-700 h-1 appearance-none cursor-pointer"
            />
            <div className="flex justify-between text-xs text-slate-label mt-1">
              <span>12</span>
              <span>64</span>
            </div>
          </div>

          {error && (
            <div className="text-red-critical text-xs mb-3">{error}</div>
          )}

          {/* Actions */}
          <div className="flex gap-2">
            <button
              onClick={generate}
              disabled={loading}
              className="btn-ghost flex items-center gap-2 flex-1"
            >
              <RefreshCw size={12} className={loading ? "animate-spin" : ""} />
              REGENERATE
            </button>
            <button
              onClick={handleCopy}
              disabled={loading || !password}
              className="btn-primary flex items-center gap-2 flex-1"
            >
              {copied ? <Check size={12} /> : <Copy size={12} />}
              {copied ? "COPIED" : "COPY"}
            </button>
          </div>

          {onUsePassword && password && (
            <button
              onClick={() => onUsePassword(password)}
              disabled={loading}
              className="btn-ghost w-full mt-2"
            >
              USE THIS PASSWORD
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
