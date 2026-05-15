/**
 * VaultView — Primary credential management interface.
 *
 * Displays the decrypted vault contents. Passwords are hidden by default
 * and revealed only on explicit user action to prevent shoulder-surfing.
 * All add/delete operations call the Rust backend, which re-encrypts
 * the vault to disk after each mutation.
 */
import React, { useState, useEffect, useCallback } from "react";
import {
  Lock,
  Plus,
  Trash2,
  Eye,
  EyeOff,
  Copy,
  Check,
  Zap,
  ShieldCheck,
  Search,
  AlertTriangle,
} from "lucide-react";
import type { CredentialEntry } from "../lib/tauri";
import { getCredentials, addCredential, deleteCredential, lockVault } from "../lib/tauri";
import { GeneratorModal } from "./GeneratorModal";

interface VaultViewProps {
  onLock: () => void;
}

interface AddCredentialForm {
  service: string;
  username: string;
  password: string;
  notes: string;
}

const EMPTY_FORM: AddCredentialForm = {
  service: "",
  username: "",
  password: "",
  notes: "",
};

export const VaultView: React.FC<VaultViewProps> = ({ onLock }) => {
  const [entries, setEntries] = useState<CredentialEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [revealedIds, setRevealedIds] = useState<Set<string>>(new Set());
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [showAddForm, setShowAddForm] = useState(false);
  const [showGenerator, setShowGenerator] = useState(false);
  const [addForm, setAddForm] = useState<AddCredentialForm>(EMPTY_FORM);
  const [addLoading, setAddLoading] = useState(false);
  const [addError, setAddError] = useState("");
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);
  const [locking, setLocking] = useState(false);

  const loadEntries = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const data = await getCredentials();
      setEntries(data);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadEntries();
  }, [loadEntries]);

  const handleLock = async () => {
    setLocking(true);
    setRevealedIds(new Set());
    try {
      await lockVault();
      onLock();
    } catch (e) {
      setError(String(e));
      setLocking(false);
    }
  };

  const toggleReveal = (id: string) => {
    setRevealedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const handleCopyPassword = async (entry: CredentialEntry) => {
    try {
      await navigator.clipboard.writeText(entry.password);
      setCopiedId(entry.id);
      // Auto-clear clipboard after 30 seconds — standard security practice
      setTimeout(async () => {
        try {
          const current = await navigator.clipboard.readText();
          if (current === entry.password) {
            await navigator.clipboard.writeText("");
          }
        } catch { /* ignore */ }
        setCopiedId((id) => (id === entry.id ? null : id));
      }, 30000);
      setTimeout(() => setCopiedId((id) => (id === entry.id ? null : id)), 2000);
    } catch {
      setError("Clipboard access denied.");
    }
  };

  const handleAddSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!addForm.service.trim() || !addForm.password.trim()) {
      setAddError("Service and password are required.");
      return;
    }
    setAddLoading(true);
    setAddError("");
    try {
      await addCredential(
        addForm.service.trim(),
        addForm.username.trim(),
        addForm.password,
        addForm.notes.trim()
      );
      setAddForm(EMPTY_FORM);
      setShowAddForm(false);
      await loadEntries();
    } catch (e) {
      setAddError(String(e));
    } finally {
      setAddLoading(false);
    }
  };

  const handleDelete = async (id: string) => {
    if (deleteConfirm !== id) {
      setDeleteConfirm(id);
      setTimeout(() => setDeleteConfirm(null), 3000);
      return;
    }
    try {
      await deleteCredential(id);
      setDeleteConfirm(null);
      await loadEntries();
    } catch (e) {
      setError(String(e));
    }
  };

  const filteredEntries = entries.filter((e) => {
    const q = searchQuery.toLowerCase();
    return (
      !q ||
      e.service.toLowerCase().includes(q) ||
      e.username.toLowerCase().includes(q) ||
      e.notes.toLowerCase().includes(q)
    );
  });

  return (
    <div className="flex flex-col h-full bg-gunmetal-900 text-slate-text font-mono overflow-hidden">
      {/* Top bar */}
      <div className="flex items-center justify-between px-5 py-3 bg-gunmetal-800 border-b border-ops-700 shrink-0">
        <div className="flex items-center gap-3">
          <img src="/app_logo.png" alt="Blacksite Node" className="h-6 w-auto object-contain" />
          <span className="text-xs uppercase tracking-widest text-slate-dim">
            BLACKSITE NODE
          </span>
          <span className="text-xs text-ops-500 select-none">|</span>
          <span className="text-xs text-blue-active">{entries.length} CREDENTIAL{entries.length !== 1 ? "S" : ""}</span>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowGenerator(true)}
            className="btn-ghost flex items-center gap-1 py-1 px-2 text-xs"
            title="Open password generator"
          >
            <Zap size={12} />
            GEN
          </button>
          <button
            onClick={() => { setShowAddForm(true); setAddForm(EMPTY_FORM); setAddError(""); }}
            className="btn-primary flex items-center gap-1 py-1 px-2 text-xs"
          >
            <Plus size={12} />
            ADD
          </button>
          <button
            onClick={handleLock}
            disabled={locking}
            className="btn-danger flex items-center gap-1 py-1 px-2 text-xs"
            title="Lock vault"
          >
            <Lock size={12} />
            {locking ? "LOCKING..." : "LOCK"}
          </button>
        </div>
      </div>

      {/* Search bar */}
      <div className="px-5 py-2 bg-gunmetal-800 border-b border-ops-700 shrink-0">
        <div className="flex items-center gap-2 bg-gunmetal-900 border border-ops-600 px-3 py-1.5 focus-within:border-blue-ops">
          <Search size={12} className="text-slate-label shrink-0" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="filter by service, username, notes..."
            className="flex-1 bg-transparent outline-none text-slate-text text-xs font-mono placeholder:text-slate-label"
          />
        </div>
      </div>

      {/* Error banner */}
      {error && (
        <div className="px-5 py-2 bg-red-dim border-b border-red-muted flex items-center gap-2 text-xs text-red-critical shrink-0">
          <AlertTriangle size={12} />
          {error}
          <button onClick={() => setError("")} className="ml-auto text-slate-label hover:text-slate-text">
            <X size={12} />
          </button>
        </div>
      )}

      {/* Add credential form */}
      {showAddForm && (
        <div className="px-5 py-4 bg-ops-900 border-b border-ops-700 shrink-0">
          <div className="label-ops mb-3">NEW CREDENTIAL</div>
          <form onSubmit={handleAddSubmit}>
            <div className="grid grid-cols-2 gap-2 mb-2">
              <div>
                <div className="label-ops mb-1 text-xs">SERVICE *</div>
                <input
                  type="text"
                  value={addForm.service}
                  onChange={(e) => setAddForm((f) => ({ ...f, service: e.target.value }))}
                  placeholder="github.com"
                  className="input-ops"
                  autoFocus
                  required
                />
              </div>
              <div>
                <div className="label-ops mb-1 text-xs">USERNAME / EMAIL</div>
                <input
                  type="text"
                  value={addForm.username}
                  onChange={(e) => setAddForm((f) => ({ ...f, username: e.target.value }))}
                  placeholder="user@domain.com"
                  className="input-ops"
                />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-2 mb-2">
              <div>
                <div className="flex items-center justify-between mb-1">
                  <div className="label-ops text-xs">PASSWORD *</div>
                  <button
                    type="button"
                    onClick={() => setShowGenerator(true)}
                    className="text-xs text-blue-ops hover:text-blue-active uppercase tracking-wider"
                  >
                    generate →
                  </button>
                </div>
                <input
                  type="password"
                  value={addForm.password}
                  onChange={(e) => setAddForm((f) => ({ ...f, password: e.target.value }))}
                  placeholder="••••••••••••"
                  className="input-ops"
                  required
                />
              </div>
              <div>
                <div className="label-ops mb-1 text-xs">NOTES</div>
                <input
                  type="text"
                  value={addForm.notes}
                  onChange={(e) => setAddForm((f) => ({ ...f, notes: e.target.value }))}
                  placeholder="optional"
                  className="input-ops"
                />
              </div>
            </div>
            {addError && (
              <div className="text-red-critical text-xs mb-2 flex items-center gap-1">
                <AlertTriangle size={10} />
                {addError}
              </div>
            )}
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => setShowAddForm(false)}
                className="btn-ghost flex-1"
              >
                CANCEL
              </button>
              <button
                type="submit"
                disabled={addLoading}
                className="btn-primary flex-1"
              >
                {addLoading ? "ENCRYPTING..." : "SAVE CREDENTIAL"}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Credentials table */}
      <div className="flex-1 overflow-y-auto">
        {loading ? (
          <div className="flex items-center justify-center h-32 text-slate-label text-xs">
            LOADING VAULT...
          </div>
        ) : filteredEntries.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-32 text-slate-label text-xs gap-2">
            {searchQuery ? (
              <>
                <Search size={24} className="opacity-30" />
                <span>NO RESULTS FOR "{searchQuery.toUpperCase()}"</span>
              </>
            ) : (
              <>
                <ShieldCheck size={24} className="opacity-30" />
                <span>VAULT IS EMPTY — ADD YOUR FIRST CREDENTIAL</span>
              </>
            )}
          </div>
        ) : (
          <table className="w-full border-collapse">
            <thead>
              <tr className="bg-gunmetal-800 border-b border-ops-700">
                <th className="text-left px-5 py-2 label-ops text-xs">SERVICE</th>
                <th className="text-left px-3 py-2 label-ops text-xs">USERNAME</th>
                <th className="text-left px-3 py-2 label-ops text-xs">PASSWORD</th>
                <th className="text-left px-3 py-2 label-ops text-xs hidden md:table-cell">NOTES</th>
                <th className="px-3 py-2 label-ops text-xs text-right">ACTIONS</th>
              </tr>
            </thead>
            <tbody>
              {filteredEntries.map((entry) => {
                const isRevealed = revealedIds.has(entry.id);
                const isCopied = copiedId === entry.id;
                const isDeleteConfirm = deleteConfirm === entry.id;
                return (
                  <tr key={entry.id} className="table-row-ops">
                    <td className="px-5 py-3 text-sm text-slate-text">{entry.service}</td>
                    <td className="px-3 py-3 text-sm text-slate-dim">{entry.username || "—"}</td>
                    <td className="px-3 py-3 text-sm font-mono">
                      <div className="flex items-center gap-1">
                        <span
                          className={
                            isRevealed
                              ? "text-slate-text select-all"
                              : "text-slate-label tracking-widest select-none"
                          }
                          data-selectable={isRevealed ? "true" : undefined}
                        >
                          {isRevealed ? entry.password : "•".repeat(Math.min(entry.password.length, 16))}
                        </span>
                      </div>
                    </td>
                    <td className="px-3 py-3 text-xs text-slate-label hidden md:table-cell">
                      {entry.notes || "—"}
                    </td>
                    <td className="px-3 py-3">
                      <div className="flex items-center justify-end gap-1">
                        <button
                          onClick={() => toggleReveal(entry.id)}
                          className="p-1.5 text-slate-label hover:text-slate-text transition-colors"
                          title={isRevealed ? "Hide password" : "Reveal password"}
                        >
                          {isRevealed ? <EyeOff size={13} /> : <Eye size={13} />}
                        </button>
                        <button
                          onClick={() => handleCopyPassword(entry)}
                          className={`p-1.5 transition-colors ${
                            isCopied ? "text-blue-active" : "text-slate-label hover:text-slate-text"
                          }`}
                          title="Copy password"
                        >
                          {isCopied ? <Check size={13} /> : <Copy size={13} />}
                        </button>
                        <button
                          onClick={() => handleDelete(entry.id)}
                          className={`p-1.5 transition-colors ${
                            isDeleteConfirm
                              ? "text-red-critical animate-pulse"
                              : "text-slate-label hover:text-red-alert"
                          }`}
                          title={isDeleteConfirm ? "Click again to confirm delete" : "Delete credential"}
                        >
                          <Trash2 size={13} />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* Status bar */}
      <div className="px-5 py-1.5 bg-gunmetal-800 border-t border-ops-700 flex items-center justify-between shrink-0">
        <span className="text-xs text-slate-label">
          {filteredEntries.length} of {entries.length} entries
        </span>
        <span className="text-xs text-slate-label">
          VAULT · ENCRYPTED AT REST · ZERO-KNOWLEDGE
        </span>
      </div>

      {/* Generator modal */}
      {showGenerator && (
        <GeneratorModal
          onClose={() => setShowGenerator(false)}
          onUsePassword={(pw) => {
            setAddForm((f) => ({ ...f, password: pw }));
            setShowGenerator(false);
            setShowAddForm(true);
          }}
        />
      )}
    </div>
  );
};

// Small inline X component for error banner dismiss
const X: React.FC<{ size: number }> = ({ size }) => (
  <svg
    width={size}
    height={size}
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth={2}
  >
    <line x1="18" y1="6" x2="6" y2="18" />
    <line x1="6" y1="6" x2="18" y2="18" />
  </svg>
);
