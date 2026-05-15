# BLACKSITE NODE
### Sovereign Offline Password Manager

```
CLASSIFICATION : PERSONAL SECURITY INFRASTRUCTURE
ARCHITECTURE   : Tauri v2 · Rust · React · TypeScript · Vite · TailwindCSS
CIPHER SUITE   : Argon2id · ChaCha20-Poly1305 · OsRng CSPRNG
STORAGE        : Single encrypted .blacksite file — zero cloud, zero sync, zero trust
```

---

## I. THE ARCHITECTURE

Blacksite Node is a fully offline, zero-knowledge password manager. There is no server. There is no account. There is no recovery email. The vault lives on your machine, encrypted, and the only key that exists is the one in your head.

**Stack**

```
┌─────────────────────────────────────────────────┐
│  React (TypeScript)  ·  Vite  ·  TailwindCSS    │  ← Untrusted display layer
│  Tauri v2 IPC bridge (JSON over secure channel) │  ← Isolation boundary
│  Rust cryptographic backend                     │  ← Single source of truth
│  OS filesystem  ·  vault.blacksite              │  ← One encrypted file
└─────────────────────────────────────────────────┘
```

The frontend is treated as an **untrusted display layer**. It never handles raw key material, never makes cryptographic decisions, and never sees plaintext outside of an active unlocked session. All security logic — key derivation, encryption, decryption, rate limiting, duress detection — is implemented exclusively in Rust.

**Zero-Knowledge Vault Philosophy**

The master passphrase is never stored. Not on disk. Not in memory beyond the duration of an active session. When the vault locks — whether by user action, window minimize, or process termination — the Rust `MasterKey` struct is dropped, triggering `ZeroizeOnDrop`: the 32 key bytes are overwritten with zeros before the memory is released. There is no recovery path. There is no backdoor. If the passphrase is lost, the vault is permanently inaccessible by design.

The vault file (`vault.blacksite`) contains:

```json
{
  "magic":              "BLACKSITE_NODE_v1",
  "version":            1,
  "salt":               "<base64, 16 bytes, random per vault>",
  "nonce":              "<base64, 12 bytes, random per write>",
  "ciphertext":         "<base64, ChaCha20-Poly1305 AEAD output>",
  "duress_salt":        "<base64, 16 bytes>",
  "duress_nonce":       "<base64, 12 bytes>",
  "duress_ciphertext":  "<base64, canary-key encrypted empty vault>"
}
```

The entire credential store is encrypted as a single atomic JSON blob. There is no per-entry encryption. Either the whole vault decrypts (correct passphrase) or nothing does (wrong passphrase → Poly1305 authentication failure before any plaintext is released).

**Page Visibility Lock**

The frontend registers a `visibilitychange` event listener. When the window is hidden — minimized, switched away from, or obscured — `lock_vault()` is called immediately. The Rust session is dropped, the master key is zeroized, and the view returns to the lock screen. The key does not wait for the user to explicitly lock. It is gone the moment the window is hidden.

---

## II. CORE PROTOCOLS

### The Duress Protocol (Canary Passphrase)

During vault initialization, the system generates two cryptographically independent 5-word passphrases:

- **Master Passphrase** — unlocks the vault and decrypts all stored credentials.
- **Canary Passphrase** — triggers silent vault destruction and opens a decoy empty session.

Both passphrases are derived via Argon2id with independent salts stored in the vault file. They are shown exactly once during setup and never persisted anywhere.

**Duress sequence (Rust backend):**

```
unlock_vault(canary_passphrase)
  │
  ├── Derive key from input + master_salt → try decrypt master ciphertext
  │     └── Poly1305 failure (wrong key)
  │
  ├── Derive key from input + duress_salt → try decrypt duress ciphertext
  │     └── Poly1305 success
  │
  ├── wipe_vault():
  │     ├── Overwrite .blacksite with zeros (file length preserved)
  │     └── fs::remove_file()
  │
  ├── Open in-memory ghost session: { vault_data: [], is_duress: true }
  │     └── add_credential / delete_credential silently no-op
  │
  └── Return Ok(()) ← identical to successful normal unlock
```

The frontend receives no duress signal. From its perspective, the unlock succeeded and the vault is empty. Subsequent writes are silently discarded. On next launch, the vault file is absent: the app presents the initialization screen as if no vault was ever created.

There is no visible "Delete Data" button. No confirmation dialog. The duress path is indistinguishable from a legitimate unlock to any observer watching the screen.

### Exponential Backoff Rate Limiter

In-memory defense against online brute-force attacks. Tracks consecutive failed authentication attempts and enforces increasing lockout durations before the next attempt is permitted.

```
Attempt 1  →  0s   (warning displayed, no lockout)
Attempt 2  →  1s
Attempt 3  →  3s
Attempt 4  →  10s
Attempt 5  →  30s
Attempt 6+ →  60s  (sustained maximum — one attempt per minute)
```

The rate limiter is in-memory only. It does not persist to disk. A process restart resets the counter. This is intentional: a persistent on-disk attempt counter would act as a side-channel, confirming the vault has been attacked. The Argon2id KDF provides the durable offline defense.

The rate limiter operates as a complement to Argon2id, not a replacement. Combined, they reduce brute-force throughput from approximately 3 attempts per second (Argon2id alone on commodity hardware) to 1 attempt per minute at sustained maximum lockout.

---

## III. THE CRYPTOGRAPHIC MATH

### Why the Vault Cannot Be Brute-Forced

**The Diceware Passphrase System**

Blacksite Node generates master and canary passphrases from a merged multilingual Diceware wordlist sourced from English (EFF Long List), Spanish, Filipino (Tagalog), and Italian — normalized through a Unicode NFD decomposition pipeline that strips all diacritical marks, enforces ASCII, and lowercases every word. The result is a clean, typeable, culturally diverse word pool of approximately **30,000 words**.

Each of the 5 passphrase words is selected independently using the OS CSPRNG (`OsRng`, backed by `BCryptGenRandom` on Windows, `getrandom(2)` on Linux) with rejection sampling to eliminate modulo bias. No word is weighted. No word is excluded from reuse.

**Combination Space**

```
Word pool  :  ~30,000 words
Words      :  5 (selected independently with replacement)
Total      :  30,000^5 = 2.43 × 10^22 possible passphrases
```

In context:

```
Grains of sand on Earth       ≈  7.5 × 10^18
Blacksite passphrase space    =  2.43 × 10^22   (≈ 3,240× more than grains of sand)
```

**The Argon2id Bottleneck**

A passphrase alone is not sufficient. The real defense is what happens when an attacker obtains the `.blacksite` file and attempts an offline dictionary attack.

Every unlock attempt — including an offline brute-force against the raw file — must run the full Argon2id key derivation:

```
Algorithm   :  Argon2id  (RFC 9106)
Memory cost :  65,536 KiB  (64 MiB per attempt)
Iterations  :  3 passes
Parallelism :  1 lane
Output      :  256 bits  (ChaCha20-Poly1305 key)
```

The 64 MiB memory requirement is the critical constraint. GPU-based cracking derives its speed from massive parallelism — thousands of cores running simultaneously. At 64 MiB per attempt, a GPU with 10 GB VRAM can sustain approximately **156 parallel derivations**. Each derivation takes roughly 300–800 ms on commodity hardware.

Optimistic attacker throughput: **~1 attempt per second** on a high-end GPU cluster.

**Time-to-Crack Calculation**

```
Passphrase space  :  2.43 × 10^22
Attacker speed    :  1 guess / second
Time to exhaust   :  2.43 × 10^22 seconds

Convert to years  :  2.43 × 10^22 ÷ 3.156 × 10^7 s/year
                  =  7.7 × 10^14 years
```

```
Time to brute-force Blacksite Node  ≈  7.7 × 10^14 years
Age of the universe                 ≈  1.38 × 10^10 years
──────────────────────────────────────────────────────────
Ratio                               ≈  55,797 universe lifetimes
```

This assumes the attacker knows the algorithm, has the vault file, has a GPU cluster, and attempts every passphrase in the entire keyspace sequentially. It does not account for the Poly1305 authentication overhead, the ChaCha20 decryption step, or the two-salt duress architecture that forces the attacker to verify against two independent ciphertexts per guess.

**The correct threat model is not brute force. It is physical coercion.** That is what the Duress Protocol addresses.

---

## IV. BUILD INSTRUCTIONS

### Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Rust | stable | `rustup install stable` |
| Node.js | 18+ | |
| Tauri CLI v2 | bundled | invoked via `npm run tauri` |
| Platform linker | Windows: MSVC or GNU | GNU used in this project |

**Windows — GNU toolchain setup:**

```powershell
# Install MSYS2 (recommended: install to a non-system drive to preserve C: space)
# Then in the MSYS2 MinGW64 shell:
pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-lld

# Set environment variables (add to your profile for permanence):
$env:CARGO_HOME  = 'D:\Rust\.cargo'
$env:RUSTUP_HOME = 'D:\Rust\.rustup'
$env:PATH        = "D:\Rust\.cargo\bin;D:\msys64\mingw64\bin;D:\msys64\usr\bin;$env:PATH"

# Install the GNU Rust target:
rustup default stable-x86_64-pc-windows-gnu
```

### Known Issues & Troubleshooting

**`export ordinal too large` linker error**

```
= note: ld.lld: error: too many exported symbols (got 101049, max 65535)
        collect2.exe: error: ld returned 1 exit status
error: could not compile `blacksite-node`
```

This error occurs when the Windows PE/DLL format's hard limit of 65,535 export ordinals is exceeded. It is triggered by including `cdylib` or `staticlib` in the crate type — both produce a Windows DLL, which hits the PE format ceiling when a large dependency tree (Tauri + cryptographic crates) is in scope.

**Fix:** Open `src-tauri/Cargo.toml` and ensure the lib section reads:

```toml
[lib]
name = "blacksite_node_lib"
crate-type = ["rlib"]
```

`cdylib` and `staticlib` are only required for mobile targets (Android/iOS). Desktop Tauri builds exclusively need `rlib`. This is the confirmed working configuration for this project — do not add `cdylib` or `staticlib` back unless targeting mobile platforms.

### Clone and Install

```bash
git clone https://github.com/Matlih/blacksite-node.git
cd Blacksite_Node
npm install
```

### Development Server

```powershell
npm run tauri dev
```

Launches Vite (port 1420) + Tauri + Rust backend with hot-reload on Rust source changes. The vault file is written to:

```
Windows  :  %APPDATA%\com.blacksite.node\vault.blacksite
macOS    :  ~/Library/Application Support/com.blacksite.node/vault.blacksite
Linux    :  ~/.local/share/com.blacksite.node/vault.blacksite
```

**To reset the vault during development:**

```powershell
# Windows
Remove-Item "$env:APPDATA\com.blacksite.node\vault.blacksite" -Force
```

```bash
# Linux / macOS
rm ~/.local/share/com.blacksite.node/vault.blacksite
```

### Production Build

```powershell
npm run tauri build
```

Produces a standalone release binary and NSIS installer bundle:

```
src-tauri\target\x86_64-pc-windows-gnu\release\bundle\nsis\
src-tauri\target\x86_64-pc-windows-gnu\release\blacksite-node.exe
```

---

## V. PORTABLE DEPLOYMENT (GNU TOOLCHAIN)

### The GNU Runtime Dependency

Because Blacksite Node is compiled with the **GNU toolchain** (`x86_64-pc-windows-gnu`), the release binary does not statically link the WebView2 loader. The portable deployment is a **two-file pair** — both must reside in the same directory for the application to initialize its rendering engine.

```
blacksite-node.exe    ← main application binary
WebView2Loader.dll    ← WebView2 runtime bridge (GNU toolchain dependency)
```

If `WebView2Loader.dll` is absent from the directory, the application will fail to launch with a missing DLL error before any window appears.

Both files are produced by `npm run tauri build` and are located at:

```
src-tauri\target\x86_64-pc-windows-gnu\release\blacksite-node.exe
src-tauri\target\x86_64-pc-windows-gnu\release\WebView2Loader.dll
```

### USB Deployment Layout

For operators running Blacksite Node from an encrypted USB drive with zero Windows Registry footprint, copy both files together:

```
[USB Drive]
├── blacksite-node.exe
├── WebView2Loader.dll
└── README.txt
```

> **Note:** The vault file (`vault.blacksite`) is written to the host machine's `%APPDATA%\com.blacksite.node\` directory, not to the USB drive. The USB carries only the stateless executable pair. If a fully self-contained deployment is required — vault traveling with the binary — see the wrapper script pattern in Section VI.

### WebView2 Runtime Requirement

The target machine must have the **Microsoft WebView2 Runtime** installed. On Windows 10 (version 1803+) and Windows 11, WebView2 ships as a system component and is updated automatically. On air-gapped or minimal installations, the NSIS installer (`Blacksite Node_0.1.0_x64-setup.exe`) bundles an offline WebView2 installer and handles this automatically.

For the portable binary on machines without WebView2, install the runtime manually before running:

```
https://developer.microsoft.com/en-us/microsoft-edge/webview2/
→ Download: Evergreen Bootstrapper or Standalone Installer (x64)
```

---

## VI. SECURITY PROPERTIES SUMMARY

| Property | Implementation |
|---|---|
| Passphrase storage | Never stored. Derived on demand, zeroized on lock. |
| Key in memory | `ZeroizeOnDrop` — 32 bytes overwritten with zeros on drop. |
| Vault encryption | ChaCha20-Poly1305 AEAD, 256-bit key, random 96-bit nonce per write. |
| Key derivation | Argon2id, 64 MiB / 3 iterations / 1 lane. |
| Nonce reuse | Impossible — OsRng generates a fresh nonce for every `encrypt_vault()` call. |
| Tamper detection | Poly1305 MAC verified before any plaintext is released. |
| Brute-force defense | Argon2id memory hardness + exponential backoff rate limiter. |
| Coercion defense | Canary Passphrase triggers silent wipe + ghost session. |
| Network exposure | Zero. No sockets. No telemetry. No cloud. Tauri allows no outbound connections. |
| Clipboard hygiene | Passwords auto-cleared from clipboard after 30 seconds. |
| Idle exposure | Lock-on-hide via Page Visibility API. Key zeroized on minimize. |

---

## VII. DISTRIBUTION & DEPLOYMENT

### Pre-Compiled Binaries

For non-technical users, pre-compiled binaries are available in the **GitHub Releases** tab. No Rust toolchain, no Node.js, no build environment required. Download, verify, run.

Each release includes:
- A SHA-256 checksum file for integrity verification
- The Windows Installer for standard deployment
- The Portable Binary for operational deployment

Verify before executing:

```powershell
# Compare the hash of the downloaded file against the published checksum
Get-FileHash .\blacksite-node-setup.exe -Algorithm SHA256
```

### Dual-Deployment Strategy

Blacksite Node ships in two distribution forms to cover different operational contexts.

---

**1. Windows Installer (`blacksite-node-setup.exe`)**

A standard NSIS installation wizard. Installs the application to `Program Files`, creates Start Menu shortcuts, and registers an uninstaller entry in the Windows Control Panel. Intended for everyday users on a fixed workstation.

```
Target audience   :  Fixed workstation operators
Installation path :  C:\Program Files\Blacksite Node\
Registry entries  :  Uninstaller key (HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall)
Vault location    :  %APPDATA%\com.blacksite.node\vault.blacksite
```

Built by Tauri's NSIS bundler as part of `npm run tauri build`. Output:

```
src-tauri\target\release\bundle\nsis\Blacksite Node_0.1.0_x64-setup.exe
```

---

**2. Portable Binary (`blacksite-node.exe`)**

A standalone executable with zero Windows Registry footprint. No installer. No elevation required. Copy it to any location — including an encrypted USB drive — and run it directly. The vault file is created in the standard OS app data directory regardless of where the binary is executed from, keeping the executable itself stateless.

```
Target audience   :  Field operators, air-gapped environments, USB deployments
Installation path :  None — single file, runs in place
Registry entries  :  Zero
Vault location    :  %APPDATA%\com.blacksite.node\vault.blacksite
```

**Recommended operational pattern for USB deployment:**

```
[Encrypted USB Drive]
├── blacksite-node.exe          ← the binary
└── README.txt                  ← passphrase storage reminder
```

Run from the USB directly. The vault file persists in the host machine's AppData between sessions. The binary itself carries no state. If the USB is lost or seized, the attacker has only an executable — no vault, no credentials.

For a fully self-contained USB setup where the vault travels with the binary, move the vault file to the USB and point the binary at it via a wrapper script:

```powershell
# Wrapper: run-blacksite.ps1 (place alongside the .exe on the USB)
# This is an advanced pattern — the vault file on the USB must itself be
# protected by drive encryption (e.g. VeraCrypt) at all times.
$env:APPDATA = "$PSScriptRoot\data"
Start-Process "$PSScriptRoot\blacksite-node.exe"
```

> The portable binary is extracted from the Tauri release build at:
> `src-tauri\target\release\blacksite-node.exe`

---

```
BLACKSITE NODE — No cloud. No account. No mercy.
```
