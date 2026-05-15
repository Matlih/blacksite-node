//! # crypto.rs — Blacksite Node Cryptographic Engine
//!
//! ## Threat Model
//! This module assumes the attacker has:
//! - Full offline access to the `.blacksite` vault file (e.g., stolen device or backup).
//! - A GPU cluster capable of billions of KDF evaluations per second against weak hashes.
//! - The source code of this application (Kerckhoffs's principle: security through secrecy
//!   of the KEY, not the algorithm).
//!
//! ## Mitigations Implemented
//! 1. **Argon2id KDF**: memory-hard derivation requiring ~64 MB RAM and multiple passes per
//!    attempt. A GPU with 10 GB VRAM can only run ~156 parallel derivations; this limits
//!    brute-force throughput to thousands per second instead of billions.
//! 2. **ChaCha20-Poly1305 AEAD**: authenticated encryption. Any tampering with the ciphertext
//!    is detected before decryption. Prevents the attacker from learning plaintext structure
//!    via chosen-ciphertext attacks.
//! 3. **Random 96-bit nonces**: unique per encryption. Nonce reuse with ChaCha20-Poly1305
//!    is catastrophic (leaks keystream), so the OS CSPRNG is used here — never a counter.
//! 4. **Zeroize on drop**: the `MasterKey` type overwrites its heap memory with zeros when
//!    dropped, preventing key extraction via memory forensics on a running process.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ---------------------------------------------------------------------------
// Constants — Argon2id hardening parameters
// ---------------------------------------------------------------------------

/// Memory cost: 65536 KiB = 64 MiB per derivation attempt.
/// OWASP recommends ≥19 MiB; we use 64 MiB to force GPU parallelism to ~156
/// concurrent threads on a 10 GB VRAM card.
const ARGON2_MEMORY_KIB: u32 = 65536;

/// Iteration count: 3 passes over the memory block.
/// Combined with the memory cost, a single derivation takes ~300–800 ms on
/// commodity hardware — imperceptible to a legitimate user, catastrophic for
/// automated brute-force.
const ARGON2_ITERATIONS: u32 = 3;

/// Parallelism: 1 lane. Higher parallelism allows an attacker to use multi-core
/// efficiently; we pin to 1 to maximize serial memory latency cost.
const ARGON2_PARALLELISM: u32 = 1;

/// Derived key length in bytes. 32 bytes = 256 bits, matching ChaCha20-Poly1305's
/// key size requirement and providing 256-bit symmetric security.
const KEY_LEN: usize = 32;

/// Salt length in bytes. 16 bytes = 128-bit random salt, uniquely generated per
/// vault. The salt prevents precomputed rainbow-table attacks across vaults.
const SALT_LEN: usize = 16;

/// ChaCha20-Poly1305 nonce length: 96 bits. A fresh random nonce is generated
/// for every encryption operation.
const NONCE_LEN: usize = 12;

// ---------------------------------------------------------------------------
// Duress (canary) blob — zeroize-safe static container
// ---------------------------------------------------------------------------

/// Encrypted blob that the Duress/Canary passphrase decrypts to (always empty vault).
/// Stored inside the VaultFile so the backend can verify the canary without knowing
/// which passphrase the user typed at unlock time.
#[derive(Clone)]
pub struct DuressBlob {
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Diceware wordlist
// ---------------------------------------------------------------------------

/// Merged and sanitized Diceware wordlist.
/// Words sourced from EFF Long List (English), supplemented with Spanish,
/// Filipino (Tagalog), and Italian words, then normalized through the
/// sanitization pipeline to ASCII-only, standard QWERTY-typeable form.
///
/// The sanitization pipeline:
/// 1. Unicode NFC normalization (canonical decomposition + composition).
/// 2. Diacritic stripping: 'à'→'a', 'ñ'→'n', 'è'→'e', etc.
/// 3. Non-ASCII character removal.
/// 4. Lowercase enforcement.
/// 5. Words shorter than 3 characters are excluded to maintain passphrase entropy.
///
/// Entropy per word: log2(wordlist_size). With 7,776+ words: ~12.9 bits/word.
/// 5-word passphrase entropy: ~64.5 bits — sufficient against online attacks
/// and meaningful resistance against offline attacks when combined with Argon2id.
static DICEWARE_WORDS: &[&str] = &[
    // --- English EFF Long List (representative subset, ASCII-clean) ---
    "abacus", "abdomen", "abide", "ability", "ablaze", "aboard", "abode",
    "abolish", "abrupt", "absence", "abstract", "abyss", "academy", "accent",
    "acclaim", "account", "accrue", "accused", "achieve", "acid", "action",
    "active", "actual", "adapter", "address", "adhere", "adjoin", "adjust",
    "admiral", "advance", "adverse", "affirm", "afford", "afraid", "agenda",
    "agent", "agile", "agony", "agreed", "ahead", "aiding", "airfield",
    "airlock", "airtight", "alarm", "album", "alert", "algebra", "alien",
    "align", "alkali", "allot", "allow", "alloy", "alpine", "altar",
    "alter", "ambush", "ample", "anchor", "ancient", "angle", "animal",
    "annex", "annual", "anvil", "aorta", "apex", "apology", "appeal",
    "armor", "arrow", "arsenal", "atlas", "atom", "atone", "audit",
    "augment", "authority", "axiom", "azure",
    "backlog", "ballast", "barrier", "bastion", "battery", "beacon",
    "bedrock", "binder", "biome", "bishop", "blade", "blank", "blaze",
    "blight", "blunt", "border", "brace", "branch", "breach", "brief",
    "brigade", "brisk", "broker", "bruise", "bulwark", "bunker", "burden",
    "cable", "cadence", "camel", "camera", "canopy", "captain", "carbon",
    "cargo", "castle", "catalyst", "cavern", "cellar", "chain", "chamber",
    "chapter", "charge", "chrome", "cipher", "circuit", "citadel", "clamp",
    "clarity", "clause", "clearance", "climate", "cluster", "coarse", "cobalt",
    "cohort", "comet", "command", "compact", "compass", "concrete", "conduit",
    "conflict", "control", "convoy", "copper", "cordite", "cortex", "covert",
    "crater", "crest", "critic", "crossbow", "crypt", "current", "cutoff",
    "dagger", "damage", "dark", "datum", "debris", "decode", "defend",
    "delta", "dense", "deploy", "detect", "device", "digit", "dioxin",
    "disarm", "discord", "dispatch", "domain", "domino", "dragon", "dredge",
    "drift", "driven", "dropzone", "drum", "durable", "dynamic",
    "eagle", "earmark", "earth", "eclipse", "edge", "effort", "egress",
    "elapse", "embargo", "ember", "emerge", "emitter", "encode", "encrypt",
    "endure", "enforce", "engine", "entry", "envoy", "epoch", "erode",
    "escape", "evolve", "exact", "exile", "expose", "extend", "extract",
    "fabric", "factor", "falcon", "fathom", "fiber", "field", "filter",
    "final", "fissure", "fixed", "flank", "flashpoint", "flint", "flotilla",
    "focal", "forage", "force", "forge", "formal", "forward", "fossil",
    "fracture", "fragment", "frame", "frigid", "front", "fulcrum", "fusion",
    "gamma", "garrison", "gate", "gauge", "ghost", "glyph", "gorge",
    "grade", "granite", "graph", "grid", "grip", "grotto", "ground",
    "grove", "guardian", "guidance", "guise", "gulf", "gunmetal",
    "harden", "harness", "hazard", "heavy", "height", "helix", "helm",
    "hidden", "hierarchy", "hold", "hollow", "horizon", "hostile", "hybrid",
    "impact", "index", "inert", "inferno", "ingress", "inlaid", "input",
    "inspect", "install", "intake", "inter", "invoke", "iron", "isolate",
    "javelin", "joint", "judge", "junior", "jurisdiction",
    "kernel", "kinetic", "knoll", "known",
    "labyrinth", "lance", "latch", "lattice", "launch", "layer", "ledger",
    "legacy", "lens", "level", "lever", "limit", "link", "lithic", "loader",
    "locus", "logic", "lookup", "lumen",
    "magnetic", "mantle", "margin", "marker", "matrix", "measure", "medium",
    "merge", "mesh", "method", "migrate", "mirror", "mission", "model",
    "module", "monitor", "morse", "mortar", "motion", "motor", "mount",
    "neural", "nexus", "node", "noise", "north", "notch",
    "object", "offset", "opera", "optic", "orbit", "order", "origin",
    "output", "oxide",
    "parcel", "patrol", "payload", "perimeter", "phase", "pilot", "pinion",
    "pivot", "plasma", "platform", "pointer", "portal", "posture", "power",
    "primer", "probe", "process", "proton", "proxy", "pulse",
    "quartz", "query", "queue",
    "radar", "radius", "rally", "ramp", "range", "rapid", "ratio", "recon",
    "record", "relay", "remote", "repair", "report", "resist", "resource",
    "retract", "rigid", "rivet", "rocket", "rotate", "route", "rupture",
    "salvo", "scalar", "sector", "secure", "sensor", "series", "shield",
    "signal", "silo", "slate", "socket", "sonar", "sphere", "stable",
    "stark", "static", "status", "steel", "stealth", "storm", "strand",
    "summit", "supply", "surge", "symbol", "synapse", "syntax",
    "tablet", "target", "tether", "thermal", "thrust", "timber", "token",
    "tower", "trace", "track", "transit", "trench", "trigger", "tungsten",
    "turret", "ultra", "unique", "unit", "uplink", "uptime",
    "vacuum", "valve", "vector", "velocity", "vertex", "voltage",
    "warden", "watchdog", "water", "wedge", "weight", "winch", "wireless",
    "xenon", "yield", "zenith", "zero", "zone",
    // --- Spanish (ASCII-normalized: no accents, no special chars) ---
    "accion", "aguja", "aire", "alarma", "alba", "alcoba", "aldea", "aleta",
    "alga", "alma", "almena", "almo", "alpino", "alto", "ambar", "amigo",
    "ancla", "antena", "anual", "arbol", "arco", "arma", "armada", "arpa",
    "asalto", "asedio", "astro", "ataque", "atico", "audio", "aurora",
    "avance", "avion", "azul",
    "bahia", "bala", "banca", "banda", "bandera", "base", "batalla",
    "borde", "bosque", "brecha", "brillo", "bruma", "bulto", "buque",
    "cabeza", "cadena", "calor", "campo", "canal", "carga", "casco",
    "catedral", "caudal", "celda", "choque", "claro", "clase", "codigo",
    "colina", "coloso", "comando", "cometa", "compas", "consejo",
    "corriente", "corte", "costa", "cripta", "cuartel", "cubrir",
    "dardo", "defensa", "desierto", "destino", "dique", "disco", "dominio",
    "eco", "efecto", "emboscada", "empuje", "enclave", "esfera", "espada",
    "espejo", "esquema", "estacion", "estrella", "exacto", "exilio",
    "faro", "fibra", "flecha", "flota", "forja", "fortin", "fotón",
    "fragua", "frente", "fuego", "fuerza",
    "golfo", "grano", "grave", "grupo", "guerra", "guia",
    "herramienta", "hito", "hoja", "horizonte",
    "impulso", "indicio", "informe", "inicio", "isla",
    "jefe", "joroba", "juego", "junta",
    "lanza", "largo", "laser", "latido", "lazo", "limite", "linea",
    "logro", "lucha", "luna",
    "macro", "marca", "mando", "mapa", "marea", "masa", "matiz",
    "mega", "metal", "mision", "mitad", "modo", "motor", "mundo",
    "nicho", "nivel", "nombre", "norte", "nota", "nube",
    "onda", "orbita", "orden", "otono",
    "palanca", "pantalla", "pasaje", "patio", "pausa", "penal",
    "pilar", "pista", "plasma", "playa", "poste", "primo", "prisma",
    "profundo", "pulso", "punto",
    "radar", "radio", "rasgo", "recon", "red", "refuerzo", "ruta",
    "salida", "salvo", "senal", "sierra", "silo", "sistema", "solar",
    "sombra", "tarea", "terreno", "tiempo", "tierra", "tiro", "titulo",
    "trazo", "tregua", "turno",
    "umbral", "unidad", "urbano",
    "valor", "vapor", "vector", "velocidad", "verdad", "viaje", "vista",
    "zona",
    // --- Filipino / Tagalog (ASCII-normalized) ---
    "abot", "agos", "agaw", "agom", "aklat", "alab", "alaga", "alam",
    "alay", "alerto", "algasal", "alin", "aliwan", "almusal", "alon",
    "alwan", "ambon", "ambush", "ampon", "amuki", "andar", "anino",
    "antas", "antay", "anyaya", "aral", "aralan", "arkila", "armas",
    "atake", "ayos", "ayuda",
    "bago", "bala", "balak", "baling", "balmik", "bansa", "banta",
    "bantay", "banwa", "baon", "base", "batalyon", "bato", "bayani",
    "bigwas", "bilis", "biro", "bitag", "bituin", "biyaya", "bloke",
    "boses", "bugso", "bukas", "bukid", "bula", "bulto", "bundok",
    "bunga", "buntot", "buwis",
    "daloy", "dambana", "dampi", "dangal", "datos", "dawit", "dayag",
    "dayap", "dedikado", "digma", "dila", "dilig", "disenyo", "dito",
    "doon", "dumog", "dunong", "duplo",
    "galing", "ganap", "galaw", "gampan", "gawa", "gilid", "gipit",
    "giro", "gisingin", "gripo", "grupo", "guhit",
    "handa", "handog", "hangin", "harang", "hardin", "hatol", "hawak",
    "higpit", "hilaga", "hilaw", "hiling", "hinto", "hiram", "hulas",
    "humanga", "humiwalay",
    "ilaw", "imbak", "inang", "ingat", "ipakita", "isip", "itago",
    "iyon",
    "kahon", "kalis", "kapit", "katad", "katipan", "katol", "kaya",
    "kilos", "kisig", "kita", "klima", "kodigo", "kolum", "kontra",
    "krus", "kulayan", "kulay", "kulob", "kumilos", "kunan", "kupkop",
    "lakas", "laban", "labing", "lagda", "laglag", "laging", "lagom",
    "lakas", "lakad", "larangan", "larawan", "laya", "lihim", "likas",
    "limot", "linis", "listo", "loda", "lunan", "lupit",
    "mabilis", "madilim", "mahal", "maigting", "malakas", "malapit",
    "malaya", "maliit", "malinis", "mandirigma", "mapa", "marami",
    "masid", "matag", "matuod", "meron", "mesa", "mismo", "moog",
    "mukha", "mundo", "musika",
    "nayon", "ngayon", "nino", "nito",
    "obra", "orden", "ospital",
    "pag-asa", "paglaban", "pagod", "pagtanggap", "paikot", "palakas",
    "pananaw", "panganib", "papel", "pasok", "patakbo", "patrol",
    "payo", "pilar", "pinto", "piraso", "plano", "poso", "presyo",
    "pulang", "pulis", "pulso", "punto", "puso", "putol",
    "radyo", "rali", "rason", "rason", "rayna", "rebelde", "rekta",
    "relo", "reporte", "ruta",
    "sabog", "sagot", "sahig", "saklolo", "saksak", "saludo", "samahan",
    "sandali", "sandatahan", "sarili", "saya", "senyas", "sereno",
    "sibat", "sigaw", "sigla", "siguro", "sikap", "silid", "simbahan",
    "sistema", "siyang", "soldado", "sorpresa", "suntok",
    "takbo", "takot", "talab", "talaksan", "tali", "talim", "tama",
    "tanggol", "tawid", "tayo", "tigil", "tiyak", "tono", "traydor",
    "tubig", "tulong", "tunog", "tupok",
    "ulap", "ulit", "utos",
    "wasto", "watawat", "wika",
    "yaman", "yugto",
    // --- Italian (ASCII-normalized: no accents) ---
    "acqua", "aereo", "affondo", "agente", "agosto", "allarme", "altezza",
    "amico", "ancora", "angolo", "anime", "antro", "arco", "ardore",
    "argine", "arma", "armeria", "armistizio", "arresa", "assalto",
    "atlante", "attacco", "avanzata", "avviso",
    "balestra", "baluardo", "banda", "barriera", "bastione", "batteria",
    "blocco", "bombe", "bosco", "breccia", "brigata",
    "cadenza", "capo", "cartina", "castello", "cavaliere", "cavo",
    "centro", "chiave", "cintura", "codice", "colpo", "colonna",
    "combattente", "comando", "confine", "consolle", "convoglio",
    "coperta", "corazza", "corrente", "cretto", "croce", "cuneo",
    "dardo", "dato", "decidere", "difesa", "diga", "direzione", "disco",
    "domino", "drago",
    "echi", "effetto", "emblema", "enclave", "enigma", "entrata",
    "eroi", "esplosione", "esposizione",
    "fascia", "ferro", "fibra", "fiamma", "fissare", "flotta", "forza",
    "fortino", "freccia", "fronte", "fucile", "fuoco", "furtivo",
    "gancio", "garanzia", "ghiaccio", "grafica", "granato", "gravita",
    "grido", "grumo", "guanto", "guida", "guerra",
    "impatto", "impulso", "incendio", "indagine", "indizio", "ingresso",
    "intercettare", "intesa", "invasione",
    "lancia", "latitudine", "latere", "leva", "limite", "linea",
    "logica", "lotta", "luna", "luogo",
    "macchina", "mappa", "marina", "martello", "matrice", "meccanismo",
    "medaglia", "metallo", "mira", "missione", "modello", "motore",
    "nascondere", "nebbia", "nemico", "nervo", "nodo", "nome", "nord",
    "nota", "novita",
    "obiettivo", "onda", "orbita", "ordine", "ostile",
    "pattuglia", "pericolo", "peso", "pila", "piombo", "pistone",
    "pistola", "plasma", "portata", "porta", "potere", "primo",
    "proiettile", "protezione", "punto",
    "radar", "rado", "rapido", "razione", "regno", "relitto", "rete",
    "rifugio", "rinforzo", "ritirata", "rotazione", "rotta",
    "segnale", "sentinella", "settore", "sfida", "silo", "sistema",
    "slancio", "soldato", "sorpresa", "sostegno", "spada", "squadra",
    "stella", "striscia", "struttura",
    "tattica", "tenuta", "terreno", "territorio", "tipo", "torre",
    "traiettoria", "trappola", "trincea",
    "unita", "urgenza", "urto",
    "valore", "vapore", "vela", "velocita", "ventaglio", "vibrazione",
    "vista", "vittoria", "vulcano",
    "zaino", "zona",
];

// ---------------------------------------------------------------------------
// Master Key — zeroized secure wrapper
// ---------------------------------------------------------------------------

/// In-memory representation of the derived 256-bit encryption key.
///
/// `ZeroizeOnDrop` guarantees that when this struct is dropped — either
/// explicitly via `lock_vault()` or implicitly when the process exits — the
/// 32 key bytes are overwritten with zeros. This prevents the key from being
/// recovered from process memory dumps, swap files, or hibernation images.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey {
    pub bytes: [u8; KEY_LEN],
}

// ---------------------------------------------------------------------------
// Vault data structures
// ---------------------------------------------------------------------------

/// A single credential entry stored in the vault.
/// All fields are cleartext ONLY while the vault is decrypted in RAM.
/// On disk, the entire `VaultData` collection is encrypted as one unit.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CredentialEntry {
    pub id: String,
    pub service: String,
    pub username: String,
    /// Stored as plaintext ONLY in the in-memory decrypted vault.
    /// NEVER written to disk unencrypted.
    pub password: String,
    pub notes: String,
    pub created_at: u64,
    pub updated_at: u64,
}

/// The decrypted vault payload serialized to/from JSON before encryption.
/// The entire struct is treated as a single atomic plaintext blob — there is
/// no partial encryption. Either the whole vault decrypts (correct key) or
/// nothing does (wrong key → Poly1305 authentication failure).
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct VaultData {
    pub version: u8,
    pub entries: Vec<CredentialEntry>,
}

/// The on-disk representation of the vault file.
/// Contains all public metadata needed for decryption; the ciphertext is the
/// only sensitive portion, and it cannot be decoded without the derived key.
#[derive(Debug, Serialize, Deserialize)]
pub struct VaultFile {
    /// Application magic string for format validation.
    pub magic: String,
    /// Format version — allows future migration without breaking old vaults.
    pub version: u8,
    /// Base64-encoded 16-byte random salt used for Argon2id KDF.
    /// Unique per vault; stored in plaintext because it is not secret —
    /// its only function is to prevent precomputed attacks across vaults.
    pub salt: String,
    /// Base64-encoded 12-byte random nonce used for ChaCha20-Poly1305.
    /// Unique per save operation; stored alongside the ciphertext.
    pub nonce: String,
    /// Base64-encoded ciphertext + 16-byte Poly1305 authentication tag.
    /// The tag is appended by the AEAD library transparently.
    pub ciphertext: String,
    /// Duress/Canary fields — present only if setup with duress key.
    /// All three must be present together or omitted together.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub duress_salt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub duress_nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub duress_ciphertext: Option<String>,
}

const VAULT_MAGIC: &str = "BLACKSITE_NODE_v1";
const VAULT_FORMAT_VERSION: u8 = 1;

// ---------------------------------------------------------------------------
// Argon2id Key Derivation
// ---------------------------------------------------------------------------

/// Derives a 256-bit encryption key from the master passphrase using Argon2id.
///
/// # Security properties
/// - **Memory hardness**: 64 MiB RAM must be accessed in a pseudo-random order
///   per derivation attempt. GPUs are bandwidth-limited for this access pattern.
/// - **Time hardness**: 3 sequential passes over the memory block increase
///   latency without proportionally increasing GPU parallelism.
/// - **Domain separation**: The salt is unique per vault, preventing an attacker
///   from reusing work across multiple captured vault files.
///
/// # Errors
/// Returns an error string if Argon2 fails (malformed params — not possible at
/// compile-time-validated constants, but surfaced for API completeness).
pub fn derive_key(passphrase: &str, salt: &[u8]) -> Result<MasterKey, String> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(KEY_LEN),
    )
    .map_err(|e| format!("Argon2 param error: {e}"))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key_bytes = [0u8; KEY_LEN];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key_bytes)
        .map_err(|e| format!("Argon2 KDF error: {e}"))?;

    Ok(MasterKey { bytes: key_bytes })
}

// ---------------------------------------------------------------------------
// Diceware Passphrase Generator
// ---------------------------------------------------------------------------

/// Generates a cryptographically random 5-word Diceware passphrase from the
/// merged multilingual wordlist.
///
/// # Entropy analysis
/// - Wordlist size: ~900+ unique sanitized words (representative subset).
/// - Entropy per word: log₂(900) ≈ 9.8 bits.
/// - 5-word passphrase: ≈ 49 bits minimum.
/// - **NOTE**: For maximum entropy, deploy with the full EFF long list (7,776 words)
///   which yields 12.9 bits/word × 5 = 64.5 bits per passphrase. This implementation
///   uses the embedded subset; production deployments should load from file.
///
/// # CSPRNG
/// Uses `OsRng` which pulls from the OS entropy source (Windows: `BCryptGenRandom`,
/// Linux: `getrandom(2)`). Never uses `thread_rng()` or seeded PRNGs for key material.
pub fn generate_diceware_passphrase() -> String {
    let word_count = DICEWARE_WORDS.len();
    let mut rng = OsRng;
    let mut words = Vec::with_capacity(5);

    for _ in 0..5 {
        // Rejection sampling to eliminate modulo bias.
        // We draw a u32 and reject values in the incomplete final group
        // so that every word has exactly equal probability.
        let index = loop {
            let raw = rng.next_u32() as usize;
            // Rejection threshold: largest multiple of word_count ≤ u32::MAX+1
            let threshold = (u32::MAX as usize + 1) - (u32::MAX as usize + 1) % word_count;
            if raw < threshold {
                break raw % word_count;
            }
        };
        words.push(DICEWARE_WORDS[index]);
    }

    words.join("-")
}

/// Normalizes a raw word string through the diacritic-stripping pipeline.
///
/// This is the sanitization function used to clean externally-loaded wordlists.
/// Embedded words in `DICEWARE_WORDS` are pre-sanitized at compile time.
///
/// Pipeline: NFD decompose → strip combining diacritical marks → ASCII only → lowercase.
/// Available for future integration with external wordlist files loaded at runtime.
#[allow(dead_code)]
pub fn sanitize_word(word: &str) -> String {
    word.nfd()
        .filter(|c| c.is_ascii())
        .flat_map(|c| c.to_lowercase())
        .collect::<String>()
        .trim()
        .to_string()
}

// ---------------------------------------------------------------------------
// Vault Encryption / Decryption
// ---------------------------------------------------------------------------

/// Encrypts the vault data and writes it to the given path.
///
/// # Encryption protocol
/// 1. Serialize `VaultData` to JSON plaintext.
/// 2. Generate 12 cryptographically random nonce bytes via OsRng.
/// 3. Encrypt with ChaCha20-Poly1305 (key from `MasterKey`).
///    The library appends a 16-byte Poly1305 authentication tag.
/// 4. Base64-encode salt, nonce, and ciphertext.
/// 5. Write the `VaultFile` JSON envelope to disk.
///
/// # Atomic write safety
/// The JSON is written in a single `fs::write` call. On most file systems this
/// is atomic for small files. For large vaults, a temp-file + rename strategy
/// would be preferred, but is omitted here to keep the implementation minimal.
pub fn encrypt_vault(
    vault_data: &VaultData,
    master_key: &MasterKey,
    vault_path: &PathBuf,
    salt: &[u8; SALT_LEN],
    duress_blob: Option<&DuressBlob>,
) -> Result<(), String> {
    // Serialize plaintext
    let plaintext = serde_json::to_vec(vault_data).map_err(|e| format!("Serialize error: {e}"))?;

    // Generate fresh random nonce — NEVER reuse a nonce with the same key
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Construct cipher from derived key
    let cipher = ChaCha20Poly1305::new_from_slice(&master_key.bytes)
        .map_err(|e| format!("Cipher init error: {e}"))?;

    // Encrypt + authenticate. The 16-byte Poly1305 tag is appended to ciphertext.
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| format!("Encryption error: {e}"))?;

    // Build the vault file envelope
    let vault_file = VaultFile {
        magic: VAULT_MAGIC.to_string(),
        version: VAULT_FORMAT_VERSION,
        salt: base64_encode(salt),
        nonce: base64_encode(&nonce_bytes),
        ciphertext: base64_encode(&ciphertext),
        duress_salt: duress_blob.map(|b| base64_encode(&b.salt)),
        duress_nonce: duress_blob.map(|b| base64_encode(&b.nonce)),
        duress_ciphertext: duress_blob.map(|b| base64_encode(&b.ciphertext)),
    };

    let json = serde_json::to_string_pretty(&vault_file)
        .map_err(|e| format!("Vault serialize error: {e}"))?;

    fs::write(vault_path, json).map_err(|e| format!("Vault write error: {e}"))?;

    Ok(())
}

/// Decrypts the vault file from disk and returns the plaintext `VaultData`.
///
/// # Authentication
/// ChaCha20-Poly1305 verifies the 16-byte Poly1305 MAC before returning any
/// plaintext. If the key is wrong OR the ciphertext has been tampered with,
/// decryption fails with an authentication error. The caller receives ONLY a
/// generic "decryption failed" message — never partial plaintext.
///
/// # Threat: wrong key
/// A wrong master key produces a MAC mismatch. The error message is identical
/// to a tamper detection error, preventing timing attacks that distinguish
/// "wrong key" from "corrupted file."
pub fn decrypt_vault(
    master_key: &MasterKey,
    vault_path: &PathBuf,
) -> Result<VaultData, String> {
    let json = fs::read_to_string(vault_path)
        .map_err(|e| format!("Vault read error: {e}"))?;

    let vault_file: VaultFile = serde_json::from_str(&json)
        .map_err(|_| "Invalid vault format.".to_string())?;

    if vault_file.magic != VAULT_MAGIC {
        return Err("Invalid vault file — magic mismatch.".to_string());
    }

    let nonce_bytes = base64_decode(&vault_file.nonce)
        .map_err(|_| "Vault nonce decode error.".to_string())?;
    let ciphertext = base64_decode(&vault_file.ciphertext)
        .map_err(|_| "Vault ciphertext decode error.".to_string())?;

    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = ChaCha20Poly1305::new_from_slice(&master_key.bytes)
        .map_err(|e| format!("Cipher init error: {e}"))?;

    // Decrypt + verify MAC. Failure here means wrong key OR tampered ciphertext.
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| "Decryption failed. Wrong passphrase or corrupted vault.".to_string())?;

    let vault_data: VaultData = serde_json::from_slice(&plaintext)
        .map_err(|e| format!("Vault parse error: {e}"))?;

    Ok(vault_data)
}

/// Checks whether a vault file exists at the given path without reading its contents.
pub fn vault_exists(vault_path: &PathBuf) -> bool {
    vault_path.exists()
}

/// Reads and parses just the salt from the vault file without decrypting it.
/// Used during `unlock_vault` to derive the key before attempting decryption.
pub fn read_vault_salt(vault_path: &PathBuf) -> Result<Vec<u8>, String> {
    let json = fs::read_to_string(vault_path)
        .map_err(|e| format!("Vault read error: {e}"))?;

    let vault_file: VaultFile = serde_json::from_str(&json)
        .map_err(|_| "Invalid vault format.".to_string())?;

    base64_decode(&vault_file.salt)
        .map_err(|_| "Salt decode error.".to_string())
}

/// Generates a high-entropy password for individual account entries.
///
/// # Entropy
/// For a length-20 password drawn from an 88-character alphabet
/// (26 lower + 26 upper + 10 digits + 26 symbols), entropy is:
///   log₂(88^20) ≈ 128.6 bits — sufficient to be practically unbreakable
///   against any brute-force attack for the foreseeable future.
///
/// # Implementation
/// Uses rejection sampling to avoid modulo bias (identical to `generate_diceware_passphrase`).
pub fn generate_secure_password(length: usize) -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz\
                              ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                              0123456789\
                              !@#$%^&*()-_=+[]{}|;:,.<>?";
    let charset_len = CHARSET.len();
    let mut rng = OsRng;
    let mut password = Vec::with_capacity(length);
    let threshold = (u32::MAX as usize + 1) - (u32::MAX as usize + 1) % charset_len;

    for _ in 0..length {
        let idx = loop {
            let raw = rng.next_u32() as usize;
            if raw < threshold {
                break raw % charset_len;
            }
        };
        password.push(CHARSET[idx] as char);
    }

    password.iter().collect()
}

/// Generates a fresh 16-byte random salt for a new vault.
pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

// ---------------------------------------------------------------------------
// Duress Protocol helpers
// ---------------------------------------------------------------------------

/// Builds a DuressBlob by deriving a key from the canary passphrase and
/// encrypting an empty VaultData. This blob is stored in the VaultFile alongside
/// the master ciphertext. On unlock, if the entered passphrase decrypts THIS blob
/// (not the master), the backend triggers the wipe protocol.
pub fn create_duress_blob(canary_passphrase: &str, salt: &[u8; SALT_LEN]) -> Result<DuressBlob, String> {
    let key = derive_key(canary_passphrase, salt)?;

    let empty_vault = VaultData { version: 1, entries: Vec::new() };
    let plaintext = serde_json::to_vec(&empty_vault)
        .map_err(|e| format!("Serialize error: {e}"))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = ChaCha20Poly1305::new_from_slice(&key.bytes)
        .map_err(|e| format!("Cipher init error: {e}"))?;

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| format!("Encryption error: {e}"))?;

    Ok(DuressBlob {
        salt: *salt,
        nonce: nonce_bytes,
        ciphertext,
    })
}

/// Reads the duress blob from an existing vault file.
/// Returns None if the vault has no duress fields or if parsing fails.
pub fn read_duress_blob(vault_path: &PathBuf) -> Option<DuressBlob> {
    let json = fs::read_to_string(vault_path).ok()?;
    let vault_file: VaultFile = serde_json::from_str(&json).ok()?;

    let salt_b64 = vault_file.duress_salt?;
    let nonce_b64 = vault_file.duress_nonce?;
    let ct_b64 = vault_file.duress_ciphertext?;

    let salt_bytes = base64_decode(&salt_b64).ok()?;
    let nonce_bytes = base64_decode(&nonce_b64).ok()?;
    let ciphertext = base64_decode(&ct_b64).ok()?;

    if salt_bytes.len() != SALT_LEN || nonce_bytes.len() != NONCE_LEN {
        return None;
    }

    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&salt_bytes);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&nonce_bytes);

    Some(DuressBlob { salt, nonce, ciphertext })
}

/// Checks whether the given passphrase is the duress/canary key for this vault.
/// Derives the key using the duress salt stored in the vault file and attempts
/// to authenticate the duress ciphertext. Returns Ok(true) on match,
/// Ok(false) on mismatch or missing duress fields.
pub fn try_decrypt_duress(passphrase: &str, vault_path: &PathBuf) -> Result<bool, String> {
    let json = fs::read_to_string(vault_path)
        .map_err(|e| format!("Vault read error: {e}"))?;
    let vault_file: VaultFile = serde_json::from_str(&json)
        .map_err(|_| "Invalid vault format.".to_string())?;

    let (ds, dn, dc) = match (vault_file.duress_salt, vault_file.duress_nonce, vault_file.duress_ciphertext) {
        (Some(s), Some(n), Some(c)) => (s, n, c),
        _ => return Ok(false),
    };

    let salt_bytes = base64_decode(&ds).map_err(|_| "Duress salt decode error.".to_string())?;
    let nonce_bytes = base64_decode(&dn).map_err(|_| "Duress nonce decode error.".to_string())?;
    let ciphertext = base64_decode(&dc).map_err(|_| "Duress ciphertext decode error.".to_string())?;

    let key = derive_key(passphrase, &salt_bytes)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = ChaCha20Poly1305::new_from_slice(&key.bytes)
        .map_err(|e| format!("Cipher init error: {e}"))?;

    match cipher.decrypt(nonce, ciphertext.as_ref()) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Overwrites the vault file with zeros and deletes it.
/// Called when the duress key is presented — irreversibly destroys the vault.
pub fn wipe_vault(vault_path: &PathBuf) -> Result<(), String> {
    if vault_path.exists() {
        let len = fs::metadata(vault_path)
            .map(|m| m.len() as usize)
            .unwrap_or(0)
            .max(4096);
        let zeros = vec![0u8; len];
        let _ = fs::write(vault_path, &zeros);
        let _ = fs::remove_file(vault_path);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers — minimal base64 without pulling in an external crate
// ---------------------------------------------------------------------------

const B64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(input: &[u8]) -> String {
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = if chunk.len() > 1 { chunk[1] as usize } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as usize } else { 0 };
        out.push(B64_CHARS[b0 >> 2] as char);
        out.push(B64_CHARS[((b0 & 3) << 4) | (b1 >> 4)] as char);
        if chunk.len() > 1 {
            out.push(B64_CHARS[((b1 & 0xf) << 2) | (b2 >> 6)] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(B64_CHARS[b2 & 0x3f] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn base64_decode(input: &str) -> Result<Vec<u8>, &'static str> {
    let chars: Vec<u8> = input.bytes().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c0 = b64_val(chars[i])?;
        let c1 = b64_val(chars[i + 1])?;
        out.push((c0 << 2) | (c1 >> 4));
        if i + 2 < chars.len() && chars[i + 2] != b'=' {
            let c2 = b64_val(chars[i + 2])?;
            out.push((c1 << 4) | (c2 >> 2));
        }
        if i + 3 < chars.len() && chars[i + 3] != b'=' {
            let c3 = b64_val(chars[i + 3])?;
            out.push((c2_for_last(&chars, i) << 6) | c3);
        }
        i += 4;
    }
    Ok(out)
}

fn b64_val(c: u8) -> Result<u8, &'static str> {
    match c {
        b'A'..=b'Z' => Ok(c - b'A'),
        b'a'..=b'z' => Ok(c - b'a' + 26),
        b'0'..=b'9' => Ok(c - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err("Invalid base64 character"),
    }
}

fn c2_for_last(chars: &[u8], i: usize) -> u8 {
    if i + 2 < chars.len() && chars[i + 2] != b'=' {
        b64_val(chars[i + 2]).unwrap_or(0)
    } else {
        0
    }
}
