//! Config + token persistence.
//!
//! **One file**: `~/.bale-vpn_config.json` — same path + JSON
//! shape the Node app used, so an existing installation
//! transitions to the Rust binary without re-auth. Token,
//! allow-list, block-list, max-clients, and the new Rust-only
//! settings (mode, nat-mode, peer-id, socks5-port) all live in
//! the same object.
//!
//! Atomic-rename write semantics: writes go to a `.tmp`
//! sibling first, then rename into place. Mode 0600 — the
//! `token` field is the auth bearer; nothing else needs read
//! access.

use lk_signaling::TokenStore;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Matches the Node app's filename + path convention exactly.
/// The fields the Node app wrote are preserved as-is so an
/// upgrade doesn't lose admission state; the Rust-added fields
/// piggy-back on the same object.
const CONFIG_FILENAME: &str = ".bale-vpn_config.json";

/// On-disk config. Field names match the Node app's JSON keys
/// where present. `serde(default)` everywhere so a partial
/// file from an old version round-trips cleanly.
#[derive(Clone, Deserialize, Serialize)]
pub struct Config {
    #[serde(default)]
    pub preferences: crate::settings::Preferences,
    // ── Node-app keys (preserved verbatim) ───────────────────
    /// Bale `access_token` cookie value. Empty / missing means
    /// unauthenticated. Read by the [`FileTokenStore`] adapter.
    #[serde(default)]
    pub token: String,

    /// Allow-list (server mode). Peer ids whose calls
    /// auto-accept. Stored as strings (Bale uids fit in i32
    /// but we keep the string shape for symmetry with the
    /// trait surface).
    #[serde(default)]
    pub admission: Vec<String>,

    /// Block-list (server mode). Peer ids whose calls silently
    /// drop.
    #[serde(default)]
    pub blacklist: Vec<String>,

    /// Server-mode capacity cap. Defaults to 5; capped at 253.
    #[serde(default = "default_max_clients", rename = "maxClients")]
    pub max_clients: u32,

    // ── Rust-added keys ──────────────────────────────────────
    /// `"client"` / `"server"`, or `None` until the user picks
    /// one in the UI. The daemon parks waiting for a mode if
    /// unset; the UI surfaces a picker.
    #[serde(default)]
    pub mode: Option<String>,

    /// `"kernel"` or `"userspace"`. Defaults to userspace on
    /// every OS — no privileged setup needed to get started.
    /// Kernel mode requires `CAP_NET_ADMIN` (Linux) or root
    /// (macOS) plus a one-time iptables / pf rule.
    #[serde(default)]
    pub nat_mode: Option<String>,

    /// HTTP UI port. CLI takes precedence.
    #[serde(default = "default_port")]
    pub port: u16,

    /// Client-mode peer to dial.
    #[serde(default, rename = "peerId")]
    pub peer_id: Option<String>,

    /// Client-mode SOCKS5 listen port.
    #[serde(default = "default_socks5_port", rename = "socks5Port")]
    pub socks5_port: u16,
}

fn default_port()        -> u16    { 3001 }
fn default_socks5_port() -> u16    { 1080 }
fn default_max_clients() -> u32    { 5 }

impl Default for Config {
    fn default() -> Self {
        Self {
            preferences: Default::default(),
            token: String::new(), admission: Vec::new(), blacklist: Vec::new(),
            max_clients: default_max_clients(), mode: None, nat_mode: None,
            port: default_port(), peer_id: None, socks5_port: default_socks5_port(),
        }
    }
}

impl Config {
    pub fn load(override_dir: Option<&Path>) -> std::io::Result<Self> {
        let path = config_path(override_dir)?;
        if !path.exists() {
            log::info!("config: {path:?} not found, using defaults");
            return Ok(Self::default());
        }
        let text = fs::read_to_string(&path)?;
        if text.trim().is_empty() {
            return Ok(Self::default());
        }
        serde_json::from_str(&text)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
    }

    /// Atomic write — `.tmp` sibling then rename. Sets mode
    /// 0600 on Unix.
    pub fn save(&self, override_dir: Option<&Path>) -> std::io::Result<()> {
        let path = config_path(override_dir)?;
        let text = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        // Portable installs may supply a config directory that does not exist
        // yet. Create it before the first settings/token write, not just in a
        // launcher, so every entry point supports a fresh installation.
        let parent = path.parent().unwrap();
        let mut directory = fs::DirBuilder::new();
        directory.recursive(true);
        #[cfg(unix)] {
            use std::os::unix::fs::DirBuilderExt;
            directory.mode(0o700);
        }
        directory.create(parent)?;
        // Exclusive random file, created as 0600 on Unix: no predictable
        // symlink target or interval where the bearer token is world-readable.
        // persist() also replaces an existing destination atomically on Windows.
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
        tmp.write_all(text.as_bytes())?;
        tmp.as_file().sync_all()?;
        tmp.persist(&path).map_err(|e| e.error)?;
        Ok(())
    }
}

/// Resolved config after merging the on-disk values with CLI
/// overrides. This is what the daemon actually operates on.
#[derive(Debug, Clone)]
pub struct Resolved {
    pub preferences: crate::settings::Preferences,
    /// `Some("client" | "server")`, or `None` until the user
    /// picks one in the UI. The daemon parks in `run_mode` when
    /// `None`; the UI surfaces a picker.
    pub mode:        Option<String>,
    /// `"kernel"` / `"userspace"`. Defaults to `"userspace"` —
    /// works on every OS without privileged setup.
    pub nat_mode:    String,
    pub port:        u16,
    pub peer_id:     Option<String>,
    pub socks5_port: u16,
    /// Client-mode only: open a local TUN device alongside
    /// SOCKS5. Driven by the `--client-tun` CLI flag.
    pub client_tun:  bool,
    /// True when the mode was set via the `--mode` CLI flag.
    /// `/logout` keeps the mode in this case (the operator
    /// pinned it via CLI) and clears it otherwise so the next
    /// sign-in shows the picker again.
    pub mode_pinned_by_cli: bool,
    /// Directory containing the JSON config file. Used by the
    /// [`FileTokenStore`] adapter and HTTP UI for atomic saves.
    pub config_dir:  PathBuf,
}

impl Resolved {
    pub fn merge_cli(
        cfg:        &Config,
        cli_mode:   Option<String>,
        cli_nat:    Option<String>,
        cli_port:   Option<u16>,
        client_tun: bool,
    ) -> Self {
        // CLI > config file > unset (UI picker).
        let mode_pinned_by_cli = cli_mode.is_some();
        let mode = cli_mode.or_else(|| cfg.mode.clone());
        // Userspace NAT on every OS — kernel needs privileged
        // setup. UI / CLI can override per-run.
        let nat_mode = cli_nat
            .or_else(|| cfg.nat_mode.clone())
            .unwrap_or_else(|| "userspace".to_string());
        let config_dir = config_dir(None).unwrap_or_else(|_| PathBuf::from("."));
        Self {
            mode,
            preferences: cfg.preferences.clone(),
            nat_mode,
            port: cli_port.unwrap_or(cfg.port),
            peer_id: cfg.peer_id.clone(),
            socks5_port: cfg.socks5_port,
            client_tun,
            mode_pinned_by_cli,
            config_dir,
        }
    }
}

/// `~/.bale-vpn_config.json` — same path the Node app used.
fn config_path(override_dir: Option<&Path>) -> std::io::Result<PathBuf> {
    let dir = config_dir(override_dir)?;
    Ok(dir.join(CONFIG_FILENAME))
}

fn config_dir(override_dir: Option<&Path>) -> std::io::Result<PathBuf> {
    if let Some(d) = override_dir { return Ok(d.to_path_buf()); }
    // Same layout as the Node app: `<dir-of-binary>/.bale-vpn_config.json`.
    // Keeps the config + executable as a single drop-in unit
    // (matches `tar xf bale-vpn.tar.gz && ./bale-vpn` deployments
    // without forcing a separate config-dir setup step).
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            return Ok(dir.to_path_buf());
        }
    }
    // Fallback: cwd. Only hit if `current_exe()` fails (rare —
    // sandboxed environments where /proc/self/exe is inaccessible).
    std::env::current_dir()
}

// ─── Shared config file handle ──────────────────────────────

/// Process-wide handle around the on-disk JSON config.
/// Holds the directory + a write lock so every read-modify-
/// write goes through `update()` and concurrent writers can't
/// lose each other's changes.
///
/// Construct once at daemon startup, share via Arc — both the
/// [`FileTokenStore`] (auth token saves) and the HTTP UI
/// `/config` handler (admission / mode / peer changes) call
/// `update()` to mutate the file safely.
pub struct ConfigFile {
    dir:        PathBuf,
    write_lock: Mutex<()>,
}

impl ConfigFile {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir, write_lock: Mutex::new(()) }
    }
    pub fn dir(&self) -> &Path { &self.dir }

    /// Snapshot the on-disk config. No lock — readers don't
    /// race with the atomic-rename writer in [`Config::save`].
    pub fn load(&self) -> Config {
        Config::load(Some(&self.dir)).unwrap_or_default()
    }

    /// Atomic read-modify-write. The mutate closure runs under
    /// the write lock; concurrent `update()` calls serialize.
    /// Returns the post-mutation `Config` so the caller can
    /// mirror fields into the in-memory `Resolved`.
    ///
    /// The closure is expected to be short + non-blocking. Hold
    /// the lock just long enough to read, mutate, and write.
    pub fn update<F: FnOnce(&mut Config)>(&self, mutate: F) -> std::io::Result<Config> {
        let _g = self.write_lock.lock();
        let mut cfg = Config::load(Some(&self.dir))?;
        mutate(&mut cfg);
        cfg.save(Some(&self.dir))?;
        Ok(cfg)
    }
}

// ─── TokenStore adapter ─────────────────────────────────────

/// `TokenStore` impl backed by the shared [`ConfigFile`].
/// Reads on `load()` come from the in-memory cache so the
/// signaling layer's `load()`-on-every-reconnect path doesn't
/// re-read the file. Writes go through `ConfigFile::update`
/// so the auth token doesn't clobber concurrent admission /
/// mode changes from the HTTP UI.
pub struct FileTokenStore {
    file:  Arc<ConfigFile>,
    cache: Mutex<Option<Vec<u8>>>,
    vault: crate::vault::Vault,
}

impl FileTokenStore {
    pub fn new(file: Arc<ConfigFile>) -> Self {
        let cfg = file.load();
        let vault = crate::vault::Vault::new(file.dir());
        let initial = match vault.read("token.bin") {
            Ok(Some(bytes)) => { if !cfg.token.is_empty() { let _ = file.update(|c| c.token.clear()); } Some(bytes) },
            Ok(None) if !cfg.token.is_empty() => {
                match vault.write("token.bin", cfg.token.as_bytes()) {
                    Ok(()) => { let _ = file.update(|c| c.token.clear()); Some(cfg.token.into_bytes()) },
                    Err(_) => { log::error!("Could not migrate legacy token to protected storage"); None }
                }
            },
            Ok(None) => None,
            Err(_) => { log::error!("Could not unlock protected token; no credentials loaded"); None }
        };
        Self { file, cache: Mutex::new(initial), vault }
    }

    pub fn into_arc(self) -> Arc<dyn TokenStore> { Arc::new(self) }
}

impl TokenStore for FileTokenStore {
    fn load(&self) -> Option<Vec<u8>> { self.cache.lock().clone() }

    fn save(&self, bytes: &[u8]) {
        if self.vault.write("token.bin", bytes).is_err() {
            log::error!("Could not persist protected token"); return;
        }
        *self.cache.lock() = Some(bytes.to_vec());
        if self.file.update(|c| c.token.clear()).is_err() { log::error!("Could not clear legacy token field"); }
    }

    fn clear(&self) {
        *self.cache.lock() = None;
        if self.vault.clear("token.bin").is_err() { log::error!("Could not remove protected token"); }
        if let Err(e) = self.file.update(|c| c.token.clear()) {
            log::warn!("token clear: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_and_legacy_defaults_agree() {
        let fresh = Config::default();
        let legacy: Config = serde_json::from_str("{}").unwrap();
        assert_eq!(fresh.port, 3001);
        assert_eq!(fresh.socks5_port, 1080);
        assert_eq!(fresh.max_clients, 5);
        assert_eq!(serde_json::to_value(fresh).unwrap(), serde_json::to_value(legacy).unwrap());
    }

    #[test]
    fn cli_port_overrides_persisted_port_only_when_supplied() {
        let cfg = Config { port: 4001, ..Config::default() };
        assert_eq!(Resolved::merge_cli(&cfg, None, None, None, false).port, 4001);
        assert_eq!(Resolved::merge_cli(&cfg, None, None, Some(5001), false).port, 5001);
    }

    #[test]
    fn first_run_creates_missing_config_directory_and_preserves_updates() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("portable build").join("data");
        assert!(!dir.exists());
        let file = ConfigFile::new(dir.clone());
        file.update(|c| c.mode = Some("client".into())).unwrap();
        file.update(|c| c.socks5_port = 1081).unwrap();
        let saved = Config::load(Some(&dir)).unwrap();
        assert_eq!(saved.mode.as_deref(), Some("client"));
        assert_eq!(saved.socks5_port, 1081);
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        }
    }

    #[test]
    fn repeated_saves_replace_config_without_losing_settings() {
        let dir = tempfile::tempdir().unwrap();
        let file = ConfigFile::new(dir.path().to_path_buf());
        file.update(|c| c.token = "test-token".into()).unwrap();
        file.update(|c| c.admission.push("123".into())).unwrap();
        let cfg = Config::load(Some(dir.path())).unwrap();
        assert_eq!(cfg.token, "test-token");
        assert_eq!(cfg.admission, ["123"]);
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(config_path(Some(dir.path())).unwrap()).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn update_preserves_corrupt_config_for_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let path = config_path(Some(dir.path())).unwrap();
        fs::write(&path, "{broken").unwrap();
        let file = ConfigFile::new(dir.path().to_path_buf());
        assert!(file.update(|c| c.token.clear()).is_err());
        assert_eq!(fs::read_to_string(path).unwrap(), "{broken");
    }

    #[test]
    fn legacy_token_migrates_out_of_json_and_logout_removes_protected_copy() {
        let dir=tempfile::tempdir().unwrap(); let file=Arc::new(ConfigFile::new(dir.path().to_owned()));
        file.update(|c|c.token="fixture-migration-token".into()).unwrap();
        let store=FileTokenStore::new(file.clone());
        assert_eq!(store.load().unwrap(),b"fixture-migration-token");
        assert!(file.load().token.is_empty());
        assert!(dir.path().join("token.bin").exists());
        let reopened=FileTokenStore::new(file.clone());assert_eq!(store.load(),reopened.load());
        reopened.clear();assert!(FileTokenStore::new(file).load().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn save_does_not_follow_predictable_temp_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        fs::write(&victim, "unchanged").unwrap();
        let tmp = config_path(Some(dir.path())).unwrap().with_extension("json.tmp");
        std::os::unix::fs::symlink(&victim, tmp).unwrap();
        Config::default().save(Some(dir.path())).unwrap();
        assert_eq!(fs::read_to_string(victim).unwrap(), "unchanged");
    }
}
