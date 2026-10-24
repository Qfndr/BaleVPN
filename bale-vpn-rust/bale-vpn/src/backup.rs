//! Password-encrypted, bounded account transfer. No OTP, logout or automatic calls.
//! Imported accounts are appended to unused profiles; existing accounts are never overwritten.
use crate::{config::Config, daemon::AppState, device::DeviceIdentity, ui::ApiError, vault::Vault};
use axum::{extract::State, Json};
use ring::{
    aead, pbkdf2,
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, io, num::NonZeroU32, path::Path, sync::Arc};
use zeroize::{Zeroize, Zeroizing};
const FORMAT: &str = "balevpn-account-v1";
const ROUNDS: u32 = 600_000;
const MAX_PLAIN: usize = 1024 * 1024;
fn error(message: &str) -> io::Error {
    io::Error::other(message)
}
fn api(e: impl std::fmt::Display) -> ApiError {
    ApiError::Internal(e.to_string())
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    format: String,
    rounds: u32,
    salt: String,
    nonce: String,
    ciphertext: String,
}
/// The native shell receives only an encrypted envelope, without a password.
pub fn encode_archive(value: serde_json::Value) -> io::Result<Vec<u8>> {
    let envelope: Envelope =
        serde_json::from_value(value).map_err(|_| error("Invalid encrypted account file"))?;
    if envelope.format != FORMAT
        || envelope.rounds != ROUNDS
        || unhex(&envelope.salt, 16)?.len() != 16
        || unhex(&envelope.nonce, 12)?.len() != 12
        || unhex(&envelope.ciphertext, MAX_PLAIN + 16)?.len() < 16
    {
        return Err(error("Invalid encrypted account file"));
    }
    Ok(serde_json::to_vec(&envelope)?)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    source: u8,
    name: String,
    config: Config,
    token: Option<String>,
    identity: Vec<u8>,
    device: DeviceIdentity,
}
impl Drop for Entry {
    fn drop(&mut self) {
        self.token.zeroize();
        self.identity.zeroize();
        self.config.token.zeroize();
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    format: String,
    accounts: Vec<Entry>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Export {
    password: String,
    slots: Vec<u8>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Import {
    password: String,
    archive: Envelope,
    entries: Option<Vec<usize>>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    slot: u8,
    name: String,
    mode: Option<String>,
    has_session: bool,
    running: bool,
}
fn unhex(s: &str, max: usize) -> io::Result<Vec<u8>> {
    if s.len() > max * 2 || s.len() % 2 != 0 || !s.is_ascii() {
        return Err(error("Invalid encrypted account file"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| error("Invalid encrypted account file"))
        })
        .collect()
}
fn key(password: &str, salt: &[u8]) -> io::Result<aead::LessSafeKey> {
    if !(12..=1024).contains(&password.chars().count()) || password.len() > 4096 {
        return Err(error("Use an archive password of at least 12 characters"));
    }
    let mut derived = Zeroizing::new([0u8; 32]);
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(ROUNDS).unwrap(),
        salt,
        password.as_bytes(),
        derived.as_mut(),
    );
    Ok(aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_256_GCM, derived.as_ref())
            .map_err(|_| error("Account encryption failed"))?,
    ))
}
fn seal(payload: &Payload, password: &str) -> io::Result<Envelope> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    let rng = SystemRandom::new();
    rng.fill(&mut salt)
        .map_err(|_| io::Error::other("Invalid or unavailable account data"))?;
    rng.fill(&mut nonce)
        .map_err(|_| io::Error::other("Invalid or unavailable account data"))?;
    let mut bytes = Zeroizing::new(serde_json::to_vec(payload)?);
    if bytes.len() > MAX_PLAIN {
        return Err(error("Account archive is too large"));
    }
    key(password, &salt)?
        .seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(FORMAT.as_bytes()),
            &mut *bytes,
        )
        .map_err(|_| error("Account encryption failed"))?;
    Ok(Envelope {
        format: FORMAT.into(),
        rounds: ROUNDS,
        salt: crate::settings::hex(&salt),
        nonce: crate::settings::hex(&nonce),
        ciphertext: crate::settings::hex(&bytes),
    })
}
fn open(envelope: Envelope, password: &str) -> io::Result<Payload> {
    if envelope.format != FORMAT || envelope.rounds != ROUNDS {
        return Err(error("Unsupported account archive format"));
    }
    let salt = unhex(&envelope.salt, 16)?;
    let nonce = unhex(&envelope.nonce, 12)?;
    if salt.len() != 16 || nonce.len() != 12 {
        return Err(error("Invalid encrypted account file"));
    }
    let mut bytes = Zeroizing::new(unhex(&envelope.ciphertext, MAX_PLAIN + 16)?);
    let plaintext = key(password, &salt)?
        .open_in_place(
            aead::Nonce::try_assume_unique_for_key(&nonce)
                .map_err(|_| io::Error::other("Invalid or unavailable account data"))?,
            aead::Aad::from(FORMAT.as_bytes()),
            &mut bytes,
        )
        .map_err(|_| error("Incorrect archive password or damaged account file"))?;
    let payload: Payload =
        serde_json::from_slice(plaintext).map_err(|_| error("Invalid account archive contents"))?;
    if payload.format != FORMAT || payload.accounts.is_empty() || payload.accounts.len() > 9 {
        return Err(error("Invalid account archive contents"));
    }
    let mut ids = HashSet::new();
    let mut identities = HashSet::new();
    let mut sessions = HashSet::new();
    for entry in &payload.accounts {
        if entry.source > 8
            || !ids.insert(entry.source)
            || entry.name.is_empty()
            || entry.name.chars().count() > 48
            || entry.name.chars().any(char::is_control)
            || entry.identity.len() > 32_768
            || entry.config.token.len() > 65_536
            || entry.token.as_ref().is_some_and(|t| {
                t.is_empty() || t.len() > 65_536 || t.chars().any(char::is_control)
            })
            || entry
                .config
                .mode
                .as_deref()
                .is_some_and(|m| !matches!(m, "client" | "server"))
        {
            return Err(error("Invalid account archive contents"));
        }
        entry.device.validate()?;
        let stored: serde_json::Value = serde_json::from_slice(&entry.identity)
            .map_err(|_| error("Invalid account identity"))?;
        let certificate: Vec<u8> = serde_json::from_value(stored["certificate"].clone())
            .map_err(|_| error("Invalid account identity"))?;
        let private_key: Zeroizing<Vec<u8>> = Zeroizing::new(
            serde_json::from_value(stored["private_key"].clone())
                .map_err(|_| error("Invalid account identity"))?,
        );
        let identity = lktunnel::security::Identity {
            certificate,
            private_key: private_key.to_vec(),
        };
        identity.options(&[], true, false).map_err(api_to_io)?;
        entry
            .config
            .preferences
            .validate(&identity)
            .map_err(api_to_io)?;
        if !identities.insert(crate::settings::code(&identity.certificate)) {
            return Err(error("Duplicate account identity in archive"));
        }
        if let Some(token) = &entry.token {
            if !sessions.insert(
                ring::digest::digest(&ring::digest::SHA256, token.as_bytes())
                    .as_ref()
                    .to_vec(),
            ) {
                return Err(error("Duplicate saved session in archive"));
            }
        }
    }
    Ok(payload)
}
fn api_to_io(e: String) -> io::Error {
    io::Error::other(e)
}
fn collect(
    directory: &Path,
    slots: &[u8],
    config: &crate::aggregate::Config,
) -> io::Result<Payload> {
    let mut accounts = Vec::new();
    let mut seen = HashSet::new();
    if slots.is_empty() || slots.len() > 9 {
        return Err(error("Select at least one account"));
    }
    for &slot in slots {
        if slot > 8 || !seen.insert(slot) {
            return Err(error("Invalid account selection"));
        }
        let (path, name) = if slot == 0 {
            (directory.to_path_buf(), "Main account".into())
        } else {
            let path = config
                .paths
                .iter()
                .find(|p| p.profile_id == slot)
                .ok_or_else(|| error("Unknown account profile"))?;
            (
                directory
                    .join("aggregate-profiles")
                    .join(format!("path-{slot}")),
                path.name.clone(),
            )
        };
        if !path.is_dir() {
            return Err(error("Start this account profile first"));
        }
        let _lock = if slot == 0 {
            None
        } else {
            Some(
                crate::vault::lock_directory(&path)
                    .map_err(|_| error("Stop selected account profiles before exporting"))?,
            )
        };
        let mut config = Config::load(Some(&path))?;
        let vault = Vault::new(&path);
        let token = match vault.read("token.bin")? {
            Some(bytes) => {
                Some(String::from_utf8(bytes).map_err(|_| error("Invalid saved account session"))?)
            }
            None if !config.token.is_empty() => Some(config.token.clone()),
            None => None,
        };
        config.token.zeroize();
        config.aggregate = Default::default();
        let identity = vault
            .read("identity.bin")?
            .ok_or_else(|| error("Account identity is missing"))?;
        accounts.push(Entry {
            source: slot,
            name,
            config,
            token,
            identity,
            device: crate::device::identity(&path)?,
        });
    }
    Ok(Payload {
        format: FORMAT.into(),
        accounts,
    })
}
pub async fn accounts(State(s): State<Arc<AppState>>) -> Result<Json<Vec<Account>>, ApiError> {
    let directory = s.config_file.dir();
    let config = s.aggregate.config();
    let workers = s.aggregate.workers.snapshots();
    let mut list = Vec::new();
    for slot in 0..=8 {
        let (path, name) = if slot == 0 {
            (directory.to_path_buf(), "Main account".into())
        } else {
            let Some(p) = config.paths.iter().find(|p| p.profile_id == slot) else {
                continue;
            };
            (
                directory
                    .join("aggregate-profiles")
                    .join(format!("path-{slot}")),
                p.name.clone(),
            )
        };
        if !path.is_dir() {
            continue;
        }
        let cfg = Config::load(Some(&path)).map_err(api)?;
        list.push(Account {
            slot,
            name,
            mode: cfg.mode,
            has_session: path.join("token.bin").is_file() || !cfg.token.is_empty(),
            running: workers
                .iter()
                .any(|w| w.slot == usize::from(slot) && w.running),
        });
    }
    Ok(Json(list))
}
pub async fn export(
    State(s): State<Arc<AppState>>,
    Json(body): Json<Export>,
) -> Result<Json<Envelope>, ApiError> {
    let _guard = s
        .backup_job
        .try_lock()
        .map_err(|_| api("Another account transfer is in progress"))?;
    let _maintenance = s.aggregate.maintenance().await;
    let _auth = if body.slots.contains(&0) {
        Some(s.auth_flow.lock().await)
    } else {
        None
    };
    let directory = s.config_file.dir().to_owned();
    let config = s.aggregate.config();
    let password = Zeroizing::new(body.password);
    let value = tokio::task::spawn_blocking(move || {
        let payload = collect(&directory, &body.slots, &config)?;
        seal(&payload, &password)
    })
    .await
    .map_err(api)?
    .map_err(api)?;
    Ok(Json(value))
}
pub async fn preview(
    State(s): State<Arc<AppState>>,
    Json(body): Json<Import>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let _guard = s
        .backup_job
        .try_lock()
        .map_err(|_| api("Another account transfer is in progress"))?;
    let password = Zeroizing::new(body.password);
    let payload = tokio::task::spawn_blocking(move || open(body.archive, &password))
        .await
        .map_err(api)?
        .map_err(api)?;
    Ok(Json(
        serde_json::json!({"ok":true,"accounts":payload.accounts.iter().enumerate().map(|(index,e)|serde_json::json!({"index":index,"name":e.name,"mode":e.config.mode,"hasSession":e.token.is_some()})).collect::<Vec<_>>()}),
    ))
}
fn restore(
    directory: &Path,
    mut config: crate::aggregate::Config,
    payload: Payload,
    selection: Option<Vec<usize>>,
    file: &crate::config::ConfigFile,
    management_port: u16,
) -> io::Result<(crate::aggregate::Config, Vec<serde_json::Value>)> {
    let selected: HashSet<usize> = selection
        .unwrap_or_else(|| (0..payload.accounts.len()).collect())
        .into_iter()
        .collect();
    if selected.is_empty() || selected.iter().any(|&i| i >= payload.accounts.len()) {
        return Err(error("Select at least one valid account"));
    }
    let parent = directory.join("aggregate-profiles");
    std::fs::create_dir_all(&parent)?;
    let staging = tempfile::Builder::new()
        .prefix(".import-")
        .tempdir_in(&parent)?;
    let mut destinations = Vec::new();
    let mut result = Vec::new();
    let mut identities = HashSet::new();
    let mut sessions = HashSet::new();
    // Do not clone a local installation into a second live account.
    for slot in 0..=8 {
        let path = if slot == 0 {
            directory.to_path_buf()
        } else {
            parent.join(format!("path-{slot}"))
        };
        if path.is_dir() {
            if let Some(token) = Vault::new(&path).read("token.bin")? {
                let token = Zeroizing::new(token);
                sessions.insert(
                    ring::digest::digest(&ring::digest::SHA256, &token)
                        .as_ref()
                        .to_vec(),
                );
            }
            if let Some(bytes) = Vault::new(&path).read("identity.bin")? {
                let v: serde_json::Value = serde_json::from_slice(&bytes)?;
                identities.insert(v["certificate"].to_string());
            }
        }
    }
    let mut used: HashSet<u16> = config
        .paths
        .iter()
        .flat_map(|p| [p.port, p.management_port])
        .chain([management_port, config.listen_port])
        .collect();
    for (index, entry) in payload
        .accounts
        .iter()
        .enumerate()
        .filter(|(i, _)| selected.contains(i))
    {
        let value: serde_json::Value = serde_json::from_slice(&entry.identity)?;
        if !identities.insert(value["certificate"].to_string()) {
            return Err(error(
                "This account identity already exists on this installation",
            ));
        }
        if let Some(token) = &entry.token {
            if !sessions.insert(
                ring::digest::digest(&ring::digest::SHA256, token.as_bytes())
                    .as_ref()
                    .to_vec(),
            ) {
                return Err(error(
                    "This saved session already exists on this installation",
                ));
            }
        }
        let slot = (1..=8)
            .find(|slot| {
                !parent.join(format!("path-{slot}")).exists()
                    && !destinations.iter().any(|(id, _)| id == slot)
                    && config
                        .paths
                        .iter()
                        .find(|p| p.profile_id == *slot)
                        .is_none_or(|p| {
                            p.name == format!("Tunnel {slot}")
                                && p.port == 1080 + u16::from(*slot)
                                && p.management_port == 37200 + u16::from(*slot)
                                && p.weight == 1
                        })
            })
            .ok_or_else(|| error("Not enough unused account slots; maximum is eight"))?;
        let mut next_port = |preferred: u16| -> io::Result<u16> {
            let port = std::iter::once(preferred)
                .chain(45000..61000)
                .find(|p| {
                    !used.contains(p)
                        && std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, *p)).is_ok()
                })
                .ok_or_else(|| error("No free local account port"))?;
            used.insert(port);
            Ok(port)
        };
        let socks = next_port(1080 + u16::from(slot))?;
        let management = next_port(37200 + u16::from(slot))?;
        let target = staging.path().join(format!("path-{slot}"));
        std::fs::create_dir(&target)?;
        let vault = Vault::new(&target);
        vault.write("identity.bin", &entry.identity)?;
        vault.write("device.bin", &serde_json::to_vec(&entry.device)?)?;
        if let Some(token) = &entry.token {
            vault.write("token.bin", token.as_bytes())?;
        }
        let mut cfg = entry.config.clone();
        cfg.token.zeroize();
        cfg.aggregate = Default::default();
        cfg.port = management;
        cfg.socks5_port = socks;
        cfg.save(Some(&target))?;
        let identity = crate::settings::identity(&target)?;
        cfg.preferences.validate(&identity).map_err(api_to_io)?;
        let path = crate::aggregate::PathConfig {
            profile_id: slot,
            name: entry.name.clone(),
            port: socks,
            management_port: management,
            weight: 1,
        };
        if let Some(p) = config.paths.iter_mut().find(|p| p.profile_id == slot) {
            *p = path;
        } else {
            config.paths.push(path);
        }
        result.push(serde_json::json!({"index":index,"slot":slot,"name":entry.name,"sessionRestored":entry.token.is_some()}));
        destinations.push((slot, target));
    }
    config.validate(management_port)?;
    let mut installed = Vec::new();
    let commit = (|| {
        for (slot, source) in &destinations {
            let destination = parent.join(format!("path-{slot}"));
            if destination.exists() {
                return Err(error(
                    "Account destination changed; nothing was overwritten",
                ));
            }
            std::fs::rename(source, &destination)?;
            installed.push(destination);
        }
        file.update(|c| c.aggregate = config.clone())?;
        Ok(())
    })();
    if let Err(e) = commit {
        for path in installed {
            let _ = std::fs::remove_dir_all(path);
        }
        return Err(e);
    }
    Ok((config, result))
}
pub async fn import(
    State(s): State<Arc<AppState>>,
    Json(body): Json<Import>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let _guard = s
        .backup_job
        .try_lock()
        .map_err(|_| api("Another account transfer is in progress"))?;
    let _maintenance = s.aggregate.maintenance().await;
    if s.aggregate.snapshot().running || s.aggregate.workers.snapshots().iter().any(|w| w.running) {
        return Err(api(
            "Stop the pool and managed profiles before importing accounts",
        ));
    }
    let password = Zeroizing::new(body.password);
    let directory = s.config_file.dir().to_owned();
    let config = s.aggregate.config();
    let file = s.config_file.clone();
    let port = s.cfg.read().await.port;
    let (config, result) = tokio::task::spawn_blocking(move || {
        let payload = open(body.archive, &password)?;
        restore(&directory, config, payload, body.entries, &file, port)
    })
    .await
    .map_err(api)?
    .map_err(api)?;
    s.aggregate.imported_config(config);
    Ok(Json(
        serde_json::json!({"ok":true,"accounts":result,"requiresOtp":false}),
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encrypted_transfer_preserves_session_device_and_pairing_without_otp() {
        let source = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        let identity = crate::settings::identity(source.path()).unwrap();
        let device = crate::device::identity(source.path()).unwrap();
        let cfg = Config::default();
        cfg.save(Some(source.path())).unwrap();
        Vault::new(source.path())
            .write("token.bin", b"fixture-existing-session-not-a-real-token")
            .unwrap();
        let payload = collect(source.path(), &[0], &Default::default()).unwrap();
        let envelope = seal(&payload, "fixture-passphrase-123").unwrap();
        let raw = serde_json::to_string(&envelope).unwrap();
        assert!(!raw.contains("fixture-existing-session"));
        let decoded = open(envelope, "fixture-passphrase-123").unwrap();
        let file = crate::config::ConfigFile::new(target.path().to_owned());
        let (_, mapping) = restore(
            target.path(),
            Default::default(),
            decoded,
            None,
            &file,
            37126,
        )
        .unwrap();
        assert_eq!(mapping.len(), 1);
        let destination = target.path().join("aggregate-profiles/path-1");
        assert_eq!(
            Vault::new(&destination).read("token.bin").unwrap().unwrap(),
            b"fixture-existing-session-not-a-real-token"
        );
        use lk_signaling::TokenStore;
        let restored_store = crate::config::FileTokenStore::new(Arc::new(
            crate::config::ConfigFile::new(destination.clone()),
        ));
        assert_eq!(
            restored_store.load().unwrap(),
            b"fixture-existing-session-not-a-real-token"
        );
        assert_eq!(
            crate::settings::identity(&destination).unwrap().certificate,
            identity.certificate
        );
        assert_eq!(
            crate::device::identity(&destination).unwrap().hash,
            device.hash
        );
        let duplicate = open(
            serde_json::from_str(&raw).unwrap(),
            "fixture-passphrase-123",
        )
        .unwrap();
        assert!(restore(
            target.path(),
            file.load().aggregate,
            duplicate,
            None,
            &file,
            37126
        )
        .is_err());
        assert!(open(serde_json::from_str(&raw).unwrap(), "wrong-passphrase-123").is_err());
        let mut corrupt: Envelope = serde_json::from_str(&raw).unwrap();
        corrupt.nonce = "00".repeat(12);
        assert!(open(corrupt, "fixture-passphrase-123").is_err());
        if let Some(path) = std::env::var_os("BALEVPN_TEST_ARCHIVE_OUT") {
            std::fs::write(path, &raw).unwrap();
        }
    }
    #[test]
    fn selective_group_restore_and_capacity_failure_do_not_overwrite_accounts() {
        let source = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        let mut config = crate::aggregate::Config::default();
        for id in [1, 2] {
            let directory = source.path().join(format!("aggregate-profiles/path-{id}"));
            crate::settings::identity(&directory).unwrap();
            crate::device::identity(&directory).unwrap();
            let mut cfg = Config::default();
            cfg.mode = Some("client".into());
            cfg.peer_id = Some(format!("42{id}"));
            cfg.save(Some(&directory)).unwrap();
            Vault::new(&directory)
                .write(
                    "token.bin",
                    format!("fixture-session-for-account-{id}").as_bytes(),
                )
                .unwrap();
        }
        let payload = collect(source.path(), &[1, 2], &config).unwrap();
        let raw =
            serde_json::to_string(&seal(&payload, "fixture-passphrase-123").unwrap()).unwrap();
        let file = crate::config::ConfigFile::new(target.path().to_owned());
        let (_, result) = restore(
            target.path(),
            config.clone(),
            open(
                serde_json::from_str(&raw).unwrap(),
                "fixture-passphrase-123",
            )
            .unwrap(),
            Some(vec![1]),
            &file,
            37126,
        )
        .unwrap();
        assert_eq!(result.len(), 1);
        let account = target.path().join("aggregate-profiles/path-1");
        assert_eq!(
            Vault::new(&account).read("token.bin").unwrap().unwrap(),
            b"fixture-session-for-account-2"
        );
        assert_eq!(
            Config::load(Some(&account)).unwrap().peer_id.as_deref(),
            Some("422")
        );
        let before = crate::settings::identity(&account)
            .unwrap()
            .certificate
            .clone();
        for id in 2..=8 {
            std::fs::create_dir_all(target.path().join(format!("aggregate-profiles/path-{id}")))
                .unwrap();
        }
        config = file.load().aggregate;
        let old_config = std::fs::read(target.path().join(".bale-vpn_config.json")).unwrap();
        let error = restore(
            target.path(),
            config,
            open(
                serde_json::from_str(&raw).unwrap(),
                "fixture-passphrase-123",
            )
            .unwrap(),
            Some(vec![0]),
            &file,
            37126,
        )
        .unwrap_err();
        assert!(error.to_string().contains("Not enough"));
        assert_eq!(
            std::fs::read(target.path().join(".bale-vpn_config.json")).unwrap(),
            old_config
        );
        assert_eq!(
            crate::settings::identity(&account).unwrap().certificate,
            before
        );
    }
    #[test]
    fn optional_cross_os_archive_reencrypts_existing_session_for_this_os() {
        let Some(path) = std::env::var_os("BALEVPN_TEST_ARCHIVE_IN") else {
            return;
        };
        let envelope = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let payload = open(envelope, "fixture-passphrase-123").unwrap();
        let target = tempfile::tempdir().unwrap();
        let file = crate::config::ConfigFile::new(target.path().to_owned());
        restore(
            target.path(),
            Default::default(),
            payload,
            None,
            &file,
            37126,
        )
        .unwrap();
        assert_eq!(
            Vault::new(&target.path().join("aggregate-profiles/path-1"))
                .read("token.bin")
                .unwrap()
                .unwrap(),
            b"fixture-existing-session-not-a-real-token"
        );
    }
    #[test]
    fn restoring_accounts_preserves_preconfigured_external_paths() {
        let source = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        crate::settings::identity(source.path()).unwrap();
        Config::default().save(Some(source.path())).unwrap();
        let payload = collect(source.path(), &[0], &Default::default()).unwrap();
        let mut config = crate::aggregate::Config::default();
        config.paths[0].name = "Existing external tunnel".into();
        config.paths[0].port = 1080;
        let file = crate::config::ConfigFile::new(target.path().to_owned());
        let (next, result) = restore(target.path(), config, payload, None, &file, 37126).unwrap();
        assert_eq!(result[0]["slot"], 2);
        assert_eq!(next.paths[0].port, 1080);
        assert_eq!(next.paths[0].name, "Existing external tunnel");
    }
}
