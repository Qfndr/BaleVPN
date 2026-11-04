//! Separate encrypted credential purpose for native iGap accounts. Never reads
//! or migrates Bale's token.bin or configuration.
use crate::{
    provider_config::{Config, IgapSessionEnvelope},
    vault::{private_write, Vault},
};
use igap_signaling::auth::SessionRecord;
use lk_signaling::TokenStore;
use parking_lot::Mutex;
use std::{
    io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};
use zeroize::Zeroizing;
const SESSION: &str = "igap-session.bin";
const MAX_SESSION: usize = 64 * 1024;
fn invalid() -> io::Error {
    io::Error::other("invalid_provider_session")
}
pub struct Store {
    directory: PathBuf,
    vault: Vault,
    cache: Mutex<Option<Zeroizing<Vec<u8>>>>,
    pending: Mutex<Option<Zeroizing<Vec<u8>>>>,
    failed: AtomicBool,
    write_lock: Mutex<()>,
}
impl Store {
    pub fn identity(&self) -> io::Result<std::sync::Arc<lktunnel::security::Identity>> {
        #[derive(serde::Serialize, serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct StoredIdentity {
            certificate: Vec<u8>,
            private_key: Vec<u8>,
        }
        let name = "igap-identity.bin";
        let stored = match self.vault.read(name)? {
            Some(bytes) => {
                let bytes = Zeroizing::new(bytes);
                if bytes.len() > 128 * 1024 {
                    return Err(invalid());
                }
                serde_json::from_slice::<StoredIdentity>(&bytes).map_err(|_| invalid())?
            }
            None => {
                let identity = lktunnel::security::Identity::generate().map_err(|_| invalid())?;
                let stored = StoredIdentity {
                    certificate: identity.certificate,
                    private_key: identity.private_key,
                };
                let bytes = Zeroizing::new(serde_json::to_vec(&stored).map_err(|_| invalid())?);
                self.vault.write(name, &bytes)?;
                stored
            }
        };
        if stored.certificate.is_empty()
            || stored.certificate.len() > 8192
            || stored.private_key.is_empty()
            || stored.private_key.len() > 16384
        {
            return Err(invalid());
        }
        let identity = lktunnel::security::Identity {
            certificate: stored.certificate,
            private_key: stored.private_key,
        };
        identity.options(&[], true, false).map_err(|_| invalid())?;
        Ok(std::sync::Arc::new(identity))
    }
    pub fn open(directory: &Path) -> io::Result<Self> {
        let vault = Vault::new(directory);
        if std::fs::metadata(directory.join(SESSION)).is_ok_and(|m| m.len() > 200_000) {
            return Err(invalid());
        }
        let cache = match vault.read(SESSION)? {
            None => None,
            Some(bytes) => {
                let bytes = Zeroizing::new(bytes);
                if bytes.len() > MAX_SESSION {
                    return Err(invalid());
                }
                let envelope: IgapSessionEnvelope =
                    serde_json::from_slice(&bytes).map_err(|_| invalid())?;
                Some(Zeroizing::new(
                    serde_json::to_vec(&envelope.record).map_err(|_| invalid())?,
                ))
            }
        };
        Ok(Self {
            directory: directory.to_owned(),
            vault,
            cache: Mutex::new(cache),
            pending: Mutex::new(None),
            failed: AtomicBool::new(false),
            write_lock: Mutex::new(()),
        })
    }
    pub fn record(&self) -> io::Result<Option<SessionRecord>> {
        let pending = self.pending.lock();
        if let Some(bytes) = pending.as_ref() {
            return serde_json::from_slice(bytes)
                .map(Some)
                .map_err(|_| invalid());
        }
        self.cache
            .lock()
            .as_ref()
            .map(|bytes| serde_json::from_slice(bytes).map_err(|_| invalid()))
            .transpose()
    }
    pub fn save_record(&self, record: SessionRecord) -> io::Result<()> {
        let _write = self.write_lock.lock();
        let envelope = IgapSessionEnvelope::new(record).map_err(|_| invalid())?;
        let bytes = Zeroizing::new(serde_json::to_vec(&envelope).map_err(|_| invalid())?);
        if bytes.len() > MAX_SESSION {
            return Err(invalid());
        }
        let raw = Zeroizing::new(serde_json::to_vec(&envelope.record).map_err(|_| invalid())?);
        *self.pending.lock() = Some(raw);
        if let Err(error) = self.vault.write(SESSION, &bytes) {
            self.failed.store(true, Ordering::Release);
            return Err(error);
        }
        let saved = self.pending.lock().take();
        *self.cache.lock() = saved;
        self.failed.store(false, Ordering::Release);
        Ok(())
    }
    pub fn failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }
    pub fn retry_pending(&self) -> io::Result<()> {
        let bytes = self
            .pending
            .lock()
            .as_ref()
            .map(|v| Zeroizing::new(v.to_vec()))
            .ok_or_else(invalid)?;
        let record = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        self.save_record(record)
    }
    pub fn config(&self) -> io::Result<Config> {
        let path = self.directory.join("config.json");
        if !path.exists() {
            return Ok(Config::default());
        }
        let data = std::fs::read(path)?;
        if data.len() > 128 * 1024 {
            return Err(io::Error::other("invalid_provider_config"));
        }
        serde_json::from_slice(&data).map_err(|_| io::Error::other("invalid_provider_config"))
    }
    pub fn save_config(&self, value: &Config) -> io::Result<()> {
        value
            .validate()
            .map_err(|_| io::Error::other("invalid_provider_config"))?;
        private_write(
            &self.directory.join("config.json"),
            &serde_json::to_vec_pretty(value)?,
        )
    }
    pub fn appearance(&self) -> io::Result<serde_json::Value> {
        let path = self.directory.join("appearance.json");
        if !path.exists() {
            return Ok(serde_json::Value::Null);
        }
        use std::io::Read;
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take(4097)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 4096 {
            return Err(io::Error::other("invalid_appearance"));
        }
        let value =
            serde_json::from_slice(&bytes).map_err(|_| io::Error::other("invalid_appearance"))?;
        crate::appearance::validate(&value).map_err(io::Error::other)?;
        Ok(value)
    }
    pub fn save_appearance(&self, value: &serde_json::Value) -> io::Result<()> {
        crate::appearance::validate(value).map_err(io::Error::other)?;
        let bytes = serde_json::to_vec(value)?;
        if bytes.len() > 4096 {
            return Err(io::Error::other("invalid_appearance"));
        }
        private_write(&self.directory.join("appearance.json"), &bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record(token: &str) -> SessionRecord {
        SessionRecord {
            provider: "igap".into(),
            user_id: "41".into(),
            token: token.into(),
            profile: igap_signaling::auth::Profile::default(),
            login_phone: String::new(),
            needs_profile: false,
        }
    }
    #[test]
    fn provider_store_is_sealed_and_preserves_other_provider_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("token.bin"), b"existing-bale-token").unwrap();
        std::fs::write(dir.path().join("identity.bin"), b"existing-bale-identity").unwrap();
        let store = Store::open(dir.path()).unwrap();
        let identity = store.identity().unwrap();
        store.save_record(record("fixture-private-token")).unwrap();
        let bytes = std::fs::read(dir.path().join(SESSION)).unwrap();
        assert!(!bytes.windows(21).any(|w| w == b"fixture-private-token"));
        assert_eq!(
            std::fs::read(dir.path().join("token.bin")).unwrap(),
            b"existing-bale-token"
        );
        let reopened = Store::open(dir.path()).unwrap();
        assert_eq!(
            reopened.identity().unwrap().certificate,
            identity.certificate
        );
        assert_eq!(
            std::fs::read(dir.path().join("identity.bin")).unwrap(),
            b"existing-bale-identity"
        );
        assert_eq!(
            reopened.record().unwrap().unwrap().token,
            "fixture-private-token"
        );
        let config = Config { relay_only: true, ..Config::default() };
        store.save_config(&config).unwrap();
        assert_eq!(store.config().unwrap().socks5_port, 18080);
        assert!(Store::open(dir.path()).unwrap().config().unwrap().relay_only);
    }
    #[test]
    fn failed_rotation_keeps_private_pending_record_for_local_retry() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        store.save_record(record("fixture-original")).unwrap();
        let path = dir.path().join(SESSION);
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(store.save_record(record("fixture-rotated")).is_err());
        assert!(store.failed());
        assert_eq!(store.record().unwrap().unwrap().token, "fixture-rotated");
        let loaded: SessionRecord = serde_json::from_slice(&store.load().unwrap()).unwrap();
        assert_eq!(loaded.token, "fixture-original");
        std::fs::remove_dir(&path).unwrap();
        store.retry_pending().unwrap();
        assert!(!store.failed());
        assert_eq!(
            Store::open(dir.path())
                .unwrap()
                .record()
                .unwrap()
                .unwrap()
                .token,
            "fixture-rotated"
        );
    }
}
impl TokenStore for Store {
    fn load(&self) -> Option<Vec<u8>> {
        self.cache.lock().as_ref().map(|v| v.to_vec())
    }
    fn save(&self, bytes: &[u8]) {
        let result = (|| {
            if bytes.len() > MAX_SESSION {
                return Err(invalid());
            }
            let record: SessionRecord = serde_json::from_slice(bytes).map_err(|_| invalid())?;
            self.save_record(record)
        })();
        if result.is_err() {
            self.failed.store(true, Ordering::Release);
        }
    }
    fn clear(&self) {
        let _write = self.write_lock.lock();
        if self.vault.clear(SESSION).is_ok() {
            *self.cache.lock() = None;
            *self.pending.lock() = None;
            self.failed.store(false, Ordering::Release);
        } else {
            self.failed.store(true, Ordering::Release);
        }
    }
}
