//! Explicit retained-session test. Private JSON travels only through stdin.
//! No registration, OTP, account revocation, session file or secret argv/env.
use igap_signaling::{
    auth::{RegistrationProfile, SessionRecord},
    IgapSignaling,
};
use lk_signaling::{Signaling, TokenStore};
use parking_lot::Mutex;
use std::{io::Read, sync::Arc};
use zeroize::Zeroizing;

const LIMIT: u64 = 64 * 1024;
#[derive(Default)]
struct MemoryStore(Mutex<Option<Zeroizing<Vec<u8>>>>);
impl TokenStore for MemoryStore {
    fn load(&self) -> Option<Vec<u8>> {
        self.0.lock().as_ref().map(|value| value.to_vec())
    }
    fn save(&self, bytes: &[u8]) {
        *self.0.lock() = Some(Zeroizing::new(bytes.to_vec()));
    }
    fn clear(&self) {
        *self.0.lock() = None;
    }
}
fn requested(args: &[String]) -> bool {
    args == ["--restore-stdin"]
}
fn read_record(input: impl Read) -> Result<SessionRecord, ()> {
    let mut bytes = Zeroizing::new(Vec::new());
    input
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.is_empty() || bytes.len() > LIMIT as usize {
        return Err(());
    }
    let record: SessionRecord = serde_json::from_slice(&bytes).map_err(|_| ())?;
    record.validate().map_err(|_| ())?;
    Ok(record)
}
fn print_result(requested: bool, authenticated: bool, identity_matches: bool, retained: bool) {
    println!("{{\"restoreRequested\":{requested},\"authenticated\":{authenticated},\"identityMatches\":{identity_matches},\"storedSessionRetained\":{retained},\"otpRequested\":false}}");
}
#[tokio::main]
async fn main() -> std::process::ExitCode {
    if !requested(&std::env::args().skip(1).collect::<Vec<_>>()) {
        print_result(false, false, false, false);
        return std::process::ExitCode::SUCCESS;
    }
    let Ok(record) = read_record(std::io::stdin().lock()) else {
        print_result(true, false, false, false);
        return std::process::ExitCode::FAILURE;
    };
    let expected = Zeroizing::new(record.user_id.clone());
    let store = Arc::new(MemoryStore::default());
    let app = IgapSignaling::new(store.clone(), RegistrationProfile::Independent);
    let restored = app.restore(record).await.is_ok();
    let authenticated = restored && app.is_authenticated();
    let identity_matches = if authenticated {
        app.whoami()
            .await
            .is_some_and(|peer| peer.id_str() == expected.as_str())
    } else {
        false
    };
    let retained = store.0.lock().is_some();
    // This closes only our channel, preserving the service session/token.
    app.disconnect().await;
    print_result(true, authenticated, identity_matches, retained);
    if authenticated && identity_matches {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record() -> SessionRecord {
        SessionRecord {
            provider: "igap".into(),
            user_id: "41".into(),
            token: "fixture-private-token".into(),
            profile: igap_signaling::auth::Profile::new(RegistrationProfile::WebV3Compatibility),
            login_phone: String::new(),
            needs_profile: false,
        }
    }
    #[test]
    fn flag_is_exact_and_never_reads_implicitly() {
        assert!(!requested(&[]));
        assert!(!requested(&["--connect".into()]));
        assert!(!requested(&["--restore-stdin".into(), "secret".into()]));
        assert!(requested(&["--restore-stdin".into()]));
    }
    #[test]
    fn private_record_roundtrips_and_rejects_malformed_or_cross_provider() {
        let bytes = Zeroizing::new(serde_json::to_vec(&record()).unwrap());
        let value = read_record(bytes.as_slice()).unwrap();
        assert_eq!(
            value.profile.mode().unwrap(),
            RegistrationProfile::WebV3Compatibility
        );
        assert_eq!(value.user_id, "41");
        assert!(!format!("{value:?}").contains("fixture-private-token"));
        assert!(read_record(&b"private-invalid-json"[..]).is_err());
        let mut invalid = record();
        invalid.provider = "bale".into();
        assert!(read_record(serde_json::to_vec(&invalid).unwrap().as_slice()).is_err());
    }
    #[test]
    fn stdin_is_bounded_and_empty_input_fails() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Counting(Arc<AtomicUsize>);
        impl Read for Counting {
            fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
                self.0.fetch_add(out.len(), Ordering::Relaxed);
                out.fill(b' ');
                Ok(out.len())
            }
        }
        let count = Arc::new(AtomicUsize::new(0));
        assert!(read_record(Counting(count.clone())).is_err());
        assert_eq!(count.load(Ordering::Relaxed), (LIMIT + 1) as usize);
        assert!(read_record(&b""[..]).is_err());
    }
    #[test]
    fn memory_store_retains_only_private_zeroizing_records() {
        let store = MemoryStore::default();
        store.save(b"private-token");
        let bytes = Zeroizing::new(store.load().unwrap());
        assert_eq!(bytes.as_slice(), b"private-token");
        store.clear();
        assert!(store.load().is_none());
    }
}
