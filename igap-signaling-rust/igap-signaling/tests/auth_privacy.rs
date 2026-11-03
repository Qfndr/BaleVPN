//! Offline fixture only: no actual account, OTP, token or service connection.
use async_trait::async_trait;
use igap_signaling::{
    adapter::{Connector, IgapSignaling},
    auth::{Profile, RegistrationProfile, SessionRecord},
    rpc::{Response, Rpc},
    wire as w, Error,
};
use lk_signaling::{Signaling, TokenStore};
use parking_lot::Mutex;
use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
};
use tokio::sync::{mpsc, Notify};

#[derive(Default)]
struct Store {
    bytes: Mutex<Option<Vec<u8>>>,
    saves: AtomicU64,
}
impl TokenStore for Store {
    fn load(&self) -> Option<Vec<u8>> {
        self.bytes.lock().clone()
    }
    fn save(&self, bytes: &[u8]) {
        *self.bytes.lock() = Some(bytes.to_vec());
        self.saves.fetch_add(1, Ordering::AcqRel);
    }
    fn clear(&self) {
        *self.bytes.lock() = None;
    }
}
struct ScriptRpc {
    ready: AtomicBool,
    steps: Mutex<VecDeque<(u16, Result<Response, Error>)>>,
    calls: Mutex<Vec<u16>>,
    gate: Mutex<Option<(u16, Arc<Notify>, Arc<Notify>)>>,
}
#[async_trait]
impl Rpc for ScriptRpc {
    async fn request(&self, action: u16, _fields: Vec<u8>) -> Result<Response, Error> {
        if !self.ready() {
            return Err(Error::NotConnected);
        }
        self.calls.lock().push(action);
        let (expected, result) = self
            .steps
            .lock()
            .pop_front()
            .expect("unexpected fixture request");
        assert_eq!(action, expected);
        let gate = self.gate.lock().as_ref().filter(|g| g.0 == action).cloned();
        if let Some((_, entered, resume)) = gate {
            entered.notify_one();
            resume.notified().await;
        }
        result
    }
    async fn login(&self, fields: Vec<u8>) -> Result<Response, Error> {
        self.request(102, fields).await
    }
    fn ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }
    fn close(&self) {
        self.ready.store(false, Ordering::Release);
    }
}
struct FixedConnector {
    rpc: Arc<ScriptRpc>,
    rx: Mutex<Option<mpsc::Receiver<Response>>>,
    _push: mpsc::Sender<Response>,
}
#[async_trait]
impl Connector for FixedConnector {
    async fn open(&self) -> Result<(Arc<dyn Rpc>, mpsc::Receiver<Response>), Error> {
        Ok((
            self.rpc.clone(),
            self.rx.lock().take().ok_or(Error::Closed)?,
        ))
    }
}
fn n(field: u32, value: u64) -> Vec<u8> {
    w::uint_field(field, value).unwrap()
}
fn t(field: u32, value: &str) -> Vec<u8> {
    w::string_field(field, value, 20000).unwrap()
}
fn response(action: u16, fields: Vec<u8>) -> Result<Response, Error> {
    Ok(Response {
        action,
        fields: w::parse(&fields).unwrap(),
    })
}
fn register() -> Result<Response, Error> {
    response(
        30100,
        [
            t(2, "fixture-private-username"),
            n(3, 42),
            n(6, 60),
            n(9, 5),
        ]
        .concat(),
    )
}
fn verified(profile_required: bool) -> Result<Response, Error> {
    response(
        30101,
        [
            t(2, "fixture-private-token"),
            n(3, u64::from(profile_required)),
        ]
        .concat(),
    )
}
fn login(uid: u64) -> Result<Response, Error> {
    response(30102, n(14, uid))
}
fn fixture(
    steps: Vec<(u16, Result<Response, Error>)>,
) -> (IgapSignaling, Arc<ScriptRpc>, Arc<Store>) {
    let (tx, rx) = mpsc::channel(4);
    let rpc = Arc::new(ScriptRpc {
        ready: AtomicBool::new(true),
        steps: Mutex::new(steps.into()),
        calls: Mutex::new(Vec::new()),
        gate: Mutex::new(None),
    });
    let store = Arc::new(Store::default());
    let connector = Arc::new(FixedConnector {
        rpc: rpc.clone(),
        rx: Mutex::new(Some(rx)),
        _push: tx,
    });
    (
        IgapSignaling::with_connector(
            store.clone(),
            RegistrationProfile::WebV3Compatibility,
            connector,
        ),
        rpc,
        store,
    )
}
fn record() -> SessionRecord {
    SessionRecord {
        provider: "igap".into(),
        user_id: "42".into(),
        token: "fixture-private-token".into(),
        profile: Profile::new(RegistrationProfile::WebV3Compatibility),
        login_phone: "+989120000001".into(),
        needs_profile: false,
    }
}

#[tokio::test]
async fn profile_completion_precedes_advertising_a_usable_authenticated_session() {
    let (adapter, rpc, store) = fixture(vec![
        (100, register()),
        (101, verified(true)),
        (102, login(42)),
        (105, response(30105, Vec::new())),
    ]);
    let code = adapter
        .start("IR", "9120000001", "+989120000001", None)
        .await
        .unwrap();
    assert_eq!(code.digits, 5);
    let state = adapter.verify("12345").await.unwrap();
    assert_eq!(state.stage, "profile_required");
    assert!(!state.signed_in);
    assert!(!adapter.is_authenticated());
    assert_eq!(store.saves.load(Ordering::Acquire), 1);
    adapter.complete_profile(" Fixture ").await.unwrap();
    assert!(adapter.is_authenticated());
    assert_eq!(store.saves.load(Ordering::Acquire), 2);
    assert_eq!(*rpc.calls.lock(), [100, 101, 102, 105]);
    adapter.disconnect().await;
}

#[tokio::test]
async fn service_wait_blocks_resends_and_profile_switches_without_erasing_pending_code() {
    let (adapter, rpc, _) = fixture(vec![
        (100, register()),
        (
            101,
            Err(Error::Rejected {
                major: 199,
                minor: 0,
                wait_seconds: 120,
            }),
        ),
    ]);
    adapter
        .start("IR", "9120000001", "+989120000001", None)
        .await
        .unwrap();
    assert!(matches!(
        adapter.verify("12345").await,
        Err(Error::Rejected {
            wait_seconds: 120,
            ..
        })
    ));
    assert_eq!(adapter.state().stage, "code");
    assert!(adapter.state().retry_after >= 119);
    assert!(matches!(
        adapter
            .start(
                "IR",
                "9120000001",
                "+989120000001",
                Some(RegistrationProfile::Independent)
            )
            .await,
        Err(Error::Busy)
    ));
    assert_eq!(
        adapter.state().profile,
        RegistrationProfile::WebV3Compatibility
    );
    assert_eq!(*rpc.calls.lock(), [100, 101]);
    adapter.disconnect().await;
    let (adapter, rpc, _) = fixture(vec![(
        100,
        Err(Error::Rejected {
            major: 199,
            minor: 0,
            wait_seconds: 120,
        }),
    )]);
    assert!(adapter
        .start("IR", "9120000001", "+989120000001", None)
        .await
        .is_err());
    assert!(adapter.state().retry_after >= 119);
    assert!(adapter
        .start("IR", "9120000001", "+989120000001", None)
        .await
        .is_err());
    assert_eq!(*rpc.calls.lock(), [100]);
    adapter.disconnect().await;
}

#[tokio::test]
async fn failed_identity_verification_and_wrong_action_cannot_overwrite_a_saved_session() {
    let (adapter, rpc, store) = fixture(vec![(102, login(43))]);
    let existing = b"fixture-existing-encrypted-record".to_vec();
    *store.bytes.lock() = Some(existing.clone());
    assert!(adapter.restore(record()).await.is_err());
    assert!(!adapter.is_authenticated());
    assert_eq!(*store.bytes.lock(), Some(existing));
    assert_eq!(store.saves.load(Ordering::Acquire), 0);
    assert_eq!(*rpc.calls.lock(), [102]);
    adapter.disconnect().await;
    let (adapter, rpc, store) = fixture(vec![
        (100, register()),
        (101, response(30132, t(2, "fixture-private-token"))),
    ]);
    adapter
        .start("IR", "9120000001", "+989120000001", None)
        .await
        .unwrap();
    assert!(adapter.verify("12345").await.is_err());
    assert_eq!(store.saves.load(Ordering::Acquire), 0);
    assert_eq!(*rpc.calls.lock(), [100, 101]);
    adapter.disconnect().await;
}

#[tokio::test]
async fn privacy_changes_only_denied_call_rules_and_requires_strict_readback() {
    let privacy_reply = |kind, level| response(30143, [n(2, kind), n(3, level)].concat());
    let (adapter, rpc, _) = fixture(vec![
        (102, login(42)),
        (143, privacy_reply(4, 1)),
        (143, privacy_reply(5, 0)),
        (144, response(30144, n(2, 4))),
        (143, privacy_reply(4, 0)),
        (143, privacy_reply(5, 0)),
    ]);
    adapter.restore(record()).await.unwrap();
    assert!(adapter
        .ensure_call_privacy_everyone()
        .await
        .unwrap()
        .everyone());
    assert_eq!(*rpc.calls.lock(), [102, 143, 143, 144, 143, 143]);
    adapter.disconnect().await;
    let (adapter, rpc, _) = fixture(vec![(102, login(42)), (143, response(30143, Vec::new()))]);
    adapter.restore(record()).await.unwrap();
    assert!(adapter.ensure_call_privacy_everyone().await.is_err());
    assert_eq!(*rpc.calls.lock(), [102, 143]);
    adapter.disconnect().await;
}

#[tokio::test]
async fn disconnect_during_privacy_read_blocks_later_mutation_and_parallel_flows() {
    let (adapter, rpc, _) = fixture(vec![
        (102, login(42)),
        (143, response(30143, [n(2, 4), n(3, 1)].concat())),
    ]);
    adapter.restore(record()).await.unwrap();
    let entered = Arc::new(Notify::new());
    let resume = Arc::new(Notify::new());
    *rpc.gate.lock() = Some((143, entered.clone(), resume.clone()));
    let task = {
        let adapter = adapter.clone();
        tokio::spawn(async move { adapter.ensure_call_privacy_everyone().await })
    };
    entered.notified().await;
    assert!(matches!(
        adapter.read_call_privacy().await,
        Err(Error::Busy)
    ));
    adapter.disconnect().await;
    resume.notify_one();
    assert!(task.await.unwrap().is_err());
    assert_eq!(*rpc.calls.lock(), [102, 143]);
}
