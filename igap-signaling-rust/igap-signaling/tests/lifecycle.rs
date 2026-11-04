use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use igap_signaling::{
    adapter::{Connector, IgapSignaling},
    auth::{Profile, RegistrationProfile, SessionRecord},
    rpc::{Response, Rpc},
    wire as w, Error,
};
use lk_signaling::{CallDecision, IncomingHandler, PeerId, Signaling, TokenStore, TunnelHooks};
use parking_lot::Mutex;
use std::{
    sync::{
        atomic::{AtomicBool, AtomicU16, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::{mpsc, Notify};
#[derive(Default)]
struct Store(Mutex<Option<Vec<u8>>>);
impl TokenStore for Store {
    fn load(&self) -> Option<Vec<u8>> {
        self.0.lock().clone()
    }
    fn save(&self, b: &[u8]) {
        *self.0.lock() = Some(b.to_vec())
    }
    fn clear(&self) {
        *self.0.lock() = None;
    }
}
struct Mock {
    ready: AtomicBool,
    calls: Mutex<Vec<u16>>,
    push: mpsc::Sender<Response>,
    defer_self: AtomicBool,
    leave_timeout: AtomicBool,
    leave_rejected: AtomicBool,
    release_leave: Notify,
    block_action: AtomicU16,
    release_action: Notify,
}
fn response(action: u16, b: Vec<u8>) -> Response {
    Response {
        action,
        fields: w::parse(&b).unwrap(),
    }
}
fn token(room: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!(
        "header.{}.signature",
        URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(
                &serde_json::json!({"sub":"41","video":{"room":room,"roomJoin":true},"exp":now+600})
            )
            .unwrap()
        )
    )
}
fn joined(room: &str) -> Response {
    let mut b = w::string_field(2, &token(room), 16384).unwrap();
    b.extend(w::uint_field(3, 41).unwrap());
    response(30914, b)
}
#[async_trait]
impl Rpc for Mock {
    async fn request(&self, action: u16, _: Vec<u8>) -> Result<Response, Error> {
        self.calls.lock().push(action);
        if self.block_action.load(Ordering::Acquire) == action {
            self.release_action.notified().await;
        }
        let body = match action {
            100 => {
                let mut b = w::string_field(2, "private-username", 256).unwrap();
                b.extend(w::uint_field(3, 41).unwrap());
                b.extend(w::uint_field(9, 5).unwrap());
                b.extend(w::uint_field(6, 60).unwrap());
                b
            }
            101 => w::string_field(2, "private-session-token", 16384).unwrap(),
            913 => w::uint_field(2, 99).unwrap(),
            915 => {
                let mut b = w::uint_field(2, 41).unwrap();
                b.extend(w::uint_field(3, 99).unwrap());
                b
            }
            918 if self.leave_timeout.load(Ordering::Relaxed) => {
                self.release_leave.notified().await;
                return Err(if self.leave_rejected.load(Ordering::Relaxed) {
                    Error::Rejected {
                        major: 4,
                        minor: 1,
                        wait_seconds: 0,
                    }
                } else {
                    Error::Timeout
                });
            }
            916 | 918 => w::uint_field(2, 41).unwrap(),
            914 => {
                if self.defer_self.load(Ordering::Relaxed) {
                    self.push
                        .send(response(30918, w::uint_field(2, 41).unwrap()))
                        .await
                        .unwrap();
                    for _ in 0..10 {
                        tokio::task::yield_now().await;
                    }
                }
                return Ok(joined("99"));
            }
            _ => return Err(Error::NotSupported),
        };
        Ok(response(action + 30000, body))
    }
    async fn login(&self, _: Vec<u8>) -> Result<Response, Error> {
        self.calls.lock().push(102);
        Ok(response(30102, w::uint_field(14, 41).unwrap()))
    }
    fn ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }
    fn close(&self) {
        self.ready.store(false, Ordering::Release);
    }
}
struct Factory {
    rpc: Arc<Mock>,
    rx: Mutex<Option<mpsc::Receiver<Response>>>,
}
#[async_trait]
impl Connector for Factory {
    async fn open(&self) -> Result<(Arc<dyn Rpc>, mpsc::Receiver<Response>), Error> {
        Ok((
            self.rpc.clone(),
            self.rx.lock().take().ok_or(Error::Closed)?,
        ))
    }
}
fn fixture() -> (IgapSignaling, Arc<Mock>, Arc<Store>) {
    let (tx, rx) = mpsc::channel(64);
    let rpc = Arc::new(Mock {
        ready: AtomicBool::new(true),
        calls: Mutex::new(vec![]),
        push: tx,
        defer_self: AtomicBool::new(false),
        leave_timeout: AtomicBool::new(false),
        leave_rejected: AtomicBool::new(false),
        release_leave: Notify::new(),
        block_action: AtomicU16::new(0),
        release_action: Notify::new(),
    });
    let store = Arc::new(Store::default());
    let app = IgapSignaling::with_connector(
        store.clone(),
        RegistrationProfile::Independent,
        Arc::new(Factory {
            rpc: rpc.clone(),
            rx: Mutex::new(Some(rx)),
        }),
    );
    (app, rpc, store)
}
fn record() -> SessionRecord {
    SessionRecord {
        provider: "igap".into(),
        user_id: "41".into(),
        token: "private-session-token".into(),
        profile: Profile::new(RegistrationProfile::WebV3Compatibility),
        login_phone: "+989120000001".into(),
        needs_profile: false,
    }
}
async fn wait_call(rpc: &Mock, action: u16) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while !rpc.calls.lock().contains(&action) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn auth_profiles_restore_without_registration_and_contacts_are_explicitly_unsupported() {
    let (app, rpc, store) = fixture();
    app.restore(record()).await.unwrap();
    assert!(app.is_authenticated());
    app.connect().await.unwrap();
    app.connect().await.unwrap();
    assert_eq!(rpc.calls.lock().as_slice(), &[102]);
    assert!(store.load().is_some());
    assert_eq!(app.state().profile, RegistrationProfile::WebV3Compatibility);
    assert!(matches!(
        app.list_contacts(None, None, 20).await,
        Err(lk_signaling::SignalingError::NotSupported)
    ));
    let a = app.resolve_peer("42").await.unwrap();
    let b = app.resolve_peer("42").await.unwrap();
    assert_eq!(a, b);
    app.disconnect().await;
    assert!(!app.is_authenticated());
    assert!(store.load().is_some());
    app.sign_out().await;
    assert!(store.load().is_none());
}
#[tokio::test]
async fn explicit_registration_honors_cooldown_and_seals_only_successful_login() {
    let (app, rpc, store) = fixture();
    let request = app
        .start(
            "IR",
            "9120000001",
            "+989120000001",
            Some(RegistrationProfile::WebV3Compatibility),
        )
        .await
        .unwrap();
    assert_eq!(request.digits, 5);
    assert!(store.load().is_none());
    assert_eq!(
        app.start("IR", "9120000001", "+989120000001", None)
            .await
            .unwrap_err(),
        Error::Busy
    );
    app.verify("12345").await.unwrap();
    assert!(app.is_authenticated());
    assert!(store.load().is_some());
    assert_eq!(rpc.calls.lock().as_slice(), &[100, 101, 102]);
    app.disconnect().await;
}
#[tokio::test]
async fn caller_uses_bound_push_once_and_preserves_websocket_on_manager_deactivate() {
    let (app, rpc, _) = fixture();
    app.restore(record()).await.unwrap();
    app.set_allowed_peers(&["42".into()]).unwrap();
    let peer = app.resolve_peer("42").await.unwrap();
    let worker = app.clone();
    let task = tokio::spawn(async move { worker.place_call(peer).await });
    wait_call(&rpc, 915).await;
    rpc.push.send(joined("100")).await.unwrap();
    tokio::task::yield_now().await;
    assert!(!task.is_finished());
    rpc.push.send(joined("99")).await.unwrap();
    let session = task.await.unwrap().unwrap();
    assert_eq!(session.url, "wss://call.igap.net/");
    assert_eq!(session.token, token("99"));
    assert!(!rpc.calls.lock().contains(&914));
    app.deactivate();
    assert!(app.is_connected());
    app.disconnect().await;
}
struct Accept;
struct Ignore;
#[async_trait]
impl IncomingHandler for Ignore {
    async fn decide(&self, _: PeerId, _: Option<String>) -> CallDecision {
        CallDecision::SilentlyIgnore
    }
}
#[tokio::test]
async fn replacing_handler_revokes_inflight_accept_before_or_after_join_rpc() {
    for delayed in [916, 914] {
        let (app, rpc, _) = fixture();
        app.restore(record()).await.unwrap();
        app.set_allowed_peers(&["42".into()]).unwrap();
        app.set_incoming_handler(Box::new(Accept));
        let mut accepted = app.accepted_sessions();
        let mut events = app.events();
        rpc.block_action.store(delayed, Ordering::Release);
        let incoming = [w::uint_field(2, 42).unwrap(), w::uint_field(3, 99).unwrap()].concat();
        rpc.push.send(response(30915, incoming)).await.unwrap();
        wait_call(&rpc, delayed).await;
        // The decision has already returned Accept; revoking only the handler's
        // future decisions cannot protect this suspended protocol operation.
        app.set_incoming_handler(Box::new(Ignore));
        rpc.leave_timeout.store(true, Ordering::Release);
        rpc.release_leave.notify_one();
        assert_eq!(app.hang_up().await, Err(Error::Timeout));
        assert!(app.set_allowed_peers(&[]).is_err());
        rpc.release_action.notify_one();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if matches!(
                    events.recv().await,
                    Some(lk_signaling::SignalingEvent::CallEnded { .. })
                ) {
                    break;
                }
            }
        })
        .await
        .unwrap();
        assert!(accepted.try_recv().is_err());
        if delayed == 916 {
            assert!(!rpc.calls.lock().contains(&914));
        }
        assert!(app.set_allowed_peers(&[]).is_ok());
        app.disconnect().await;
    }
}
#[async_trait]
impl IncomingHandler for Accept {
    async fn decide(&self, _: PeerId, _: Option<String>) -> CallDecision {
        CallDecision::Accept
    }
}
#[tokio::test]
async fn receiver_requires_allowed_peer_and_explicit_handler_and_defers_only_join_selfleave() {
    let (app, rpc, _) = fixture();
    app.restore(record()).await.unwrap();
    let mut events = app.events();
    let mut accepted = app.accepted_sessions();
    let mut b = w::uint_field(2, 42).unwrap();
    b.extend(w::uint_field(3, 99).unwrap());
    rpc.push.send(response(30915, b.clone())).await.unwrap();
    tokio::task::yield_now().await;
    assert!(!rpc.calls.lock().contains(&916));
    app.set_allowed_peers(&["42".into()]).unwrap();
    app.set_incoming_handler(Box::new(Accept));
    rpc.defer_self.store(true, Ordering::Relaxed);
    rpc.push.send(response(30915, b)).await.unwrap();
    let (_, session) = tokio::time::timeout(Duration::from_secs(2), accepted.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(session.peer_id.id_str(), "42");
    assert_eq!(session.token, token("99"));
    assert_eq!(rpc.calls.lock().iter().filter(|a| **a == 914).count(), 1);
    assert!(
        events.try_recv().is_err(),
        "deferred own leave must not queue false CallEnded"
    );
    let diagnostic = app.service_leave_diagnostic().unwrap();
    assert_eq!(
        (diagnostic.actor, diagnostic.phase, diagnostic.deferred),
        ("self", "joining", true)
    );
    app.disconnect().await;
}
#[tokio::test]
async fn concurrent_call_rejection_does_not_cancel_the_owned_call() {
    let (app, rpc, _) = fixture();
    app.restore(record()).await.unwrap();
    app.set_allowed_peers(&["42".into()]).unwrap();
    let peer = app.resolve_peer("42").await.unwrap();
    let first = app.clone();
    let task = tokio::spawn({
        let peer = peer.clone();
        async move { first.place_call(peer).await }
    });
    wait_call(&rpc, 915).await;
    assert!(app.place_call(peer).await.is_err());
    rpc.push.send(joined("99")).await.unwrap();
    assert!(task.await.unwrap().is_ok());
    app.disconnect().await;
}
#[tokio::test]
async fn disconnect_cancels_pending_call_and_cross_account_peer_handles_are_rejected() {
    let (app, rpc, _) = fixture();
    let (other, _, _) = fixture();
    app.restore(record()).await.unwrap();
    app.set_allowed_peers(&["42".into()]).unwrap();
    let alien = other.resolve_peer("42").await.unwrap();
    assert!(app.place_call(alien).await.is_err());
    let peer = app.resolve_peer("42").await.unwrap();
    let worker = app.clone();
    let task = tokio::spawn(async move { worker.place_call(peer).await });
    wait_call(&rpc, 915).await;
    app.disconnect().await;
    assert!(task.await.unwrap().is_err());
    assert!(!app.is_connected());
}

#[tokio::test]
async fn dropping_a_pending_dial_cannot_leave_a_credential_owner_or_block_the_next_call() {
    let (app, rpc, _) = fixture();
    app.restore(record()).await.unwrap();
    app.set_allowed_peers(&["42".into()]).unwrap();
    let peer = app.resolve_peer("42").await.unwrap();
    let first = app.clone();
    let task = tokio::spawn({
        let peer = peer.clone();
        async move { first.place_call(peer).await }
    });
    wait_call(&rpc, 915).await;
    task.abort();
    assert!(matches!(task.await,Err(error) if error.is_cancelled()));
    let previous = rpc.calls.lock().iter().filter(|a| **a == 915).count();
    let worker = app.clone();
    let next = tokio::spawn(async move { worker.place_call(peer).await });
    tokio::time::timeout(Duration::from_secs(2), async {
        while rpc.calls.lock().iter().filter(|a| **a == 915).count() == previous {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    rpc.push.send(joined("99")).await.unwrap();
    assert!(next.await.unwrap().is_ok());
    app.disconnect().await;
}

async fn joined_fixture() -> (IgapSignaling, Arc<Mock>) {
    let (app, rpc, _) = fixture();
    app.restore(record()).await.unwrap();
    app.set_allowed_peers(&["42".into()]).unwrap();
    let peer = app.resolve_peer("42").await.unwrap();
    let worker = app.clone();
    let task = tokio::spawn(async move { worker.place_call(peer).await });
    wait_call(&rpc, 915).await;
    rpc.push.send(joined("99")).await.unwrap();
    task.await.unwrap().unwrap();
    (app, rpc)
}
async fn push_leave(app: &IgapSignaling, rpc: &Mock, actor: u64) {
    let mut events = app.events();
    rpc.push
        .send(response(30918, w::uint_field(2, actor).unwrap()))
        .await
        .unwrap();
    if actor == 41 || actor == 42 {
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(2), events.recv())
                .await
                .unwrap(),
            Some(lk_signaling::SignalingEvent::CallEnded { .. })
        ));
    }
}
#[tokio::test]
async fn matched_service_leave_confirms_timeout_without_duplicate_end_event() {
    for actor in [41, 42] {
        let (app, rpc) = joined_fixture().await;
        let mut events = app.events();
        rpc.leave_timeout.store(true, Ordering::Relaxed);
        let worker = app.clone();
        let task = tokio::spawn(async move { worker.hang_up().await });
        wait_call(&rpc, 918).await;
        push_leave(&app, &rpc, actor).await;
        rpc.release_leave.notify_one();
        task.await.unwrap().unwrap();
        assert!(matches!(
            events.recv().await,
            Some(lk_signaling::SignalingEvent::CallEnded { .. })
        ));
        assert!(events.try_recv().is_err());
        assert!(app.is_authenticated());
        assert_eq!(app.hang_up().await, Err(Error::InvalidInput));
        app.disconnect().await;
    }
}
#[tokio::test]
async fn unmatched_leave_and_absent_leave_do_not_swallow_timeout() {
    for actor in [0, 43] {
        let (app, rpc) = joined_fixture().await;
        rpc.leave_timeout.store(true, Ordering::Relaxed);
        let worker = app.clone();
        let task = tokio::spawn(async move { worker.hang_up().await });
        wait_call(&rpc, 918).await;
        if actor != 0 {
            push_leave(&app, &rpc, actor).await;
        }
        rpc.release_leave.notify_one();
        assert_eq!(task.await.unwrap(), Err(Error::Timeout));
        rpc.leave_timeout.store(false, Ordering::Relaxed);
        app.hang_up().await.unwrap();
        app.disconnect().await;
    }
}
#[tokio::test]
async fn matched_leave_cannot_confirm_after_channel_disconnect() {
    let (app, rpc) = joined_fixture().await;
    rpc.leave_timeout.store(true, Ordering::Relaxed);
    let worker = app.clone();
    let task = tokio::spawn(async move { worker.hang_up().await });
    wait_call(&rpc, 918).await;
    push_leave(&app, &rpc, 42).await;
    app.disconnect().await;
    rpc.release_leave.notify_one();
    assert_eq!(task.await.unwrap(), Err(Error::Cancelled));
}
#[tokio::test]
async fn matched_leave_does_not_touch_a_new_incoming_call() {
    let (app, rpc) = joined_fixture().await;
    app.set_incoming_handler(Box::new(Accept));
    let mut accepted = app.accepted_sessions();
    rpc.leave_timeout.store(true, Ordering::Relaxed);
    let worker = app.clone();
    let task = tokio::spawn(async move { worker.hang_up().await });
    wait_call(&rpc, 918).await;
    push_leave(&app, &rpc, 42).await;
    let mut incoming = w::uint_field(2, 42).unwrap();
    incoming.extend(w::uint_field(3, 99).unwrap());
    rpc.push.send(response(30915, incoming)).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), accepted.recv())
        .await
        .unwrap()
        .unwrap();
    rpc.release_leave.notify_one();
    assert_eq!(task.await.unwrap(), Err(Error::Cancelled));
    rpc.leave_timeout.store(false, Ordering::Relaxed);
    app.hang_up().await.unwrap();
    app.disconnect().await;
}

#[tokio::test]
async fn matched_service_leave_does_not_mask_service_rejection() {
    let (app, rpc) = joined_fixture().await;
    rpc.leave_timeout.store(true, Ordering::Relaxed);
    rpc.leave_rejected.store(true, Ordering::Relaxed);
    let worker = app.clone();
    let task = tokio::spawn(async move { worker.hang_up().await });
    wait_call(&rpc, 918).await;
    push_leave(&app, &rpc, 42).await;
    rpc.release_leave.notify_one();
    assert_eq!(
        task.await.unwrap(),
        Err(Error::Rejected {
            major: 4,
            minor: 1,
            wait_seconds: 0
        })
    );
    app.disconnect().await;
}
