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
        atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering},
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
    join_order: AtomicU64,
    leave_timeout: AtomicBool,
    leave_rejected: AtomicBool,
    release_leave: Notify,
    block_action: AtomicU16,
    release_action: Notify,
}
fn response(action: u16, b: Vec<u8>) -> Response {
    Response {
        received_order: None,
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
                let mut reply = joined("99");
                reply.received_order = match self.join_order.load(Ordering::Acquire) {
                    0 => None,
                    order => Some(order),
                };
                return Ok(reply);
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
fn fixture_connector() -> (Arc<Factory>, Arc<Mock>, Arc<Store>) {
    let (tx, rx) = mpsc::channel(64);
    let rpc = Arc::new(Mock {
        ready: AtomicBool::new(true),
        calls: Mutex::new(vec![]),
        push: tx,
        defer_self: AtomicBool::new(false),
        join_order: AtomicU64::new(0),
        leave_timeout: AtomicBool::new(false),
        leave_rejected: AtomicBool::new(false),
        release_leave: Notify::new(),
        block_action: AtomicU16::new(0),
        release_action: Notify::new(),
    });
    let store = Arc::new(Store::default());
    let factory = Arc::new(Factory {
        rpc: rpc.clone(),
        rx: Mutex::new(Some(rx)),
    });
    (factory, rpc, store)
}
fn fixture() -> (IgapSignaling, Arc<Mock>, Arc<Store>) {
    let (factory, rpc, store) = fixture_connector();
    let app =
        IgapSignaling::with_connector(store.clone(), RegistrationProfile::Independent, factory);
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

#[tokio::test]
async fn transport_revision_rejects_stale_same_peer_session_and_real_end() {
    let (app, rpc, _) = fixture();
    app.restore(record()).await.unwrap();
    app.set_allowed_peers(&["42".into()]).unwrap();
    let peer = app.resolve_peer("42").await.unwrap();
    let worker = app.clone();
    let task = tokio::spawn(async move { worker.place_call(peer).await });
    wait_call(&rpc, 915).await;
    rpc.push.send(joined("99")).await.unwrap();
    let session = task.await.unwrap().unwrap();
    let revision = app.joined_call_revision(&session).unwrap();
    assert!(app.is_joined_call_revision(revision));
    let unrelated = lk_signaling::TransportSession {
        url: session.url.clone(),
        token: "a-different-transport-token".into(),
        peer_id: session.peer_id.clone(),
    };
    assert!(app.joined_call_revision(&unrelated).is_none());
    push_leave(&app, &rpc, 42).await;
    assert!(!app.is_joined_call_revision(revision));
    assert!(app.joined_call_revision(&session).is_none());
    app.disconnect().await;
}

#[tokio::test]
async fn delayed_pre_join_self_leave_preserves_only_the_matching_receiver_join() {
    for (actor, receipt, deferred) in [
        (41, Some(19), true),
        (41, Some(20), false),
        (41, Some(21), false),
        (41, None, false),
        (42, Some(19), false),
    ] {
        let (app, rpc, _) = fixture();
        app.restore(record()).await.unwrap();
        app.set_allowed_peers(&["42".into()]).unwrap();
        app.set_incoming_handler(Box::new(Accept));
        rpc.join_order.store(20, Ordering::Release);
        let mut accepted = app.accepted_sessions();
        let mut events = app.events();
        // Capture the earlier wire receipt now, but deliberately withhold its
        // delivery until the join reply continuation has published the session.
        let mut queued_leave = response(30918, w::uint_field(2, actor).unwrap());
        queued_leave.received_order = receipt;
        rpc.push
            .send(response(
                30915,
                [w::uint_field(2, 42).unwrap(), w::uint_field(3, 99).unwrap()].concat(),
            ))
            .await
            .unwrap();
        let (_, session) = tokio::time::timeout(Duration::from_secs(2), accepted.recv())
            .await
            .unwrap()
            .unwrap();
        let revision = app.joined_call_revision(&session).unwrap();
        rpc.push.send(queued_leave).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while app.service_leave_diagnostic().is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(app.service_leave_diagnostic().unwrap().deferred, deferred);
        assert_eq!(app.is_joined_call_revision(revision), deferred);
        if deferred {
            assert!(events.try_recv().is_err());
            // A later real self-hangup must still terminate the same call.
            let mut later = response(30918, w::uint_field(2, 41).unwrap());
            later.received_order = Some(21);
            rpc.push.send(later).await.unwrap();
        }
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(2), events.recv())
                .await
                .unwrap(),
            Some(lk_signaling::SignalingEvent::CallEnded { .. })
        ));
        assert!(!app.is_joined_call_revision(revision));
        app.disconnect().await;
    }
}

struct RotatingFactory(Mutex<std::collections::VecDeque<Arc<Factory>>>);
#[async_trait]
impl Connector for RotatingFactory {
    async fn open(&self) -> Result<(Arc<dyn Rpc>, mpsc::Receiver<Response>), Error> {
        let factory = self.0.lock().pop_front().ok_or(Error::Closed)?;
        factory.open().await
    }
}
#[tokio::test]
async fn receipt_order_is_scoped_to_the_physical_authenticated_connection() {
    for new_epoch in [true, false] {
        let (first, old_rpc, store) = fixture_connector();
        let (second, new_rpc, _) = fixture_connector();
        new_rpc.join_order.store(2, Ordering::Release);
        let app = IgapSignaling::with_connector(
            store,
            RegistrationProfile::Independent,
            Arc::new(RotatingFactory(Mutex::new([first, second].into()))),
        );
        app.restore(record()).await.unwrap();
        if new_epoch {
            app.disconnect().await;
            app.restore(record()).await.unwrap();
        } else {
            // Replacing a closed channel can preserve the authentication epoch.
            // Old receive-order numbers must still remain scoped to that channel.
            old_rpc.close();
            app.connect().await.unwrap();
        }
        app.set_allowed_peers(&["42".into()]).unwrap();
        app.set_incoming_handler(Box::new(Accept));
        let mut accepted = app.accepted_sessions();
        new_rpc
            .push
            .send(response(
                30915,
                [w::uint_field(2, 42).unwrap(), w::uint_field(3, 99).unwrap()].concat(),
            ))
            .await
            .unwrap();
        let (_, session) = tokio::time::timeout(Duration::from_secs(2), accepted.recv())
            .await
            .unwrap()
            .unwrap();
        let revision = app.joined_call_revision(&session).unwrap();
        let mut old_leave = response(30918, w::uint_field(2, 41).unwrap());
        old_leave.received_order = Some(100);
        let _ = old_rpc.push.send(old_leave).await;
        // Closing the old receiver proves its queued event passed the old-context
        // guard, rather than depending on a scheduler delay to inspect new state.
        tokio::time::timeout(Duration::from_secs(2), old_rpc.push.closed())
            .await
            .unwrap();
        assert!(app.is_joined_call_revision(revision));
        assert!(app.service_leave_diagnostic().is_none());
        let mut current_leave = response(30918, w::uint_field(2, 41).unwrap());
        current_leave.received_order = Some(3);
        let mut events = app.events();
        new_rpc.push.send(current_leave).await.unwrap();
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(2), events.recv())
                .await
                .unwrap(),
            Some(lk_signaling::SignalingEvent::CallEnded { .. })
        ));
        assert!(!app.is_joined_call_revision(revision));
        app.disconnect().await;
    }
}

#[tokio::test]
async fn old_accept_cleanup_cannot_end_same_room_on_replacement_connection() {
    for delayed in [916, 914] {
        let (first, old_rpc, store) = fixture_connector();
        let (second, new_rpc, _) = fixture_connector();
        let app = IgapSignaling::with_connector(
            store,
            RegistrationProfile::Independent,
            Arc::new(RotatingFactory(Mutex::new([first, second].into()))),
        );
        app.restore(record()).await.unwrap();
        app.set_allowed_peers(&["42".into()]).unwrap();
        app.set_incoming_handler(Box::new(Accept));
        let mut accepted = app.accepted_sessions();
        let incoming = || {
            response(
                30915,
                [w::uint_field(2, 42).unwrap(), w::uint_field(3, 99).unwrap()].concat(),
            )
        };
        old_rpc.block_action.store(delayed, Ordering::Release);
        old_rpc.push.send(incoming()).await.unwrap();
        wait_call(&old_rpc, delayed).await;
        old_rpc.close();
        app.connect().await.unwrap();
        // Wake the old push consumer so its stale context is fully released.
        let _ = old_rpc
            .push
            .send(response(30916, w::uint_field(2, 41).unwrap()))
            .await;
        tokio::time::timeout(Duration::from_secs(2), old_rpc.push.closed())
            .await
            .unwrap();
        new_rpc.push.send(incoming()).await.unwrap();
        let (_, session) = tokio::time::timeout(Duration::from_secs(2), accepted.recv())
            .await
            .unwrap()
            .unwrap();
        let revision = app.joined_call_revision(&session).unwrap();
        let mut events = app.events();
        old_rpc.release_action.notify_one();
        // The only surviving old-RPC owner should be this test once the
        // suspended acceptance and its cleanup have both finished.
        tokio::time::timeout(Duration::from_secs(2), async {
            while Arc::strong_count(&old_rpc) != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(
            events.try_recv().is_err(),
            "old cleanup ended the replacement call"
        );
        assert!(app.is_joined_call_revision(revision));
        new_rpc
            .push
            .send(response(30918, w::uint_field(2, 42).unwrap()))
            .await
            .unwrap();
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(2), events.recv())
                .await
                .unwrap(),
            Some(lk_signaling::SignalingEvent::CallEnded { .. })
        ));
        assert!(!app.is_joined_call_revision(revision));
        app.disconnect().await;
    }
}
