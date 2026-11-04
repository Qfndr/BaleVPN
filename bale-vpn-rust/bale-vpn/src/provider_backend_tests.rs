//! Real HTTP router and native auth adapter over an in-memory RPC peer.
use super::*;
use async_trait::async_trait;
use axum::{
    body::{to_bytes, Body},
    http::Request,
};
use igap_signaling::{
    adapter::Connector,
    rpc::{Response as RpcResponse, Rpc},
    wire as w,
};
use std::sync::atomic::{AtomicBool, Ordering};
use tower::ServiceExt;

#[derive(Default)]
struct MockRpc {
    ready: AtomicBool,
    leave_fails: AtomicBool,
    actions: Mutex<Vec<u16>>,
}
#[async_trait]
impl Rpc for MockRpc {
    async fn request(
        &self,
        action: u16,
        fields: Vec<u8>,
    ) -> std::result::Result<RpcResponse, igap_signaling::Error> {
        self.actions.lock().push(action);
        let input = w::parse(&fields).unwrap();
        let response = match action {
            100 => {
                assert!(!input.is_empty());
                [
                    w::string_field(2, "fixture-registration", 256).unwrap(),
                    w::uint_field(3, 41).unwrap(),
                    w::uint_field(5, 1).unwrap(),
                    w::uint_field(6, 0).unwrap(),
                    w::uint_field(9, 5).unwrap(),
                ]
                .concat()
            }
            101 => {
                assert_eq!(w::number(&input, 2, u64::MAX).unwrap(), 12345);
                [
                    w::string_field(2, "fixture-secret-session-token", 16384).unwrap(),
                    w::uint_field(3, 0).unwrap(),
                ]
                .concat()
            }
            914 => [
                w::string_field(2, "header.eyJzdWIiOiI0MSIsInZpZGVvIjp7InJvb20iOiI5OSIsInJvb21Kb2luIjp0cnVlfSwiZXhwIjo0MTAyNDQ0ODAwfQ.signature", 16384).unwrap(),
                w::uint_field(3, 41).unwrap(),
            ].concat(),
            916 => w::uint_field(2, 41).unwrap(),
            918 if self.leave_fails.load(Ordering::Acquire) => return Err(igap_signaling::Error::Timeout),
            918 => w::uint_field(2, 41).unwrap(),
            _ => panic!("unexpected non-auth RPC"),
        };
        Ok(RpcResponse {
            received_order: None,
            action: action + 30000,
            fields: w::parse(&response).unwrap(),
        })
    }
    async fn login(
        &self,
        fields: Vec<u8>,
    ) -> std::result::Result<RpcResponse, igap_signaling::Error> {
        self.actions.lock().push(102);
        assert_eq!(
            w::text(&w::parse(&fields).unwrap(), 2, 16384).unwrap(),
            "fixture-secret-session-token"
        );
        let fields = [w::uint_field(2, 0).unwrap(), w::uint_field(14, 41).unwrap()].concat();
        Ok(RpcResponse {
            received_order: None,
            action: 30102,
            fields: w::parse(&fields).unwrap(),
        })
    }
    fn ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }
    fn close(&self) {
        self.ready.store(false, Ordering::Release);
    }
}
struct MockConnector {
    rpc: Arc<MockRpc>,
    senders: Mutex<Vec<tokio::sync::mpsc::Sender<RpcResponse>>>,
}
#[async_trait]
impl Connector for MockConnector {
    async fn open(
        &self,
    ) -> std::result::Result<
        (Arc<dyn Rpc>, tokio::sync::mpsc::Receiver<RpcResponse>),
        igap_signaling::Error,
    > {
        self.rpc.ready.store(true, Ordering::Release);
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        self.senders.lock().push(tx);
        Ok((self.rpc.clone(), rx))
    }
}
async fn request(
    service: &Arc<Service>,
    method: &str,
    path: &str,
    body: Value,
) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header("Host", "127.0.0.1:37129")
        .header("Origin", "http://127.0.0.1:37129")
        .header("Content-Type", "application/json")
        .header("X-Provider-CSRF", &service.csrf)
        .body(if method == "GET" {
            Body::empty()
        } else {
            Body::from(body.to_string())
        })
        .unwrap();
    let response = router(service.clone()).oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 128 * 1024).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}
#[tokio::test]
async fn http_auth_seals_session_before_ready_and_explicit_restore_uses_only_login_rpc() {
    let dir = tempfile::tempdir().unwrap();
    let service = Service::new(dir.path().join("providers/igap"));
    let lock = crate::vault::lock_directory(&service.directory).unwrap();
    let store = Arc::new(Store::open(&service.directory).unwrap());
    let rpc = Arc::new(MockRpc::default());
    let connector = Arc::new(MockConnector {
        rpc: rpc.clone(),
        senders: Mutex::new(vec![]),
    });
    let app = Arc::new(IgapSignaling::with_connector(
        store.clone(),
        RegistrationProfile::Independent,
        connector.clone(),
    ));
    let accepted = app.accepted_sessions();
    let backend = Arc::new(Backend {
        _lock: lock,
        store: store.clone(),
        identity: store.identity().unwrap(),
        app: app.clone(),
        config: Mutex::new(Config::default()),
        operation: tokio::sync::Mutex::new(()),
        job: tokio::sync::Mutex::new(None),
        accepted: tokio::sync::Mutex::new(accepted),
        tunnel: Mutex::new(None),
        phase: Mutex::new("idle"),
        error: Mutex::new(None),
        admission_enabled: Mutex::new(false),
        admission_permit: Mutex::new(Arc::new(AtomicBool::new(false))),
        media_terminal: Mutex::new(None),
    });
    assert!(service.backend.set(backend.clone()).is_ok());
    let (status, start) = request(
        &service,
        "POST",
        "/auth/start",
        json!({
            "country":"US", "nationalNumber":"2025550123", "internationalNumber":"+12025550123"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(start["codeDigits"], 5);
    assert!(store.record().unwrap().is_none());
    assert_eq!(*rpc.actions.lock(), vec![100]);
    let (status, verified) =
        request(&service, "POST", "/auth/verify", json!({"code":"12345"})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(verified["authenticated"], true);
    assert_eq!(verified["credentialsSaved"], true);
    assert_eq!(*rpc.actions.lock(), vec![100, 101, 102]);
    assert!(!verified.to_string().contains("fixture-secret"));
    let sealed = std::fs::read(service.directory.join("igap-session.bin")).unwrap();
    assert!(!sealed
        .windows(b"fixture-secret".len())
        .any(|v| v == b"fixture-secret"));
    let reopened = Store::open(&service.directory).unwrap();
    assert_eq!(
        reopened.record().unwrap().unwrap().token,
        "fixture-secret-session-token"
    );
    app.disconnect().await;
    let (status, restored) = request(&service, "POST", "/session/restore", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(restored["authenticated"], true);
    assert_eq!(*rpc.actions.lock(), vec![100, 101, 102, 102]);
    assert!(!restored.to_string().contains("fixture-secret"));
    // A worker failure must revoke admission even if a timed-out leave keeps
    // the old call active and makes allow-list mutation return Busy.
    let peer = app.resolve_peer("42").await.unwrap();
    app.set_allowed_peers(&["42".into()]).unwrap();
    let old_handler = backend.set_admission(Some(peer.clone()));
    let sender = connector.senders.lock().last().unwrap().clone();
    let incoming = || RpcResponse {
        received_order: None,
        action: 30915,
        fields: w::parse(
            &[
                w::bytes_field(1, &w::uint_field(2, 100).unwrap()).unwrap(),
                w::uint_field(2, 42).unwrap(),
                w::uint_field(3, 99).unwrap(),
            ]
            .concat(),
        )
        .unwrap(),
    };
    sender.send(incoming()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), backend.accepted.lock().await.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(app.set_allowed_peers(&[]).is_err());
    rpc.leave_fails.store(true, Ordering::Release);
    assert!(!backend.cleanup_connection().await);
    assert!(matches!(
        old_handler.decide(peer.clone(), None).await,
        CallDecision::SilentlyIgnore
    ));
    assert!(
        app.set_allowed_peers(&[]).is_err(),
        "failed leave must still be represented as active"
    );
    let mut late_end_events = app.events();
    sender
        .send(RpcResponse {
            received_order: None,
            action: 30918,
            fields: w::parse(
                &[
                    w::bytes_field(1, &w::uint_field(2, 99).unwrap()).unwrap(),
                    w::uint_field(2, 42).unwrap(),
                ]
                .concat(),
            )
            .unwrap(),
        })
        .await
        .unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), late_end_events.recv())
            .await
            .unwrap(),
        Some(SignalingEvent::CallEnded { .. })
    ));
    backend.capture_media_terminal("control", "call_ended");
    let ended = backend.snapshot();
    assert_eq!(ended["mediaDiagnostic"]["serviceLeave"]["actor"], "peer");
    assert_eq!(ended["mediaDiagnostic"]["serviceLeave"]["phase"], "joined");
    assert_eq!(
        ended["mediaDiagnostic"]["serviceLeave"]["metadataTimestampOrder"], "earlier",
        "metadata ordering is observable and never suppresses a real leave"
    );
    assert_eq!(
        ended["mediaDiagnostic"]["lastEvent"]["serviceLeave"],
        ended["mediaDiagnostic"]["serviceLeave"]
    );
    // Ping the ordered push stream with a new offer after the late leave.
    sender.send(incoming()).await.unwrap();
    assert!(tokio::time::timeout(
        Duration::from_millis(80),
        backend.accepted.lock().await.recv()
    )
    .await
    .is_err());
    assert_eq!(
        rpc.actions.lock().iter().filter(|a| **a == 916).count(),
        1,
        "late caller must not be auto-answered by an orphan worker"
    );
    rpc.leave_fails.store(false, Ordering::Release);
    assert!(backend.cleanup_connection().await);
    let new_handler = backend.set_admission(Some(peer.clone()));
    assert!(matches!(
        new_handler.decide(peer.clone(), None).await,
        CallDecision::Accept
    ));
    assert!(
        matches!(
            old_handler.decide(peer.clone(), None).await,
            CallDecision::SilentlyIgnore
        ),
        "a new cycle cannot reactivate a captured old handler"
    );
    backend.set_admission(None);
    // The same authenticated adapter can accept two successive calls, with
    // explicit cleanup between them and without any outgoing call request.
    let peer = app.resolve_peer("42").await.unwrap();
    let mut health = tokio::time::interval(Duration::from_secs(1));
    *backend.admission_enabled.lock() = true;
    let mut signals = app.events();
    for _ in 0..2 {
        let (_stop, mut stopped) = oneshot::channel();
        let accepting =
            backend.accept_session(&peer, "42", &mut stopped, &mut signals, &mut health);
        tokio::pin!(accepting);
        let mut tick = tokio::time::interval(Duration::from_millis(5));
        let received = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                tokio::select! {
                    value=&mut accepting => break value.unwrap().unwrap(),
                    _=tick.tick()=>sender.send(incoming()).await.unwrap(),
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(received.peer_id, peer);
        let active = backend.snapshot();
        assert!(active["mediaDiagnostic"]["serviceLeave"].is_null());
        assert_eq!(
            active["mediaDiagnostic"]["lastEvent"]["serviceLeave"]["actor"], "peer",
            "a new call must not rewrite the retained previous leave event"
        );
        assert!(backend.cleanup_connection().await);
    }
    assert_eq!(rpc.actions.lock().iter().filter(|a| **a == 916).count(), 3);
    assert!(!rpc.actions.lock().iter().any(|a| matches!(*a, 913 | 915)));
    let (stop, mut stopped) = oneshot::channel();
    stop.send(()).unwrap();
    let mut signals = app.events();
    assert!(backend
        .accept_session(&peer, "42", &mut stopped, &mut signals, &mut health)
        .await
        .unwrap()
        .is_none());
    sender.send(incoming()).await.unwrap();
    assert!(tokio::time::timeout(
        Duration::from_millis(80),
        backend.accepted.lock().await.recv()
    )
    .await
    .is_err());
    assert_eq!(
        rpc.actions.lock().iter().filter(|a| **a == 916).count(),
        3,
        "cancelled next cycle must not reopen admission"
    );
    service.shutdown().await;
}

#[test]
fn queued_previous_call_end_does_not_end_current_transport_or_listening() {
    struct TestPeer;
    impl lk_signaling::PeerRef for TestPeer {
        fn id_str(&self) -> &str {
            "42"
        }
    }
    let ended = || {
        Some(SignalingEvent::CallEnded {
            peer_id: PeerId::new(TestPeer),
            reason: lk_signaling::EndReason::CallerHangup,
        })
    };
    assert!(check_waiting_signal(ended()).is_ok());
    assert!(check_call_signal(ended(), true).is_ok());
    assert!(matches!(
        check_call_signal(ended(), false),
        Err(Failure("call_ended"))
    ));
    for joined in [false, true] {
        assert!(matches!(
            check_call_signal(Some(SignalingEvent::AuthExpired), joined),
            Err(Failure("auth_expired"))
        ));
        assert!(matches!(
            check_call_signal(Some(SignalingEvent::ProtocolObsolete), joined),
            Err(Failure("protocol_obsolete"))
        ));
        assert!(matches!(
            check_call_signal(None, joined),
            Err(Failure("signaling_closed"))
        ));
    }
}
