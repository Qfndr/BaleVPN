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
    call_error: Mutex<Option<igap_signaling::Error>>,
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
            913 => return Err(self.call_error.lock().unwrap_or(igap_signaling::Error::Timeout)),
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
        retry: Mutex::new(RetryStatus::default()),
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
    let previous_config = backend.config.lock().clone();
    backend.config.lock().mode = Some(Role::Client);
    backend.config.lock().auto_reconnect = true;
    assert!(matches!(backend.disconnect(false).await, Err(Failure("call_cleanup_failed"))));
    assert!(backend.job.lock().await.is_none(), "uncertain old call must prevent manual restart");
    assert!(!rpc.actions.lock().iter().any(|action| *action == 913));
    *backend.config.lock() = previous_config;
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

#[test]
fn diagnostic_relay_environment_accepts_only_explicit_boolean_values() {
    assert!(!parse_diagnostic_relay_only(None).unwrap());
    assert!(!parse_diagnostic_relay_only(Some("0".into())).unwrap());
    assert!(parse_diagnostic_relay_only(Some("1".into())).unwrap());
    for invalid in ["", "true", "false", " 1", "1 ", "relay"] {
        assert_eq!(parse_diagnostic_relay_only(Some(invalid.into())).unwrap_err().0,
            "invalid_diagnostic_relay_only");
    }
}


async fn retry_fixture(
    error: igap_signaling::Error,
) -> (tempfile::TempDir, Arc<Service>, Arc<MockRpc>) {
    let dir = tempfile::tempdir().unwrap();
    let service = Service::new(dir.path().join("providers/igap"));
    let lock = crate::vault::lock_directory(&service.directory).unwrap();
    let store = Arc::new(Store::open(&service.directory).unwrap());
    let rpc = Arc::new(MockRpc::default());
    *rpc.call_error.lock() = Some(error);
    let connector = Arc::new(MockConnector {
        rpc: rpc.clone(),
        senders: Mutex::new(vec![]),
    });
    let app = Arc::new(IgapSignaling::with_connector(
        store.clone(),
        RegistrationProfile::Independent,
        connector,
    ));
    app.restore(igap_signaling::auth::SessionRecord {
        provider: "igap".into(),
        user_id: "41".into(),
        token: "fixture-secret-session-token".into(),
        login_phone: String::new(),
        needs_profile: false,
        profile: igap_signaling::auth::Profile::new(RegistrationProfile::Independent),
    })
    .await
    .unwrap();
    let accepted = app.accepted_sessions();
    let peer = Identity::generate().unwrap();
    let config = Config {
        mode: Some(Role::Client),
        peer_id: Some("42".into()),
        trusted_certificates: vec![hex(&peer.certificate)],
        auto_reconnect: true,
        ..Config::default()
    };
    store.save_config(&config).unwrap();
    let backend = Arc::new(Backend {
        _lock: lock,
        store: store.clone(),
        identity: store.identity().unwrap(),
        app,
        config: Mutex::new(config),
        operation: tokio::sync::Mutex::new(()),
        job: tokio::sync::Mutex::new(None),
        accepted: tokio::sync::Mutex::new(accepted),
        tunnel: Mutex::new(None),
        phase: Mutex::new("idle"),
        error: Mutex::new(None),
        admission_enabled: Mutex::new(false),
        admission_permit: Mutex::new(Arc::new(AtomicBool::new(false))),
        media_terminal: Mutex::new(None),
        retry: Mutex::new(RetryStatus::default()),
    });
    assert!(service.backend.set(backend).is_ok());
    (dir, service, rpc)
}
async fn wait_phase(service: &Arc<Service>, phase: &str) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if service.backend().await.unwrap().snapshot()["phase"] == phase {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}

async fn wait_for_admission(backend: &Backend) {
    tokio::time::timeout(Duration::from_secs(8), async {
        while !backend.admission_permit.lock().load(Ordering::Acquire) || backend.retry.lock().active {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }).await.unwrap();
}

#[tokio::test]
async fn server_listening_recovery_is_separate_and_never_places_a_call() {
    let (_dir, service, rpc) = retry_fixture(igap_signaling::Error::Timeout).await;
    let backend = service.backend().await.unwrap();
    backend.config.lock().mode = Some(Role::Server);
    assert!(backend.config.lock().auto_reconnect);
    assert!(!backend.config.lock().server_auto_reconnect);
    backend.start().await.unwrap();
    wait_for_admission(&backend).await;
    rpc.ready.store(false, Ordering::Release);
    wait_phase(&service, "failed").await;
    assert!(!backend.retry.lock().active);
    backend.stop().await;

    backend.config.lock().server_auto_reconnect = true;
    backend.start().await.unwrap();
    wait_for_admission(&backend).await;
    rpc.ready.store(false, Ordering::Release);
    wait_phase(&service, "reconnecting").await;
    assert!(!backend.admission_permit.lock().load(Ordering::Acquire));
    wait_for_admission(&backend).await;
    assert_eq!(backend.snapshot()["phase"], "listening");
    assert!(!backend.retry.lock().active);
    rpc.ready.store(false, Ordering::Release);
    wait_phase(&service, "reconnecting").await;
    backend.stop().await;
    assert_eq!(backend.snapshot()["phase"], "stopped");
    assert!(!backend.admission_permit.lock().load(Ordering::Acquire));
    assert!(!rpc.actions.lock().contains(&913));
}

#[test]
fn server_recovery_rejects_active_or_ambiguous_and_security_failures() {
    assert!(waiting_server_recovery(Some(1), 1, &Err(Failure("signaling_disconnected"))));
    assert!(!waiting_server_recovery(Some(1), 2, &Err(Failure("signaling_disconnected"))));
    assert!(!waiting_server_recovery(None, 1, &Err(Failure("signaling_disconnected"))));
    assert!(!waiting_server_recovery(Some(1), 1, &Err(Failure("auth_expired"))));
    assert!(!waiting_server_recovery(Some(1), 1, &Err(Failure("unexpected_peer"))));
    let old: Config = serde_json::from_value(json!({"format":1,"provider":"igap","mode":"server","autoReconnect":true})).unwrap();
    assert!(retry_enabled(&old, Role::Client));
    assert!(!retry_enabled(&old, Role::Server));
}

#[tokio::test]
async fn auto_reconnect_retries_serially_and_off_cancels_waiting_or_manual_retry() {
    let (_dir, service, rpc) = retry_fixture(igap_signaling::Error::Timeout).await;
    let backend = service.backend().await.unwrap();
    backend.start().await.unwrap();
    wait_phase(&service, "reconnecting").await;
    assert!(
        backend.snapshot()["reconnectAfterSeconds"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert_eq!(rpc.actions.lock().iter().filter(|a| **a == 913).count(), 1);
    assert_eq!(
        request(&service, "POST", "/connect", json!({})).await.1["error"]["reason"],
        "account_busy"
    );
    tokio::time::timeout(Duration::from_secs(7), async {
        loop {
            if rpc.actions.lock().iter().filter(|a| **a == 913).count() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    wait_phase(&service, "reconnecting").await;
    assert_eq!(
        request(
            &service,
            "POST",
            "/auto-reconnect",
            json!({"enabled":false})
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(backend.snapshot()["phase"], "stopped");
    assert!(!backend.store.config().unwrap().auto_reconnect);
    assert!(backend.job.lock().await.is_none());
    assert_eq!(
        request(&service, "POST", "/disconnect", json!({})).await.0,
        StatusCode::OK
    );
    assert!(backend.job.lock().await.is_none());
    let attempts = rpc.actions.lock().iter().filter(|a| **a == 913).count();
    assert_eq!(attempts, 2);
    assert_eq!(
        request(&service, "POST", "/auto-reconnect", json!({"enabled":true}))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        rpc.actions.lock().iter().filter(|a| **a == 913).count(),
        attempts,
        "enabling does not dial before Connect"
    );
    assert_eq!(
        request(&service, "POST", "/disconnect", json!({})).await.0,
        StatusCode::OK
    );
    wait_phase(&service, "reconnecting").await;
    assert_eq!(
        rpc.actions.lock().iter().filter(|a| **a == 913).count(),
        attempts,
        "manual reconnect waits for backoff"
    );
    assert_eq!(
        request(
            &service,
            "POST",
            "/disconnect",
            json!({"pauseAutoReconnect":true})
        )
        .await
        .0,
        StatusCode::OK
    );
    assert!(backend.job.lock().await.is_none());
    service.shutdown().await;
}

#[tokio::test]
async fn rejected_or_invalid_account_call_never_automatically_redials() {
    for error in [
        igap_signaling::Error::Rejected {
            major: 1,
            minor: 1,
            wait_seconds: 0,
        },
        igap_signaling::Error::NotAuthenticated,
    ] {
        let (_dir, service, rpc) = retry_fixture(error).await;
        service.backend().await.unwrap().start().await.unwrap();
        wait_phase(&service, "failed").await;
        let backend = service.backend().await.unwrap();
        assert!(!backend.snapshot()["reconnecting"].as_bool().unwrap());
        assert_eq!(rpc.actions.lock().iter().filter(|a| **a == 913).count(), 1);
        tokio::time::timeout(Duration::from_secs(2), async {
            while !backend
                .job
                .lock()
                .await
                .as_ref()
                .unwrap()
                .task
                .is_finished()
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        service.shutdown().await;
    }
}

#[test]
fn retry_policy_caps_delay_and_excludes_security_rejection_and_configuration_errors() {
    let mut recovery = crate::reconnect::Recovery::default();
    for seconds in [5, 10, 20, 40, 80, 120, 120] {
        assert_eq!(
            client_retry_delay(
                &mut recovery,
                "42",
                false,
                &Err(Failure("call_timeout")),
                None
            ),
            Some(Duration::from_secs(seconds))
        );
    }
    for reason in [
        "call_rejected",
        "not_authenticated",
        "auth_expired",
        "session_restore_failed",
        "proxy_bind_failed",
        "invalid_provider_trust",
        "call_cleanup_failed",
        "call_failed",
    ] {
        assert!(
            client_retry_delay(&mut recovery, "42", false, &Err(Failure(reason)), None).is_none()
        );
    }
    for code in [
        "unknown",
        "peer_authentication_failed",
        "certificate_rejected",
    ] {
        let terminal = json!({"reason":{"code":code}});
        assert!(client_retry_delay(
            &mut recovery,
            "42",
            false,
            &Err(Failure("media_failed")),
            Some(&terminal)
        )
        .is_none());
    }
}


#[tokio::test]
async fn a_new_attempt_cannot_reuse_the_previous_network_failure_for_a_security_decision() {
    let (_dir, service, _) = retry_fixture(igap_signaling::Error::Timeout).await;
    let backend = service.backend().await.unwrap();
    *backend.media_terminal.lock() = Some(json!({"reason":{"code":"subscriber_failed"}}));
    backend.begin_attempt(Role::Client);
    assert!(backend.media_terminal.lock().is_none());
    backend.capture_media_terminal("error", "certificate verification failed");
    let terminal = backend.media_terminal.lock().clone();
    let mut recovery = crate::reconnect::Recovery::default();
    assert!(client_retry_delay(
        &mut recovery,
        "42",
        false,
        &Err(Failure("media_failed")),
        terminal.as_ref()
    )
    .is_none());
    service.shutdown().await;
}


#[test]
fn media_stream_closure_before_authentication_requires_a_known_network_reason() {
    let mut recovery = crate::reconnect::Recovery::default();
    let closed = Err(Failure("media_closed"));
    assert!(client_retry_delay(&mut recovery, "42", false, &closed, None).is_none());
    let unknown = json!({"reason":{"code":"unknown"}});
    assert!(client_retry_delay(&mut recovery, "42", false, &closed, Some(&unknown)).is_none());
    assert_eq!(
        client_retry_delay(&mut recovery, "42", true, &closed, None),
        Some(Duration::from_secs(5))
    );
    let network = json!({"reason":{"code":"subscriber_failed"}});
    assert!(client_retry_delay(&mut recovery, "42", false, &closed, Some(&network)).is_some());
}
