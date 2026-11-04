//! Lazy native iGap service. Shared by the desktop router and explicit CLI
//! selection; no provider network operation is performed by construction.
#[cfg(test)]
#[path = "provider_backend_tests.rs"]
mod backend_tests;
use crate::{
    provider_config::{Config, IgapSessionEnvelope, Role},
    provider_store::Store,
};
use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use igap_signaling::{auth::RegistrationProfile, IgapSignaling};
use lk_signaling::{
    CallDecision, IncomingHandler, PeerId, Signaling, SignalingEvent, TransportSession, TunnelHooks,
};
use lktunnel::{security::Identity, EventKind, LkTunnel, TunnelRole};
use parking_lot::Mutex;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::{oneshot, OnceCell};

pub struct Service {
    directory: PathBuf,
    csrf: String,
    backend: OnceCell<Arc<Backend>>,
    closing: AtomicBool,
}
pub struct Backend {
    _lock: std::fs::File,
    store: Arc<Store>,
    identity: Arc<Identity>,
    app: Arc<IgapSignaling>,
    config: Mutex<Config>,
    operation: tokio::sync::Mutex<()>,
    job: tokio::sync::Mutex<Option<Job>>,
    accepted: tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<(PeerId, TransportSession)>>,
    tunnel: Mutex<Option<Arc<LkTunnel>>>,
    phase: Mutex<&'static str>,
    error: Mutex<Option<&'static str>>,
    admission_enabled: Mutex<bool>,
    admission_permit: Mutex<Arc<AtomicBool>>,
    media_terminal: Mutex<Option<Value>>,
}
struct Job {
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}
#[derive(Debug)]
struct Failure(&'static str);
type Result<T> = std::result::Result<T, Failure>;
impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok":false,"provider":"igap","error":{"reason":self.0}})),
        )
            .into_response()
    }
}
fn failure(_: impl std::fmt::Display) -> Failure {
    Failure("provider_storage_failed")
}
fn igap_failure(error: igap_signaling::Error) -> Failure {
    use igap_signaling::Error::*;
    Failure(match error {
        InvalidPacket => "invalid_packet",
        NotConnected => "not_connected",
        Timeout => "timeout",
        Closed | Cancelled => "cancelled",
        Busy => "account_busy",
        InvalidInput => "invalid_input",
        NotAuthenticated => "not_authenticated",
        Rejected { .. } => "service_rejected",
        InvalidResponse => "invalid_response",
        NotSupported => "not_supported",
    })
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
impl Service {
    pub(crate) async fn disconnect_if_loaded(&self) {
        if let Some(backend) = self.backend.get() {
            let _operation = backend.operation.lock().await;
            backend.stop().await;
        }
    }
    pub fn new(directory: PathBuf) -> Arc<Self> {
        let mut bytes = [0u8; 32];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes)
            .expect("OS randomness");
        Arc::new(Self {
            directory,
            csrf: hex(&bytes),
            backend: OnceCell::new(),
            closing: AtomicBool::new(false),
        })
    }
    async fn backend(&self) -> Result<Arc<Backend>> {
        if self.closing.load(Ordering::Acquire) {
            return Err(Failure("provider_closed"));
        }
        let result = self
            .backend
            .get_or_try_init(|| async {
                let lock = crate::vault::lock_directory(&self.directory).map_err(failure)?;
                let store = Arc::new(Store::open(&self.directory).map_err(failure)?);
                let config = store.config().map_err(failure)?;
                let identity = store.identity().map_err(failure)?;
                let app = Arc::new(IgapSignaling::new(
                    store.clone(),
                    RegistrationProfile::Independent,
                ));
                let accepted = app.accepted_sessions();
                Ok(Arc::new(Backend {
                    _lock: lock,
                    store,
                    identity,
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
                }))
            })
            .await
            .cloned();
        if self.closing.load(Ordering::Acquire) {
            return Err(Failure("provider_closed"));
        }
        result
    }
    pub async fn shutdown(&self) {
        self.closing.store(true, Ordering::Release);
        if let Some(b) = self.backend.get() {
            let _operation = b.operation.lock().await;
            b.stop().await;
            b.app.disconnect().await;
        }
    }
}
impl Backend {
    fn idle(&self) -> Result<()> {
        if self.tunnel.lock().is_some()
            || !matches!(*self.phase.lock(), "idle" | "failed" | "stopped")
        {
            return Err(Failure("account_busy"));
        }
        Ok(())
    }
    fn saved(&self) -> Result<()> {
        if self.store.failed() {
            Err(Failure("session_save_failed"))
        } else {
            Ok(())
        }
    }
    fn account(&self) -> Value {
        match self.store.record() {
            Ok(Some(record)) => {
                json!({"userId":record.user_id,"maskedPhone":if record.login_phone.len()>=4{format!("•••• {}",&record.login_phone[record.login_phone.len()-4..])}else{String::new()},"deviceName":record.profile.device_name,"registrationProfile":record.profile.registration_profile,"needsProfile":record.needs_profile})
            }
            _ => Value::Null,
        }
    }
    fn snapshot(&self) -> Value {
        let auth = self.app.state();
        let tunnel = self.tunnel.lock();
        let (media, paired, ready, traffic, metrics) = tunnel
            .as_ref()
            .map(|t| {
                let stats = t.stats();
                (
                    t.is_connected(),
                    t.is_peer_authenticated(),
                    t.is_proxy_ready(),
                    json!({"receivedBytes":stats[1],"sentBytes":stats[3]}),
                    serde_json::to_value(t.connection_metrics()).unwrap_or(Value::Null),
                )
            })
            .unwrap_or((
                false,
                false,
                false,
                json!({"receivedBytes":0,"sentBytes":0}),
                Value::Null,
            ));
        let last_event = self.media_terminal.lock().clone();
        let rtc = tunnel
            .as_ref()
            .and_then(|t| t.media_diagnostic())
            .or_else(|| last_event.as_ref().and_then(|v| v.get("rtc").cloned()));
        json!({"provider":"igap","phase":*self.phase.lock(),"error":self.error.lock().map(|reason|json!({"reason":reason})),"authenticated":auth.signed_in&&!self.store.failed(),"credentialsSaved":!self.store.failed(),"wsReady":self.app.is_connected(),"hasSession":self.store.record().ok().flatten().is_some(),"authStage":auth.stage,"retryAfterSeconds":auth.retry_after,"codeDigits":auth.code_digits,"deliveryMethod":auth.delivery_method,"mode":self.config.lock().mode,"mediaConnected":media,"peerAuthenticated":paired,"proxyReady":ready&&paired,"traffic":traffic,"metrics":metrics,"mediaDiagnostic":{"rtc":rtc,"lastEvent":last_event,"serviceLeave":self.app.service_leave_diagnostic()},"account":self.account(),"publicCode":hex(&self.identity.certificate),"frontendReady":true,"billingVerified":false})
    }
    async fn stop(&self) {
        {
            let mut enabled = self.admission_enabled.lock();
            *enabled = false;
            self.set_admission(None);
        }
        let _ = self.app.set_allowed_peers(&[]);
        if let Some(Job { stop, mut task }) = self.job.lock().await.take() {
            let _ = stop.send(());
            if tokio::time::timeout(Duration::from_secs(12), &mut task)
                .await
                .is_err()
            {
                task.abort();
                let _ = task.await;
            }
        }
        if let Some(tunnel) = self.tunnel.lock().take() {
            tunnel.disconnect();
        }
        let _ = self.app.set_allowed_peers(&[]);
        *self.phase.lock() = "stopped";
    }
    async fn start(self: &Arc<Self>) -> Result<()> {
        self.saved()?;
        let mut current = self.job.lock().await;
        if current.as_ref().is_some_and(|job| !job.task.is_finished()) {
            return Err(Failure("account_busy"));
        }
        if let Some(job) = current.take() {
            let _ = job.task.await;
        }
        let config = self.config.lock().clone();
        config
            .validate_ready()
            .map_err(|_| Failure("provider_not_configured"))?;
        if !self.app.is_authenticated() {
            if self.store.record().map_err(failure)?.is_none() {
                return Err(Failure("not_authenticated"));
            }
            self.app
                .connect()
                .await
                .map_err(|_| Failure("session_restore_failed"))?;
            self.saved()?;
        }
        let record = self
            .store
            .record()
            .map_err(failure)?
            .ok_or(Failure("not_authenticated"))?;
        if config.peer_id.as_deref() == Some(record.user_id.as_str()) {
            return Err(Failure("invalid_provider_peer"));
        }
        let role = config.mode.ok_or(Failure("provider_not_configured"))?;
        let trusted = config
            .trusted_der()
            .map_err(|_| Failure("invalid_provider_trust"))?;
        self.identity
            .options(&trusted, role == Role::Server, config.throughput)
            .map_err(|_| Failure("invalid_provider_trust"))?;
        let (stop, mut rx) = oneshot::channel();
        let this = self.clone();
        *self.phase.lock() = if role == Role::Server {
            "listening"
        } else {
            "calling"
        };
        *self.error.lock() = None;
        *self.media_terminal.lock() = None;
        *self.admission_enabled.lock() = true;
        let task = tokio::spawn(async move {
            loop {
                if stop_requested(&mut rx) {
                    *this.phase.lock() = "stopped";
                    break;
                }
                let result = this.connection(config.clone(), &mut rx).await;
                let last_tunnel = this.tunnel.lock().clone();
                if let Some(tunnel) = last_tunnel {
                    tunnel.capture_media_stats().await;
                    if let Some(terminal) = this.media_terminal.lock().as_mut() {
                        terminal["rtc"] = tunnel.media_diagnostic().unwrap_or(Value::Null);
                    }
                }
                this.capture_media_terminal(
                    "control",
                    &result.as_ref().err().map(|e| e.0).unwrap_or("local_stop"),
                );
                let cleared = this.cleanup_connection().await;
                if role == Role::Server
                    && cleared
                    && this.app.is_authenticated()
                    && this.app.is_connected()
                    && recoverable_server_end(&result)
                    && !stop_requested(&mut rx)
                {
                    *this.phase.lock() = "listening";
                    continue;
                }
                if let Err(error) = result {
                    *this.error.lock() = Some(if cleared {
                        error.0
                    } else {
                        "call_cleanup_failed"
                    });
                    *this.phase.lock() = "failed";
                } else {
                    *this.phase.lock() = "stopped";
                }
                break;
            }
            *this.admission_enabled.lock() = false;
        });
        *current = Some(Job { stop, task });
        Ok(())
    }
    fn set_admission(&self, peer: Option<PeerId>) -> Admission {
        let mut previous = self.admission_permit.lock();
        previous.store(false, Ordering::Release);
        let permit = Arc::new(AtomicBool::new(peer.is_some()));
        *previous = permit.clone();
        let handler = Admission { peer, permit };
        self.app.set_incoming_handler(Box::new(handler.clone()));
        handler
    }
    fn capture_media_terminal(&self, kind: &'static str, reason: &str) {
        let rtc = self
            .tunnel
            .lock()
            .as_ref()
            .and_then(|t| t.media_diagnostic());
        let mut current = self.media_terminal.lock();
        if current.is_none() {
            *current = Some(
                json!({"kind":kind,"reason":media_reason(reason),"rtc":rtc,"serviceLeave":self.app.service_leave_diagnostic()}),
            );
        }
    }
    async fn cleanup_connection(&self) -> bool {
        // Revoke admission before awaiting the network: a failed leave keeps
        // the adapter busy, so clearing its allow-list alone can fail.
        self.set_admission(None);
        let _ = tokio::time::timeout(Duration::from_secs(8), self.app.hang_up()).await;
        if let Some(t) = self.tunnel.lock().take() {
            t.disconnect();
        }
        self.app.set_allowed_peers(&[]).is_ok()
    }
    async fn accept_session(
        &self,
        peer: &PeerId,
        peer_id: &str,
        stop: &mut oneshot::Receiver<()>,
        signals: &mut tokio::sync::mpsc::UnboundedReceiver<SignalingEvent>,
        health: &mut tokio::time::Interval,
    ) -> Result<Option<TransportSession>> {
        let mut accepted = self.accepted.lock().await;
        while accepted.try_recv().is_ok() {}
        // Historical call-end notifications are not scoped to the next admission.
        while let Ok(event) = signals.try_recv() {
            check_waiting_signal(Some(event))?;
        }
        // A stop between two calls must never re-enable admission.
        {
            let enabled = self.admission_enabled.lock();
            if !*enabled || stop_requested(stop) {
                return Ok(None);
            }
            self.set_admission(Some(peer.clone()));
            self.app
                .set_allowed_peers(&[peer_id.to_owned()])
                .map_err(igap_failure)?;
        }
        loop {
            tokio::select! {
                biased;
                _=&mut *stop=>return Ok(None),
                value=accepted.recv()=>{let (from,session)=value.ok_or(Failure("signaling_closed"))?;if &from!=peer{return Err(Failure("unexpected_peer"));}if self.app.joined_call_revision(&session).is_some(){return Ok(Some(session));}},
                _=health.tick()=>if !self.app.is_connected(){return Err(Failure("signaling_disconnected"));},
                event=signals.recv()=>check_waiting_signal(event)?,
            }
        }
    }
    async fn connection(&self, config: Config, stop: &mut oneshot::Receiver<()>) -> Result<()> {
        let peer_id = config
            .peer_id
            .as_ref()
            .ok_or(Failure("provider_not_configured"))?;
        let peer = self
            .app
            .resolve_peer(peer_id)
            .await
            .ok_or(Failure("invalid_provider_peer"))?;
        self.app.set_allowed_peers(&[]).map_err(igap_failure)?;
        self.set_admission(None);
        let mut signals = self.app.events();
        let mut health = tokio::time::interval(Duration::from_secs(1));
        let role = config.mode.ok_or(Failure("provider_not_configured"))?;
        let session = if role == Role::Server {
            match self
                .accept_session(&peer, peer_id, stop, &mut signals, &mut health)
                .await?
            {
                Some(session) => session,
                None => return Ok(()),
            }
        } else {
            self.app
                .set_allowed_peers(&[peer_id.clone()])
                .map_err(igap_failure)?;
            let placing = self.app.place_call(peer.clone());
            tokio::pin!(placing);
            tokio::select! {
                value=&mut placing=>value.map_err(|_|Failure("call_failed"))?,
                _=&mut *stop=>{let _=tokio::time::timeout(Duration::from_secs(8),self.app.hang_up()).await;return Ok(());},
            }
        };
        // This accepted transport starts a new diagnostic generation even if
        // a service leave races its validation before media can be created.
        *self.media_terminal.lock() = None;
        let call_revision = self
            .app
            .joined_call_revision(&session)
            .ok_or(Failure("call_ended"))?;
        if session.url != "wss://call.igap.net/" || session.peer_id != peer {
            return Err(Failure("invalid_transport_session"));
        }
        let mut options = self
            .identity
            .options(
                &config
                    .trusted_der()
                    .map_err(|_| Failure("invalid_provider_trust"))?,
                role == Role::Server,
                config.throughput,
            )
            .map_err(|_| Failure("invalid_provider_trust"))?;
        options.wait_for_track_published = true;
        let tunnel = LkTunnel::connect_with_options(
            session.url,
            session.token,
            if role == Role::Server {
                TunnelRole::Server
            } else {
                TunnelRole::Client
            },
            options,
        );
        let mut events = tunnel.events().ok_or(Failure("media_events_unavailable"))?;
        *self.tunnel.lock() = Some(tunnel.clone());
        *self.phase.lock() = "connecting";
        let deadline = tokio::time::sleep(Duration::from_secs(50));
        tokio::pin!(deadline);
        let mut initialized = false;
        loop {
            tokio::select! {
                _=&mut *stop=>return Ok(()),
                _=&mut deadline,if !tunnel.is_peer_authenticated()=>return Err(Failure("authentication_timeout")),
                _=health.tick()=>{
                    if !self.app.is_connected(){return Err(Failure("signaling_disconnected"));}
                    if tunnel.is_peer_authenticated(){*self.phase.lock()="connected";}
                },
                event=signals.recv()=>check_call_signal(event, self.app.is_joined_call_revision(call_revision))?,
                event=events.recv()=>{
                    let event=event.ok_or(Failure("media_closed"))?;
                    match event.kind {
                        EventKind::Connected if !initialized=>{
                            initialized=true;
                            if role==Role::Server{tunnel.start_server().map_err(|_|Failure("server_setup_failed"))?;}
                            else{tokio::select!{result=tunnel.enable_socks5_server(config.socks5_port)=>{result.map_err(|_|Failure("proxy_bind_failed"))?;},_=&mut *stop=>return Ok(())}}
                        },
                        EventKind::Disconnected|EventKind::Error=>{
                            self.capture_media_terminal(if event.kind==EventKind::Error{"error"}else{"disconnected"}, &event.info);
                            return Err(Failure("media_failed"));
                        },
                        _=>{}
                    }
                },
            }
        }
    }
}
fn stop_requested(stop: &mut oneshot::Receiver<()>) -> bool {
    !matches!(stop.try_recv(), Err(oneshot::error::TryRecvError::Empty))
}
fn media_reason(info: &str) -> Value {
    if let Some(body) = info.strip_prefix("server leave reason=") {
        let fields: Vec<_> = body.split_whitespace().collect();
        if fields.len() == 3 {
            let reason = fields[0]
                .parse::<i32>()
                .ok()
                .filter(|n| (-1..=16).contains(n));
            let action = fields[1]
                .strip_prefix("action=")
                .and_then(|s| s.parse::<i32>().ok())
                .filter(|n| (-1..=2).contains(n));
            let reconnect = fields[2]
                .strip_prefix("reconnect=")
                .and_then(|s| s.parse::<u8>().ok())
                .filter(|n| *n <= 1);
            if let (Some(reason), Some(action), Some(reconnect)) = (reason, action, reconnect) {
                return json!({"code":"server_leave","serviceReason":reason,"serviceAction":action,"reconnect":reconnect==1});
            }
        }
    }
    let code = match info {
        "room empty" => "room_empty",
        "remote carrier track ended" => "remote_track_ended",
        "signal stream ended" => "signal_stream_ended",
        "tunnel torn down" => "local_teardown",
        "local_stop" => "local_stop",
        "connect failed" => "engine_connect_failed",
        "no peer joined within timeout" => "peer_wait_timeout",
        "publisher PC failed" => "publisher_failed",
        "publisher PC closed" => "publisher_closed",
        "subscriber PC failed" => "subscriber_failed",
        "subscriber PC closed" => "subscriber_closed",
        "local SDP send failed" => "local_sdp_send_failed",
        "local ICE send failed" => "local_ice_send_failed",
        "local ICE candidate queue limit" => "local_ice_queue_limit",
        "local ICE candidate size limit" => "local_ice_size_limit",
        "local SDP generation superseded" => "local_sdp_superseded",
        "call_ended" => "call_ended",
        "signaling_disconnected" => "signaling_disconnected",
        "signaling_closed" => "signaling_closed",
        "auth_expired" => "auth_expired",
        "authentication_timeout" => "peer_authentication_timeout",
        "proxy_bind_failed" => "proxy_bind_failed",
        _ if info.starts_with("signal closed: ") => "signal_closed",
        _ => "unknown",
    };
    json!({"code":code})
}
fn recoverable_server_end(result: &Result<()>) -> bool {
    matches!(
        result,
        Err(Failure(
            "call_ended" | "media_closed" | "media_failed" | "authentication_timeout"
        ))
    )
}
fn check_waiting_signal(event: Option<SignalingEvent>) -> Result<()> {
    // There is no accepted transport yet: ending an earlier/pending call does
    // not stop a listening server. Authentication/protocol failures still do.
    if matches!(event, Some(SignalingEvent::CallEnded { .. })) {
        return Ok(());
    }
    check_signal(event)
}
fn check_call_signal(event: Option<SignalingEvent>, same_call_joined: bool) -> Result<()> {
    if same_call_joined && matches!(event, Some(SignalingEvent::CallEnded { .. })) {
        return Ok(());
    }
    check_signal(event)
}
fn check_signal(event: Option<SignalingEvent>) -> Result<()> {
    match event {
        Some(SignalingEvent::AuthExpired) => Err(Failure("auth_expired")),
        Some(SignalingEvent::ProtocolObsolete) => Err(Failure("protocol_obsolete")),
        Some(SignalingEvent::CallEnded { .. }) => Err(Failure("call_ended")),
        None => Err(Failure("signaling_closed")),
        _ => Ok(()),
    }
}
#[derive(Clone)]
struct Admission {
    peer: Option<PeerId>,
    permit: Arc<AtomicBool>,
}
#[async_trait::async_trait]
impl IncomingHandler for Admission {
    async fn decide(&self, peer: PeerId, _: Option<String>) -> CallDecision {
        if self.permit.load(Ordering::Acquire) && self.peer.as_ref() == Some(&peer) {
            CallDecision::Accept
        } else {
            CallDecision::SilentlyIgnore
        }
    }
}

async fn csrf(State(service): State<Arc<Service>>, request: Request, next: Next) -> Response {
    if service.closing.load(Ordering::Acquire) {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    // Match the existing native window's zero-body focus request. It cannot
    // change account/config state and still passes the Host/Origin guard.
    let focus = request.method() == axum::http::Method::POST
        && request.uri().path().ends_with("/desktop/show");
    if !focus
        && request.method() != axum::http::Method::GET
        && request.method() != axum::http::Method::HEAD
    {
        let token = request
            .headers()
            .get("x-provider-csrf")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let equal = token.len() == service.csrf.len()
            && token
                .bytes()
                .zip(service.csrf.bytes())
                .fold(0u8, |a, (b, c)| a | (b ^ c))
                == 0;
        if !equal {
            return StatusCode::FORBIDDEN.into_response();
        }
        if !request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.split(';').next() == Some("application/json"))
        {
            return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
        }
    }
    let mut response = next.run(request).await;
    for (key, value) in [
        (header::CACHE_CONTROL, "no-store"),
        (header::REFERRER_POLICY, "no-referrer"),
        (header::X_FRAME_OPTIONS, "DENY"),
    ] {
        response
            .headers_mut()
            .insert(key, axum::http::HeaderValue::from_static(value));
    }
    response.headers_mut().insert(header::CONTENT_SECURITY_POLICY,axum::http::HeaderValue::from_static("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"));
    response
}
pub fn router(service: Arc<Service>) -> Router {
    Router::new()
        .route("/", get(provider_index))
        .route("/ui", get(provider_index))
        .route("/ui.js", get(provider_script))
        .route("/countries.js", get(provider_countries))
        .route("/fonts/:name", get(crate::ui::font))
        .route("/flags/:name", get(crate::ui::country_flag))
        .route("/info", get(info))
        .route("/desktop/show", post(desktop_show))
        .route("/state", get(state))
        .route("/account", get(account))
        .route("/config", get(config).post(set_config))
        .route(
            "/appearance",
            get(appearance)
                .post(set_appearance)
                .layer(axum::extract::DefaultBodyLimit::max(4096)),
        )
        .route("/session/import", post(import_session))
        .route("/session/save", post(save_session))
        .route("/session/restore", post(restore_session))
        .route("/auth/start", post(auth_start))
        .route("/auth/verify", post(auth_verify))
        .route("/auth/password", post(auth_password))
        .route("/auth/profile", post(auth_profile))
        .route("/connect", post(connect))
        .route("/disconnect", post(disconnect))
        .route("/logout", post(logout))
        .route("/server/call-privacy", get(privacy).post(allow_privacy))
        .layer(axum::extract::DefaultBodyLimit::max(128 * 1024))
        .layer(middleware::from_fn_with_state(service.clone(), csrf))
        .layer(middleware::from_fn(crate::ui::protect_management_ui))
        .with_state(service)
}
async fn provider_index() -> axum::response::Html<&'static str> {
    axum::response::Html(include_str!("../assets/provider.html"))
}
async fn desktop_show() -> Json<Value> {
    #[cfg(feature = "gui")]
    let ok = crate::ui_native::request_show();
    #[cfg(not(feature = "gui"))]
    let ok = false;
    Json(json!({"ok":ok}))
}
async fn provider_script() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../assets/provider-ui.js"),
    )
}
async fn provider_countries() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../assets/provider-countries.js"),
    )
}
async fn info(State(s): State<Arc<Service>>) -> Json<Value> {
    Json(
        json!({"provider":"igap","csrfToken":s.csrf,"frontendReady":true,"capabilities":{"native":true,"login":true,"retainedSessionImport":true,"client":true,"server":true,"contacts":false,"automaticReconnect":false},"billingVerified":false}),
    )
}
async fn state(State(s): State<Arc<Service>>) -> Result<Json<Value>> {
    Ok(Json(s.backend().await?.snapshot()))
}
async fn account(State(s): State<Arc<Service>>) -> Result<Json<Value>> {
    Ok(Json(s.backend().await?.account()))
}
async fn config(State(s): State<Arc<Service>>) -> Result<Json<Config>> {
    let b = s.backend().await?;
    let value = b.config.lock().clone();
    Ok(Json(value))
}
async fn appearance(State(s): State<Arc<Service>>) -> Result<Json<Value>> {
    let b = s.backend().await?;
    Ok(Json(b.store.appearance().map_err(failure)?))
}
async fn set_appearance(
    State(s): State<Arc<Service>>,
    Json(value): Json<Value>,
) -> Result<Json<Value>> {
    let b = s.backend().await?;
    b.store
        .save_appearance(&value)
        .map_err(|_| Failure("invalid_appearance"))?;
    Ok(Json(json!({"ok":true})))
}
async fn set_config(
    State(s): State<Arc<Service>>,
    Json(value): Json<Config>,
) -> Result<Json<Value>> {
    let b = s.backend().await?;
    let _op = b
        .operation
        .try_lock()
        .map_err(|_| Failure("account_busy"))?;
    b.idle()?;
    if !value.trusted_certificates.is_empty() {
        let trust = value
            .trusted_der()
            .map_err(|_| Failure("invalid_provider_trust"))?;
        if trust.contains(&b.identity.certificate) {
            return Err(Failure("invalid_provider_trust"));
        }
        b.identity
            .options(&trust, value.mode == Some(Role::Server), value.throughput)
            .map_err(|_| Failure("invalid_provider_trust"))?;
    }
    b.store.save_config(&value).map_err(failure)?;
    *b.config.lock() = value;
    Ok(Json(json!({"ok":true})))
}
async fn import_session(
    State(s): State<Arc<Service>>,
    Json(value): Json<IgapSessionEnvelope>,
) -> Result<Json<Value>> {
    let b = s.backend().await?;
    let _op = b
        .operation
        .try_lock()
        .map_err(|_| Failure("account_busy"))?;
    b.idle()?;
    if b.store.record().map_err(failure)?.is_some() {
        return Err(Failure("session_exists"));
    }
    b.store.save_record(value.into_record()).map_err(failure)?;
    Ok(Json(
        json!({"ok":true,"imported":true,"authenticated":false}),
    ))
}
async fn save_session(State(s): State<Arc<Service>>, Json(_): Json<Empty>) -> Result<Json<Value>> {
    let b = s.backend().await?;
    let _op = b
        .operation
        .try_lock()
        .map_err(|_| Failure("account_busy"))?;
    b.idle()?;
    b.store.retry_pending().map_err(failure)?;
    Ok(Json(b.snapshot()))
}
async fn restore_session(
    State(s): State<Arc<Service>>,
    Json(_): Json<Empty>,
) -> Result<Json<Value>> {
    let b = s.backend().await?;
    let _op = b
        .operation
        .try_lock()
        .map_err(|_| Failure("account_busy"))?;
    b.idle()?;
    b.saved()?;
    if b.store.record().map_err(failure)?.is_none() {
        return Err(Failure("no_saved_session"));
    }
    b.app
        .connect()
        .await
        .map_err(|_| Failure("session_restore_failed"))?;
    b.saved()?;
    Ok(Json(b.snapshot()))
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Start {
    country: String,
    national_number: String,
    international_number: String,
    registration_profile: Option<RegistrationProfile>,
}
async fn auth_start(
    State(s): State<Arc<Service>>,
    Json(value): Json<Start>,
) -> Result<Json<Value>> {
    let b = s.backend().await?;
    let _op = b
        .operation
        .try_lock()
        .map_err(|_| Failure("account_busy"))?;
    b.idle()?;
    if b.store.record().map_err(failure)?.is_some() {
        return Err(Failure("session_exists"));
    }
    let reply = b
        .app
        .start(
            &value.country,
            &value.national_number,
            &value.international_number,
            value.registration_profile,
        )
        .await
        .map_err(igap_failure)?;
    Ok(Json(
        json!({"ok":true,"deliveryMethod":reply.delivery_method,"codeDigits":reply.digits,"retryAfterSeconds":reply.retry_after}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Code {
    code: String,
}
async fn auth_verify(
    State(s): State<Arc<Service>>,
    Json(value): Json<Code>,
) -> Result<Json<Value>> {
    let b = s.backend().await?;
    let _op = b
        .operation
        .try_lock()
        .map_err(|_| Failure("account_busy"))?;
    b.idle()?;
    b.app.verify(&value.code).await.map_err(igap_failure)?;
    b.saved()?;
    Ok(Json(b.snapshot()))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Password {
    password: String,
}
async fn auth_password(
    State(s): State<Arc<Service>>,
    Json(value): Json<Password>,
) -> Result<Json<Value>> {
    let b = s.backend().await?;
    let _op = b
        .operation
        .try_lock()
        .map_err(|_| Failure("account_busy"))?;
    b.idle()?;
    b.app
        .password(&value.password)
        .await
        .map_err(igap_failure)?;
    b.saved()?;
    Ok(Json(b.snapshot()))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileName {
    name: String,
}
async fn auth_profile(
    State(s): State<Arc<Service>>,
    Json(value): Json<ProfileName>,
) -> Result<Json<Value>> {
    let b = s.backend().await?;
    let _op = b
        .operation
        .try_lock()
        .map_err(|_| Failure("account_busy"))?;
    b.idle()?;
    b.app
        .complete_profile(&value.name)
        .await
        .map_err(igap_failure)?;
    b.saved()?;
    Ok(Json(b.snapshot()))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
async fn connect(State(s): State<Arc<Service>>, Json(_): Json<Empty>) -> Result<Json<Value>> {
    let b = s.backend().await?;
    let _op = b
        .operation
        .try_lock()
        .map_err(|_| Failure("account_busy"))?;
    b.start().await?;
    Ok(Json(b.snapshot()))
}
async fn disconnect(State(s): State<Arc<Service>>, Json(_): Json<Empty>) -> Result<Json<Value>> {
    let b = s.backend().await?;
    let _op = b
        .operation
        .try_lock()
        .map_err(|_| Failure("account_busy"))?;
    b.stop().await;
    Ok(Json(b.snapshot()))
}
async fn logout(State(s): State<Arc<Service>>, Json(_): Json<Empty>) -> Result<Json<Value>> {
    let b = s.backend().await?;
    let _op = b
        .operation
        .try_lock()
        .map_err(|_| Failure("account_busy"))?;
    b.stop().await;
    if !b.app.is_connected() {
        b.app
            .connect()
            .await
            .map_err(|_| Failure("session_restore_failed"))?;
    }
    b.app.logout().await.map_err(igap_failure)?;
    b.saved()?;
    Ok(Json(b.snapshot()))
}
async fn privacy(State(s): State<Arc<Service>>) -> Result<Json<Value>> {
    let b = s.backend().await?;
    let _op = b
        .operation
        .try_lock()
        .map_err(|_| Failure("account_busy"))?;
    Ok(Json(
        serde_json::to_value(b.app.read_call_privacy().await.map_err(igap_failure)?)
            .map_err(failure)?,
    ))
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Privacy {
    allow_everyone: bool,
}
async fn allow_privacy(
    State(s): State<Arc<Service>>,
    Json(value): Json<Privacy>,
) -> Result<Json<Value>> {
    if !value.allow_everyone {
        return Err(Failure("invalid_input"));
    }
    let b = s.backend().await?;
    let _op = b
        .operation
        .try_lock()
        .map_err(|_| Failure("account_busy"))?;
    Ok(Json(
        serde_json::to_value(
            b.app
                .ensure_call_privacy_everyone()
                .await
                .map_err(igap_failure)?,
        )
        .map_err(failure)?,
    ))
}

pub async fn run(
    cfg: crate::config::Resolved,
    shutdown: oneshot::Receiver<()>,
    ready: Option<std::sync::mpsc::SyncSender<std::result::Result<(), String>>>,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    if cfg.client_tun || cfg.nat_mode != "userspace" {
        return Err(std::io::Error::other(
            "iGap currently supports SOCKS and userspace server mode only",
        )
        .into());
    }
    lktunnel::dispatcher::init();
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", cfg.port)).await?;
    let service = Service::new(cfg.config_dir.join("providers/igap"));
    let b = service
        .backend()
        .await
        .map_err(|e| std::io::Error::other(e.0))?;
    if let Some(mode) = cfg.mode {
        let mut value = b.config.lock().clone();
        value.mode = Some(if mode == "server" {
            Role::Server
        } else {
            Role::Client
        });
        b.store.save_config(&value)?;
        *b.config.lock() = value;
    }
    let app = router(service.clone());
    let mut server = tokio::spawn(async move { axum::serve(listener, app).await });
    if let Some(tx) = ready {
        let _ = tx.send(Ok(()));
    }
    let managed_stop = Arc::new(tokio::sync::Notify::new());
    if cfg.managed_profile {
        let signal = managed_stop.clone();
        std::thread::Builder::new()
            .name("provider-supervisor-pipe".into())
            .spawn(move || {
                use std::io::Read;
                let stdin = std::io::stdin();
                let mut input = stdin.lock();
                let mut byte = [0; 1];
                loop {
                    match input.read(&mut byte) {
                        Ok(0) => break,
                        Ok(_) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                    }
                }
                signal.notify_one();
            })?;
    }
    tokio::select! {_=&mut server=>{},_=shutdown=>{},_=crate::daemon::wait_for_signal()=>{},_=managed_stop.notified(),if cfg.managed_profile=>{}}
    server.abort();
    service.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn media_diagnostics_keep_only_known_codes_and_bounded_service_enums() {
        assert_eq!(super::media_reason("room empty")["code"], "room_empty");
        assert_eq!(
            super::media_reason("publisher PC failed")["code"],
            "publisher_failed"
        );
        assert_eq!(
            super::media_reason("subscriber PC closed")["code"],
            "subscriber_closed"
        );
        assert_eq!(
            super::media_reason("server leave reason=14 action=0 reconnect=0"),
            serde_json::json!({"code":"server_leave","serviceReason":14,"serviceAction":0,"reconnect":false})
        );
        for text in [
            "private-token https://private.example",
            "server leave reason=999 action=0 reconnect=0",
            "server leave reason=14 action=0 reconnect=0 private",
        ] {
            assert_eq!(
                super::media_reason(text),
                serde_json::json!({"code":"unknown"})
            );
        }
        assert_eq!(
            super::media_reason("signal closed: private reason"),
            serde_json::json!({"code":"signal_closed"})
        );
    }
    #[test]
    fn server_continuation_excludes_stop_signaling_and_security_failures() {
        for reason in [
            "call_ended",
            "media_closed",
            "media_failed",
            "authentication_timeout",
        ] {
            assert!(super::recoverable_server_end(&Err(super::Failure(reason))));
        }
        for reason in [
            "invalid_transport_session",
            "unexpected_peer",
            "signaling_disconnected",
            "auth_expired",
            "proxy_bind_failed",
        ] {
            assert!(!super::recoverable_server_end(&Err(super::Failure(reason))));
        }
        assert!(!super::recoverable_server_end(&Ok(())));
    }
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use tower::ServiceExt;
    async fn call(
        app: Router,
        path: &str,
        method: &str,
        token: Option<&str>,
        body: Value,
    ) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .uri(path)
            .method(method)
            .header("Host", "127.0.0.1:37129");
        if method != "GET" {
            request = request
                .header("Origin", "http://127.0.0.1:37129")
                .header("Content-Type", "application/json");
        }
        if let Some(token) = token {
            request = request.header("X-Provider-CSRF", token);
        }
        let response = app
            .oneshot(
                request
                    .body(if method == "GET" {
                        Body::empty()
                    } else {
                        Body::from(body.to_string())
                    })
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 128 * 1024).await.unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }
    fn record() -> igap_signaling::auth::SessionRecord {
        igap_signaling::auth::SessionRecord {
            provider: "igap".into(),
            user_id: "41".into(),
            token: "fixture-secret-session".into(),
            profile: igap_signaling::auth::Profile::default(),
            login_phone: String::new(),
            needs_profile: false,
        }
    }
    #[tokio::test]
    async fn lazy_info_creates_no_store_and_foreign_websites_cannot_mutate() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("providers/igap");
        let service = Service::new(dir.clone());
        let app = router(service.clone());
        let (status, info) = call(app.clone(), "/info", "GET", None, Value::Null).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(info["provider"], "igap");
        assert!(!dir.exists());
        assert!(service.backend.get().is_none());
        let focus = Request::builder()
            .uri("/desktop/show")
            .method("POST")
            .header("Host", "127.0.0.1:37129")
            .header("Origin", "http://127.0.0.1:37129")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(focus).await.unwrap().status(),
            StatusCode::OK
        );
        assert!(!dir.exists());
        let (status, _) = call(app.clone(), "/disconnect", "POST", None, json!({})).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let request = Request::builder()
            .uri("/disconnect")
            .method("POST")
            .header("Host", "127.0.0.1:37129")
            .header("Origin", "https://evil.invalid")
            .header("Content-Type", "application/json")
            .header("X-Provider-CSRF", &service.csrf)
            .body(Body::from("{}"))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        let request = Request::builder()
            .uri("/state")
            .header("Host", "evil.invalid")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.oneshot(request).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        assert!(!dir.exists());
    }
    #[tokio::test]
    async fn shutdown_closes_intake_without_initializing_an_unused_provider() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("providers/igap");
        let service = Service::new(dir.clone());
        service.shutdown().await;
        let (status, _) = call(router(service.clone()), "/state", "GET", None, Value::Null).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(!dir.exists());
        assert!(service.backend.get().is_none());
    }
    #[tokio::test]
    async fn appearance_persists_independently_and_cannot_smuggle_account_settings() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("providers/igap");
        let service = Service::new(dir.clone());
        let app = router(service.clone());
        let value = json!({"language":"fa","theme":"dark","palette":"teal","motion":false});
        let (status, _) = call(
            app.clone(),
            "/appearance",
            "POST",
            Some(&service.csrf),
            value.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(Store::open(&dir).unwrap().appearance().unwrap(), value);
        let (status, _) = call(
            app.clone(),
            "/appearance",
            "POST",
            Some(&service.csrf),
            json!({"token":"secret"}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (_, restored) = call(app, "/appearance", "GET", None, Value::Null).await;
        assert_eq!(restored, value);
        assert!(!service.backend().await.unwrap().app.is_connected());
    }
    #[tokio::test]
    async fn imported_account_is_sealed_isolated_and_never_logged_in_implicitly() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("token.bin"), b"existing-bale-data").unwrap();
        let service = Service::new(root.path().join("providers/igap"));
        let app = router(service.clone());
        let source = serde_json::to_value(IgapSessionEnvelope::new(record()).unwrap()).unwrap();
        let (status, value) = call(
            app.clone(),
            "/session/import",
            "POST",
            Some(&service.csrf),
            source.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["authenticated"], false);
        let backend = service.backend().await.unwrap();
        assert!(!backend.app.is_connected());
        assert_eq!(
            serde_json::to_value(backend.store.record().unwrap().unwrap()).unwrap(),
            source["record"]
        );
        assert_eq!(
            std::fs::read(root.path().join("token.bin")).unwrap(),
            b"existing-bale-data"
        );
        let disk = std::fs::read(service.directory.join("igap-session.bin")).unwrap();
        assert!(!disk
            .windows(b"fixture-secret-session".len())
            .any(|w| w == b"fixture-secret-session"));
        let (status, state) = call(app.clone(), "/state", "GET", None, Value::Null).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(state["authenticated"], false);
        assert_eq!(state["hasSession"], true);
        assert!(!state.to_string().contains("fixture-secret-session"));
        let (status, _) = call(
            app.clone(),
            "/session/import",
            "POST",
            Some(&service.csrf),
            source.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let mut wrong = source;
        wrong["provider"] = "bale".into();
        let (status, _) = call(app, "/session/import", "POST", Some(&service.csrf), wrong).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(!backend.app.is_connected());
    }
    #[tokio::test]
    async fn explicit_config_persists_without_connecting_and_rejects_own_pairing_key() {
        let root = tempfile::tempdir().unwrap();
        let service = Service::new(root.path().join("providers/igap"));
        let app = router(service.clone());
        let backend = service.backend().await.unwrap();
        let mut value = Config {
            mode: Some(Role::Client),
            peer_id: Some("42".into()),
            trusted_certificates: vec![hex(&backend.identity.certificate)],
            ..Default::default()
        };
        let (status, _) = call(
            app.clone(),
            "/config",
            "POST",
            Some(&service.csrf),
            serde_json::to_value(&value).unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        value.trusted_certificates = vec![hex(&Identity::generate().unwrap().certificate)];
        let (status, _) = call(
            app.clone(),
            "/config",
            "POST",
            Some(&service.csrf),
            serde_json::to_value(&value).unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            backend.store.config().unwrap().peer_id.as_deref(),
            Some("42")
        );
        assert!(!backend.app.is_connected());
        let (status, state) = call(app, "/connect", "POST", Some(&service.csrf), json!({})).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(state["error"]["reason"], "not_authenticated");
        assert!(!backend.app.is_connected());
    }
}
