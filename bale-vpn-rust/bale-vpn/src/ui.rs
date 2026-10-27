//! HTTP UI server. Bound to 127.0.0.1 so the management surface
//! isn't reachable from off-host without an explicit ssh-tunnel
//! (the headless deployment recipe).
//!
//! The route shape mirrors the Node app's `http-server.js` so
//! the existing HTML/JS frontend can drop in unchanged. Routes
//! land in chunks:
//!
//!   - **(this chunk)** auth + connection + state. Enough to
//!     sign in and bring the WS up.
//!   - Next: contacts (`/peers`, `/contacts/search`,
//!     `/refresh-peers`).
//!   - Next: server admin (`/server/admission`,
//!     `/server/blacklist`, `/server/max-clients`,
//!     `/server/pending`).
//!   - Next: tunnel status (`/tunnel/status`, `/tunnel/clients`).
//!   - Eventually: embed the HTML/JS at `GET /`.

use crate::daemon::AppState;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json};
use axum::routing::{delete, get, post};
use axum::Router;
use axum::middleware::{self, Next};
use axum::extract::Request;
use bale_signaling::auth::{AuthOutcome, StartResult};
use lk_signaling::Signaling;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

/// Build the router. Caller spawns this against a TcpListener.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/flags/:name", get(country_flag))
        .route("/",              get(index))
        .route("/fonts/:name", get(font))
        .route("/config",        get(get_config).post(set_config))
        .route("/settings",      get(get_settings).post(set_settings))
        .route("/appearance", get(get_appearance).post(set_appearance).layer(axum::extract::DefaultBodyLimit::max(4096)))
        .route("/client/auto-reconnect", post(set_auto_reconnect))
        .route("/diagnostics",   get(diagnostics))
        .route("/state",         get(get_state))
        .route("/account", get(get_account))
        .route("/pool-telemetry.js", get(|| async { ([(header::CONTENT_TYPE,"text/javascript; charset=utf-8")],include_str!("../assets/pool-telemetry.js")) }))
        .route("/bond/server",get(bond_server_status).post(bond_server_config))
        .route("/bond-ui.js",get(||async{([(header::CONTENT_TYPE,"text/javascript; charset=utf-8")],include_str!("../assets/bond-ui.js"))}))
        .route("/instance", get(|| async {Json(serde_json::json!({"pid":std::process::id()}))}))
        .route("/shutdown", post(shutdown))
        .route("/desktop/show",post(desktop_show))
        .route("/aggregate", get(get_aggregate).post(configure_aggregate))
        .route("/backup/accounts",get(crate::backup::accounts))
        .route("/backup/export",post(crate::backup::export))
        .route("/backup/preview",post(crate::backup::preview).layer(axum::extract::DefaultBodyLimit::max(4*1024*1024)))
        .route("/backup/import",post(crate::backup::import).layer(axum::extract::DefaultBodyLimit::max(4*1024*1024)))
        .route("/aggregate/start", post(start_aggregate))
        .route("/aggregate/stop", post(stop_aggregate))
        .route("/aggregate/worker", post(aggregate_worker))
        .route("/aggregate/account-ports",post(configure_account_ports))
        .route("/aggregate/profiles/:slot/",get(crate::profiles::view))
        .route("/aggregate/profiles/:slot/*path",get(crate::profiles::forward).post(crate::profiles::forward).delete(crate::profiles::forward))
        .route("/connect",       post(connect))
        .route("/disconnect",    post(disconnect))
        .route("/logout",        post(logout))
        .route("/auth/start",    post(auth_start))
        .route("/auth/verify",   post(auth_verify))
        .route("/auth/signup",   post(auth_signup))
        // Contacts.
        .route("/peers",            get(list_peers))
        .route("/peers/refresh",    post(refresh_peers))
        .route("/contacts/search",  post(contacts_search))
        // Server-mode admission. Matches the Node app's URL
        // shape so the existing HTML/JS frontend ports
        // verbatim.
        .route("/server/admission",          get(get_admission).post(add_admission))
        .route("/server/admission/:peer_id", delete(remove_admission))
        .route("/server/blacklist",          get(get_blacklist).post(add_blacklist))
        .route("/server/blacklist/:peer_id", delete(remove_blacklist))
        .route("/server/max-clients",        get(get_max_clients).post(set_max_clients))
        .route("/server/call-privacy",       post(allow_server_calls))
        .route("/server/pending",            get(get_pending))
        .route("/server/pending/:peer_id/accept", post(accept_pending))
        .route("/server/pending/:peer_id/reject", post(reject_pending))
        // Tunnel status + admin. `/tunnel/config` shares its
        // body shape with `POST /config` (the Node frontend
        // uses /tunnel/config; we accept either).
        .route("/tunnel/status",            get(tunnel_status))
        .route("/tunnel/config",            post(set_config))
        .route("/tunnel/disconnect",        post(tunnel_disconnect))
        .route("/tunnel/clients",           get(tunnel_clients))
        .route("/tunnel/clients/:peer_id/disconnect", post(tunnel_client_disconnect))
        .with_state(state)
        .layer(middleware::from_fn(protect_management_ui))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"),
        ))
        .layer(TraceLayer::new_for_http())
        // Blanket `Cache-Control: no-store` on every response.
        // The embedded GUI webview (wry — WKWebView on macOS,
        // WebView2 on Windows, WebKitGTK on Linux) otherwise
        // caches `/state`, `/peers`, `/server/admission`, … and
        // serves stale post-login pages from before the user
        // authenticated, with no way to disable cache short of
        // the user manually right-click→Reload. Regular browsers
        // with devtools open mask this with their "Disable cache"
        // checkbox. `no-store` (stricter than `no-cache`) tells
        // every layer along the way — webview, intermediary
        // proxies (none here, but defensive) — to neither store
        // nor reuse the response.
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
}

// Loopback binding alone does not stop a hostile website from submitting
// forms to localhost, or accessing the API through DNS rebinding.
fn trusted_request(headers: &axum::http::HeaderMap) -> bool {
    if headers.get_all(header::HOST).iter().count() != 1 {
        return false;
    }
    let Some(host) = headers.get(header::HOST).and_then(|h| h.to_str().ok()) else {
        return false;
    };
    let Ok(authority) = host.parse::<axum::http::uri::Authority>() else {
        return false;
    };
    if !matches!(authority.host(), "127.0.0.1" | "localhost" | "[::1]") {
        return false;
    }
    if headers.get("sec-fetch-site").is_some_and(|v| v != "same-origin" && v != "none") {
        return false;
    }
    if headers.get_all(header::ORIGIN).iter().count() > 1 {
        return false;
    }
    if let Some(origin) = headers.get(header::ORIGIN) {
        let Ok(origin) = origin.to_str() else { return false; };
        // The UI is served over HTTP, at exactly the requested authority.
        if origin != format!("http://{host}") {
            return false;
        }
    }
    true
}

async fn protect_management_ui(request: Request, next: Next) -> axum::response::Response {
    if !trusted_request(request.headers()) {
        return StatusCode::FORBIDDEN.into_response();
    }
    next.run(request).await
}

/// Bind + serve forever. Returns on listener accept-loop exit.
pub async fn serve(state: Arc<AppState>, listener: tokio::net::TcpListener) -> std::io::Result<()> {
    log::info!("HTTP UI listening on http://{}",listener.local_addr()?);
    axum::serve(listener, router(state)).await
}

// ─── Embedded HTML UI ─────────────────────────────────────────────────────
//
// Ported verbatim from `bale-vpn-node/src/ui-html.js`. JS
// template-literal escapes (`\${...}` and `\``) have been
// unescaped so the embedded asset is plain HTML. Drives every
// /auth/*, /state, /peers, /connect, /tunnel/*, /server/* call;
// the URL surface in `router()` matches what the JS expects.
pub(crate) const INDEX_HTML: &str = include_str!("../assets/index.html");

async fn shutdown(State(s):State<Arc<AppState>>)->Json<OkBody>{s.shutdown.notify_one();Json(OkBody{ok:true})}
async fn desktop_show()->Json<OkBody>{
    #[cfg(feature="gui")]let ok=crate::ui_native::request_show();
    #[cfg(not(feature="gui"))]let ok=false;
    Json(OkBody{ok})
}
async fn get_aggregate(State(s):State<Arc<AppState>>)->Json<serde_json::Value>{Json(serde_json::json!({"config":s.aggregate.config(),"status":s.aggregate.snapshot(),"workers":s.aggregate.workers.snapshots()}))}
async fn configure_aggregate(State(s):State<Arc<AppState>>,Json(config):Json<crate::aggregate::Config>)->Result<Json<OkBody>,ApiError>{
    let primary=s.cfg.read().await.socks5_port;
    if config.listen_port==primary||config.paths.iter().any(|p|p.port==primary||p.management_port==primary){return Err(ApiError::Internal("Account ports must not overlap the main SOCKS port".into()));}
    s.aggregate.configure(config,&s.config_file).await.map_err(|e|ApiError::Internal(e.to_string()))?;Ok(Json(OkBody{ok:true}))
}
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct AccountPorts { slot:u8,socks5_port:u16,management_port:u16 }
async fn configure_account_ports(State(s):State<Arc<AppState>>,Json(body):Json<AccountPorts>)->Result<Json<OkBody>,ApiError>{
    let primary=s.cfg.read().await.socks5_port;
    s.aggregate.configure_account_ports(body.slot,body.socks5_port,body.management_port,primary,&s.config_file).await.map_err(|e|ApiError::Internal(e.to_string()))?;
    Ok(Json(OkBody{ok:true}))
}
async fn start_aggregate(State(s):State<Arc<AppState>>)->Result<Json<OkBody>,ApiError>{
    if let Some(port)=s.aggregate.config().primary_port {
        let cfg=s.cfg.read().await;
        if cfg.mode.as_deref()!=Some("client") || port!=cfg.socks5_port || !s.client.snapshot().await.is_some_and(|c|c.connected&&c.socks5_port==port) || !s.client.tunnel().is_some_and(|t|t.is_peer_authenticated()) {
            return Err(ApiError::Internal("Connect and authenticate the main account before including it in the pool".into()));
        }
    }
    s.aggregate.start().await.map_err(|e|ApiError::Internal(e.to_string()))?;Ok(Json(OkBody{ok:true}))
}
async fn stop_aggregate(State(s):State<Arc<AppState>>)->Json<OkBody>{s.aggregate.stop().await;Json(OkBody{ok:true})}
async fn bond_server_status(State(s):State<Arc<AppState>>)->Json<serde_json::Value>{Json(s.bond_server.as_ref().map(|server|server.snapshot()).unwrap_or_else(||serde_json::json!({"enabled":false,"managedProfile":true}))) }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BondServerBody{enabled:bool}
async fn bond_server_config(State(s):State<Arc<AppState>>,Json(body):Json<BondServerBody>)->Result<Json<OkBody>,ApiError>{
    let server=s.bond_server.as_ref().ok_or_else(||ApiError::Internal("Configure bonding on the main server controller".into()))?;
    s.config_file.update(|c|c.bond_server_enabled=body.enabled).map_err(|_|ApiError::Internal("Could not save bonding relay settings".into()))?;
    server.set_enabled(body.enabled);Ok(Json(OkBody{ok:true}))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerRequest {slot:usize,start:bool}
async fn aggregate_worker(State(s):State<Arc<AppState>>,Json(request):Json<WorkerRequest>)->Result<Json<OkBody>,ApiError>{s.aggregate.worker(request.slot,request.start).await.map_err(|e|ApiError::Internal(e.to_string()))?;Ok(Json(OkBody{ok:true}))}

// Fixed embedded assets only: no filesystem access or external font service.
async fn font(axum::extract::Path(name): axum::extract::Path<String>) -> axum::response::Response {
    let (bytes, content_type): (&'static [u8], &'static str) = match name.as_str() {
        "Vazirmatn.woff2" => (include_bytes!("../assets/fonts/Vazirmatn.woff2"), "font/woff2"),
        "InterVariable.woff2" => (include_bytes!("../assets/fonts/InterVariable.woff2"), "font/woff2"),
        "Vazirmatn-OFL.txt" => (include_bytes!("../assets/fonts/Vazirmatn-OFL.txt"), "text/plain; charset=utf-8"),
        "Inter-LICENSE.txt" => (include_bytes!("../assets/fonts/Inter-LICENSE.txt"), "text/plain; charset=utf-8"),
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    ([(header::CONTENT_TYPE, content_type)], bytes).into_response()
}

async fn country_flag(Path(name):Path<String>) -> axum::response::Response {
    match crate::country_flags::get(&name) {
        Some(bytes) => ([(header::CONTENT_TYPE,"image/svg+xml")],bytes).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
async fn index() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        INDEX_HTML,
    )
}

// ─── /config + /state ─────────────────────────────────────────────────────

#[derive(Serialize)]
struct ConfigBody {
    /// `Some("client" | "server")` once the user has picked,
    /// `null` on first run — the UI shows a mode picker for
    /// the null case.
    mode:        Option<String>,
    nat_mode:    String,
    peer_id:     Option<String>,
    socks5_port: u16,
}

async fn get_config(State(s): State<Arc<AppState>>) -> Json<ConfigBody> {
    let cfg = s.cfg.read().await;
    Json(ConfigBody {
        mode:        cfg.mode.clone(),
        nat_mode:    cfg.nat_mode.clone(),
        peer_id:     cfg.peer_id.clone(),
        socks5_port: cfg.socks5_port,
    })
}

async fn get_appearance(State(s): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({"ok":true,"appearance":s.config_file.load().appearance}))
}
async fn set_appearance(State(s): State<Arc<AppState>>, Json(value): Json<serde_json::Value>) -> Result<Json<OkBody>,ApiError> {
    crate::appearance::validate(&value).map_err(|e|ApiError::Internal(e.into()))?;
    s.config_file.update(|c|c.appearance=Some(value)).map_err(|_|ApiError::Internal("Could not save appearance preferences".into()))?;
    Ok(Json(OkBody{ok:true}))
}
async fn get_settings(State(s): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let preferences = s.cfg.read().await.preferences.clone();
    Json(serde_json::json!({"preferences":preferences,
        "savedPeerId":s.config_file.load().peer_id,
        "publicCode":crate::settings::code(&s.identity.certificate),
        "fingerprint":crate::settings::hex(ring::digest::digest(&ring::digest::SHA256,&s.identity.certificate).as_ref()),
        "credentialStorage":if cfg!(windows) {"Windows DPAPI (current OS user)"} else {"AES-256-GCM; private master key or BALEVPN_MASTER_KEY_FILE"}}))
}

async fn get_account(State(s): State<Arc<AppState>>) -> Result<Json<serde_json::Value>,ApiError> {
    let device=crate::device::identity(s.config_file.dir()).map_err(|_|ApiError::Internal("Could not read account device information".into()))?;
    let token=s.token_store.load();
    let own=if token.is_some(){s.signaling.account_identity()}else{None};
    let phone=token.as_ref().and_then(|t|crate::device::phone_for_session(&device,t));
    let model=crate::device::model_details(&device.label);
    let cfg=s.cfg.read().await;
    Ok(Json(serde_json::json!({"ok":true,"signedIn":token.is_some(),
        "id":own.as_ref().map(|u|u.uid.to_string()),"name":own.as_ref().and_then(|u|u.name.clone()),
        "username":own.as_ref().and_then(|u|u.nick.clone()),"loginPhone":phone,
        "deviceLabel":device.label,"mode":cfg.mode,"socks5Port":cfg.socks5_port,"managementPort":cfg.port,
        "deviceId":device.hash,"deviceBrand":model.map(|m|m.0),"deviceModel":model.map(|m|m.1),"deviceModelCode":model.map(|m|m.2),
        "deviceProtocol":"Bale web / gRPC-web","authAppId":4,"authLanguage":"fa","verifiedLoginMetadata":phone.is_some(),
        "secureMode":cfg.preferences.secure_mode,"version":env!("CARGO_PKG_VERSION")})))
}

async fn set_settings(State(s): State<Arc<AppState>>, Json(mut preferences): Json<crate::settings::Preferences>) -> Result<Json<OkBody>,ApiError> {
    preferences.normalize_codes().map_err(ApiError::Internal)?;
    preferences.validate(&s.identity).map_err(ApiError::Internal)?;
    if s.cfg.read().await.preferences == preferences { return Ok(Json(OkBody {ok:true})); }
    // Applying settings must not silently terminate a working session.
    if s.cfg.read().await.peer_id.is_some() || s.server.client_count().await>0 {
        return Err(ApiError::Internal("Disconnect the tunnel before changing security or performance settings".into()));
    }
    s.config_file.update(|c| c.preferences=preferences.clone()).map_err(|_|ApiError::Internal("Could not save settings".into()))?;
    let mode = { let mut cfg=s.cfg.write().await; cfg.preferences=preferences; cfg.mode.clone() };
    let _ = s.mode_tx.send(mode);
    Ok(Json(OkBody {ok:true}))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AutoReconnectBody { enabled: bool }
async fn set_auto_reconnect(State(s): State<Arc<AppState>>, Json(body): Json<AutoReconnectBody>) -> Result<Json<OkBody>,ApiError> {
    let mut cfg=s.cfg.write().await;
    s.config_file.update(|c|c.preferences.auto_reconnect=body.enabled).map_err(|_|ApiError::Internal("Could not save settings".into()))?;
    cfg.preferences.auto_reconnect=body.enabled;
    // Turning the option off stops a scheduled/in-progress recovery, but
    // leaves an established connection alone.
    if !body.enabled && s.client.reconnect_status().0 {
        cfg.peer_id=None;s.client.clear_error();
        let _=s.mode_tx.send(cfg.mode.clone());
    }
    Ok(Json(OkBody {ok:true}))
}

async fn diagnostics(State(s): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let cfg=s.cfg.read().await.clone();
    let snap=s.client.snapshot().await;
    let fingerprint=|bytes:&[u8]|crate::settings::hex(ring::digest::digest(&ring::digest::SHA256,bytes).as_ref());
    let trusted:Vec<_>=cfg.preferences.client_codes.iter().filter_map(|code|crate::settings::decode(code).ok()).map(|c|fingerprint(&c)).collect();
    // Public certificate hashes allow pairing comparison, never the codes/keys.
    // The event ring stores only fixed classifications, not raw error strings.
    Json(serde_json::json!({"applicationVersion":env!("CARGO_PKG_VERSION"),"mode":cfg.mode,
        "secureMode":cfg.preferences.secure_mode,"peerAuthenticated":s.client.tunnel().is_some_and(|t|t.is_peer_authenticated()) || s.server.authenticated_count()>0,"profile":cfg.preferences.profile,
        "websocketReady":s.signaling.is_connected(),"proxyReady":snap.as_ref().is_some_and(|x|x.connected),
        "socks5Port":cfg.socks5_port,"metrics":s.client.tunnel().and_then(|t|t.connection_metrics()),
        "autoReconnect":cfg.preferences.auto_reconnect,"pairingFingerprint":fingerprint(&s.identity.certificate),
        "trustedServerFingerprint":crate::settings::decode(&cfg.preferences.server_code).ok().map(|c|fingerprint(&c)),
        "trustedClientFingerprints":trusted,"activeServerClients":s.server.client_count().await,
        "pendingServerClients":s.server.pending_list().await.len(),"allowedCallerCount":s.server.admission_list().await.len(),"maxServerClients":s.server.max_clients(),
        "events":lktunnel::diagnostics::snapshot(),
        "lastClientFailure":s.client.last_error().map(|e|lktunnel::diagnostics::reason(&e)),
        "clientReconnecting":s.client.reconnect_status().0,
        "retryAfterSeconds":s.attempts.lock().remaining(&cfg.preferences,std::time::Instant::now())}))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetConfigBody {
    #[serde(default)]
    mode:           Option<String>,
    #[serde(default)]
    nat_mode:       Option<String>,
    /// UI's peer dropdown sends `serverPeerId`. `peerId` is
    /// kept as a deserialize alias for direct API users.
    #[serde(default, alias = "peerId")]
    server_peer_id: Option<String>,
    #[serde(default)]
    socks5_port:    Option<u16>,
    // Any other JSON keys the UI sends (`serverPeerType`,
    // `transport`, etc.) are silently dropped by serde —
    // they exist in the Node app's payload shape but the
    // Rust binary only supports one transport / peer type,
    // so there's nothing to map.
}

/// Update the live config. Persists to `~/.bale-vpn_config.json`
/// (so a daemon restart preserves UI changes) and updates the
/// in-memory `Resolved` so query handlers see fresh values
/// without a re-read. `mode` changes also publish on
/// `state.mode_tx` so [`crate::daemon::run_mode`] can tear down
/// the old per-mode task and restart in the new mode without a
/// process restart.
async fn set_config(
    State(s):   State<Arc<AppState>>,
    Json(body): Json<SetConfigBody>,
) -> Result<Json<OkBody>, ApiError> {
    if let Some(port)=body.socks5_port {
        let cfg=s.cfg.read().await;
        if port!=cfg.socks5_port {
            if cfg.managed_profile {return Err(ApiError::Internal("Change managed account ports in the main account list".into()));}
            let aggregate=s.aggregate.config();
            if port==cfg.port||port==aggregate.listen_port||aggregate.paths.iter().any(|p|port==p.port||port==p.management_port){return Err(ApiError::Internal("Account ports must not overlap other account or management ports".into()));}
            if body.server_peer_id.is_none()&&cfg.peer_id.is_some(){return Err(ApiError::Internal("Disconnect this account before changing its port".into()));}
            if port!=0 {let _socket=std::net::TcpListener::bind(("127.0.0.1",port)).map_err(|_|ApiError::Internal("The requested account port is already in use".into()))?;}
        }
    }
    if body.server_peer_id.is_some() {
        let cfg = s.cfg.read().await;
        if cfg.mode.as_deref()!=Some("client") { return Err(ApiError::Internal("Select Client mode before dialing".into())); }
        if cfg.preferences.secure_mode { cfg.preferences.options(&s.identity,false).map_err(ApiError::Internal)?; }
        if cfg.peer_id.is_none() {
            let wait=s.attempts.lock().remaining(&cfg.preferences,std::time::Instant::now());
            if wait>0 {return Err(ApiError::Internal(format!("Wait {wait}s before another call attempt")));}
        }
    }
    if body.mode.as_deref().is_some_and(|m| !matches!(m, "client" | "server"))
        || body.nat_mode.as_deref().is_some_and(|m| !matches!(m, "kernel" | "userspace"))
        || body.socks5_port == Some(0)
    {
        return Err(ApiError::Internal("invalid mode, NAT mode, or SOCKS5 port".into()));
    }
    // Persist to disk under the shared write lock. Cheap sync
    // RMW — fine to call from the async handler.
    let mode_disk    = body.mode.clone();
    let nat_disk     = body.nat_mode.clone();
    let peer_disk    = body.server_peer_id.clone();
    let socks5_disk  = body.socks5_port;
    s.config_file.update(|c| {
        if let Some(m) = mode_disk   { c.mode = Some(m); }
        if let Some(n) = nat_disk    { c.nat_mode = Some(n); }
        if let Some(p) = peer_disk   { c.peer_id = Some(p); }
        if let Some(p) = socks5_disk { c.socks5_port = p; }
    }).map_err(|e| ApiError::Internal(format!("persist: {e}")))?;

    // Mirror into the live Resolved so /config GET and other
    // handlers see the new values right away.
    let mut should_restart = false;
    let restart_mode;
    {
        let mut cfg = s.cfg.write().await;
        if let Some(m) = body.mode {
            if cfg.mode.as_deref() != Some(m.as_str()) {
                should_restart = true;
            }
            cfg.mode = Some(m);
        }
        if let Some(n) = body.nat_mode {
            should_restart |= cfg.nat_mode != n;
            cfg.nat_mode = n;
        }
        if let Some(p) = body.server_peer_id {
            // Client mode reads peer_id once at the top of
            // `run_client` and then parks — without kicking
            // run_mode, the new selection is ignored until the
            // next process restart. Republish current mode on
            // every peer_id change so the mode loop tears down
            // and re-enters with the fresh cfg.
            if cfg.peer_id.as_deref() != Some(p.as_str()) {
                should_restart = true;
            }
            cfg.peer_id = Some(p);
        }
        if let Some(p) = body.socks5_port {
            should_restart |= cfg.socks5_port != p;
            cfg.socks5_port = p;
        }
        restart_mode = cfg.mode.clone();
    }
    if should_restart {
        s.client.clear_error();
        // Best-effort: if there are no subscribers (run_mode
        // exited), the send fails silently — fine, the new
        // values will be picked up on the next connect.
        let _ = s.mode_tx.send(restart_mode);
    }
    Ok(Json(OkBody { ok: true }))
}

/// The shape the embedded HTML/JS UI expects from `/state`.
/// Names and fields mirror the Node app's response verbatim
/// (camelCase, nested `self`, separate `wsReady`/`wsConnecting`
/// flags) so the existing frontend renders without changes.
///
/// Some fields don't have a direct Rust equivalent yet (e.g.
/// `sessionExpired`, `versionMismatch`); they default to `false`
/// and will get wired through as the corresponding signaling
/// events are surfaced upward.
#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
struct StateBody {
    aggregate: crate::aggregate::Snapshot,
    aggregate_workers: Vec<crate::workers::Snapshot>,
    secure_mode: bool,
    peer_authenticated: bool,
    retry_after_seconds: u64,
    metrics: Option<serde_json::Value>,
    traffic: crate::client::TrafficSnapshot,
    server_call_privacy: Option<crate::server::CallPrivacySnapshot>,
    /// Token persisted? Drives login-vs-VPN view in the UI.
    token_set:          bool,
    /// `"client"` / `"server"` once chosen, `null` on first
    /// run. The UI shows a mode picker for the null case.
    mode:               Option<String>,
    /// Bale closed us with 4401 → token cleared. Sticky one-shot
    /// banner; the UI clears the flag after showing it.
    session_expired:    bool,
    /// Protocol mismatch (e.g. obsolete build); sticky banner.
    version_mismatch:   bool,
    /// Signed-in user info. `None` until `load_self` completes.
    #[serde(rename = "self")]
    self_info:          Option<SelfInfo>,
    /// WS handshake complete + ready for RPCs.
    ws_ready:           bool,
    /// Run loop active but handshake not yet done (initial dial
    /// or reconnect-backoff window). Distinct from intent —
    /// the rule engine may have intentionally NOT spawned the
    /// loop (e.g., during a call), in which case this is false.
    ws_connecting:      bool,
    /// WS is intentionally paused (rule engine sees an active
    /// client call → push channel not needed). UI renders this
    /// as "Paused (in call)" rather than "Disconnected" or
    /// "Connecting…".
    ws_paused:          bool,
    /// Client mode: user pressed Activate / config has peer set.
    /// Not currently surfaced — Rust always auto-activates on
    /// `--mode client` with a configured peer, so this just
    /// mirrors "the LK tunnel is up".
    client_activated:   bool,
    client_reconnecting: bool,
    auto_reconnect: bool,
    /// Client mode: LK room established AND peer joined.
    client_room_ready:  bool,
    /// Client mode: last place_call attempt got
    /// PlaceCallError::Rejected. Sticky until next Activate.
    client_rejected:    bool,
    /// Last failed attempt remains visible even after its session is torn down.
    client_error:       Option<String>,
    /// Server mode: how many connected LK rooms (= clients).
    lk_rooms:           usize,
    /// Client mode: LK channel up (peer hasn't necessarily
    /// joined yet). Used by the UI to distinguish "Connecting…"
    /// vs "Waiting for server to pick up…".
    lk_active:          bool,
    /// Client mode: bound SOCKS5 listener port (0 if not up).
    socks5_port:        u16,
    /// Currently active per-flow session count. Cosmetic.
    sessions:           u32,
    /// Client mode: the dialed peer's display info, for the
    /// "→ peer X" line in the status row.
    server_peer:        Option<PeerInfo>,
    /// Client-mode bytes counters for the status row.
    cli_tx_bytes:       u64,
    cli_rx_bytes:       u64,
}

#[derive(Serialize, Default)]
struct SelfInfo {
    id:   String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    nick: Option<String>,
}

#[derive(Serialize)]
struct PeerInfo {
    id:   String,
    name: String,
}

async fn get_state(State(s): State<Arc<AppState>>) -> Json<StateBody> {
    let cfg = s.cfg.read().await;
    let token_set = s.signaling.is_authenticated();
    let ws_ready  = s.signaling.is_connected();
    // "connecting" = run loop actively trying to handshake /
    // reconnect (`running && !ready`). NOT just "user wants
    // connection" (`is_connect_requested`) — the rule engine
    // intentionally tears the WS down during a client call
    // (call_active gate); intent stays true but the loop isn't
    // running, so showing "Connecting…" would be misleading.
    let ws_connecting = s.signaling.ws_is_attempting_connect();

    let self_info = if token_set {
        s.signaling.whoami().await.map(|p| SelfInfo {
            id:   p.id_str().to_string(),
            name: s.signaling.peer_display_name(&p).unwrap_or_default(),
            nick: s.signaling.account_identity().and_then(|u|u.nick),
        })
    } else {
        None
    };

    let (socks5_port, client_room_ready, cli_tx, cli_rx) = match s.client.snapshot().await {
        Some(snap) => (snap.socks5_port, snap.connected, snap.tx_bytes, snap.rx_bytes),
        None       => (cfg.socks5_port, false, 0, 0),
    };
    let lk_rooms = s.server.client_count().await;

    // Look up the configured peer's display name (best-effort —
    // empty if the cache hasn't seen them yet). Async because
    // resolve_peer is async on the trait surface.
    let is_client = cfg.mode.as_deref() == Some("client");
    let server_peer = if is_client {
        match &cfg.peer_id {
            Some(pid) => {
                let name = match s.signaling.resolve_peer(pid).await {
                    Some(p) => s.signaling.peer_display_name(&p).unwrap_or_default(),
                    None    => String::new(),
                };
                Some(PeerInfo { id: pid.clone(), name })
            }
            None => None,
        }
    } else {
        None
    };

    // ws_paused: client mode + LK room up. The rule engine has
    // pulled the WS down on call_active=true; this gives the UI a
    // way to render "Paused (in call)" instead of "Disconnected".
    let ws_paused = is_client && client_room_ready && !ws_ready;
    Json(StateBody {
        aggregate: s.aggregate.snapshot(),
        aggregate_workers: s.aggregate.workers.snapshots(),
        secure_mode: cfg.preferences.secure_mode,
        peer_authenticated: s.client.tunnel().is_some_and(|t|t.is_peer_authenticated()) || s.server.authenticated_count()>0,
        retry_after_seconds: s.attempts.lock().remaining(&cfg.preferences,std::time::Instant::now()).max(s.client.reconnect_status().1),
        metrics: s.client.tunnel().and_then(|t|t.connection_metrics()),
        traffic: s.client.traffic_snapshot(),
        server_call_privacy: if cfg.mode.as_deref() == Some("server") { Some(s.server.call_privacy()) } else { None },
        token_set,
        mode:              cfg.mode.clone(),
        self_info,
        ws_ready,
        ws_connecting,
        ws_paused,
        client_activated:  is_client && cfg.peer_id.is_some() && token_set,
        client_reconnecting: is_client && cfg.peer_id.is_some() && s.client.reconnect_status().0,
        auto_reconnect: cfg.preferences.auto_reconnect,
        client_error:      if is_client { s.client.last_error() } else { None },
        client_room_ready,
        lk_rooms,
        lk_active:         client_room_ready,
        socks5_port,
        server_peer,
        cli_tx_bytes:      cli_tx,
        cli_rx_bytes:      cli_rx,
        ..StateBody::default()
    })
}

// ─── /connect + /disconnect + /logout ─────────────────────────────────────

#[derive(Deserialize, Default)]
struct ConnectBody {
    /// Optional access_token to persist before connecting. The
    /// HTML UI uses this when the user pastes a Bale cookie —
    /// the backend writes it to the same `TokenStore` the
    /// signaling layer reads from, then proceeds to connect.
    #[serde(default)]
    token: Option<String>,
}

async fn connect(
    State(s): State<Arc<AppState>>,
    body: Option<Json<ConnectBody>>,
) -> Result<Json<OkBody>, ApiError> {
    // Optional body — UI's "Paste token" form sends `{token}`;
    // a programmatic re-connect after the token's already
    // saved doesn't.
    if let Some(Json(ConnectBody { token: Some(t) })) = body {
        let t = t.trim();
        if !t.is_empty() {
            s.auth.clear_completed_auth().await;
            s.token_store.save(t.as_bytes());
        }
    }
    s.signaling.connect().await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    if s.cfg.read().await.mode.as_deref() == Some("server") && s.server.call_privacy().error.is_some() {
        // A fresh activation retries an earlier failed privacy preparation.
        let state = s.clone();
        tokio::spawn(async move { let _ = state.server.allow_bale_calls(&state.signaling).await; });
    }
    Ok(Json(OkBody { ok: true }))
}

async fn allow_server_calls(State(s): State<Arc<AppState>>) -> Result<Json<OkBody>, ApiError> {
    if s.cfg.read().await.mode.as_deref() != Some("server") {
        return Err(ApiError::Internal("Call privacy can only be changed in Server mode".into()));
    }
    s.server.allow_bale_calls(&s.signaling).await.map_err(ApiError::Internal)?;
    Ok(Json(OkBody { ok: true }))
}

async fn disconnect(State(s): State<Arc<AppState>>) -> Json<OkBody> {
    // Server mode: drop every connected client first. Each
    // `tunnel.disconnect()` sends a participant-leave so the peer
    // gets a `callEnded` over the WS while it's still up — then we
    // tear the WS down. Matches the daemon's shutdown drain order.
    // No-op in client mode (no installed clients, no pending).
    s.server.clear_all().await;
    s.signaling.disconnect().await;
    Json(OkBody { ok: true })
}

async fn logout(State(s): State<Arc<AppState>>) -> Json<OkBody> {
    let _flow=s.auth_flow.lock().await;
    s.client.clear_error();
    s.server.reset_call_privacy();
    s.auth.clear_completed_auth().await;
    s.signaling.sign_out().await;

    // Mode reset: if the operator pinned the mode via `--mode`
    // on the CLI, leave it alone — they explicitly wanted this
    // mode and don't expect the picker on re-login. If it was
    // a user choice from the picker, clear both the live
    // Resolved.mode and the on-disk Config.mode so the next
    // sign-in shows the picker again.
    let pinned = s.cfg.read().await.mode_pinned_by_cli;
    if !pinned {
        s.cfg.write().await.mode = None;
        if let Err(e) = s.config_file.update(|c| { c.mode = None; }) {
            log::warn!("logout: clear mode: {e}");
        }
    }

    // Force the daemon's run_mode loop out of its current per-mode
    // parking and back to the auth-wait state. Without this push,
    // the mode loop keeps running against a disconnected WS until
    // some other state change wakes it.
    let _ = s.mode_tx.send(None);
    Json(OkBody { ok: true })
}

// ─── Auth ─────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct AuthStartBody { phone: String }

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthStartReply {
    ok:                bool,
    transaction_hash:  String,
    is_registered:     bool,
    sent_code_type:    i32,
    next_send_code_wait_time: Option<u64>,
}

async fn auth_start(
    State(s):   State<Arc<AppState>>,
    Json(body): Json<AuthStartBody>,
) -> Result<Json<AuthStartReply>, ApiError> {
    let _flow=s.auth_flow.lock().await;
    if s.signaling.is_authenticated(){return Err(ApiError::Internal("This account already has a saved session; no login code was requested".into()));}
    let device=crate::device::prepare_login(s.config_file.dir()).map_err(|_|ApiError::Internal("Could not save account device identity".into()))?;
    s.auth.use_device(&device.hash,&device.label).map_err(|e|ApiError::Internal(e.to_string()))?;
    let r: StartResult = s.auth.start_phone_auth(&body.phone).await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(Json(AuthStartReply {
        ok:                true,
        transaction_hash:  r.transaction_hash,
        is_registered:     r.is_registered,
        sent_code_type:    r.sent_code_type,
        next_send_code_wait_time: r.next_send_code_wait_time,
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthVerifyBody {
    transaction_hash: String,
    code:             String,
    /// From `/auth/start`. A registered phone that comes back with
    /// no JWT means a wrong/expired code — not a signup. Without
    /// this hint the empty-JWT response is ambiguous and gets
    /// misread as `NeedsSignupName`. Defaults to false so an older
    /// client that omits it keeps the prior (signup) behaviour.
    #[serde(default)]
    is_registered:    bool,
}

/// Response shape the embedded HTML/JS UI parses for both
/// `/auth/verify` and `/auth/signup`:
///   `{ok: true,  needsSignup: false}` → token saved server-side; caller polls /state.
///   `{ok: true,  needsSignup: true, transactionHash}` → collect a name + POST /auth/signup.
///   `{ok: false, error}` → re-try the flow.
#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
struct AuthReply {
    ok:                 bool,
    needs_signup:       bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    transaction_hash:   Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error:              Option<String>,
}

async fn auth_verify(
    State(s):   State<Arc<AppState>>,
    Json(body): Json<AuthVerifyBody>,
) -> Json<AuthReply> {
    let _flow=s.auth_flow.lock().await;
    match s.auth.submit_otp(&body.transaction_hash, &body.code).await {
        // A registered phone with no JWT isn't a signup — it's a
        // wrong/expired code. Surface it as an error instead of
        // sliding into the signup row.
        Ok(AuthOutcome::NeedsSignupName { .. }) if body.is_registered => Json(AuthReply {
            ok:    false,
            error: Some("Incorrect or expired code".into()),
            ..Default::default()
        }),
        Ok(outcome) => {let phone=s.auth.verified_login_phone(&body.transaction_hash).await;Json(persist_outcome(&s, outcome,phone).await)},
        Err(e)      => Json(AuthReply { ok: false, error: Some(e.to_string()), ..Default::default() }),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthSignupBody {
    transaction_hash: String,
    name:             String,
}

async fn auth_signup(
    State(s):   State<Arc<AppState>>,
    Json(body): Json<AuthSignupBody>,
) -> Json<AuthReply> {
    let _flow=s.auth_flow.lock().await;
    match s.auth.submit_signup_name(&body.transaction_hash, &body.name).await {
        Ok(outcome) => {let phone=s.auth.verified_login_phone(&body.transaction_hash).await;Json(persist_outcome(&s, outcome,phone).await)},
        Err(e)      => Json(AuthReply { ok: false, error: Some(e.to_string()), ..Default::default() }),
    }
}

/// Common tail for both verify + signup. On Authenticated,
/// persist the access_token through the same TokenStore the
/// signaling layer reads. Caller then `/connect`s explicitly.
async fn persist_outcome(s: &AppState, outcome: AuthOutcome,phone:Option<String>) -> AuthReply {
    match outcome {
        AuthOutcome::Authenticated { access_token } => {
            if crate::device::mark_authenticated(s.config_file.dir(),phone,access_token.as_bytes()).is_err(){return AuthReply{ok:false,error:Some("Could not save account device identity".into()),..Default::default()};}
            s.token_store.save(access_token.as_bytes());
            if s.token_store.load().as_deref()!=Some(access_token.as_bytes()){return AuthReply{ok:false,error:Some("Could not save account session".into()),..Default::default()};}
            // Kick the signaling layer to bring the WS up so /state
            // flips to authenticated quickly — otherwise the UI sits
            // on "Logging in…" until run_mode's 1-second auth-poll
            // tick catches up.
            let _ = s.signaling.connect().await;
            AuthReply { ok: true, needs_signup: false, ..Default::default() }
        }
        AuthOutcome::NeedsSignupName { transaction_hash } => AuthReply {
            ok:                true,
            needs_signup:      true,
            transaction_hash:  Some(transaction_hash),
            ..Default::default()
        },
    }
}

// ─── Contacts ─────────────────────────────────────────────────────────────
//
// Both `/peers` and `/contacts/search` return UI-shaped peer rows:
// `{id, name?, nick?}`. The embedded HTML uses `id` as a string
// (it's the Bale uid as decimal) and renders `name` / `nick` for
// the picker label. We strip the cursor (no infinite-scroll UI)
// and return all matches in one shot.

#[derive(Serialize)]
struct UiPeer {
    /// Bale uid as a decimal string. Matches what `nativePlaceCall`
    /// expects on the way back through `/connect` → place_call.
    id:   String,
    /// Display name (cached or empty). UI falls back to "(no name)".
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    nick: Option<String>,
}

#[derive(Serialize)]
struct PeersReply { peers: Vec<UiPeer> }

#[derive(Serialize)]
struct UsersReply { ok: bool, users: Vec<UiPeer> }

async fn list_peers(
    State(s):  State<Arc<AppState>>,
    Query(_):  Query<std::collections::HashMap<String, String>>,
) -> Json<PeersReply> {
    let page = match s.signaling.list_contacts(None, None, 200).await {
        Ok(p)  => p,
        Err(_) => return Json(PeersReply { peers: vec![] }),
    };
    let peers = page.peers.iter().map(|p| UiPeer {
        id:   p.id_str().to_string(),
        name: s.signaling.peer_display_name(p).unwrap_or_default(),
        nick: None,
    }).collect();
    Json(PeersReply { peers })
}

async fn refresh_peers(State(s): State<Arc<AppState>>) -> Json<OkBody> {
    // Force a fresh list_contacts pull; the cache lives in the
    // Bale impl and gets invalidated only on add/remove. This is
    // a no-op for cache freshness, but the UI hits it to mean
    // "go look again" — re-rendering the dropdown after the
    // result is enough.
    let _ = s.signaling.list_contacts(None, None, 200).await;
    Json(OkBody { ok: true })
}

#[derive(Deserialize)]
struct ContactSearchBody {
    // UI sends `{query: "..."}`; older Node app used `{phone}`.
    // Accept either to be permissive.
    #[serde(default)]
    query: Option<String>,
    #[serde(default)]
    phone: Option<String>,
}

async fn contacts_search(
    State(s):   State<Arc<AppState>>,
    Json(body): Json<ContactSearchBody>,
) -> Json<UsersReply> {
    let q = body.query.or(body.phone).unwrap_or_default();
    let peers = match s.signaling.search_contact_by_phone(&q).await {
        Ok(p)  => p,
        Err(_) => return Json(UsersReply { ok: true, users: vec![] }),
    };
    let users = peers.iter().map(|p| UiPeer {
        id:   p.id_str().to_string(),
        name: s.signaling.peer_display_name(p).unwrap_or_default(),
        nick: None,
    }).collect();
    Json(UsersReply { ok: true, users })
}

// ─── Server-mode admission ────────────────────────────────────────────────
//
// The UI uses `callerId` / `callerName` keys to match the Node
// app's response shape. Each id is a Bale uid (decimal string);
// `callerName` is the cached display name when known.

#[derive(Serialize)]
struct CallerRow {
    #[serde(rename = "callerId")]
    caller_id:   String,
    #[serde(rename = "callerName", skip_serializing_if = "Option::is_none")]
    caller_name: Option<String>,
}

/// Build a row with the cached display name (sync — never RPCs).
async fn caller_row(s: &AppState, id: &str) -> CallerRow {
    let name = match s.signaling.resolve_peer(id).await {
        Some(p) => s.signaling.peer_display_name(&p).filter(|n| !n.is_empty()),
        None    => None,
    };
    CallerRow { caller_id: id.to_string(), caller_name: name }
}

#[derive(Deserialize)]
struct CallerIdBody {
    #[serde(rename = "callerId")]
    caller_id:   String,
    // callerName isn't persisted server-side (we resolve via
    // peer_display_name). Accept-and-ignore for forwards compat.
    #[serde(default, rename = "callerName")]
    _caller_name: Option<String>,
}

async fn get_admission(State(s): State<Arc<AppState>>) -> Json<Vec<CallerRow>> {
    let ids = s.server.admission_list().await;
    let mut rows = Vec::with_capacity(ids.len());
    for id in ids { rows.push(caller_row(&s, &id).await); }
    Json(rows)
}
async fn add_admission(
    State(s): State<Arc<AppState>>,
    Json(b):  Json<CallerIdBody>,
) -> Json<OkBody> {
    s.server.admission_add(&b.caller_id).await;
    // Persist the new list to disk so the change survives a
    // daemon restart. ServerState is in-memory; the config file
    // is the source of truth at startup. Same pattern for the
    // sibling mutators below.
    let snapshot = s.server.admission_list().await;
    if let Err(e) = s.config_file.update(|c| c.admission = snapshot) {
        log::warn!("persist admission: {e}");
    }
    Json(OkBody { ok: true })
}
async fn remove_admission(
    State(s):       State<Arc<AppState>>,
    Path(caller_id): Path<String>,
) -> Json<OkBody> {
    s.server.admission_remove(&caller_id).await;
    let snapshot = s.server.admission_list().await;
    if let Err(e) = s.config_file.update(|c| c.admission = snapshot) {
        log::warn!("persist admission: {e}");
    }
    Json(OkBody { ok: true })
}

async fn get_blacklist(State(s): State<Arc<AppState>>) -> Json<Vec<CallerRow>> {
    let ids = s.server.blacklist_list().await;
    let mut rows = Vec::with_capacity(ids.len());
    for id in ids { rows.push(caller_row(&s, &id).await); }
    Json(rows)
}
async fn add_blacklist(
    State(s): State<Arc<AppState>>,
    Json(b):  Json<CallerIdBody>,
) -> Json<OkBody> {
    s.server.blacklist_add(&b.caller_id).await;
    let snapshot = s.server.blacklist_list().await;
    if let Err(e) = s.config_file.update(|c| c.blacklist = snapshot) {
        log::warn!("persist blacklist: {e}");
    }
    Json(OkBody { ok: true })
}
async fn remove_blacklist(
    State(s):       State<Arc<AppState>>,
    Path(caller_id): Path<String>,
) -> Json<OkBody> {
    s.server.blacklist_remove(&caller_id).await;
    let snapshot = s.server.blacklist_list().await;
    if let Err(e) = s.config_file.update(|c| c.blacklist = snapshot) {
        log::warn!("persist blacklist: {e}");
    }
    Json(OkBody { ok: true })
}

/// UI parses `{value, max}` — `value` = current cap, `max` =
/// hard upper bound for the input's `max` attribute.
#[derive(Serialize)]
struct MaxClientsReply { value: u32, max: u32 }
#[derive(Deserialize)]
struct MaxClientsBody  { value: u32 }

async fn get_max_clients(State(s): State<Arc<AppState>>) -> Json<MaxClientsReply> {
    Json(MaxClientsReply {
        value: s.server.max_clients(),
        max:   crate::daemon::KERNEL_TUN_SLOT_LIMIT as u32,
    })
}
async fn set_max_clients(
    State(s): State<Arc<AppState>>,
    Json(b):  Json<MaxClientsBody>,
) -> Json<OkBody> {
    s.server.set_max_clients(b.value).await;
    // Persist the new cap so it survives daemon restart —
    // ServerState.max_clients is in-memory only.
    let snapshot = s.server.max_clients();
    if let Err(e) = s.config_file.update(|c| c.max_clients = snapshot) {
        log::warn!("persist max_clients: {e}");
    }
    Json(OkBody { ok: true })
}

#[derive(Serialize)]
struct PendingRow {
    #[serde(rename = "callerId")]
    caller_id:   String,
    #[serde(rename = "callerName", skip_serializing_if = "Option::is_none")]
    caller_name: Option<String>,
    #[serde(rename = "receivedAt")]
    received_at: u64,
}

async fn get_pending(State(s): State<Arc<AppState>>) -> Json<Vec<PendingRow>> {
    let raw = s.server.pending_list().await;
    Json(raw.into_iter().map(|p| PendingRow {
        caller_id:   p.peer_id,
        caller_name: p.display_name.filter(|n| !n.is_empty()),
        received_at: p.received_at,
    }).collect())
}
#[derive(Deserialize, Default)]
struct AcceptPendingBody {
    /// "Allow always" sticky-add — bumps the caller into the
    /// allow-list so future calls auto-accept. "Accept once"
    /// leaves the list untouched.
    #[serde(default, rename = "addToList")]
    add_to_list: bool,
}

async fn accept_pending(
    State(s):       State<Arc<AppState>>,
    Path(peer_id):  Path<String>,
    body:           Option<Json<AcceptPendingBody>>,
) -> Json<OkBody> {
    s.server.pending_resolve(&peer_id, lk_signaling::CallDecision::Accept).await;
    if let Some(Json(AcceptPendingBody { add_to_list: true })) = body {
        s.server.admission_add(&peer_id).await;
        let snapshot = s.server.admission_list().await;
        if let Err(e) = s.config_file.update(|c| c.admission = snapshot) {
            log::warn!("persist admission: {e}");
        }
    }
    Json(OkBody { ok: true })
}
async fn reject_pending(
    State(s):       State<Arc<AppState>>,
    Path(peer_id):  Path<String>,
) -> Json<OkBody> {
    s.server.pending_resolve(&peer_id, lk_signaling::CallDecision::Reject).await;
    // Reject is always sticky — blacklists the caller. There's
    // no "decline once" option in the UI by design (matches the
    // Allow always / Allow once asymmetry: positive intent is
    // explicit, negative intent is sticky).
    s.server.blacklist_add(&peer_id).await;
    let snapshot = s.server.blacklist_list().await;
    if let Err(e) = s.config_file.update(|c| c.blacklist = snapshot) {
        log::warn!("persist blacklist: {e}");
    }
    Json(OkBody { ok: true })
}

/// End the current call. With auto-reconnect enabled, keep the
/// selected peer and schedule a replacement call after the call budget permits.
/// Otherwise clear the live peer and stay offline. The saved peer remains on
/// disk for future selection. Publish mode_tx to tear down the old session.
///
/// Does NOT touch the WS — the WS lifecycle is owned entirely
/// by the rule engine; the call going away will flip
/// `call_active=false` via the global LK observer and the WS
/// will resume on its own.
#[derive(Deserialize,Default)]
#[serde(default,rename_all="camelCase",deny_unknown_fields)]
struct DisconnectBody { pause_auto_reconnect: bool }
async fn tunnel_disconnect(State(s): State<Arc<AppState>>, body: Option<Json<DisconnectBody>>) -> Result<Json<OkBody>, ApiError> {
    // Account-transfer maintenance must keep the source stopped without
    // changing its saved auto-reconnect preference. Normal Disconnect honors it.
    let pause=body.is_some_and(|Json(b)|b.pause_auto_reconnect);
    // Keep the last peer on disk for restored UI selection. Startup always
    // clears the live peer before running a mode; this cannot auto-dial.
    // Ending a call must also work when the config filesystem is read-only.
    let restart_mode = {
        let mut cfg = s.cfg.write().await;
        s.client.clear_error();
        if cfg.preferences.auto_reconnect && cfg.peer_id.is_some() && !pause {
            let delay=cfg.preferences.retry_delay_secs.max(s.attempts.lock().remaining(&cfg.preferences,std::time::Instant::now()));
            s.client.reconnect_after(std::time::Duration::from_secs(delay));
        } else { cfg.peer_id = None; }
        cfg.mode.clone()
    };
    let _ = s.mode_tx.send(restart_mode);
    Ok(Json(OkBody { ok: true }))
}

// ─── Tunnel status ────────────────────────────────────────────────────────

#[derive(Serialize)]
struct TunnelStatus {
    /// `null` until the user has picked a mode.
    mode:           Option<String>,
    connected:      bool,
    socks5_bound:   Option<u16>,
    client_count:   usize,
}

async fn tunnel_status(State(s): State<Arc<AppState>>) -> Json<TunnelStatus> {
    let cfg = s.cfg.read().await;
    Json(TunnelStatus {
        mode:         cfg.mode.clone(),
        connected:    s.signaling.is_connected(),
        socks5_bound: s.client.socks5_bound_port().await,
        client_count: s.server.client_count().await,
    })
}

/// UI iterates the response as a plain Array<row>. Each row has
/// camelCase `callKey` (string id, = peer id), optional
/// `callerId` / `callerName`, plus per-flow counters.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TunnelClientRow {
    peer_authenticated: bool,
    call_key:    String,
    caller_id:   String,
    #[serde(skip_serializing_if = "Option::is_none")]
    caller_name: Option<String>,
    rx_bytes:    u64,
    tx_bytes:    u64,
    /// Absolute epoch-ms when this client connected. UI's
    /// `fmtAge` expects an epoch timestamp (not a duration)
    /// and renders `Date.now() - connectedAt` — a duration
    /// here yields `NaN` after the subtraction.
    connected_at: u64,
}

async fn tunnel_clients(State(s): State<Arc<AppState>>) -> Json<Vec<TunnelClientRow>> {
    let infos = s.server.client_infos().await;
    Json(infos.into_iter().map(|c| TunnelClientRow {
        peer_authenticated: c.authenticated,
        call_key:    c.peer_id.clone(),
        caller_id:   c.peer_id,
        caller_name: c.display_name.filter(|n| !n.is_empty()),
        rx_bytes:    c.rx_bytes,
        tx_bytes:    c.tx_bytes,
        connected_at: c.connected_at_ms,
    }).collect())
}

/// Kick a connected server-side client. Closes the LkTunnel
/// for the peer; LK signals participant-disconnect, Bale fires
/// callEnded, the server's events collector tears the entry
/// from `ServerState`. No-op in client mode (no per-peer entry
/// to kick).
async fn tunnel_client_disconnect(
    State(s):       State<Arc<AppState>>,
    Path(peer_id):  Path<String>,
) -> Json<OkBody> {
    s.server.remove_client(&peer_id).await;
    Json(OkBody { ok: true })
}

// ─── Boilerplate ──────────────────────────────────────────────────────────

#[derive(Serialize)]
struct OkBody { ok: bool }

/// Tiny error wrapper. Returns **200 + `{ok:false, error:..}`**
/// so the embedded HTML/JS UI (which checks `data.ok`, not the
/// HTTP status) can surface the message. Matches the Node app's
/// response shape — calling code stays branch-free.
#[derive(Debug)]
pub(crate) enum ApiError {
    Internal(String),
}
impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let Self::Internal(m) = self;
        // 200 OK; failure flag lives in the body. The 500 path
        // was a footgun — tower-http logs every failed call as
        // an alarming server error, and the UI never gets to
        // read the message because `fetch` rejects on non-2xx.
        (StatusCode::OK,
         Json(serde_json::json!({ "ok": false, "error": m })))
            .into_response()
    }
}

#[cfg(test)]
mod security_tests {
    use super::*;
    use axum::body::Body;
    use tower::ServiceExt;

    #[tokio::test]
    async fn management_origin_guard_blocks_browser_attacks() {
        let app = Router::new().route("/", get(|| async { "ok" }))
            .layer(middleware::from_fn(protect_management_ui));
        for (host, origin, site, expected) in [
            ("127.0.0.1:3001", None, None, StatusCode::OK),
            ("localhost:3001", Some("http://localhost:3001"), Some("same-origin"), StatusCode::OK),
            ("127.0.0.1:3001", None, Some("none"), StatusCode::OK),
            ("attacker.example:3001", None, None, StatusCode::FORBIDDEN),
            ("localhost.attacker.example:3001", None, None, StatusCode::FORBIDDEN),
            ("127.0.0.1:3001", Some("https://attacker.example"), None, StatusCode::FORBIDDEN),
            ("127.0.0.1:3001", Some("null"), None, StatusCode::FORBIDDEN),
            ("127.0.0.1:3001", Some("http://127.0.0.1:4001"), None, StatusCode::FORBIDDEN),
            ("127.0.0.1:3001", None, Some("cross-site"), StatusCode::FORBIDDEN),
            ("127.0.0.1:3001", None, Some("same-site"), StatusCode::FORBIDDEN),
        ] {
            let mut req = Request::builder().uri("/").header(header::HOST, host);
            if let Some(origin) = origin { req = req.header(header::ORIGIN, origin); }
            if let Some(site) = site { req = req.header("sec-fetch-site", site); }
            let response = app.clone().oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
            assert_eq!(response.status(), expected, "host={host}, origin={origin:?}, site={site:?}");
        }
        let response = app.oneshot(Request::builder().uri("/").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
