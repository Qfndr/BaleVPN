//! Independent single-account laboratory endpoint. Secrets travel only over stdin.
use async_trait::async_trait;
use igap_signaling::{
    auth::{RegistrationProfile, SessionRecord},
    IgapSignaling,
};
use lk_signaling::{
    CallDecision, EndReason, IncomingHandler, PeerId, Signaling, SignalingEvent, TokenStore,
    TransportSession, TunnelHooks,
};
use lktunnel::{security::Identity, EventKind, LkTunnel, TunnelRole};
use parking_lot::Mutex;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::{
    io::{BufRead, Read, Write},
    sync::Arc,
    time::Duration,
};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

const LIMIT: usize = 64 * 1024;
const ENDPOINT: &str = "wss://call.igap.net/";

struct MediaDiagnostic {
    publisher: AtomicU8,
    subscriber: AtomicU8,
    offer_sent: AtomicBool,
    sdp_error: AtomicU8,
}
static MEDIA_DIAGNOSTIC: MediaDiagnostic = MediaDiagnostic {
    publisher: AtomicU8::new(0),
    subscriber: AtomicU8::new(0),
    offer_sent: AtomicBool::new(false),
    sdp_error: AtomicU8::new(0),
};
impl MediaDiagnostic {
    fn observe(&self, text: &str) {
        let Some((prefix, body)) = text.split_once("]: ") else {
            return;
        };
        let Some(id) = prefix.strip_prefix("rtc[") else {
            return;
        };
        if id.is_empty() || !id.bytes().all(|b| b.is_ascii_digit()) {
            return;
        }
        let state = |s: &str| match s {
            "new" => 1,
            "connecting" => 2,
            "connected" => 3,
            "disconnected" => 4,
            "failed" => 5,
            "closed" => 6,
            _ => 0,
        };
        if let Some(s) = body.strip_prefix("publisher PC → ") {
            let n = state(s);
            if n > 0 {
                self.publisher.store(n, Ordering::Relaxed);
            }
        }
        if let Some(s) = body.strip_prefix("subscriber PC → ") {
            let n = state(s);
            if n > 0 {
                self.subscriber.store(n, Ordering::Relaxed);
            }
        }
        if body.starts_with("publisher offer sent (") && body.ends_with(" track[s])") {
            self.offer_sent.store(true, Ordering::Relaxed);
        }
        for (prefix, code) in [
            ("sub set_remote: ", 1),
            ("sub set_local: ", 2),
            ("pub set_remote: ", 3),
            ("parse offer: ", 4),
            ("parse answer: ", 5),
        ] {
            if body.starts_with(prefix) {
                self.sdp_error.store(code, Ordering::Relaxed);
            }
        }
    }
    fn snapshot(&self) -> Value {
        let state = |n: u8| match n {
            1 => "new",
            2 => "connecting",
            3 => "connected",
            4 => "disconnected",
            5 => "failed",
            6 => "closed",
            _ => "unobserved",
        };
        json!({"publisherState":state(self.publisher.load(Ordering::Relaxed)),"subscriberState":state(self.subscriber.load(Ordering::Relaxed)),"offerSent":self.offer_sent.load(Ordering::Relaxed),"sdpErrorCode":self.sdp_error.load(Ordering::Relaxed)})
    }
}
impl log::Log for MediaDiagnostic {
    fn enabled(&self, m: &log::Metadata<'_>) -> bool {
        m.target() == "lktunnel::rtc" && m.level() <= log::Level::Info
    }
    fn log(&self, record: &log::Record<'_>) {
        if self.enabled(record.metadata()) {
            self.observe(&format!("{}", record.args()));
        }
    }
    fn flush(&self) {}
}

#[derive(Default)]
struct MemoryStore(Mutex<Option<Zeroizing<Vec<u8>>>>);
impl TokenStore for MemoryStore {
    fn load(&self) -> Option<Vec<u8>> {
        self.0.lock().as_ref().map(|x| x.to_vec())
    }
    fn save(&self, b: &[u8]) {
        *self.0.lock() = Some(Zeroizing::new(b.to_vec()));
    }
    fn clear(&self) {
        *self.0.lock() = None;
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Config {
    command: String,
    session_record: SessionRecord,
    role: String,
    expected_peer: String,
    trusted_certificates: Vec<String>,
    socks_port: u16,
    throughput: bool,
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn pairing(items: &[String], own: &[u8]) -> Result<Vec<Vec<u8>>, &'static str> {
    if items.is_empty() || items.len() > 8 {
        return Err("invalid_pairing");
    }
    let mut result = Vec::new();
    for text in items {
        if !(128..=16384).contains(&text.len())
            || text.len() % 2 != 0
            || !text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("invalid_pairing");
        }
        let cert = (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|_| "invalid_pairing"))
            .collect::<Result<Vec<_>, _>>()?;
        if cert == own || result.contains(&cert) {
            return Err("invalid_pairing");
        }
        result.push(cert);
    }
    Ok(result)
}
fn configuration(
    line: &[u8],
    own: &[u8],
) -> Result<(Config, TunnelRole, Vec<Vec<u8>>), &'static str> {
    let c: Config = serde_json::from_slice(line).map_err(|_| "invalid_config")?;
    c.session_record.validate().map_err(|_| "invalid_session")?;
    if c.command != "configure"
        || c.expected_peer == c.session_record.user_id
        || c.expected_peer
            .parse::<u64>()
            .ok()
            .filter(|id| *id > 0)
            .map(|id| id.to_string())
            .as_deref()
            != Some(c.expected_peer.as_str())
        || (c.socks_port != 0 && c.socks_port < 1024)
    {
        return Err("invalid_config");
    }
    let role = match c.role.as_str() {
        "client" => TunnelRole::Client,
        "server" => TunnelRole::Server,
        _ => return Err("invalid_role"),
    };
    let certs = pairing(&c.trusted_certificates, own)?;
    Ok((c, role, certs))
}
fn output(v: Value) -> Result<(), &'static str> {
    let mut out = std::io::stdout().lock();
    serde_json::to_writer(&mut out, &v).map_err(|_| "output_closed")?;
    out.write_all(b"\n")
        .and_then(|_| out.flush())
        .map_err(|_| "output_closed")
}
// Never forward Event.info: signaling errors may include private URLs or JWTs.
fn media_reason(kind: &EventKind, info: &str) -> &'static str {
    match kind {
        EventKind::Connected => "connected",
        EventKind::PeerJoined => "peer_joined",
        EventKind::PeerLeft => "peer_left",
        EventKind::Disconnected | EventKind::Error => match info {
            "publisher PC failed" => "publisher_pc_failed",
            "publisher PC closed" => "publisher_pc_closed",
            "subscriber PC failed" => "subscriber_pc_failed",
            "subscriber PC closed" => "subscriber_pc_closed",
            "signal stream ended" => "signal_ended",
            "server leave" => "server_leave",
            "remote carrier track ended" => "carrier_track_ended",
            text if text.starts_with("signal closed: ") => "signal_closed",
            text if leave_metadata(text).is_some() => "server_leave",
            _ => "transport_failed",
        },
    }
}
fn end_reason(reason: EndReason) -> &'static str {
    match reason {
        EndReason::Rejected => "rejected",
        EndReason::CallerHangup => "caller_hangup",
        EndReason::Timeout => "timeout",
        EndReason::NetworkDrop => "network_drop",
        EndReason::Other(_) => "other",
    }
}
fn leave_metadata(info: &str) -> Option<Value> {
    let rest = info.strip_prefix("server leave reason=")?;
    let (reason, rest) = rest.split_once(" action=")?;
    let (action, reconnect) = rest.split_once(" reconnect=")?;
    let code = |text: &str, max: i32| -> Option<Option<i32>> {
        if text == "-1" {
            return Some(None);
        }
        let value = text.parse::<i32>().ok()?;
        if !(0..=max).contains(&value) || value.to_string() != text {
            return None;
        }
        Some(Some(value))
    };
    Some(
        json!({"reasonCode":code(reason,16)?,"actionCode":code(action,2)?,"canReconnect":match reconnect {"0"=>false,"1"=>true,_=>return None}}),
    )
}
// Bounded before parsing, zeroized on consumption; never materialize token in Value.
fn read_command(input: &mut impl BufRead) -> Result<Option<Zeroizing<Vec<u8>>>, &'static str> {
    let mut line = Zeroizing::new(Vec::new());
    match input.take((LIMIT + 1) as u64).read_until(b'\n', &mut line) {
        Ok(0) => Ok(None),
        Ok(_) if line.len() > LIMIT || line.last() != Some(&b'\n') => Err("invalid_command"),
        Ok(_) => Ok(Some(line)),
        Err(_) => Err("input_closed"),
    }
}
fn reader() -> mpsc::Receiver<Result<Zeroizing<Vec<u8>>, &'static str>> {
    let (tx, rx) = mpsc::channel(4);
    std::thread::spawn(move || {
        let mut input = std::io::stdin().lock();
        loop {
            let result = match read_command(&mut input) {
                Ok(None) => return,
                Ok(Some(line)) => Ok(line),
                Err(e) => Err(e),
            };
            let failed = result.is_err();
            if tx.blocking_send(result).is_err() || failed {
                return;
            }
        }
    });
    rx
}
fn command(line: &[u8], expected: &str) -> bool {
    serde_json::from_slice::<Value>(line).ok() == Some(json!({"command":expected}))
}
async fn stop_only(
    rx: &mut mpsc::Receiver<Result<Zeroizing<Vec<u8>>, &'static str>>,
) -> Result<(), &'static str> {
    match rx.recv().await {
        None => Ok(()),
        Some(Ok(line)) if command(&line, "stop") => Ok(()),
        Some(Err(e)) => Err(e),
        _ => Err("invalid_control_command"),
    }
}
fn control_mode(args: &[String]) -> Option<bool> {
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["--control-stdin"] => Some(false),
        ["--control-stdin", "--defer-media"] => Some(true),
        _ => None,
    }
}
fn media_start_command(line: &[u8]) -> Result<bool, &'static str> {
    if command(line, "startMedia") {
        Ok(true)
    } else if command(line, "stop") {
        Ok(false)
    } else {
        Err("invalid_control_command")
    }
}
struct Admission(PeerId);
#[async_trait]
impl IncomingHandler for Admission {
    async fn decide(&self, peer: PeerId, _: Option<String>) -> CallDecision {
        if peer == self.0 {
            CallDecision::Accept
        } else {
            CallDecision::SilentlyIgnore
        }
    }
}
struct Disconnect(Arc<LkTunnel>);
impl Drop for Disconnect {
    fn drop(&mut self) {
        self.0.disconnect();
    }
}

async fn run(
    identity: &mut Identity,
    app: &IgapSignaling,
    rx: &mut mpsc::Receiver<Result<Zeroizing<Vec<u8>>, &'static str>>,
    defer_media: bool,
) -> Result<(), &'static str> {
    let line = tokio::time::timeout(Duration::from_secs(60), rx.recv())
        .await
        .map_err(|_| "config_timeout")?
        .ok_or("input_closed")??;
    if command(&line, "stop") {
        return Ok(());
    }
    let (config, role, certs) = configuration(&line, &identity.certificate)?;
    drop(line);
    let options = identity
        .options(&certs, role == TunnelRole::Server, config.throughput)
        .map_err(|_| "invalid_pairing")?;
    identity.private_key.fill(0);
    let Config {
        session_record,
        expected_peer,
        socks_port,
        ..
    } = config;
    tokio::select! {
        result=app.restore(session_record)=>{result.map_err(|_|"restore_failed")?;},
        stop=stop_only(rx)=>return stop,
    }
    let peer = app
        .resolve_peer(&expected_peer)
        .await
        .ok_or("invalid_peer")?;
    app.set_allowed_peers(&[expected_peer])
        .map_err(|_| "invalid_peer")?;
    let mut signaling_events = app.events();
    let mut accepted = app.accepted_sessions();
    output(
        json!({"event":"authenticated","authenticated":app.is_authenticated(),"dialed":false,"listening":false}),
    )?;
    let mut health = tokio::time::interval(Duration::from_secs(1));
    health.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let line = loop {
        tokio::select! {
            line=rx.recv()=>break line.ok_or("input_closed")??,
            _=health.tick()=>if !app.is_connected() {return Err("signaling_disconnected");},
            event=signaling_events.recv()=>match event {
                Some(SignalingEvent::AuthExpired)=>return Err("auth_expired"),
                Some(SignalingEvent::ProtocolObsolete)=>return Err("protocol_obsolete"),
                None=>return Err("signaling_closed"),_=>{}
            }
        }
    };
    if command(&line, "stop") {
        return Ok(());
    }
    let session: TransportSession = if role == TunnelRole::Server {
        if !command(&line, "listen") {
            return Err("invalid_control_command");
        }
        app.set_incoming_handler(Box::new(Admission(peer.clone())));
        output(json!({"event":"listening","listening":true}))?;
        loop {
            tokio::select! {
                result=accepted.recv()=>{
                    let (sender,session)=result.ok_or("signaling_closed")?;
                    if sender!=peer {return Err("unexpected_peer");}
                    break session;
                },
                stop=stop_only(rx)=>return stop,
                _=health.tick()=>if !app.is_connected() {return Err("signaling_disconnected");},
                event=signaling_events.recv()=>match event {
                    Some(SignalingEvent::AuthExpired)=>return Err("auth_expired"),
                    Some(SignalingEvent::ProtocolObsolete)=>return Err("protocol_obsolete"),
                    Some(SignalingEvent::CallEnded{reason,..})=>{output(json!({"event":"callEnded","reason":end_reason(reason),"serviceLeave":app.service_leave_diagnostic()}))?;return Err("call_ended");},
                    None=>return Err("signaling_closed"),_=>{}
                }
            }
        }
    } else {
        if !command(&line, "connect") {
            return Err("invalid_control_command");
        }
        output(json!({"event":"calling"}))?;
        // Keep the future and its call lease alive until service leave has
        // been attempted; dropping it first would remove local room ownership.
        let placing = app.place_call(peer.clone());
        tokio::pin!(placing);
        tokio::select! {
            result=&mut placing=>result.map_err(|_|"call_failed")?,
            stop=stop_only(rx)=>{
                let _=tokio::time::timeout(Duration::from_secs(10),app.hang_up()).await;
                return stop;
            },
        }
    };
    if session.url != ENDPOINT || session.peer_id != peer {
        return Err("invalid_transport_session");
    }
    output(
        json!({"event":"transportSession","role":if role==TunnelRole::Server {"server"} else {"client"},"serviceLeave":app.service_leave_diagnostic(),"deferredMediaStart":defer_media}),
    )?;
    // Diagnostic only: reproduce the successful laboratory's simultaneous
    // start without transferring room tokens between endpoint processes.
    if defer_media {
        let deadline = tokio::time::sleep(Duration::from_secs(20));
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                line=rx.recv()=>{
                    let Some(line)=line else {return Ok(());};
                    if !media_start_command(&line?)? {return Ok(());}
                    break;
                },
                _=&mut deadline=>return Err("media_start_timeout"),
                _=health.tick()=>if !app.is_connected() {return Err("signaling_disconnected");},
                event=signaling_events.recv()=>match event {
                    Some(SignalingEvent::CallEnded{..})=>return Err("call_ended"),
                    Some(SignalingEvent::AuthExpired)=>return Err("auth_expired"),
                    Some(SignalingEvent::ProtocolObsolete)=>return Err("protocol_obsolete"),
                    None=>return Err("signaling_closed"),_=>{}
                }
            }
        }
    }
    let tunnel = LkTunnel::connect_with_options(ENDPOINT, session.token, role, options);
    let _disconnect = Disconnect(tunnel.clone());
    let mut media_events = tunnel.events().ok_or("media_events_unavailable")?;
    let deadline = tokio::time::sleep(Duration::from_secs(50));
    tokio::pin!(deadline);
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut connected = false;
    loop {
        tokio::select! {
            stop=stop_only(rx)=>return stop,
            _=&mut deadline,if !tunnel.is_peer_authenticated()=>return Err("authentication_timeout"),
            event=signaling_events.recv()=>match event {
                Some(SignalingEvent::CallEnded{reason,..})=>{output(json!({"event":"callEnded","reason":end_reason(reason),"serviceLeave":app.service_leave_diagnostic()}))?;return Err("call_ended");},
                Some(SignalingEvent::AuthExpired)=>return Err("auth_expired"),
                Some(SignalingEvent::ProtocolObsolete)=>return Err("protocol_obsolete"),
                None=>return Err("signaling_closed"),_=>{}
            },
            event=media_events.recv()=>{
                let event=event.ok_or("media_closed")?;
                output(json!({"event":"mediaEvent","reason":media_reason(&event.kind,&event.info),"serverLeave":leave_metadata(&event.info),"mediaDiagnostic":MEDIA_DIAGNOSTIC.snapshot()}))?;
                match event.kind {
                EventKind::Connected if !connected=>{
                    connected=true;
                    if role==TunnelRole::Server {tunnel.start_server().map_err(|_|"server_setup_failed")?;}
                    else {tokio::select! {
                        result=tunnel.enable_socks5_server(socks_port)=>{let address=result.map_err(|_|"proxy_bind_failed")?;output(json!({"event":"proxyBound","port":address.port()}))?;},
                        stop=stop_only(rx)=>return stop,
                    }}
                    output(json!({"event":"mediaConnected","peerAuthenticated":tunnel.is_peer_authenticated(),"proxyReady":tunnel.is_proxy_ready()}))?;
                },
                EventKind::Disconnected|EventKind::PeerLeft=>return Err("media_disconnected"),
                EventKind::Error=>return Err("media_failed"),_=>{}
                }
            },
            _=interval.tick()=>{
                if !app.is_connected() {return Err("signaling_disconnected");}
                let stats=tunnel.stats();
                output(json!({"event":"metrics","mediaConnected":tunnel.is_connected(),"peerAuthenticated":tunnel.is_peer_authenticated(),"proxyReady":tunnel.is_proxy_ready(),"receivedBytes":stats[1],"sentBytes":stats[3],"quic":tunnel.connection_metrics(),"mediaDiagnostic":MEDIA_DIAGNOSTIC.snapshot(),"billingVerified":false,"providerPathVerified":false}))?;
            }
        }
    }
}
fn main() -> std::process::ExitCode {
    let Some(defer_media) = control_mode(&std::env::args().skip(1).collect::<Vec<_>>()) else {
        let _ = output(json!({"event":"error","reason":"explicit_control_required"}));
        return std::process::ExitCode::FAILURE;
    };
    std::panic::set_hook(Box::new(|_| {
        let _ = output(json!({"event":"error","reason":"endpoint_panic"}));
    }));
    if std::env::var_os("SSLKEYLOGFILE").is_some()
        || std::env::var("NODE_TLS_REJECT_UNAUTHORIZED")
            .ok()
            .as_deref()
            == Some("0")
    {
        let _ = output(json!({"event":"error","reason":"unsafe_environment"}));
        return std::process::ExitCode::FAILURE;
    }
    // Standalone binary only: select ring for media's inherited rustls builders.
    let _ = rustls::crypto::ring::default_provider().install_default();
    // No console/file logger. Only exact module state messages become enums.
    if log::set_logger(&MEDIA_DIAGNOSTIC).is_err() {
        return std::process::ExitCode::FAILURE;
    }
    log::set_max_level(log::LevelFilter::Info);
    let Ok(mut identity) = Identity::generate() else {
        let _ = output(json!({"event":"error","reason":"identity_failed"}));
        return std::process::ExitCode::FAILURE;
    };
    if output(json!({"event":"identity","protocol":1,"certificate":hex(&identity.certificate)}))
        .is_err()
    {
        return std::process::ExitCode::FAILURE;
    }
    let result = lktunnel::runtime().block_on(async {
        let app = IgapSignaling::new(
            Arc::new(MemoryStore::default()),
            RegistrationProfile::Independent,
        );
        let result = run(&mut identity, &app, &mut reader(), defer_media).await;
        let _ = tokio::time::timeout(Duration::from_secs(10), app.hang_up()).await;
        app.disconnect().await;
        result
    });
    identity.private_key.fill(0);
    match result {
        Ok(()) => {
            let _ = output(json!({"event":"stopped"}));
            std::process::ExitCode::SUCCESS
        }
        Err(reason) => {
            let _ = output(json!({"event":"error","reason":reason}));
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn controls_are_exact() {
        assert!(command(br#"{"command":"stop"}"#, "stop"));
        assert!(!command(br#"{"command":"stop","token":"secret"}"#, "stop"));
        assert!(!command(br#"{"command":"connect"}"#, "listen"));
        assert_eq!(control_mode(&[]), None);
        assert_eq!(control_mode(&["--control-stdin".into()]), Some(false));
        assert_eq!(
            control_mode(&["--control-stdin".into(), "--defer-media".into()]),
            Some(true)
        );
        assert_eq!(control_mode(&["--defer-media".into()]), None);
        assert_eq!(
            media_start_command(br#"{"command":"startMedia"}"#),
            Ok(true)
        );
        assert_eq!(media_start_command(br#"{"command":"stop"}"#), Ok(false));
        assert!(media_start_command(br#"{"command":"connect"}"#).is_err());
        assert!(media_start_command(br#"{"command":"startMedia","token":"private"}"#).is_err());
    }
    #[test]
    fn pairing_rejects_empty_duplicate_self_and_nonhex() {
        assert!(pairing(&[], &[]).is_err());
        assert!(pairing(&["aa".repeat(80)], &vec![0xaa; 80]).is_err());
        assert!(pairing(&["aa".repeat(80), "aa".repeat(80)], &[]).is_err());
        assert!(pairing(&["zz".repeat(80)], &[]).is_err());
        assert!(pairing(&["aa".repeat(80)], &[]).is_ok());
    }
    fn fixture() -> Value {
        json!({"command":"configure","sessionRecord":{
            "provider":"igap","userId":"41","token":"fixture-token",
            "profile":igap_signaling::auth::Profile::new(RegistrationProfile::WebV3Compatibility),
            "loginPhone":"","needsProfile":false
        },"role":"client","expectedPeer":"42","trustedCertificates":["aa".repeat(80)],"socksPort":1094,"throughput":true})
    }
    #[test]
    fn config_rejects_cross_account_unsafe_ports_and_unknown_options() {
        let original = fixture();
        assert!(configuration(&serde_json::to_vec(&original).unwrap(), &[]).is_ok());
        for (key, value) in [
            ("expectedPeer", json!("41")),
            ("expectedPeer", json!("042")),
            ("expectedPeer", json!("0")),
            ("role", json!("relay")),
            ("socksPort", json!(80)),
            ("allowUnauthenticated", json!(true)),
        ] {
            let mut input = original.clone();
            input[key] = value;
            assert!(
                configuration(&serde_json::to_vec(&input).unwrap(), &[]).is_err(),
                "{key}"
            );
        }
        let mut other = original;
        other["sessionRecord"]["provider"] = json!("bale");
        assert!(configuration(&serde_json::to_vec(&other).unwrap(), &[]).is_err());
    }
    #[test]
    fn reader_bounds_before_parsing_and_rejects_truncated_input() {
        assert!(read_command(&mut std::io::Cursor::new(Vec::<u8>::new()))
            .unwrap()
            .is_none());
        assert!(read_command(&mut std::io::Cursor::new(
            b"{\"command\":\"stop\"}".to_vec()
        ))
        .is_err());
        let mut oversized = vec![b'x'; LIMIT + 100];
        oversized.push(b'\n');
        let mut input = std::io::Cursor::new(oversized);
        assert!(read_command(&mut input).is_err());
        assert_eq!(input.position(), (LIMIT + 1) as u64);
        let mut lines = std::io::Cursor::new(b"{\"command\":\"stop\"}\nsecond\n".to_vec());
        assert!(command(&read_command(&mut lines).unwrap().unwrap(), "stop"));
        assert_eq!(
            read_command(&mut lines).unwrap().unwrap().as_slice(),
            b"second\n"
        );
    }
    #[test]
    fn media_diagnostics_cannot_echo_private_context() {
        assert_eq!(
            media_reason(&EventKind::Disconnected, "publisher PC failed"),
            "publisher_pc_failed"
        );
        assert_eq!(
            media_reason(
                &EventKind::Error,
                "signal closed: wss://secret.invalid/token"
            ),
            "signal_closed"
        );
        assert_eq!(
            media_reason(&EventKind::Error, "secret-token"),
            "transport_failed"
        );
        assert_eq!(
            leave_metadata("server leave reason=0 action=1 reconnect=0"),
            Some(json!({"reasonCode":0,"actionCode":1,"canReconnect":false}))
        );
        for s in [
            "server leave reason=17 action=0 reconnect=0",
            "server leave reason=0 action=0 reconnect=0 secret",
            "server leave reason=0 action=0 reconnect=0\nsecret",
        ] {
            assert!(leave_metadata(s).is_none());
        }
    }
    #[test]
    fn rtc_logger_maps_only_fixed_states_without_exposing_log_context() {
        let d = MediaDiagnostic {
            publisher: AtomicU8::new(0),
            subscriber: AtomicU8::new(0),
            offer_sent: AtomicBool::new(false),
            sdp_error: AtomicU8::new(0),
        };
        d.observe("rtc[19]: publisher PC → connecting");
        d.observe("rtc[19]: subscriber PC → connected");
        d.observe("rtc[19]: publisher offer sent (1 track[s])");
        d.observe("rtc[19]: sub set_remote: private token and SDP");
        assert_eq!(
            d.snapshot(),
            json!({"publisherState":"connecting","subscriberState":"connected","offerSent":true,"sdpErrorCode":1})
        );
        for text in [
            "rtc[private-token]: publisher PC → failed",
            "rtc[19]: publisher PC → private-token",
            "rtc[19]: subscriber PC → connected secret",
            "secret-url",
        ] {
            d.observe(text);
        }
        assert_eq!(d.snapshot()["publisherState"], json!("connecting"));
        assert_eq!(d.snapshot()["subscriberState"], json!("connected"));
        assert!(!d.snapshot().to_string().contains("private"));
    }
}
