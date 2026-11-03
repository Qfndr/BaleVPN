//! Experimental, pipe-controlled iGap media bridge. No token in argv/env/files.
//! This does not authenticate a messenger account or certify carrier billing.
use lktunnel::{security::Identity, EventKind, LkTunnel, TunnelRole};
use serde_json::{json, Value};
use std::io::{BufRead, Read, Write};
use std::time::Duration;
use tokio::sync::mpsc;

const MAX_COMMAND: usize = 64 * 1024;
const ENDPOINT: &str = "wss://call.igap.net/";

fn server_leave_metadata(info: &str) -> Option<Value> {
    let rest=info.strip_prefix("server leave reason=")?;
    let (reason,rest)=rest.split_once(" action=")?;
    let (action,reconnect)=rest.split_once(" reconnect=")?;
    let code=|text:&str,max:i32| -> Option<Option<i32>> {
        if text=="-1" {return Some(None);}
        let value=text.parse::<i32>().ok()?;
        if !(0..=max).contains(&value)||value.to_string()!=text {return None;}
        Some(Some(value))
    };
    let reason=code(reason,16)?;let action=code(action,2)?;
    let reconnect=match reconnect {"0"=>false,"1"=>true,_=>return None};
    Some(json!({"event":"serverLeave","reasonCode":reason,"actionCode":action,"canReconnect":reconnect}))
}

// Event.info may contain identities or server text. Classify only known engine
// messages and emit fixed codes; never forward the original context to IPC.
fn disconnect_reason(kind: &EventKind, info: &str, fallback: &'static str) -> &'static str {
    if *kind == EventKind::PeerLeft {
        return "peer_left";
    }
    if !matches!(kind, EventKind::Disconnected | EventKind::Error) {
        return fallback;
    }
    if server_leave_metadata(info).is_some() {return "server_leave";}
    match info {
        "publisher PC failed" => "publisher_pc_failed",
        "publisher PC closed" => "publisher_pc_closed",
        "subscriber PC failed" => "subscriber_pc_failed",
        "subscriber PC closed" => "subscriber_pc_closed",
        "signal stream ended" => "signal_ended",
        "server leave" => "server_leave",
        "remote carrier track ended" => "carrier_track_ended",
        text if text.starts_with("signal closed: ") => "signal_closed",
        _ => fallback,
    }
}

fn output(value: Value) -> Result<(), &'static str> {
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &value).map_err(|_| "output_closed")?;
    stdout.write_all(b"\n").map_err(|_| "output_closed")?;
    stdout.flush().map_err(|_| "output_closed")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn certificate(value: &Value) -> Result<Vec<u8>, &'static str> {
    let text = value.as_str().ok_or("invalid_pairing")?;
    if !(128..=16384).contains(&text.len()) || text.len() % 2 != 0 ||
        !text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
        return Err("invalid_pairing");
    }
    (0..text.len()).step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at+2], 16).map_err(|_| "invalid_pairing"))
        .collect()
}

struct Config {
    token: String,
    role: TunnelRole,
    trusted: Vec<Vec<u8>>,
    port: u16,
    throughput: bool,
}

fn config(value: Value, own: &[u8]) -> Result<Config, &'static str> {
    let object = value.as_object().ok_or("invalid_config")?;
    let allowed = ["command", "provider", "url", "token", "role", "trustedCertificates", "socksPort", "throughput"];
    if object.keys().any(|key| !allowed.contains(&key.as_str())) ||
        value["command"] != "connect" || value["provider"] != "igap" || value["url"] != ENDPOINT {
        return Err("invalid_config");
    }
    let role = match value["role"].as_str() {
        Some("client") => TunnelRole::Client,
        Some("server") => TunnelRole::Server,
        _ => return Err("invalid_role"),
    };
    let token = value["token"].as_str().ok_or("invalid_token")?;
    let parts: Vec<_> = token.split('.').collect();
    if token.len() > 16384 || parts.len() != 3 || parts.iter().any(|part| part.is_empty() ||
        !part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')) {
        return Err("invalid_token");
    }
    let items = value["trustedCertificates"].as_array().ok_or("invalid_pairing")?;
    if items.is_empty() || items.len() > 8 { return Err("invalid_pairing"); }
    let mut trusted = Vec::new();
    for item in items {
        let cert = certificate(item)?;
        if cert == own || trusted.contains(&cert) { return Err("invalid_pairing"); }
        trusted.push(cert);
    }
    let port = value["socksPort"].as_u64().ok_or("invalid_port")?;
    if port > 65535 || (port != 0 && port < 1024) { return Err("invalid_port"); }
    let throughput = value["throughput"].as_bool().ok_or("invalid_profile")?;
    Ok(Config {token: token.to_owned(), role, trusted, port: port as u16, throughput})
}

// Bound allocations before parsing JSON. EOF/oversized input closes the native
// tunnel, including when the parent dies during initial connection setup.
fn reader() -> mpsc::Receiver<Result<Value, &'static str>> {
    let (tx, rx) = mpsc::channel(4);
    std::thread::spawn(move || {
        let mut input = std::io::stdin().lock();
        loop {
            let mut line = Vec::new();
            let read = (&mut input).take((MAX_COMMAND + 1) as u64).read_until(b'\n', &mut line);
            let result = match read {
                Ok(0) => return,
                Ok(_) if line.len() > MAX_COMMAND || line.last() != Some(&b'\n') => Err("invalid_command"),
                Ok(_) => serde_json::from_slice(&line).map_err(|_| "invalid_command"),
                Err(_) => Err("input_closed"),
            };
            line.fill(0);
            let failed = result.is_err();
            if tx.blocking_send(result).is_err() || failed { return; }
        }
    });
    rx
}

struct Disconnect(std::sync::Arc<LkTunnel>);
impl Drop for Disconnect { fn drop(&mut self) { self.0.disconnect(); } }

async fn run(mut identity: Identity, mut commands: mpsc::Receiver<Result<Value, &'static str>>)
    -> Result<(), &'static str> {
    let command = tokio::time::timeout(Duration::from_secs(60), commands.recv()).await
        .map_err(|_| "config_timeout")?.ok_or("input_closed")??;
    if command == json!({"command": "stop"}) { return Ok(()); }
    let config = config(command, &identity.certificate)?;
    let options = identity.options(&config.trusted, config.role == TunnelRole::Server, config.throughput)
        .map_err(|_| "invalid_pairing")?;
    identity.private_key.fill(0);
    let tunnel = LkTunnel::connect_with_options(ENDPOINT, config.token, config.role, options);
    let _disconnect = Disconnect(tunnel.clone());
    let mut events = tunnel.events().ok_or("event_stream_unavailable")?;
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let deadline = tokio::time::sleep(Duration::from_secs(45));
    tokio::pin!(deadline);
    let mut connected = false;
    let mut address = None;
    loop {
        tokio::select! {
            command = commands.recv() => {
                match command {
                    None => return Ok(()),
                    Some(Ok(value)) if value == json!({"command":"stop"}) => return Ok(()),
                    Some(Err(reason)) => return Err(reason),
                    _ => return Err("invalid_control_command"),
                }
            },
            _ = &mut deadline, if !connected => return Err("connect_timeout"),
            event = events.recv() => {
                let event = event.ok_or("transport_closed")?;
                if matches!(event.kind,EventKind::Disconnected|EventKind::Error) {
                    if let Some(metadata)=server_leave_metadata(&event.info) {output(metadata)?;}
                }
                match event.kind {
                    EventKind::Connected => {
                        connected = true;
                        if config.role == TunnelRole::Server {
                            tunnel.start_server().map_err(|_| "server_setup_failed")?;
                        } else {
                            address = Some(tunnel.enable_socks5_server(config.port).await
                                .map_err(|_| "proxy_bind_failed")?.to_string());
                        }
                        output(json!({"event":"connected","provider":"igap","mediaConnected":true,
                            "socksAddress":address,"peerAuthenticated":tunnel.is_peer_authenticated(),
                            "proxyReady":tunnel.is_proxy_ready(),"providerPathVerified":false,"billingVerified":false}))?;
                    },
                    EventKind::Disconnected | EventKind::PeerLeft => return Err(disconnect_reason(&event.kind,&event.info,"transport_disconnected")),
                    EventKind::Error => return Err(disconnect_reason(&event.kind,&event.info,"transport_failed")),
                    EventKind::PeerJoined => {},
                }
            },
            _ = interval.tick(), if connected => {
                let stats = tunnel.stats();
                output(json!({"event":"metrics","mediaConnected":tunnel.is_connected(),
                    "peerAuthenticated":tunnel.is_peer_authenticated(),"proxyReady":tunnel.is_proxy_ready(),
                    "receivedBytes":stats[1],"sentBytes":stats[3],"quic":tunnel.connection_metrics(),
                    "providerPathVerified":false,"billingVerified":false}))?;
            },
        }
    }
}

fn main() {
    // Never echo a panic payload or a third-party networking error containing
    // URLs, SDP or JWTs. The parent receives only fixed reason codes.
    std::panic::set_hook(Box::new(|_| { let _ = output(json!({"event":"error","reason":"bridge_panic"})); }));
    if std::env::args_os().len() != 1 {
        let _ = output(json!({"event":"error","reason":"arguments_not_allowed"}));
        std::process::exit(2);
    }
    if std::env::var_os("SSLKEYLOGFILE").is_some() ||
        std::env::var("NODE_TLS_REJECT_UNAUTHORIZED").ok().as_deref() == Some("0") {
        let _ = output(json!({"event":"error","reason":"unsafe_environment"}));
        std::process::exit(2);
    }
    let identity = match Identity::generate() {
        Ok(identity) => identity,
        Err(_) => { let _ = output(json!({"event":"error","reason":"identity_failed"})); std::process::exit(1); },
    };
    if output(json!({"event":"prepared","protocol":1,"publicCertificate":hex(&identity.certificate)})).is_err() {
        return;
    }
    let result = lktunnel::runtime().block_on(run(identity, reader()));
    match result {
        Ok(()) => { let _ = output(json!({"event":"stopped"})); },
        Err(reason) => { let _ = output(json!({"event":"error","reason":reason})); std::process::exit(1); },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> Value {
        json!({"command":"connect","provider":"igap","url":ENDPOINT,"role":"client",
            "token":"fixture.payload.signature","trustedCertificates":["aa".repeat(80)],
            "socksPort":1080,"throughput":true})
    }
    #[test]
    fn only_fixed_provider_endpoint_and_strict_pairing_are_accepted() {
        assert!(config(sample(), &[1,2]).is_ok());
        for key in ["provider", "url", "role", "token", "trustedCertificates", "socksPort", "throughput"] {
            let mut input = sample(); input.as_object_mut().unwrap().remove(key);
            assert!(config(input, &[1,2]).is_err(), "missing {key}");
        }
        for value in [json!([]), json!(["aa".repeat(80),"aa".repeat(80)]), json!(["xx".repeat(80)])] {
            let mut input=sample();input["trustedCertificates"]=value;assert!(config(input,&[1,2]).is_err());
        }
        assert!(config(sample(), &vec![0xaa;80]).is_err());
        let mut input=sample(); input["url"]=json!("wss://foreign.invalid/");assert!(config(input,&[1,2]).is_err());
        let mut input=sample(); input["allowUnauthenticated"]=json!(true);assert!(config(input,&[1,2]).is_err());
    }
    #[test]
    fn disconnect_context_is_classified_without_forwarding_details() {
        for (message, expected) in [
            ("publisher PC failed", "publisher_pc_failed"),
            ("publisher PC closed", "publisher_pc_closed"),
            ("subscriber PC failed", "subscriber_pc_failed"),
            ("subscriber PC closed", "subscriber_pc_closed"),
            ("signal stream ended", "signal_ended"),
            ("server leave", "server_leave"),
            ("remote carrier track ended", "carrier_track_ended"),
            ("signal closed: private-token-or-server-message", "signal_closed"),
        ] {
            assert_eq!(disconnect_reason(&EventKind::Disconnected, message, "transport_disconnected"), expected);
        }
        for message in ["private-token", "publisher PC failed: private-token", "publisher PC disconnected", "signal closed private-token", "subscriber PC failed\nprivate-token"] {
            assert_eq!(disconnect_reason(&EventKind::Disconnected, message, "transport_disconnected"), "transport_disconnected");
            assert_eq!(disconnect_reason(&EventKind::Error, message, "transport_failed"), "transport_failed");
        }
        assert_eq!(disconnect_reason(&EventKind::PeerLeft, "private-peer-id", "transport_disconnected"), "peer_left");
        assert_eq!(disconnect_reason(&EventKind::Connected, "publisher PC failed", "transport_failed"), "transport_failed");
    }

    #[test]
    fn leave_metadata_accepts_only_exact_bounded_context() {
        assert_eq!(server_leave_metadata("server leave reason=16 action=2 reconnect=1"),Some(json!({"event":"serverLeave","reasonCode":16,"actionCode":2,"canReconnect":true})));
        assert_eq!(server_leave_metadata("server leave reason=-1 action=-1 reconnect=0"),Some(json!({"event":"serverLeave","reasonCode":null,"actionCode":null,"canReconnect":false})));
        assert_eq!(disconnect_reason(&EventKind::Disconnected,"server leave reason=0 action=0 reconnect=0","transport_disconnected"),"server_leave");
        for text in ["server leave","server leave reason=17 action=0 reconnect=0","server leave reason=0 action=3 reconnect=0",
            "server leave reason=00 action=0 reconnect=0","server leave reason=0 action=0 reconnect=true",
            "server leave reason=0 action=0 reconnect=0 private-token","server leave reason=0 action=0 reconnect=0\nprivate-token"] {
            assert!(server_leave_metadata(text).is_none());
        }
        assert_eq!(disconnect_reason(&EventKind::Disconnected,"server leave","transport_disconnected"),"server_leave");
    }

    #[test]
    fn tokens_ports_and_certificate_lengths_are_bounded() {
        for token in ["", "a.b", "a.b.c?secret", &"a".repeat(17000)] {
            let mut input=sample(); input["token"]=json!(token);assert!(config(input,&[1,2]).is_err());
        }
        for port in [json!(-1), json!(80), json!(65536), json!(1.5), json!("1080")] {
            let mut input=sample();input["socksPort"]=port;assert!(config(input,&[1,2]).is_err());
        }
        for cert in [json!("a"), json!("aa".repeat(9000)), json!(null)] { assert!(certificate(&cert).is_err()); }
    }
}
