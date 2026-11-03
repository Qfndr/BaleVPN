// Shared private relay-only helper implementation. Provider identity is fixed
// by the separate binary, never chosen by a control message.
use lktunnel::{
    carrier,
    peer_media::{MediaDisconnectStage, MediaError, RelayMedia},
    security::Identity,
    EventKind, TunnelRole,
};
use serde_json::{json, Value};
use std::{
    future::Future,
    io::{BufRead, Read, Write},
    time::Duration,
};
use tokio::sync::mpsc;
use webrtc::{
    ice_transport::{
        ice_candidate::RTCIceCandidateInit, ice_credential_type::RTCIceCredentialType,
        ice_server::RTCIceServer,
    },
    peer_connection::sdp::session_description::RTCSessionDescription,
};
const MAX_COMMAND: usize = 192 * 1024;
#[cfg(test)]
#[path = "nasim_bridge_process_tests.rs"]
mod process_tests;
fn output(value: Value) -> Result<(), &'static str> {
    let mut stream = std::io::stdout().lock();
    serde_json::to_writer(&mut stream, &value).map_err(|_| "output_closed")?;
    stream
        .write_all(b"\n")
        .and_then(|_| stream.flush())
        .map_err(|_| "output_closed")
}
fn keys(value: &Value, allowed: &[&str]) -> bool {
    value
        .as_object()
        .map(|o| o.keys().all(|k| allowed.contains(&k.as_str())))
        .unwrap_or(false)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn certificate(value: &Value) -> Result<Vec<u8>, &'static str> {
    let text = value.as_str().ok_or("invalid_pairing")?;
    if !(128..=16384).contains(&text.len())
        || text.len() % 2 != 0
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid_pairing");
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).map_err(|_| "invalid_pairing"))
        .collect()
}
struct Config {
    role: TunnelRole,
    trusted: Vec<Vec<u8>>,
    port: u16,
    throughput: bool,
    servers: Vec<RTCIceServer>,
}
fn config(value: Value, own: &[u8]) -> Result<Config, &'static str> {
    if !keys(
        &value,
        &[
            "command",
            "provider",
            "role",
            "trustedCertificates",
            "socksPort",
            "throughput",
            "iceServers",
        ],
    ) || value["command"] != "configure"
        || value["provider"] != PROVIDER
    {
        return Err("invalid_config");
    }
    let role = match value["role"].as_str() {
        Some("client") => TunnelRole::Client,
        Some("server") => TunnelRole::Server,
        _ => return Err("invalid_role"),
    };
    let items = value["trustedCertificates"]
        .as_array()
        .ok_or("invalid_pairing")?;
    if items.is_empty() || items.len() > 8 {
        return Err("invalid_pairing");
    }
    let mut trusted = Vec::new();
    for item in items {
        let cert = certificate(item)?;
        if cert == own || trusted.contains(&cert) {
            return Err("invalid_pairing");
        }
        trusted.push(cert);
    }
    let port = value["socksPort"]
        .as_u64()
        .filter(|p| *p == 0 || (1024..=65535).contains(p))
        .ok_or("invalid_port")? as u16;
    let throughput = value["throughput"].as_bool().ok_or("invalid_profile")?;
    let servers = value["iceServers"].as_array().ok_or("invalid_relay")?;
    if servers.is_empty() || servers.len() > 4 {
        return Err("invalid_relay");
    }
    let mut ice = Vec::new();
    for item in servers {
        if !keys(item, &["urls", "username", "credential"]) {
            return Err("invalid_relay");
        }
        let urls = item["urls"].as_array().ok_or("invalid_relay")?;
        if urls.is_empty() || urls.len() > 4 {
            return Err("invalid_relay");
        }
        let urls = urls
            .iter()
            .map(|u| {
                u.as_str()
                    .filter(|s| s.len() <= 512)
                    .map(str::to_owned)
                    .ok_or("invalid_relay")
            })
            .collect::<Result<Vec<_>, _>>()?;
        let secret = |key: &str| {
            item[key]
                .as_str()
                .filter(|s| !s.is_empty() && s.len() <= 1024)
                .map(str::to_owned)
                .ok_or("invalid_relay")
        };
        ice.push(RTCIceServer {
            urls,
            username: secret("username")?,
            credential: secret("credential")?,
            credential_type: RTCIceCredentialType::Password,
        });
    }
    Ok(Config {
        role,
        trusted,
        port,
        throughput,
        servers: ice,
    })
}
fn description(value: &Value, kind: &str) -> Result<RTCSessionDescription, &'static str> {
    if !keys(value, &["type", "sdp"]) || value["type"] != kind {
        return Err("invalid_description");
    }
    let sdp = value["sdp"]
        .as_str()
        .filter(|s| s.len() <= 65535 && !s.contains('\0'))
        .ok_or("invalid_description")?
        .to_owned();
    match kind {
        "offer" => RTCSessionDescription::offer(sdp),
        "answer" => RTCSessionDescription::answer(sdp),
        _ => return Err("invalid_description"),
    }
    .map_err(|_| "invalid_description")
}
fn reason(error: MediaError) -> &'static str {
    match error {
        MediaError::InvalidRelay => "invalid_relay",
        MediaError::Setup => "media_setup_failed",
        MediaError::InvalidDescription => "invalid_description",
        MediaError::Negotiation => "negotiation_failed",
        MediaError::GatherTimeout => "gather_timeout",
        MediaError::NoRelay => "no_relay",
        MediaError::Closed => "transport_closed",
    }
}
fn disconnect_reason(stage: MediaDisconnectStage, fallback: &'static str) -> &'static str {
    match stage {
        MediaDisconnectStage::Ice => "ice_failed",
        MediaDisconnectStage::Dtls => "dtls_failed",
        MediaDisconnectStage::RelayRoute => "relay_route_failed",
        MediaDisconnectStage::Unknown => fallback,
    }
}
fn reader() -> mpsc::Receiver<Result<Value, &'static str>> {
    let (tx, rx) = mpsc::channel(4);
    std::thread::spawn(move || {
        let mut stream = std::io::stdin().lock();
        loop {
            let mut line = Vec::new();
            let result = match (&mut stream)
                .take((MAX_COMMAND + 1) as u64)
                .read_until(b'\n', &mut line)
            {
                Ok(0) => return,
                Ok(_) if line.len() > MAX_COMMAND || line.last() != Some(&b'\n') => {
                    Err("invalid_command")
                }
                Ok(_) => serde_json::from_slice(&line).map_err(|_| "invalid_command"),
                Err(_) => Err("input_closed"),
            };
            line.fill(0);
            let failed = result.is_err();
            if tx.blocking_send(result).is_err() || failed {
                return;
            }
        }
    });
    rx
}
/// EOF/stop takes priority even while ICE gathering or setup is awaiting I/O.
async fn controlled<T>(
    future: impl Future<Output = Result<T, MediaError>>,
    commands: &mut mpsc::Receiver<Result<Value, &'static str>>,
) -> Result<Option<T>, &'static str> {
    tokio::select! {biased;
        command=commands.recv()=>match command {None=>Ok(None),Some(Ok(v)) if v==json!({"command":"stop"})=>Ok(None),Some(Err(e))=>Err(e),_=>Err("invalid_control_command")},
        result=future=>result.map(Some).map_err(reason),
    }
}
async fn run(
    mut identity: Identity,
    mut commands: mpsc::Receiver<Result<Value, &'static str>>,
) -> Result<(), &'static str> {
    let command = tokio::time::timeout(Duration::from_secs(60), commands.recv())
        .await
        .map_err(|_| "config_timeout")?
        .ok_or("input_closed")??;
    if command == json!({"command":"stop"}) {
        return Ok(());
    }
    let config = config(command, &identity.certificate)?;
    let options = identity
        .options(
            &config.trusted,
            config.role == TunnelRole::Server,
            config.throughput,
        )
        .map_err(|_| "invalid_pairing")?;
    identity.private_key.fill(0);
    let (tunnel, input, output_carrier) =
        carrier::authenticated(config.role, options).map_err(|_| "invalid_pairing")?;
    let Some(media) = controlled(
        RelayMedia::new(input, output_carrier, config.servers),
        &mut commands,
    )
    .await?
    else {
        return Ok(());
    };
    let mut events = tunnel.events().ok_or("event_stream_unavailable")?;
    output(json!({"event":"configured","provider":PROVIDER}))?;
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let deadline = tokio::time::sleep(Duration::from_secs(45));
    tokio::pin!(deadline);
    let mut connected = false;
    let mut address = None;
    loop {
        tokio::select! {biased;
            command=commands.recv()=>{
                let Some(command)=command else {return Ok(());};let command=command?;
                if command==json!({"command":"stop"}){return Ok(());}
                match command["command"].as_str(){
                    Some("offer") if command==json!({"command":"offer"})=>{
                        let Some(sdp)=controlled(media.offer(),&mut commands).await? else{return Ok(());};
                        output(json!({"event":"description","description":sdp}))?;
                    },
                    Some("answer") if keys(&command,&["command","description"])=>{
                        let offer=description(&command["description"],"offer")?;
                        let Some(sdp)=controlled(media.answer(offer),&mut commands).await? else{return Ok(());};
                        output(json!({"event":"description","description":sdp}))?;
                    },
                    Some("setAnswer") if keys(&command,&["command","description"])=>{
                        let answer=description(&command["description"],"answer")?;
                        if controlled(media.set_answer(answer),&mut commands).await?.is_none(){return Ok(());}
                        output(json!({"event":"negotiated"}))?;
                    },
                    Some("candidate") if keys(&command,&["command","candidate"])=>{
                        let value=&command["candidate"];
                        if !keys(value,&["candidate","sdpMid","sdpMLineIndex","usernameFragment"]) ||
                            value["candidate"].as_str().map(|s|s.len()>4096).unwrap_or(true) ||
                            value["sdpMid"].as_str().map(|s|s.len()>128).unwrap_or(false) ||
                            value["usernameFragment"].as_str().map(|s|s.len()>256).unwrap_or(false) {return Err("invalid_description");}
                        let candidate:RTCIceCandidateInit=serde_json::from_value(value.clone()).map_err(|_|"invalid_description")?;
                        if controlled(media.add_candidate(candidate),&mut commands).await?.is_none(){return Ok(());}
                        output(json!({"event":"candidateAdded"}))?;
                    },
                    _=>return Err("invalid_control_command"),
                }
            },
            _=&mut deadline,if !connected=>return Err("connect_timeout"),
            event=events.recv()=>{
                let event=event.ok_or("transport_closed")?;
                match event.kind {
                    EventKind::Connected=>{
                        if connected{return Err("transport_failed");}connected=true;
                        if config.role==TunnelRole::Server {tunnel.start_server().map_err(|_|"server_setup_failed")?;}
                        else {address=Some(tunnel.enable_socks5_server(config.port).await.map_err(|_|"proxy_bind_failed")?.to_string());}
                        output(json!({"event":"connected","provider":PROVIDER,"mediaConnected":true,"relayPair":true,
                            "socksAddress":address,"peerAuthenticated":tunnel.is_peer_authenticated(),"proxyReady":tunnel.is_proxy_ready(),
                            "providerPathVerified":false,"billingVerified":false}))?;
                    },
                    EventKind::Disconnected|EventKind::PeerLeft=>return Err(disconnect_reason(media.disconnect_stage(),"transport_disconnected")),EventKind::Error=>return Err(disconnect_reason(media.disconnect_stage(),"transport_failed")),_=>{},
                }
            },
            _=interval.tick(),if connected=>{
                let stats=tunnel.stats();output(json!({"event":"metrics","mediaConnected":tunnel.is_connected(),"relayPair":true,
                    "peerAuthenticated":tunnel.is_peer_authenticated(),"proxyReady":tunnel.is_proxy_ready(),"receivedBytes":stats[1],"sentBytes":stats[3],
                    "quic":tunnel.connection_metrics(),"providerPathVerified":false,"billingVerified":false}))?;
            },
        }
    }
}
fn main() {
    std::panic::set_hook(Box::new(|_| {
        let _ = output(json!({"event":"error","reason":"bridge_panic"}));
    }));
    if std::env::args_os().len() != 1 {
        let _ = output(json!({"event":"error","reason":"arguments_not_allowed"}));
        std::process::exit(2);
    }
    if std::env::var_os("SSLKEYLOGFILE").is_some()
        || std::env::var("NODE_TLS_REJECT_UNAUTHORIZED")
            .ok()
            .as_deref()
            == Some("0")
    {
        let _ = output(json!({"event":"error","reason":"unsafe_environment"}));
        std::process::exit(2);
    }
    let identity = match Identity::generate() {
        Ok(value) => value,
        Err(_) => {
            let _ = output(json!({"event":"error","reason":"identity_failed"}));
            std::process::exit(1);
        }
    };
    if output(json!({"event":"prepared","protocol":2,"provider":PROVIDER,"publicCertificate":hex(&identity.certificate)})).is_err(){return;}
    match lktunnel::runtime().block_on(run(identity, reader())) {
        Ok(()) => {
            let _ = output(json!({"event":"stopped"}));
        }
        Err(reason) => {
            let _ = output(json!({"event":"error","reason":reason}));
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> Value {
        json!({"command":"configure","provider":PROVIDER,"role":"client","trustedCertificates":["aa".repeat(80)],
        "socksPort":1089,"throughput":true,"iceServers":[{"urls":["turn:relay.example.test:3478"],"username":"fixture","credential":"fixture-secret"}]})
    }
    #[test]
    fn independent_provider_and_strict_pairing_are_required() {
        assert!(config(sample(), &[1, 2]).is_ok());
        for field in [
            "command",
            "provider",
            "role",
            "trustedCertificates",
            "socksPort",
            "throughput",
            "iceServers",
        ] {
            let mut value = sample();
            value.as_object_mut().unwrap().remove(field);
            assert!(config(value, &[1, 2]).is_err());
        }
        for change in [
            json!({"provider":"bale"}),
            json!({"provider":if PROVIDER=="eitaa" {"nasim"} else {"eitaa"}}),
            json!({"token":"secret"}),
            json!({"role":"other"}),
            json!({"trustedCertificates":[]}),
            json!({"trustedCertificates":["aa".repeat(80),"aa".repeat(80)]}),
            json!({"socksPort":80}),
            json!({"throughput":"true"}),
        ] {
            let mut value = sample();
            value
                .as_object_mut()
                .unwrap()
                .extend(change.as_object().unwrap().clone());
            assert!(config(value, &[1, 2]).is_err());
        }
        assert!(config(sample(), &vec![0xaa; 80]).is_err());
    }
    #[test]
    fn relay_and_description_inputs_are_bounded_and_errors_are_fixed() {
        for ice in [
            json!([]),
            json!([{"urls":[],"username":"u","credential":"p"}]),
            json!([{"urls":["turn:r:3478"],"username":"u","credential":"p","token":"secret"}]),
        ] {
            let mut value = sample();
            value["iceServers"] = ice;
            assert!(config(value, &[1, 2]).is_err());
        }
        assert!(description(&json!({"type":"offer","sdp":"invalid-secret"}), "offer").is_err());
        assert!(description(&json!({"type":"answer","sdp":"v=0"}), "offer").is_err());
        assert_eq!(reason(MediaError::Negotiation), "negotiation_failed");
        assert_eq!(
            disconnect_reason(MediaDisconnectStage::Ice, "transport_disconnected"),
            "ice_failed"
        );
        assert_eq!(
            disconnect_reason(MediaDisconnectStage::Dtls, "transport_disconnected"),
            "dtls_failed"
        );
        assert_eq!(
            disconnect_reason(MediaDisconnectStage::RelayRoute, "transport_disconnected"),
            "relay_route_failed"
        );
        assert_eq!(
            disconnect_reason(MediaDisconnectStage::Unknown, "transport_disconnected"),
            "transport_disconnected"
        );
        assert_eq!(
            disconnect_reason(MediaDisconnectStage::Unknown, "transport_failed"),
            "transport_failed"
        );
    }
    #[tokio::test]
    async fn stop_and_eof_cancel_pending_setup_without_waiting_for_network() {
        let (tx, mut rx) = mpsc::channel(1);
        tx.send(Ok(json!({"command":"stop"}))).await.unwrap();
        assert!(
            controlled(std::future::pending::<Result<(), MediaError>>(), &mut rx)
                .await
                .unwrap()
                .is_none()
        );
        drop(tx);
        assert!(
            controlled(std::future::pending::<Result<(), MediaError>>(), &mut rx)
                .await
                .unwrap()
                .is_none()
        );
    }
}
