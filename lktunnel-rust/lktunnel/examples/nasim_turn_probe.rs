//! Explicit diagnostic only. Accepts two verified current Nasim TURN configs on
//! stdin and exchanges exact random nonces, optionally inside STUN Binding
//! requests, exclusively between its own two allocations.
use serde_json::{json, Value};
use std::{
    io::Read,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use webrtc::{
    ice::url::{ProtoType, SchemeType, Url},
    turn::client::{Client, ClientConfig},
    util::Conn,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PayloadKind {
    Nonce,
    StunBinding,
}

struct Config {
    endpoint: String,
    username: String,
    password: String,
}

fn configs(input: &[u8]) -> Result<(Vec<Config>, PayloadKind), ()> {
    if input.len() > 16384 {
        return Err(());
    }
    let value: Value = serde_json::from_slice(input).map_err(|_| ())?;
    let root = value.as_object().ok_or(())?;
    if !(2..=3).contains(&root.len())
        || root
            .keys()
            .any(|key| !matches!(key.as_str(), "provider" | "accounts" | "payloadKind"))
        || root.get("provider").and_then(Value::as_str) != Some("nasim")
    {
        return Err(());
    }
    let payload_kind = match root.get("payloadKind") {
        None => PayloadKind::Nonce,
        Some(Value::String(value)) if value == "nonce" => PayloadKind::Nonce,
        Some(Value::String(value)) if value == "stunBinding" => PayloadKind::StunBinding,
        _ => return Err(()),
    };
    let accounts = root.get("accounts").and_then(Value::as_array).ok_or(())?;
    if accounts.len() != 2 {
        return Err(());
    }
    let configs = accounts
        .iter()
        .map(|account| {
            let object = account.as_object().ok_or(())?;
            if object.len() != 3 {
                return Err(());
            }
            let text = |key| {
                object
                    .get(key)
                    .and_then(Value::as_str)
                    .filter(|s| {
                        !s.is_empty() && s.len() <= 1024 && !s.chars().any(char::is_control)
                    })
                    .ok_or(())
            };
            let url = text("url")?;
            if url.len() > 512 || url.contains(['@', '#']) {
                return Err(());
            }
            let parsed = Url::parse_url(url).map_err(|_| ())?;
            if parsed.scheme != SchemeType::Turn
                || parsed.proto != ProtoType::Udp
                || parsed.port == 0
            {
                return Err(());
            }
            let endpoint = if parsed.host.contains(':') {
                format!("[{}]:{}", parsed.host.trim_matches(['[', ']']), parsed.port)
            } else {
                format!("{}:{}", parsed.host, parsed.port)
            };
            Ok(Config {
                endpoint,
                username: text("username")?.to_owned(),
                password: text("credential")?.to_owned(),
            })
        })
        .collect::<Result<Vec<_>, ()>>()?;
    Ok((configs, payload_kind))
}

fn public_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(a == 0
                || a == 10
                || a == 127
                || a >= 224
                || a == 100 && (64..=127).contains(&b)
                || a == 169 && b == 254
                || a == 172 && (16..=31).contains(&b)
                || a == 192 && (b == 168 || b == 0 && (c == 0 || c == 2))
                || a == 192 && b == 88 && c == 99
                || a == 198 && (b == 18 || b == 19 || b == 51 && c == 100)
                || a == 203 && b == 0 && c == 113)
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            // Global unicast only, excluding special-use and transition ranges.
            segments[0] & 0xe000 == 0x2000
                && !(segments[0] == 0x2001 && (segments[1] < 0x200 || segments[1] == 0xdb8))
                && segments[0] != 0x2002
                && !(segments[0] == 0x3fff && segments[1] < 0x1000)
        }
    }
}

#[derive(Default)]
struct Owners {
    sockets: Vec<Arc<dyn Conn + Send + Sync>>,
    clients: Vec<Client>,
    allocations: Vec<Arc<dyn Conn + Send + Sync>>,
}

impl Owners {
    async fn close(&self) -> bool {
        let deallocate = futures_util::future::join_all(
            self.allocations.iter().map(|allocation| allocation.close()),
        );
        let deallocated = matches!(tokio::time::timeout(Duration::from_millis(500), deallocate).await,
            Ok(results) if results.iter().all(Result::is_ok));
        // Always cancel both client receive loops, including after failed or
        // timed-out deallocation. The process then shuts down its private
        // runtime, aborts outstanding tasks and drops every socket owner.
        let close_clients = futures_util::future::join_all(self.clients.iter().map(Client::close));
        let clients_closed = matches!(tokio::time::timeout(Duration::from_millis(100), close_clients).await,
            Ok(results) if results.iter().all(Result::is_ok));
        deallocated && clients_closed
    }
}

fn probe_payload(kind: PayloadKind) -> Result<[u8; 32], ()> {
    let mut nonce = [0_u8; 32];
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut nonce)
        .map_err(|_| ())?;
    if kind == PayloadKind::Nonce {
        return Ok(nonce);
    }
    // RFC 8489 section 5 and RFC 5780 section 7.6. The fixed 20-byte
    // header plus one 4-byte attribute header and 8-byte padding is 32 bytes.
    let mut message = webrtc::stun::message::Message::new();
    message.typ = webrtc::stun::message::BINDING_REQUEST;
    message.transaction_id.0.copy_from_slice(&nonce[..12]);
    message.add(webrtc::stun::attributes::ATTR_PADDING, &nonce[12..20]);
    message.write_header();
    message.raw.as_slice().try_into().map_err(|_| ())
}

async fn exchange(
    configs: Vec<Config>,
    payload_kind: PayloadKind,
    owners: &mut Owners,
    stage: &mut &'static str,
) -> Result<(), ()> {
    for (index, config) in configs.into_iter().enumerate() {
        *stage = if index == 0 {
            "allocate_1"
        } else {
            "allocate_2"
        };
        // Resolve once and connect to that exact validated address. No separate
        // target or alternate DNS lookup can be supplied by the caller.
        let endpoints: Vec<_> = tokio::net::lookup_host(&config.endpoint)
            .await
            .map_err(|_| ())?
            .take(17)
            .collect();
        if endpoints.is_empty() || endpoints.len() > 16 {
            return Err(());
        }
        #[cfg(not(test))]
        if endpoints
            .iter()
            .any(|endpoint| !public_address(endpoint.ip()))
        {
            return Err(());
        }
        let endpoint = endpoints[0];
        let bind = if endpoint.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = Arc::new(tokio::net::UdpSocket::bind(bind).await.map_err(|_| ())?);
        owners.sockets.push(socket.clone());
        let client = Client::new(ClientConfig {
            stun_serv_addr: endpoint.to_string(),
            turn_serv_addr: endpoint.to_string(),
            username: config.username,
            password: config.password,
            realm: String::new(),
            software: String::new(),
            rto_in_ms: 200,
            conn: socket,
            vnet: None,
        })
        .await
        .map_err(|_| ())?;
        owners.clients.push(client);
        let client = owners.clients.last().ok_or(())?;
        client.listen().await.map_err(|_| ())?;
        owners
            .allocations
            .push(Arc::new(client.allocate().await.map_err(|_| ())?));
    }
    let a = &owners.allocations[0];
    let b = &owners.allocations[1];
    let addr_a = a.local_addr().map_err(|_| ())?;
    let addr_b = b.local_addr().map_err(|_| ())?;
    *stage = "relay_address";
    if addr_a == addr_b || addr_a.port() == 0 || addr_b.port() == 0 {
        return Err(());
    }
    #[cfg(not(test))]
    if !public_address(addr_a.ip()) || !public_address(addr_b.ip()) {
        return Err(());
    }
    if addr_a.is_ipv4() != addr_b.is_ipv4() {
        *stage = "address_family";
        return Err(());
    }
    let nonce_a = probe_payload(payload_kind)?;
    let nonce_b = probe_payload(payload_kind)?;
    *stage = "permission_and_send";
    // Both permissions must exist before expecting delivery. One fixed second
    // send handles the initial permission race; there is no retry loop.
    let (first_a, first_b) = tokio::join!(a.send_to(&nonce_a, addr_b), b.send_to(&nonce_b, addr_a));
    first_a.map_err(|_| ())?;
    first_b.map_err(|_| ())?;
    let (sent_a, sent_b) = tokio::join!(a.send_to(&nonce_a, addr_b), b.send_to(&nonce_b, addr_a));
    // turn 0.8 returns the encoded SEND-INDICATION length until its channel
    // bind completes. Validate payload length and integrity on receipt below.
    sent_a.map_err(|_| ())?;
    sent_b.map_err(|_| ())?;
    *stage = "receive_and_verify";
    let mut buffer_a = [0_u8; 64];
    let mut buffer_b = [0_u8; 64];
    let (read_a, read_b) = tokio::join!(a.recv_from(&mut buffer_a), b.recv_from(&mut buffer_b));
    let (len_a, from_a) = read_a.map_err(|_| ())?;
    let (len_b, from_b) = read_b.map_err(|_| ())?;
    if from_a != addr_b
        || from_b != addr_a
        || len_a != 32
        || len_b != 32
        || buffer_a[..32] != nonce_b
        || buffer_b[..32] != nonce_a
    {
        return Err(());
    }
    *stage = "complete";
    Ok(())
}

async fn run(configs: Vec<Config>, payload_kind: PayloadKind, budget: Duration) -> Value {
    let mut owners = Owners::default();
    let mut stage = "setup";
    let result = tokio::time::timeout(
        budget,
        exchange(configs, payload_kind, &mut owners, &mut stage),
    )
    .await;
    let (ok, reason) = match result {
        Ok(Ok(())) => (true, "complete"),
        Ok(Err(())) => (false, "failed"),
        Err(_) => (false, "timeout"),
    };
    let allocated = owners.allocations.len();
    let local_cleanup_complete = owners.close().await;
    // A cancelled allocation may have reached the remote server before its
    // response arrived. This acknowledges local cleanup, not remote deletion.
    json!({"event":"turnProbe","ok":ok,"stage":stage,"reason":reason,"allocated":allocated,"bidirectionalVerified":ok,"localCleanupComplete":local_cleanup_complete})
}

fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    let started = Instant::now();
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut input = Vec::new();
        let result = std::io::stdin()
            .take(16385)
            .read_to_end(&mut input)
            .map(|_| input);
        let _ = tx.send(result);
    });
    let parsed = rx
        .recv_timeout(Duration::from_secs(2))
        .ok()
        .and_then(Result::ok)
        .and_then(|input| configs(&input).ok());
    let output = match parsed {
        None => {
            json!({"event":"turnProbe","ok":false,"stage":"input","reason":"invalid_input","allocated":0,"bidirectionalVerified":false,"localCleanupComplete":true})
        }
        Some((configs, payload_kind)) => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build();
            match runtime {
                Ok(runtime) => {
                    let output = runtime.block_on(run(
                        configs,
                        payload_kind,
                        Duration::from_secs(14).saturating_sub(started.elapsed()),
                    ));
                    runtime.shutdown_timeout(Duration::from_millis(100));
                    output
                }
                Err(_) => {
                    json!({"event":"turnProbe","ok":false,"stage":"setup","reason":"failed","allocated":0,"bidirectionalVerified":false,"localCleanupComplete":true})
                }
            }
        }
    };
    println!("{output}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};
    use webrtc::turn::{
        auth::{generate_auth_key, AuthHandler},
        relay::relay_static::RelayAddressGeneratorStatic,
        server::{
            config::{ConnConfig, ServerConfig},
            Server,
        },
    };
    struct Auth;
    impl AuthHandler for Auth {
        fn auth_handle(
            &self,
            username: &str,
            realm: &str,
            _: SocketAddr,
        ) -> Result<Vec<u8>, webrtc::turn::Error> {
            Ok(generate_auth_key(username, realm, "fixture-password"))
        }
    }
    async fn server() -> (Server, String) {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let endpoint = socket.local_addr().unwrap().to_string();
        let server = Server::new(ServerConfig {
            conn_configs: vec![ConnConfig {
                conn: socket,
                relay_addr_generator: Box::new(RelayAddressGeneratorStatic {
                    relay_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    address: "127.0.0.1".into(),
                    net: Arc::new(webrtc::util::vnet::net::Net::new(None)),
                }),
            }],
            realm: "fixture".into(),
            auth_handler: Arc::new(Auth),
            channel_bind_timeout: Duration::ZERO,
            alloc_close_notify: None,
        })
        .await
        .unwrap();
        (server, endpoint)
    }
    fn pair(endpoint: &str, password: &str) -> Vec<Config> {
        ["account-one", "account-two"]
            .into_iter()
            .map(|username| Config {
                endpoint: endpoint.into(),
                username: username.into(),
                password: password.into(),
            })
            .collect()
    }
    #[tokio::test]
    async fn two_owned_allocations_exchange_exact_nonces() {
        let (server, endpoint) = server().await;
        let result = run(
            pair(&endpoint, "fixture-password"),
            PayloadKind::Nonce,
            Duration::from_secs(5),
        )
        .await;
        server.close().await.unwrap();
        assert_eq!(result["ok"], true, "safe diagnostic result: {result}");
        assert_eq!(result["allocated"], 2);
        assert_eq!(result["bidirectionalVerified"], true);
        assert_eq!(result["localCleanupComplete"], true);
    }
    #[tokio::test]
    async fn rejected_credentials_are_redacted_and_bounded() {
        let (server, endpoint) = server().await;
        let result = run(
            pair(&endpoint, "private-wrong-password"),
            PayloadKind::Nonce,
            Duration::from_millis(300),
        )
        .await;
        server.close().await.unwrap();
        assert_eq!(result["ok"], false);
        assert_eq!(result["allocated"], 0);
        let output = result.to_string();
        assert!(!output.contains(&endpoint));
        assert!(!output.contains("private-wrong-password"));
        assert!(!output.contains("account-one"));
    }
    #[test]
    fn strict_input_has_no_separate_destination_or_extra_keys() {
        let valid = json!({"provider":"nasim","accounts":[{"url":"turn:127.0.0.1:3478","username":"a","credential":"b"},{"url":"turn:127.0.0.1:3478","username":"c","credential":"d"}]});
        assert_eq!(
            configs(&serde_json::to_vec(&valid).unwrap()).unwrap().1,
            PayloadKind::Nonce
        );
        for invalid in [json!("unknown"), json!(true), json!(null)] {
            let mut value = valid.clone();
            value["payloadKind"] = invalid;
            assert!(configs(&serde_json::to_vec(&value).unwrap()).is_err());
        }
        let mut stun = valid.clone();
        stun["payloadKind"] = json!("stunBinding");
        assert_eq!(
            configs(&serde_json::to_vec(&stun).unwrap()).unwrap().1,
            PayloadKind::StunBinding
        );
        let mut extra = valid.clone();
        extra["target"] = json!("arbitrary");
        assert!(configs(&serde_json::to_vec(&extra).unwrap()).is_err());
        let mut tcp = valid;
        tcp["accounts"][0]["url"] = json!("turn:127.0.0.1:3478?transport=tcp");
        assert!(configs(&serde_json::to_vec(&tcp).unwrap()).is_err());
        assert!(configs(&vec![b' '; 16385]).is_err());
    }
    #[test]
    fn stun_payload_decodes_as_a_32_byte_binding_request_with_padding() {
        let bytes = probe_payload(PayloadKind::StunBinding).unwrap();
        let mut decoded = webrtc::stun::message::Message::new();
        decoded.unmarshal_binary(&bytes).unwrap();
        assert_eq!(decoded.typ, webrtc::stun::message::BINDING_REQUEST);
        assert_eq!(decoded.length, 12);
        assert_eq!(decoded.transaction_id.0, bytes[8..20]);
        let padding = decoded.get(webrtc::stun::attributes::ATTR_PADDING).unwrap();
        assert_eq!(padding.len(), 8);
        assert_eq!(padding, bytes[24..32]);
        assert_eq!(bytes[4..8], 0x2112a442_u32.to_be_bytes());
    }

    #[tokio::test]
    async fn two_owned_allocations_exchange_exact_stun_binding_requests() {
        let (server, endpoint) = server().await;
        let result = run(
            pair(&endpoint, "fixture-password"),
            PayloadKind::StunBinding,
            Duration::from_secs(5),
        )
        .await;
        server.close().await.unwrap();
        assert_eq!(result["ok"], true, "safe diagnostic result: {result}");
        assert_eq!(result["allocated"], 2);
        assert_eq!(result["bidirectionalVerified"], true);
        assert_eq!(result["localCleanupComplete"], true);
    }

    #[test]
    fn production_guard_rejects_private_reserved_and_mapped_addresses() {
        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.168.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "::1",
            "::ffff:8.8.8.8",
            "fe80::1",
            "fc00::1",
            "2001:db8::1",
            "2002::1",
            "3fff::1",
        ] {
            assert!(!public_address(address.parse().unwrap()));
        }
        assert!(public_address("8.8.8.8".parse().unwrap()));
        assert!(public_address("2606:4700:4700::1111".parse().unwrap()));
    }
}
