//! Opt-in test of the normal helper executable, never the test binary itself.
use super::*;
use std::process::{Child, ChildStdin, Command, Stdio};
struct Process {
    child: Child,
    input: ChildStdin,
    events: std::sync::mpsc::Receiver<Value>,
}
impl Process {
    fn new(executable: &std::ffi::OsStr) -> Self {
        let mut command = Command::new(executable);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        for key in [
            "SSLKEYLOGFILE",
            "NODE_TLS_REJECT_UNAUTHORIZED",
            "RUST_LOG",
            "RUST_BACKTRACE",
        ] {
            command.env_remove(key);
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        let mut child = command.spawn().unwrap();
        let input = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, events) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut stream = std::io::BufReader::new(stdout);
            loop {
                let mut bytes = Vec::new();
                let read = (&mut stream)
                    .take((MAX_COMMAND + 1) as u64)
                    .read_until(b'\n', &mut bytes);
                if !matches!(read,Ok(n) if n>0) || bytes.len() > MAX_COMMAND {
                    return;
                }
                let result = serde_json::from_slice::<Value>(&bytes);
                bytes.fill(0);
                match result {
                    Ok(value) => {
                        if tx.send(value).is_err() {
                            return;
                        }
                    }
                    Err(_) => return,
                }
            }
        });
        Self {
            child,
            input,
            events,
        }
    }
    fn send(&mut self, value: Value) {
        serde_json::to_writer(&mut self.input, &value).unwrap();
        self.input.write_all(b"\n").unwrap();
        self.input.flush().unwrap();
    }
    fn until(&self, event: &str, ready: bool) -> Value {
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            let value = self
                .events
                .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
                .expect("private helper reply timed out");
            assert_ne!(
                value["event"], "error",
                "helper returned a fixed protocol error"
            );
            if value["event"] == event && (!ready || value["proxyReady"] == true) {
                return value;
            }
        }
    }
    fn stop(&mut self) {
        self.send(json!({"command":"stop"}));
        self.until("stopped", false);
        assert!(self.child.wait().unwrap().success());
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "Requires the matching BALEVPN_NASIM_BRIDGE or BALEVPN_EITAA_BRIDGE normal helper"]
async fn two_actual_helpers_negotiate_relay_quic_and_keep_ssrf_protection() {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::Arc,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
            user: &str,
            realm: &str,
            _: SocketAddr,
        ) -> Result<Vec<u8>, webrtc::turn::Error> {
            if user == "fixture" && realm == "private-local-test" {
                Ok(generate_auth_key(user, realm, "fixture-relay-password"))
            } else {
                Err(webrtc::turn::Error::ErrFakeErr)
            }
        }
    }
    let executable = std::env::var_os(BRIDGE_ENV)
        .expect("Build the helper and set BALEVPN_NASIM_BRIDGE first");
    let conn = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let port = conn.local_addr().unwrap().port();
    let relay = Server::new(ServerConfig {
        conn_configs: vec![ConnConfig {
            conn,
            relay_addr_generator: Box::new(RelayAddressGeneratorStatic {
                relay_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                address: "127.0.0.1".into(),
                net: Arc::new(webrtc::util::vnet::net::Net::new(None)),
            }),
        }],
        realm: "private-local-test".into(),
        auth_handler: Arc::new(Auth),
        channel_bind_timeout: Duration::ZERO,
        alloc_close_notify: None,
    })
    .await
    .unwrap();
    let mut a = Process::new(&executable);
    let mut b = Process::new(&executable);
    let a_cert = a.until("prepared", false)["publicCertificate"].clone();
    let b_cert = b.until("prepared", false)["publicCertificate"].clone();
    assert_ne!(a_cert, b_cert);
    let configuration = |role: &str, certificate: Value| {
        json!({"command":"configure","provider":PROVIDER,"role":role,
        "trustedCertificates":[certificate],"socksPort":0,"throughput":false,
        "iceServers":[{"urls":[format!("turn:127.0.0.1:{port}")],"username":"fixture","credential":"fixture-relay-password"}]})
    };
    a.send(configuration("client", b_cert));
    b.send(configuration("server", a_cert));
    a.until("configured", false);
    b.until("configured", false);
    b.send(json!({"command":"offer"}));
    let offer = b.until("description", false)["description"].clone();
    a.send(json!({"command":"answer","description":offer}));
    let answer = a.until("description", false)["description"].clone();
    b.send(json!({"command":"setAnswer","description":answer}));
    b.until("negotiated", false);
    let connected = a.until("connected", false);
    assert_eq!(connected["relayPair"], true);
    assert_eq!(connected["billingVerified"], false);
    let address = connected["socksAddress"].as_str().unwrap();
    assert!(address.starts_with("127.0.0.1:"));
    let metrics = a.until("metrics", true);
    assert_eq!(metrics["peerAuthenticated"], true);
    assert_eq!(metrics["providerPathVerified"], false);
    // No SSRF opt-out is enabled in these normal helper executables.
    let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        socket.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0; 2];
        socket.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);
        socket
            .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80])
            .await
            .unwrap();
        let mut reply = [0; 10];
        socket.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 2);
    })
    .await
    .unwrap();
    drop(socket);
    a.stop();
    b.stop();
    relay.close().await.unwrap();
}
