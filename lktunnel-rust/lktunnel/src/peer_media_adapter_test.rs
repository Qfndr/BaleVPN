// Included only inside peer_media's cfg(test) module. The external process
// handles private fixture SDP; no account/provider login or public API exists.
struct EitaaAdapter {
    child: std::process::Child,
    input: std::process::ChildStdin,
    events: std::sync::mpsc::Receiver<Result<serde_json::Value, &'static str>>,
}
impl EitaaAdapter {
    fn start() -> Self {
        Self::with_script("../../scripts/eitaa-media-fixture-adapter.cjs")
    }
    fn with_script(relative: &str) -> Self {
        let executable = std::env::var_os("BALEVPN_EITAA_ADAPTER_NODE")
            .expect("explicit Node executable required for this opt-in fixture");
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(relative);
        let mut command = std::process::Command::new(executable);
        command.arg(script).stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null());
        for key in ["SSLKEYLOGFILE", "NODE_TLS_REJECT_UNAUTHORIZED", "RUST_LOG", "RUST_BACKTRACE"] {
            command.env_remove(key);
        }
        #[cfg(windows)] {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        let mut child = command.spawn().expect("fixture adapter did not start");
        let input = child.stdin.take().expect("private input unavailable");
        let stdout = child.stdout.take().expect("private output unavailable");
        let (sender, events) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            use std::io::{BufRead, Read};
            let mut output = std::io::BufReader::new(stdout);
            loop {
                let mut line = Vec::new();
                let read = (&mut output).take(192 * 1024 + 1).read_until(b'\n', &mut line);
                if !matches!(read, Ok(n) if n > 0) || line.len() > 192 * 1024 {
                    line.fill(0); let _ = sender.send(Err("invalid_adapter_output")); return;
                }
                let result = serde_json::from_slice(&line).map_err(|_| "invalid_adapter_json");
                line.fill(0);
                if sender.send(result).is_err() { return; }
            }
        });
        let mut adapter = Self { child, input, events };
        assert_eq!(adapter.read()["event"], "ready");
        adapter
    }
    fn read(&mut self) -> serde_json::Value {
        self.events.recv_timeout(Duration::from_secs(15)).expect("private adapter reply timed out")
            .expect("invalid private adapter reply")
    }
    fn project(&mut self, description: RTCSessionDescription, kind: &str) -> RTCSessionDescription {
        use std::io::Write;
        serde_json::to_writer(&mut self.input, &serde_json::json!({"command":kind,"description":description}))
            .expect("private adapter input failed");
        self.input.write_all(b"\n").expect("private adapter input closed");
        self.input.flush().expect("private adapter input failed");
        let result = self.read();
        if result["event"] != "description" {
            panic!("adapter rejected private description: {}", result["reason"].as_str().unwrap_or("fixture_failed"));
        }
        assert!(result["signalPackets"].as_u64().unwrap_or(0) >= 2);
        let sdp = result["description"]["sdp"].as_str().expect("private description missing").to_owned();
        assert_eq!(result["description"]["type"], kind);
        match kind {
            "offer" => RTCSessionDescription::offer(sdp),
            "answer" => RTCSessionDescription::answer(sdp),
            _ => panic!("invalid fixture phase"),
        }.expect("invalid private SDP")
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires BALEVPN_EITAA_ADAPTER_NODE and normal BALEVPN_EITAA_BRIDGE helper"]
async fn actual_eitaa_call_media_owns_normal_helpers_and_preserves_proxy_target_filter() {
    use std::io::Write;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    assert!(std::env::var_os("BALEVPN_EITAA_BRIDGE").is_some(), "explicit normal Eitaa helper required");
    let mut fixture = EitaaAdapter::with_script("../../scripts/eitaa-native-call-fixture.cjs");
    let (relay, config) = relay().await;
    let port: u16 = config.urls[0].rsplit(':').next().unwrap().parse().unwrap();
    serde_json::to_writer(&mut fixture.input, &serde_json::json!({"command":"connect","turnPort":port})).unwrap();
    fixture.input.write_all(b"\n").unwrap();fixture.input.flush().unwrap();
    let result=fixture.read();assert_eq!(result["event"],"connected","normal helper integration failed");
    for key in ["client","server"] {
        assert_eq!(result[key]["provider"],"eitaa");assert_eq!(result[key]["phase"],"connected");
        for flag in ["relayPair","mediaConnected","peerAuthenticated","ready"] {assert_eq!(result[key][flag],true);}
        assert_eq!(result[key]["providerPathVerified"],false);assert_eq!(result[key]["billingVerified"],false);
    }
    assert_eq!(result["client"]["proxyReady"],true);assert_eq!(result["server"]["proxyReady"],false);assert_eq!(result["server"]["serverReady"],true);
    let address=result["client"]["socksAddress"].as_str().unwrap();assert!(address.starts_with("127.0.0.1:"));
    let mut socket=tokio::net::TcpStream::connect(address).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5),async {
        socket.write_all(&[5,1,0]).await.unwrap();let mut method=[0;2];socket.read_exact(&mut method).await.unwrap();assert_eq!(method,[5,0]);
        socket.write_all(&[5,1,0,1,127,0,0,1,0,80]).await.unwrap();let mut reply=[0;10];socket.read_exact(&mut reply).await.unwrap();assert_eq!(reply[1],2);
    }).await.unwrap();drop(socket);
    fixture.input.write_all(b"{\"command\":\"stop\"}\n").unwrap();fixture.input.flush().unwrap();assert_eq!(fixture.read()["event"],"stopped");
    relay.close().await.unwrap();
}
impl Drop for EitaaAdapter {
    fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); }
}

#[tokio::test]
#[ignore = "requires explicit BALEVPN_EITAA_ADAPTER_NODE and local-only Node fixture"]
async fn real_turn_dtls_rtp_quic_survives_eitaa_json_projection() {
    let mut adapter = EitaaAdapter::start();
    let (relay, server) = relay().await;
    let mut a_id = Identity::generate().unwrap();
    let mut b_id = Identity::generate().unwrap();
    let (a, a_in, a_out) = carrier::authenticated(TunnelRole::Client,
        a_id.options(&[b_id.certificate.clone()], false, false).unwrap()).unwrap();
    let (b, b_in, b_out) = carrier::authenticated(TunnelRole::Server,
        b_id.options(&[a_id.certificate.clone()], true, false).unwrap()).unwrap();
    a_id.private_key.fill(0); b_id.private_key.fill(0);
    let a_media = RelayMedia::new(a_in, a_out, vec![server.clone()]).await.unwrap();
    let b_media = RelayMedia::new(b_in, b_out, vec![server]).await.unwrap();
    // Offer/callee direction is independent of the proxy client/server role.
    let offer = adapter.project(b_media.offer().await.unwrap(), "offer");
    assert!(secure_audio(&offer.sdp));
    let answer = adapter.project(a_media.answer(offer).await.unwrap(), "answer");
    b_media.set_answer(answer).await.unwrap();
    tokio::join!(media_connected(&a), media_connected(&b));
    assert_eq!(a_media.selected_route().await, RelayRoute::RelayPair);
    assert_eq!(b_media.selected_route().await, RelayRoute::RelayPair);
    assert!(!a.is_peer_authenticated());
    let endpoint = b.enable_quic_server().unwrap();
    let echo = tokio::spawn(async move {
        let Some(incoming) = endpoint.endpoint.accept().await else { return; };
        let Ok(connection) = incoming.await else { return; };
        let Ok((mut write, mut read)) = connection.accept_bi().await else { return; };
        let _ = tokio::io::copy(&mut read, &mut write).await;
    });
    tokio::time::timeout(Duration::from_secs(15), a.ensure_quic_client()).await.unwrap().unwrap();
    assert!(a.is_peer_authenticated());
    let connection = a.quic_client.lock().as_ref().unwrap().connection.clone();
    let (mut write, mut read) = connection.open_bi().await.unwrap();
    let payload: Vec<u8> = (0..262144).map(|i| (i % 251) as u8).collect();
    let mut received = vec![0; payload.len()];
    tokio::time::timeout(Duration::from_secs(20), async {
        let (sent, read) = tokio::join!(write.write_all(&payload), read.read_exact(&mut received));
        sent.unwrap(); read.unwrap();
    }).await.unwrap();
    assert!(payload == received, "fixture payload changed");
    a_media.close().await; b_media.close().await; relay.close().await.unwrap(); echo.abort();
    assert!(!a.is_connected()); assert!(!b.is_connected()); assert!(!a.is_peer_authenticated());
}
