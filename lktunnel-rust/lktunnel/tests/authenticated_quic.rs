use lktunnel::security::Identity;
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn mutual_tls_rejects_wrong_server_and_unpaired_client() {
    let server = Identity::generate().unwrap();
    let client = Identity::generate().unwrap();
    let rogue = Identity::generate().unwrap();
    for case in [0, 1, 2, 3] {
        let so = server
            .options(&[client.certificate.clone()], true, false)
            .unwrap();
        let server_ep =
            quinn::Endpoint::server(so.server.unwrap(), "127.0.0.1:0".parse().unwrap()).unwrap();
        let identity = if case == 2 { &rogue } else { &client };
        let trust = if case == 1 {
            rogue.certificate.clone()
        } else {
            server.certificate.clone()
        };
        let co = identity.options(&[trust], false, false).unwrap();
        let mut client_ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        if case == 3 {
            let mut roots = rustls::RootCertStore::empty();
            roots
                .add(rustls::pki_types::CertificateDer::from(
                    server.certificate.clone(),
                ))
                .unwrap();
            let mut tls = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            tls.alpn_protocols = vec![b"balevpn-auth-v1".to_vec()];
            let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
            client_ep.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
        } else {
            client_ep.set_default_client_config(co.client.unwrap());
        }
        let outgoing = client_ep
            .connect(server_ep.local_addr().unwrap(), "lktunnel")
            .unwrap();
        let task = tokio::spawn(async move { outgoing.await });
        let incoming = server_ep.accept().await.unwrap();
        let received = tokio::time::timeout(Duration::from_secs(3), incoming).await;
        let connected = task.await.unwrap();
        if case == 0 {
            assert!(received.unwrap().is_ok());
            assert!(connected.is_ok());
        } else if case == 1 {
            assert!(connected.is_err());
        } else {
            assert!(received.unwrap().is_err());
        }
        client_ep.close(0u32.into(), b"test done");
        server_ep.close(0u32.into(), b"test done");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_carrier_roundtrip_and_throughput() {
    // Both code paths use the same SOCKS/TCP/QUIC carrier and payload size.
    // No internet, Bale account, phone, or OTP is used by this benchmark.
    lktunnel::socks5_quic::set_ssrf_filter_enabled(false);
    let server = Identity::generate().unwrap();
    let client = Identity::generate().unwrap();
    let mut results = vec![];
    for mode in [
        "legacy",
        "authenticated",
        "authenticated",
        "legacy",
        "throughput",
    ] {
        let authenticated = mode != "legacy";
        let (a, b) = if authenticated {
            lktunnel::connect_loopback_with_options(
                client
                    .options(&[server.certificate.clone()], false, mode == "throughput")
                    .unwrap(),
                server
                    .options(&[client.certificate.clone()], true, mode == "throughput")
                    .unwrap(),
            )
        } else {
            lktunnel::connect_loopback()
        };
        b.start_server().unwrap();
        if authenticated {
            assert!(
                b.flow_stats().is_none(),
                "Raw IP NAT must be unavailable in secure mode"
            );
        }
        let proxy = a.enable_socks5_server(0).await.unwrap();
        tokio::time::timeout(Duration::from_secs(10), a.ensure_quic_client())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(a.is_peer_authenticated(), authenticated);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let echo = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut b = vec![0; 65536];
            while let Ok(n) = s.read(&mut b).await {
                if n == 0 {
                    break;
                }
                if s.write_all(&b[..n]).await.is_err() {
                    break;
                }
            }
        });
        let mut stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
        stream.set_nodelay(true).unwrap();
        stream.write_all(&[5, 1, 0]).await.unwrap();
        let mut greeting = [0; 2];
        stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 0]);
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&port.to_be_bytes());
        stream.write_all(&request).await.unwrap();
        let mut reply = [0; 10];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0);
        let payload = Arc::new(
            (0..16 * 1024 * 1024)
                .map(|i| ((i * 31) ^ (i >> 5)) as u8)
                .collect::<Vec<_>>(),
        );
        let (mut read, mut write) = stream.into_split();
        let mut samples = vec![];
        for trial in 0..6 {
            let start = std::time::Instant::now();
            let mut received = vec![0; payload.len()];
            let (sent, got) = tokio::time::timeout(Duration::from_secs(20), async {
                tokio::join!(write.write_all(&payload), read.read_exact(&mut received))
            })
            .await
            .expect("Bulk transfer stalled");
            sent.unwrap();
            got.unwrap();
            assert_eq!(received.as_slice(), payload.as_slice());
            if trial > 0 {
                samples.push(payload.len() as f64 / start.elapsed().as_secs_f64());
            }
        }
        samples.sort_by(f64::total_cmp);
        let median = samples[samples.len() / 2];
        results.push((mode, median));
        println!("BENCH mode={mode} median_bytes_per_second={median:.0}");
        a.disconnect();
        b.disconnect();
        echo.abort();
    }
    let legacy = (results[0].1 + results[3].1) / 2.0;
    let secure = (results[1].1 + results[2].1) / 2.0;
    println!("BENCH authenticated_vs_legacy={:.3}", secure / legacy);
    lktunnel::socks5_quic::set_ssrf_filter_enabled(true);
}
