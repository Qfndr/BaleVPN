//! A fresh call must carry real bytes on the same SOCKS port without restarting
//! the process. Uses paired TLS identities and a controlled local echo server.
use lktunnel::security::Identity;
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_transfer_survives_repeated_call_replacement_on_same_port() {
    lktunnel::socks5_quic::set_ssrf_filter_enabled(false);
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = echo.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        while let Ok((mut socket, _)) = echo.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = socket.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    let client = Identity::generate().unwrap();
    let server = Identity::generate().unwrap();
    let mut port = 0;
    for round in 0..4 {
        let (a, b) = lktunnel::connect_loopback_with_options(
            client
                .options(&[server.certificate.clone()], false, false)
                .unwrap(),
            server
                .options(&[client.certificate.clone()], true, false)
                .unwrap(),
        );
        b.start_server().unwrap();
        let address = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                match a.enable_socks5_server(port).await {
                    Ok(address) => break address,
                    Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                }
            }
        })
        .await
        .expect("old listener kept the port occupied");
        port = address.port();
        tokio::time::timeout(Duration::from_secs(5), a.ensure_quic_client())
            .await
            .unwrap()
            .unwrap();
        assert!(a.is_peer_authenticated());
        transfer(address, target, round).await;
        // Model a terminal call after network loss, then explicitly Disconnect.
        // The companion unit test covers the engine-state-before-cleanup order.
        b.disconnect();
        a.disconnect();
        assert!(!a.is_proxy_ready());
    }
    echo_task.abort();
    lktunnel::socks5_quic::set_ssrf_filter_enabled(true);
}

async fn transfer(proxy: std::net::SocketAddr, target: std::net::SocketAddr, round: u8) {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut greeting = [0; 2];
    s.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 0]);
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&target.port().to_be_bytes());
    s.write_all(&request).await.unwrap();
    let mut reply = [0; 10];
    s.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0);
    let payload = vec![round; 256 * 1024];
    let mut received = vec![0; payload.len()];
    let (mut r, mut w) = s.into_split();
    tokio::time::timeout(Duration::from_secs(5), async {
        let (sent, got) = tokio::join!(w.write_all(&payload), r.read_exact(&mut received));
        sent.unwrap();
        got.unwrap();
    })
    .await
    .expect("fresh call connected but did not transfer data");
    assert_eq!(received, payload);
}
