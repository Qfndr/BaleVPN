use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn short_bidirectional_blackout_retransmits_without_a_new_session() {
    let (a, b) = paired();
    let server = b.enable_quic_server().unwrap();
    let echo = tokio::spawn(async move {
        let connection = server.endpoint.accept().await.unwrap().await.unwrap();
        let (mut w, mut r) = connection.accept_bi().await.unwrap();
        let _ = tokio::io::copy(&mut r, &mut w).await;
    });
    a.ensure_quic_client().await.unwrap();
    let connection = a.quic_client.lock().as_ref().unwrap().connection.clone();
    let identity = connection.stable_id();
    let (mut w, mut r) = connection.open_bi().await.unwrap();
    w.write_all(b"before").await.unwrap();
    let mut warmup = [0; 6];
    r.read_exact(&mut warmup).await.unwrap();
    assert_eq!(&warmup, b"before");
    // Drop carrier datagrams in both directions, without touching the user's
    // network adapters or changing production packet forwarding.
    let a_rx = a.quic_rx_tx.lock().take();
    let b_rx = b.quic_rx_tx.lock().take();
    let payload = vec![0x5a; 256 * 1024];
    let mut received = vec![0; payload.len()];
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            async {
                tokio::time::sleep(Duration::from_millis(200)).await;
                *a.quic_rx_tx.lock() = a_rx;
                *b.quic_rx_tx.lock() = b_rx;
            },
            async {
                let (sent, got) = tokio::join!(w.write_all(&payload), r.read_exact(&mut received));
                sent.unwrap();
                got.unwrap();
            }
        );
    })
    .await
    .expect("transfer did not recover after short carrier blackout");
    assert_eq!(payload, received);
    assert!(a.is_peer_authenticated());
    assert_eq!(
        a.quic_client
            .lock()
            .as_ref()
            .unwrap()
            .connection
            .stable_id(),
        identity
    );
    a.disconnect();
    b.disconnect();
    echo.abort();
}

fn paired() -> (Arc<LkTunnel>, Arc<LkTunnel>) {
    let a = security::Identity::generate().unwrap();
    let b = security::Identity::generate().unwrap();
    connect_loopback_with_options(
        a.options(&[b.certificate.clone()], false, false).unwrap(),
        b.options(&[a.certificate.clone()], true, false).unwrap(),
    )
}

#[tokio::test]
async fn terminal_engine_state_still_releases_proxy_port_and_open_sockets() {
    let (a, b) = paired();
    b.start_server().unwrap();
    let address = a.enable_socks5_server(0).await.unwrap();
    a.ensure_quic_client().await.unwrap();
    let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while a
            .socks5_handle
            .lock()
            .as_ref()
            .unwrap()
            .conn_aborts
            .lock()
            .is_empty()
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    // This is the ordering on ICE failure: engine state changes before the
    // manager/desktop asks the tunnel to release its resources.
    a.state_tx.send_replace(TunnelState::Disconnected);
    a.connected.store(false, Ordering::Relaxed);
    a.disconnect();
    assert!(a.socks5_handle.lock().is_none());
    assert!(a.quic_client.lock().is_none());
    let read = tokio::time::timeout(Duration::from_secs(3), socket.read(&mut [0]))
        .await
        .unwrap();
    assert!(
        matches!(read, Ok(0) | Err(_)),
        "old SOCKS connection survived teardown"
    );
    let rebound = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Ok(listener) = tokio::net::TcpListener::bind(address).await {
                break listener;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    drop(rebound);
    a.disconnect(); // idempotent after terminal state and resource cleanup
    b.disconnect();
}

#[tokio::test]
async fn cancelling_a_handshake_does_not_poison_the_next_attempt() {
    let (a, b) = paired();
    assert!(
        tokio::time::timeout(Duration::from_millis(50), a.connect_quic_to_peer())
            .await
            .is_err()
    );
    assert!(
        a.quic_rx_tx.lock().is_none(),
        "cancelled handshake leaked receive slot"
    );
    b.start_server().unwrap();
    tokio::time::timeout(Duration::from_secs(5), a.ensure_quic_client())
        .await
        .unwrap()
        .unwrap();
    assert!(a.is_peer_authenticated());
    a.disconnect();
    b.disconnect();
}

#[tokio::test]
async fn closed_quic_is_not_ready_and_concurrent_ensure_recovers() {
    let (a, b) = paired();
    b.start_server().unwrap();
    a.ensure_quic_client().await.unwrap();
    let gate = a.connect_lock.lock().await;
    let old = a.quic_client.lock().as_ref().unwrap().connection.clone();
    old.close(0u32.into(), b"simulate lost transport");
    assert!(!a.is_quic_connected());
    assert!(!a.is_proxy_ready());
    let copy = a.clone();
    let ensure = tokio::spawn(async move { copy.ensure_quic_client().await });
    drop(gate);
    tokio::time::timeout(Duration::from_secs(5), ensure)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(a.is_peer_authenticated());
    assert_ne!(
        a.quic_client
            .lock()
            .as_ref()
            .unwrap()
            .connection
            .stable_id(),
        old.stable_id()
    );
    a.disconnect();
    b.disconnect();
}
