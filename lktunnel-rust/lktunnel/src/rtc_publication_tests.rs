//! Local wire-level regressions: no provider credentials or external SFU.
use super::*;
use futures_util::{SinkExt, StreamExt};
use prost::Message as _;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_tungstenite::{accept_async, tungstenite::Message, WebSocketStream};

type Socket = WebSocketStream<TcpStream>;
const LIMIT: Duration = Duration::from_secs(5);

async fn fixture() -> (String, tokio::task::JoinHandle<Socket>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        send(&mut socket, proto::signal_response::Message::Join(proto::JoinResponse {
            participant: Some(proto::ParticipantInfo { identity: "fixture-local".into(), ..Default::default() }),
            subscriber_primary: true,
            ping_interval: 60,
            ping_timeout: 120,
            ..Default::default()
        })).await;
        socket
    });
    (url, task)
}

async fn send(socket: &mut Socket, message: proto::signal_response::Message) {
    socket.send(Message::Binary(proto::SignalResponse { message: Some(message) }.encode_to_vec().into())).await.unwrap();
}

async fn request(socket: &mut Socket) -> Option<proto::signal_request::Message> {
    loop {
        match socket.next().await {
            Some(Ok(Message::Binary(data))) => {
                if let Some(message) = proto::SignalRequest::decode(data.as_ref()).unwrap().message {
                    return Some(message);
                }
            }
            Some(Ok(Message::Ping(data))) => { let _ = socket.send(Message::Pong(data)).await; }
            Some(Ok(Message::Close(_))) => {
                let _ = socket.flush().await;
                return None;
            }
            Some(Err(_)) | None => return None,
            _ => {}
        }
    }
}

async fn add_track(socket: &mut Socket) -> proto::AddTrackRequest {
    timeout(LIMIT, async {
        loop {
            match request(socket).await.expect("socket closed before AddTrack") {
                proto::signal_request::Message::AddTrack(track) => return track,
                proto::signal_request::Message::Offer(_) => panic!("offer preceded AddTrack"),
                _ => {}
            }
        }
    }).await.expect("AddTrack deadline")
}

async fn acknowledge(socket: &mut Socket, cid: &str, track: Option<proto::TrackInfo>) {
    send(socket, proto::signal_response::Message::TrackPublished(proto::TrackPublishedResponse {
        cid: cid.into(), track,
    })).await;
}

fn audio_track() -> proto::TrackInfo {
    proto::TrackInfo { sid: "TR_fixture".into(), r#type: proto::TrackType::Audio as i32, ..Default::default() }
}

async fn no_offer(socket: &mut Socket) {
    // Drain all other messages throughout the interval, rather than mistaking
    // an ICE/ping message for proof that no publisher offer was emitted.
    assert!(timeout(Duration::from_millis(80), async {
        loop {
            match request(socket).await.expect("connection unexpectedly closed") {
                proto::signal_request::Message::Offer(_) => return,
                _ => {}
            }
        }
    }).await.is_err(), "publisher negotiated before matching publication ACK");
}

async fn closed_without_offer(socket: &mut Socket) {
    timeout(LIMIT, async {
        while let Some(message) = request(socket).await {
            assert!(!matches!(message, proto::signal_request::Message::Offer(_)), "failed startup emitted offer");
        }
    }).await.expect("failed/cancelled startup retained its signaling socket");
}

async fn shutdown(engine: &Engine, socket: &mut Socket) {
    timeout(LIMIT, async {
        tokio::join!(engine.close(), async {
            while request(socket).await.is_some() {}
        });
    }).await.expect("engine shutdown deadline");
}

#[tokio::test]
async fn exact_publication_ack_gates_offer_while_subscriber_negotiates() {
    let (url, accept) = fixture().await;
    let connect = tokio::spawn(async move { Engine::connect_inner(901, &url, "fixture-token", Arc::new(|_| {}), true, LIMIT).await });
    let mut socket = timeout(LIMIT, accept).await.unwrap().unwrap();
    let track = add_track(&mut socket).await;
    no_offer(&mut socket).await;
    acknowledge(&mut socket, "unrelated-cid", Some(audio_track())).await;
    no_offer(&mut socket).await;

    let remote = super::make_api().unwrap().new_peer_connection(RTCConfiguration::default()).await.unwrap();
    remote.add_track(Arc::new(TrackLocalStaticSample::new(
        RTCRtpCodecCapability { mime_type: MIME_TYPE_OPUS.into(), clock_rate: 48000, channels: 2, ..Default::default() },
        "remote-audio".into(), "remote-stream".into(),
    ))).await.unwrap();
    let offer = remote.create_offer(None).await.unwrap();
    remote.set_local_description(offer.clone()).await.unwrap();
    send(&mut socket, proto::signal_response::Message::Offer(proto::SessionDescription {
        r#type: "offer".into(), sdp: offer.sdp, ..Default::default()
    })).await;
    let answer = timeout(LIMIT, async {
        loop {
            match request(&mut socket).await.expect("socket closed during subscriber negotiation") {
                proto::signal_request::Message::Answer(answer) => return answer,
                proto::signal_request::Message::Offer(_) => panic!("publisher offer before publication ACK"),
                _ => {}
            }
        }
    }).await.unwrap();
    assert_eq!(answer.r#type, "answer");
    remote.set_remote_description(RTCSessionDescription::answer(answer.sdp).unwrap()).await.unwrap();
    no_offer(&mut socket).await;
    acknowledge(&mut socket, &track.cid, Some(audio_track())).await;
    timeout(LIMIT, async {
        loop {
            if let Some(proto::signal_request::Message::Offer(offer)) = request(&mut socket).await {
                assert_eq!(offer.r#type, "offer");
                assert!(offer.sdp.contains("m=audio"));
                break;
            }
        }
    }).await.unwrap();
    let (engine, senders, _) = timeout(LIMIT, connect).await.unwrap().unwrap().unwrap();
    assert_eq!(senders.len(), rtp::TRACK_COUNT);
    shutdown(&engine, &mut socket).await;
    remote.close().await.unwrap();
}

#[tokio::test]
async fn publication_response_without_track_fails_and_closes_socket() {
    let (url, accept) = fixture().await;
    let connect = tokio::spawn(async move { Engine::connect_inner(902, &url, "fixture-token", Arc::new(|_| {}), true, LIMIT).await });
    let mut socket = timeout(LIMIT, accept).await.unwrap().unwrap();
    let track = add_track(&mut socket).await;
    acknowledge(&mut socket, &track.cid, None).await;
    let result = timeout(LIMIT, connect).await.unwrap().unwrap();
    assert!(matches!(result, Err(ref reason) if reason == "track publication response invalid"));
    closed_without_offer(&mut socket).await;
}

#[tokio::test]
async fn publication_timeout_closes_socket_without_negotiation() {
    let (url, accept) = fixture().await;
    let connect = tokio::spawn(async move { Engine::connect_inner(903, &url, "fixture-token", Arc::new(|_| {}), true, Duration::from_millis(50)).await });
    let mut socket = timeout(LIMIT, accept).await.unwrap().unwrap();
    add_track(&mut socket).await;
    let result = timeout(LIMIT, connect).await.unwrap().unwrap();
    assert!(matches!(result, Err(ref reason) if reason == "track publication timed out"));
    closed_without_offer(&mut socket).await;
}

#[tokio::test]
async fn cancelled_publication_wait_closes_socket() {
    let (url, accept) = fixture().await;
    let connect = tokio::spawn(async move { Engine::connect_inner(904, &url, "fixture-token", Arc::new(|_| {}), true, LIMIT).await });
    let mut socket = timeout(LIMIT, accept).await.unwrap().unwrap();
    add_track(&mut socket).await;
    connect.abort();
    assert!(matches!(connect.await, Err(error) if error.is_cancelled()));
    closed_without_offer(&mut socket).await;
}

#[tokio::test]
async fn legacy_mode_negotiates_without_publication_ack() {
    assert!(!crate::security::TunnelOptions::default().wait_for_track_published);
    let (url, accept) = fixture().await;
    let connect = tokio::spawn(async move { Engine::connect_inner(905, &url, "fixture-token", Arc::new(|_| {}), false, LIMIT).await });
    let mut socket = timeout(LIMIT, accept).await.unwrap().unwrap();
    add_track(&mut socket).await;
    timeout(LIMIT, async {
        loop {
            match request(&mut socket).await.expect("legacy socket closed") {
                proto::signal_request::Message::Offer(_) => break,
                _ => {}
            }
        }
    }).await.expect("legacy mode incorrectly waited for publication ACK");
    let (engine, _, _) = timeout(LIMIT, connect).await.unwrap().unwrap().unwrap();
    shutdown(&engine, &mut socket).await;
}

#[tokio::test]
async fn signal_abort_completes_without_remote_close_handshake() {
    let (url, accept) = fixture().await;
    let connect = tokio::spawn(async move {
        SignalClient::connect(&url, "fixture-token", SignalOptions::default()).await
    });
    // Keep the server socket alive and deliberately never poll it after Join.
    // No server task can read a Close frame or supply its acknowledgement.
    let silent_socket = timeout(LIMIT, accept).await.unwrap().unwrap();
    let (signal, _, _events) = timeout(LIMIT, connect).await.unwrap().unwrap().unwrap();
    timeout(Duration::from_millis(500), signal.abort()).await
        .expect("abort waited for the silent server's close handshake");
    assert!(!signal.is_connected().await);
    timeout(Duration::from_millis(500), signal.abort()).await
        .expect("repeat abort must remain idempotent");
    drop(silent_socket);
}

#[tokio::test]
async fn signal_abort_interrupts_an_already_waiting_graceful_close() {
    let (url, accept) = fixture().await;
    let connect = tokio::spawn(async move {
        SignalClient::connect(&url, "fixture-token", SignalOptions::default()).await
    });
    let silent_socket = timeout(LIMIT, accept).await.unwrap().unwrap();
    let (signal, _, _events) = timeout(LIMIT, connect).await.unwrap().unwrap().unwrap();
    let signal = Arc::new(signal);
    let closing = {
        let signal = signal.clone();
        tokio::spawn(async move { signal.close().await })
    };
    tokio::task::yield_now().await;
    // Abort handles must be reachable independently of the stream write lock
    // held by close while it waits for the unpolled server's read response.
    timeout(Duration::from_millis(500), signal.abort()).await.unwrap();
    timeout(Duration::from_millis(500), closing).await.unwrap().unwrap();
    assert!(!signal.is_connected().await);
    drop(silent_socket);
}

#[tokio::test]
async fn abandoned_startup_closes_both_actual_peer_connections_with_silent_server() {
    let (url, accept) = fixture().await;
    let connect = tokio::spawn(async move {
        SignalClient::connect(&url, "fixture-token", SignalOptions::default()).await
    });
    let silent_socket = timeout(LIMIT, accept).await.unwrap().unwrap();
    let (signal, _, _events) = timeout(LIMIT, connect).await.unwrap().unwrap().unwrap();
    let signal = Arc::new(signal);
    let api = super::make_api().unwrap();
    let publisher = Arc::new(api.new_peer_connection(RTCConfiguration::default()).await.unwrap());
    let subscriber = Arc::new(api.new_peer_connection(RTCConfiguration::default()).await.unwrap());
    let (closed_tx, mut closed_rx) = tokio::sync::mpsc::unbounded_channel();
    for (index, pc) in [&publisher, &subscriber].into_iter().enumerate() {
        let closed_tx = closed_tx.clone();
        pc.on_peer_connection_state_change(Box::new(move |state| {
            if state == RTCPeerConnectionState::Closed {
                let _ = closed_tx.send(index);
            }
            Box::pin(async {})
        }));
    }
    drop(super::StartupResources {
        signal: signal.clone(),
        publisher: Some(publisher.clone()),
        subscriber: Some(subscriber.clone()),
        task: None,
        armed: true,
    });
    timeout(Duration::from_secs(2), async {
        let mut observed = [false; 2];
        while !observed.into_iter().all(|closed| closed) {
            observed[closed_rx.recv().await.expect("close event channel ended")] = true;
        }
    }).await.expect("abandoned startup retained a peer connection");
    assert_eq!(publisher.connection_state(), RTCPeerConnectionState::Closed);
    assert_eq!(subscriber.connection_state(), RTCPeerConnectionState::Closed);
    // The cleanup's signaling task also finishes despite the unpolled peer.
    timeout(Duration::from_secs(2), async {
        while signal.is_connected().await { tokio::task::yield_now().await; }
    }).await.expect("abandoned startup retained its signaling connection");
    drop(silent_socket);
}

#[tokio::test]
async fn cancelling_before_join_aborts_the_already_running_signal_stream() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let accept = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        accept_async(stream).await.unwrap()
    });
    let connect = tokio::spawn(async move {
        Engine::connect_inner(906, &url, "fixture-token", Arc::new(|_| {}), true, LIMIT).await
    });
    let mut socket = timeout(LIMIT, accept).await.unwrap().unwrap();
    // Do not send JoinResponse. A successful ping/pong proves both stream I/O
    // tasks started, so cancellation tests the pending-Join ownership gap,
    // rather than merely dropping an unfinished WebSocket handshake.
    let ping = vec![7, 3, 1];
    socket.send(Message::Ping(ping.clone().into())).await.unwrap();
    timeout(LIMIT, async {
        loop {
            match socket.next().await {
                Some(Ok(Message::Pong(data))) if data.as_ref() == ping.as_slice() => break,
                Some(Ok(Message::Binary(_))) => panic!("application request before JoinResponse"),
                Some(Ok(_)) => {},
                _ => panic!("signal stream ended before proving I/O startup"),
            }
        }
    }).await.expect("pending signal stream did not answer ping");
    assert!(!connect.is_finished(), "startup unexpectedly completed without JoinResponse");
    connect.abort();
    assert!(matches!(connect.await, Err(error) if error.is_cancelled()));
    closed_without_offer(&mut socket).await;
}
