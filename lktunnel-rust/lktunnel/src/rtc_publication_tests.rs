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
    fixture_with_roster(Vec::new()).await
}
async fn fixture_with_roster(roster:Vec<proto::ParticipantInfo>) -> (String, tokio::task::JoinHandle<Socket>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        send(&mut socket, proto::signal_response::Message::Join(proto::JoinResponse {
            participant: Some(proto::ParticipantInfo { identity: "fixture-local".into(), ..Default::default() }),
            other_participants: roster,
            subscriber_primary: true,
            ping_interval: 60,
            ping_timeout: 120,
            ..Default::default()
        })).await;
        socket
    });
    (url, task)
}

#[tokio::test]
async fn joined_initial_roster_unblocks_startup_without_authenticating_the_peer() {
    let (url,accept)=fixture_with_roster(vec![proto::ParticipantInfo {
        identity:"fixture-remote".into(),state:proto::participant_info::State::Joined as i32,..Default::default()
    }]).await;
    let local=crate::security::Identity::generate().unwrap();
    let remote=crate::security::Identity::generate().unwrap();
    let options=local.options(&[remote.certificate],false,false).unwrap();
    let tunnel=crate::LkTunnel::connect_with_options(url,"fixture-token",crate::TunnelRole::Client,options);
    let mut events=tunnel.events().unwrap();
    let mut socket=timeout(LIMIT,accept).await.unwrap().unwrap();
    add_track(&mut socket).await;
    timeout(LIMIT,async {
        loop {
            match events.recv().await {
                Some(crate::Event {kind:crate::EventKind::Connected,..})=>break,
                Some(_)=>{},
                None=>panic!("tunnel closed before processing initial roster"),
            }
        }
    }).await.expect("initial JOINED participant did not unblock peer wait");
    assert!(tunnel.is_connected());
    timeout(LIMIT,async {
        while tunnel.media_diagnostic().unwrap()["quicClientStarted"]!=true {tokio::task::yield_now().await;}
    }).await.expect("initial roster did not start cryptographic warmup");
    let diagnostic=tunnel.media_diagnostic().unwrap();
    assert_eq!(diagnostic["peerCount"],1);
    assert_eq!(diagnostic["initialRosterPeerCount"],1);
    assert_eq!(diagnostic["peerWaitReleased"],true);
    assert!(!tunnel.is_peer_authenticated(),"roster presence is not cryptographic proof");
    tunnel.disconnect();
    assert_eq!(tunnel.media_diagnostic().unwrap()["quicClientStarted"],true,"terminal diagnostics must survive cleanup");
    timeout(LIMIT,async {while request(&mut socket).await.is_some(){}}).await.unwrap();
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
async fn no_negotiation(socket:&mut Socket) {
    let result=timeout(Duration::from_millis(40),async {
        loop {
            match request(socket).await {
                Some(proto::signal_request::Message::Offer(_)|proto::signal_request::Message::Answer(_)|proto::signal_request::Message::Trickle(_))=>return,
                None=>return,
                _=>{}, // Normal signaling heartbeat is unrelated to SDP/ICE order.
            }
        }
    }).await;
    assert!(result.is_err(),"negotiation escaped before its gate opened, or stream closed");
}
async fn closed_without_negotiation(socket:&mut Socket) {
    timeout(LIMIT,async {
        while let Some(message)=request(socket).await {
            assert!(!matches!(message,proto::signal_request::Message::Offer(_)|proto::signal_request::Message::Answer(_)|proto::signal_request::Message::Trickle(_)),"negotiation was sent after close");
        }
    }).await.unwrap();
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
async fn gathered_local_ice_is_held_until_its_actual_sdp_write() {
    for target in [proto::SignalTarget::Publisher,proto::SignalTarget::Subscriber] {
        let (url,accept)=fixture().await;
        let (signal,_,_events)=SignalClient::connect(&url,"fixture-token",SignalOptions::default()).await.unwrap();
        let signal=Arc::new(signal);
        let mut socket=accept.await.unwrap();
        let pc=Arc::new(super::make_api().unwrap().new_peer_connection(RTCConfiguration::default()).await.unwrap());
        let (events,_)=tokio::sync::mpsc::unbounded_channel();
        let gate=wire_pc(920,&pc,target==proto::SignalTarget::Publisher,target,signal.clone(),events);
        let generation=gate.begin().unwrap();
        let remote=super::make_api().unwrap().new_peer_connection(RTCConfiguration::default()).await.unwrap();
        let mut gathered=pc.gathering_complete_promise().await;
        let description=if target==proto::SignalTarget::Publisher {
            pc.create_data_channel("fixture",None).await.unwrap();
            pc.create_offer(None).await.unwrap()
        } else {
            remote.create_data_channel("fixture",None).await.unwrap();
            pc.set_remote_description(remote.create_offer(None).await.unwrap()).await.unwrap();
            pc.create_answer(None).await.unwrap()
        };
        pc.set_local_description(description.clone()).await.unwrap();
        timeout(LIMIT,gathered.recv()).await.unwrap();
        timeout(LIMIT,async {while gate.state.lock().pending.is_empty(){tokio::task::yield_now().await;}}).await.unwrap();
        no_negotiation(&mut socket).await;
        let session=proto::SessionDescription {r#type:description.sdp_type.to_string(),sdp:description.sdp,id:37,..Default::default()};
        let message=if target==proto::SignalTarget::Publisher {proto::signal_request::Message::Offer(session)} else {proto::signal_request::Message::Answer(session)};
        gate.send_sdp(&signal,generation,message).await.unwrap();
        match request(&mut socket).await.unwrap() {
            proto::signal_request::Message::Offer(sdp)|proto::signal_request::Message::Answer(sdp)=>assert_eq!(sdp.id,37),
            _=>panic!("first negotiation message was not SDP"),
        }
        match request(&mut socket).await.unwrap() {
            proto::signal_request::Message::Trickle(candidate)=>assert_eq!(candidate.target,target as i32),
            _=>panic!("queued ICE was not forwarded after SDP"),
        }
        let previous_stream=gate.state.lock().stream.clone().unwrap();
        gate.begin().unwrap();
        assert!(gate.candidate("next-generation".into()).unwrap().is_none());
        assert!(gate.release(generation,previous_stream).is_err());
        assert!(!gate.state.lock().ready);
        assert_eq!(gate.state.lock().pending.len(),1);
        gate.close();
        pc.close().await.unwrap();remote.close().await.unwrap();
        timeout(LIMIT,async {tokio::join!(signal.close(),async {while request(&mut socket).await.is_some(){}});}).await.unwrap();
    }
}

#[tokio::test]
async fn failed_sdp_write_never_opens_or_replays_queued_local_ice() {
    let (url,accept)=fixture().await;
    let (signal,_,_events)=SignalClient::connect(&url,"fixture-token",SignalOptions::default()).await.unwrap();
    let mut socket=accept.await.unwrap();
    let gate=LocalIceGate {target:proto::SignalTarget::Subscriber as i32,state:Mutex::new(LocalIceState::default())};
    let generation=gate.begin().unwrap();
    assert!(gate.candidate("fixture".into()).unwrap().is_none());
    signal.abort().await;
    let result=timeout(LIMIT,gate.send_sdp(&signal,generation,proto::signal_request::Message::Answer(proto::SessionDescription::default()))).await.unwrap();
    assert!(result.is_err());
    assert!(!gate.state.lock().ready);
    assert!(gate.state.lock().pending.is_empty());
    closed_without_negotiation(&mut socket).await;
}

#[test]
fn local_ice_queue_has_explicit_count_and_byte_bounds() {
    let gate=LocalIceGate {target:0,state:Mutex::new(LocalIceState::default())};
    gate.begin().unwrap();
    assert!(gate.candidate("x".repeat(MAX_REMOTE_ICE_JSON+1)).is_err());
    for index in 0..MAX_PENDING_REMOTE_ICE {assert!(gate.candidate(format!("candidate-{index}")).unwrap().is_none());}
    assert!(gate.candidate("overflow".into()).is_err());
    let next=gate.begin().unwrap();
    assert_eq!(next,2);
    assert!(gate.state.lock().pending.is_empty());
    assert!(!gate.state.lock().ready);
    for index in 0..4 {assert!(gate.candidate(format!("{index}{}","x".repeat(MAX_REMOTE_ICE_JSON-1))).unwrap().is_none());}
    assert!(gate.candidate("more".into()).is_err());
}

#[tokio::test]
async fn checked_negotiation_write_rejects_another_stream_token_without_sending() {
    let (url_a,accept_a)=fixture().await;
    let (a,_,_events_a)=SignalClient::connect(&url_a,"fixture-token",SignalOptions::default()).await.unwrap();
    let mut socket_a=accept_a.await.unwrap();
    let token=a.send_sdp_or_ice(proto::signal_request::Message::Offer(proto::SessionDescription::default()),None).await.unwrap();
    assert!(matches!(request(&mut socket_a).await,Some(proto::signal_request::Message::Offer(_))));
    let (url_b,accept_b)=fixture().await;
    let (b,_,_events_b)=SignalClient::connect(&url_b,"fixture-token",SignalOptions::default()).await.unwrap();
    let mut socket_b=accept_b.await.unwrap();
    let result=b.send_sdp_or_ice(proto::signal_request::Message::Trickle(proto::TrickleRequest::default()),Some(&token)).await;
    assert!(result.is_err());
    no_negotiation(&mut socket_b).await;
    a.abort().await;b.abort().await;
    assert!(timeout(LIMIT,LocalIceGate::write(&a,proto::signal_request::Message::Trickle(proto::TrickleRequest::default()),Some(&token))).await.unwrap().is_err());
    closed_without_negotiation(&mut socket_a).await;
    closed_without_negotiation(&mut socket_b).await;
}

#[tokio::test]
async fn cancelled_sdp_completion_cannot_reopen_gate_or_cancel_a_new_generation() {
    let (url,accept)=fixture().await;
    let (signal,_,_events)=SignalClient::connect(&url,"fixture-token",SignalOptions::default()).await.unwrap();
    let signal=Arc::new(signal);let mut socket=accept.await.unwrap();
    let token=signal.send_sdp_or_ice(proto::signal_request::Message::Offer(proto::SessionDescription::default()),None).await.unwrap();
    request(&mut socket).await.unwrap();
    for fail in [false,true] {
        let gate=Arc::new(LocalIceGate {target:0,state:Mutex::new(LocalIceState::default())});
        let generation=gate.begin().unwrap();gate.candidate("old".into()).unwrap();
        let (started,waiting)=tokio::sync::oneshot::channel();
        let (release,resume)=tokio::sync::oneshot::channel();
        let task=tokio::spawn({let gate=gate.clone();let signal=signal.clone();let token=token.clone();async move {
            gate.finish_sdp(&signal,generation,async move {
                let _=started.send(());resume.await.unwrap();
                if fail {Err("write failed".to_owned())}else{Ok(token)}
            }).await
        }});
        waiting.await.unwrap();
        gate.close();
        assert!(gate.candidate("late-after-close".into()).unwrap().is_none());
        assert!(gate.state.lock().pending.is_empty());
        let next=gate.begin().unwrap();gate.candidate("new".into()).unwrap();
        release.send(()).unwrap();assert!(task.await.unwrap().is_err());
        assert_eq!(gate.state.lock().generation,next);
        assert!(gate.state.lock().accepting);
        assert!(!gate.state.lock().ready);
        assert_eq!(gate.state.lock().pending.len(),1);
        no_negotiation(&mut socket).await;
        gate.close();
    }
    signal.abort().await;closed_without_negotiation(&mut socket).await;
}

#[tokio::test]
async fn exact_publication_ack_gates_offer_while_subscriber_negotiates() {
    let (url, accept) = fixture().await;
    let connect = tokio::spawn(async move { Engine::connect_inner(901, &url, "fixture-token", Arc::new(|_| {}), true, IceRouting::default(), LIMIT).await });
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
    for candidate_init in ["invalid-json",r#"{"candidate":"invalid-candidate"}"#] {
        send(&mut socket,proto::signal_response::Message::Trickle(proto::TrickleRequest {candidate_init:candidate_init.into(),target:proto::SignalTarget::Subscriber as i32,..Default::default()})).await;
    }
    send(&mut socket, proto::signal_response::Message::Offer(proto::SessionDescription {
        r#type: "offer".into(), sdp: offer.sdp, id: 73, ..Default::default()
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
    assert_eq!(answer.id, 73, "subscriber answer must echo the SFU offer id");
    remote.set_remote_description(RTCSessionDescription::answer(answer.sdp).unwrap()).await.unwrap();
    no_offer(&mut socket).await;
    acknowledge(&mut socket, &track.cid, Some(audio_track())).await;
    let publisher_offer=timeout(LIMIT, async {
        loop {
            if let Some(proto::signal_request::Message::Offer(offer)) = request(&mut socket).await {
                assert_eq!(offer.r#type, "offer");
                assert!(offer.sdp.contains("m=audio"));
                break offer;
            }
        }
    }).await.unwrap();
    let (engine, senders, _) = timeout(LIMIT, connect).await.unwrap().unwrap().unwrap();
    assert_eq!(senders.len(), rtp::TRACK_COUNT);
    assert_eq!(publisher_offer.id,1);
    let publishing_remote=super::make_api().unwrap().new_peer_connection(RTCConfiguration::default()).await.unwrap();
    publishing_remote.set_remote_description(RTCSessionDescription::offer(publisher_offer.sdp).unwrap()).await.unwrap();
    let publisher_answer=publishing_remote.create_answer(None).await.unwrap();
    publishing_remote.set_local_description(publisher_answer.clone()).await.unwrap();
    send(&mut socket,proto::signal_response::Message::Answer(proto::SessionDescription {
        r#type:"answer".into(),sdp:publisher_answer.sdp.clone(),id:2,..Default::default()
    })).await;
    // A second subscriber negotiation is an ordered barrier: when its answer
    // arrives, the earlier stale publisher answer has necessarily been handled.
    let next_offer=remote.create_offer(None).await.unwrap();
    remote.set_local_description(next_offer.clone()).await.unwrap();
    send(&mut socket,proto::signal_response::Message::Offer(proto::SessionDescription {
        r#type:"offer".into(),sdp:next_offer.sdp,id:74,..Default::default()
    })).await;
    let next_answer=timeout(LIMIT,async {
        loop { if let Some(proto::signal_request::Message::Answer(answer))=request(&mut socket).await { break answer; } }
    }).await.unwrap();
    assert_eq!(next_answer.id,74);
    remote.set_remote_description(RTCSessionDescription::answer(next_answer.sdp).unwrap()).await.unwrap();
    assert!(engine.publisher.remote_description().await.is_none(),"stale nonzero publisher answer was applied");
    // The peer can receive the answer before the sending task publishes its
    // post-write diagnostics. Wait for that completion before reading them.
    let diagnostic = timeout(LIMIT, async {
        loop {
            let diagnostic = engine.media_diagnostic()["negotiation"].clone();
            if diagnostic["subscriberAnswerId"] == 74 {
                break diagnostic;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    for (key,value) in [("publisherOfferId",1),("subscriberOfferId",74),("subscriberAnswerId",74),("subscriberOfferCount",2),("stalePublisherAnswers",1)] {
        assert_eq!(diagnostic[key],value);
    }
    assert_eq!(diagnostic["subscriberOffer"]["audioSections"],1);
    assert_eq!(diagnostic["subscriberAnswer"]["hasIcePassword"],true);
    assert_eq!(diagnostic["remoteIce"]["subscriber"]["received"],2);
    assert_eq!(diagnostic["remoteIce"]["subscriber"]["parseFailed"],1);
    assert_eq!(diagnostic["remoteIce"]["subscriber"]["addFailed"],1);
    send(&mut socket,proto::signal_response::Message::Answer(proto::SessionDescription {
        r#type:"answer".into(),sdp:publisher_answer.sdp,id:1,..Default::default()
    })).await;
    timeout(LIMIT,async {while engine.publisher.remote_description().await.is_none(){tokio::task::yield_now().await;}}).await.unwrap();
    shutdown(&engine, &mut socket).await;
    remote.close().await.unwrap();
    publishing_remote.close().await.unwrap();
}

#[tokio::test]
async fn publication_response_without_track_fails_and_closes_socket() {
    let (url, accept) = fixture().await;
    let connect = tokio::spawn(async move { Engine::connect_inner(902, &url, "fixture-token", Arc::new(|_| {}), true, IceRouting::default(), LIMIT).await });
    let mut socket = timeout(LIMIT, accept).await.unwrap().unwrap();
    let track = add_track(&mut socket).await;
    acknowledge(&mut socket, &track.cid, None).await;
    let result = timeout(LIMIT, connect).await.unwrap().unwrap();
    assert!(matches!(result, Err(ref reason) if reason == "track publication response invalid"));
    closed_without_offer(&mut socket).await;
}

#[tokio::test]
async fn subscriber_accepts_application_only_offer_without_a_local_data_channel() {
    let (url, accept) = fixture().await;
    let connect=tokio::spawn(async move {Engine::connect_inner(909,&url,"fixture-token",Arc::new(|_|{}),true, IceRouting::default(), LIMIT).await});
    let mut socket=timeout(LIMIT,accept).await.unwrap().unwrap();
    let track=add_track(&mut socket).await;
    let remote=super::make_api().unwrap().new_peer_connection(RTCConfiguration::default()).await.unwrap();
    remote.create_data_channel("fixture-control",None).await.unwrap();
    let mut gathering=remote.gathering_complete_promise().await;
    let offer=remote.create_offer(None).await.unwrap();
    remote.set_local_description(offer).await.unwrap();
    timeout(LIMIT,gathering.recv()).await.unwrap();
    let offer=remote.local_description().await.unwrap();
    assert!(offer.sdp.contains("m=application"));
    assert!(!offer.sdp.contains("m=audio"));
    send(&mut socket,proto::signal_response::Message::Offer(proto::SessionDescription {
        r#type:"offer".into(),sdp:offer.sdp,id:91,..Default::default()
    })).await;
    timeout(LIMIT,async {
        loop {
            if remote.connection_state()==RTCPeerConnectionState::Connected {break;}
            tokio::select! {
                incoming=request(&mut socket)=>match incoming.expect("subscriber transport socket closed") {
                    proto::signal_request::Message::Answer(answer)=>{
                        assert_eq!(answer.id,91);
                        assert!(answer.sdp.contains("m=application"));
                        remote.set_remote_description(RTCSessionDescription::answer(answer.sdp).unwrap()).await.unwrap();
                    },
                    proto::signal_request::Message::Trickle(candidate) if candidate.target==proto::SignalTarget::Subscriber as i32=>{
                        remote.add_ice_candidate(serde_json::from_str(&candidate.candidate_init).unwrap()).await.unwrap();
                    },
                    proto::signal_request::Message::Offer(_)=>panic!("publisher started before explicit acknowledgement"),
                    _=>{},
                },
                _=tokio::time::sleep(Duration::from_millis(5))=>{},
            }
        }
    }).await.expect("application-only subscriber ICE/DTLS did not connect");
    acknowledge(&mut socket,&track.cid,Some(audio_track())).await;
    let (engine,_,_)=timeout(LIMIT,connect).await.unwrap().unwrap().unwrap();
    assert_eq!(engine.subscriber.connection_state(),RTCPeerConnectionState::Connected);
    engine.capture_ice_stats().await;
    let stats=engine.media_diagnostic()["candidateStats"]["subscriber"].clone();
    assert_eq!(stats["status"],"ok");
    assert!(stats["remoteCandidates"].as_u64().unwrap()>0);
    assert!(stats["pairsSucceeded"].as_u64().unwrap()>0);
    assert_eq!(stats["requestCountersSupported"],false);
    assert_eq!(stats["configuredTransportRole"],"controlled");
    assert_eq!(stats["selectedPairPresent"],true);
    assert_eq!(stats["transportState"],"connected");
    assert_eq!(stats["dtlsState"],"connected");
    assert!(!stats.to_string().contains("candidate:"));
    shutdown(&engine,&mut socket).await;
    remote.close().await.unwrap();
}

#[tokio::test]
async fn publication_timeout_closes_socket_without_negotiation() {
    let (url, accept) = fixture().await;
    let connect = tokio::spawn(async move { Engine::connect_inner(903, &url, "fixture-token", Arc::new(|_| {}), true, IceRouting::default(), Duration::from_millis(50)).await });
    let mut socket = timeout(LIMIT, accept).await.unwrap().unwrap();
    add_track(&mut socket).await;
    let result = timeout(LIMIT, connect).await.unwrap().unwrap();
    assert!(matches!(result, Err(ref reason) if reason == "track publication timed out"));
    closed_without_offer(&mut socket).await;
}

#[tokio::test]
async fn cancelled_publication_wait_closes_socket() {
    let (url, accept) = fixture().await;
    let connect = tokio::spawn(async move { Engine::connect_inner(904, &url, "fixture-token", Arc::new(|_| {}), true, IceRouting::default(), LIMIT).await });
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
    let connect = tokio::spawn(async move { Engine::connect_inner(905, &url, "fixture-token", Arc::new(|_| {}), false, IceRouting::default(), LIMIT).await });
    let mut socket = timeout(LIMIT, accept).await.unwrap().unwrap();
    add_track(&mut socket).await;
    let offer=timeout(LIMIT, async {
        loop {
            match request(&mut socket).await.expect("legacy socket closed") {
                proto::signal_request::Message::Offer(offer) => break offer,
                _ => {}
            }
        }
    }).await.expect("legacy mode incorrectly waited for publication ACK");
    let (engine, _, _) = timeout(LIMIT, connect).await.unwrap().unwrap().unwrap();
    assert_eq!(offer.id,1);
    let remote=super::make_api().unwrap().new_peer_connection(RTCConfiguration::default()).await.unwrap();
    remote.set_remote_description(RTCSessionDescription::offer(offer.sdp).unwrap()).await.unwrap();
    let answer=remote.create_answer(None).await.unwrap();
    remote.set_local_description(answer.clone()).await.unwrap();
    send(&mut socket,proto::signal_response::Message::Answer(proto::SessionDescription {
        r#type:"answer".into(),sdp:answer.sdp,id:0,..Default::default()
    })).await;
    timeout(LIMIT,async {while engine.publisher.remote_description().await.is_none(){tokio::task::yield_now().await;}}).await.unwrap();
    assert_eq!(engine.media_diagnostic()["negotiation"]["stalePublisherAnswers"],0);
    shutdown(&engine, &mut socket).await;
    remote.close().await.unwrap();
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
        local_ice:Vec::new(),
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
        Engine::connect_inner(906, &url, "fixture-token", Arc::new(|_| {}), true, IceRouting::default(), LIMIT).await
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

#[tokio::test]
async fn terminal_rtp_counts_require_actual_rtp_and_omit_stream_identifiers() {
    let api = super::make_api().unwrap();
    let sender = api
        .new_peer_connection(RTCConfiguration::default())
        .await
        .unwrap();
    let receiver = api
        .new_peer_connection(RTCConfiguration::default())
        .await
        .unwrap();
    let track = Arc::new(TrackLocalStaticSample::new(
        RTCRtpCodecCapability {
            mime_type: MIME_TYPE_OPUS.into(),
            clock_rate: 48000,
            channels: 2,
            ..Default::default()
        },
        "private-fixture-track".into(),
        "private-fixture-stream".into(),
    ));
    sender.add_track(track.clone()).await.unwrap();
    let before = super::peer_ice_stats(&sender).await;
    assert!(before["rtp"]["outboundPacketWrites"].is_null());
    let (received_track, mut tracks) = tokio::sync::mpsc::unbounded_channel();
    receiver.on_track(Box::new(move |track, _, _| {
        let _ = received_track.send(track);
        Box::pin(async {})
    }));
    let mut gather = sender.gathering_complete_promise().await;
    sender
        .set_local_description(sender.create_offer(None).await.unwrap())
        .await
        .unwrap();
    timeout(LIMIT, gather.recv()).await.unwrap();
    receiver
        .set_remote_description(sender.local_description().await.unwrap())
        .await
        .unwrap();
    let mut gather = receiver.gathering_complete_promise().await;
    receiver
        .set_local_description(receiver.create_answer(None).await.unwrap())
        .await
        .unwrap();
    timeout(LIMIT, gather.recv()).await.unwrap();
    sender
        .set_remote_description(receiver.local_description().await.unwrap())
        .await
        .unwrap();
    timeout(LIMIT, async {
        while sender.connection_state() != RTCPeerConnectionState::Connected {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let payload = bytes::Bytes::from_static(&[0x78, 1, 2, 3, 4]);
    track
        .write_sample(&Sample {
            data: payload.clone(),
            duration: Duration::from_millis(20),
            ..Default::default()
        })
        .await
        .unwrap();
    let remote = timeout(LIMIT, tracks.recv()).await.unwrap().unwrap();
    let (packet, _) = timeout(LIMIT, remote.read_rtp()).await.unwrap().unwrap();
    assert_eq!(packet.payload, payload);
    let (sent, received) = timeout(LIMIT, async {
        loop {
            let (sent, received) = tokio::join!(
                super::peer_ice_stats(&sender),
                super::peer_ice_stats(&receiver)
            );
            if sent["rtp"]["outboundPacketWrites"].as_u64().unwrap_or(0) > 0
                && received["rtp"]["inboundPackets"].as_u64().unwrap_or(0) > 0
            {
                break (sent, received);
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(sent["rtp"]["outboundPayloadBytes"].as_u64().unwrap() >= payload.len() as u64);
    assert!(received["rtp"]["inboundPayloadBytes"].as_u64().unwrap() >= payload.len() as u64);
    for summary in [sent, received] {
        let text = summary.to_string();
        assert!(!text.contains("private-fixture"));
        assert!(!text.contains("127.0.0.1"));
    }
    sender.close().await.unwrap();
    receiver.close().await.unwrap();
}

#[tokio::test]
async fn sender_queue_counts_reservations_and_rejects_full_or_closed_without_growth() {
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    let task = tokio::spawn(async {});
    let sender = RtpSender {
        tx,
        depth: Arc::new(AtomicUsize::new(0)),
        _writer: task.abort_handle(),
        _track: Arc::new(TrackLocalStaticSample::new(
            RTCRtpCodecCapability::default(),
            "fixture".into(),
            "fixture".into(),
        )),
    };
    assert!(sender.send(&[1]));
    assert_eq!(sender.queue_depth(), 1);
    assert!(!sender.send(&[2]));
    assert_eq!(sender.queue_depth(), 1);
    drop(rx);
    assert!(!sender.send(&[3]));
    assert_eq!(sender.queue_depth(), 0);
    task.await.unwrap();
}
