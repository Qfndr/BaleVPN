//! Local carrier feasibility probe; NOT a working iGap client.
//! No provider login, STUN/TURN, external signaling or LiveKit connection.
//! See docs/igap-research-fa.md for what this proves and what remains untested.
use std::{sync::Arc,time::{Duration,Instant}};
use bytes::Bytes;
use tokio::sync::mpsc;
use webrtc::{api::{APIBuilder,media_engine::{MediaEngine,MIME_TYPE_OPUS}},
    peer_connection::{RTCPeerConnection,configuration::RTCConfiguration},
    rtp::{header::Header,packet::Packet},
    rtp_transceiver::rtp_codec::RTCRtpCodecCapability,
    track::track_local::{TrackLocal,TrackLocalWriter,track_local_static_rtp::TrackLocalStaticRTP},
    dtls_transport::dtls_transport_state::RTCDtlsTransportState};

async fn peer()->Result<Arc<RTCPeerConnection>,Box<dyn std::error::Error>>{
    let mut media=MediaEngine::default();media.register_default_codecs()?;
    Ok(Arc::new(APIBuilder::new().with_media_engine(media).build()
        .new_peer_connection(RTCConfiguration{ice_servers:vec![],..Default::default()}).await?))
}
async fn negotiate(a:&RTCPeerConnection,b:&RTCPeerConnection)->Result<(),Box<dyn std::error::Error>>{
    let offer=a.create_offer(None).await?;let mut done=a.gathering_complete_promise().await;
    a.set_local_description(offer).await?;done.recv().await;
    let offer=a.local_description().await.ok_or("Missing local offer")?;
    if !offer.sdp.contains("a=fingerprint:sha-256")||!offer.sdp.contains("UDP/TLS/RTP/SAVPF"){return Err("Expected DTLS-SRTP offer".into());}
    b.set_remote_description(offer).await?;
    let answer=b.create_answer(None).await?;let mut done=b.gathering_complete_promise().await;
    b.set_local_description(answer).await?;done.recv().await;
    a.set_remote_description(b.local_description().await.ok_or("Missing answer")?).await?;Ok(())
}
fn payload(sequence:u16)->Bytes{Bytes::from((0..1024).map(|i|((i*37+sequence as usize*13)%256)as u8).collect::<Vec<_>>())}
async fn probe(a:&RTCPeerConnection,b:&RTCPeerConnection)->Result<serde_json::Value,Box<dyn std::error::Error>>{
    let (tx,mut rx)=mpsc::channel(256);
    let mut tracks=Vec::new();
    for (direction,pc) in [a,b].into_iter().enumerate(){
        let tx=tx.clone();pc.on_track(Box::new(move |track,_,_|{let tx=tx.clone();tokio::spawn(async move{
            while let Ok((packet,_))=track.read_rtp().await{if tx.send((direction,packet)).await.is_err(){break;}}
        });Box::pin(async{})}));
        let track=Arc::new(TrackLocalStaticRTP::new(RTCRtpCodecCapability{mime_type:MIME_TYPE_OPUS.to_owned(),clock_rate:48000,channels:2,..Default::default()},"carrier".into(),"local-feasibility".into()));
        let sender=pc.add_track(track.clone()as Arc<dyn TrackLocal+Send+Sync>).await?;
        tokio::spawn(async move{let mut rtcp=[0;1500];while sender.read(&mut rtcp).await.is_ok(){}});
        tracks.push(track);
    }
    negotiate(a,b).await?;
    let connected=Instant::now();while a.dtls_transport().state()!=RTCDtlsTransportState::Connected||b.dtls_transport().state()!=RTCDtlsTransportState::Connected{
        if connected.elapsed()>Duration::from_secs(10){return Err("Local DTLS-SRTP timeout".into());}
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let start=Instant::now();let mut received=[0usize;2];
    // Sequential checks bound memory and expose corrupt/duplicate/out-of-order data.
    for seq in 0u16..128{
        for (side,track)in tracks.iter().enumerate(){track.write_rtp(&Packet{header:Header{version:2,sequence_number:seq,timestamp:seq as u32*960,ssrc:1+side as u32,..Default::default()},payload:payload(seq)}).await?;}
        let mut seen=[false;2];for _ in 0..2{
            let (direction,packet)=tokio::time::timeout(Duration::from_secs(2),rx.recv()).await?.ok_or("Receiver closed")?;
            if seen[direction]||packet.header.sequence_number!=seq||packet.payload!=payload(seq){return Err("Local carrier integrity/order mismatch".into());}
            seen[direction]=true;received[direction]+=packet.payload.len();
        }
    }
    let selected=a.dtls_transport().ice_transport().get_selected_candidate_pair().await.is_some();
    if !selected{return Err("Missing selected ICE pair".into());}
    Ok(serde_json::json!({"ok":true,"localOnly":true,"providerVerified":false,"baleTransportModified":false,
        "carrier":"raw binary payload / Opus RTP / DTLS-SRTP","externalIceServers":0,
        "selectedIcePair":selected,"bytesEachDirection":received,"integrityCheckedPackets":256,
        "elapsedMs":start.elapsed().as_millis(),"liveIgapSignalingTested":false,"liveRelayTested":false,
        "internetThroughputBenchmark":false}))
}
#[tokio::main]
async fn main()->Result<(),Box<dyn std::error::Error>>{
    let a=peer().await?;let b=peer().await?;
    let result=tokio::time::timeout(Duration::from_secs(25),probe(&a,&b)).await;
    let _=a.close().await;let _=b.close().await;
    println!("{}",serde_json::to_string_pretty(&result??)?);Ok(())
}
