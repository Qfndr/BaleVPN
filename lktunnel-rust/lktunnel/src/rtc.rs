//! Pure-Rust WebRTC engine — the LiveKit-SFU transport that used to be
//! the `livekit` SDK (libwebrtc under the hood). Replaced with
//! `webrtc-rs` + the reused `livekit-api` signal client + `livekit-
//! protocol` wire types, so there's no C++ / libwebrtc / NDK dependency
//! and no DTLS/SCTP fingerprint surface we don't control.
//!
//! Model: LiveKit's **two PeerConnection** design.
//!   * **publisher** PC — we add the outgoing carrier track(s) and send
//!     an offer; the SFU answers. Our tunnel bytes ride out as the
//!     (substituted) Opus payload of this track's RTP.
//!   * **subscriber** PC — the SFU sends offers as remote tracks appear
//!     (`subscriber_primary` + `auto_subscribe`); we answer. Incoming
//!     carrier frames arrive via `on_track` → `read_rtp` → [`rtp::unpack`].
//!
//! Signaling is the raw `SignalClient` WebSocket (impersonating the JS
//! SDK via `sdk=js`), with offer/answer/trickle routed by
//! [`proto::SignalTarget`]. Peer presence is derived from
//! `ParticipantUpdate`. No data channels — the carrier is RTP media only.
//!
//! [`Engine`] is the drop-in for `livekit::Room` that `lib.rs` drives:
//! [`Engine::connect`] returns the engine, the published [`RtpSender`]s,
//! and an [`EngineEvent`] stream; [`Engine::close`] tears it down.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

use livekit_api::signal_client::{SignalClient, SignalEvent, SignalOptions, SignalSdkOptions};
use livekit_protocol as proto;

use webrtc::api::interceptor_registry::{configure_nack, configure_rtcp_reports};
use webrtc::api::media_engine::{MediaEngine, MIME_TYPE_OPUS};
use webrtc::api::APIBuilder;
use webrtc::ice_transport::ice_candidate::{RTCIceCandidate, RTCIceCandidateInit};
use webrtc::ice_transport::ice_credential_type::RTCIceCredentialType;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::media::Sample;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::rtp_transceiver::rtp_codec::RTCRtpCodecCapability;
use webrtc::track::track_local::track_local_static_sample::TrackLocalStaticSample;
use webrtc::track::track_local::TrackLocal;

use crate::rtp;

#[cfg(test)]
#[path = "rtc_publication_tests.rs"]
mod publication_tests;

/// The SDK identity we impersonate on the signaling URL + join. Bale's
/// SFU keys some behaviour off this; the LiveKit JS SDK is what its web
/// client uses, so we match it.
const IMPERSONATE_SDK: &str = "js";
const IMPERSONATE_SDK_VERSION: &str = "2.13.6";

/// Bounded per-track send queue. `RtpSender::send` is the backpressure
/// surface: a full queue returns false so the send loop retries across
/// tracks and ultimately stalls quinn (see `lib.rs` send loop). 256 slots
/// matches the depth the old libwebrtc FrameTransformer queue used.
const SEND_QUEUE_DEPTH: usize = 256;

/// Lifecycle signal surfaced to `lib.rs`'s tunnel loop. Mirrors the subset
/// of `livekit::RoomEvent` the loop actually consumed.
#[derive(Debug, Clone)]
pub enum EngineEvent {
    /// A remote participant became active (initial roster or join).
    PeerJoined(String),
    /// A remote participant left.
    PeerLeft(String),
    /// Signaling or media plane went down — `lib.rs` tears the tunnel
    /// down on this (no auto-reconnect; the daemon redials).
    Disconnected(String),
}

/// Sender-side carrier handle. Holds a bounded queue feeding a writer task
/// that calls `TrackLocalStaticSample::write_sample`; the track stays
/// alive (and the writer task running) for as long as the handle is held.
pub struct RtpSender {
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    depth: Arc<AtomicUsize>,
    _writer: tokio::task::AbortHandle,
    /// Kept alive so the track isn't dropped from the PC; `write_sample`
    /// is driven through the writer task, not here.
    _track: Arc<TrackLocalStaticSample>,
}

impl RtpSender {
    /// Try to enqueue a carrier frame. Returns false on queue overflow —
    /// caller backpressures (RTP semantics: best-effort).
    pub fn send(&self, data: &[u8]) -> bool {
        match self.tx.try_send(data.to_vec()) {
            Ok(()) => {
                self.depth.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(_) => false,
        }
    }

    pub fn queue_depth(&self) -> usize {
        self.depth.load(Ordering::Relaxed)
    }
}

/// Connected WebRTC engine. Owns the two PeerConnections, the signal
/// client, and the background signal-event task. Drop / [`close`] tears
/// the lot down.
pub struct Engine {
    id: u64,
    signal: Arc<SignalClient>,
    publisher: Arc<RTCPeerConnection>,
    subscriber: Arc<RTCPeerConnection>,
    /// Remote participants currently present (identities). Updated by the
    /// signal task from `ParticipantUpdate`.
    peers: Arc<Mutex<HashSet<String>>>,
    event_task: Mutex<Option<tokio::task::AbortHandle>>,
}

/// Register before AddTrack so an immediate acknowledgement cannot be lost.
/// Only the exact locally requested CID can release publication; unknown
/// responses consume no queue space. This is sequencing, not peer admission.
#[derive(Default)]
struct PublicationGate(Mutex<(bool, HashMap<String, tokio::sync::oneshot::Sender<Result<(), &'static str>>>)>);
impl PublicationGate {
    fn register(&self, cid: String) -> Result<tokio::sync::oneshot::Receiver<Result<(), &'static str>>, String> {
        let mut state=self.0.lock();
        if state.0 || state.1.len() >= rtp::TRACK_COUNT || state.1.contains_key(&cid) {
            return Err("track publication unavailable".into());
        }
        let (tx,rx)=tokio::sync::oneshot::channel();state.1.insert(cid,tx);Ok(rx)
    }
    fn published(&self, response: &proto::TrackPublishedResponse) {
        let Some(tx)=self.0.lock().1.remove(&response.cid) else {return};
        let valid=response.track.as_ref().is_some_and(|track| !track.sid.is_empty() && track.sid.len() <= 128 && track.r#type == proto::TrackType::Audio as i32);
        let _=tx.send(if valid {Ok(())} else {Err("track publication response invalid")});
    }
    fn close(&self) {
        let mut state=self.0.lock();state.0=true;
        for (_,tx) in state.1.drain(){let _=tx.send(Err("signaling ended before track publication"));}
    }
}
struct PublicationScope(Option<Arc<PublicationGate>>);
impl Drop for PublicationScope {fn drop(&mut self){if let Some(gate)=&self.0{gate.close();}}}

/// Also runs when the connecting future is cancelled before Engine is returned.
/// It never retains tokens or logs remote descriptions.
struct StartupResources {
    signal: Arc<SignalClient>,
    publisher: Option<Arc<RTCPeerConnection>>,
    subscriber: Option<Arc<RTCPeerConnection>>,
    task: Option<tokio::task::AbortHandle>,
    armed: bool,
}
impl Drop for StartupResources {
    fn drop(&mut self) {
        if !self.armed {return;}
        if let Some(task)=self.task.take(){task.abort();}
        let signal=self.signal.clone();let publisher=self.publisher.take();let subscriber=self.subscriber.take();
        crate::runtime().spawn(async move {
            tokio::join!(
                async {
                    let _=tokio::time::timeout(Duration::from_secs(1),signal.send(proto::signal_request::Message::Leave(proto::LeaveRequest::default()))).await;
                    signal.abort().await;
                },
                async {if let Some(pc)=publisher{let _=pc.close().await;}},
                async {if let Some(pc)=subscriber{let _=pc.close().await;}},
            );
        });
    }
}

impl Engine {
    /// Join the SFU and bring up both PeerConnections. `on_packet` is
    /// invoked once per received (unpacked) carrier packet — i.e. the
    /// frame-tagged payload `lib.rs`'s `dispatch_payload` expects.
    ///
    /// Returns the engine, the published carrier senders (one per
    /// [`rtp::TRACK_COUNT`]), and the lifecycle event stream.
    pub async fn connect(
        id: u64,
        url: &str,
        token: &str,
        on_packet: Arc<dyn Fn(bytes::Bytes) + Send + Sync>,
        wait_for_track_published: bool,
    ) -> Result<(Arc<Engine>, Vec<Arc<RtpSender>>, tokio::sync::mpsc::UnboundedReceiver<EngineEvent>), String>
    {
        Self::connect_inner(id,url,token,on_packet,wait_for_track_published,Duration::from_secs(10)).await
    }
    async fn connect_inner(
        id: u64, url: &str, token: &str,
        on_packet: Arc<dyn Fn(bytes::Bytes) + Send + Sync>,
        wait_for_track_published: bool, publication_timeout: Duration,
    ) -> Result<(Arc<Engine>, Vec<Arc<RtpSender>>, tokio::sync::mpsc::UnboundedReceiver<EngineEvent>), String> {
        // ── Signal join (impersonate the JS SDK) ──────────────────────
        let mut sdk_options = SignalSdkOptions::default();
        sdk_options.sdk = IMPERSONATE_SDK.to_string();
        sdk_options.sdk_version = Some(IMPERSONATE_SDK_VERSION.to_string());
        let mut opts = SignalOptions::default();
        opts.auto_subscribe = true;
        opts.sdk_options = sdk_options;

        let (signal, join, events) = SignalClient::connect(url, token, opts)
            .await
            .map_err(|e| format!("signal connect: {e}"))?;
        let signal = Arc::new(signal);
        let mut startup=StartupResources {signal:signal.clone(),publisher:None,subscriber:None,task:None,armed:true};
        log::info!(
            "rtc[{id}]: joined subscriber_primary={} ice_servers={} peers={}",
            join.subscriber_primary,
            join.ice_servers.len(),
            join.other_participants.len(),
        );

        // ── Build the two PeerConnections ─────────────────────────────
        let api = make_api()?;
        let ice_servers = map_ice_servers(&join.ice_servers);
        let mk_config = || RTCConfiguration { ice_servers: ice_servers.clone(), ..Default::default() };

        let publisher = Arc::new(
            api.new_peer_connection(mk_config())
                .await
                .map_err(|e| format!("publisher pc: {e}"))?,
        );
        startup.publisher=Some(publisher.clone());
        let subscriber = Arc::new(
            api.new_peer_connection(mk_config())
                .await
                .map_err(|e| format!("subscriber pc: {e}"))?,
        );
        startup.subscriber=Some(subscriber.clone());

        let (event_tx, event_rx) = tokio::sync::mpsc::unbounded_channel::<EngineEvent>();

        wire_pc(id, &publisher, true, proto::SignalTarget::Publisher, signal.clone(), event_tx.clone());
        wire_pc(id, &subscriber, false, proto::SignalTarget::Subscriber, signal.clone(), event_tx.clone());

        // Receive carrier: every remote track funnels into `on_packet`.
        // When a remote carrier track's read loop ends, the peer has
        // unpublished / left the room — and that's the *authoritative*
        // peer-gone signal, because the SFU's ParticipantUpdate(Disconnected)
        // is unreliable (observed: it often never arrives). No carrier
        // track = no tunnel, so we emit Disconnected to tear down.
        {
            let on_packet = on_packet.clone();
            let track_end_tx = event_tx.clone();
            subscriber.on_track(Box::new(move |track, _receiver, _transceiver| {
                let on_packet = on_packet.clone();
                let track_end_tx = track_end_tx.clone();
                log::info!("rtc[{id}]: on_track id={} kind={}", track.id(), track.kind());
                Box::pin(async move {
                    tokio::spawn(async move {
                        let mut frames: u64 = 0;
                        while let Ok((pkt, _)) = track.read_rtp().await {
                            frames += 1;
                            if frames.is_power_of_two() {
                                log::debug!("rtc: rx checkpoint {frames} frames (last={}B)", pkt.payload.len());
                            }
                            rtp::unpack(&pkt.payload, |p| (on_packet)(p));
                        }
                        log::info!("rtc[{id}]: remote carrier track ended after {frames} frames — peer gone");
                        let _ = track_end_tx.send(EngineEvent::Disconnected(
                            "remote carrier track ended".into(),
                        ));
                    });
                })
            }));
        }

        let local_identity=join.participant.as_ref().map(|p|p.identity.clone()).unwrap_or_default();
        let peers=Arc::new(Mutex::new(HashSet::new()));
        seed_peers(&peers,&join.other_participants,&local_identity,&event_tx);
        let gate=wait_for_track_published.then(||Arc::new(PublicationGate::default()));
        let mut events=Some(events);
        if wait_for_track_published {
            let task=crate::runtime().spawn(signal_loop(id,events.take().expect("signal events owned"),signal.clone(),publisher.clone(),subscriber.clone(),peers.clone(),local_identity.clone(),event_tx.clone(),gate.clone()));
            startup.task=Some(task.abort_handle());
        }
        let publication_deadline=tokio::time::Instant::now()+publication_timeout;
        // ── Publish the outgoing carrier track(s) ─────────────────────
        // One deadline covers AddTrack setup, signaling writes, ACK wait and
        // the initial offer, rather than only the acknowledgement receiver.
        let publish=async {
        let mut senders = Vec::with_capacity(rtp::TRACK_COUNT);
        for index in 0..rtp::TRACK_COUNT {
            let track = Arc::new(TrackLocalStaticSample::new(
                RTCRtpCodecCapability {
                    mime_type: MIME_TYPE_OPUS.to_owned(),
                    clock_rate: 48000,
                    channels: 2,
                    ..Default::default()
                },
                format!("tunnel-{index}"),
                "tunnel-stream".to_string(),
            ));
            publisher
                .add_track(track.clone())
                .await
                .map_err(|e| format!("add_track {index}: {e}"))?;
            let publication=gate.as_ref().map(|gate|gate.register(track.id().to_string())).transpose()?;
            signal
                .send(proto::signal_request::Message::AddTrack(proto::AddTrackRequest {
                    cid: track.id().to_string(),
                    name: format!("tunnel-{index}"),
                    r#type: proto::TrackType::Audio as i32,
                    source: proto::TrackSource::Microphone as i32,
                    // No `disable_dtx`: that gated libwebrtc's Opus encoder.
                    // We write RTP samples directly (no encoder), so a
                    // packet goes out per `write_sample` regardless — there
                    // is no DTX silence-suppression to turn off.
                    ..Default::default()
                }))
                .await;
            if let Some(publication)=publication {
                publication.await
                    .map_err(|_|"track publication cancelled".to_string())?
                    .map_err(str::to_owned)?;
            }
            senders.push(Arc::new(make_sender(id, index, track)));
        }

        // Publisher offer — the SFU answers (handled in the signal task).
        let offer = publisher
            .create_offer(None)
            .await
            .map_err(|e| format!("create_offer: {e}"))?;
        publisher
            .set_local_description(offer.clone())
            .await
            .map_err(|e| format!("pub set_local: {e}"))?;
        signal
            .send(proto::signal_request::Message::Offer(proto::SessionDescription {
                r#type: "offer".to_string(),
                sdp: offer.sdp,
                ..Default::default()
            }))
            .await;
        log::info!("rtc[{id}]: publisher offer sent ({} track[s])", senders.len());
        Ok::<_,String>(senders)
        };
        let senders=if wait_for_track_published {
            tokio::time::timeout_at(publication_deadline,publish).await
                .map_err(|_|"track publication timed out".to_string())??
        } else {publish.await?};

        // Default transports retain their previous post-offer event startup.
        // The opted-in path is already consuming events to await publication.
        if let Some(events)=events {
        let task = crate::runtime().spawn(signal_loop(
            id,
            events,
            signal.clone(),
            publisher.clone(),
            subscriber.clone(),
            peers.clone(),
            local_identity,
            event_tx,
            gate,
        ));
        startup.task=Some(task.abort_handle());
        }

        let engine = Arc::new(Engine {
            id,
            signal,
            publisher,
            subscriber,
            peers,
            event_task: Mutex::new(startup.task.take()),
        });
        startup.armed=false;
        Ok((engine, senders, event_rx))
    }

    /// True while at least one remote participant is present.
    pub fn peer_present(&self) -> bool {
        !self.peers.lock().is_empty()
    }
    pub(crate) fn media_diagnostic(&self) -> serde_json::Value {
        serde_json::json!({
            "publisherState": media_state_name(self.publisher.connection_state()),
            "subscriberState": media_state_name(self.subscriber.connection_state()),
        })
    }

    /// Idempotent teardown.
    ///
    /// Sends an explicit LiveKit **Leave** before dropping the socket.
    /// `SignalClient::close()` only closes the WebSocket — the SFU treats a
    /// bare socket drop as a possible resume and waits out its ~10 s
    /// participant timeout before declaring us gone (and only then notifies
    /// the other peer). A `Leave` makes it remove us — and renegotiate the
    /// peer's subscription / fire ParticipantUpdate(Disconnected) —
    /// immediately. (The LiveKit SDK's `room.close()` does the same.)
    pub async fn close(&self) {
        self.signal
            .send(proto::signal_request::Message::Leave(proto::LeaveRequest::default()))
            .await;
        self.signal.close().await;
        if let Some(h) = self.event_task.lock().take() { h.abort(); }
        let _ = self.publisher.close().await;
        let _ = self.subscriber.close().await;
        log::info!("rtc[{}]: closed", self.id);
    }
}

fn media_state_name(state: RTCPeerConnectionState) -> &'static str {
    match state {
        RTCPeerConnectionState::New => "new",
        RTCPeerConnectionState::Connecting => "connecting",
        RTCPeerConnectionState::Connected => "connected",
        RTCPeerConnectionState::Disconnected => "disconnected",
        RTCPeerConnectionState::Failed => "failed",
        RTCPeerConnectionState::Closed => "closed",
        _ => "unknown",
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        if let Some(h) = self.event_task.lock().take() { h.abort(); }
        // PCs/signal close on their own Arc drop; the explicit async
        // `close()` (called from teardown) is the graceful path.
    }
}

/// Build the webrtc-rs API with default codecs + NACK and RTCP reports —
/// but deliberately WITHOUT TWCC (transport-wide congestion control).
///
/// TWCC's only job is to feed WebRTC's bandwidth estimator, which we don't
/// use: QUIC does congestion control above the carrier and the sender
/// writes RTP as fast as data arrives. Skipping `configure_twcc` means the
/// transport-cc header extension is never negotiated, so the SFU stops
/// sending the transport-wide feedback that webrtc-rs's RTCP parser chokes
/// on ("Packet status chunk must be 2 bytes" — harmless but noisy). One
/// fewer interceptor in the hot path, and no chance of WebRTC BWE ever
/// throttling our send pacer.
fn make_api() -> Result<webrtc::api::API, String> {
    let mut media = MediaEngine::default();
    media.register_default_codecs().map_err(|e| format!("register_default_codecs: {e}"))?;
    let mut registry = Registry::new();
    registry = configure_nack(registry, &mut media);
    registry = configure_rtcp_reports(registry);
    Ok(APIBuilder::new()
        .with_media_engine(media)
        .with_interceptor_registry(registry)
        .build())
}

/// Map LiveKit's advertised ICE servers to webrtc-rs config. webrtc-rs
/// rejects TURN servers unless `credential_type` is `Password` (its
/// Default is `Unspecified`); libwebrtc set this implicitly.
fn map_ice_servers(servers: &[proto::IceServer]) -> Vec<RTCIceServer> {
    servers
        .iter()
        .map(|s| RTCIceServer {
            urls: s.urls.clone(),
            username: s.username.clone(),
            credential: s.credential.clone(),
            credential_type: RTCIceCredentialType::Password,
        })
        .collect()
}

/// Wire a PC's connection-state + ICE-candidate callbacks. A Failed /
/// Closed / Disconnected state emits [`EngineEvent::Disconnected`]; local
/// ICE candidates are trickled to the SFU tagged with `target`.
fn wire_pc(
    id: u64,
    pc: &Arc<RTCPeerConnection>,
    is_publisher: bool,
    target: proto::SignalTarget,
    signal: Arc<SignalClient>,
    event_tx: tokio::sync::mpsc::UnboundedSender<EngineEvent>,
) {
    let label = if is_publisher { "publisher" } else { "subscriber" };
    {
        let event_tx = event_tx.clone();
        pc.on_peer_connection_state_change(Box::new(move |s: RTCPeerConnectionState| {
            log::info!("rtc[{id}]: {label} PC → {s}");
            let event_tx = event_tx.clone();
            Box::pin(async move {
                // Only `Failed`/`Closed` are terminal. `Disconnected` is a
                // TRANSIENT ICE state — a brief connectivity blip (e.g. the
                // app backgrounding, a Wi-Fi↔cellular hop) — that webrtc-rs
                // recovers from on its own. Tearing down on it killed the
                // tunnel on every background→foreground cycle, so we ignore
                // it and wait for either recovery or a real `Failed`.
                if matches!(s, RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed) {
                    let _ = event_tx.send(EngineEvent::Disconnected(format!("{label} PC {s}")));
                }
            })
        }));
    }
    {
        let target = target as i32;
        pc.on_ice_candidate(Box::new(move |cand: Option<RTCIceCandidate>| {
            let signal = signal.clone();
            Box::pin(async move {
                if let Some(cand) = cand {
                    if let Ok(init) = cand.to_json() {
                        let json = serde_json::to_string(&init).unwrap_or_default();
                        signal
                            .send(proto::signal_request::Message::Trickle(proto::TrickleRequest {
                                candidate_init: json,
                                target,
                                ..Default::default()
                            }))
                            .await;
                    }
                }
            })
        }));
    }
}

/// Build an [`RtpSender`] around a published track: a bounded queue + a
/// writer task that drains it into `write_sample`. `write_sample` errors
/// (e.g. before the track binds) are dropped — the carrier is lossy and
/// QUIC retransmits above it.
fn make_sender(id: u64, index: usize, track: Arc<TrackLocalStaticSample>) -> RtpSender {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(SEND_QUEUE_DEPTH);
    let depth = Arc::new(AtomicUsize::new(0));
    let writer_track = track.clone();
    let writer_depth = depth.clone();
    let writer = crate::runtime().spawn(async move {
        let mut sent: u64 = 0;
        while let Some(buf) = rx.recv().await {
            writer_depth.fetch_sub(1, Ordering::Relaxed);
            let sample = Sample {
                data: bytes::Bytes::from(buf),
                duration: Duration::from_millis(20),
                ..Default::default()
            };
            match writer_track.write_sample(&sample).await {
                Ok(()) => {
                    sent += 1;
                    if sent.is_power_of_two() {
                        log::debug!("rtc[{id}]: track {index} tx checkpoint {sent} frames");
                    }
                }
                Err(e) => {
                    static WARNED: AtomicU64 = AtomicU64::new(0);
                    if WARNED.fetch_add(1, Ordering::Relaxed) % 256 == 0 {
                        log::debug!("rtc[{id}]: track {index} write_sample dropped: {e}");
                    }
                }
            }
        }
    });
    RtpSender { tx, depth, _writer: writer.abort_handle(), _track: track }
}

/// Seed the peer set from the join roster and emit a `PeerJoined` for each
/// active participant (so `lib.rs`'s loop sees them like late joins).
fn seed_peers(
    peers: &Arc<Mutex<HashSet<String>>>,
    roster: &[proto::ParticipantInfo],
    local_identity: &str,
    event_tx: &tokio::sync::mpsc::UnboundedSender<EngineEvent>,
) {
    let mut set = peers.lock();
    for p in roster {
        if p.identity == local_identity { continue; }
        if p.state == proto::participant_info::State::Active as i32 {
            if set.insert(p.identity.clone()) {
                let _ = event_tx.send(EngineEvent::PeerJoined(p.identity.clone()));
            }
        }
    }
}

// webrtc-rs rejects (rather than buffers) trickle received before remote SDP.
// Keep initial negotiation candidates local to their PC; this is not an ICE
// restart queue. The signal loop is the sole setter of both remote descriptions.
const MAX_REMOTE_ICE_JSON: usize = 16 * 1024;
const MAX_PENDING_REMOTE_ICE: usize = 128;
const MAX_PENDING_REMOTE_ICE_BYTES: usize = 64 * 1024;
#[derive(Default)]
struct PendingRemoteIce {
    entries: VecDeque<(RTCIceCandidateInit, usize)>,
    bytes: usize,
}
impl PendingRemoteIce {
    fn push(&mut self, init: RTCIceCandidateInit, size: usize) -> Result<(), &'static str> {
        if size > MAX_REMOTE_ICE_JSON { return Err("ICE candidate size limit"); }
        if self.entries.iter().any(|(item, _)| item == &init) { return Ok(()); }
        if self.entries.len() >= MAX_PENDING_REMOTE_ICE ||
            size > MAX_PENDING_REMOTE_ICE_BYTES.saturating_sub(self.bytes) {
            return Err("ICE candidate queue limit");
        }
        self.bytes += size;
        self.entries.push_back((init, size));
        Ok(())
    }
    async fn flush(&mut self, pc: &RTCPeerConnection) -> usize {
        let Some(remote) = pc.remote_description().await else { return 0; };
        let mut applied = 0;
        while let Some((init, size)) = self.entries.pop_front() {
            self.bytes -= size;
            // Explicit fragments must belong to the SDP which unlocked this
            // initial queue. Legacy candidates without a fragment are retained.
            if init.username_fragment.as_ref().is_some_and(|fragment|
                !remote.sdp.lines().any(|line| line.strip_prefix("a=ice-ufrag:") == Some(fragment.as_str()))) {
                continue;
            }
            if pc.add_ice_candidate(init).await.is_ok() { applied += 1; }
        }
        applied
    }
}
async fn add_remote_ice(pc: &RTCPeerConnection, pending: &mut PendingRemoteIce,
    init: RTCIceCandidateInit, size: usize) -> Result<(), &'static str> {
    if size > MAX_REMOTE_ICE_JSON { return Err("ICE candidate size limit"); }
    if pc.remote_description().await.is_none() { return pending.push(init, size); }
    // Malformed candidates have always been ignored; never log their addresses.
    let _ = pc.add_ice_candidate(init).await;
    Ok(())
}

/// Persistent signal-event loop: routes offer/answer/trickle to the right
/// PC and turns `ParticipantUpdate` / `Leave` into [`EngineEvent`]s. Ends
/// (emitting `Disconnected`) when the signal stream closes.
async fn signal_loop(
    id: u64,
    mut events: tokio::sync::mpsc::UnboundedReceiver<SignalEvent>,
    signal: Arc<SignalClient>,
    publisher: Arc<RTCPeerConnection>,
    subscriber: Arc<RTCPeerConnection>,
    peers: Arc<Mutex<HashSet<String>>>,
    local_identity: String,
    event_tx: tokio::sync::mpsc::UnboundedSender<EngineEvent>,
    publication: Option<Arc<PublicationGate>>,
) {
    let _publication_scope=PublicationScope(publication.clone());
    let mut publisher_ice = PendingRemoteIce::default();
    let mut subscriber_ice = PendingRemoteIce::default();
    while let Some(ev) = events.recv().await {
        match ev {
            SignalEvent::Close(reason) => {
                log::info!("rtc[{id}]: signal closed: {reason}");
                let _ = event_tx.send(EngineEvent::Disconnected(format!("signal closed: {reason}")));
                return;
            }
            SignalEvent::Message(msg) => match *msg {
                proto::signal_response::Message::TrackPublished(response)=>{
                    if let Some(gate)=&publication{gate.published(&response);}
                },
                // SFU subscriber offer — answer it.
                proto::signal_response::Message::Offer(sd) => {
                    match RTCSessionDescription::offer(sd.sdp) {
                        Ok(offer) => {
                            if let Err(e) = subscriber.set_remote_description(offer).await {
                                log::warn!("rtc[{id}]: sub set_remote: {e}");
                            } else {
                              subscriber_ice.flush(&subscriber).await;
                              if let Ok(answer) = subscriber.create_answer(None).await {
                                if let Err(e) = subscriber.set_local_description(answer.clone()).await {
                                    log::warn!("rtc[{id}]: sub set_local: {e}");
                                } else {
                                    signal
                                        .send(proto::signal_request::Message::Answer(
                                            proto::SessionDescription {
                                                r#type: "answer".to_string(),
                                                sdp: answer.sdp,
                                                ..Default::default()
                                            },
                                        ))
                                        .await;
                                }
                              }
                            }
                        }
                        Err(e) => log::warn!("rtc[{id}]: parse offer: {e}"),
                    }
                }
                // Answer to our publisher offer.
                proto::signal_response::Message::Answer(sd) => {
                    match RTCSessionDescription::answer(sd.sdp) {
                        Ok(answer) => {
                            if let Err(e) = publisher.set_remote_description(answer).await {
                                log::warn!("rtc[{id}]: pub set_remote: {e}");
                            } else {
                                publisher_ice.flush(&publisher).await;
                            }
                        }
                        Err(e) => log::warn!("rtc[{id}]: parse answer: {e}"),
                    }
                }
                proto::signal_response::Message::Trickle(t) => {
                    let (pc, pending) = if t.target == proto::SignalTarget::Publisher as i32 {
                        (&publisher, &mut publisher_ice)
                    } else if t.target == proto::SignalTarget::Subscriber as i32 {
                        (&subscriber, &mut subscriber_ice)
                    } else { continue; };
                    if t.candidate_init.len() > MAX_REMOTE_ICE_JSON {
                        let _ = event_tx.send(EngineEvent::Disconnected("ICE candidate size limit".into()));
                        return;
                    }
                    if let Ok(init) = serde_json::from_str::<RTCIceCandidateInit>(&t.candidate_init) {
                        if let Err(reason) = add_remote_ice(pc, pending, init, t.candidate_init.len()).await {
                            let _ = event_tx.send(EngineEvent::Disconnected(reason.into()));
                            return;
                        }
                    }
                }
                proto::signal_response::Message::Update(update) => {
                    apply_participant_update(&peers, &update.participants, &local_identity, &event_tx);
                }
                proto::signal_response::Message::Leave(leave) => {
                    log::info!("rtc[{id}]: server LEAVE (action={})", leave.action);
                    let _ = event_tx.send(EngineEvent::Disconnected(server_leave_context(&leave)));
                    return;
                }
                _ => {}
            },
        }
    }
    let _ = event_tx.send(EngineEvent::Disconnected("signal stream ended".into()));
}

// Only bounded protocol enum values enter diagnostics; regions and arbitrary
// server payloads never enter the event context.
fn server_leave_context(leave: &proto::LeaveRequest) -> String {
    let reason = if (0..=16).contains(&leave.reason) { leave.reason } else { -1 };
    let action = if (0..=2).contains(&leave.action) { leave.action } else { -1 };
    format!("server leave reason={reason} action={action} reconnect={}", u8::from(leave.can_reconnect))
}

#[cfg(test)]
mod remote_ice_tests {
    use super::*;
    #[test]
    fn media_state_names_are_fixed_enums() {
        assert_eq!(media_state_name(RTCPeerConnectionState::default()),"unknown");
        for (state,name) in [(RTCPeerConnectionState::New,"new"),(RTCPeerConnectionState::Connecting,"connecting"),(RTCPeerConnectionState::Connected,"connected"),(RTCPeerConnectionState::Disconnected,"disconnected"),(RTCPeerConnectionState::Failed,"failed"),(RTCPeerConnectionState::Closed,"closed")] {
            assert_eq!(media_state_name(state),name);
        }
    }
    fn candidate(port: u16) -> RTCIceCandidateInit {
        RTCIceCandidateInit { candidate: format!("candidate:1 1 udp 2130706431 127.0.0.1 {port} typ host"),
            sdp_mid: Some("0".into()), sdp_mline_index: Some(0), username_fragment: None }
    }
    async fn pc() -> RTCPeerConnection {
        APIBuilder::new().build().new_peer_connection(RTCConfiguration::default()).await.unwrap()
    }
    async fn remote_candidates(pc: &RTCPeerConnection) -> usize {
        pc.get_stats().await.reports.values().filter(|s| matches!(s, webrtc::stats::StatsReportType::RemoteCandidate(_))).count()
    }
    async fn wait_candidate(pc: &RTCPeerConnection) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while remote_candidates(pc).await == 0 { tokio::time::sleep(Duration::from_millis(10)).await; }
        }).await.expect("Buffered candidate never reached real ICE transport");
    }
    #[tokio::test]
    async fn early_candidates_reach_real_transport_only_after_their_pc_gets_remote_sdp() {
        let source = pc().await;
        source.create_data_channel("fixture", None).await.unwrap();
        let offer = source.create_offer(None).await.unwrap();
        let publisher = pc().await;
        let subscriber = pc().await;
        assert!(matches!(publisher.add_ice_candidate(candidate(5000)).await,
            Err(webrtc::Error::ErrNoRemoteDescription)));
        let mut pub_queue = PendingRemoteIce::default();
        let mut sub_queue = PendingRemoteIce::default();
        add_remote_ice(&publisher, &mut pub_queue, candidate(5000), 100).await.unwrap();
        add_remote_ice(&subscriber, &mut sub_queue, candidate(5001), 100).await.unwrap();
        assert_eq!(pub_queue.flush(&publisher).await, 0);
        assert_eq!(pub_queue.entries.len(), 1);
        assert_eq!(remote_candidates(&publisher).await, 0);
        // A rejected answer cannot unlock or discard the pending queue.
        let wrong = RTCSessionDescription::answer(offer.sdp.clone()).unwrap();
        assert!(publisher.set_remote_description(wrong).await.is_err());
        assert_eq!(pub_queue.flush(&publisher).await, 0);
        subscriber.set_remote_description(offer.clone()).await.unwrap();
        assert_eq!(sub_queue.flush(&subscriber).await, 1);
        wait_candidate(&subscriber).await;
        assert_eq!(remote_candidates(&publisher).await, 0);
        assert_eq!(pub_queue.entries.len(), 1);
        publisher.set_remote_description(offer).await.unwrap();
        assert_eq!(pub_queue.flush(&publisher).await, 1);
        wait_candidate(&publisher).await;
        assert!(pub_queue.entries.is_empty()); assert_eq!(pub_queue.bytes, 0);
        publisher.close().await.unwrap(); subscriber.close().await.unwrap(); source.close().await.unwrap();
    }
    #[tokio::test]
    async fn queued_fragment_must_match_initial_sdp_and_bad_candidates_do_not_block_good_ones() {
        let source = pc().await;
        source.create_data_channel("fixture", None).await.unwrap();
        let offer = source.create_offer(None).await.unwrap();
        let fragment = offer.sdp.lines().find_map(|line| line.strip_prefix("a=ice-ufrag:")).unwrap().to_owned();
        let receiver = pc().await; let mut queue = PendingRemoteIce::default();
        let mut stale = candidate(5000); stale.username_fragment = Some("wrong-generation".into());
        queue.push(stale, 100).unwrap();
        let mut malformed = candidate(5001); malformed.candidate = "not-a-candidate".into();
        queue.push(malformed, 100).unwrap();
        let mut good = candidate(5002); good.username_fragment = Some(fragment);
        queue.push(good, 100).unwrap();
        receiver.set_remote_description(offer).await.unwrap();
        assert_eq!(queue.flush(&receiver).await, 1);
        wait_candidate(&receiver).await;
        assert_eq!(queue.bytes, 0);
        assert!(queue.entries.is_empty());
        receiver.close().await.unwrap(); source.close().await.unwrap();
    }
    #[test]
    fn pending_candidates_preserve_fifo_and_end_marker_with_strict_memory_limits() {
        let mut queue = PendingRemoteIce::default();
        queue.push(candidate(5000), 100).unwrap();
        queue.push(candidate(5000), 100).unwrap(); // duplicate does not consume budget
        queue.push(RTCIceCandidateInit::default(), 20).unwrap();
        assert_eq!(queue.entries.len(), 2);
        assert_eq!(queue.bytes, 120);
        assert_eq!(queue.entries[0].0, candidate(5000));
        assert!(queue.entries[1].0.candidate.is_empty());
        assert!(queue.push(candidate(5001), MAX_REMOTE_ICE_JSON + 1).is_err());
        let mut count = PendingRemoteIce::default();
        for port in 5000..5000 + MAX_PENDING_REMOTE_ICE as u16 { count.push(candidate(port), 100).unwrap(); }
        assert!(count.push(candidate(6000), 100).is_err());
        let mut bytes = PendingRemoteIce::default();
        for port in 5000..5004 { bytes.push(candidate(port), MAX_REMOTE_ICE_JSON).unwrap(); }
        assert_eq!(bytes.bytes, MAX_PENDING_REMOTE_ICE_BYTES);
        assert!(bytes.push(candidate(6000), 1).is_err());
    }
}

#[cfg(test)]
mod leave_diagnostic_tests {
    use super::*;
    #[test]
    fn leave_context_bounds_unknown_enums_and_excludes_unrelated_data() {
        for (reason, action, expected) in [(0,0,"server leave reason=0 action=0 reconnect=1"),
            (16,2,"server leave reason=16 action=2 reconnect=1"),
            (-9,i32::MAX,"server leave reason=-1 action=-1 reconnect=1")] {
            let leave=proto::LeaveRequest {reason,action,can_reconnect:true,..Default::default()};
            assert_eq!(server_leave_context(&leave),expected);
        }
        assert_eq!(server_leave_context(&proto::LeaveRequest::default()),"server leave reason=0 action=0 reconnect=0");
    }
}

/// Apply a `ParticipantUpdate`: diff against the known peer set, emitting
/// `PeerJoined` for newly-active and `PeerLeft` for newly-disconnected.
fn apply_participant_update(
    peers: &Arc<Mutex<HashSet<String>>>,
    participants: &[proto::ParticipantInfo],
    local_identity: &str,
    event_tx: &tokio::sync::mpsc::UnboundedSender<EngineEvent>,
) {
    let disconnected = proto::participant_info::State::Disconnected as i32;
    let mut set = peers.lock();
    for p in participants {
        log::info!("rtc: participant update: identity={} state={}", p.identity, p.state);
        if p.identity == local_identity { continue; }  // skip ourselves (matches the LK SDK)
        if p.state == disconnected {
            if set.remove(&p.identity) {
                let _ = event_tx.send(EngineEvent::PeerLeft(p.identity.clone()));
            }
        } else if set.insert(p.identity.clone()) {
            let _ = event_tx.send(EngineEvent::PeerJoined(p.identity.clone()));
        }
    }
}
