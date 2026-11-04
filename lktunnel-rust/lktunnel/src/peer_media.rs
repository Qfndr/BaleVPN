//! Experimental one-peer RTP carrier, independent of LiveKit/Bale signaling.
//!
//! Both peers must be compatible native tunnel endpoints. No microphone,
//! camera, data channel, host/STUN candidate fallback, or provider login here.
//! TURN credentials must come from the authenticated provider call controller;
//! relay-only ICE alone does not establish provider ownership or billing.
use crate::carrier::{CarrierInput, CarrierOutput};
use crate::rtp;
use bytes::Bytes;
use parking_lot::Mutex;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::time::Duration;
use webrtc::{
    api::{
        media_engine::{MediaEngine, MIME_TYPE_OPUS},
        APIBuilder,
    },
    dtls_transport::dtls_transport_state::RTCDtlsTransportState,
    ice::candidate::{
        candidate_base::unmarshal_candidate, Candidate, CandidatePairState, CandidateType,
    },
    ice_transport::{
        ice_candidate::RTCIceCandidateInit, ice_connection_state::RTCIceConnectionState,
        ice_credential_type::RTCIceCredentialType, ice_server::RTCIceServer,
    },
    media::Sample,
    peer_connection::{
        configuration::RTCConfiguration,
        peer_connection_state::RTCPeerConnectionState,
        policy::ice_transport_policy::RTCIceTransportPolicy,
        sdp::{sdp_type::RTCSdpType, session_description::RTCSessionDescription},
        RTCPeerConnection,
    },
    rtp_transceiver::rtp_codec::RTCRtpCodecCapability,
    stats::{StatsReport, StatsReportType},
    track::track_local::track_local_static_sample::TrackLocalStaticSample,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaError {
    InvalidRelay,
    Setup,
    InvalidDescription,
    Negotiation,
    GatherTimeout,
    NoRelay,
    Closed,
}

/// Only non-sensitive route metadata is public. Neither addresses nor TURN
/// passwords, SDP, ICE credentials or DTLS key material appear here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayRoute {
    Unknown,
    RelayPair,
    Other,
}

/// Failure stage only: no candidate IDs, addresses, credentials or SDP.
/// This classifies observed terminal state; it does not claim the root cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaDisconnectStage {
    Unknown,
    Ice,
    Dtls,
    RelayRoute,
}

fn disconnect_stage(
    ice: RTCIceConnectionState,
    dtls: RTCDtlsTransportState,
    route_rejected: bool,
) -> MediaDisconnectStage {
    if route_rejected {
        MediaDisconnectStage::RelayRoute
    } else if dtls == RTCDtlsTransportState::Failed {
        MediaDisconnectStage::Dtls
    } else if matches!(
        ice,
        RTCIceConnectionState::Failed | RTCIceConnectionState::Disconnected
    ) {
        MediaDisconnectStage::Ice
    } else {
        MediaDisconnectStage::Unknown
    }
}

pub struct RelayMedia {
    pc: Arc<RTCPeerConnection>,
    input: CarrierInput,
    tasks: Arc<Mutex<Vec<tokio::task::AbortHandle>>>,
    closed: Arc<AtomicBool>,
    route_rejected: Arc<AtomicBool>,
    gathered_local_relay_candidates: AtomicU64,
    remote_description_relay_candidates: AtomicU64,
}

/// Counts only: intentionally excludes candidate IDs, addresses and credentials.
#[derive(Clone, Debug, Default)]
pub struct IceDiagnostics {
    pub local_relay_candidates: u64,
    pub remote_relay_candidates: u64,
    /// Retained signaling evidence, distinct from the current agent lists
    /// which webrtc-ice clears before emitting Failed. None means unavailable.
    pub gathered_local_relay_candidates: Option<u64>,
    pub remote_description_relay_candidates: Option<u64>,
    pub pair_waiting: u64,
    pub pair_in_progress: u64,
    pub pair_failed: u64,
    pub pair_succeeded: u64,
    pub pair_unspecified: u64,
    pub nominated_pairs: u64,
    // webrtc-ice 0.11 hardcodes these stats to zero. None means unavailable,
    // not a measured absence of connectivity-check traffic.
    pub requests_sent: Option<u64>,
    pub requests_received: Option<u64>,
    pub responses_sent: Option<u64>,
    pub responses_received: Option<u64>,
}

fn ice_diagnostics(stats: &StatsReport) -> IceDiagnostics {
    let mut result = IceDiagnostics::default();
    let add = |total: &mut u64, value: u64| *total = total.saturating_add(value).min(1_000_000_000);
    for report in stats.reports.values() {
        match report {
            StatsReportType::LocalCandidate(c) if c.candidate_type == CandidateType::Relay => add(&mut result.local_relay_candidates, 1),
            StatsReportType::RemoteCandidate(c) if c.candidate_type == CandidateType::Relay => add(&mut result.remote_relay_candidates, 1),
            StatsReportType::CandidatePair(pair) => {
                let count = match pair.state {
                    CandidatePairState::Waiting => &mut result.pair_waiting,
                    CandidatePairState::InProgress => &mut result.pair_in_progress,
                    CandidatePairState::Failed => &mut result.pair_failed,
                    CandidatePairState::Succeeded => &mut result.pair_succeeded,
                    _ => &mut result.pair_unspecified,
                };
                add(count, 1);
                if pair.nominated { add(&mut result.nominated_pairs, 1); }
            }
            _ => {}
        }
    }
    result
}

fn config(servers: Vec<RTCIceServer>) -> Result<RTCConfiguration, MediaError> {
    if servers.is_empty() || servers.len() > 4 {
        return Err(MediaError::InvalidRelay);
    }
    for server in &servers {
        if server.urls.is_empty()
            || server.urls.len() > 4
            || server.username.is_empty()
            || server.username.len() > 1024
            || server.credential.is_empty()
            || server.credential.len() > 1024
            || server.credential_type != RTCIceCredentialType::Password
        {
            return Err(MediaError::InvalidRelay);
        }
        for url in &server.urls {
            if url.len() > 512
                || !url.starts_with("turn:")
                || url.contains('@')
                || url.contains('#')
            {
                return Err(MediaError::InvalidRelay);
            }
            let parsed =
                webrtc::ice::url::Url::parse_url(url).map_err(|_| MediaError::InvalidRelay)?;
            if parsed.proto != webrtc::ice::url::ProtoType::Udp {
                return Err(MediaError::InvalidRelay);
            }
        }
    }
    Ok(RTCConfiguration {
        ice_servers: servers,
        ice_transport_policy: RTCIceTransportPolicy::Relay,
        ..Default::default()
    })
}

fn route(stats: &StatsReport) -> RelayRoute {
    for report in stats.reports.values() {
        if let StatsReportType::CandidatePair(pair) = report {
            if !pair.nominated || pair.state != CandidatePairState::Succeeded {
                continue;
            }
            let local = stats.reports.values().find_map(|s| match s {
                StatsReportType::LocalCandidate(c) if c.id == pair.local_candidate_id => {
                    Some(c.candidate_type)
                }
                _ => None,
            });
            let remote = stats.reports.values().find_map(|s| match s {
                StatsReportType::RemoteCandidate(c) if c.id == pair.remote_candidate_id => {
                    Some(c.candidate_type)
                }
                _ => None,
            });
            return match (local, remote) {
                (Some(CandidateType::Relay), Some(CandidateType::Relay)) => RelayRoute::RelayPair,
                (Some(_), Some(_)) => RelayRoute::Other,
                _ => RelayRoute::Unknown,
            };
        }
    }
    RelayRoute::Unknown
}

fn relay_candidate(value: &str) -> bool {
    let Some(raw) = value.strip_prefix("candidate:") else {
        return false;
    };
    if value.len() > 4096
        || value.contains(['\r', '\n'])
        || raw.split_whitespace().nth(6) != Some("typ")
    {
        return false;
    }
    unmarshal_candidate(raw)
        .map(|candidate| candidate.candidate_type() == CandidateType::Relay)
        .unwrap_or(false)
}

fn secure_audio(sdp: &str) -> bool {
    sdp.len() <= 65535
        && sdp.starts_with("v=0")
        && !sdp.contains('\0')
        && sdp.lines().filter(|s| s.starts_with("m=")).count() == 1
        && sdp
            .lines()
            .any(|s| s.starts_with("m=audio ") && s.contains(" UDP/TLS/RTP/SAVPF "))
        && sdp.lines().any(|s| s.starts_with("a=fingerprint:sha-256 "))
        && !sdp.lines().any(|s| {
            s.starts_with("a=crypto:")
                || (s.starts_with("a=candidate:") && !relay_candidate(&s[2..]))
        })
}

fn relay_description_count(sdp: &str) -> u64 {
    sdp.lines()
        .filter(|line| line.starts_with("a=candidate:") && relay_candidate(&line[2..]))
        .count()
        .min(1_000_000_000) as u64
}

impl RelayMedia {
    pub async fn ice_diagnostics(&self) -> IceDiagnostics {
        let mut counts = ice_diagnostics(&self.pc.get_stats().await);
        let local = self.gathered_local_relay_candidates.load(Ordering::Acquire);
        let remote = self.remote_description_relay_candidates.load(Ordering::Acquire);
        counts.gathered_local_relay_candidates = (local != u64::MAX).then_some(local);
        counts.remote_description_relay_candidates = (remote != u64::MAX).then_some(remote);
        counts
    }
    /// Takes ownership of the external carrier. A failed setup drops its
    /// output and disconnects QUIC, rather than leaving a half-ready proxy.
    pub async fn new(
        input: CarrierInput,
        mut output: CarrierOutput,
        servers: Vec<RTCIceServer>,
    ) -> Result<Self, MediaError> {
        let configuration = config(servers)?;
        let mut media = MediaEngine::default();
        media
            .register_default_codecs()
            .map_err(|_| MediaError::Setup)?;
        let api = APIBuilder::new().with_media_engine(media).build();
        let pc = Arc::new(
            api.new_peer_connection(configuration)
                .await
                .map_err(|_| MediaError::Setup)?,
        );
        let tasks = Arc::new(Mutex::new(Vec::new()));
        // Construct the owner before fallible track setup, so all later error
        // paths close the PC and invalidate the input as well as the output.
        let closed = Arc::new(AtomicBool::new(false));
        let route_rejected = Arc::new(AtomicBool::new(false));
        let owner = Self {
            pc: pc.clone(),
            input: input.clone(),
            tasks: tasks.clone(),
            closed: closed.clone(),
            route_rejected: route_rejected.clone(),
            gathered_local_relay_candidates: AtomicU64::new(u64::MAX),
            remote_description_relay_candidates: AtomicU64::new(u64::MAX),
        };
        let weak_pc = Arc::downgrade(&pc);
        let state_input = input.clone();
        pc.on_peer_connection_state_change(Box::new(move |state| {
            let weak_pc = weak_pc.clone();
            let input = state_input.clone();
            let route_rejected = route_rejected.clone();
            Box::pin(async move {
                if state == RTCPeerConnectionState::Connected {
                    // Verify the nominated pair through typed stats before
                    // exposing media readiness. Never infer this from SDP.
                    let Some(pc) = weak_pc.upgrade() else { return };
                    if route(&pc.get_stats().await) == RelayRoute::RelayPair {
                        let _ = input.connected();
                    } else {
                        route_rejected.store(true, Ordering::Release);
                        input.disconnect();
                        tokio::spawn(async move {
                            let _ = pc.close().await;
                        });
                    }
                } else if matches!(
                    state,
                    RTCPeerConnectionState::Failed
                        | RTCPeerConnectionState::Disconnected
                        | RTCPeerConnectionState::Closed
                ) {
                    input.disconnect();
                }
            })
        }));
        let track_seen = Arc::new(AtomicBool::new(false));
        let receive_input = input.clone();
        let receive_tasks = tasks.clone();
        let receive_closed = closed.clone();
        pc.on_track(Box::new(move |track, _, _| {
            let input = receive_input.clone();
            let tasks = receive_tasks.clone();
            let closed = receive_closed.clone();
            let seen = track_seen.swap(true, Ordering::AcqRel);
            Box::pin(async move {
                if seen
                    || !track
                        .codec()
                        .capability
                        .mime_type
                        .eq_ignore_ascii_case(MIME_TYPE_OPUS)
                {
                    input.disconnect();
                    return;
                }
                let mut handles = tasks.lock();
                if closed.load(Ordering::Acquire) {
                    return;
                }
                let task = tokio::spawn(async move {
                    while let Ok((packet, _)) = track.read_rtp().await {
                        if packet.payload.len() > rtp::MAX_FRAME_BYTES {
                            break;
                        }
                        rtp::unpack(&packet.payload, |frame| {
                            let _ = input.receive(frame);
                        });
                    }
                    input.disconnect();
                });
                handles.push(task.abort_handle());
            })
        }));
        let track = Arc::new(TrackLocalStaticSample::new(
            RTCRtpCodecCapability {
                mime_type: MIME_TYPE_OPUS.into(),
                clock_rate: 48000,
                channels: 2,
                ..Default::default()
            },
            "tunnel".into(),
            "tunnel-media".into(),
        ));
        let sender = pc
            .add_track(track.clone())
            .await
            .map_err(|_| MediaError::Setup)?;
        tasks.lock().push(
            tokio::spawn(async move { while sender.read_rtcp().await.is_ok() {} }).abort_handle(),
        );
        tasks.lock().push(
            tokio::spawn(async move {
                while let Some(frame) = output.recv().await {
                    // QUIC's datagram MTU already fits one carrier RTP payload.
                    // No extra queue, sleeps, JS roundtrips or second reliability
                    // layer: QUIC handles carrier loss and congestion above RTP.
                    if frame.len() + 2 > rtp::MAX_FRAME_BYTES {
                        break;
                    }
                    let mut packed = Vec::with_capacity(frame.len() + 2);
                    rtp::push_packed(&mut packed, &frame, rtp::MAX_FRAME_BYTES);
                    if track
                        .write_sample(&Sample {
                            data: Bytes::from(packed),
                            duration: Duration::from_millis(20),
                            ..Default::default()
                        })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            })
            .abort_handle(),
        );
        Ok(owner)
    }

    async fn local(
        &self,
        description: RTCSessionDescription,
    ) -> Result<RTCSessionDescription, MediaError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(MediaError::Closed);
        }
        let mut gathering = self.pc.gathering_complete_promise().await;
        self.pc
            .set_local_description(description)
            .await
            .map_err(|_| MediaError::Negotiation)?;
        if tokio::time::timeout(Duration::from_secs(10), gathering.recv())
            .await
            .is_err()
        {
            self.close().await;
            return Err(MediaError::GatherTimeout);
        }
        let description = self
            .pc
            .local_description()
            .await
            .ok_or(MediaError::Negotiation)?;
        if !secure_audio(&description.sdp)
            || !description
                .sdp
                .lines()
                .any(|s| s.starts_with("a=candidate:") && relay_candidate(&s[2..]))
        {
            self.close().await;
            return Err(MediaError::NoRelay);
        }
        self.gathered_local_relay_candidates
            .store(relay_description_count(&description.sdp), Ordering::Release);
        Ok(description)
    }

    /// SDP is private signaling material and must never be logged or exposed
    /// as public HTTP state. Offerer/callee is independent of QUIC client/server.
    pub async fn offer(&self) -> Result<RTCSessionDescription, MediaError> {
        let description = self
            .pc
            .create_offer(None)
            .await
            .map_err(|_| MediaError::Negotiation)?;
        self.local(description).await
    }
    pub async fn answer(
        &self,
        offer: RTCSessionDescription,
    ) -> Result<RTCSessionDescription, MediaError> {
        if offer.sdp_type != RTCSdpType::Offer || !secure_audio(&offer.sdp) {
            return Err(MediaError::InvalidDescription);
        }
        let remote_candidates = relay_description_count(&offer.sdp);
        self.pc
            .set_remote_description(offer)
            .await
            .map_err(|_| MediaError::Negotiation)?;
        self.remote_description_relay_candidates
            .store(remote_candidates, Ordering::Release);
        let answer = self
            .pc
            .create_answer(None)
            .await
            .map_err(|_| MediaError::Negotiation)?;
        self.local(answer).await
    }
    pub async fn set_answer(&self, answer: RTCSessionDescription) -> Result<(), MediaError> {
        if answer.sdp_type != RTCSdpType::Answer || !secure_audio(&answer.sdp) {
            return Err(MediaError::InvalidDescription);
        }
        let remote_candidates = relay_description_count(&answer.sdp);
        self.pc
            .set_remote_description(answer)
            .await
            .map_err(|_| MediaError::Negotiation)?;
        self.remote_description_relay_candidates
            .store(remote_candidates, Ordering::Release);
        Ok(())
    }
    pub async fn add_candidate(&self, candidate: RTCIceCandidateInit) -> Result<(), MediaError> {
        if !relay_candidate(&candidate.candidate) {
            return Err(MediaError::InvalidDescription);
        }
        self.pc
            .add_ice_candidate(candidate)
            .await
            .map_err(|_| MediaError::Negotiation)
    }
    pub async fn selected_route(&self) -> RelayRoute {
        if self.closed.load(Ordering::Acquire)
            || self.pc.connection_state() != RTCPeerConnectionState::Connected
        {
            return RelayRoute::Unknown;
        }
        route(&self.pc.get_stats().await)
    }

    /// Read-only classification used only when the owning carrier reports a
    /// terminal event. Unknown stays unknown instead of inferring an ICE or
    /// DTLS fault from an elapsed timeout or a generic QUIC disconnect.
    pub fn disconnect_stage(&self) -> MediaDisconnectStage {
        disconnect_stage(
            self.pc.ice_connection_state(),
            self.pc.sctp().transport().state(),
            self.route_rejected.load(Ordering::Acquire),
        )
    }
    pub async fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.input.disconnect();
        for task in self.tasks.lock().drain(..) {
            task.abort();
        }
        let _ = self.pc.close().await;
    }
}
impl Drop for RelayMedia {
    fn drop(&mut self) {
        let was_closed = self.closed.swap(true, Ordering::AcqRel);
        self.input.disconnect();
        for task in self.tasks.lock().drain(..) {
            task.abort();
        }
        if !was_closed {
            let pc = self.pc.clone();
            crate::runtime().spawn(async move {
                let _ = pc.close().await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{carrier, security::Identity, LkTunnel, TunnelRole, TunnelState};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use webrtc::turn::{
        auth::{generate_auth_key, AuthHandler},
        relay::relay_static::RelayAddressGeneratorStatic,
        server::{
            config::{ConnConfig, ServerConfig},
            Server,
        },
    };

    #[test]
    fn disconnect_stage_requires_observed_failure_and_never_infers_from_waiting_or_closure() {
        for ice in [
            RTCIceConnectionState::Unspecified,
            RTCIceConnectionState::New,
            RTCIceConnectionState::Checking,
            RTCIceConnectionState::Connected,
            RTCIceConnectionState::Completed,
            RTCIceConnectionState::Closed,
        ] {
            for dtls in [
                RTCDtlsTransportState::Unspecified,
                RTCDtlsTransportState::New,
                RTCDtlsTransportState::Connecting,
                RTCDtlsTransportState::Connected,
                RTCDtlsTransportState::Closed,
            ] {
                assert_eq!(
                    disconnect_stage(ice, dtls, false),
                    MediaDisconnectStage::Unknown
                );
            }
        }
        assert_eq!(
            disconnect_stage(
                RTCIceConnectionState::Failed,
                RTCDtlsTransportState::New,
                false
            ),
            MediaDisconnectStage::Ice
        );
        assert_eq!(
            disconnect_stage(
                RTCIceConnectionState::Disconnected,
                RTCDtlsTransportState::Connected,
                false
            ),
            MediaDisconnectStage::Ice
        );
        assert_eq!(
            disconnect_stage(
                RTCIceConnectionState::Connected,
                RTCDtlsTransportState::Failed,
                false
            ),
            MediaDisconnectStage::Dtls
        );
        assert_eq!(
            disconnect_stage(
                RTCIceConnectionState::Closed,
                RTCDtlsTransportState::Closed,
                true
            ),
            MediaDisconnectStage::RelayRoute
        );
    }

    struct Auth;
    impl AuthHandler for Auth {
        fn auth_handle(
            &self,
            username: &str,
            realm: &str,
            _: SocketAddr,
        ) -> Result<Vec<u8>, webrtc::turn::Error> {
            if username == "fixture" && realm == "local-test" {
                Ok(generate_auth_key(username, realm, "local-fixture-password"))
            } else {
                Err(webrtc::turn::Error::ErrFakeErr)
            }
        }
    }
    async fn relay() -> (Server, RTCIceServer) {
        let conn = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let port = conn.local_addr().unwrap().port();
        let server = Server::new(ServerConfig {
            conn_configs: vec![ConnConfig {
                conn,
                relay_addr_generator: Box::new(RelayAddressGeneratorStatic {
                    relay_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    address: "127.0.0.1".into(),
                    net: Arc::new(webrtc::util::vnet::net::Net::new(None)),
                }),
            }],
            realm: "local-test".into(),
            auth_handler: Arc::new(Auth),
            channel_bind_timeout: Duration::ZERO,
            alloc_close_notify: None,
        })
        .await
        .unwrap();
        (
            server,
            RTCIceServer {
                urls: vec![format!("turn:127.0.0.1:{port}")],
                username: "fixture".into(),
                credential: "local-fixture-password".into(),
                credential_type: RTCIceCredentialType::Password,
            },
        )
    }
    async fn media_connected(tunnel: &Arc<LkTunnel>) {
        let mut state = tunnel.state();
        let result = tokio::time::timeout(
            Duration::from_secs(15),
            state.wait_for(|s| !matches!(s, TunnelState::Connecting)),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            matches!(*result, TunnelState::Connected),
            "media became terminal before connection"
        );
    }
    #[test]
    fn relay_config_cannot_enable_direct_or_unauthenticated_fallback() {
        assert!(matches!(config(vec![]), Err(MediaError::InvalidRelay)));
        let mut server = RTCIceServer {
            urls: vec!["turn:127.0.0.1:3478".into()],
            username: "u".into(),
            credential: "p".into(),
            credential_type: RTCIceCredentialType::Password,
        };
        assert_eq!(
            config(vec![server.clone()]).unwrap().ice_transport_policy,
            RTCIceTransportPolicy::Relay
        );
        for bad in [
            "stun:example.test:3478",
            "turn:user:password@example.test:3478",
            "https://example.test/",
            "turn:example.test:3478#secret",
            "turn:example.test:3478?transport=tcp",
            "turns:example.test:5349",
        ] {
            server.urls = vec![bad.into()];
            assert!(matches!(
                config(vec![server.clone()]),
                Err(MediaError::InvalidRelay)
            ));
        }
        server.urls = vec!["turn:example.test:3478".into()];
        server.credential.clear();
        assert!(matches!(
            config(vec![server]),
            Err(MediaError::InvalidRelay)
        ));
        assert!(!secure_audio("v=0\r\nm=audio 9 RTP/AVP 0\r\n"));
        assert!(!relay_candidate(
            "candidate:1 1 udp 1 127.0.0.1 33333 typ host x typ relay"
        ));
        assert!(!relay_candidate(
            "candidate:1 1 udp 1 127.0.0.1 33333 wrong relay"
        ));
        assert!(relay_candidate(
            "candidate:1 1 udp 1 127.0.0.1 33333 typ relay"
        ));
    }
    #[tokio::test]
    async fn real_relay_only_webrtc_carries_mutually_authenticated_quic_without_byte_changes() {
        let (relay, server) = relay().await;
        let a_id = Identity::generate().unwrap();
        let b_id = Identity::generate().unwrap();
        let (a, a_in, a_out) = carrier::authenticated(
            TunnelRole::Client,
            a_id.options(&[b_id.certificate.clone()], false, false)
                .unwrap(),
        )
        .unwrap();
        let (b, b_in, b_out) = carrier::authenticated(
            TunnelRole::Server,
            b_id.options(&[a_id.certificate.clone()], true, false)
                .unwrap(),
        )
        .unwrap();
        let a_media = RelayMedia::new(a_in, a_out, vec![server.clone()])
            .await
            .unwrap();
        let b_media = RelayMedia::new(b_in, b_out, vec![server]).await.unwrap();
        let before_description = b_media.ice_diagnostics().await;
        assert_eq!(before_description.gathered_local_relay_candidates, None);
        assert_eq!(before_description.remote_description_relay_candidates, None);
        // Nasim's invited callee can be the offerer. SDP direction must not
        // decide which endpoint provides the Internet/SOCKS role.
        let offer = b_media.offer().await.unwrap();
        assert!(secure_audio(&offer.sdp));
        let gathering_only = b_media.ice_diagnostics().await;
        assert!(gathering_only.local_relay_candidates > 0);
        assert_eq!(gathering_only.remote_relay_candidates, 0);
        assert!(gathering_only.gathered_local_relay_candidates.is_some_and(|count| count > 0));
        assert_eq!(gathering_only.remote_description_relay_candidates, None);
        assert_eq!(gathering_only.pair_succeeded, 0);
        let answer = a_media.answer(offer).await.unwrap();
        b_media.set_answer(answer).await.unwrap();
        tokio::join!(media_connected(&a), media_connected(&b));
        assert_eq!(a_media.selected_route().await, RelayRoute::RelayPair);
        assert_eq!(b_media.selected_route().await, RelayRoute::RelayPair);
        for media in [&a_media, &b_media] {
            let counts = media.ice_diagnostics().await;
            assert!(counts.local_relay_candidates > 0);
            assert!(counts.remote_relay_candidates > 0);
            assert!(counts.gathered_local_relay_candidates.is_some_and(|count| count > 0));
            assert!(counts.remote_description_relay_candidates.is_some_and(|count| count > 0));
            assert!(counts.pair_succeeded > 0);
            assert!(counts.nominated_pairs > 0);
            assert!(counts.requests_sent.is_none() && counts.requests_received.is_none());
            assert!(counts.responses_sent.is_none() && counts.responses_received.is_none());
        }
        assert!(!a.is_peer_authenticated());
        assert!(!a.is_proxy_ready());
        let endpoint = b.enable_quic_server().unwrap();
        let echo = tokio::spawn(async move {
            let connection = endpoint.endpoint.accept().await.unwrap().await.unwrap();
            let (mut write, mut read) = connection.accept_bi().await.unwrap();
            tokio::io::copy(&mut read, &mut write).await.unwrap();
        });
        tokio::time::timeout(Duration::from_secs(15), a.ensure_quic_client())
            .await
            .unwrap()
            .unwrap();
        assert!(a.is_peer_authenticated());
        let connection = a.quic_client.lock().as_ref().unwrap().connection.clone();
        let (mut write, mut read) = connection.open_bi().await.unwrap();
        let payload: Vec<u8> = (0..262144).map(|i| (i % 251) as u8).collect();
        let mut received = vec![0; payload.len()];
        tokio::time::timeout(Duration::from_secs(20), async {
            let (sent, read) =
                tokio::join!(write.write_all(&payload), read.read_exact(&mut received));
            sent.unwrap();
            read.unwrap();
        })
        .await
        .unwrap();
        assert_eq!(payload, received);
        a_media.close().await;
        b_media.close().await;
        relay.close().await.unwrap();
        echo.abort();
        assert!(!a.is_connected());
        assert!(!b.is_connected());
        assert!(!a.is_peer_authenticated());
        assert_eq!(a_media.selected_route().await, RelayRoute::Unknown);
        for media in [&a_media, &b_media] {
            let counts = media.ice_diagnostics().await;
            assert!(counts.gathered_local_relay_candidates.is_some_and(|count| count > 0));
            assert!(counts.remote_description_relay_candidates.is_some_and(|count| count > 0));
        }
    }

    #[tokio::test]
    async fn invalid_setup_and_owner_drop_leave_no_half_ready_tunnel() {
        let id = Identity::generate().unwrap();
        let (tunnel, input, output) = carrier::authenticated(
            TunnelRole::Client,
            id.options(&[id.certificate.clone()], false, false).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            RelayMedia::new(input, output, vec![]).await,
            Err(MediaError::InvalidRelay)
        ));
        assert!(!tunnel.is_connected());
        assert!(matches!(
            *tunnel.state().borrow(),
            TunnelState::Disconnected
        ));
        let (relay, server) = relay().await;
        let (tunnel, input, output) = carrier::authenticated(
            TunnelRole::Client,
            id.options(&[id.certificate.clone()], false, false).unwrap(),
        )
        .unwrap();
        let media = RelayMedia::new(input.clone(), output, vec![server])
            .await
            .unwrap();
        drop(media);
        assert!(matches!(
            *tunnel.state().borrow(),
            TunnelState::Disconnected
        ));
        assert!(input.connected().is_err());
        assert!(!tunnel.is_proxy_ready());
        relay.close().await.unwrap();
    }

    #[tokio::test]
    async fn reachable_relay_and_dtls_cannot_bypass_the_quic_identity_pin() {
        let (relay, server) = relay().await;
        let a_id = Identity::generate().unwrap();
        let b_id = Identity::generate().unwrap();
        let outsider = Identity::generate().unwrap();
        let (a, a_in, a_out) = carrier::authenticated(
            TunnelRole::Client,
            a_id.options(&[outsider.certificate], false, false).unwrap(),
        )
        .unwrap();
        let (b, b_in, b_out) = carrier::authenticated(
            TunnelRole::Server,
            b_id.options(&[a_id.certificate], true, false).unwrap(),
        )
        .unwrap();
        let a_media = RelayMedia::new(a_in, a_out, vec![server.clone()])
            .await
            .unwrap();
        let b_media = RelayMedia::new(b_in, b_out, vec![server]).await.unwrap();
        let offer = b_media.offer().await.unwrap();
        let answer = a_media.answer(offer).await.unwrap();
        b_media.set_answer(answer).await.unwrap();
        tokio::join!(media_connected(&a), media_connected(&b));
        let endpoint = b.enable_quic_server().unwrap();
        let accept = tokio::spawn(async move {
            if let Some(incoming) = endpoint.endpoint.accept().await {
                let _ = incoming.await;
            }
        });
        let result = tokio::time::timeout(Duration::from_secs(15), a.ensure_quic_client())
            .await
            .unwrap();
        assert!(result.is_err());
        assert!(!a.is_peer_authenticated());
        assert!(!a.is_proxy_ready());
        a_media.close().await;
        b_media.close().await;
        relay.close().await.unwrap();
        accept.abort();
    }

    #[tokio::test]
    async fn socks5_round_trip_uses_relay_media_and_owner_drop_closes_proxy_sockets() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // The production SSRF guard correctly rejects loopback targets. Its
        // existing test hook is process-global, so isolate this fixture in
        // a child test process rather than racing other security tests.
        const CHILD: &str = "BALEVPN_TEST_LOCAL_RELAY_PROXY";
        if std::env::var_os(CHILD).is_none() {
            let result=std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact","peer_media::tests::socks5_round_trip_uses_relay_media_and_owner_drop_closes_proxy_sockets"])
                .env(CHILD,"1").output().unwrap();
            assert!(
                result.status.success(),
                "isolated proxy fixture failed: {} {}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
            assert!(String::from_utf8_lossy(&result.stdout).contains("1 passed; 0 failed"));
            return;
        }
        crate::socks5_quic::set_ssrf_filter_enabled(false);
        let (relay, server) = relay().await;
        let a_id = Identity::generate().unwrap();
        let b_id = Identity::generate().unwrap();
        let (a, a_in, a_out) = carrier::authenticated(
            TunnelRole::Client,
            a_id.options(&[b_id.certificate.clone()], false, false)
                .unwrap(),
        )
        .unwrap();
        let (b, b_in, b_out) = carrier::authenticated(
            TunnelRole::Server,
            b_id.options(&[a_id.certificate], true, false).unwrap(),
        )
        .unwrap();
        let a_media = RelayMedia::new(a_in, a_out, vec![server.clone()])
            .await
            .unwrap();
        let b_media = RelayMedia::new(b_in, b_out, vec![server]).await.unwrap();
        let offer = b_media.offer().await.unwrap();
        let answer = a_media.answer(offer).await.unwrap();
        b_media.set_answer(answer).await.unwrap();
        tokio::join!(media_connected(&a), media_connected(&b));
        assert_eq!(a_media.selected_route().await, RelayRoute::RelayPair);
        b.start_server().unwrap();
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = target.local_addr().unwrap().port();
        let echo = tokio::spawn(async move {
            let (mut socket, _) = target.accept().await.unwrap();
            let (mut read, mut write) = socket.split();
            let _ = tokio::io::copy(&mut read, &mut write).await;
        });
        let address = a.enable_socks5_server(0).await.unwrap();
        assert!(address.ip().is_loopback());
        let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
        tokio::time::timeout(Duration::from_secs(20), async {
            socket.write_all(&[5, 1, 0]).await.unwrap();
            let mut greeting = [0; 2];
            socket.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 0]);
            let mut connect = vec![5, 1, 0, 1, 127, 0, 0, 1];
            connect.extend_from_slice(&target_port.to_be_bytes());
            socket.write_all(&connect).await.unwrap();
            let mut reply = [0; 10];
            socket.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply[..4], &[5, 0, 0, 1]);
            let payload: Vec<u8> = (0..524288).map(|i| (i % 251) as u8).collect();
            let mut received = vec![0; payload.len()];
            let (mut read, mut write) = socket.split();
            let (sent, got) =
                tokio::join!(write.write_all(&payload), read.read_exact(&mut received));
            sent.unwrap();
            got.unwrap();
            assert_eq!(payload, received);
        })
        .await
        .unwrap();
        assert!(a.is_proxy_ready());
        // The parent disappears without calling close: existing TCP sockets
        // and the listener must still die, not merely change the UI status.
        drop(a_media);
        assert!(!a.is_connected());
        assert!(!a.is_proxy_ready());
        let ended = tokio::time::timeout(Duration::from_secs(3), socket.read(&mut [0]))
            .await
            .unwrap();
        assert!(matches!(ended, Ok(0) | Err(_)));
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Ok(listener) = tokio::net::TcpListener::bind(address).await {
                    drop(listener);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        b_media.close().await;
        relay.close().await.unwrap();
        echo.abort();
    }
    include!("peer_media_adapter_test.rs");
}
