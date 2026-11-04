//! Private WebRTC adapters for the explicit Nasim asymmetric experiment.
use crate::nasim_route_policy::{
    Candidate, CandidateKind, NasimRoutePolicy, NominatedPair, RouteProof,
};
use std::net::SocketAddr;
use webrtc::{
    ice::candidate::{
        candidate_base::unmarshal_candidate, Candidate as IceCandidate, CandidatePairState,
        CandidateType,
    },
    peer_connection::sdp::{sdp_type::RTCSdpType, session_description::RTCSessionDescription},
    stats::{ICECandidateStats, StatsReport, StatsReportType},
};

fn kind(value: CandidateType) -> CandidateKind {
    match value {
        CandidateType::Host => CandidateKind::Host,
        CandidateType::ServerReflexive => CandidateKind::ServerReflexive,
        CandidateType::Relay => CandidateKind::Relay,
        _ => CandidateKind::Other,
    }
}

pub(crate) fn candidate(policy: NasimRoutePolicy, value: &str, local: bool) -> Option<String> {
    if value.len() > 4096 || value.contains(['\r', '\n', '\0']) {
        return None;
    }
    let raw = value.strip_prefix("candidate:")?;
    let parsed = unmarshal_candidate(raw).ok()?;
    let ip = parsed.address().parse().ok()?;
    let candidate = Candidate {
        address: SocketAddr::new(ip, parsed.port()),
        kind: kind(parsed.candidate_type()),
        udp: parsed.network_type().is_udp(),
        component: parsed.component(),
    };
    if !policy.allows(candidate, local) {
        return None;
    }
    // Only required public candidate fields leave this adapter. In particular,
    // do not copy related-address, related-port or vendor extensions containing
    // the source host address into signaling.
    Some(format!(
        "candidate:{} {} udp {} {} {} typ {}",
        parsed.foundation(),
        parsed.component(),
        parsed.priority(),
        candidate.address.ip(),
        candidate.address.port(),
        parsed.candidate_type()
    ))
}

pub(crate) fn description(
    policy: NasimRoutePolicy,
    value: RTCSessionDescription,
    local: bool,
) -> Option<RTCSessionDescription> {
    if value.sdp.len() > 65535 || value.sdp.contains('\0') {
        return None;
    }
    let mut parsed = value.unmarshal().ok()?;
    if parsed.media_descriptions.len() != 1
        || parsed.media_descriptions[0].media_name.media != "audio"
    {
        return None;
    }
    let mut total = 0;
    let mut accepted = 0;
    // Candidate values are edited as parsed attributes. Every other attribute,
    // including ICE credentials and the DTLS fingerprint, is preserved.
    for attributes in std::iter::once(&mut parsed.attributes).chain(
        parsed
            .media_descriptions
            .iter_mut()
            .map(|media| &mut media.attributes),
    ) {
        if attributes.len() > 512 {
            return None;
        }
        let mut sanitized = Vec::with_capacity(attributes.len());
        for mut attribute in std::mem::take(attributes) {
            if attribute.key == "candidate" {
                total += 1;
                if total > 64 {
                    return None;
                }
                let input = format!("candidate:{}", attribute.value.as_deref()?);
                match candidate(policy, &input, local) {
                    Some(value) => {
                        attribute.value = Some(value.strip_prefix("candidate:")?.to_owned());
                        accepted += 1;
                    }
                    None if local => continue,
                    None => return None,
                }
            }
            sanitized.push(attribute);
        }
        *attributes = sanitized;
    }
    if accepted == 0 {
        return None;
    }
    let sdp = parsed.marshal();
    match value.sdp_type {
        RTCSdpType::Offer => RTCSessionDescription::offer(sdp).ok(),
        RTCSdpType::Answer => RTCSessionDescription::answer(sdp).ok(),
        _ => None,
    }
}

fn stats_candidate(value: &ICECandidateStats) -> Option<Candidate> {
    Some(Candidate {
        address: SocketAddr::new(value.ip.parse().ok()?, value.port),
        kind: kind(value.candidate_type),
        udp: value.network_type.is_udp(),
        component: 1,
    })
}

pub(crate) fn proof(
    policy: NasimRoutePolicy,
    selected_exists: bool,
    stats: &StatsReport,
) -> RouteProof {
    if stats.reports.len() > 1024 {
        return RouteProof::Rejected;
    }
    let mut pairs = Vec::new();
    for value in stats.reports.values() {
        let StatsReportType::CandidatePair(pair) = value else {
            continue;
        };
        if !pair.nominated {
            continue;
        }
        if pairs.len() == 64 {
            return RouteProof::Rejected;
        }
        let local = stats.reports.values().find_map(|value| match value {
            StatsReportType::LocalCandidate(candidate)
                if candidate.id == pair.local_candidate_id =>
            {
                stats_candidate(candidate)
            }
            _ => None,
        });
        let remote = stats.reports.values().find_map(|value| match value {
            StatsReportType::RemoteCandidate(candidate)
                if candidate.id == pair.remote_candidate_id =>
            {
                stats_candidate(candidate)
            }
            _ => None,
        });
        let (Some(local), Some(remote)) = (local, remote) else {
            return RouteProof::Unverified;
        };
        pairs.push(NominatedPair {
            local,
            remote,
            nominated: true,
            succeeded: pair.state == CandidatePairState::Succeeded,
        });
    }
    policy.prove(selected_exists, &pairs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nasim_route_policy::Role;

    fn policy() -> NasimRoutePolicy {
        NasimRoutePolicy::new(Role::Client)
    }

    #[test]
    fn candidate_parser_strips_private_related_address_extensions() {
        let value = "candidate:f 1 udp 123 1.1.1.1 48000 typ relay raddr 10.1.2.3 rport 5000";
        let sanitized = candidate(policy(), value, true).unwrap();
        assert_eq!(sanitized, "candidate:f 1 udp 123 1.1.1.1 48000 typ relay");
        assert!(candidate(
            policy(),
            "candidate:f 1 udp 123 hidden.local 48000 typ relay",
            true
        )
        .is_none());
        assert!(candidate(
            policy(),
            "candidate:f 1 tcp 123 1.1.1.1 48000 typ relay",
            true
        )
        .is_none());
    }

    #[test]
    fn description_keeps_credentials_and_fingerprint_while_filtering_local_candidates() {
        let sdp="v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\nc=IN IP4 0.0.0.0\r\na=ice-ufrag:fixtureUfrag\r\na=ice-pwd:fixturePassword\r\na=fingerprint:sha-256 AA:BB:CC\r\na=candidate:private 1 udp 100 10.0.0.1 40000 typ host\r\na=candidate:relay 1 udp 99 1.1.1.1 48000 typ relay raddr 10.0.0.1 rport 40000\r\n";
        let filtered = description(
            policy(),
            RTCSessionDescription::offer(sdp.into()).unwrap(),
            true,
        )
        .unwrap();
        assert!(filtered.sdp.contains("a=ice-ufrag:fixtureUfrag"));
        assert!(filtered.sdp.contains("a=ice-pwd:fixturePassword"));
        assert!(filtered.sdp.contains("a=fingerprint:sha-256 AA:BB:CC"));
        assert!(!filtered.sdp.contains("10.0.0.1"));
        assert!(description(
            policy(),
            RTCSessionDescription::offer(sdp.into()).unwrap(),
            false
        )
        .is_none());
    }
}
