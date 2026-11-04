//! Explicit experimental Nasim route policy. This module does not enable it.
//! The existing relay-only media constructor remains the default.
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CandidateKind {
    Host,
    ServerReflexive,
    Relay,
    PeerReflexive,
    Other,
}

/// Deliberately has no Debug/Display implementation: addresses stay private.
#[derive(Clone, Copy)]
pub struct Candidate {
    pub address: SocketAddr,
    pub kind: CandidateKind,
    pub udp: bool,
    pub component: u16,
}

pub struct NominatedPair {
    pub local: Candidate,
    pub remote: Candidate,
    pub nominated: bool,
    pub succeeded: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteProof {
    Unverified,
    ClientRelayServerPublic,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouteProofReason {
    NoSelectedPair,
    NoNomination,
    MultipleNominations,
    NominationNotSucceeded,
    MissingCandidateStats,
    StatsLimit,
    AddressFamilyMismatch,
    LocalCandidateRejected,
    RemoteCandidateRejected,
    Verified,
}

impl RouteProofReason {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::NoSelectedPair => "noSelectedPair",
            Self::NoNomination => "noNomination",
            Self::MultipleNominations => "multipleNominations",
            Self::NominationNotSucceeded => "nominationNotSucceeded",
            Self::MissingCandidateStats => "missingCandidateStats",
            Self::StatsLimit => "statsLimit",
            Self::AddressFamilyMismatch => "addressFamilyMismatch",
            Self::LocalCandidateRejected => "localCandidateRejected",
            Self::RemoteCandidateRejected => "remoteCandidateRejected",
            Self::Verified => "verified",
        }
    }

    pub(crate) fn proof(self) -> RouteProof {
        match self {
            Self::NoSelectedPair | Self::NoNomination | Self::MissingCandidateStats => {
                RouteProof::Unverified
            }
            Self::Verified => RouteProof::ClientRelayServerPublic,
            _ => RouteProof::Rejected,
        }
    }
}

impl CandidateKind {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::ServerReflexive => "srflx",
            Self::PeerReflexive => "prflx",
            Self::Relay => "relay",
            Self::Other => "unknown",
        }
    }
}

/// Candidate policy for the two authenticated Nasim call roles. The server
/// discovers its own public endpoint through ICE without an operator IP pin.
#[derive(Clone, Copy)]
pub struct NasimRoutePolicy {
    role: Role,
    #[cfg(test)]
    local_fixture: bool,
}

/// A proof belongs to one selection generation. An old async verification
/// cannot restore readiness after a newer selection has revoked it.
pub struct RouteEpoch {
    current: AtomicU64,
    verified: AtomicU64,
}

impl Default for RouteEpoch {
    fn default() -> Self {
        Self {
            current: AtomicU64::new(1),
            verified: AtomicU64::new(0),
        }
    }
}

impl RouteEpoch {
    pub fn revoke(&self) -> u64 {
        match self
            .current
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            }) {
            Ok(previous) => previous + 1,
            Err(_) => u64::MAX,
        }
    }

    pub fn verify(&self, generation: u64) -> bool {
        if generation == 0
            || generation == u64::MAX
            || self.current.load(Ordering::Acquire) != generation
        {
            return false;
        }
        self.publish(generation);
        self.current.load(Ordering::Acquire) == generation
    }

    fn publish(&self, generation: u64) {
        self.verified.fetch_max(generation, Ordering::AcqRel);
    }

    pub fn is_verified(&self) -> bool {
        let current = self.current.load(Ordering::Acquire);
        current != 0
            && current != u64::MAX
            && self.verified.load(Ordering::Acquire) == current
            && self.current.load(Ordering::Acquire) == current
    }

    pub fn is_current(&self, generation: u64) -> bool {
        generation != 0
            && generation != u64::MAX
            && self.current.load(Ordering::Acquire) == generation
    }
}

pub fn is_public_ip(ip: IpAddr) -> bool {
    if crate::nat::filter::is_blocked_dst(ip) {
        return false;
    }
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(a >= 240
                || a == 192 && b == 0 && c == 0
                || a == 192 && b == 88 && c == 99
                || a == 198 && (b == 18 || b == 19))
        }
        IpAddr::V6(ip) => {
            let s = ip.segments();
            s[0] & 0xe000 == 0x2000
                && !(s[0] == 0x2001 && (s[1] < 0x200 || s[1] == 0xdb8))
                && s[0] != 0x2002
                && !(s[0] == 0x3fff && s[1] < 0x1000)
        }
    }
}

impl NasimRoutePolicy {
    pub fn new(role: Role) -> Self {
        Self {
            role,
            #[cfg(test)]
            local_fixture: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn local_fixture(role: Role) -> Self {
        Self {
            role,
            local_fixture: true,
        }
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn allows(&self, candidate: Candidate, local: bool) -> bool {
        if !candidate.udp
            || !matches!(candidate.component, 1 | 2)
            || candidate.address.port() == 0
            || !self.public_candidate(candidate.address.ip())
        {
            return false;
        }
        let server_candidate = (self.role == Role::Server) == local;
        if server_candidate {
            candidate.address.port() >= 1024
                && matches!(
                    candidate.kind,
                    CandidateKind::Host | CandidateKind::ServerReflexive
                )
        } else {
            candidate.kind == CandidateKind::Relay
        }
    }

    pub(crate) fn public_candidate(&self, address: IpAddr) -> bool {
        #[cfg(test)]
        if self.local_fixture && address.is_loopback() {
            return true;
        }
        is_public_ip(address)
    }

    /// The adapter must supply only pairs joined to their exact typed candidate
    /// IDs. The pinned ICE agent marks the selected pair nominated before
    /// publishing selection. More than one nomination is intentionally rejected.
    /// A missing first stats snapshot is Unverified so a bounded retry can run.
    pub fn prove(&self, selected_exists: bool, pairs: &[NominatedPair]) -> RouteProof {
        self.proof_reason(selected_exists, pairs).proof()
    }

    pub(crate) fn proof_reason(
        &self,
        selected_exists: bool,
        pairs: &[NominatedPair],
    ) -> RouteProofReason {
        if !selected_exists {
            return RouteProofReason::NoSelectedPair;
        }
        let mut nominated = pairs.iter().filter(|pair| pair.nominated);
        let Some(pair) = nominated.next() else {
            return RouteProofReason::NoNomination;
        };
        if nominated.next().is_some() {
            return RouteProofReason::MultipleNominations;
        }
        if !pair.succeeded {
            return RouteProofReason::NominationNotSucceeded;
        }
        if pair.local.address.is_ipv4() != pair.remote.address.is_ipv4() {
            return RouteProofReason::AddressFamilyMismatch;
        }
        if !self.allows(pair.local, true) {
            return RouteProofReason::LocalCandidateRejected;
        }
        if !self.allows(pair.remote, false) {
            return RouteProofReason::RemoteCandidateRejected;
        }
        RouteProofReason::Verified
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint() -> SocketAddr {
        "8.8.8.8:37000".parse().unwrap()
    }
    fn relay() -> Candidate {
        Candidate {
            address: "1.1.1.1:48000".parse().unwrap(),
            kind: CandidateKind::Relay,
            udp: true,
            component: 1,
        }
    }
    fn server() -> Candidate {
        Candidate {
            address: endpoint(),
            kind: CandidateKind::Host,
            udp: true,
            component: 1,
        }
    }
    fn pair() -> NominatedPair {
        NominatedPair {
            local: relay(),
            remote: server(),
            nominated: true,
            succeeded: true,
        }
    }

    #[test]
    fn requires_discovered_server_candidate_to_be_public_and_nonprivileged() {
        let policy = NasimRoutePolicy::new(Role::Client);
        for value in [
            "127.0.0.1:37000",
            "10.0.0.1:37000",
            "169.254.169.254:37000",
            "198.18.0.1:37000",
            "192.0.2.1:37000",
            "[::1]:37000",
            "[::ffff:8.8.8.8]:37000",
            "[2001:db8::1]:37000",
            "8.8.8.8:0",
            "8.8.8.8:443",
        ] {
            let mut candidate = server();
            candidate.address = value.parse().unwrap();
            assert!(!policy.allows(candidate, false));
        }
        assert!(policy.allows(server(), false));
    }

    #[test]
    fn client_requires_own_relay_and_accepts_public_server_address_changes() {
        let policy = NasimRoutePolicy::new(Role::Client);
        assert!(policy.allows(relay(), true));
        assert!(policy.allows(server(), false));
        assert!(!policy.allows(server(), true));
        assert!(!policy.allows(relay(), false));
        let mut changed = server();
        changed.address.set_port(37001);
        assert!(policy.allows(changed, false));
        changed = server();
        changed.address.set_ip("9.9.9.9".parse().unwrap());
        assert!(policy.allows(changed, false));
    }

    #[test]
    fn server_has_inverse_roles_and_rejects_peer_host_candidates() {
        let policy = NasimRoutePolicy::new(Role::Server);
        assert!(policy.allows(server(), true));
        assert!(policy.allows(relay(), false));
        assert!(!policy.allows(server(), false));
        assert!(!policy.allows(relay(), true));
    }

    #[test]
    fn rejects_tcp_private_unknown_components_and_peer_reflexive() {
        let policy = NasimRoutePolicy::new(Role::Client);
        let mut candidate = relay();
        candidate.udp = false;
        assert!(!policy.allows(candidate, true));
        candidate = relay();
        candidate.address.set_ip("10.0.0.1".parse().unwrap());
        assert!(!policy.allows(candidate, true));
        candidate = relay();
        candidate.component = 3;
        assert!(!policy.allows(candidate, true));
        candidate = relay();
        candidate.kind = CandidateKind::Other;
        assert!(!policy.allows(candidate, true));
    }

    #[test]
    fn proof_requires_selected_unique_successful_nomination() {
        let policy = NasimRoutePolicy::new(Role::Client);
        assert_eq!(policy.prove(false, &[pair()]), RouteProof::Unverified);
        assert_eq!(policy.prove(true, &[]), RouteProof::Unverified);
        assert_eq!(
            policy.prove(true, &[pair()]),
            RouteProof::ClientRelayServerPublic
        );
        assert_eq!(policy.prove(true, &[pair(), pair()]), RouteProof::Rejected);
        let mut failed = pair();
        failed.succeeded = false;
        assert_eq!(policy.prove(true, &[failed]), RouteProof::Rejected);
        let mut bypass = pair();
        bypass.local = server();
        assert_eq!(policy.prove(true, &[bypass]), RouteProof::Rejected);
        let mut peer_reflexive = pair();
        peer_reflexive.remote.kind = CandidateKind::PeerReflexive;
        let reason = policy.proof_reason(true, &[peer_reflexive]);
        assert_eq!(reason, RouteProofReason::RemoteCandidateRejected);
        assert_eq!(reason.proof(), RouteProof::Rejected);
        assert_eq!(reason.code(), "remoteCandidateRejected");
        assert_eq!(CandidateKind::PeerReflexive.code(), "prflx");
        let mut mixed = pair();
        mixed.local.address = "[2606:4700:4700::1111]:48000".parse().unwrap();
        assert_eq!(policy.prove(true, &[mixed]), RouteProof::Rejected);
    }

    #[test]
    fn server_reflexive_allowed_only_for_server_role() {
        let policy = NasimRoutePolicy::new(Role::Client);
        let mut candidate = server();
        candidate.kind = CandidateKind::ServerReflexive;
        assert!(policy.allows(candidate, false));
        assert!(!policy.allows(candidate, true));
    }

    #[test]
    fn newer_selection_revokes_old_proof_even_if_old_work_finishes_late() {
        let epoch = RouteEpoch::default();
        assert!(!epoch.is_verified());
        let first = epoch.revoke();
        assert!(epoch.verify(first));
        assert!(epoch.is_verified());
        let second = epoch.revoke();
        assert!(!epoch.is_verified());
        assert!(!epoch.verify(first));
        assert!(!epoch.is_verified());
        assert!(epoch.verify(second));
        assert!(epoch.is_verified());
        epoch.publish(first);
        assert!(epoch.is_verified());
    }

    #[test]
    fn exhausted_generation_never_wraps_or_reuses_an_old_proof() {
        let epoch = RouteEpoch {
            current: AtomicU64::new(u64::MAX - 1),
            verified: AtomicU64::new(u64::MAX - 1),
        };
        assert!(epoch.is_verified());
        assert_eq!(epoch.revoke(), u64::MAX);
        assert!(!epoch.is_verified());
        assert!(!epoch.verify(u64::MAX));
        assert_eq!(epoch.revoke(), u64::MAX);
        assert!(!epoch.is_verified());
    }
}
