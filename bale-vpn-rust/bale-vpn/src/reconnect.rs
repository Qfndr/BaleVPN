//! Reconnect policy runs only after a session ends; no packet-path work.
use std::time::Duration;

#[derive(Default)]
pub struct Recovery {
    peer: Option<String>,
    failures: u32,
}
impl Recovery {
    pub fn delay(
        &mut self,
        peer: &str,
        established: bool,
        error: Option<&str>,
        base: u64,
        budget: u64,
    ) -> Option<Duration> {
        if self.peer.as_deref() != Some(peer) || established {
            self.failures = 0;
        }
        self.peer = Some(peer.to_owned());
        if !retryable(error) {
            self.failures = 0;
            return None;
        }
        let seconds = base
            .saturating_mul(1u64 << self.failures.min(5))
            .min(120)
            .max(budget);
        self.failures = self.failures.saturating_add(1);
        Some(Duration::from_secs(seconds))
    }
}
fn retryable(error: Option<&str>) -> bool {
    let Some(error) = error else {
        return true;
    };
    let error = error.to_ascii_lowercase();
    // Explicit refusal, invalid settings and failed peer verification need user
    // action. Never weaken pairing or repeatedly call a rejecting account.
    if [
        "reject",
        "callnotapproved",
        "invalidpeer",
        "unknown peer",
        "not authenticated",
        "unauthenticated",
        "unauthorized",
        "session expired",
        "auth_key",
        "certificate",
        "untrusted",
        "authentication",
        "identity",
        "pairing",
        "public key",
        "private key",
        "raw tun is disabled",
        "forbidden",
        "permission denied",
        "not authorized",
        "access denied",
        "invalid token",
        "token expired",
        "user_blocked",
        "invalid_peer",
    ]
    .iter()
    .any(|s| error.contains(s))
    {
        return false;
    }
    [
        "timeout",
        "timed out",
        "lk failed to connect",
        "lk disconnected",
        "manager events stream closed",
        "transport:",
        "network",
        "connection reset",
        "connection closed",
        "connection lost",
        "broken pipe",
        "not connected",
        "flood",
        "rate limit",
        "too many requests",
        "code=8",
        "code=429",
        "http 429",
        "before another call attempt",
    ]
    .iter()
    .any(|s| error.contains(s))
}

/// A manual disconnect, logout, new selection or role change wakes this wait.
/// The caller tears the dead session down before waiting.
pub async fn wait(
    delay: Duration,
    changes: &mut tokio::sync::watch::Receiver<Option<String>>,
) -> bool {
    tokio::select! {biased; _=changes.changed()=>false, _=tokio::time::sleep(delay)=>true}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ended_calls_retry_backoff_resets_after_success_or_new_peer() {
        let mut r = Recovery::default();
        assert_eq!(
            r.delay("a", true, None, 10, 0),
            Some(Duration::from_secs(10))
        );
        for seconds in [20, 40, 80, 120, 120] {
            assert_eq!(
                r.delay("a", false, Some("peer never joined (timeout)"), 10, 0),
                Some(Duration::from_secs(seconds))
            );
        }
        assert_eq!(
            r.delay("a", true, None, 10, 0),
            Some(Duration::from_secs(10))
        );
        assert_eq!(
            r.delay("b", false, Some("transport: network offline"), 10, 0),
            Some(Duration::from_secs(10))
        );
        assert_eq!(
            r.delay("b", false, Some("transport: FLOOD_WAIT_600"), 10, 600),
            Some(Duration::from_secs(600))
        );
    }
    #[test]
    fn refusal_identity_and_configuration_failures_stop_instead_of_redialing() {
        for e in [
            "call rejected by peer",
            "transport: CallNotApproved",
            "transport: InvalidPeer",
            "client: unknown peer (resolve_peer returned None)",
            "not authenticated",
            "Secure transport: invalid certificate",
            "Secure transport: peer authentication failed",
            "Secure transport: unknown identity",
            "Address already in use",
            "Authenticated mode supports SOCKS5; raw TUN is disabled",
        ] {
            assert_eq!(
                Recovery::default().delay("a", false, Some(e), 10, 0),
                None,
                "{e}"
            );
        }
        for e in [
            "LK failed to connect",
            "LK disconnected before connect",
            "manager events stream closed",
            "transport: connection reset",
            "Secure transport: connection timed out",
            "Wait 30s before another call attempt",
        ] {
            assert!(retryable(Some(e)), "{e}");
        }
    }
    #[tokio::test]
    async fn disconnect_logout_and_role_changes_cancel_pending_reconnect() {
        for value in [Some("client".to_owned()), None, Some("server".to_owned())] {
            let (tx, mut rx) = tokio::sync::watch::channel(Some("client".to_owned()));
            let task = tokio::spawn(async move { wait(Duration::from_secs(3600), &mut rx).await });
            tx.send(value).unwrap();
            assert!(!tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap());
        }
        let (tx, mut rx) = tokio::sync::watch::channel(None);
        drop(tx);
        assert!(!wait(Duration::from_secs(3600), &mut rx).await);
        let (_tx, mut rx) = tokio::sync::watch::channel(None);
        assert!(wait(Duration::ZERO, &mut rx).await);
    }
}
