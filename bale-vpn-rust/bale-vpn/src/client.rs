//! Client-mode state. Holds the per-session [`LkTunnel`] and
//! exposes a tiny query surface for the HTTP UI.

use lktunnel::LkTunnel;
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Tracked client-mode session. `None` until [`Self::set_tunnel`]
/// is called from the daemon's place-call success path.
#[derive(Default)]
pub struct ClientState {
    inner: Mutex<Option<Inner>>,
    last_error: Mutex<Option<String>>,
    completed: Mutex<CompletedTraffic>,
    reconnect_at: Mutex<Option<Instant>>,
}

#[derive(Default)]
struct CompletedTraffic {
    received: u64,
    sent: u64,
    elapsed: Duration,
    last: Option<(u64, u64, u64, u64)>,
}

#[derive(Clone, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrafficSnapshot {
    pub session_id: Option<u64>,
    pub session_elapsed_ms: u64,
    pub received_bytes: u64,
    pub sent_bytes: u64,
    pub process_received_bytes: u64,
    pub process_sent_bytes: u64,
    pub process_active_ms: u64,
    pub active: bool,
}

struct Inner {
    tunnel:       Arc<LkTunnel>,
    socks5_port:  u16,
    started: Instant,
}

impl ClientState {
    pub fn new() -> Arc<Self> { Arc::new(Self::default()) }

    pub fn set_tunnel(&self, tunnel: Arc<LkTunnel>, socks5_port: u16) {
        if self.inner.lock().as_ref().is_some_and(|i| Arc::ptr_eq(&i.tunnel, &tunnel)) { return; }
        self.clear();
        self.clear_error();
        *self.inner.lock() = Some(Inner { tunnel, socks5_port, started: Instant::now() });
    }

    pub fn clear(&self) {
        let mut inner = self.inner.lock();
        if let Some(previous) = inner.take() {
            previous.tunnel.disconnect();
            let stats = previous.tunnel.stats();
            let elapsed = previous.started.elapsed();
            let mut completed = self.completed.lock();
            completed.received = completed.received.saturating_add(stats[1]);
            completed.sent = completed.sent.saturating_add(stats[3]);
            completed.elapsed = completed.elapsed.saturating_add(elapsed);
            completed.last = Some((previous.tunnel.id(), stats[1], stats[3], elapsed.as_millis() as u64));
        }
    }

    /// Read existing counters only when polled; no accounting on the packet path.
    /// Process totals live in memory and reset when the application exits.
    pub fn traffic_snapshot(&self) -> TrafficSnapshot {
        let inner = self.inner.lock();
        let completed = self.completed.lock();
        let (session_id, rx, tx, elapsed, active) = if let Some(i) = inner.as_ref() {
            let stats = i.tunnel.stats();
            (Some(i.tunnel.id()), stats[1], stats[3], i.started.elapsed().as_millis() as u64, true)
        } else if let Some((id, rx, tx, elapsed)) = completed.last {
            (Some(id), rx, tx, elapsed, false)
        } else { (None, 0, 0, 0, false) };
        TrafficSnapshot {
            session_id, received_bytes: rx, sent_bytes: tx, session_elapsed_ms: elapsed, active,
            process_received_bytes: completed.received.saturating_add(if active { rx } else { 0 }),
            process_sent_bytes: completed.sent.saturating_add(if active { tx } else { 0 }),
            process_active_ms: (completed.elapsed.as_millis() as u64).saturating_add(if active { elapsed } else { 0 }),
        }
    }

    // Session teardown must not erase the failure before the next UI poll.
    // Only an explicit new attempt, disconnect, role change, or logout clears it.
    pub fn set_error(&self, error: String) { *self.last_error.lock() = Some(error); }
    pub fn clear_error(&self) { *self.last_error.lock() = None; *self.reconnect_at.lock() = None; }
    pub fn last_error(&self) -> Option<String> { self.last_error.lock().clone() }
    pub fn reconnect_after(&self, delay: Duration) { *self.reconnect_at.lock() = Some(Instant::now()+delay); }
    pub fn stop_reconnect(&self) { *self.reconnect_at.lock() = None; }
    pub fn reconnect_delay(&self) -> Option<Duration> { self.reconnect_at.lock().map(|at|at.saturating_duration_since(Instant::now())) }
    pub fn reconnect_status(&self) -> (bool,u64) {
        let at=*self.reconnect_at.lock();
        (at.is_some(),at.map(|at| {let d=at.saturating_duration_since(Instant::now());d.as_secs()+u64::from(d.subsec_nanos()>0)}).unwrap_or(0))
    }

    pub async fn socks5_bound_port(&self) -> Option<u16> {
        self.inner.lock().as_ref().map(|i| i.socks5_port)
    }

    /// Strong handle to the active tunnel, if any. Useful for
    /// runtime mutations (toggle SOCKS5 on/off via the UI).
    /// Returns `None` when no client session is up. Currently
    /// unused — wired in once the SOCKS5 toggle and port-change
    /// HTTP endpoints land.
    #[allow(dead_code)]
    pub fn tunnel(&self) -> Option<Arc<LkTunnel>> {
        self.inner.lock().as_ref().map(|i| i.tunnel.clone())
    }

    /// Snapshot for the HTTP `/state` endpoint — connection flag,
    /// SOCKS5 port, RX/TX bytes. None when no client session is
    /// active.
    pub async fn snapshot(&self) -> Option<ClientSnapshot> {
        let inner = self.inner.lock();
        let i = inner.as_ref()?;
        let connected = i.tunnel.is_proxy_ready();
        let stats = i.tunnel.stats();
        Some(ClientSnapshot {
            socks5_port: i.socks5_port,
            connected,
            // stats layout: [rx_pkts, rx_bytes, tx_pkts, tx_bytes].
            rx_bytes: stats[1],
            tx_bytes: stats[3],
        })
    }
}

#[derive(Clone)]
pub struct ClientSnapshot {
    pub socks5_port: u16,
    pub connected:   bool,
    pub rx_bytes:    u64,
    pub tx_bytes:    u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn traffic_totals_keep_direction_survive_disconnect_and_accumulate_calls() {
        let state = ClientState::new();
        let mut expected_rx = 0; let mut expected_tx = 0;
        let mut previous_id = None;
        for n in [5usize, 11] {
            let (a,b) = lktunnel::connect_loopback();
            state.set_tunnel(a.clone(), 1080);
            // Controlled carrier bytes only; no account, network or SOCKS dial.
            a.send_raw_frame(vec![b'Q'; n+1], n).unwrap();
            b.send_raw_frame(vec![b'Q'; n*2+1], n*2).unwrap();
            tokio::time::timeout(Duration::from_secs(3), async {
                while a.stats()[1] != (n*2) as u64 { tokio::time::sleep(Duration::from_millis(5)).await; }
            }).await.unwrap();
            let active = state.traffic_snapshot();
            assert!(active.active);
            assert_eq!(active.received_bytes, (n*2) as u64);
            assert_eq!(active.sent_bytes, n as u64);
            assert_ne!(active.session_id, previous_id);
            previous_id=active.session_id;
            expected_rx += (n*2) as u64; expected_tx += n as u64;
            assert_eq!(active.process_received_bytes, expected_rx);
            assert_eq!(active.process_sent_bytes, expected_tx);
            state.set_tunnel(a.clone(),1080); // duplicate publication is harmless
            assert!(a.is_connected());
            state.clear();state.clear(); // no duplicate accounting
            let ended = state.traffic_snapshot();
            assert!(!ended.active);
            assert_eq!(ended.session_id, previous_id);
            assert_eq!(ended.process_received_bytes, expected_rx);
            assert_eq!(ended.process_sent_bytes, expected_tx);
            b.disconnect();
        }
    }

    #[test]
    fn failed_attempt_survives_session_teardown_until_explicit_reset() {
        let client = ClientState::new();
        client.set_error("StartCall: CallNotApproved".into());
        client.clear();
        assert_eq!(client.last_error().as_deref(), Some("StartCall: CallNotApproved"));
        client.clear_error();
        assert_eq!(client.last_error(), None);
    }

    #[tokio::test]
    async fn reconnect_status_survives_teardown_but_success_or_manual_disconnect_clears_it() {
        let client=ClientState::new();
        client.set_error("Connection interrupted".into());
        client.reconnect_after(Duration::from_secs(10));
        client.clear();
        assert!(client.reconnect_status().0 && client.reconnect_status().1>0);
        client.clear_error();
        assert_eq!(client.reconnect_status(),(false,0));
        client.reconnect_after(Duration::from_secs(10));
        let(a,b)=lktunnel::connect_loopback();
        client.set_tunnel(a,1080);
        assert_eq!(client.reconnect_status(),(false,0));
        assert!(client.last_error().is_none());
        client.clear();b.disconnect();
    }
}
