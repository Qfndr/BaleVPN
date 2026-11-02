//! Authenticated QUIC over a separately established media carrier.
//!
//! This module has no provider signaling or sockets. A native WebRTC driver
//! takes outbound frames and feeds received frames back after DTLS/SRTP.
//! The existing LiveKit/Bale connection path does not call this API.
use crate::{
    security::TunnelOptions, Event, EventKind, LkTunnel, TunnelRole, TunnelState, FRAME_TYPE_QUIC,
};
use bytes::Bytes;
use std::sync::{atomic::Ordering, Arc, Weak};
use tokio::sync::{mpsc, watch};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarrierError {
    AuthenticationRequired,
    WrongRoleConfiguration,
    Closed,
    NotConnected,
    InvalidFrame,
    NotReady,
    Backpressure,
}

/// Input may be cloned into per-track RTP callbacks. It holds only a weak
/// reference, so a callback cannot keep a dead tunnel or carrier alive.
#[derive(Clone)]
pub struct CarrierInput {
    tunnel: Weak<LkTunnel>,
}

/// One reader owns the media send path. Dropping it disconnects QUIC/SOCKS and
/// wakes waiters; buffered data is never replayed into another media session.
pub struct CarrierOutput {
    tunnel: Arc<LkTunnel>,
    receiver: mpsc::Receiver<Vec<u8>>,
    state: watch::Receiver<TunnelState>,
}

/// Prepare an authenticated tunnel in Connecting state. The media owner must
/// call [`CarrierInput::connected`] only after its encrypted carrier is ready.
pub fn authenticated(
    role: TunnelRole,
    options: TunnelOptions,
) -> Result<(Arc<LkTunnel>, CarrierInput, CarrierOutput), CarrierError> {
    if !options.authenticated {
        return Err(CarrierError::AuthenticationRequired);
    }
    if (role == TunnelRole::Client && options.client.is_none())
        || (role == TunnelRole::Server && options.server.is_none())
    {
        return Err(CarrierError::WrongRoleConfiguration);
    }
    let (tunnel, receiver) = crate::build_channel_inner(role, options);
    let input = CarrierInput {
        tunnel: Arc::downgrade(&tunnel),
    };
    let output = CarrierOutput {
        state: tunnel.state(),
        tunnel: tunnel.clone(),
        receiver,
    };
    Ok((tunnel, input, output))
}

impl CarrierInput {
    pub fn connected(&self) -> Result<(), CarrierError> {
        let tunnel = self.tunnel.upgrade().ok_or(CarrierError::Closed)?;
        let mut accepted = false;
        // Serialize the transition with teardown's state mutation. Emitting
        // inside this lock prevents Connected after a terminal state/event.
        tunnel.state_tx.send_if_modified(|state| {
            if tunnel.torn_down.load(Ordering::Acquire) {
                return false;
            }
            if matches!(state, TunnelState::Connected) {
                accepted = true;
                return false;
            }
            if !matches!(state, TunnelState::Connecting) {
                return false;
            }
            tunnel.connected.store(true, Ordering::Release);
            *state = TunnelState::Connected;
            let _ = tunnel.events_tx.send(Event {
                kind: EventKind::Connected,
                info: "media carrier ready".into(),
            });
            accepted = true;
            true
        });
        if accepted {
            Ok(())
        } else {
            Err(CarrierError::Closed)
        }
    }

    /// Feed one decoded RTP carrier frame. Only QUIC ciphertext is admitted.
    /// Bytes::slice keeps ingress zero-copy; queue overflow remains ordinary
    /// carrier loss that QUIC handles, rather than an unbounded extra queue.
    pub fn receive(&self, frame: Bytes) -> Result<(), CarrierError> {
        let tunnel = self.tunnel.upgrade().ok_or(CarrierError::Closed)?;
        if tunnel.torn_down.load(Ordering::Acquire) {
            return Err(CarrierError::Closed);
        }
        if !tunnel.connected.load(Ordering::Acquire) {
            return Err(CarrierError::NotConnected);
        }
        if frame.first() != Some(&FRAME_TYPE_QUIC) || frame.len() < 2 || frame.len() > 65536 {
            return Err(CarrierError::InvalidFrame);
        }
        let payload = frame.slice(1..);
        tunnel.counters.bump_rx(payload.len());
        let sender = tunnel
            .quic_rx_tx
            .lock()
            .clone()
            .ok_or(CarrierError::NotReady)?;
        match sender.try_send(payload) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => Err(CarrierError::Backpressure),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(CarrierError::NotReady),
        }
    }

    pub fn disconnect(&self) {
        if let Some(tunnel) = self.tunnel.upgrade() {
            tunnel.disconnect();
        }
    }
}

impl CarrierOutput {
    /// Wait for one outbound frame, or None when the media session ends.
    /// Dequeuing wakes existing backpressure waiters without copying packets.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        loop {
            if self.tunnel.torn_down.load(Ordering::Acquire) {
                return None;
            }
            tokio::select! {
                changed = self.state.changed() => {
                    if changed.is_err() || matches!(*self.state.borrow(), TunnelState::Failed(_) | TunnelState::Disconnected) { return None; }
                },
                frame = self.receiver.recv() => {
                    let frame = frame?;
                    let waiters: Vec<_> = self.tunnel.drain_waiters.lock().drain(..).collect();
                    for waiter in waiters { waiter(); }
                    if self.tunnel.torn_down.load(Ordering::Acquire) { return None; }
                    return Some(frame);
                },
            }
        }
    }
}

impl Drop for CarrierOutput {
    fn drop(&mut self) {
        self.tunnel.disconnect();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{security::Identity, SendError};
    use std::time::Duration;

    fn paired() -> (
        (Arc<LkTunnel>, CarrierInput, CarrierOutput),
        (Arc<LkTunnel>, CarrierInput, CarrierOutput),
    ) {
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        (
            authenticated(
                TunnelRole::Client,
                a.options(&[b.certificate.clone()], false, false).unwrap(),
            )
            .unwrap(),
            authenticated(
                TunnelRole::Server,
                b.options(&[a.certificate.clone()], true, false).unwrap(),
            )
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn rejects_unauthenticated_or_wrong_role_and_does_not_report_ready_before_media() {
        assert!(matches!(
            authenticated(TunnelRole::Client, Default::default()),
            Err(CarrierError::AuthenticationRequired)
        ));
        let id = Identity::generate().unwrap();
        assert!(matches!(
            authenticated(
                TunnelRole::Server,
                id.options(&[id.certificate.clone()], false, false).unwrap()
            ),
            Err(CarrierError::WrongRoleConfiguration)
        ));
        let ((a, input, mut output), _) = paired();
        assert!(!a.is_connected());
        assert!(!a.is_peer_authenticated());
        assert_eq!(
            a.send_raw_frame(vec![FRAME_TYPE_QUIC, 1], 1),
            Err(SendError::NotConnected)
        );
        assert_eq!(
            input.receive(Bytes::from_static(b"Qx")),
            Err(CarrierError::NotConnected)
        );
        input.connected().unwrap();
        assert!(a.is_connected());
        assert!(!a.is_proxy_ready());
        assert_eq!(
            input.receive(Bytes::from_static(b"Iplaintext")),
            Err(CarrierError::InvalidFrame)
        );
        assert_eq!(a.send_ip(&[0x45, 0, 0, 20]), Err(SendError::Invalid));
        input.disconnect();
        assert_eq!(input.connected(), Err(CarrierError::Closed));
        assert!(tokio::time::timeout(Duration::from_secs(1), output.recv())
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn connected_is_idempotent_and_dropping_the_media_output_is_terminal() {
        let ((a, input, output), _) = paired();
        let mut events = a.events().unwrap();
        input.connected().unwrap();
        input.connected().unwrap();
        assert_eq!(events.recv().await.unwrap().kind, EventKind::Connected);
        assert!(events.try_recv().is_err());
        drop(output);
        assert_eq!(events.recv().await.unwrap().kind, EventKind::Disconnected);
        assert_eq!(input.connected(), Err(CarrierError::Closed));
        assert!(!a.is_connected());
        assert_eq!(
            input.receive(Bytes::from_static(b"Qx")),
            Err(CarrierError::Closed)
        );
    }

    #[tokio::test]
    async fn bounded_egress_preserves_backpressure_and_wakes_waiters_when_a_frame_is_taken() {
        let ((a, input, mut output), _) = paired();
        input.connected().unwrap();
        for _ in 0..crate::SEND_QUEUE_CAP {
            a.send_raw_frame(vec![FRAME_TYPE_QUIC, 1], 1).unwrap();
        }
        assert_eq!(
            a.send_raw_frame(vec![FRAME_TYPE_QUIC, 1], 1),
            Err(SendError::Backpressure)
        );
        let woke = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = woke.clone();
        a.on_send_drained(move || {
            flag.store(true, Ordering::SeqCst);
        });
        assert!(!woke.load(Ordering::SeqCst));
        assert_eq!(output.recv().await.unwrap(), vec![FRAME_TYPE_QUIC, 1]);
        assert!(woke.load(Ordering::SeqCst));
        input.disconnect();
        assert!(output.recv().await.is_none());
    }

    #[tokio::test]
    async fn real_mutual_quic_and_byte_integrity_work_over_external_carrier_channels() {
        let ((a, input_a, mut output_a), (b, input_b, mut output_b)) = paired();
        input_a.connected().unwrap();
        input_b.connected().unwrap();
        let forward_b = input_b.clone();
        let forward_a = input_a.clone();
        let sender_a = tokio::spawn(async move {
            while let Some(frame) = output_a.recv().await {
                let _ = forward_b.receive(Bytes::from(frame));
            }
        });
        let sender_b = tokio::spawn(async move {
            while let Some(frame) = output_b.recv().await {
                let _ = forward_a.receive(Bytes::from(frame));
            }
        });
        let server = b.enable_quic_server().unwrap();
        let echo = tokio::spawn(async move {
            let connection = server.endpoint.accept().await.unwrap().await.unwrap();
            let (mut write, mut read) = connection.accept_bi().await.unwrap();
            tokio::io::copy(&mut read, &mut write).await.unwrap();
        });
        tokio::time::timeout(Duration::from_secs(5), a.ensure_quic_client())
            .await
            .unwrap()
            .unwrap();
        assert!(a.is_peer_authenticated());
        let connection = a.quic_client.lock().as_ref().unwrap().connection.clone();
        let (mut write, mut read) = connection.open_bi().await.unwrap();
        let payload: Vec<u8> = (0..256 * 1024).map(|n| (n % 251) as u8).collect();
        let mut received = vec![0; payload.len()];
        tokio::time::timeout(Duration::from_secs(5), async {
            let (sent, read) =
                tokio::join!(write.write_all(&payload), read.read_exact(&mut received));
            sent.unwrap();
            read.unwrap();
        })
        .await
        .unwrap();
        assert_eq!(payload, received);
        input_a.disconnect();
        input_b.disconnect();
        sender_a.await.unwrap();
        sender_b.await.unwrap();
        echo.abort();
    }
}
