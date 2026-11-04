# LiveKit API compatibility patch

`livekit-api/` contains the published source of `livekit-api` 0.4.24 (Apache-2.0),
from https://github.com/livekit/rust-sdks at commit aec91c8e1b70614e7b254589c00aaba992c0a39f.
Only the published normalized `Cargo.toml` and `src/` are included.

The original feature patch in `src/http_client.rs` exports `reqwest::Client` when
`signal-client-tokio` is enabled as well as when `services-tokio` is enabled.
The signal client's `region.rs` needs this type. Upstream's feature gate prevents
a signaling-only build, forcing consumers to enable server services, JWT, and
an unused RustCrypto RSA implementation with RUSTSEC-2023-0071.

The three transport-consuming workspace roots patch this crate to the same path.
The application enables only the signaling and rustls root-certificate features.
Crypto and certificate verification are unchanged. Additional signaling lifecycle
changes are described below.
Remove this patch when upgrading to an upstream release that supports this
feature combination, and rerun every workspace's tests and security audit.

## Signaling startup cancellation and ordered negotiation

The signal stream uses abortable read/write tasks and a pending-stream guard so
cancelled joins and abandoned startup do not retain background WebSocket tasks.
The ordinary public `send` behavior remains unchanged.

`send_sdp_or_ice` is an additive checked write for Offer, Answer and Trickle only.
It returns an opaque physical-stream token after a successful write, rejects a
token from a different/replaced stream, does not replay negotiation on reconnect,
and bounds the entire operation including lock acquisition. Cancelled queued
writes are skipped. No credentials, SDP, or addresses enter these tokens.
The tunnel's bounded per-PC generation gate uses this result to send SDP before
releasing locally gathered ICE candidates. Gate bookkeeping never holds its
mutex across an await, and failed/cancelled generations cannot reopen a new one.

Local WebSocket/real-peer-connection fixtures cover ordering, failure, generation
revocation, stream ownership, legacy negotiation and startup cancellation.

## DTLS curve arithmetic security update — 2.6.2

`webrtc-dtls/` retains the published `webrtc-dtls` 0.10.0 source (MIT/Apache-2.0)
while updating its P-256/P-384 dependency chain to upstream RustCrypto 0.14,
`sec1` 0.8 and `crypto-bigint` >=0.7.6 (currently locked to 0.7.7).
This removes RUSTSEC-2026-0387, including in Android's JNI library.
The companion `ctutils` dependency is locked to the fixed 0.4.5 release.

The source adjustments use the upstream `Sec1Point` name and fallible
OS-backed `Generate::try_generate` API, and import the already-used
`subtle::ConstantTimeEq` directly. No local big-integer or curve implementation
is introduced. DTLS record protection, cipher suites, protocol versions,
certificate verification and the RTP/QUIC packet pipeline are unchanged.
Precomputed curve tables remain enabled for handshake performance.

`UPSTREAM.json` records the original registry checksum, source revision and
normalized file hashes. `scripts/check-crypto-dependencies.py` checks all
lockfiles and rejects unexpected changes outside the explicit patch/test files.
Tests exercise P-256/P-384 agreement against ring, malformed SEC1 points,
retransmission consistency and the upstream DTLS handshake suite.
Run `cargo test --manifest-path vendor/webrtc-dtls/Cargo.toml --locked --lib`.
