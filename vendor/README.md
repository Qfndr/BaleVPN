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
`sec1` 0.8 and `crypto-bigint` >=0.7.10 (currently locked to 0.7.10).
This removes RUSTSEC-2026-0387, including in Android's JNI library.
The companion `ctutils` dependency is locked to 0.4.8.

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

The local DTLS state snapshot uses a private codec in `src/state_codec.rs`.
It preserves the fixed-width little-endian format previously emitted by
`bincode 1.3`, including trailing-byte tolerance on read. The parsed snapshot
is limited to 16 MiB and 4096 certificates. Snapshots exceeding those limits
are rejected. The codec is separate from DTLS packet handling.

The vendored crate's development-only Clap 3 dependency enables `std` and
`suggestions` explicitly instead of its default terminal-color feature. That
removes the unsound, unmaintained `atty` dependency from the standalone test and
example graph. Example CLI parsing remains available; automatic help coloring
is disabled. `tests/cli_compatibility.rs` exercises the exposed PSK and
certificate example endpoint flags, required arguments, help output and errors.
The packaged upstream example programs also reference an absent upstream
`hub` helper, so this test covers their CLI definitions independently. Runtime
DTLS dependencies and protocol behavior are unchanged.

### PHF generator 0.8.0

The desktop GTK dependency graph uses this crate to generate static lookup
tables at build time. Its fixed-seed generator now calls the same PCG algorithms
directly through `rand_pcg 0.2.1` and `rand_core 0.5.1`, removing the
`rand 0.7.3` dependency affected by RUSTSEC-2026-0097. The key stream, table
layout and library API are preserved. This patch does not supply randomness
for any runtime cryptography.

`phf_generator/UPSTREAM.json` identifies the exact registry archive, source
revision and license. The vendored package contains the upstream library only.
The upstream benchmark and benchmark-data generator are excluded.
