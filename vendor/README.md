# LiveKit API compatibility patch

`livekit-api/` contains the published source of `livekit-api` 0.4.24 (Apache-2.0),
from https://github.com/livekit/rust-sdks at commit aec91c8e1b70614e7b254589c00aaba992c0a39f.
Only the published normalized `Cargo.toml` and `src/` are included.

There is one source change: `src/http_client.rs` exports `reqwest::Client` when
`signal-client-tokio` is enabled as well as when `services-tokio` is enabled.
The signal client's `region.rs` needs this type. Upstream's feature gate prevents
a signaling-only build, forcing consumers to enable server services, JWT, and
an unused RustCrypto RSA implementation with RUSTSEC-2023-0071.

The three transport-consuming workspace roots patch this crate to the same path.
The application enables only the signaling and rustls root-certificate features.
No crypto, HTTP, WebSocket, protocol, or certificate verification logic is changed.
Remove this patch when upgrading to an upstream release that supports this
feature combination, and rerun every workspace's tests and security audit.
