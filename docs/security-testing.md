# Security verification for 2.1.3

The automated checks cover local code and dependencies. They do not establish that the VPN is anonymous, authenticated end to end, or free of vulnerabilities.

## Reproducing the checks

```sh
cargo test --manifest-path lktunnel-rust/Cargo.toml --workspace --locked --release
cargo test --manifest-path lk-signaling-rust/Cargo.toml --workspace --locked --release
cargo test --manifest-path bale-signaling-rust/Cargo.toml --workspace --locked --release
cargo test --manifest-path bale-vpn-rust/Cargo.toml --locked --no-default-features
node --test scripts/test-ui-security.cjs

cargo install cargo-audit --locked --no-default-features
for workspace in lk-signaling-rust bale-signaling-rust lktunnel-rust bale-vpn-rust bale-vpn-android/rust; do
  cargo audit --file "$workspace/Cargo.lock" || exit 1
done
```

`.github/workflows/rust.yml` runs the Rust suites on Linux, Windows, and both macOS architectures, the JavaScript injection tests, and a RustSec audit of all five lockfiles. Android and desktop packaging run in their own workflows. The manual `Refresh security lockfiles` workflow produces updated lockfiles as reviewable artifacts without committing them automatically.

## Regression coverage

- Requests from hostile origins, opaque origins, other local ports, cross-site and same-site browser contexts, missing Host headers, and DNS-rebinding hostnames are denied by the actual Axum middleware.
- Malicious peer names and IDs remain inert in all four management lists, including inline event handler arguments.
- Loopback, LAN, cloud metadata, CGNAT, and IPv4-mapped private destinations are blocked by the egress policy. A QUIC integration test checks that the server refuses a real loopback connection.
- Real SOCKS5 traffic crosses two in-process QUIC peers and reaches a controlled echo server. The default listener address is checked, and switching to LAN binding requires an explicit API call.
- Credential writes replace an existing configuration on Windows, retain other settings, and refuse to overwrite a corrupt configuration. Unix checks also verify 0600 permissions and resistance to predictable temporary-file symlinks.
- Malformed protobuf length prefixes and varints, partial gRPC headers, unsupported compression flags, and invalid gRPC status values are rejected.

## Remaining limits

- Raw IP mode is not end-to-end encrypted against the SFU. QUIC uses self-signed certificates without peer identity verification; an active relay can impersonate peers. Use application TLS for confidentiality. The existing README describes this threat model.
- Android LAN sharing is an unauthenticated proxy on the local network when explicitly enabled. Enable it only on a trusted network.
- The Linux GTK3 GUI dependency chain still brings GLib 0.18 and older helper crates. RustSec informational warnings (including GLib VariantStrIter unsoundness and unmaintained crates) remain visible; the application does not directly call VariantStrIter. These warnings are not suppressed or represented as fixed.
- Unit tests and CI builds do not replace a two-device test using actual Bale accounts, a physical Android device, or a review of Bale infrastructure. No third-party systems are penetration-tested by these checks.
