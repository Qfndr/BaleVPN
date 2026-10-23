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
- The Linux GTK3 GUI dependency chain still brings GLib 0.18 and older helper crates. RustSec informational warnings (including GLib VariantStrIter unsoundness, the older GUI dependency chain's rand warning, and unmaintained crates) remain visible; the application does not directly call VariantStrIter. These warnings are not suppressed or represented as fixed.
- Unit tests and CI builds do not replace a two-device test using actual Bale accounts, a physical Android device, or a review of Bale infrastructure. No third-party systems are penetration-tested by these checks.

## Secret scanning

Gitleaks 8.30.1 checks the tracked source snapshot. Its archive is verified against
the published SHA-256 checksum before execution in CI. `.gitleaks.toml` allows only
the published SDK's `vendor/livekit-api/src/test_token.txt` test fixture; this token
is not used by the application. Production paths remain covered by default rules.

The initial full-history scan reported 36 findings in historical extracted Bale
web assets and earlier implementations. Inspection identified public application
constants and PEM-format marker strings, rather than a confirmed leaked user
credential. The history has not been rewritten, and third-party keys were not
validated against external services.

## Verification results — 2026-10-23

The runtime changes at [6450ce2](https://github.com/Qfndr/BaleVPN/commit/6450ce252bcf416426a0ea97e01f1d8cef399c7c) passed the following checks:

- Linux: 157 Rust tests and four JavaScript security tests; Windows and both macOS architectures also passed their Rust and UI test suites.
- Desktop GUI and headless release builds on Linux, Windows, macOS Apple Silicon, and macOS Intel.
- Android release APK build, including the shared Rust JNI libraries.
- RustSec audit of all five lockfiles with no vulnerability advisories reported and no advisory ignores. The informational warnings described above remain.
- Gitleaks scan of the tracked source snapshot, with only the documented upstream JWT fixture excluded.
- Execution of the actual CI-built Windows headless binary: version 2.1.3, persisted-port startup, configuration-directory writes, defaults, response headers, and rejection of hostile Origin and Host values.

The final contacts-refresh URL correction was checked against the Axum route table, and all four JavaScript regression tests were rerun afterward. The final documentation download links were checked to resolve to this repository's releases.

CI evidence: [Rust tests and security checks](https://github.com/Qfndr/BaleVPN/actions/runs/39976123599), [desktop builds](https://github.com/Qfndr/BaleVPN/actions/runs/39976123656), [Android APK build](https://github.com/Qfndr/BaleVPN/actions/runs/39976123622).
