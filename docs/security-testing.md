# Security verification

The 2.2 desktop/headless development path uses mutual TLS 1.3 with persisted
identities and trusted public certificates. See [secure setup](secure-pairing-fa.md).
The historical 2.1.3 results below are not evidence of a live 2.2 deployment.

New checks cover actual QUIC handshakes (paired, wrong server, unknown client,
and missing client certificate), real authenticated SOCKS5/TCP/QUIC transfer,
plaintext-token migration, protected storage tampering/context binding,
exclusive data-directory ownership, pairing persistence and malformed input,
call budgets, cooldown UI, diagnostic redaction, and desktop/mobile browser UI.
Recovery regression checks cover cleanup after the engine has already marked a
session disconnected, closing existing SOCKS sockets, reusing the proxy port,
cancellation-safe QUIC handshakes, concurrent recovery and initial warmup,
Windows network-down accept errors, and real authenticated transfers across
four calls on the same proxy port without restarting the process.
The release-mode offline transfer comparison reports throughput; it is not a
Bale internet-capacity benchmark or a zero-regression guarantee on every path.


The automated checks cover local code and dependencies. They do not establish that the VPN is anonymous, authenticated end to end, or free of vulnerabilities.

## Reproducing the checks

```sh
cargo test --manifest-path lktunnel-rust/Cargo.toml --workspace --locked --release
cargo test --manifest-path lk-signaling-rust/Cargo.toml --workspace --locked --release
cargo test --manifest-path bale-signaling-rust/Cargo.toml --workspace --locked --release
cargo test --manifest-path bale-vpn-rust/Cargo.toml --locked --no-default-features
python scripts/test-production-transport.py -- --nocapture
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
- Credential writes create missing configuration directories, replace an existing configuration on Windows, retain other settings, and refuse to overwrite a corrupt configuration. Unix checks also verify 0700 permissions on newly created directories, 0600 on files, and resistance to predictable temporary-file symlinks.
- Malformed protobuf length prefixes and varints, partial gRPC headers, unsupported compression flags, and invalid gRPC status values are rejected.

Desktop packaging also runs `python scripts/smoke-desktop.py PATH_TO_BINARY`
against both staged GUI and headless executables before uploading artifacts.
Each run starts with a missing configuration directory, selects each role via
the same HTTP endpoint as the UI, saves settings twice, and restarts the process
to verify persistence. It also checks invalid-phone rejection and the Origin
guard. It does not request a live OTP or establish an account-to-account tunnel.

## Remaining limits

- Raw IP, older releases and explicit legacy compatibility retain the unauthenticated threat model. Authenticated 2.2 desktop SOCKS5 rejects unpaired peers and disables the raw-IP bypass. The exit server, compromised endpoints, metadata and stored-key access remain outside the tunnel encryption guarantee. Use application TLS for the destination leg.
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


## In-app account controls — 2.5.0

The local profile gateway is restricted to subprocesses owned by the current controller, checks each process PID and uses an explicit HTTP method/path allowlist. Requests cannot choose a destination host, follow redirects, inherit ambient proxy settings, forward arbitrary cookies/headers, invoke shutdown or recursively manage workers. Request/response sizes are bounded. The existing loopback Host, Origin and Sec-Fetch-Site guard also protects these routes. Only owned profile HTML permits same-origin framing; the root workspace retains DENY and frame-ancestors none.

Account login transactions, tokens and private identities remain separate. Parent summaries contain only readiness, role and display name. Browser storage contains appearance and per-profile non-sensitive peer/port selections. Hidden account views suspend state polling. Data-plane encryption, buffers and transport settings are unchanged by this UI work.

Run `node scripts/test-ui-accounts-browser.cjs` with a local Playwright/browser installation for mock account-isolation and Persian UI checks. Run `python scripts/smoke-aggregate.py BINARY` for real owned-process identity, profile routing/Origin restrictions, adding a third account without disturbing existing keys and shutdown checks. These tests do not sign into live Bale accounts or measure internet speed.


## Encrypted session transfer and native shell — 2.6.0

The `.balevault` envelope uses AES-256-GCM and PBKDF2-HMAC-SHA256 with 600,000 rounds, a random 128-bit salt, random 96-bit nonce and a version-bound authenticated-data label. Passwords require at least 12 Unicode characters. Fixed KDF parameters, request/plaintext limits and one transfer job per process bound resource use. Decryption and key derivation run outside async runtime workers.

Archives contain existing tokens, original pairing identities and device identities, not platform master keys. Restore reencrypts each account for the destination OS and appends to unused local profiles; duplicate identities/sessions, existing directories and configured external paths are protected. No OTP endpoint or login creation is part of restore. Source profiles must be stopped for a consistent export. Device metadata is randomized for a fresh sign-in, stays stable through retries/restarts/transfer and is not an anonymity guarantee. Provider-expired/revoked tokens cannot be made valid by importing a file.

The native bridge checks the UI origin, bounds message sizes and accepts a fixed command set. Saving an archive receives only a validated encrypted envelope, writes outside the GUI thread, uses a generated filename in the configured export directory and refuses to overwrite existing files. It receives no password or plaintext token. Native menus do not disable pairing or call throttles. Closing to tray pauses UI work while keeping the existing transport alive. Headless builds do not depend on GTK or tray libraries.

Tests: `scripts/smoke-backup.py` exercises real single/group export, selective restore, preserved identities and tamper/password/Origin/running-profile guards. Rust tests verify exact token/key/device round trips, capacity/duplicate/external-path protection and optional cross-OS fixtures. `scripts/smoke-native-windows.py` uses a dedicated WebView2 debugging endpoint and temporary data to verify the real native titlebar, absence of a console, tray visibility, hide/show, settings and encrypted-file saving. `scripts/smoke-native-linux.py` exercises GTK/WebKit lifecycle in an isolated X11 display. Actual live Bale acceptance and internet speed are separate from these local fixtures.
