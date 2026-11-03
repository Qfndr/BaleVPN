# Private native media bridge, protocol 2

`examples/nasim_relay_bridge.rs` is an experimental helper for two compatible
native tunnel endpoints. It is not a login client or a finished VPN application.
It does not place, accept or authorize a messenger call. The existing iGap
protocol 1 helper and production Bale transport are unchanged.

`NativeMediaBridge` in `native-media-bridge.cjs` owns the hidden child process.
It passes no command arguments and uses no shell. TURN configuration, peer
certificates, SDP and ICE candidates cross private pipes only. **stdout is a
private control channel, not a diagnostic log or an HTTP response.** In
particular, `description` replies contain sensitive SDP/ICE credentials. They
are delivered to the awaited signaling operation and are excluded from `state`.

The helper generates a fresh native identity for each run and sends a
`prepared` event with `protocol: 2`, `provider: nasim` and its public certificate.
Private keys remain in the native process. The parent obtains both public
certificates before configuring mutually trusted peers. This temporary local
pairing is not a cross-device trust-distribution system; that still needs to be
bound to approved accounts in the future call controller.

Commands are newline-delimited JSON, bounded to 192 KiB, with at most four
queued inputs. Unknown keys and commands are rejected. No account token is
accepted by this helper. A private `configure` command supplies `provider`,
client/server `role`, `trustedCertificates`, `socksPort`, `throughput` and bounded
`iceServers`. Each relay entry has `urls` (an array), `username` and `credential`.
Only authenticated TURN/UDP is supported by the media driver; there is no
plaintext, STUN/host or direct-VPS fallback. The controller must obtain and
validate these relays from an authenticated provider call; a `nasim` label in
this protocol does not prove their ownership or billing classification.

After `configured`, the offerer sends `offer`; the peer sends `answer` with the
private offer description, then the offerer sends `setAnswer` with the returned
answer. Each negotiation waits for its private reply. Gathered relay candidates
are embedded in SDP; `candidate` also admits later relay ICE. There is only one
pending parent operation at a time. Server/client tunnel role is independent
of which endpoint sends the SDP offer. Parent call logic must explicitly bind
the participants, call UUID and sender device before forwarding these messages.

`connected` means media and a nominated relay pair, not an authenticated proxy.
`metrics` reports actual core counters, authentication and proxy readiness.
The SOCKS listener binds loopback only. Public state contains whitelisted
numeric data, fixed error codes, and booleans; private relay/SDP material and raw
stderr never appear. `providerPathVerified`, `billingVerified` and
`internationalOutageVerified` remain false. Ordinary WebRTC/QUIC connection
readiness cannot establish those properties.

EOF and the exact `stop` command cancel setup or negotiation and tear down
media, QUIC and proxy resources. Configuration has a 60-second deadline, media
connection a 45-second deadline, and the parent bounds each negotiation to
20 seconds. The core separately bounds ICE gathering to ten seconds. The
parent forcibly terminates a helper that fails to stop. Key logging and TLS
verification bypass are refused; raw panic/network error text is not emitted.

Terminal media errors may additionally use the fixed reasons `ice_failed`,
`dtls_failed`, and `relay_route_failed`. The first reflects an observed failed
or disconnected ICE state, the second an observed failed DTLS state, and the
third a rejected nominated relay/relay route check. These describe the observed
stage, not the network's root cause. Waiting, intentional closure, and an unknown
QUIC disconnect retain the existing generic reason; a timeout alone is not
labelled an ICE or DTLS failure. No candidate IDs, addresses, SDP, usernames,
passwords, or raw library errors are added to the IPC protocol.
No global logger is installed in the helper.

Build and verify from `lktunnel-rust`:

```powershell
cargo build --release --locked -p lktunnel --example nasim_relay_bridge
$env:BALEVPN_NASIM_BRIDGE = (Resolve-Path target/release/examples/nasim_relay_bridge.exe).Path
cargo test --release --locked -p lktunnel --example nasim_relay_bridge -- --include-ignored
cd ..
node --test scripts/test-nasim-native.cjs
```

The opt-in process test starts two **normal built executables**, not test
binaries, and a real loopback TURN server. It verifies private SDP negotiation,
mutual QUIC proxy readiness, normal shutdown and rejection of a loopback SOCKS
target with the production SSRF guard still enabled. Node tests also exercise
actual executable startup, fresh identities, malformed/oversized input,
argument/key-log refusal and cancellation during pending relay gathering.
Fixture-only tests cover private reply handling and public state redaction.
Set `BALEVPN_NASIM_BRIDGE` when running them; otherwise three native-process
Node tests skip and the Rust cross-process test remains ignored unless opted in.

The recorded Windows run passed all four Rust example tests with the process
test explicitly enabled, and all 101 Node tests with both native helpers set.
After the final build, all ten Nasim bridge Node tests passed again; the gather
cancellation test first observed a TURN packet at a local UDP socket and then
stopped the helper while that socket deliberately withheld its reply. The
delivered executable also passed the four Rust tests. See
[bridge evidence](native-bridge-evidence-2026-11-02.json) for its SHA-256 and the
remaining provider, performance, billing and outage gates.

Linux source build:

```bash
cd lktunnel-rust
cargo build --release --locked -p lktunnel --example nasim_relay_bridge
export BALEVPN_NASIM_BRIDGE="$PWD/target/release/examples/nasim_relay_bridge"
cargo test --release --locked -p lktunnel --example nasim_relay_bridge -- --include-ignored
cd ..
node --test scripts/test-nasim-native.cjs
```

The [account-owned call controller](call-controller.md) now integrates this
manager; the local lab now exposes explicit controls for its two-account
flow, tested with injected provider/native fixtures. That evidence
must not be confused with the real helper/relay process tests above.

Windows execution has been tested. This Linux command is source-build guidance;
a Linux helper has not yet been built or executed here. No live provider login,
call, provider-selected relay, remote VPS, sustained-speed, tariff or outage
test is implied. The lab UI can now invoke the helper when an absolute
`--nasim-bridge` path is supplied; the main product does not enable it.
