# Eitaa-specific normal native helper and call/media owner

`eitaa_relay_bridge` is now a **normal executable**, not a test binary. Its
compile-time provider is Eitaa and its private IPC protocol is version 2. A
Nasim binary cannot act as this helper: the Node binding validates the prepared
provider before exposing its pairing identity, and each binary rejects another
provider in its configure command. Messenger tokens, OTPs and account API calls
never enter the native helper.

The implementation is shared with `nasim_relay_bridge` in
`lktunnel-rust/lktunnel/examples/support/relay_bridge.rs`. Each example fixes its
own provider; a control message cannot switch it. The Node IPC parser is shared
in `experiments/providers/relay-media-bridge.cjs` with separate provider-specific
wrappers. Existing Nasim restrictions and its safe-integer ID boundary are
retained; the Eitaa wrapper keeps exact positive signed-64-bit IDs as strings.
Production Bale and the Rust packet/carrier library code are unchanged. No new
dependency or alternate plaintext/direct transport is introduced.

## Call-bound relay configuration

`relay-config.cjs` projects authenticated private `phoneConnectionWebrtc` records
into TURN servers. Only records marked TURN are used. STUN-only and legacy UDP
reflector records are not a fallback. IPv4/IPv6 literals, port and credential
bounds are checked; hostnames, zone identifiers, duplicate relay IDs/targets,
control characters and empty credentials are rejected. At most four TURN
records are configured. Four fixtures match the pinned official pure `RQ`
projector after excluding its STUN entries. The official projector's P2P
permission is not copied into the native transport policy.

The candidate/relay configuration is private call material, not a field for
user-supplied URLs. Syntax validation does not prove relay ownership, domestic
routing or discounted billing. The local integration deliberately uses a
loopback TURN server; it is not a real Eitaa relay. Provider route verification
and tariff measurement remain separate requirements.

## Media lifecycle

`call-media.cjs` owns one native helper and attaches to the private
[`CallSession`](call-session.md) callbacks. Preparation creates an independent
public QUIC certificate; the counterpart certificate must be explicitly pinned
before configuring media. `onSecure` validates the call/self/peer context and
configures only that call's TURN records. The outgoing call side generates the
offer; this is independent of whether that account carries proxy-client or
proxy-server traffic. Native SDP passes through the bounded Eitaa
[`InitialSetup`/`Candidates` adapter](media-description.md) and encrypted signaling.
The incoming side creates an answer, and the caller applies it.

Setup and candidate messages may arrive in either order. After initial
negotiation, new relay candidates are validated and added once. Accumulation is
limited to eight candidate messages, 64 entries and 128 KiB. Another setup,
changed call context, host/reflexive candidate or unsupported profile fails
explicitly instead of renegotiating or downgrading silently. The profile is for
two compatible native single-audio endpoints; video/SCTP and general official
browser interoperability are not claimed. Failure/end closes the child process;
late preparation cannot resurrect an old owner.

The helper uses the existing relay-only DTLS/SRTP/RTP carrier, checks the typed
nominated relay pair and requires independently pinned mutual QUIC authentication.
The packet data path stays native; no per-packet JavaScript processing is added.
Throughput/balanced configuration is forwarded unchanged. No speed improvement
or live-provider benchmark is claimed by local correctness tests.

## Role-specific readiness

`proxyReady` in the core means the **client's local SOCKS proxy** has a usable
QUIC client. A server has a QUIC acceptor and no such local proxy, so its
`proxyReady` correctly remains false. Waiting for that flag on both roles made
the first real composed test stall even though mutual authentication succeeded.

The media owner now exposes `ready` for either role, `serverReady` for an
authenticated negotiated server, and `proxyReady` only for the proxy client.
Server readiness additionally requires the native connected phase, which follows
successful server-acceptor setup. The same role mistake was corrected in the
experimental Nasim call controller and its fixtures now model a server with
`proxyReady:false`. Neither controller treats a signaling key or open WebSocket
as data readiness. Public state excludes TURN secrets, SDP and private key
material; provider-route, billing and outage verification flags remain false.

The signaling controller's own state still describes signaling. Consumers must
read the media owner's readiness separately; it does not mutate account state.
An owner is single-use and generates a new identity when recreated. Persisted
pairing/account identity, reuse across reconnect, target resolution and the
lab/product UI still need integration before this is offered as an application
feature. The running lab was not restarted for this step.

## Verification and limits

* 260 provider Node tests pass with zero failures/skips, including both real
  normal helper executables, provider isolation, stop during gather and media
  lifecycle tests. Existing Nasim and other-provider regression is included.
* All 60 Rust library tests pass, including the explicit normal-helper integration
  and the earlier exact 262,144-byte local carrier echo.
* Both example suites pass four tests each, including real two-helper TURN/QUIC
  negotiation and protected SOCKS target handling: eight tests total, none ignored
  in the explicit configured run.
* The composed native test uses real Eitaa normal executables, call controllers,
  encrypted SDP delivery, local TURN, DTLS/SRTP/RTP, mutual QUIC and client SOCKS.
  Both roles become ready, while server proxy readiness stays false. A loopback
  proxy target is correctly refused; no SSRF exception is added.

Execution/build was Windows x64. The actual provider API/events in the native
fixture are synthetic; its TURN credentials are local test credentials. No
real login, Eitaa call, foreign provider relay, operator bill, outage test,
Linux/macOS runtime or new product binary/release is claimed. The existing 256
KiB echo proves the underlying carrier, not an external download through these
normal helpers.

From the `lktunnel-rust` directory, with a cached Rust toolchain:

```powershell
cargo build --offline --locked --release -p lktunnel --example eitaa_relay_bridge --example nasim_relay_bridge
$env:BALEVPN_EITAA_BRIDGE = (Resolve-Path target/release/examples/eitaa_relay_bridge.exe).Path
$env:BALEVPN_NASIM_BRIDGE = (Resolve-Path target/release/examples/nasim_relay_bridge.exe).Path
$env:BALEVPN_EITAA_ADAPTER_NODE = (Get-Command node.exe).Source
cargo test --offline --locked --release -p lktunnel --lib -- --include-ignored --test-threads=4
cargo test --offline --locked --release -p lktunnel --example eitaa_relay_bridge --example nasim_relay_bridge -- --include-ignored --test-threads=2
cd ..
node --test scripts/test-eitaa-native.cjs scripts/test-eitaa-call-media.cjs scripts/test-nasim-native.cjs scripts/test-nasim-call.cjs
# Offline official projector parity, using the already pinned dialogs source:
$env:BALEVPN_EITAA_CALL_UI = 'ABSOLUTE-PATH-TO-appDialogsManager-CtDWV_rQ.js'
node scripts/test-eitaa-official-relay-config.cjs
```
