# Native iGap signaling adapter

The desktop application now uses this adapter for its independent iGap page
and `--provider igap` mode. See the [application guide](../docs/igap-production-backend-fa.md)
and [real application transfer evidence](../experiments/igap/production-app-evidence-2026-11-04.json).
The standalone endpoint below remains a separate diagnostic tool.

## Independent native endpoint (laboratory only)

The optional `media` feature builds `native_endpoint`, a single-account process
that can run independently on a client or a server. That diagnostic executable
is not packaged with the application. Build with `cargo build
--manifest-path igap-signaling-rust/Cargo.toml --locked --features media --example
native_endpoint` after setting `TEMP`, `TMP`, `TMPDIR`, `CARGO_HOME` and
`CARGO_TARGET_DIR` to task-specific locations on E: as required by `AGENTS.md`.

Launch only with `--control-stdin`. Exchange newline-delimited JSON through
private pipes; never put the saved session in command arguments, environment
variables or plaintext files. The process first emits `identity` with its fresh
public `certificate` (lowercase DER hex). A trusted controller exchanges the two
public certificates out of band, then sends:

```text
{"command":"configure","sessionRecord":<private retained iGap record>,"role":"client"|"server","expectedPeer":"<other account numeric ID>","trustedCertificates":["<other endpoint public certificate>"],"socksPort":1094,"throughput":true}
```

This placeholder is a protocol description, not executable JSON. Successful
session restoration emits `authenticated` without requesting an OTP or placing
a call. Send `{"command":"listen"}` to the server and wait for `listening`, then
send `{"command":"connect"}` to the client. The server admits only the configured
account, and QUIC requires the explicitly paired certificate in both directions.
`mediaConnected` reports media setup; use subsequent `metrics.peerAuthenticated`
and client `metrics.proxyReady` before transferring data. `proxyBound` contains
only the bound local port (useful when requesting port zero). The SOCKS listener
binds loopback. The endpoint supports one call, without automatic redial.

`{"command":"stop"}` or closing stdin disconnects media, attempts a bounded
call hangup and closes signaling while retaining the service login. Errors are
fixed reason codes; raw tokens, account IDs, URLs, SDP and server messages are
never forwarded. Input lines are capped at 64 KiB and queue depth four. A
missing explicit control flag causes no identity creation, stdin read or network
request. Identities are currently ephemeral, so each new process requires a new
public-certificate exchange; persistent encrypted identities remain host work.

This protocol does not itself provide a user-facing secure remote control
channel or encrypted session export. Use an authenticated private pipe/controller
and do not expose stdin control or the SOCKS listener publicly. A local successful
test is not proof of foreign-VPS routing, domestic traffic classification,
discounted operator billing or functionality during an international outage.

The endpoint's diagnostic `mediaEvent` exposes only fixed reasons and bounded
LiveKit leave enums. In `livekit-protocol` 0.7.7's primary schema
`protocol/protobufs/livekit_models.proto`, disconnect reason 14 is
`CONNECTION_TIMEOUT`. Room-level `mediaConnected` does not establish ICE/DTLS
success. `metrics.mediaDiagnostic` therefore reports fixed publisher/subscriber
peer-connection states, an offer-sent boolean and a bounded SDP error code:
0 none observed, 1 subscriber remote description, 2 subscriber local description,
3 publisher remote description, 4 offer parsing, 5 answer parsing. An
endpoint-only logger extracts these from the existing `lktunnel::rtc` state logs;
it never prints or stores raw log records, SDP, tokens, URLs or identifiers. This
does not alter shared media behavior or enable logs in the production Bale app.

This Rust workspace is connected to the **desktop/headless BaleVPN executable
and its iGap interface**, but not to mobile or multi-account workers. It implements the
existing `lk-signaling::Signaling` and `TunnelHooks` contracts, without importing
Bale signaling or modifying the application's existing credentials.

It ports the independently tested iGap v3 laboratory protocol: bounded protobuf
messages, pinned nested RSA key exchange, TLS-verified encrypted WebSocket RPC,
CBC/GCM connection encryption, explicit registration/OTP/password/profile flow,
exact retained-session restoration, call-only privacy read/write/readback, and
single-account incoming/outgoing LiveKit room lifecycle. Unsupported contact
operations return `NotSupported`; they never pretend a request succeeded.

## Integration API

- Construct `IgapSignaling::new(account_store, RegistrationProfile::Independent)`.
  Independent public AppID 67291 remains the default. The explicit
  `WebV3Compatibility` profile uses public AppID 1 and truthful lab metadata;
  the laboratory has verified that choice with real accounts. Imported legacy
  profiles are retained exactly. Selecting a profile never sends an OTP.
- `start(country_iso, national_digits, international_number, profile_choice)`
  makes one explicit registration request. `verify`, `password`, and
  `complete_profile` complete the transaction. `state` contains delivery method,
  code length, cooldown and stage, never OTPs, passwords or bearer tokens.
- `restore(SessionRecord)` or `Signaling::connect()` checks the retained
  session by authenticated login, without another registration or OTP request.
- `read_call_privacy` and `ensure_call_privacy_everyone` operate only on voice
  and video permissions and verify service readback. No privacy mutation occurs
  merely because the account is connected.
- Configure `set_allowed_peers` and an `IncomingHandler` before accepting calls.
  The default denies all incoming peers. Incoming handling is explicit and
  bounded; `Reject` sends leave, `SilentlyIgnore` makes no acceptance request.
- Resolve opaque peer handles through this account's `resolve_peer`; handles
  from another account instance cannot authorize a call. `place_call` returns
  exactly one `TransportSession`; `accepted_sessions` has one consumer.
- `hang_up` ends the active call. `disconnect` tears down local transport while
  retaining the stored session. `sign_out` clears local credentials and store;
  it does **not** claim service-side session revocation. Explicit `logout`
  performs service revocation first and clears local credentials only on a
  confirmed reply.

The caller follows the observed official peer-call flow: create/offer, then a
token-bearing service push. Tokens must bind the exact self/room, permit room
join and have a usable expiry. The correlated receiver join tolerates a
roomless self-leave only while that same join is pending; peer departures,
timeouts, invalid credentials and account changes still cancel it. The channel
stays open during active calls; `activate`/`deactivate` do not send Bale RPCs.
The fixed transport endpoint is `wss://call.igap.net/`. LiveKit verifies JWT
signatures; decoding claims here only binds authenticated context.

## Storage and security boundaries

The caller must supply an **account-specific encrypted `TokenStore`**. This crate
does not write plaintext session files or migrate Bale account directories.
`SessionRecord` is secret-bearing despite its redacted `Debug`; encrypt it
before export or transfer. Its token and pending login username zeroize on drop.
The inherited `TokenStore::save` API returns no result, so durable-save failure
reporting remains the host application's responsibility.

Internal network queues and pending RPCs are bounded (32 requests, 64 pushes),
with 10-second securing, 8-second RPC, 5-second write and 2-second close limits.
Incoming decisions time out after 20 seconds; outgoing acceptance after 35.
Dropping an outgoing future invalidates its local credential ownership.
The existing `lk-signaling` contract exposes unbounded event/accepted-session
receivers; its consumers must continuously drain them. This foundation currently
supports one active call per account and does not add a reconnect/redial loop.

No claim is made that local laboratory transport proves foreign-VPS routing,
carrier billing, regional outage survival, throughput improvement, mobile
compatibility, or immunity from provider account limits. These remain separate
integration and cross-host acceptance gates.

## Validation

Run from PowerShell with all generated files on E:

```powershell
$env:TEMP='E:\CodexTemp'; $env:TMP='E:\CodexTemp'; $env:TMPDIR='E:\CodexTemp'
$env:CARGO_HOME='E:\CodexBuilds\BaleVPN\cargo-linux'
$env:CARGO_TARGET_DIR='E:\CodexBuilds\BaleVPN\igap-native-target'
cargo test --manifest-path igap-signaling-rust/Cargo.toml --locked --offline
```

Tests use synthetic secrets and protocol fixtures only. Coverage includes exact
Node CBC/GCM vectors, RSA exchange, malformed/duplicate wire fields, auth-profile
preservation, cooldowns, privacy readback, one-time token ownership, caller and
receiver lifecycle, cross-account isolation, and concurrent/reset cancellation.

`public_probe` requires explicit `--connect` before its single anonymous config
RPC. `restore_probe` requires explicit `--restore-stdin` before reading stdin or
opening the network. It accepts at most 64 KiB of private `SessionRecord` JSON,
uses a zeroizing memory store, verifies the restored self identity internally,
and prints booleans only. It disconnects without logging out or signing out.
Use a private pipe for session JSON, never command arguments or environment
variables. Both probes perform no network action by default.

For a controlled timing comparison only, `native_endpoint --control-stdin
--defer-media` emits `transportSession` before starting media and then requires
the exact `{"command":"startMedia"}` control within 20 seconds. A two-process
controller can wait for both endpoints before starting them, without sharing
their private room tokens. `stop`, EOF, signaling failure or call termination
still closes the pending call. The default endpoint starts media immediately;
this diagnostic mode does not add latency to normal startup or establish VPS
readiness by itself.
