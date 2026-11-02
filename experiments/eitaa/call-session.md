# Account-bound Eitaa call lifecycle

`call-session.cjs` now composes the private authenticated RPC client, validated
DH exchange and encrypted signaling into a two-party call controller. It is
still a private protocol component: it is not yet attached to the provider lab
buttons or a packaged Eitaa-specific media helper. Live service acceptance,
provider relay routing, tariffs and international-outage behavior remain
unverified. Production Bale and its packet path are unchanged.

## Account and call ownership

The constructor takes an Eitaa `AuthSession` and an explicit list of at most 32
allowed peer user IDs. Start requires a signed-in, self-confirmed account. It
pins that account's exact self ID, retained token and web identifier; every
operation checks that binding again. Logout, stop or token/device changes
invalidate the call instead of adopting another account's credentials. No OTP,
registration, token refresh, automatic dial or automatic accept is performed.
The existing retained-session format is reused without another login.

`start({pollInterval: 0})` starts explicit manual polling. An interval of
1,000–30,000 ms enables optional polling, with one queued poll at a time.
`updates.getState` establishes a fresh initial cursor; restoring missed call
history across a stopped controller is not implemented. Differences/slices are applied
in order, including call events alongside unrelated messages. Cursor regression
is rejected **before** performing call actions; cursor advancement happens only
after the complete call-event batch succeeds. Too-long history requires explicit
resynchronization; there is no silent cursor reset or message-history dump.
Unrelated account messages are not persisted or published by this component.

One call can be active per controller. Dial requires an allowed peer's exact
user ID and an access hash resolved **for that calling account**. A hash from
another account's self record must not be assumed interchangeable; the target
resolver/UI is still to be integrated. Call IDs, access hashes, participant IDs,
audio protocol/library compatibility and caller/callee roles are checked. Video
is unsupported. Other calls and unallowed callers cannot replace the active call
or trigger an acknowledgement. Retired call IDs are retained in a bounded set.

## Handshake and signaling

The outgoing side requests reviewed DH parameters, validates the safe group,
generates a native ephemeral key and sends its commitment. The incoming side
acknowledges only an allowed request, then waits for explicit `accept()`. It
generates its own ephemeral key and returns its public value. The caller derives
the shared key, confirms its public value/fingerprint and checks the confirmed
call identity and fingerprint. The callee verifies **both** the original
commitment and confirmed fingerprint before installing its signaling cipher.
The server's random field is structurally checked; private exponent entropy
comes from the independent native CSPRNG, not from trusting server random bytes.

The controller advertises the fixed relay-only request profile. That does not
verify the eventual nominated route: the media engine must still enforce its
relay policy and independent pinned QUIC authentication. Call signaling keys
are never treated as proof of the tunnel peer's independent identity.

Up to 16 early signaling packets / 128 KiB can wait for key confirmation. After
verification, they pass the existing authenticated decryption, replay window and
bounded JSON parser. A corrupt, replayed or invalid packet terminates the private
call state; it is not redelivered or retried. Call keys/cipher state and buffered
early packets are cleared on failure, explicit stop or end. Handshake progress
has a 60-second deadline. An uncertain RPC result is not retried automatically.

`hangUp()` requires a matching discarded-call event from the service reply before
reporting a confirmed end. `stop()` is local cancellation; it does not claim that
the service received a discard. Late replies cannot resurrect the canceled call.
The account session itself is preserved for explicit restart.

## Private media integration seam

`onSecure(context)` receives a direction, call ID, private service connection
records and a call-bound `send(signal)` function. `onSignal(signal, context)`
receives authenticated parsed JSON and the same kind of sender. `onEnd()` closes
owned media resources. Never expose connection credentials or signal content in
public state, diagnostics or plaintext storage.

Callback sends are serialized and snapshot their input. After a callback returns,
its sender uses the controller queue and still checks the exact original call and
cipher. It cannot send on a later call. Await the supplied `context.send()` inside
callbacks; awaiting the public queued `session.sendSignal()` from inside the same
callback would re-enter its own queue. Private callback work is limited to 20
seconds and canceled by stop, so a stalled media hook does not permanently hold
the call queue. The queue is limited to 32 jobs / 256 KiB, and external ingested
events are round-tripped through the bounded private TL codec before queuing.

The [separate media owner](native-media.md) now implements Eitaa relay/configuration
and normal-helper adaptation. A successful signaling handshake reports `keyNegotiated`, **not**
`mediaConnected`, `peerAuthenticated`, `proxyReady`, provider routing or billing.
Those fields remain false in this signaling-only state; consumers read the
separate media owner's role-specific readiness. The core public state contains no token, access hash, DH key, TURN
credential, SDP or raw error response.

## Verification

Twenty-one offline lifecycle tests cover both caller directions, actual native
DH/fingerprint agreement, encrypted bidirectional signaling, early messages,
participant/access-hash mismatches, replay/corruption, immutable account binding,
late replies, retired calls, malformed/oversized events, queue limits, explicit
end, callback cancellation/timeouts and optional polling with a fake clock. One
cross-component fixture uses the real `AuthSession`, `AccountClient` and
`CallClient` codecs over synthetic HTTP responses: a retained token/device is
confirmed and reused with no additional code request or sign-in.

The existing Rust native integration now runs the **actual call controllers**
inside its private Node fixture. Synthetic account RPC/events establish the call
keys; actual native offers/answers become encrypted setup/candidate messages,
pass through call-ID-bound delivery and become remote SDP. A real local TURN
server and native DTLS/SRTP/RTP + independently pinned QUIC then transfer/echo
262,144 bytes exactly. The TURN configuration is supplied separately by the local
Rust fixture; the synthetic call's example relay credentials are not a live Eitaa
configuration. This verifies composition, not a provider-carried route.

The complete Node regression passed 236 tests with zero failures/skips. All 59
Rust library tests passed with the opt-in local fixture enabled and none ignored.
Execution was on Windows. No real account, OTP, provider call, foreign relay,
operator billing measurement, Linux/macOS runtime or production UI change is
claimed by these results.

```powershell
node --test scripts/test-eitaa-call-session.cjs
$env:BALEVPN_EITAA_ADAPTER_NODE = (Get-Command node.exe).Source
cd lktunnel-rust
cargo build --offline --locked --release -p lktunnel --example eitaa_relay_bridge
$env:BALEVPN_EITAA_BRIDGE = (Resolve-Path target/release/examples/eitaa_relay_bridge.exe).Path
cargo test --offline --locked --release -p lktunnel --lib -- --include-ignored --test-threads=4
```
