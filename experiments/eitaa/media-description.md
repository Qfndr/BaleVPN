# Eitaa single-audio native media adaptation

This private adapter connects Eitaa-shaped call descriptions to the existing
native one-audio WebRTC carrier. It does not log in, dial, answer a service call,
subscribe to events or expose a proxy in the product. Both endpoints of this
profile must be compatible native tunnel clients. Live provider routing,
throughput, tariffs and international-outage behavior remain unverified.

`media-description.cjs` converts a private native offer/answer into an
`InitialSetup` and bounded `Candidates` batches. The reverse conversion produces
SDP suitable for the existing relay-only engine. Native SDP and parsed ICE/DTLS
fields remain private; never return them through public HTTP state or logs.

The profile preserves SHA-256 DTLS fingerprints/roles, ICE credentials, Opus
48000/2, RTP extension IDs, codec parameters/feedback and the audio SSRC. The
native offer may list additional audio codecs; only the required Opus codec is
forwarded and negotiated. It does not silently project video, screencast,
SCTP/data channels or multiple media sections into the single-audio carrier.
Those unsupported profiles fail explicitly.

The official projector uses signed 32-bit strings for the SSRC. The adapter
normalizes high-bit native sources to that representation on the JSON wire and
restores the same unsigned RTP identity when building SDP. The official pure
parser/projector agrees on eight offer/answer fixtures, including
`0x7fffffff`, `0x80000000` and `0xffffffff`. Setup attributes are placed at media
level, as consumed by the official projector. The source is the same SHA-pinned
dialogs chunk recorded in [call-signaling.md](call-signaling.md); no UI entry,
imports, account storage or network are executed by that parity test.

Only UDP relay candidates for the negotiated audio context are admitted.
Host/reflexive candidates, TCP, DNS candidate addresses, mismatched MID/ufrag,
insecure SDP and ambiguous ICE/DTLS attributes are rejected. With `rtcp-mux`,
the native gather can also contain a separate RTCP component. Valid relay
component-2 entries are omitted; a component-1 relay is still mandatory, and a
non-relay component-2 entry does not bypass validation. Candidate messages are
batched in groups of 16, with a total cap of 64. Description size is capped at
65,535 bytes; control-character/parameter injection and unsupported codecs fail
before reaching the native engine.

Candidate syntax/type validation is **not** provider ownership, a public-IP
allow-list or billing verification. The local test intentionally uses a
loopback TURN server. A live call controller still needs to validate service
context and relay configuration, bind account/call IDs, assemble bounded
candidate events and apply the independent QUIC identity pin. The existing
carrier verifies the nominated pair through typed stats before becoming ready.

## Real native local integration

The opt-in Rust test `real_turn_dtls_rtp_quic_survives_eitaa_json_projection`
creates an actual local TURN server and two native DTLS/SRTP/RTP carriers with
independent pinned QUIC identities. Its private Node subprocess:

1. Establishes fixture account calls using the real private caller/callee
   controllers, DH validation and Eitaa signaling ciphers.
2. Projects the actual native offer into setup/candidate messages, encrypts and
   decrypts them in caller/callee roles, then reconstructs the remote offer.
3. Repeats the inverse direction for the actual answer.

The test then checks a relay-to-relay nominated route for both sides, performs
mutual QUIC authentication and transfers/echoes exactly **262,144 bytes** through
that real media path without changes. The proxy server is the offerer, showing
that signaling direction does not choose the client/server traffic role.
Carrier teardown clears readiness; private subprocess replies are bounded and
time-limited and the subprocess is reaped on drop. The test never sends an OTP
or a provider RPC, and no external destination or SSRF exception is enabled.

The current fixture composes the [call controllers](call-session.md) with the
carrier; its account RPC/events are synthetic and its TURN server is local.

This uses the actual carrier engine inside a Rust test, **not** a packaged
Eitaa-specific helper or a live Eitaa call. The production Bale path is unchanged;
the only Rust entry added is inside `cfg(test)`. Live account call control and
provider-specific bridge integration remain to be completed. Current test execution was on
Windows; Linux/macOS execution is not claimed.

```powershell
node --test scripts/test-eitaa-media-description.cjs
$env:BALEVPN_EITAA_CALL_UI = 'ABSOLUTE-PATH-TO-appDialogsManager-CtDWV_rQ.js'
node scripts/test-eitaa-official-media-description.cjs

$env:BALEVPN_EITAA_ADAPTER_NODE = (Get-Command node.exe).Source
cd lktunnel-rust
cargo test --release --locked -p lktunnel --lib real_turn_dtls_rtp_quic_survives_eitaa_json_projection -- --ignored
# Full core suite including this explicitly configured fixture:
cargo test --release --locked -p lktunnel --lib -- --include-ignored --test-threads=4
```

There are nine adapter tests and eight offline official projector fixtures.
The complete Node regression suite passed **206 tests** without skips. All
**59 Rust library tests** passed with the explicit local fixture enabled and
zero ignored tests. These results do not establish provider service acceptance,
real traffic discounts, account call limits or behavior during an outage.
