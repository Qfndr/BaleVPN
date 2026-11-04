# iGap feasibility spike

The JavaScript code in this directory remains experimental and is **not imported
by the application**. The application now uses the independent Rust iGap adapter
and provides its own [login, pairing and connection interface](../../docs/igap-production-backend-fa.md).
A real in-application client/server transfer passed payload hash checks; see
[production evidence](production-app-evidence-2026-11-04.json). Remote VPS,
long-running operation, video transport and billing remain unverified.
The separate [local login laboratory](../../docs/provider-local-login-fa.md)
is retained for protocol research. Older results below describe their own stage.

The current web client also uses LiveKit room RPCs. See
[current multi-provider findings](../../docs/messenger-providers-fa.md); the legacy
SDP codec below is not the sole/current call implementation.

Implemented:

- `auth-session.cjs`: independent two-account login state, resend cooldown,
  optional second password/profile completion, encrypted-channel login and
  saved-session restoration. Tested with protocol-shaped fixtures, not real OTPs.
  Session storage and the local UI live in `../providers`; no Bale data is read.
  The iGap-only registration selector defaults to the independent public AppID
  `67291`. The explicit `web-v3-compat` experiment uses public AppID `1`, as
  observed in the inspected current web protocol, while retaining the lab's
  own application/device metadata. This tests an interoperability difference;
  it does not prove independent IDs are invalid or guarantee SMS delivery.
  Selection applies only to the next admitted request, respects resend cooldown,
  never retries automatically, and does not rewrite existing sealed sessions.
  The public `registrationProfile` state reflects the account profile; an unsent
  UI selection survives polling and language changes. Service `deliveryMethod`
  hints distinguish SMS, existing-session delivery, both, and phone calls.
- `privacy.cjs`: call-only voice/video permissions with service readback. The
  current Web schema describes repeated nested rules in response field 4, while
  the live service also returns the original single-rule type 2 / level 3 shape
  defined in the [pinned official API](https://github.com/KianIranian-STDG/iGap-API/blob/2b1d7d9e27ddc81f7839ee300a2f2a06f4f805fe/app/assets/proto/UserPrivacyGetRule.proto).
  Both forms require an exact matching call type and valid level. Empty,
  conflicting and duplicate responses fail closed. Shape diagnostics contain
  bounded field numbers, wire types, lengths and fixed privacy enums only.
- `secure-connection.cjs`, `rpc-connection.cjs`: actual v3 connection securing and
  correlated encrypted requests. Key exchange and unauthenticated InfoConfig
  round-trip were tested against the real service; no login or call was made.
- `../providers/native-bridge.cjs`, `media-pair.cjs`, and the Rust
  `provider_bridge` example: optional two-process media trial with fresh
  reciprocal certificate pins, stdin-only credentials, loopback SOCKS and
  strict mutual authentication. Windows process tests passed; no real call,
  throughput, Linux execution, carrier-route or billing proof yet.
- `call-session.cjs`: account-bound create/offer/ring/join/leave, two-party
  admission, no automatic dialing, correlated credentials and late-response
  cancellation. Real service calls and actual media transport are unverified.
  The inspected Web peer-call flow joins the receiver explicitly and supplies
  the caller a token-bearing join push. Such caller pushes are admitted only
  on the pinned authenticated outgoing call, with the exact room and subject,
  join grant and usable expiry. The `video.room` / `video.roomJoin` layout is
  defined in [LiveKit's protocol grants](https://github.com/livekit/protocol/blob/main/auth/grants.go).
  These checks bind context; LiveKit verifies the token signature. Unknown
  iGap claim naming fails closed with boolean-only `joinPushDiagnostic` state.
  A repeated join control after accepted push does not send another join RPC.
- `room-signaling.cjs`: current room create/join/invite/leave codec, with
  account-specific LiveKit credential checks. Live room calls remain untested.
- `web-v3-schema.json`: factual call/auth field descriptors extracted from the
  public current web bundle, with source URL and SHA-256; not application code.

- `signaling.cjs`: bounded encoding of documented actions 900–905 and decoding
  of responses 30900–30905. Preserves 64-bit peer IDs without JS number rounding,
  parses ICE configuration, rejects malformed messages and returns fixed errors.
- `capabilities()`: an explicitly unverified, redacted configuration summary.
- `../../lktunnel-rust/lktunnel/examples/igap_p2p_probe.rs`: two real local WebRTC
  peers, offer/answer negotiation, DTLS-SRTP, and binary RTP integrity checks in
  both directions, without LiveKit or any external ICE server.

The codec handles the **plaintext packet inside connection encryption**. Its
output must not be sent directly to the documented production WebSocket. iGap
live authentication, incoming call handling and real relay behavior remain
unverified. The experimental `call-session.cjs` now handles admitted incoming offers and explicit ring/join/leave operations. The optional pipe-controlled native helper is now connected to the existing RTP/QUIC engine, but real iGap media forwarding is unverified. Caller-side duplicate join behavior still needs real-service verification; see `call-cycle-evidence-2026-11-02.json`. The separate v3 connection module secures its own
WebSocket; it does not turn the legacy SDP codec into an authenticated provider.
Decoded SDP, tokens and ICE credentials are sensitive; do not log them.

Run from the repository root:

```powershell
node --test scripts/test-igap-signaling.cjs
node --test scripts/test-igap-current.cjs scripts/test-igap-rpc.cjs scripts/test-igap-call.cjs
# Optional: receive one public iGap greeting, no account or application payload:
node scripts/probe-igap-public.cjs --connect
node scripts/probe-igap-secure.cjs --connect
node scripts/probe-igap-rpc.cjs --connect
cd lktunnel-rust
cargo run --release --locked -p lktunnel --example igap_p2p_probe
```

The carrier probe prints only counts and boolean results. It gathers host
candidates and connects two peers on this machine; it does not call iGap,
request OTP or load any account directory. It is an integrity experiment, **not
an Internet speed benchmark or evidence that iGap forwards these packets**.

See [the Persian research record](../../docs/igap-research-fa.md) for primary
sources, pinned source revisions, international-number observations and the
remaining integration gates.
