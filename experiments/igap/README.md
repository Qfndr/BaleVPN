# iGap feasibility spike

This directory is experimental and is **not imported by the application**.
It does not add a selectable provider to BaleVPN. The separate loopback-only
[local login laboratory](../../docs/provider-local-login-fa.md) now implements
the current login flow; live account login and calls still need verification.

The current web client also uses LiveKit room RPCs. See
[current multi-provider findings](../../docs/messenger-providers-fa.md); the legacy
SDP codec below is not the sole/current call implementation.

Implemented:

- `auth-session.cjs`: independent two-account login state, resend cooldown,
  optional second password/profile completion, encrypted-channel login and
  saved-session restoration. Tested with protocol-shaped fixtures, not real OTPs.
  Session storage and the local UI live in `../providers`; no Bale data is read.
- `secure-connection.cjs`, `rpc-connection.cjs`: actual v3 connection securing and
  correlated encrypted requests. Key exchange and unauthenticated InfoConfig
  round-trip were tested against the real service; no login or call was made.
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
unverified. Incoming call handling is not implemented. The separate v3 connection module secures its own
WebSocket; it does not turn the legacy SDP codec into an authenticated provider.
Decoded SDP, tokens and ICE credentials are sensitive; do not log them.

Run from the repository root:

```powershell
node --test scripts/test-igap-signaling.cjs
node --test scripts/test-igap-current.cjs scripts/test-igap-rpc.cjs
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
