# iGap feasibility spike

This directory is experimental and is **not imported by the application**.
It does not add iGap login or a selectable provider to BaleVPN.

Implemented:

- `signaling.cjs`: bounded encoding of documented actions 900–905 and decoding
  of responses 30900–30905. Preserves 64-bit peer IDs without JS number rounding,
  parses ICE configuration, rejects malformed messages and returns fixed errors.
- `capabilities()`: an explicitly unverified, redacted configuration summary.
- `../../lktunnel-rust/lktunnel/examples/igap_p2p_probe.rs`: two real local WebRTC
  peers, offer/answer negotiation, DTLS-SRTP, and binary RTP integrity checks in
  both directions, without LiveKit or any external ICE server.

The codec handles the **plaintext packet inside connection encryption**. Its
output must not be sent directly to the documented production WebSocket. iGap
connection securing, authentication, current-version compatibility, incoming
call handling and real relay behavior are not implemented or verified here.
Decoded SDP, tokens and ICE credentials are sensitive; do not log them.

Run from the repository root:

```powershell
node --test scripts/test-igap-signaling.cjs
# Optional: receive one public iGap greeting, no account or application payload:
node scripts/probe-igap-public.cjs --connect
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
