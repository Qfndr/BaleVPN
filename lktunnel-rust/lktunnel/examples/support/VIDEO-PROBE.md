The `video_carrier_probe` example is an isolated experiment. It does not change
the application's audio carrier, codec negotiation, provider call flags, or
production tunnel defaults.

It sends synthetic black H.264 pictures with binary data in an unregistered SEI
message between two local WebRTC peers. Received complete access units must
exactly equal what was sent. A separate installed Chromium decoder checks an
actual received access unit and its pixels. The UUID is a public format marker,
not a secret or an authentication mechanism.

From the repository root, after setting `TEMP`, `TMP`, `TMPDIR`, `CARGO_HOME`,
`CARGO_TARGET_DIR`, and all browser/cache paths to the E-drive locations required
by `AGENTS.md`:

```powershell
cargo test --offline --manifest-path lktunnel-rust/Cargo.toml -p lktunnel --example video_carrier_probe
$env:VIDEO_PROBE_DECODE_SAMPLE='E:\CodexBuilds\BaleVPN\video-carrier\received-sei-black16.h264'
cargo run --offline --manifest-path lktunnel-rust/Cargo.toml -p lktunnel --example video_carrier_probe
node scripts/test-video-carrier-decoder.cjs $env:VIDEO_PROBE_DECODE_SAMPLE
```

The decoder script needs `BALEVPN_PLAYWRIGHT_MODULE` and
`BALEVPN_BROWSER_EXECUTABLE` pointing to already installed Playwright and
Chromium. It downloads nothing, serves only a loopback synthetic fixture, and
creates its temporary browser profile beneath `TEMP`.

SEI metadata can be removed by an intermediary while preserving normal video.
Local success does not prove forwarding by iGap, Eitaa, Nasim, Rubika or Bale,
nor greater speed, delivery reliability, or a ready end-to-end tunnel. Loss
currently discards the affected access unit; no retransmission, congestion
control or provider integration is claimed. Payload and parser budgets are local
experimental bounds, not protocol limits.
