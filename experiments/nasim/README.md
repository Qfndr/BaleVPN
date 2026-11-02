# Nasim Rezvan experimental connector

This code is used only by the independent loopback provider laboratory. It is
not imported by the production application and does not enable a Nasim tunnel.
See [the local panel guide](../../docs/provider-local-login-fa.md) and
[the pinned source evidence](auth-evidence-2026-11-02.json).

- `msgpack.cjs`: bounded, non-extension MessagePack authentication payloads;
  string-only safe map keys, exact BigInt IDs, invalid UTF-8/duplicates rejected.
  Large JS Numbers use float64 to match the current official msgpackr encoder;
  64-bit integer payloads remain BigInt.
- `wire.cjs`: the observed AES-128-GCM service framing using Node crypto.
  Service key derivation is required for compatibility; it is not independent
  end-to-end tunnel protection. HTTPS validation remains mandatory.
- `http-client.cjs`: fixed endpoint/path allow-lists, no redirects, bounded
  responses, one outstanding request per account, cancellation without retries,
  fixed public errors. Explicit logout follows the legacy official PUT route
  and its JSON/AES-CBC acknowledgment format.
- `sse-parser.cjs`, `signaling-connection.cjs`, `call-codec.cjs`: bounded
  encrypted SSE events and the separate v2.5 encrypted JSON call API. Only
  approved provider HTTPS destinations receive headers. Complete frames,
  account cancellation, replay cursors and private relay/SDP handling are
  covered by fixtures. No automatic answering/retry/history download.
- `auth-session.cjs`: distinct device/account state, OTP, optional second
  password, one device registration, explicit naming for new users, encrypted
  vault export and restore without OTP or another device registration.

The restore read confirms token acceptance by the protected status endpoint;
its `active` field describes the cross-messenger feature, not account validity.
If the response does not return self ID, `selfConfirmed` stays false. The original
identity remains the one in the authenticated vault record. A returned different
ID is rejected. Service expiry or revocation can still require a new login.

Offline interoperability passed with the pinned **official browser worker** in
both directions, including Unicode, numeric boundaries, exact uint64 IDs and
legacy CBC replies. No real phone, OTP or service call was involved. A separate
anonymous status read received HTTP 401: this is not an encrypted round-trip or
login proof. **Real login, SMS delivery, calls, media, billing, outage behavior
and production integration remain unverified.**

```powershell
node --test scripts/test-nasim-wire.cjs scripts/test-nasim-http.cjs scripts/test-nasim-auth.cjs scripts/test-nasim-signaling.cjs
# Opt-in, read-only anonymous request. Does not request OTP:
node scripts/probe-nasim-public.cjs --connect
# Set BALEVPN_NASIM_WORKER to the downloaded pinned worker. Requires Playwright:
node scripts/test-nasim-official-worker.cjs
```

The official worker is not redistributed. Its source URL and SHA-256 are in the
evidence file. The worker test blocks external networking and uses fixture data.
The production Bale account folders, tokens and keys are never read or migrated.

The panel exposes an explicit **Receive events** action per signed-in Nasim account. This does not place or answer calls. A `cleanSession` notice now raises a private `streamReset` event and keeps the live stream open, matching the official worker. A future call controller must discard stale call state on that event. The public state reports `historyGaps` and `awaitingFreshEvent`; it does not claim that chat history was synchronized. No history is downloaded.

`scripts/test-nasim-official-sse.cjs` executes the pinned, unmodified official SSE worker and crypto worker in Chrome with an in-memory fixture stream and blocked external networking. It verifies that a fresh encrypted call event follows `cleanSession` without disconnecting. Set `BALEVPN_NASIM_SSE_WORKER`, `BALEVPN_NASIM_WORKER` and the Playwright/browser paths before running it. This is offline parser/lifecycle interoperability, not a real service or network-stream test. The older signaling evidence file describes the previous milestone; see `stream-recovery-evidence-2026-11-02.json` for the correction.

The Rust `lktunnel::carrier` API prepares mutually authenticated QUIC over externally supplied media channels. It rejects plaintext frames, bounds queues and closes the tunnel when the media owner disappears. The experimental `lktunnel::peer_media::RelayMedia` now supplies a native one-peer DTLS/SRTP carrier with mandatory TURN/UDP and no host/STUN fallback. See [native media](native-media.md) for its API, security boundaries and local-network tests. The existing Bale connection path is unchanged. A native pipe helper, call admission/controller integration, actual provider TURN validation, real account testing and production integration remain outstanding.
