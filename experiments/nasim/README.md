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

The panel exposes an explicit **Receive events** action per signed-in Nasim account. This does not place or answer calls. A `cleanSession` notice now raises a private `streamReset` event and keeps the live stream open, matching the official worker. The new [account-owned call controller](call-controller.md) invalidates active/pending calls on that event while leaving idle reception open; it is now attached to the local two-account call panel. The public stream state reports `historyGaps` and `awaitingFreshEvent`; it does not claim that chat history was synchronized. No history is downloaded.

`scripts/test-nasim-official-sse.cjs` executes the pinned, unmodified official SSE worker and crypto worker in Chrome with an in-memory fixture stream and blocked external networking. It verifies that a fresh encrypted call event follows `cleanSession` without disconnecting. Set `BALEVPN_NASIM_SSE_WORKER`, `BALEVPN_NASIM_WORKER` and the Playwright/browser paths before running it. This is offline parser/lifecycle interoperability, not a real service or network-stream test. The older signaling evidence file describes the previous milestone; see `stream-recovery-evidence-2026-11-02.json` for the correction.

The Rust `lktunnel::carrier` API prepares mutually authenticated QUIC over externally supplied media channels. It rejects plaintext frames, bounds queues and closes the tunnel when the media owner disappears. The experimental `lktunnel::peer_media::RelayMedia` now supplies a native one-peer DTLS/SRTP carrier with mandatory TURN/UDP and no host/STUN fallback. See [native media](native-media.md) for its API, security boundaries and local-network tests, and [private bridge protocol](native-bridge-protocol.md) for the pipe-controlled executable and parent manager. Two normal Windows helper processes negotiated through local TURN and reached authenticated QUIC proxy readiness; their ordinary SSRF protection remained enabled. The existing Bale connection path is unchanged. The [local paired call panel](../../docs/nasim-call-lab-fa.md) now connects admission, the account event stream and the private native manager, with explicit approval controls. Its browser/HTTP flow is fixture-tested. Actual provider TURN validation, real account testing, remote trust distribution and main-product integration remain outstanding.

### Terminal ICE diagnostics (2026-11-04)

The earlier [live trial](live-media-evidence-2026-11-04.json) completed signaling but failed ICE. The helper now captures eight measured counts at media failure or connection timeout: local/remote relay candidates, pairs waiting/in progress/failed/succeeded/unspecified, and nominated pairs. It does not add ongoing polling. Collection has a 250 ms deadline; unavailable samples are omitted without replacing the original failure reason. Only bounded numbers reach the account terminal snapshot; no candidate IDs, IP addresses, credentials, SDP or raw stats do.

The four request/response fields are explicitly `null`. Pinned `webrtc-ice` 0.11 leaves them at default zero even for a successful local TURN connection, so presenting those zeros as measured packet absence would be misleading. The strict IPC schema rejects numeric values for these unsupported fields.

The actual local TURN/two-peer fixture verified a gathered local relay before remote SDP, both relay counts after negotiation, and a successful nominated pair; its existing authenticated QUIC transfer also passed. The 250 ms cancellation test and 63 Node tests passed, including all three Nasim native helper checks. Six Eitaa/Rubika executable checks were skipped. See [evidence and private helper path](ice-diagnostics-evidence-2026-11-04.json). This is diagnostic preparation, not a fix or a new live Nasim test; relay-only restrictions remain enforced.

### Preserving future call cleanup context

The laboratory now seals a minimal cleanup intent when a matching call config
arrives, before it proceeds with media configuration or SDP. The separate vault
purpose contains the call UUID, peer/self IDs, local device ID, a hashed account
binding and capture time; it contains no token, SDP or TURN credentials. Readback
must succeed before the call continues. An ICE failure or reset preserves this
record, and another call is blocked until cleanup is acknowledged. Old calls
whose UUIDs were already discarded cannot be reconstructed by this change.

Restoring or checking an intent sends no network request. The existing private
laboratory API adds the explicit action
`POST /api/nasim/media/cleanup` with `{"slot":1}` or `{"slot":2}`, protected by
the same local authorization and origin checks. It reconnects that account's
event subscription if needed and sends one `bye` for the exact saved call/peer.
It does not dial. `cleanupStored` and `call.cleanup` expose only availability,
busy and save-failure flags. The action is not performed automatically on start.
Cleanup needs authenticated signaling only; it remains available when no native
media helper executable is configured, including after a restart. A focused
HTTP regression separately verifies that this action sends only the saved-call
`bye`, clears its intent on acknowledgement and does not start media.

An intent is cleared only after the validated peer terminal event for that call,
or a decrypted `status: success` reply to the exact in-flight `bye` operation
with unchanged account/device/connection binding. Generic acknowledgements,
timeouts, changed accounts and wrong-call replies do not clear it. Successful
cleanup reports `serviceAcknowledged: true` and **still reports
`remoteEndedVerified: false`**: service acceptance does not prove the other
device received the event. Explicit pair-end attempts to terminate both local
account calls instead of discarding the second account's cleanup context.

The intent does not expire merely because time passed. A changed account token
or device binding requires separate reconciliation; it is not silently applied
to another session. Disk-save failure keeps the call blocked. These paths and
encrypted-vault separation passed 77 offline tests; no live cleanup or new
provider call was performed. See [cleanup implementation evidence](cleanup-intent-evidence-2026-11-04.json).
