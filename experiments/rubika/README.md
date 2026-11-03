# Rubika service-wire research

This is an isolated research component, not a supported tunnel in the product.
The Rubika lab tab now exposes two independent experimental login forms. No Bale/iGap/Nasim data,
device registrations, sessions or traffic paths are read or changed.

The current official HTML on 2026-11-03 still references
`main-es2015.6421623571994c9dd619.js`. The locally pinned bundle has SHA-256
`47b302b9166ed8c9138f9d959e9107c53dcb78c9447f8281715f657b68080acb`.
Its web client version is `4.4.34`, distinct from the previously inspected
Android APK version `4.1.1`. Full third-party sources/APKs are not redistributed.

`wire.cjs` implements the observed JSON/AES-256-CBC service framing with Node
crypto, strict base64/UTF-8/padding checks and bounded payloads. Each temporary
32-character session uses cryptographic randomness. V6's character transform is
computed per account without the official single-account global memoization.
`public_key` wraps the public PEM using that transform. The server's auth reply
uses RSA-OAEP with the legacy SHA-1 parameter; authenticated requests sign the
base64 ciphertext string with RSA-SHA256. Account private keys never belong in
HTTP public state, logs, command arguments or an unencrypted session export.

The official web generator defaults to 1024-bit RSA. This research implementation
generates and accepts **2048-bit or stronger** keys and has no silent weak-key
fallback. Offline official crypto helpers accepted the stronger fixture key;
**the real server's acceptance of that size remains untested**. Service CBC's
fixed IV and legacy OAEP hash are compatibility behavior, not new end-to-end
tunnel protection. HTTPS validation stays mandatory; a future tunnel requires
its own authenticated encryption and approved peer identity.

`http-client.cjs` allows `sendCode`, `signIn`, `registerDevice`, `getUserInfo`,
`logout` and the seven private experimental call methods documented below.
It does not invoke them automatically. Anonymous `getDCs` discovery
is a separate version-4 plaintext request to a fixed HTTPS provider endpoint.
Every discovered API URL must be HTTPS under `iranlms.ir`, with no URL user info,
query, fragment, custom path or nonstandard port. Only validated URLs can receive
encrypted account requests. Redirects, automatic retries, raw service error
messages and automatic device re-registration are disabled. Requests are
account-local, serialized, time-bounded and cancelled on close. API successes
require a valid encrypted response; discovery is the explicit plaintext exception.

The login API uses digits-only international `phone_number`, `send_type: SMS`,
and optional `pass_key` for its password challenge. Sign-in additionally sends
the code hash, verification code and wrapped public key. Their HTTP shapes are
fixture-tested; **actual SMS delivery, international-number acceptance, second
password behavior, user registration and login are unverified**. This module
now provides an account-local auth state machine, sealed session storage and
restore, password challenge handling and two account forms in the local lab.
`auth-session.cjs` saves accepted credentials before device registration. Restore
validates the stored self user ID through a signed protected read without an OTP,
sign-in or automatic device registration. An uncertain registration is retained;
explicit registration recovery is available only after a service requirement.
Cancellation epochs and per-slot write queues prevent late operations from
reviving a closed account or overwriting a newer snapshot. Device metadata
identifies this desktop lab honestly; it does not impersonate a mobile phone.
See [the Persian walkthrough](../../docs/rubika-login-lab-fa.md).

Recorded evidence is in [auth-wire-evidence-2026-11-03.json](auth-wire-evidence-2026-11-03.json).
The opt-in anonymous discovery succeeded with one request, without a phone,
OTP, account token or registration. This proves neither authenticated encrypted
service round trips nor messenger calls, relay ownership, routing or tariffs.

```powershell
node --test scripts/test-rubika-wire.cjs scripts/test-rubika-http.cjs
# No connection unless explicitly opted in; never requests OTP:
node scripts/probe-rubika-public.cjs --connect
# Point to the previously downloaded, pinned official bundle; requires Playwright:
$env:BALEVPN_RUBIKA_WEB = "ABSOLUTE-PATH-TO-main-es2015.6421623571994c9dd619.js"
node scripts/test-rubika-official-wire.cjs
```

The offline official-code test loads the bundle as webpack factory definitions,
without executing its Angular entry/runtime, then invokes only the crypto
factories/helpers with fixture data in Chrome. External browser requests are
blocked. It verifies four CBC fixtures in both directions, RSA-OAEP auth in both
directions, identical RSA-SHA256 signatures, auth transform and public-key field.
No real account or service request is involved. The full Node regression suite
passed 146 tests without skips, including 25 Rubika wire/HTTP/auth tests.
The earlier browser suite passed with offline provider fixtures in FA/EN and widths
320–1440px. Real network login, SMS and calls are not included in those results.

## Private call RPC boundary

Bounded, nonexecuting inspection of the official Android 4.1.1 APK now links
`CallUtils` inputs to `NetworkHelperImpl`'s literal RPC names and typed output
models. The SHA-256-pinned observations and limitations are recorded in
[call-protocol-evidence-2026-11-03.json](call-protocol-evidence-2026-11-03.json).
This establishes compiled client behavior, not server acceptance of these
methods with our Web session. No raw APK or third-party source is committed.

`call-codec.cjs` validates only `requestCall`, `receivedCall`, `acceptCall`,
`discardCall`, **`sendSignalingData`**, `getSignalingData` and `callStarted`.
Calls require signed, encrypted account requests. Normal voice requests exclude
phone/SIP/call-out fields. Protocol layers and reviewed native library versions
must be supplied explicitly; no unverified layer defaults are invented. The
observed version list excludes Eitaa's `4.0.0`; Eitaa native media interoperability
must not be assumed. `PhoneCall.key` is converted to bytes by the Android client,
not base64-decoded like its signaling strings. It remains private service data,
not proof of provider-blind end-to-end security.

Opaque signaling has strict canonical outbound base64, bounded Android-compatible
inbound ASCII whitespace handling, and ordered bounded `data_list` decoding.
The 48 KiB payload/batch-byte and 256-entry bounds are **local safety policies**,
not measured provider limits. There is no automatic dialing, answering, polling,
retrying, native protocol negotiation or public call endpoint in this change.

```powershell
node --test scripts/test-rubika-wire.cjs scripts/test-rubika-http.cjs scripts/test-rubika-auth.cjs scripts/test-rubika-call.cjs
python scripts/test-dex-call-references.py
# Offline, explicit class selection; never installs or runs the APK:
python scripts/inspect-dex-call-references.py PATH-TO-OFFICIAL.apk --class-prefix 'Lir/aaap/messengercore/CallUtils;' --class-prefix 'Lir/aaap/messengercore/network/NetworkHelperImpl;' --output LOCAL-REFERENCES.json
```

The extractor is a bounded **linear reference reader**, not a decompiler or a
control/data-flow proof. It accepts standard DEX 035/037–040 with 112-byte headers;
DEX 041 containers and optimized/unknown instructions are refused. Synthetic tests
cover malformed tables, instructions, payload alignment, LEB128 and code bounds.

Voice-call media support remains a separate research task. The current main web
bundle does not establish an available voice-call implementation. No Rubika media
route, foreign-VPS transport, sustained throughput, billing discount or outage
behavior is claimed. Neither the live lab nor a production binary was restarted
or rebuilt for this private protocol change.

## Account-bound update reader

Further bounded APK inspection establishes an eighth private method, `getUpdate`:
`NotificationUtils.getUpdate` creates the fieldless `GetUpdateInput`, and
`NetworkHelperImpl.getUpdate` serializes it with the literal `getUpdate` method
and `GetUpdateOutput` type. `GetUpdateOutput.update_data` points to
`MessengerUpdateObject`. `CoreMainClassImpl.handleMessengerNotification` routes
its `call_updates` to the account's notification center and `call_signal_data`
to that account's call signal processor. `CallProxy` distinguishes New/Edit/Delete;
Edit and Delete are matched to the current call ID. These are compiled-client
observations; no server response has been obtained with a real account.

`call-client.cjs` now wraps the HTTP transport with a confirmed Rubika account.
Explicit `start()` verifies matching RSA keys of at least 2048 bits and discovers
the provider API. Each operation rechecks the exact self ID and retained auth/key
binding, including after awaited network I/O. Close cancels the owned transport;
late replies cannot establish readiness. It neither signs in nor registers a
device, and never stops the owning auth session. Concurrent calls are refused,
input objects are snapshotted, and service failures never trigger retries.

`call-updates.cjs` projects only bounded call fields. It requires the exact self
`user_guid` in `getUpdate.update_data` as a **local fail-closed policy**; that
field's presence in every live response is not yet verified. Per-call replies
must match the requested call ID and any nested PhoneCall ID. Partial Edit and
Delete records stay partial, not fabricated full snapshots. This reader does not
merge edits or infer caller/receiver roles. The private controller below now
merges edits under explicit local policy.
Java long connection IDs are preserved as exact decimal strings, with unsafe
numeric JSON representations rejected. Endpoint syntax is checked without
connecting to an address. Tg/WebRTC is preserved as a type, not treated as proof
of a provider relay route. Unrelated chat/message data is discarded.

The returned call key, TURN credentials and signaling buffers are **private**;
only safe readiness/error metadata belongs in UI state. `ready` means transport
prepared, **never an established call or proxy**. `mediaReady` remains false.
Raw base64-decoded signaling still needs the correct native protocol/decryption;
this does not make it safe to interpret as plaintext SDP or Eitaa signaling.

```powershell
node --test scripts/test-rubika-call-client.cjs
```

Account-bound reader milestone: **296 provider Node tests passed, 0 failed, 0 skipped**,
including 48 Rubika tests. Its 17 tests cover account isolation, account/key
changes, late completion, cancellation, mutation during pending I/O, update/self
and nested call-ID mismatches, partial updates, exact numeric IDs, bounded signal
batches, private error redaction and the real HTTP crypto pipeline against an
offline service fixture. No real account, live call or tariff test is included.

## Private single-call controller

`call-session.cjs` now owns one call per confirmed Rubika account. It requires
an explicit reviewed protocol profile and a peer allow-list. There is no assumed
layer default, native `9.0.0` media implementation or production call button.
Explicit `start`, `dial`, `pollOnce`, `acknowledge`, `accept`, and `hangup` actions
use the account-bound client; a receipt does not accept a call. Polling is manual,
with no periodic API traffic, automatic answering or redial. A 250 ms local timer
checks cancellation/account binding and the 60-second pending-call deadline; it
does not send network requests. No `callStarted` is sent without a media engine.

The controller only admits a New Requested **voice** event with an allowed
`object_guid`. For this local profile the event's object GUID must equal the
selected peer, and any participant GUID must be that peer or self. These are
explicit admission rules requiring live verification, not an inference of native
caller/receiver identity or cryptographic peer authentication. Other call IDs,
retired calls, unapproved peers and unsupported incoming Video/CallOut are ignored.
The typed reader preserves those declared call types so an unrelated video call
does not terminate voice-call monitoring.

Local timestamp policy treats update timestamps as Unix seconds, allowing 30
seconds forward clock skew and a 120-second New-event window. Clock semantics
and compatibility are **not yet live verified**. Only named `updated_parameters`
are merged for Edit. Per-field timestamps preserve newer values; state transitions
remain monotonic, including forward transitions with equal timestamps. An ambiguous
Edit stops this experimental controller rather than overwriting retained keys
with serializer defaults. Deletion at least as recent as the latest observed
update clears the call. Acceptance on another device ends an incoming local
ring unless local accept was explicitly requested.

Signals are opaque protocol bytes, bounded to 32 queued entries / 48 KiB total,
and isolated by call ID. Service-owned buffers are copied and wiped; queued data
is wiped on hangup, failure, timeout or close. `takeOpaqueSignals()` transfers
ownership only after service acceptance; its caller must wipe the returned bytes
after use. `sendOpaqueSignal` **does not encrypt**: its future media adapter must
provide the correct native ciphertext. Completed IDs are retained for this
controller's lifetime with a 128-call bound; reaching it requires a new explicit
controller, never silently evicting IDs and reaccepting an old call.

Public metadata contains no service keys, credentials or signal payloads.
`accepted` is service signaling state. `mediaReady`, `peerAuthenticated` and
`providerVerified` remain **false**, and there is no SOCKS listener or proxy-ready
state. The native signaling encryption/media adapter, live calls, path/billing
verification, lab UI integration and production integration remain unfinished.

```powershell
node --test scripts/test-rubika-call-session.cjs
```

Current full provider regression: **316 Node tests passed, 0 failed, 0 skipped**,
including 68 Rubika tests. The 20 controller tests cover incoming/manual acceptance,
outgoing calls, stale/equal-time/out-of-order updates, receipt versus acceptance,
cross-peer/call isolation, retired calls, timeout, cancellation, bounded private
signal queues and the complete offline lifecycle through the actual signed HTTP
client and service encryption. No new live account request or lab restart occurred.
