# Rubika service-wire research

Call privacy is isolated in `call-privacy.cjs` and `privacy-wire.cjs`. The explicit
read/allow operation uses the official `getPrivacySetting` and `setSetting`
methods, writes only `can_called_by: Everybody` plus removal of `CanCalled`
exception entries when needed, preserves non-call exception entries, and checks
the result with an independent read. Public results contain only the permission,
counts and verification booleans. Unrelated phone/profile/last-seen settings,
credentials and private exception GUIDs are not returned or rewritten. A close
or changed account aborts the operation without a late follow-up setter.

The pinned Web client's `handleCustomErrors` distinguishes
`ERROR_ACTION / INVALID_AUTH` (invalid session) from
`ERROR_GENERIC / INVALID_AUTH` (operation access denied). The transport now
preserves this distinction. A denied call does not by itself prove that the
whole session is revoked, or that changing privacy will permit Web calls.
See `call-privacy-evidence-2026-11-03.json` for the exact primary-source facts.
Live privacy reads/writes and a successful service call still need verification.

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

Controller milestone: **316 Node tests passed, 0 failed, 0 skipped**,
including 68 Rubika tests. The 20 controller tests cover incoming/manual acceptance,
outgoing calls, stale/equal-time/out-of-order updates, receipt versus acceptance,
cross-peer/call isolation, retired calls, timeout, cancellation, bounded private
signal queues and the complete offline lifecycle through the actual signed HTTP
client and service encryption. No new live account request or lab restart occurred.

## Native legacy signaling profile research

The bounded ELF reader now checks the SHA-pinned APK's x86-64 shared library
without loading it. [Recorded native observations](native-profile-evidence-2026-11-03.json)
contain function hashes and six selected symbols. The three
`GetConnectionMaxLayer` functions are exactly `mov eax, 92; ret`; the legacy
`InstanceV2_4_0_0Impl.GetVersions` function contains the literal writes for `6.0.0`.
That literal is not a full C++ data-flow proof. No whole source equivalence,
native execution, negotiated minimum layer or server acceptance is asserted.

For comparison, the pinned upstream [6.0.0 implementation](https://github.com/DrKLO/Telegram/blob/fb2e545101f41303f1e2712de2e7611a9335f1c3/TMessagesProj/jni/voip/tgcalls/v2_4_0_0/InstanceV2_4_0_0Impl.cpp)
uses the legacy raw signaling cipher, through
[SignalingEncryption](https://github.com/DrKLO/Telegram/blob/fb2e545101f41303f1e2712de2e7611a9335f1c3/TMessagesProj/jni/voip/tgcalls/v2/SignalingEncryption.cpp)
and [EncryptedConnection](https://github.com/DrKLO/Telegram/blob/fb2e545101f41303f1e2712de2e7611a9335f1c3/TMessagesProj/jni/voip/tgcalls/EncryptedConnection.cpp).
The inspected native class/symbols and literal support this compatibility
**hypothesis**, not a claim that Rubika's modified binary equals upstream.
Upstream source is linked for review, not copied into this MIT repository.

`legacy-signal-cipher.cjs` provides an independent experimental raw packet codec,
enabled only by explicit `libraryVersion: '6.0.0'` and `protocolLayer: 92`.
It never downgrades a newer profile. It requires an owned 256-byte nonzero key;
the optional `serviceKey()` conversion requires exactly 256 bytes of round-tripping
UTF-8, without guessing base64 or stretching a short key. Live key shape/encoding
is unverified, so an incompatible service key is refused.

This is compatibility keyed-hash/AES-CTR framing, **not new AEAD**, and the service
supplies the key. It cannot establish provider-blind peer authentication; a future
tunnel still requires independent pinned QUIC authentication/encryption. Raw
payloads are opaque bytes, not automatically trusted JSON/SDP. The codec uses a
64-counter replay window, strips the native receive sequence flag bits, rejects
zero counters, and stops outgoing counters before flag-bit exhaustion. Its local
payload bound leaves room for the 20-byte envelope within the existing 48 KiB
signaling limit. Close wipes retained key and replay state.

Six codec tests and eight malformed-ELF tests passed. The optional SHA-pinned
**official Eitaa legacy cipher** oracle produced six byte-identical packets and
bidirectional decryptions, plus masked-counter checks. That proves shared legacy
packet compatibility only: it does not execute or test a Rubika native call.
The legacy codec milestone passed **322 Node tests, 0 failures, 0 skips**,
including 74 Rubika tests. No account request, APK installation, lab restart,
production build, release or change to Bale's traffic path is part of this step.

```powershell
node --test scripts/test-rubika-legacy-signal.cjs
python scripts/test-rubika-native-profile.py
python scripts/inspect-rubika-native-profile.py PATH-TO-PINNED-APK --output LOCAL-NATIVE-PROFILE.json
# Optional offline oracle; source stays outside the repository:
$env:BALEVPN_EITAA_CALL_UI = 'ABSOLUTE-PATH-TO-appDialogsManager-CtDWV_rQ.js'
node scripts/test-rubika-official-legacy-signal.cjs
```

The local media components below now compose this profile with typed descriptions
and the relay-only helper. Account-controller wiring, actual Rubika interoperation,
provider route, billing, throughput and outage verification remain pending. The
presence of this codec does not enable a Rubika tunnel in the application.

## Local media/helper composition

`CallMedia` now requires the explicit 6.0.0/layer-92 profile and owns one independent
`rubika_relay_bridge` process. The shared legacy media owner is provider-bound by
factory; Eitaa keeps its exact numeric-ID policy, Rubika keeps opaque GUIDs, and
neither shares an auth session, key, worker or state with the other. The native
helper's provider identity is fixed at compilation and checked over hidden pipes;
an Eitaa/Nasim/Bale helper cannot supply Rubika pairing identity or readiness.

`relay-config.cjs` only projects credentialed `WebRTC` IP entries to TURN URLs.
It excludes Tg reflectors and accepts neither hostname guesses nor STUN/direct
fallback. The pure legacy JSON/single-audio SDP converter is shared with the
reviewed Eitaa converter; this reuse does **not** prove native Rubika compatibility.
Only negotiated relay media plus independently pinned QUIC authentication makes
the local proxy ready. Server readiness is separate from client SOCKS readiness.
Private SDP, TURN credentials and approved certificates stay outside public state.

The Windows helper was built offline from existing dependencies; artifacts and
test scratch were kept on E. The local fixture tests passed through the real
Rust media engine, real local TURN, DTLS/SRTP/RTP, authenticated QUIC and the Node
legacy encryption/description projection. **262,144 bytes echoed byte-for-byte**.
A second test used two normal Rubika helper executables and the actual Node
`CallMedia` owner; both selected relay routes and authenticated independent QUIC
identities, while the normal SOCKS listener retained its private-target denial.
Accepted-call contexts and signaling transport were synthetic, not provider RPC.

Local helper milestone: **340 provider Node tests passed, 0 failed, 0 skipped**,
including 92 Rubika tests; **62 Rust library tests and 4 Rubika helper tests passed,
0 failed, 0 ignored**. The unchanged Eitaa media path also passed its real normal
helper and 256 KiB projected-media regressions after the shared-owner extraction.
These results are Windows/local-network tests, not Linux packaging, live calls,
Internet throughput, operator routing, discounted billing or outage evidence.

```powershell
# From lktunnel-rust, with TEMP/TMP on the E drive:
cargo build --offline --locked --release -p lktunnel --example rubika_relay_bridge
$env:BALEVPN_RUBIKA_BRIDGE = 'ABSOLUTE-PATH-TO-rubika_relay_bridge.exe'
$env:BALEVPN_RUBIKA_ADAPTER_NODE = (Get-Command node).Source
cargo test --offline --locked --release -p lktunnel --lib rubika -- --include-ignored
cargo test --offline --locked --release -p lktunnel --example rubika_relay_bridge -- --include-ignored
# From repository root:
node --test scripts/test-rubika-native.cjs scripts/test-rubika-call-media.cjs
```

The fixture scripts have no provider socket, OTP or retained-account operation.
The deployed lab was not restarted and the main application's Bale traffic path
was not modified. The private handoff below now joins accepted-call control and
media, with live-account interoperation and UI integration still unverified.
No Rubika tunnel is advertised as live.

## Accepted-account media ownership

`CallSession.issueLegacyMedia()` now issues one nonserializable, single-consumer
handoff for an accepted call. Only an explicitly advertised 6.0.0 profile,
negotiated layer 92, the returned 6.0.0 capability, exact 256-byte service key
and valid WebRTC TURN entries qualify. The owned key copy is wiped after cipher
creation. Handoff methods are nonenumerable, so JSON logging produces `{}`.
This is a private API, never a session backup, HTTP response or public state.

The lease pins the account epoch, call ID and a revision of key/relay/protocol/
participant data. Ending the call, logout or relevant parameter changes revoke
it before another packet can be sent. Duration-only changes preserve it. Before
handoff, same-second state advancement may supply negotiated keys/relays;
after handoff, conflicting equal-timestamp security parameters abort rather than
leave stale material active. A second consumer is refused to avoid resetting a
signaling counter under the same call key.

`account-media.cjs` owns an exclusive CallSession/CallMedia pairing for one call:
prepare and approve independent peer certificates, attach the accepted call,
poll/update and drain its bounded private queue, and hang up or cancel. Its
caller must not concurrently operate the underlying CallSession. JSON setup/
candidates are validated, encrypted with the explicit legacy codec, and sent
through the account-bound call client; received packets are authenticated before
being interpreted as media signals. Authenticated duplicates/expired counters
are discarded, not replayed or used to tear down a working proxy. Malformed or
unauthenticated ciphertext fails closed. All drained buffers are wiped.

Only actual media readiness (relay route plus approved QUIC identity) can trigger
`callStarted`; public proxy readiness additionally waits for that service ACK.
The ACK is sent once per call. A lost response aborts locally without blindly
retrying or redialing. A 250 ms local monitor checks revocation/native failure
and reports newly ready media; it does not poll provider updates automatically.
Explicit hangup sends `discardCall` and then closes the owned worker/cipher.
Remote deletion closes media while preserving the authenticated account and
listening control session. A local abort/close cancels its control session too;
it does not log out the owning account or promise a remote network ACK.

```powershell
node --test scripts/test-rubika-account-media.cjs
```

Account-media milestone: **355 Node tests passed, 0 failed, 0 skipped**,
including 107 Rubika tests. Fifteen handoff/owner tests cover single consumption,
negotiation, key/profile revocation, same-second changes, readiness and one-time
ACK, redelivery, tampering, account isolation, hangup and cancellation. All
**62 Rust library tests passed, 0 failed, 0 ignored**, including the normal
Rubika helper fixture now driven through actual account-bound CallClient and
CallSession classes, retained-key checks, media handoff and ACK handling. The
other real-media regression still echoes 256 KiB byte-for-byte. Accounts,
provider discovery/HTTP and notifications in these fixtures remain synthetic.

No live account request, lab restart, production build, release or change to the
Bale packet path occurred. Real service acceptance, native Rubika interoperability,
live key shape/clock semantics, external-VPS route, tariff and outage tests are
still required, followed by product integration. The guarded lab UI is now
implemented below.

## Explicit two-account call lab

The isolated lab now accepts `--rubika-bridge` and provides authenticated,
same-origin `/api/rubika/media/{prepare,dial,accept,end,reset}` routes. Only exact
typed options and an unlocked vault are accepted. `CallPair` binds two distinct,
confirmed accounts and prepares fresh local helpers/QUIC pins without dialing.
Either account can explicitly dial the other; acceptance remains manual and
transport client/server roles are independent of call direction. Account IDs
come from each confirmed session, not guessed phone/GUID conversions.

After explicit preparation, a serialized two-second event poll handles account
notifications. Media attachment waits for complete, eligible negotiated fields
on both sides; it does not fail simply because Accepted arrived before a key or
relay update. Account changes, vault lock/reset, stop/resume/logout/forget cancel
the experiment and owned workers. Public state excludes account keys, raw SDP,
TURN credentials and pairing certificates. Uncertain remote hangup is separate
from confirmed termination. No automatic answer, redial or device registration
is introduced. Local API readiness never changes the provider capability flags
to a verified tunnel or tariff.

The Rubika tab has compact controls, per-account role/status/actions, byte/RTT/
loss metrics, tooltip help and bilingual errors. The existing local FA/EN fonts,
theme/language persistence and responsive layout are retained. The browser test
completed prepare/call/manual accept/end in FA/EN, dark/light at 320–1440 px,
checked no horizontal overflow, cleared vault input, no sensitive state and zero
application external requests. The earlier four-provider browser flow also
passed. Both are synthetic provider/native-media fixtures, not live login/calls.

Current provider suite: **366 Node tests passed, 0 failures, 0 skips**, including
118 Rubika tests. Seven pair-manager and four HTTP tests cover explicit actions,
either caller direction, cancellation, revocation, fixed-provider helpers,
vault/origin/auth guards, private output and uncertain shutdown. Both targeted
Rust local-media tests passed; the normal Rubika helper fixture now exercises
this actual pair manager, typed account/call clients, media owner and one-time
start ACK. The 256 KiB projected real-media echo remains byte-identical. The
latest full Rust library regression remains 62 passed with no ignored tests;
no Rust core source changed in this lab step.

```powershell
node --test scripts/test-rubika-call-pair.cjs scripts/test-rubika-call-lab.cjs
node scripts/test-rubika-call-lab-browser.cjs
```

See [the Persian call-lab guide](../../docs/rubika-call-lab-fa.md). Production
UI/binaries and the live running lab were not restarted or published in this
step. Each lab serves UI/backend from its startup snapshot; changed source does
not upgrade an existing process. Real-account login, API/native interoperation,
cross-machine persistent pairing, Linux packaging and external-VPS route/tariff/
outage checks remain unfinished. No provider tunnel is advertised as verified.

## Explicit Android login compatibility (experimental)

An empty Rubika login card now offers `web` (the unchanged default) and
`android-4.1.1-compat`. The latter follows the pinned APK's client identifiers,
numeric V6 version, `is_background`, Firebase device registration fields, and
the exact Android public-key/ciphertext/signature Base64 wrapping. It retains
the laboratory's truthful desktop device name and at least 2048-bit RSA; it
does not claim to be an installed phone or reproduce a weak legacy key size.

The selected protocol is saved with the account's device profile and reused by
auth restoration, call requests, privacy requests and notification decryption.
Legacy records without a protocol field remain Web. A transport cannot silently
use a record from a different profile, and changing the profile during an active
account operation cancels its ownership. The profile selector performs no
network action and cannot relabel an existing saved session.

For live testing use an **empty slot in a separate isolated lab data directory**;
keep the existing encrypted Web session store intact. New auth is still sealed
before device registration, so a partial registration failure cannot discard
it. No automatic registration retry, OTP request, logout, record replacement or
conversion of an old Web session has been added. The current running lab must
be explicitly reloaded by its owner to see source changes.

The Android profile has passed offline encrypted login/registration/restore,
cross-profile binding, byte-fixture and browser tests only. Service login,
Android-profile socket handshake interoperability, real calls and media remain
unverified. See [source evidence](android-login-profile-evidence-2026-11-04.json).

```powershell
$env:TEMP='E:\CodexTemp'; $env:TMP=$env:TEMP; $env:TMPDIR=$env:TEMP
$env:NODE_COMPILE_CACHE='E:\CodexBuilds\BaleVPN\cache\node'
node --test scripts/test-rubika-client-profile.cjs
```
