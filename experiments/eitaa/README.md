# Eitaa service and call research

This component is isolated from production Bale. Eitaa is still marked as
a two-account login laboratory in the local provider panel. Media and tunnels
remain unavailable; real login is unverified.

The official web HTML was checked again on 2026-11-03. Its SHA-256 and main
script reference were unchanged from the previous download. The pinned worker
is `https://web.eitaa.com/mtproto.worker-CJJzYEpd.js`, SHA-256
`3f26a2a9706ac7a7761efae1fe1f96ef16c2063ede6b20397cf69e802b95825f`.

The worker includes MTProto declarations, but its current `getNetworker` path
explicitly creates a networker **without an authKey**. `getEncryptedOutput`
then serializes the custom `eitaaObject` TL method: token, web device identifier,
packed TL payload, layer 135 and flags 128. `transportHTTP` chooses from ten
fixed client DCs; the declared socket transport has no implementation there.
Responses in that path are read directly as TL objects. This is HTTPS transport
encryption, **not proof of an MTProto encrypted account channel**.

`wire.cjs` implements bounded TL primitives, this envelope and ping/error parsing.
`http-client.cjs` exposes only anonymous ping, with TLS validation, fixed official
client DCs, no redirects, no retries, one pending request, cancellation and size
limits. It accepts no phone, OTP, token or call method. Each probe creates a
fresh opaque 20-character web identifier; it is not saved or printed. The
HTTP/error/public result never exposes raw response text or device identifiers.

One live anonymous request to `https://hasan.eitaa.ir/eitaa/` returned a valid
`pong` with the exact cryptographically random ping ID (609 ms on this machine).
This measures one application exchange, not a tunnel ping, bandwidth, relay
availability or operator discount. No account, OTP, login or call was used.

The official worker has a branch that resolves an `auth.sendCode` request after
a `pong` with a synthetic six-digit `auth.sentCode`, using the request message
ID as its hash. The synthetic sent-code response is not copied: a ping
acknowledgement cannot prove delivery, authorization or a service-issued hash.
The controller labels the acknowledgement unconfirmed and offers the local
correlation compatibility path only after an explicit received-code submission.
Actual service acceptance of that path remains unverified.

`service-schema.json` stores selected factual field/ID declarations for 16
login/call methods and 15 constructors, extracted without running the worker.
It includes the current authorization token and user fields, password method,
call DH/protocol fields, and WebRTC connection credentials. Their declarations
do not prove that the service accepts them. Live verification of token refresh,
code/hash semantics, password handling and retained-device restore remains,
along with live call events, DH validation and a provider relay carrier, before
Eitaa can be offered as a working tunnel.

`auth-schema.json` now records the full selected account dependency closure:
eight account methods and 73 constructors, including the nested self profile,
password challenges and token events. It is extracted from the pinned literal
table using a string-aware balanced scan and JSON parsing, without executing the
worker. `auth-wire.cjs` implements the account codec with depth, object, vector
and string bounds; unknown flags, wrong nested types, trailing data and invalid
RPC wrappers fail closed. Account IDs remain exact signed 64-bit values.

`account-client.cjs` is a **private protocol component**, not a public login
route. It supports explicit code/sign-in/password requests, protected self read,
logout and explicit token refresh. Each client retains its own web identifier
and token; no credentials are taken from another provider. The web-main API ID
and hash follow the official domain-specific override (2496), rather than the
unused initial configuration. Refresh metadata identifies this desktop lab
honestly. Expired tokens are reported instead of being refreshed or retried
automatically. Error strings are reduced to a fixed code whitelist and bounded
flood-wait duration. Raw decoded account records must never reach public state.

For an acknowledged `sendCode` pong the result is only
`{acknowledged:true,codeIssued:false}`. This private client invents no hash. A
sign-in or self-read pong is rejected. The controller's explicit compatibility
attempt is separate and still needs actual account evidence. The legacy calculation
SHA-256(salt || UTF-8 password || salt) matches three offline official fixtures;
this does not verify live password acceptance or implement the modern SRP KDF.
The account lifecycle, sealed storage/restore and two local forms are now
connected. See [the Persian login guide](../../docs/eitaa-login-lab-fa.md) and
[auth lab evidence](auth-lab-evidence-2026-11-03.json).
See [account-wire evidence](account-wire-evidence-2026-11-03.json).

```powershell
node --test scripts/test-eitaa-wire.cjs
node --test scripts/test-eitaa-account.cjs scripts/test-eitaa-auth.cjs
# Opt-in only: anonymous ping, never OTP or login:
node scripts/probe-eitaa-public.cjs --connect
# Offline parity; point at the already downloaded, pinned worker:
$env:BALEVPN_EITAA_WORKER = 'ABSOLUTE-PATH-TO-mtproto.worker-CJJzYEpd.js'
node scripts/test-eitaa-official-wire.cjs
node scripts/extract-eitaa-schema.cjs $env:BALEVPN_EITAA_WORKER experiments/eitaa/service-schema.json
node scripts/extract-eitaa-schema.cjs $env:BALEVPN_EITAA_WORKER experiments/eitaa/auth-schema.json --auth
```

The parity test executes only the SHA-pinned serializer class and legacy
password helper with fixture data in an isolated VM context; it does not execute the worker entry,
imports, account storage, telemetry or network. Four envelope fixtures cover
Unicode and short/long TL byte encoding; four ping fixtures cover signed longs.
The extracted field declarations must also match both committed schemas. Eight
account request shapes and four private response fixtures match the official
serializer, including nested Unicode self profiles and shared flag fields.
The Node regression suite passed 179 tests without failures or skips.
The browser suite covers eight isolated account forms, Eitaa acknowledgement
and password flows, encrypted restore, both languages/themes and 320–1440px. Existing helper process tests used the real Windows executables;
the Eitaa HTTP tests used bounded offline responses in addition to the separate
single live anonymous probe. No production executable was rebuilt for this step.

The Android APK was previously inspected as compiled metadata/DEX fields, not
installed, run or recovered as original source. Neither that inspection nor
this service probe verifies voice/video support, provider-carried traffic,
foreign-VPS performance, quarter-rate billing or international-outage behavior.

## Account lifecycle and acknowledgement compatibility

`auth-session.cjs` saves accepted credentials before protected self confirmation.
Only the exact active self ID can establish public signed-in state. Late replies
are invalidated by epochs; writes remain serialized across cancellation. Stop
preserves accepted credentials, logout requires true from the service, and local
forget is independent. Restore reuses the retained token, web device ID and
profile and never requests an OTP, sign-in, registration or automatic refresh.
Explicit token refresh seals the replacement before another self confirmation.
Device metadata is marked unadvertised until that explicit refresh.

The private account client still does not invent a service-issued hash after
pong. The controller offers the official web compatibility path only after an
explicit user-entered received code. It places a local request correlation in
the sign-in field that the official web also fills locally; the UI reports code
issuance/delivery as unconfirmed and labels its provenance localCompatibility.
Four offline fixtures match the SHA-pinned official request-ID generator,
including repeated/backwards clocks. This is compatibility evidence, not proof
of real OTP delivery or server acceptance. A lost request is uncertain and has
a cooldown; no verify or retry is initiated automatically.

Legacy password handling retains the received code only in memory, uses the
observed salt KDF and wipes temporary hash/salt buffers. Modern SRP remains
unimplemented and is explicitly rejected rather than downgraded. This must be
completed if the live service requires it. The browser exercises the actual
Eitaa controller with a synthetic account client, not a real account. A separate
real AccountClient/wire/vault fixture verifies disk restore without another OTP.
