# Eitaa service and call research

This component is isolated from production Bale. Eitaa is still marked as
research in the local provider panel: no login, media or tunnel is enabled.

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
ID as its hash. This branch is not copied: a ping acknowledgement cannot prove
code delivery, authorization or a valid service-issued code hash. The eventual
login controller must handle this compatibility question from actual account
evidence and show uncertain acknowledgement honestly.

`service-schema.json` stores selected factual field/ID declarations for 16
login/call methods and 15 constructors, extracted without running the worker.
It includes the current authorization token and user fields, password method,
call DH/protocol fields, and WebRTC connection credentials. Their declarations
do not prove that the service accepts them. Token refresh/sign generation,
actual code/hash semantics, password handling, retained-device restore,
live call events, DH validation and a real provider relay carrier remain work
to complete before Eitaa can be offered as a working tunnel.

```powershell
node --test scripts/test-eitaa-wire.cjs
# Opt-in only: anonymous ping, never OTP or login:
node scripts/probe-eitaa-public.cjs --connect
# Offline parity; point at the already downloaded, pinned worker:
$env:BALEVPN_EITAA_WORKER = 'ABSOLUTE-PATH-TO-mtproto.worker-CJJzYEpd.js'
node scripts/test-eitaa-official-wire.cjs
node scripts/extract-eitaa-schema.cjs $env:BALEVPN_EITAA_WORKER experiments/eitaa/service-schema.json
```

The parity test executes only the SHA-pinned serializer class with fixture
methods in an isolated VM context; it does not execute the worker entry,
imports, account storage, telemetry or network. Four envelope fixtures cover
Unicode and short/long TL byte encoding; four ping fixtures cover signed longs.
The extracted field declarations must also match the committed schema.
The Node regression suite passed 156 tests without failures or skips, including
10 Eitaa tests. Existing helper process tests used the real Windows executables;
the Eitaa HTTP tests used bounded offline responses in addition to the separate
single live anonymous probe. No production executable was rebuilt for this step.

The Android APK was previously inspected as compiled metadata/DEX fields, not
installed, run or recovered as original source. Neither that inspection nor
this service probe verifies voice/video support, provider-carried traffic,
foreign-VPS performance, quarter-rate billing or international-outage behavior.
