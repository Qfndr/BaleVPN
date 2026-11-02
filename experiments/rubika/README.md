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

`http-client.cjs` allows only `sendCode`, `signIn`, `registerDevice`, `getUserInfo`
and `logout`. It does not invoke them automatically. Anonymous `getDCs` discovery
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
The browser suite passed with offline provider fixtures in FA/EN and widths
320–1440px. Real network login, SMS and calls are not included in those results.

Voice-call support remains a separate research task: native APK declarations
include WebRTC/relay fields, but the current main web bundle does not establish
an available voice-call implementation. No Rubika media route, foreign-VPS
transport, sustained throughput, billing discount or outage behavior is claimed.
