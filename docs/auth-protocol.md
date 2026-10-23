# Login delivery compatibility

The previous client always sent `sendCodeType = 3` (SMS) and omitted
`StartPhoneAuth.options`. That request did not advertise Telegram Gateway
support. It also discarded the server's delivery channel and accepted an empty
transaction hash as success. Compilation and codec unit tests did not establish
that a real user could receive a code.

## Reference and request

Compared on 2026-10-23 with the JavaScript served by the
[official Bale web application](https://web.bale.ai/), specifically
[`index.fe3fa18088.js`](https://web.bale.ai/static/js/index.fe3fa18088.js).
SHA-256 of the inspected bundle:
`15997b72b0b94d9929edc58b5d8944d80a352695ccd65cb0b2c72174fd252e57`.

The relevant `StartPhoneAuth` protobuf fields are:

| Field | Meaning | Client value |
| --- | --- | --- |
| 1 | Phone number, int64 | Validated international digits |
| 2 | Application ID | 4 (web) |
| 3 | Public application API key | Existing web application constant |
| 4 | Device identity, bytes | UTF-8 UUID, reused by the auth client |
| 5 | Device title | BaleVPN |
| 7 | Preferred language | fa |
| 9 | Delivery enum | 1, DEFAULT |
| 10 | Packed capability enum list | 0 (Telegram Gateway), 1 (six-digit OTP) |

The default delivery request lets Bale select an available channel; it does not
guarantee Telegram delivery for every account. The response's field 5 identifies
the selected channel, including 2 (Bale), 3 (SMS), and 9/12 (Telegram).
Wrapped int64 field 8 supplies the next request wait time in seconds. The desktop
UI displays that channel and enables retry after the wait. If the server omits
the wait, the UI uses 120 seconds. A transaction hash is required before the UI
asks for a verification code.

Iranian local mobile numbers (`09...`), international `+`/`00` formats, and
Persian/Arabic digits are normalized. Invalid characters and invalid lengths
produce a local error rather than silently sending phone number zero.

## Verification and limits

Authentication completion uses the successful `ValidateCode` or `SignUp` RPC
response directly: a newly issued `access_token` HttpOnly cookie takes precedence,
otherwise the returned JWT is the native client's token. The official web bundle
uses `CrossBrowserHttpTransport({withCredentials: true})`; its validation handler
saves the authenticated user without making a separate `/set-cookie/` request.
The old mandatory GET to that endpoint could return HTTP 403 after consuming a
valid OTP, and submitting the same OTP again then produced `PHONE_CODE_EXPIRED`.
There is now no cookie-exchange HTTP request in the auth flow.

The shared Rust client serializes auth operations and retains one completed
transaction in memory for up to five minutes. Retrying that transaction returns
its completed result without consuming the OTP again. A new successful phone
request clears this cache; expired entries and other transaction hashes are not
reused. Cookies left over from an earlier attempt cannot turn an empty validation
response into success. Desktop and Android consume this same implementation.
The desktop UI discards an expired transaction while retaining the server's
resend cooldown. Android propagates RPC failures through JNI and returns to the
phone screen for an expired code instead of repeatedly verifying it.

The HTTP regression fixtures exercise real reqwest requests to a loopback
server: gRPC framing, request capabilities, delivery metadata, cooldown,
header-only errors, and empty successful responses. Browser tests exercise
Telegram messaging, rejection of false success, retry, and replacement of an
old login attempt. Additional HTTP fixtures cover JWT-only and cookie-only OTP
and signup completion, cookie precedence, stale cookies, concurrent duplicate
verification, cache expiry, and expired-code errors. They do not contact real
phone numbers.

An explicit network health check uses the invalid phone number zero:

```sh
cargo test --manifest-path bale-signaling-rust/Cargo.toml --locked \
  live_auth_endpoint_rejects_invalid_phone -- --ignored --nocapture
```

This check passed on 2026-10-23: TLS validation succeeded and Bale returned
`PHONE_NUMBER_INVALID`. It confirms endpoint access and error handling, not
delivery to a real account. It is ignored during ordinary CI because it depends
on an external service.

Actual code delivery, OTP acceptance, and a complete authenticated tunnel still
require an account-owner test. Enter the code only in the running application;
do not include phone numbers, OTPs, transaction hashes, or tokens in issue logs.
