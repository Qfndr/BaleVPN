# Private Eitaa call RPC and event codec

The selected call API now has a bounded authenticated HTTPS/TL client, separate
from login and from production Bale. It does **not** yet dial or answer through
the provider laboratory. No real account or provider call was used in this step.

`call-schema.json` is the dependency closure of twelve methods from the same pinned
official worker recorded in [README.md](README.md): DH configuration, call
configuration, request/accept/confirm/received/discard, encrypted signaling, update
state, update differences and two read-only contact/username lookups. Its 499 constructors cover the full declared update
dependencies, including unrelated messages/media which can accompany a call.
`call-wire.cjs` and account-only `auth-wire.cjs` share `tl-codec.cjs`; the account
wrapper still cannot encode a call method. The codec retains its 64 KiB frame,
256-element vector, 2,048-node and 16-level limits. Unsupported flags, nested RPC
wrappers, wrong result types, truncated frames and trailing bytes are rejected.

API types take precedence over MTProto types during dependency extraction. In
particular the transport-level `message` declaration must not shadow the API
`message` constructor used by update differences. Some API predicates have
multiple legacy IDs. Every ID can be decoded; encoding chooses the first API
declaration, matching the official writer's `find`. Legacy decoded objects are
private records, not a promise of re-encoding to the same constructor version.
Finite double encoding/decoding supports unrelated geographic fields without
discarding their surrounding update batch. Call/account IDs and access hashes
remain exact signed 64-bit values.

`call-client.cjs` requires an explicit retained Eitaa token and web device ID.
It does not request an OTP, refresh tokens, poll, retry, reconnect or dial on its
own. It uses the existing fixed official HTTPS endpoints with certificate checks,
bounded streamed replies, cancellation and one pending request per client. Two
clients retain separate credentials. Closing a client invalidates late replies;
error messages never contain raw service text, credentials or decoded records.
An expiring token is reported to the controller rather than silently refreshed.
A pong is never accepted as a successful call or event response.

The call request profile advertises layer 92/library 4.0.0 and UDP reflector
support; it does not advertise UDP P2P. Caller-supplied protocol, video and
transport overrides are refused. DH public fields are 256 bytes, commitments
32 bytes, and encrypted signaling packets 21–49,172 bytes. This is structural
request validation; the existing DH and signaling modules provide the separate
cryptographic checks. Neither a request flag nor a returned TURN declaration
proves that media actually uses a provider relay. The native nominated route and
independent QUIC identity still have to be verified by the future media integration.

The private client also exposes explicit `updates.getState` and
`updates.getDifference` requests. The latter fixes `pts_total_limit` to 256 and
retains final/intermediate cursors, call events and other updates. It does not
itself implement a scheduling loop, cursor commit or call-ID binding. The
[separate call controller](call-session.md) now implements those responsibilities;
the [separate media owner](native-media.md) now composes the provider-specific
helper for local verification; live service acceptance remains. A full history
response exceeding current bounds
fails explicitly; no messages or call events are silently skipped. These private
objects contain account/message metadata and must never be sent to public
HTTP state, UI diagnostics, logs or persisted as plaintext.

## Verification

Nine offline call tests cover actual TL envelopes, independent saved identities,
relay-only request flags, all twelve methods, mixed message/call event batches,
legacy constructor IDs, invalid input, uncertain/error replies and cancellation.
The pinned official serializer agrees byte-for-byte on twelve requests and eleven
responses; decoded synthetic responses also match. Only the pure serializer
class is executed in an isolated VM, without worker startup, telemetry, session
access or network. Schema extraction uses literal parsing and a SHA-256 gate.

```powershell
node --test scripts/test-eitaa-call-rpc.cjs
$env:BALEVPN_EITAA_WORKER = 'ABSOLUTE-PATH-TO-mtproto.worker-CJJzYEpd.js'
node scripts/test-eitaa-official-call-wire.cjs
node scripts/test-eitaa-official-wire.cjs
node scripts/extract-eitaa-schema.cjs $env:BALEVPN_EITAA_WORKER experiments/eitaa/call-schema.json --calls
```

Live account acceptance, event transport, caller/callee lifecycle, provider relay
configuration, native helper integration, bandwidth, billing and international
outage behavior remain unverified. Production provider UI, packaging and live
end-to-end verification remain part of the full task. No release or new test
application binary is produced for this private protocol component.
