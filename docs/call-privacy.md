# Automatic call permission for a BaleVPN server

Bale can reject a call with `StartCall: RPC error code=7 message="CallNotApproved"`
before BaleVPN receives an incoming request. In the reported deployment, the
server account's call privacy was set to Nobody. Allowing Everyone in Bale fixed
that rejection.

The Rust desktop/headless application now prepares this setting when entering
Server mode, on Linux, Windows, and macOS. Client mode does not change account
privacy. This is an account-wide change: it also affects the same account in the
official Bale applications and remains after BaleVPN is stopped or logged out.
Other privacy settings are preserved.

## Behavior

1. Read the server account's current `privacy.call` parameter.
2. If it is already `always` (Everyone), avoid a write.
3. Otherwise, edit only `privacy.call` to `always`.
4. Read it back. Display **Bale incoming calls: Everyone (verified)** only when
   the response confirms that exact value.

The server panel displays checking and failure states separately. A failed read,
write, timeout, malformed response, or unconfirmed readback does not become a
success message. The **Allow Bale calls and recheck** button retries preparation.
A new Server activation also retries an earlier failed preparation. Each check
has a 20-second overall timeout. A failure does not stop the admission handler;
the operator can still fix the setting in the official Bale app.

Allowing calls in Bale does not automatically authorize a tunnel. BaleVPN's
pending requests, allow-list, block-list, and connection limit still apply.
Selecting Client, using Connect as a client, or posting to the privacy endpoint
in Client mode cannot trigger this change. Existing installations need an updated
server binary; updating the Windows client alone cannot change a remote server's
account setting.

## Protocol source

Inspected the JavaScript served by the [official Bale Web app](https://web.bale.ai/):
[index.fe3fa18088.js](https://web.bale.ai/static/js/index.fe3fa18088.js).
The live index referenced the same asset during implementation.

- Settings key: `privacy.call`; the official call-privacy selector defaults to
  `always`.
- Service: `bale.v1.Configs`.
- `GetParameters` request: empty protobuf; response field 1 repeats Parameter.
- Parameter: field 1 key string, field 2 value string.
- `EditParameter`: field 1 key string, field 2 an optional StringValue message,
  whose field 1 contains the value string. Sending a plain string at field 2
  would be a different wire shape.
- Transport: authenticated gRPC-web HTTPS using the existing Bale HTTP client.

This is an inspected client protocol, not a documented stability guarantee from
Bale. Responses are checked and failures remain visible if that protocol changes.

## Validation and limits

Loopback HTTP tests exercise the actual gRPC framing and exact edit payload,
restricted/missing settings, no-op for Everyone, read/write rejection, malformed
responses, and failed readback. UI tests cover checking, verified, and failure
states. Packaged application smoke checks reject privacy changes in Client mode.

No remote server credentials were supplied to the coding session, so automatic
changes on the user's Linux server have not been verified live. The reported
manual change is separate from these offline tests. This does not by itself
prove a complete client-to-server tunnel works.
