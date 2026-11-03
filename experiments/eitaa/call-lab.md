# Eitaa two-account laboratory integration

The isolated provider lab now exposes explicit Eitaa prepare/dial/accept/end/reset
controls through `call-pair.cjs`. No production Bale UI or packet code changed.
The complete browser flow passes against synthetic account/relay fixtures; live
provider acceptance remains unverified. See the [Persian operator guide](../../docs/eitaa-call-lab-fa.md).

`TargetResolver` first confirms each exact self ID with its retained account
token and web device identifier. If the other confirmed self has a public
username, it resolves that name from the **calling account** and verifies the
returned user ID and username. This avoids reading the whole address book when
unnecessary. Otherwise it reads the caller's contacts and requires the exact
target contact/user ID with a usable, non-minimal access hash. Duplicate,
deleted, bot, incomplete or reassigned targets cannot select another account.
No phone number, contact import, arbitrary search or self-record hash transfer
is used. Target hashes stay private and are discarded on invalidation.

The reviewed call schema now includes `contacts.getContacts` and
`contacts.resolveUsername`: 12 methods and 499 dependency constructors. All 12
request and 11 response fixtures match the pinned official serializer, including
the complete contacts/resolved-user reply. No live method was invoked by the
parity tests. The full response remains subject to existing 64 KiB/vector bounds;
uncached not-modified responses fail instead of inventing a contact cache.

The pair prepares both normal native helpers and exchanges public pairing
certificates only inside the local process. Neither the browser nor provider
signaling supplies trust keys. Both listeners start with optional bounded
two-second polling; preparation never dials or accepts. Either account can be
the caller independently of its proxy client/server role. Explicit actions also
check pending updates to reduce local orchestration delay; service updates that
arrive later are handled by the regular serialized poller.

Preparation/lookup/worker creation are epoch-bound to both exact account records.
Reset, stop, logout, refresh, local forget, vault lock and lab shutdown close both
owners and invalidate late completions. Account sessions remain sealed separately
and are not replaced by target lookup. Pairing identities are currently single-use;
remote deployment, durable identity and reconnect are still pending. End closes
local transport immediately and reports uncertainty if the remote discard cannot
be confirmed. No automatic dial/accept/redial is introduced.

## Private local routes

All existing bearer, same-origin, host, vault and body-size gates apply.
The routes reject browser-provided SDP, tokens, target hashes, certificates and
unknown fields. Stopping another provider does not reset the Eitaa pair.

| POST route | Allowed input |
|---|---|
| `/api/eitaa/media/prepare` | clientSlot, socksPort, throughput |
| `/api/eitaa/media/dial` | slot |
| `/api/eitaa/media/accept` | slot |
| `/api/eitaa/media/end` | slot |
| `/api/eitaa/media/reset` | empty object |

`/api/state` adds `eitaaMedia` and each Eitaa account's public call state. It
contains no access hashes, certificate pins, TURN secrets, SDP or tokens. Native
readiness remains role-specific. The UI labels QUIC loss, shows byte totals/RTT,
uses translated statuses and tooltip help, and keeps port/role controls compact.
The mobile form uses two columns; no checkbox was added.

The new `--eitaa-bridge` argument requires an absolute helper path. Research
helper copies with SHA-256 metadata are under
`E:\My Project\BaleVPN-Research\Provider-Lab-Native-2026-11-03-call-lab\windows-x64`.
These are experimental helper executables, not a new product application or
release. The existing lab was confirmed live with an empty locked vault and no
active accounts. Automatic approval review rejected its stop/restart command
with `blocked by policy`; no alternate restart was attempted. Read-only inspection
confirmed the running process still has the previous startup snapshot. The new
code must be started manually before its controls are available in that instance.

## Verification

* 273 provider Node tests pass, with no failure/skip. New coverage includes seven
  target-resolver tests, four orchestration tests and two HTTP call/control tests.
* The browser drives real local HTTP from login through explicit Eitaa
  prepare/dial/accept, metrics and end, then encrypted vault restore without OTP.
  FA/EN, dark/light and 320–1440px widths pass with no application external request
  or page error. Desktop and mobile captures were inspected. Accounts/native
  media in that browser test are synthetic.
* All 60 Rust library tests pass with the actual normal-helper fixture enabled.
  The new target schema/lab integration is additional Node control-plane work;
  this turn changes no Rust source or media packet path.

The live laboratory remains unlogged-in. Actual OTP/session acceptance, contacts
and username methods, service calls/relay, cross-machine operation, performance,
operator tariff and outage behavior are not established by these tests. No new
Linux/macOS/mobile product package or release is produced in this step.
