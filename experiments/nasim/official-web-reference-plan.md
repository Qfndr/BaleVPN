# Official Web call reference

The adapter loads eight SHA-256-pinned vendor files. It removes only the exact
top-level `Xd(),l(Jd,{target:document.body}),` UI bootstrap expression from the
pinned entry module. Call, account, crypto and message-worker implementations
remain unchanged. The offline page has no title element because the vendor's
title subscription runs before its translation initializer.

`scripts/test-nasim-official-reference.cjs` validates two isolated browser
contexts, separate synthetic in-memory accounts, exported call APIs and fake
audio. It denies every non-fixture request and all WebSockets, blocks service
workers, and returns a local 404 for notification audio. A deliberately attempted
registration request verifies that the network gate blocks it before delivery.
It does not test a real call or provide a live network allowlist.

`official-call-gate.cjs` now implements a separate network-free admission
policy. It reuses `CallCodec` and `CleanupIntent`, binds both account/device
identities, persists the pre-request intent, permits one call request, retains
the response UUID and both cleanup records before media admission, and requires
matched terminal acknowledgements or a strictly matched peer `bye` SSE event.
These two evidence types remain distinct in the journal. Restarted intents
permit cleanup only.
Its injected journal store must implement encrypted compare-and-swap writes
against the supplied previous record, and honor the supplied account guard.
The gate does not open that store or a network connection itself. The vault
adapter implements that store in a separate sealed pair journal with an
exclusive owner marker. It syncs the replacement file before rename and syncs
the directory on Linux. Windows validation covers process restart, with no
claim about directory metadata durability across power loss. An abandoned
owner marker blocks concurrent use and is never removed by an automatic reset.

Events returned as `defer: true` must be bounded and staged by the future
transport adapter until the durable response UUID is known. The HTTP adapter
seals the complete first reply and its HTTP status before decoding. It admits
only the pinned source's `POST https://api.gaplication.com/` v2.5 call packets,
with the exact account, client and topic. A blocked Chromium request confirmed
that destination and payload for the vendor's actual `start` implementation.

The browser pair uses fake audio and the vendor's `all` ICE policy. It disables
Chromium's mDNS host masking so the guard can compare exact numeric IP/port
pairs. The guard rejects private peer candidates unless captured on the other
test context's local peer connection. Approved relay URLs and host pins are
checked before creating a peer connection. The synthetic service fixture uses
explicit loopback-only relay configuration and does not contact a provider.
Both vendor browser peers have exchanged synthetic audio through that fixture,
and one HTTP bye acknowledgement plus the matching peer event cleared the
encrypted journal. The private reference runner uses the normal authenticated
SSE parser and cursor setup. A full synthetic service fixture exercises that
runner, including protected session reads, clock verification and terminal
cleanup. Real provider interoperability remains unverified.

The entry module exports account model `N`, account manager `M`, call manager
`tt`, account repository `pt` and message API `nt`. `M.login(N.fromJson(record))`
sets the in-memory account without going through OTP or device registration.
The normal Auth screen must not be mounted for a retained-session experiment.

## Private runner invocation

Use `runOfficialReference` from `official-reference-runner.cjs`. It requires
an already-unlocked `SessionVault`, a `Map` of the two retained account
controllers, the installed Playwright `chromium` and executable, the absolute
pinned source directory, an `OfficialMediaGuard`, a verified-TLS `fetchImpl`,
and an asynchronous `checkIdle` callback. `callerSlot` defaults to 1 and
`mediaTimeoutMs` defaults to 20 seconds. The runner has no CLI or public route.

Keep the vault password and local Lab key inside the existing private helpers.
The runner verifies the supplied account records against the encrypted Nasim
slots, performs one normal protected session restore per slot, and requires
both server clocks to be verified before dialing. It compares browser and saved
session identities after the run. It only writes the separate call journal and
matching cleanup intents.

Before invoking it, pause the original Lab's Nasim signaling consumers through
its existing reset operation when both calls are idle or ended. Keep the Lab
idle through the reference. `checkIdle` should privately verify the Lab's
`/api/state` shows both expected retained slots, no busy operations, no pending
cleanup and no active Nasim event consumers. The callback runs twice. The owner
marker fences other reference processes, so Lab coordination remains necessary.

Supply only exact, previously vetted STUN and TURN URLs from the official call
configuration. For a hostname, supply its vetted public IP in `hostPins` so
Chromium uses a pinned resolution. A changed or unapproved relay URL is rejected
before creating a peer connection. Browser permission for camera is never granted.

An existing journal blocks a fresh attempt. An archived successful response can
be decoded locally to recover its UUID. Pending cleanup is surfaced as a typed
result and requires the retained matching call context. No fresh dial or
registration is used to recover it.

## Live safeguards

The private runner and its operator use the following conditions.

1. Stop the Lab's signaling consumers for both selected accounts. Verify their
   pending-call and cleanup records are clear. Do not restart or overwrite the
   Lab's saved sessions.
2. Unlock the existing encrypted vault through its normal private helper. Bind
   each context to one retained user ID, client ID and token fingerprint. Seed
   only memory and the retained local `duid`, with no new login or device ID.
3. Install the request gate before importing vendor code. Allow only exact
   verified provider origins and audited method/path combinations needed for
   the selected two-account call. Decode outbound encrypted signaling privately
   to enforce peer, method, call UUID and count. Block registration, OTP, logout,
   unrelated messages, profile writes and generic retry paths. CORS/OPTIONS
   handling must not broaden this gate. Block service workers and WebSockets.
4. Keep fake microphone flags enabled and never request camera access. Suppress
   vendor logs. Disable HAR, tracing, screenshots and raw response logging.
   Report only sanitized ICE/candidate-pair counters and state transitions.
5. Persist an encrypted, account-bound operation intent before releasing the
   single outgoing callRequest. The intent includes source hashes, operation
   identity, both account bindings and the expected peer. No second callRequest
   may pass the gate, including retries by vendor JavaScript.
6. Capture the returned call UUID in the encrypted intent before releasing the
   HTTP result or related incoming SSE event to vendor code. Correlate UUID and
   both participants before accepting either account's events. Events arriving
   first must wait for the same durable capture. Reject stale or competing calls.
7. Terminate using the vendor's matching-call `sendBye` path. Allow only the
   audited terminal/update packets for that UUID. Persist the server's terminal
   acknowledgement before clearing the intent. A browser timeout or closed
   window is not proof of remote cleanup.
8. If startup finds an intent with uncertain outcome, block all new calls.
   Recover a known UUID from the sealed response/event and finish its exact
   cleanup. If no UUID was retained, require authoritative remote cleanup
   evidence instead of guessing, expiring or deleting the intent.
9. Compare account token/client ID fingerprints before and after the operation.
   Any unexpected mutation stops the runner and preserves recovery evidence.
   No changed credential is silently written over the original session.

An official default-ICE test and an adapter-forced relay-only test are different
experiments. The latter changes `iceTransportPolicy` and must be labeled as
such. The offline fixture covers the default-policy runner. It does not establish
live provider routing or forced-relay behavior.
