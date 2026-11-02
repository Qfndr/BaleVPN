# Account-owned experimental call controller

`call-session.cjs` connects one authenticated Nasim account/event connection to
one private native media bridge. The local two-account lab now instantiates it
through `call-pair.cjs`, with explicit prepare/dial/approve/end controls. See
[panel evidence](panel-evidence-2026-11-03.json) and the
[Persian guide](../../docs/nasim-call-lab-fa.md). Main-product provider
integration, live-account testing, tariff validation and outage testing remain
required. The existing iGap/Bale controllers and traffic paths are unchanged.

The controller pins the actual account user ID, client/device ID and signaling
object. A signed-in flag supplied separately is insufficient. Replacement,
closure or identity change invalidates its media and queued actions. Cleanup
closes the pinned old connection and does not close a newer account subscription.
All API and native errors are converted to fixed codes; raw error messages,
SDP and TURN credentials do not enter its public state.

The intended integration order is:

1. Sign in both distinct accounts and explicitly start their event streams,
   routing each private callback to its own controller's `handleEvent`.
2. Set the intended peer IDs with `setAllowedPeers`.
3. Call `prepare` with the local tunnel role/port/profile. It opens a fresh
   native process and returns only its public certificate.
4. Explicitly bind the expected peer's certificate using `trustCertificate`.
   The two-account local lab can exchange these directly in-process. A remote
   deployment still needs authenticated cross-device trust distribution;
   account IDs alone are not substitutes for QUIC certificate pins.
5. Call `dial` once on the caller. Incoming configuration becomes `incoming`
   on the approved peer; it does not configure or start media until `accept`.
6. The accepting callee sends `accept`, generates an SDP offer through the
   native helper, and sends it privately. The caller answers only after the
   selected remote device has accepted. Tunnel client/server role remains
   independent of offerer/answerer direction.
7. Native mutually authenticated proxy readiness, completed negotiation and
   both parties' approval are all required for `connected`. A call API
   acknowledgment, relay configuration or SDP exchange alone is insufficient.
8. `end` closes local media immediately and attempts one appropriate terminal
   signal. A lost acknowledgment is uncertain; there is no automatic retry.
   `reset` also invalidates the owned event subscription and trust preparation.

The official web build can create the callee's offer before user acceptance.
This experiment deliberately delays native media until explicit approval.
Its acceptance-first ordering is fixture-tested, not yet validated against
the real service. Some WebRTC peers may exchange audio SDP with this code, but
only compatible native tunnel endpoints can complete its independent QUIC
authentication and carry tunnel traffic.

Config is admitted only for the two allowed participants. Outgoing config
must belong to this initiating client ID; another device's outgoing call is
ignored. The caller selects one accepting callee device; the callee pins the
initiating caller device. Answers must target the current local device. Wrong
call UUIDs, devices, participants, duplicate descriptions and replacement
configuration cannot redirect an active negotiation. An acceptance/termination
by another local-account device ends this instance without activating media.

Early signals are bounded to 16 events / 256 KiB until matching config arrives;
early offers are limited to four remote devices. Remote relay ICE is targeted,
deduplicated and bounded to 64 entries. The asynchronous queue holds at most 32
waiting actions and 2 MiB of event data. Queue overflow closes media and its
owned stream. At most 128 retired call UUIDs are remembered; they cannot
resurrect a call. Explicit reset/epoch guards also close late native preparation
and prevent late SDP or HTTP replies from reviving an ended call.

`cleanSession` while idle/prepared keeps event reception open. During an active
or pending call, its `streamReset` invalidates the possibly incomplete call,
closes the owned stream and requires explicit fresh setup. A 60-second local
call deadline bounds unanswered/setup states; media/connection changes are
checked each second. No automatic call, answer or redial is triggered.

Run from the repository root:

```powershell
node --test scripts/test-nasim-call.cjs
```

All 16 controller tests use two synthetic accounts, the actual call wire codec
and injected native process fixtures. They test reciprocal pairing, explicit
acceptance, role/direction independence, device binding, early messages, private
state redaction, history gaps, ownership changes, late cancellation, bounded
queues, ICE filtering and uncertain acknowledgments. **They do not execute the
native helper or contact the provider.** Separate native-bridge/core tests cover
real helper processes, local TURN, QUIC and SOCKS behavior. Combining those
results is not proof of a live messenger call or a working provider tariff.

The full Node suite passed 117 tests without skips; native helper paths were
set for the existing process tests. After the ownership-cleanup refinement,
the 16 controller tests passed again. See
[controller evidence](call-controller-evidence-2026-11-03.json).
