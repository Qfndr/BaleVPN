# Native WebRTC media

`lktunnel::peer_media::RelayMedia` is an experimental one-peer WebRTC audio/RTP
carrier for two compatible native tunnel endpoints. It is independent of the
existing LiveKit/Bale `rtc::Engine`. It uses the authenticated external-carrier
API and the existing SOCKS5/QUIC stack. A [private native pipe helper](native-bridge-protocol.md)
and parent process controller expose it in the experimental account controller
and the local two-account lab. Two live Nasim calls on one Windows host carried
integrity-verified HTTPS traffic in the asymmetric mode described below.
[Recorded evidence](turn-path-evidence-2026-11-04.json)

The owner supplies private TURN configuration from an authenticated call. The
driver accepts bounded TURN/UDP URLs with separate password credentials. Empty
relay configuration, STUN-only configuration, TURN/TCP, TURNS, URL-embedded
credentials and plaintext/mixed-media SDP are rejected. There is no direct
host/STUN fallback. The current webrtc-rs 0.11 ICE gather implementation only
implements TURN/UDP; unsupported transports fail instead of silently selecting
another route.

`offer()` and `answer()` gather relay candidates into a bounded audio-only SDP
with a ten-second gathering deadline. `set_answer()` completes negotiation;
`add_candidate()` admits parsed relay candidates from private signaling. The
offerer is independent of the tunnel's client/server role. Nasim's invited
callee can therefore offer while the caller answers, matching the current web
protocol. SDP and candidates must never be placed in public state or logs.

In the default relay-only mode, before calling the external carrier's `connected()`, the driver checks typed
ICE statistics for a successful nominated relay/relay pair. This establishes
the candidate types, not the provider's ownership, geolocation, tariff or
outage behavior. `selected_route()` exposes only an enum without addresses or
credentials, and returns Unknown after closure. A real provider controller
still needs to validate the supplied relay and establish the actual route.

## Nasim asymmetric endpoint

The explicit Nasim mode requires a nominated local TURN relay on the client
and a public UDP candidate on the server side. The client accepts an
ICE-discovered peer-reflexive address in selected-pair proof after the
authenticated Binding checks. SDP and trickle candidates use the stricter
admission policy. Both endpoints must authenticate their pinned QUIC peers
before the proxy passes user traffic.

The source for the two-role test kit is in
[`nasim-asymmetric-endpoint.cjs`](nasim-asymmetric-endpoint.cjs) and
[`nasim-asymmetric-launch.cjs`](nasim-asymmetric-launch.cjs). The launcher
requires Node.js 22 or newer, the verified helper and its SHA-256, and a retained
encrypted vault for one account per endpoint. Password entry stays in the
local terminal. The public pairing certificates are exchanged through a
trusted channel. Each run generates a new certificate and supports one call.

The same-host result covers authenticated transfer and cleanup. Transfer on
separate access networks, operator accounting, and behavior during an
international outage still require separate measurements.

### Opt-in app panel

On the x64 Windows or Linux app, pass the extracted kit, trusted Node
executable and retained vault using absolute paths. The app adds a Nasim tab
to its local management page when those options are supplied.

```bash
./bale-vpn --headless --nasim-kit /path/to/extracted-kit \
  --nasim-node /path/to/node --nasim-vault /path/to/encrypted-vault
```

Open the Nasim tab, select the role and vault slot, and enter the peer account
ID and vault password. Use the public certificate shown on each endpoint to
pair the two sides, then dial from the client and accept on the server.
The process supervisor keeps the vault locked while its worker is running.
Each start prepares a single call with a fresh certificate. The default
call limit is 90 seconds. For a longer test, select 5 or 15 minutes at both
endpoints before preparation. Both applications and endpoint kits must
support the selected duration. The client timer begins on dial and the
server timer on accept. Either endpoint can end the call sooner.
This panel uses retained sessions and the experimental asymmetric transport.

Two BaleVPN processes on one Windows host completed a live Nasim call in
headless mode. Both endpoints verified the route and authenticated their
peer. The client transferred and checked a 1,024-byte HTTPS download and an
8,192-byte upload through SOCKS5. Both endpoints confirmed cleanup.
[App trial evidence](app-live-evidence-2026-11-04.json)

DTLS/SRTP protects the media transport. QUIC adds independent certificate-pinned
mutual authentication between the tunnel endpoints; a connected media call
does not make the SOCKS proxy ready by itself. No microphone, camera or data
channel is created. Encrypted QUIC datagrams ride in the existing length-prefixed
RTP framing; no JavaScript packet loop, extra reliability layer, fixed send sleep
or unbounded queue is added. This does not claim that arbitrary RTP payloads
are indistinguishable from encoded voice, or that any service will relay them
unchanged. The production Bale traffic path does not invoke this module.

The media owner controls the lifetime. Closing or dropping it disconnects QUIC,
aborts owned tasks, closes WebRTC and releases the SOCKS listener and active
sockets. Late track callbacks cannot add tasks to a closed owner. Media failure
is terminal; a future call controller must create a fresh instance and obtain
fresh call credentials rather than replaying old queued packets.

Run from `lktunnel-rust`:

```powershell
cargo test --release --locked -p lktunnel --lib peer_media::tests
cargo test --release --locked -p lktunnel --lib
```

The Windows run passed all **58** library tests, including five new media tests:
relay configuration validation, 256 KiB QUIC echo with exact byte comparison,
terminal invalid setup/owner drop, wrong certificate-pin rejection despite a
connected media carrier, and a 512 KiB SOCKS5-to-TCP round trip followed by
active-socket closure and port reuse after owner drop. See
[recorded evidence](native-media-evidence-2026-11-02.json). These are functional
tests, not sustained-throughput benchmarks or evidence about operator tariffs.

Tests create a real password-authenticated TURN server on an ephemeral loopback
UDP port and two real WebRTC peer connections. They make no requests to Nasim
or any other provider. The SOCKS-to-loopback echo fixture uses the existing
test-only SSRF opt-out in a separate child test process; the parent security
tests and production SSRF behavior retain their defaults. Its initial refusal
of that local target was expected security behavior, not a transport failure.
Native provider signaling, actual account calls, selected
provider relay validation, remote-VPS operation, sustained throughput, operator
billing, Internet outage behavior and Linux execution remain separate gates.

References: the [WebRTC relay policy](https://www.w3.org/TR/2023/REC-webrtc-20230306/#rtcicetransportpolicy-enum)
specifies use of media relay candidates. The TURN/UDP implementation limit was
verified in the locally resolved `webrtc-ice` 0.11.0 source,
`src/agent/agent_gather.rs` (`gather_candidates_relay`), rather than inferred
from the API's support for parsing TCP/TLS URLs.
