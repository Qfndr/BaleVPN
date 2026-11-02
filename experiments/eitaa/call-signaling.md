# Eitaa encrypted WebRTC call signaling

This private protocol component is isolated from production Bale and is not yet
connected to a live call controller or media carrier. It does not place a call,
open a proxy or prove provider-carried traffic, discounts or outage behavior.

The official `pageIm-EdTTRwhx.js` loads
`https://web.eitaa.com/appDialogsManager-CtDWV_rQ.js`, downloaded on 2026-11-03:
2,554,999 bytes, SHA-256
`877c5cf4317887f7144a682b18a6c01fe443206d1e12e0fb81a13df740049c40`.
Unlike the previously inspected declarations, this source contains actual
caller/callee controller code, `acceptCall`/`confirmCall`, fingerprint checks,
WebRTC setup and encrypted `phone.sendSignalingData` handling. The observed
protocol advertises layer 92 / library `4.0.0`, and exchanges `InitialSetup` and
`Candidates` JSON. This establishes an implementation in the web client, not
acceptance of those methods by the current authenticated service.

The default official protocol advertises both P2P and a reflector. Its WebRTC
configuration selects all ICE routes when the service permits P2P, or relay
otherwise. A future tunnel must explicitly disable direct fallback and verify
the nominated provider relay; copying that default would not establish the
user's billing/outage objective. The returned TURN credentials, ICE password
and DTLS fingerprint are private call material, never public account state.

`call-signaling.cjs` matches the observed private signaling packet format:

- A big-endian 32-bit sequence followed by the UTF-8 JSON/raw payload.
- A 16-byte message key from SHA-256(key slice || sequence+payload).
- Role-separated SHA-256-derived AES-256-CTR key/IV, with directional offsets
  128 and 136 into the shared key. The header is the message key; the counter is
  encrypted. Sender/callee direction is explicit and never guessed.
- On receive, a constant-time message-key comparison precedes exposing bytes
  or updating replay state. This is the legacy service construction, **not a
  newly designed AEAD**, and cannot replace independently pinned QUIC identity.

Compatibility with the minimal shared integer from the official DH helper is
explicit: 248–256-byte keys are accepted, including rare leading-zero trimming;
shorter and all-zero keys are rejected. Full integrity verification still uses
the exact slices observed in the official source, without silently padding the
shared key and changing packet bytes. Live service interoperability remains to
be tested. A fresh validated DH key is required for each call; a cipher must
never be recreated to reset counters under a reused key.

Security/resource changes from the official class are deliberate:

- Packet payload is capped at 48 KiB so it fits inside the bounded 64 KiB TL
  management frame, rather than the source's 128 MiB packet allowance.
- A fixed 4,096-entry sequence ring (16 KiB) replaces the unbounded seen map.
  Duplicates, zero/wrapped counters and stale packets are rejected; bounded
  out-of-order arrival is supported. Bad authentication cannot move the window.
- Encryption is synchronous native Node crypto, avoiding async counter/replay
  races and repeated WebCrypto key imports. It runs only for call setup/ICE,
  not on the VPN data stream.
- JSON is strict UTF-8 with bounded depth, node count, strings and arrays.
  Only the observed setup/candidate types are accepted, including bounded
  SHA-256 DTLS fingerprint and ICE fields. Cycles, serialization hooks,
  accessors, prototype-pollution keys and control-character SDP injection fail.
  Optional undefined object fields are omitted as in the official JSON sender.
- Errors contain fixed reasons only. The official logging of decrypted JSON
  and whole call instances is not copied. Keys and temporary plaintext buffers
  are cleared on close/completion where JS permits it. Caller-owned decoded
  objects and native key handles cannot have guaranteed immediate cleansing.

The cipher is not an SDP adapter or a relay-address validator. In particular,
an authenticated candidate is not proof of an allowed route; a future media
controller must enforce TURN/relay policy and bind the cipher to the exact
account IDs, call/access IDs and ordered handshake before using any description.

```powershell
node --test scripts/test-eitaa-call-key.cjs scripts/test-eitaa-call-signaling.cjs
$env:BALEVPN_EITAA_CALL_UI = 'ABSOLUTE-PATH-TO-appDialogsManager-CtDWV_rQ.js'
node scripts/test-eitaa-official-call-signaling.cjs
```

The offline parity test executes only the SHA-pinned packet cipher class with
fixture keys and real WebCrypto primitives. It excludes the UI entry, imports,
account storage, media, telemetry and network. All 24 packets match exactly in
both roles across 248/255/256-byte keys, Unicode, byte-length boundaries and the
maximum payload; both implementations decrypt one another. The source's
counter wrap is explicitly rejected. Nine local signaling tests additionally
cover tampering, role reflection, replay/window gaps, malformed JSON, lifecycle
and actual native DH → encrypted-signaling integration. That integration found
and fixed native public values shorter than 256 bytes; both DH setup paths now
pad them before validation and public commitment. No real account or call was
used. Live RPC/events, SDP/media adaptation, relay selection and route/billing
measurements remain required.
The complete Node regression suite passed 197 tests without failures or skips.
