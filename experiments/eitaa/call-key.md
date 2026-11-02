# Eitaa call key exchange research

This private component prepares the DH part of a possible call controller. It
is not wired into a call button, media carrier, account storage or production
Bale path. Real Eitaa calls and the provider relay remain unverified.

The main official web bundle references
`https://web.eitaa.com/crypto.worker-BvnnVP9w.js`. The 70,662-byte worker was
downloaded from that exact official URL on 2026-11-03, SHA-256
`c4bd9ad27612c3459d895933072a236d229b4715ebb4a13523e8c8751f976339`.
Its selected helpers generate a padded 256-byte `g_a`, commit SHA-256 of that
public value, compute the shared integer by modular exponentiation and derive
the signed little-endian fingerprint from the last eight bytes of SHA-1.

An interoperability detail is explicit: the worker hashes the **minimal
big-endian shared integer**, while its public value is padded. Our native engine
returns padded shared bytes; they are trimmed before the compatibility
fingerprint. A leading-zero fixture exercises this difference. This does not
establish which media codec or encryption format a live service call requires.
SHA-1 here is a legacy service fingerprint, not the tunnel's AEAD or independent
peer authentication mechanism.

`call-key.cjs` uses Node/OpenSSL for private key generation and DH computation;
it does not implement production secret modular exponentiation in JavaScript.
It requires an exactly 2048-bit safe prime, a generator from 2 through 7 with
the corresponding residue checks, and public values strictly inside
`2^1984 < value < p - 2^1984`. Unknown groups are checked asynchronously for
both p and (p−1)/2 using 64 primality iterations. At most four unknown validations
can run together; identical pending groups share work, and at most eight
validated public prime hashes are cached. A cached prime still undergoes the
generator-specific residue checks.

The public validation rules follow the [DH safety checks in the MTProto
specification](https://core.telegram.org/mtproto/auth_key); this is a safety
reference, not proof that Eitaa uses the complete MTProto authorization flow.
The [Node crypto APIs](https://nodejs.org/api/crypto.html#cryptocheckprimecandidate-options-callback)
provide the native primality and DH operations. `call-key-reference.json` records
the public safe-prime reference used by an offline test; it is not a captured
Eitaa call parameter. The separate composite-q test uses a generated public
prime with p = 7 mod 12 and verifies that checking p alone is insufficient.

The built-in `modp14` group with generator 2 uses the native prevalidated group
constructor. Two local peer setups and derivations took approximately 6 ms in
one development smoke check; this is not a throughput benchmark or a promise
about Eitaa's actual group. Custom-group setup also has generic OpenSSL checks.
There is no per-packet work or production Bale overhead from this component.

Each instance is one-use: invalid input consumes the pending exchange, success
releases the native private handle, and close removes the remaining references
and public buffers. JS cannot guarantee immediate cleansing of a native handle;
the result's private `key` buffer belongs to its caller and must be cleared when
the call ends. No key/private exponent is returned in public state or saved.
Public values are defensive copies. An aborted setup cannot generate a usable
key after the asynchronous validation completes.

The optional commitment and fingerprint checks report exactly which evidence
was provided. `commitmentVerified` and `fingerprintVerified` do **not** mean that
the remote user is trusted. The future call controller must bind both account
IDs, call/access IDs and the ordered handshake, handle the confirmation reply,
and apply the independent pinned QUIC identity before exposing a proxy. Relay
selection must enforce provider-carried traffic; direct P2P would not prove the
user's billing or international-outage objective.

```powershell
node --test scripts/test-eitaa-call-key.cjs
$env:BALEVPN_EITAA_CRYPTO = 'ABSOLUTE-PATH-TO-crypto.worker-BvnnVP9w.js'
node scripts/test-eitaa-official-call-key.cjs
```

The offline parity test executes only the SHA-pinned arithmetic library and
selected pure DH helpers in an isolated context, with fixture randomness and
native hashes. It excludes worker startup, prototype changes, ports, account
storage, telemetry and network. Actual official modular exponentiation is
compared with native results for two 2048-bit groups. No OTP, account or call is
used. Eight security/lifecycle tests cover native agreement, safe-prime checks,
weak/boundary public values, altered commitments/fingerprints, cancellation,
work limits and the minimal-byte fingerprint. A live signaling controller,
media carrier and real route/billing tests are still required.
The full Node regression suite passed 187 tests with no failures or skips.
