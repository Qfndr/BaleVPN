# Scoped RSA advisory assessment

Reviewed on 2026-11-04. This is an exposure assessment, **not a dependency fix**.

[RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html), reported
on 2023-11-22 and last modified on 2026-09-14, concerns private-key recovery from
observable timing. The advisory explicitly lists `rsa` 0.9.10 as affected and
states that no patched release is available. TLS alone is not the basis for the
exception below.

The reviewed native iGap code imports `RsaPublicKey` and performs public-key
encryption for its key exchange in `igap-signaling/src/security.rs`. It does not
hold an RSA private key in the production path. `RsaPrivateKey` and RSA private
decryption occur only inside that file's `#[cfg(test)]` module, using generated
fixture keys. Incoming production decryption is AES, not RSA private decryption.
This limits exposure to the particular private-key timing attack; it does not
establish that all cryptographic operations or the upstream dependency are free
of vulnerabilities.

## CI policy

Raw `cargo audit --json` reports remain unchanged and retain the advisory.
`scripts/classify-rust-audit.py` writes a separate disposition. It permits a
scoped exception only when all these checks pass:

- Workspace is exactly `bale-vpn-rust`; there is exactly one finding, for
  `RUSTSEC-2023-0071`, registry package `rsa` version `0.9.10`.
- The checksum in the workspace lockfile matches the reviewed release.
- Full Cargo metadata identifies `igap-signaling`, from the exact local manifest,
  as the only direct consumer. Additional, renamed or unexpected consumers fail.
  Unused test-only declarations in external registry packages are not resolved
  application consumers; any actual resolved edge still fails this check.
- The complete reviewed Rust source inventory for the iGap package, including
  tests/examples and manifests, matches normalized SHA-256 hashes in
  `scripts/rsa-public-only-review.json`. New or modified source files fail.
- No additional vulnerability, warning, malformed report or audit execution
  failure is present.

The outcome is named `pass_with_scoped_exception`, with
`rawVulnerabilityCount: 1` and `upstreamPatched: false`. It must not be described
as a clean dependency audit. There is no global cargo-audit ignore entry.

Any iGap source or dependency change requires a new manual security review
before refreshing the inventory. Do not regenerate hashes merely to make CI
pass. Private-key RSA use, another consumer or another advisory is outside this
exception and must be assessed separately.

The 2026-11-04 follow-up review updated only the workspace manifest fingerprint
for the local `webrtc-ice` patch. RSA dependencies, features and all reviewed
cryptographic source files remained unchanged.

A subsequent lifecycle review refreshed only `src/adapter.rs` and
`tests/lifecycle.rs` fingerprints for accepted-transport generation binding and
atomic call-end handling. The added SHA256 digest identifies an accepted call
without retaining its transport token. RSA operations and configuration remain
unchanged; this refresh does not expand the RSA exception.

The later service-leave diagnostic review refreshed `src/adapter.rs` and
`src/room.rs` for bounded optional timestamp parsing and relative-order labels.
These metadata changes leave RSA operations and call admission decisions
unchanged.

The receive-order review refreshed `src/adapter.rs`, `src/rpc.rs`, and the
lifecycle/authentication fixtures. It covers reader-assigned ordering of
authenticated replies and pushes, with the call epoch and active RPC checked
under the call lock. RSA encryption, keys and registration parameters retain
their previously reviewed behavior.

The subsequent adapter/lifecycle review binds acceptance and cleanup to the
call revision and rechecks the authenticated RPC at call-state commits. Only
those two source fingerprints were refreshed for this generation-safety change.

The release publication verifier remains stricter: it still requires zero raw
vulnerability findings. This CI disposition does not authorize publication or
silently alter that rule.

## Verification

Run `python scripts/test-rust-audit-policy.py`. The fixtures cover changed source,
new files/consumers, different advisories, warning findings, malformed reports,
audit failure and cross-platform line endings. Actual lockfile/metadata
validation is separate from those fixtures; a fixture report is never presented
as an actual cargo-audit result.
