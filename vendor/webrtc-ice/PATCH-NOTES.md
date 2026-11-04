# Pending ICE nomination backport

This is the published webrtc-ice **0.11.0** crate, with MIT/Apache-2.0 license files and package version preserved. Archive identities and selected source hashes are recorded in PATCH-PROVENANCE.json.

The controlled-agent pending-nomination behavior from the published **0.14.0** source is backported. CandidatePair remembers a USE-CANDIDATE request that arrives before its connectivity check succeeds. The controlled selector acknowledges that request and selects the nominated pair after its triggered check succeeds. No ICE role is overridden.

PENDING-NOMINATION.patch records the exact production-source patch against the original 0.11.0 archive. The added deterministic regression uses an in-memory packet recorder, without sockets, to verify acknowledgement, no premature selection, and selection after successful triggered check. The module declaration is the only additional change to an original source file.

Original and upstream archives: https://crates.io/crates/webrtc-ice/0.11.0 and https://crates.io/crates/webrtc-ice/0.14.0. No other upstream behavior changes are included.

The unused upstream coverage-upload credential in `codecov.yml` is replaced with a comment. Original and redacted file hashes are recorded separately in provenance, and the verifier requires exactly this redaction while preserving all other bytes. No credential value is recorded in provenance or the patch.


The local diagnostic addition counts authenticated USE-CANDIDATE requests and pending nominations. Enable only `webrtc_ice::nomination=trace` to receive fixed counter messages for acceptance and successful triggered checks. Messages contain no candidate IDs, addresses, credentials, packet bytes, or SDP. Each agent emits at most 64 messages and each snapshot examines at most 4096 pairs. With the target disabled, no additional snapshot lock or scan runs. Counters do not select pairs or change protocol decisions.

The additional diagnostics regression tests invalid-integrity rejection, retransmission counting, and pending-to-selected transition. The original-code negative control omits only this additive diagnostic test tail, retaining the pinned original nomination regression.
