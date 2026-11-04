# GLib 0.18.5 security backport

This directory preserves the crates.io `glib` 0.18.5 archive, including its MIT
license and copyright notices. `UPSTREAM.json` records the archive checksum,
original per-file checksums, original VCS commit, and modified file checksums.
The archive checksum was verified against the application Cargo.lock before
extraction. The package version remains 0.18.5.

The only production source change is the two-line fix from gtk-rs/gtk-rs-core
[PR 1343](https://github.com/gtk-rs/gtk-rs-core/pull/1343): make the pointer in
`VariantStrIter::impl_get` mutable and pass `&mut p` to the variadic GLib
function. This repairs the immutable-reference write described by
[RUSTSEC-2024-0429](https://rustsec.org/advisories/RUSTSEC-2024-0429.html).
A regression test exercises forward/backward iteration, Unicode, empty strings,
exhaustion, and large skip indexes. It must be run with optimization enabled:

```sh
cargo test --manifest-path vendor/glib/Cargo.toml --release --lib test_variant_str_iter
```

This requires GLib development libraries (for example, the existing Linux GUI
CI environment). No runtime test has been performed merely by preparing this
source directory. Existing iterator tests should also pass in debug and release
modes once the workspace patch is wired and its lockfiles resolved.

This directory alone does not change dependency resolution. Cargo workspace
patch wiring, lockfile verification, and actual optimized tests are separate
steps. Default cargo-audit still identifies version 0.18.5 as affected; a
reviewed exact-source exception may describe this backport, but must not pretend
that upstream published a patched 0.18 release or suppress unrelated advisories.
