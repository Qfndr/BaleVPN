# Complete dependency audit inputs

Each shipped lockfile is audited with registry fetching enabled. In the pinned
[cargo-audit 0.22.2 implementation](https://github.com/rustsec/rustsec/blob/cargo-audit/v0.22.2/cargo-audit/src/auditor.rs#L117-L168),
`--no-fetch` changes both advisory-database handling and registry handling:
the registry uses `CachedIndex::open` instead of `CachedIndex::fetch`.
[Sparse index documentation](https://docs.rs/rustsec/0.33.0/rustsec/registry/struct.CachedIndex.html)
specifies that `open` only reads cached crate entries, while `fetch` permits
on-demand retrieval. A previous, smaller graph therefore cannot prime all the
index entries needed by later graphs.

CI preserves each raw JSON report and captures stderr separately. A missing
registry entry, inability to open/update the index, or an audit error fails the
job. This additional check is necessary because cargo-audit 0.22.2 prints
individual yank-lookup failures to stderr without adding them to the JSON
warnings (the same source, lines 322–347).

The observed transient sparse-index response-decoding failure permits at most
three attempts per graph, with a short delay. Every raw attempt is preserved.
The final report still passes the same warning/error policy; advisory findings
and unmaintained warnings alone never trigger a retry or receive an exemption.

This repair does not excuse any actual vulnerability, unmaintained/unsound
dependency warning, or yanked dependency. The existing classifier still checks
the raw findings and warnings. Separately documented dispositions cover exact
RSA public-only use and the verified GLib source backport; all other findings
and warnings still require their own review or dependency remediation.

The GLib disposition is restricted to `RUSTSEC-2024-0429`, version 0.18.5, and
the active local `vendor/glib` dependency in the desktop application graph.
`scripts/verify-glib-backport.py` pins the complete upstream file inventory,
backport source and provenance hashes, rejects additional files/symlinks, and
checks the resolved dependency path. CI runs its tamper tests and an optimized
Linux string-iterator regression in the desktop binary workflow. Raw audit
warnings remain present; the result describes a reviewed source backport, not
an upstream patched release. Unmaintained dependencies and the separate rand
advisory are not covered by this disposition.
