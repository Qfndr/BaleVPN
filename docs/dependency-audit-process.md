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

This repair does not excuse any actual vulnerability, unmaintained/unsound
dependency warning, or yanked dependency. The existing classifier still checks
the raw findings and warnings. Its separately documented, exact RSA public-only
review remains the sole scoped vulnerability disposition.
