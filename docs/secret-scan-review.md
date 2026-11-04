# Reviewed secret-scanner false positives

Gitleaks 8.30.1 found 34 `generic-api-key` matches in the source snapshot
`ddaf0767e48ddb46a9414b5ee3bbbd5af3aa7eda`. Review classified them as:

- 24 occurrences of synthetic passwords used only by disposable test vaults.
- Six occurrences of public Eitaa application API identifiers from the pinned
  official Android/web client and their compatibility fixtures. These identify
  the application; they are not user authentication/session credentials.
- Three exact public SHA256 provenance values in the RSA source inventory and
  video-decoder evidence.
- One literal RSA algorithm name in the Rubika source-audit explanation.

The additional `.gitleaks.toml` exceptions require **both** an exact file path
and an exact reviewed extracted value (`condition = "AND"`). They apply only
to `generic-api-key`. They do not exclude directories, test files generally,
password patterns, arbitrary hashes, or user/session stores. Updating a source
hash or adding another constant requires a fresh review.

Validation used the official Windows x64 Gitleaks 8.30.1 archive, checked against
its GitHub release SHA256
`d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e`.
The exact archived commit reproduced all 34 findings when scanned from its root;
the reviewed configuration reduced these to zero. Reports were redacted and
kept on drive E. No account credentials were printed or added to exceptions.

`scripts/test-secret-scan-allowlists.py --gitleaks PATH` runs the real scanner in
an isolated temporary directory. It verifies that a newly generated credential
in each of the 11 reviewed files is still detected, and that a reviewed literal
in an unrelated file is also detected. All 12 controls passed. CI runs this
regression with the same checksum-pinned scanner after scanning the snapshot.

This scanner review does not waive dependency advisories or establish that
runtime accounts, servers, or the whole application have no security defects.
