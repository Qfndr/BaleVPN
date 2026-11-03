# Release policy

Publish a GitHub release, push a release tag, upload release assets, or start a
publication workflow only when the user explicitly requests publication.
Requests to fix bugs, run tests, build the project, change a version number, or
push code to `main` do not authorize a release. A new explicit publication request
is required after this policy was recorded, as instructed by the user.

# Build, test, and temporary storage

The user requires all task-generated temporary files, build/test outputs,
browser test profiles, downloads, and dependency caches to stay on drive E:.
Do not create them on C:. Existing installed tools on C: must be preserved.

Before any build/test or tool that creates temporary files, explicitly set
TEMP, TMP, and TMPDIR to E:\CodexTemp in that process. Use E:\CodexBuilds\BaleVPN
for build artifacts and task-specific dependency caches. Configure tool-specific
cache/profile paths on E: (including Cargo, Python, npm, and Playwright) rather
than relying on defaults under the Windows user profile. Propagate these rules
and environment settings to sub-agents and child processes. Do not change
unrelated applications' global configuration or remove installed runtimes.

Cleanup is limited to verified disposable caches and temporary artifacts;
preserve user data, account/session stores, signing keys, and applications.
A directory name containing tmp or cache does not establish disposability.
In particular, Codex state databases/session indexes and active bundled runtimes
must not be deleted. Do not delete or resize Windows pagefile.sys as cleanup.
