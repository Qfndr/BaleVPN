"""Verify the isolated ICE backport and prepare an original-code negative control.

Network access is explicit through --prepare-baseline. It downloads only the two
fixed public crate archives and verifies their pinned SHA-256 before reading.
Never extracts archive paths or runs downloaded source during verification.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
VENDOR = ROOT / "vendor" / "webrtc-ice"
PRODUCTION = ("src/candidate/mod.rs", "src/agent/agent_selector.rs", "src/agent/agent_internal.rs")
BASE_SHA256 = "4d4f0ca6d4df8d1bdd34eece61b51b62540840b7a000397bcfb53a7bfcf347c8"
UPSTREAM_SHA256 = "69cb13fd1a373e68addc4bba0c8ca058627518e54342583d024bdcbb8ae5d97d"
TEST_PATH = "src/agent/agent_nomination_test.rs"
TEST_SHA256 = "e8cb2ab9a75f40d03f4cb5e57c5e979f7374e9ae40ee3292910ccc76d9f94c62"
BASE_TEST_SHA256 = "b0906d3b6d2f505263c8a201a5df5495a1f0b9a98783f18589b1933e310903ed"
DIAGNOSTIC_TEST_MARKER = b"// Nomination diagnostics regression below.\n"
ADDITIONS = {"PATCH-PROVENANCE.json", "PENDING-NOMINATION.patch", "PATCH-NOTES.md", TEST_PATH}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def archive(version, expected):
    url = f"https://static.crates.io/crates/webrtc-ice/webrtc-ice-{version}.crate"
    with urllib.request.urlopen(url, timeout=30) as response:
        data = response.read(8 * 1024 * 1024 + 1)
    assert len(data) <= 8 * 1024 * 1024, "crate exceeds bound"
    assert digest(data) == expected, "public crate checksum mismatch"
    return tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--prepare-baseline", type=Path)
    args = parser.parse_args()
    provenance = json.loads((VENDOR / "PATCH-PROVENANCE.json").read_text())
    assert not VENDOR.is_symlink(), "vendor directory must not be a symlink"
    local_files = set()
    for path in VENDOR.rglob("*"):
        assert not path.is_symlink(), f"symlink forbidden: {path.relative_to(VENDOR)}"
        if path.is_file():
            local_files.add(path.relative_to(VENDOR).as_posix())
        else:
            assert path.is_dir(), "nonregular vendor entry"
    assert provenance["base"]["version"] == "0.11.0"
    assert provenance["upstream"]["version"] == "0.14.0"
    assert provenance["base"]["sha256"] == BASE_SHA256
    assert provenance["upstream"]["sha256"] == UPSTREAM_SHA256
    assert digest((VENDOR / TEST_PATH).read_bytes()) == TEST_SHA256, "regression source changed"
    redactions = provenance["nonProductionRedactions"]
    assert len(redactions) == 1 and redactions[0]["path"] == "codecov.yml"
    assert digest((VENDOR / "codecov.yml").read_bytes()) == redactions[0]["redactedSha256"]
    for entry in provenance["files"]:
        assert entry["path"] in PRODUCTION
        assert digest((VENDOR / entry["path"]).read_bytes()) == entry["patchedSha256"]
    assert len(provenance["files"]) == len(PRODUCTION)
    if args.prepare_baseline is None:
        print("ICE backport recorded source hashes match.")
        return
    target = args.prepare_baseline.resolve()
    assert not target.exists(), "negative-control directory must be new"
    assert target != VENDOR.resolve() and VENDOR.resolve() not in target.parents
    with archive("0.11.0", BASE_SHA256) as original, archive(
        "0.14.0", UPSTREAM_SHA256
    ) as upstream:
        for entry in provenance["files"]:
            path = entry["path"]
            assert digest(original.extractfile(f"webrtc-ice-0.11.0/{path}").read()) == entry["originalSha256"]
            assert digest(upstream.extractfile(f"webrtc-ice-0.14.0/{path}").read()) == entry["upstream014Sha256"]
        # Verify the whole original crate, including licenses, manifest and lock.
        # The sole other original-source edit enables our added regression module.
        original_files = set()
        for member in original.getmembers():
            assert member.isdir() or member.isfile(), "nonregular archive entry"
            if member.isdir():
                continue
            relative = Path(member.name).relative_to("webrtc-ice-0.11.0")
            assert ".." not in relative.parts
            original_files.add(relative.as_posix())
            if relative.as_posix() in PRODUCTION:
                continue
            expected = original.extractfile(member).read()
            if relative.as_posix() == "codecov.yml":
                assert digest(expected) == redactions[0]["originalSha256"]
                expected, count = re.subn(
                    rb"(?m)^[ \t]*token:[^\r\n]*(\r?\n|$)",
                    b"  # Upstream upload credential removed; vendored code does not upload coverage.\n",
                    expected,
                )
                assert count == 1, "expected exactly one unused upstream credential"
                assert digest(expected) == redactions[0]["redactedSha256"]
            if relative.as_posix() == "src/agent/mod.rs":
                expected = expected.replace(b"#[cfg(test)]\nmod agent_gather_test;", b"#[cfg(test)]\nmod agent_gather_test;\n#[cfg(test)]\nmod agent_nomination_test;", 1)
            assert (VENDOR / relative).read_bytes() == expected, f"unexpected original-source change: {relative}"
        assert local_files == original_files | ADDITIONS, "unexpected or missing vendor files"
        shutil.copytree(VENDOR, target, ignore=shutil.ignore_patterns("target", ".git"))
        for path in PRODUCTION:
            (target / path).write_bytes(original.extractfile(f"webrtc-ice-0.11.0/{path}").read())
        # The original-code control retains the original nomination regression,
        # while additive diagnostics tests require the patched implementation.
        test_source = (VENDOR / TEST_PATH).read_bytes()
        assert test_source.count(DIAGNOSTIC_TEST_MARKER) == 1
        baseline_tests = test_source.split(DIAGNOSTIC_TEST_MARKER)[0]
        assert digest(baseline_tests) == BASE_TEST_SHA256
        (target / TEST_PATH).write_bytes(baseline_tests)
    print("Verified both crate archives and preserved source; original-code control prepared.")


if __name__ == "__main__":
    main()
