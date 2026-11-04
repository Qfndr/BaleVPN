"""Verify the reviewed GLib backport and its active Cargo resolution."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath

MANIFEST_SHA256 = "4efa15ab9d0d27c039251c67cafaba31ba56232c9c5b3469a86958ac0dd1ef0e"
PATCHED_SHA256 = "eec14e8c4dcc91161ff3dbe93cc1e1db70b97e52c9f119e2549ea8a427060f1f"


def _fail(reason):
    raise ValueError(reason)


def _hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_glib_backport(root, metadata):
    """Return source proof, or reject with a fixed non-sensitive reason."""
    try:
        root = Path(root).resolve(strict=True)
        vendor = root / "vendor" / "glib"
        if vendor.is_symlink() or not vendor.is_dir():
            _fail("glib_backport_missing")
        manifest = vendor / "UPSTREAM.json"
        if manifest.is_symlink() or _hash(manifest) != MANIFEST_SHA256:
            _fail("glib_provenance_changed")
        provenance = json.loads(manifest.read_text(encoding="utf-8"))
        originals = provenance["original_file_sha256"]
        if len(originals) != 121:
            _fail("glib_inventory_invalid")
        expected = set(originals) | {"UPSTREAM.json", "BACKPORT.md"}
        actual = set()
        for file in vendor.rglob("*"):
            if file.is_symlink():
                _fail("glib_symlink_rejected")
            if file.is_file():
                actual.add(file.relative_to(vendor).as_posix())
        if actual != expected:
            _fail("glib_inventory_changed")
        for name, digest in originals.items():
            parts = PurePosixPath(name)
            if parts.is_absolute() or ".." in parts.parts or "\\" in name:
                _fail("glib_inventory_invalid")
            wanted = PATCHED_SHA256 if name == "src/variant_iter.rs" else digest
            if _hash(vendor / name) != wanted:
                _fail("glib_source_changed")

        if not isinstance(metadata, dict):
            _fail("glib_metadata_invalid")
        if Path(metadata["workspace_root"]).resolve() != root / "bale-vpn-rust":
            _fail("glib_workspace_mismatch")
        candidates = [p for p in metadata["packages"]
                      if p.get("name") == "glib" and p.get("version") == "0.18.5"]
        if len(candidates) != 1:
            _fail("glib_resolution_ambiguous")
        package = candidates[0]
        if package.get("source") is not None:
            _fail("glib_registry_source_rejected")
        if Path(package["manifest_path"]).resolve() != vendor / "Cargo.toml":
            _fail("glib_manifest_mismatch")
        nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
        members = metadata["workspace_members"]
        if not members or any(m not in nodes for m in members):
            _fail("glib_metadata_invalid")
        pending = list(members)
        reachable = set()
        while pending:
            current = pending.pop()
            if current in reachable:
                continue
            if current not in nodes:
                _fail("glib_metadata_invalid")
            reachable.add(current)
            pending.extend(nodes[current]["dependencies"])
        if package["id"] not in reachable:
            _fail("glib_not_resolved")
        return {"crate": "glib", "version": "0.18.5", "backportVerified": True,
                "upstreamPatchedRelease": False, "filesVerified": len(originals),
                "provenanceSha256": MANIFEST_SHA256, "patchedSourceSha256": PATCHED_SHA256}
    except json.JSONDecodeError:
        _fail("glib_proof_invalid")
    except ValueError:
        raise
    except (OSError, KeyError, TypeError, AttributeError):
        _fail("glib_proof_invalid")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--metadata", type=Path, required=True)
    args = parser.parse_args()
    try:
        proof = verify_glib_backport(args.root, json.loads(args.metadata.read_text(encoding="utf-8")))
    except (ValueError, OSError):
        raise SystemExit("GLib backport verification failed")
    print(json.dumps(proof, sort_keys=True))


if __name__ == "__main__":
    main()
