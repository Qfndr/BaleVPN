"""Isolated source/resolution regressions for the reviewed GLib backport."""
import copy
import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("glib_proof", ROOT / "scripts/verify-glib-backport.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class GlibBackportPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="glib-backport-policy-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shutil.copytree(ROOT / "vendor/glib", self.root / "vendor/glib")
        (self.root / "bale-vpn-rust").mkdir()
        self.metadata = {
            "workspace_root": str(self.root / "bale-vpn-rust"),
            "workspace_members": ["app"],
            "packages": [{"id": "glib", "name": "glib", "version": "0.18.5",
                          "source": None, "manifest_path": str(self.root / "vendor/glib/Cargo.toml")}],
            "resolve": {"nodes": [{"id": "app", "dependencies": ["glib"]},
                                  {"id": "glib", "dependencies": []}]},
        }

    def test_reviewed_source_and_resolution(self):
        result = policy.verify_glib_backport(self.root, self.metadata)
        self.assertTrue(result["backportVerified"])
        self.assertFalse(result["upstreamPatchedRelease"])

    def test_changed_production_source(self):
        path = self.root / "vendor/glib/src/variant_iter.rs"
        path.write_bytes(path.read_bytes().replace(b"&mut p,", b"&p,"))
        with self.assertRaisesRegex(ValueError, "glib_source_changed"):
            policy.verify_glib_backport(self.root, self.metadata)

    def test_extra_source_or_file(self):
        for name in ["src/new.rs", "unexpected.txt"]:
            path = self.root / "vendor/glib" / name
            path.write_text("extra", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "glib_inventory_changed"):
                policy.verify_glib_backport(self.root, self.metadata)
            path.unlink()

    def test_provenance_cannot_self_authorize(self):
        path = self.root / "vendor/glib/UPSTREAM.json"
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaisesRegex(ValueError, "glib_provenance_changed"):
            policy.verify_glib_backport(self.root, self.metadata)

    def test_registry_or_wrong_manifest_rejected(self):
        for key, value in [("source", "registry+https://github.com/rust-lang/crates.io-index"),
                           ("manifest_path", str(self.root / "other/Cargo.toml"))]:
            metadata = copy.deepcopy(self.metadata)
            metadata["packages"][0][key] = value
            with self.assertRaises(ValueError):
                policy.verify_glib_backport(self.root, metadata)

    def test_unreachable_or_wrong_workspace_rejected(self):
        metadata = copy.deepcopy(self.metadata)
        metadata["resolve"]["nodes"][0]["dependencies"] = []
        with self.assertRaisesRegex(ValueError, "glib_not_resolved"):
            policy.verify_glib_backport(self.root, metadata)
        metadata = copy.deepcopy(self.metadata)
        metadata["workspace_root"] = str(self.root)
        with self.assertRaisesRegex(ValueError, "glib_workspace_mismatch"):
            policy.verify_glib_backport(self.root, metadata)


if __name__ == "__main__":
    unittest.main()
