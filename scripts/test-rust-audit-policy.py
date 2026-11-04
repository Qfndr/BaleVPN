import copy
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("audit_policy", REPO / "scripts/classify-rust-audit.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class AuditPolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="rsa-audit-policy-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        review = json.loads((REPO / policy.INVENTORY).read_text())
        for relative in [*review["files"], str(policy.INVENTORY), "bale-vpn-rust/Cargo.lock"]:
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO / relative, destination)
        self.report = {"vulnerabilities": {"found": True, "count": 1, "list": [{
            "advisory": {"id": policy.ADVISORY, "package": "rsa"},
            "package": {"name": "rsa", "version": "0.9.10", "source": policy.REGISTRY}}]}, "warnings": {}}
        self.metadata = {"workspace_root": str(self.root / "bale-vpn-rust"), "packages": [
            {"id": "rsa", "name": "rsa", "version": "0.9.10", "source": policy.REGISTRY, "dependencies": []},
            {"id": "igap", "name": "igap-signaling", "source": None,
             "manifest_path": str(self.root / policy.PACKAGE_ROOT / "Cargo.toml"), "dependencies": [{"name": "rsa"}]}],
            "resolve": {"nodes": [{"id": "igap", "deps": [{"name": "rsa", "pkg": "rsa"}]}, {"id": "rsa", "deps": []}]}}

    def classify(self, report=None, metadata=None, workspace="bale-vpn-rust", exit_code=1):
        return policy.classify(self.report if report is None else report, workspace, self.root,
                               self.metadata if metadata is None else metadata, exit_code)

    def test_only_exact_reviewed_use_is_scoped_and_raw_report_is_unchanged(self):
        original = copy.deepcopy(self.report)
        result = self.classify()
        self.assertEqual(result["status"], "pass_with_scoped_exception")
        self.assertEqual(result["rawVulnerabilityCount"], 1)
        self.assertFalse(result["scopedExceptions"][0]["upstreamPatched"])
        self.assertEqual(self.report, original)

    def test_other_advisory_package_version_or_workspace_remains_fatal(self):
        for area, field, value in [("advisory", "id", "RUSTSEC-2099-9999"),
                                   ("package", "version", "0.9.11"), ("package", "name", "other")]:
            report = copy.deepcopy(self.report)
            report["vulnerabilities"]["list"][0][area][field] = value
            with self.assertRaises(policy.PolicyError):
                self.classify(report=report)
        with self.assertRaises(policy.PolicyError):
            self.classify(workspace="lktunnel-rust")

    def test_additional_advisory_and_warnings_are_fatal(self):
        report = copy.deepcopy(self.report)
        report["vulnerabilities"]["list"].append(copy.deepcopy(report["vulnerabilities"]["list"][0]))
        report["vulnerabilities"]["count"] = 2
        with self.assertRaises(policy.PolicyError): self.classify(report=report)
        report = copy.deepcopy(self.report)
        report["warnings"] = {"unmaintained": [{"package": "other"}]}
        with self.assertRaises(policy.PolicyError): self.classify(report=report)

    def test_changed_source_or_new_rust_file_invalidates_review(self):
        source = self.root / policy.PACKAGE_ROOT / "src/security.rs"
        original = source.read_bytes()
        source.write_bytes(original + b"\n// changed crypto\n")
        with self.assertRaisesRegex(policy.PolicyError, "reviewed_source_changed"): self.classify()
        source.write_bytes(original)
        (source.parent / "private_rsa.rs").write_text("// unreviewed module")
        with self.assertRaisesRegex(policy.PolicyError, "reviewed_source_changed"): self.classify()

    def test_new_or_renamed_or_wrong_source_consumer_invalidates_review(self):
        meta = copy.deepcopy(self.metadata)
        meta["packages"].append({"id": "another", "name": "another", "dependencies": [{"name": "rsa"}]})
        meta["resolve"]["nodes"].append({"id": "another", "deps": [{"name": "rsa", "pkg": "rsa"}]})
        with self.assertRaises(policy.PolicyError): self.classify(metadata=meta)
        meta = copy.deepcopy(self.metadata); meta["resolve"]["nodes"][0]["deps"][0]["name"] = "renamed"
        with self.assertRaises(policy.PolicyError): self.classify(metadata=meta)
        meta = copy.deepcopy(self.metadata); meta["packages"][0]["source"] = "git+unreviewed"
        with self.assertRaises(policy.PolicyError): self.classify(metadata=meta)

    def test_malformed_reports_and_execution_failure_are_not_clean_results(self):
        for report in [{}, {"vulnerabilities": None}, {"vulnerabilities": {"list": [], "count": 0, "found": True}}]:
            with self.assertRaises(policy.PolicyError): self.classify(report=report)
        clean = {"vulnerabilities": {"list": [], "count": 0, "found": False}, "warnings": {}}
        with self.assertRaises(policy.PolicyError): self.classify(report=clean, exit_code=1)
        self.assertEqual(self.classify(report=clean, exit_code=0)["status"], "pass")

    def test_unused_registry_test_declaration_is_not_a_resolved_consumer(self):
        meta = copy.deepcopy(self.metadata)
        meta["packages"].append({"id": "rcgen", "name": "rcgen", "source": policy.REGISTRY,
                                 "dependencies": [{"name": "rsa", "kind": "dev"}]})
        self.assertEqual(self.classify(metadata=meta)["status"], "pass_with_scoped_exception")
        meta["resolve"]["nodes"].append({"id": "rcgen", "deps": [{"name": "rsa", "pkg": "rsa"}]})
        with self.assertRaises(policy.PolicyError): self.classify(metadata=meta)

    def test_line_endings_do_not_change_the_reviewed_source(self):
        source = self.root / policy.PACKAGE_ROOT / "src/security.rs"
        source.write_bytes(source.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
        self.assertEqual(self.classify()["status"], "pass_with_scoped_exception")


if __name__ == "__main__":
    unittest.main()
