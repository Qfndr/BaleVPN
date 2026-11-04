"""Fail-closed disposition of raw cargo-audit output; never edits the raw report.

Scoped dispositions cover reviewed public-key-only RSA use and the exact
vendored GLib backport. Raw findings remain unchanged.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tomllib

ADVISORY = "RUSTSEC-2023-0071"
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
PACKAGE_ROOT = Path("igap-signaling-rust/igap-signaling")
INVENTORY = Path("scripts/rsa-public-only-review.json")
GLIB_ADVISORY = "RUSTSEC-2024-0429"


class PolicyError(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise PolicyError(reason)


def source_inventory(root):
    base = root / PACKAGE_ROOT
    require(base.is_dir() and not base.is_symlink(), "invalid_source_root")
    paths = set(base.rglob("*.rs")) | {base / "Cargo.toml", root / "igap-signaling-rust/Cargo.toml"}
    result = {}
    for path in sorted(paths):
        require(path.is_file() and not path.is_symlink(), "invalid_source_file")
        require(path.resolve().is_relative_to(root.resolve()), "source_outside_repository")
        data = path.read_bytes().replace(b"\r\n", b"\n")
        result[path.relative_to(root).as_posix()] = hashlib.sha256(data).hexdigest()
    return result


def verify_public_only(root, metadata):
    review = json.loads((root / INVENTORY).read_text(encoding="utf-8"))
    require(review.get("format") == 1 and review.get("advisory") == ADVISORY and
            review.get("rsaVersion") == "0.9.10", "invalid_review_manifest")
    require(source_inventory(root) == review.get("files"), "reviewed_source_changed")
    require(isinstance(metadata, dict), "metadata_required")
    require(Path(metadata.get("workspace_root", "")).resolve() == (root / "bale-vpn-rust").resolve(), "wrong_metadata_workspace")
    packages = metadata.get("packages")
    require(isinstance(packages, list), "invalid_metadata")
    rsa = [p for p in packages if p.get("name") == "rsa"]
    require(len(rsa) == 1 and rsa[0].get("version") == "0.9.10" and rsa[0].get("source") == REGISTRY, "unexpected_rsa_package")
    by_id = {p["id"]: p for p in packages}
    nodes = metadata.get("resolve", {}).get("nodes")
    require(isinstance(nodes, list), "resolved_metadata_required")
    consumers = set()
    for node in nodes:
        require(isinstance(node.get("deps"), list), "invalid_metadata_edges")
        for dep in node["deps"]:
            if dep.get("pkg") == rsa[0]["id"]:
                require(dep.get("name") == "rsa", "renamed_rsa_consumer")
                consumers.add(node["id"])
    require(len(consumers) == 1, "unexpected_rsa_consumers")
    consumer = by_id.get(next(iter(consumers)), {})
    require(consumer.get("name") == "igap-signaling" and consumer.get("source") is None and
            Path(consumer.get("manifest_path", "")).resolve() == (root / PACKAGE_ROOT / "Cargo.toml").resolve(), "unexpected_rsa_consumer")
    # Also catch disabled/target-specific declarations not represented by the
    # selected resolved edge set. They must not silently become another user.
    for package in packages:
        declared = [d for d in package.get("dependencies", []) if d.get("name") == "rsa"]
        # Registry dependency manifests include their own test dependencies,
        # although Cargo does not build those tests for this application.
        unused_registry_test = (package.get("source") == REGISTRY and
                                package["id"] not in metadata.get("workspace_members", []) and
                                all(d.get("kind") == "dev" for d in declared))
        require(not declared or package["id"] == consumer["id"] or unused_registry_test,
                "additional_rsa_declaration")
    lock = tomllib.loads((root / "bale-vpn-rust/Cargo.lock").read_text(encoding="utf-8"))
    locked = [p for p in lock.get("package", []) if p.get("name") == "rsa"]
    require(len(locked) == 1 and locked[0].get("version") == "0.9.10" and
            locked[0].get("source") == REGISTRY and locked[0].get("checksum") == review.get("rsaChecksum"), "unreviewed_rsa_lock_entry")


def classify(report, workspace, root, metadata=None, audit_exit_code=0):
    require(isinstance(report, dict), "invalid_audit_report")
    vulnerabilities = report.get("vulnerabilities")
    require(isinstance(vulnerabilities, dict), "invalid_audit_report")
    findings = vulnerabilities.get("list")
    require(isinstance(findings, list) and type(vulnerabilities.get("count")) is int and
            type(vulnerabilities.get("found")) is bool and vulnerabilities["count"] == len(findings) and
            vulnerabilities["found"] == bool(findings), "inconsistent_audit_report")
    warnings = report.get("warnings", {})
    require(isinstance(warnings, dict), "invalid_audit_warnings")
    scoped = []
    glib_warnings = []
    for kind, items in warnings.items():
        require(isinstance(items, list), "invalid_audit_warnings")
        for item in items:
            require(isinstance(item, dict), "invalid_audit_warnings")
            package, advisory = item.get("package", {}), item.get("advisory", {})
            require(isinstance(package, dict) and isinstance(advisory, dict), "invalid_audit_warnings")
            require(workspace == "bale-vpn-rust" and kind == "unsound" and
                    item.get("kind") == "unsound" and advisory.get("id") == GLIB_ADVISORY and
                    advisory.get("package") == "glib" and package.get("name") == "glib" and
                    package.get("version") == "0.18.5" and package.get("source") is None,
                    "audit_warnings_require_review")
            glib_warnings.append(item)
    if glib_warnings:
        require(len(glib_warnings) == 1, "duplicate_glib_warning")
        spec = importlib.util.spec_from_file_location("glib_backport_proof", Path(__file__).with_name("verify-glib-backport.py"))
        proof_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(proof_module)
        try:
            proof = proof_module.verify_glib_backport(root, metadata)
        except ValueError as error:
            raise PolicyError(str(error)) from error
        scoped.append({"advisory": GLIB_ADVISORY, "package": "glib", "version": "0.18.5",
                       "disposition": "fixed-in-reviewed-backport", "upstreamPatched": False,
                       "sourceProof": proof,
                       "requiredValidation": "Linux optimized test_variant_str_iter in the binary workflow",
                       "limitation": "Raw warning retained; only this exact active source backport is covered."})
    require(not report.get("error"), "audit_execution_failed")
    require(audit_exit_code == (1 if findings else 0), "audit_execution_failed")
    if not findings:
        return {"status": "pass_with_scoped_exception" if scoped else "pass",
                "rawVulnerabilityCount": 0, "scopedExceptions": scoped}
    require(workspace == "bale-vpn-rust" and len(findings) == 1, "unapproved_vulnerability")
    item = findings[0]
    require(isinstance(item, dict), "invalid_audit_finding")
    advisory, package = item.get("advisory", {}), item.get("package", {})
    require(isinstance(advisory, dict) and isinstance(package, dict), "invalid_audit_finding")
    require(advisory.get("id") == ADVISORY and advisory.get("package") == "rsa" and
            package.get("name") == "rsa" and package.get("version") == "0.9.10" and
            package.get("source") == REGISTRY, "unapproved_vulnerability")
    verify_public_only(root, metadata)
    scoped.append({"advisory": ADVISORY, "package": "rsa", "version": "0.9.10",
                "consumer": "igap-signaling", "upstreamPatched": False,
                "basis": "Exact reviewed source uses RSA public-key encryption; private RSA operations occur only in tests.",
                "limitation": "Not a repaired dependency or a general exemption; any source/consumer change requires new review."})
    return {"status": "pass_with_scoped_exception", "rawVulnerabilityCount": 1,
            "scopedExceptions": scoped}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--metadata", type=Path)
    parser.add_argument("--audit-exit-code", type=int, required=True)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = classify(json.loads(args.report.read_text(encoding="utf-8")), args.workspace, args.repo_root.resolve(),
                          json.loads(args.metadata.read_text(encoding="utf-8")) if args.metadata else None, args.audit_exit_code)
    except (PolicyError, OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        reason = str(error) if isinstance(error, PolicyError) else "audit_policy_input_error"
        result = {"status": "fail", "reason": reason}
    text = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    print(text, end="")
    return 1 if result["status"] == "fail" else 0


if __name__ == "__main__":
    sys.exit(main())
