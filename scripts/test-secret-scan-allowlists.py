"""Exercise the real pinned scanner: reviewed literals never exempt whole files."""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import tomllib


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gitleaks", type=Path, required=True)
    args = parser.parse_args()
    scanner = args.gitleaks.resolve()
    repo = Path(__file__).resolve().parent.parent
    config = repo / ".gitleaks.toml"
    groups = [g for g in tomllib.loads(config.read_text())["allowlists"]
              if g.get("condition") == "AND"]
    assert len(groups) == 4
    paths = set()
    for group in groups:
        assert group["targetRules"] == ["generic-api-key"]
        assert group["regexTarget"] == "secret"
        assert group["regexes"] and group["paths"]
        for pattern in group["regexes"]:
            assert pattern.startswith("^") and pattern.endswith("$")
        for pattern in group["paths"]:
            assert pattern.startswith("^") and pattern.endswith("$")
            paths.add(re.sub(r"\\(.)", r"\1", pattern[1:-1]))
    with tempfile.TemporaryDirectory(prefix="secret-allowlist-regression-") as temp:
        root = Path(temp)
        source = root / "source"
        source.mkdir()
        (source / ".gitleaks.toml").write_bytes(config.read_bytes())
        # Each reviewed file must still reject a fresh high-entropy credential.
        for name in paths:
            file = source / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text('api_key = "' + secrets.token_hex(24) + '"\n')
        # A reviewed public literal in an unrelated file must also be detected.
        literal = re.sub(r"\\(.)", r"\1", groups[0]["regexes"][0][1:-1])
        (source / "unrelated.txt").write_text('api_key = "' + literal + '"\n')
        report = root / "redacted.json"
        result = subprocess.run(
            [str(scanner), "dir", ".", "--config", ".gitleaks.toml", "--redact",
             "--no-banner", "--report-format", "json", "--report-path", str(report)],
            cwd=source, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=60, env=os.environ.copy())
        assert result.returncode == 1, "Fresh credentials must fail scanning"
        findings = json.loads(report.read_text())
        detected = {row["File"].replace("\\", "/") for row in findings}
        assert detected == paths | {"unrelated.txt"}, "A path or literal was broadly exempted"
        assert all(row["RuleID"] == "generic-api-key" for row in findings)
        assert all(row["Secret"] == "REDACTED" for row in findings)
    print(f"PASS: new credentials detected in {len(paths)} reviewed files; literal outside approved paths detected")


if __name__ == "__main__":
    main()
