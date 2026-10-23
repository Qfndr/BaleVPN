"""Run transport integration tests with the desktop's exact dependency versions.

Cargo cannot test dev-dependencies of an external path dependency directly.
An isolated harness reuses the desktop lockfile without editing either workspace.
Use BALEVPN_BENCH_MIB=128 and BALEVPN_BENCH_TRIALS=8 for a longer comparison.
Dependencies must already be downloaded (the harness runs offline).
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tomllib


def main():
    repo = Path(__file__).resolve().parent.parent
    quote = lambda p: json.dumps(p.as_posix())
    original = repo / "bale-vpn-rust/Cargo.lock"
    with tempfile.TemporaryDirectory(prefix="balevpn-transport-") as directory:
        root = Path(directory)
        manifest = f'''[package]
name="balevpn-production-transport-tests"
version="0.0.0"
edition="2021"
publish=false
[dependencies]
lktunnel={{path={quote(repo / "lktunnel-rust/lktunnel")}}}
tokio={{version="1",features=["full"]}}
quinn={{version="0.11",default-features=false,features=["runtime-tokio","rustls-ring"]}}
rustls={{version="0.23",default-features=false,features=["std","ring"]}}
env_logger="0.11"
log="0.4"
[patch.crates-io]
livekit-api={{path={quote(repo / "vendor/livekit-api")}}}
[[test]]
name="authenticated_quic"
path={quote(repo / "lktunnel-rust/lktunnel/tests/authenticated_quic.rs")}
[[test]]
name="socks5_quic_e2e"
path={quote(repo / "lktunnel-rust/lktunnel/tests/socks5_quic_e2e.rs")}
[[test]]
name="reconnect_quic"
path={quote(repo / "lktunnel-rust/lktunnel/tests/reconnect_quic.rs")}
[profile.release]
opt-level=3
lto="thin"
codegen-units=1
panic="abort"
'''
        (root / "Cargo.toml").write_text(manifest, encoding="utf-8")
        shutil.copy2(original, root / "Cargo.lock")
        env = dict(os.environ)
        env.setdefault("CARGO_TARGET_DIR", str(repo / "bale-vpn-rust/target"))
        base = ["cargo", "--offline"]
        subprocess.run(base + ["test", "--manifest-path", str(root / "Cargo.toml"),
                               "--release", "--no-run"], check=True, env=env)
        def versions(path):
            return {(p["name"], p["version"], p.get("source"))
                    for p in tomllib.loads(path.read_text(encoding="utf-8"))["package"]}
        extra = versions(root / "Cargo.lock") - versions(original)
        if extra != {("balevpn-production-transport-tests", "0.0.0", None)}:
            raise RuntimeError(f"Harness changed production dependency versions: {sorted(extra)}")
        print("Verified: transport harness uses desktop dependency versions", flush=True)
        subprocess.run(base + ["test", "--manifest-path", str(root / "Cargo.toml"),
                               "--locked", "--release"] + sys.argv[1:], check=True, env=env)


if __name__ == "__main__":
    main()
