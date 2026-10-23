"""Exercise a packaged desktop binary without an account or live OTP request.

Usage: python scripts/smoke-desktop.py PATH_TO_BINARY [--report report.json]
"""

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


@contextmanager
def running(binary, directory, work):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    with (work / "process.log").open("wb") as log:
        process = subprocess.Popen(
            [str(binary), "--headless", "--port", str(port),
             "--config-dir", str(directory)], stdout=log, stderr=log,
        )
        try:
            for _ in range(150):
                try:
                    with urllib.request.urlopen(base, timeout=1) as response:
                        html = response.read().decode()
                        assert "Verification code" in html
                        assert response.headers["X-Frame-Options"] == "DENY"
                    break
                except (urllib.error.URLError, TimeoutError):
                    if process.poll() is not None:
                        raise RuntimeError((work / "process.log").read_text(errors="replace"))
                    time.sleep(0.1)
            else:
                raise RuntimeError("Local UI did not become ready")
            yield base
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)


def request(base, path, body=None, origin=None):
    headers = {"Origin": origin or base}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    with urllib.request.urlopen(
        urllib.request.Request(base + path, data=data, headers=headers), timeout=5
    ) as response:
        return json.load(response)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    version = subprocess.check_output([str(binary), "--version"], text=True).strip()
    for mode in ("client", "server"):
        with tempfile.TemporaryDirectory(prefix="balevpn-fresh-install-") as temporary:
            work = Path(temporary)
            directory = work / "portable build" / "data"
            assert not directory.exists()
            with running(binary, directory, work) as base:
                assert request(base, "/config")["mode"] is None
                # Same requests the mode picker and settings screen make.
                assert request(base, "/config", {"mode": mode})["ok"] is True
                assert request(base, "/config", {"socks5Port": 1081})["ok"] is True
                saved = json.loads((directory / ".bale-vpn_config.json").read_text())
                assert saved["mode"] == mode and saved["socks5Port"] == 1081
                if os.name == "posix":
                    assert directory.stat().st_mode & 0o777 == 0o700
                    assert (directory / ".bale-vpn_config.json").stat().st_mode & 0o777 == 0o600
                assert request(base, "/config")["mode"] == mode
                if mode == "client":
                    # Even an explicit request cannot mutate this account's
                    # call privacy while the application is in Client mode.
                    try:
                        request(base, "/server/call-privacy", {})
                    except urllib.error.HTTPError as error:
                        reply = json.load(error)
                        assert "Server mode" in reply["error"], reply
                    else:
                        raise AssertionError("Client mode accepted a call privacy change")
                request(base, "/state")
                invalid = request(base, "/auth/start", {"phone": "0"})
                assert invalid["ok"] is False
                assert "valid international phone" in invalid["error"]
                try:
                    request(base, "/state", origin="https://attacker.invalid")
                except urllib.error.HTTPError as error:
                    assert error.code == 403
                else:
                    raise AssertionError("Hostile Origin accepted")
            with running(binary, directory, work) as base:
                restored = request(base, "/config")
                assert restored["mode"] == mode and restored["socks5_port"] == 1081
            print(f"PASS: fresh {mode} selection, repeated saves, restart, auth validation, Origin guard")
    report = {
        "version": version, "fresh_client_selection": True,
        "fresh_server_selection": True, "repeated_config_saves": True,
        "restart_persistence": True, "ui": True, "invalid_auth_rejected": True,
        "hostile_origin_rejected": True, "live_account_login_tested": False,
    }
    if args.report:
        args.report.write_text(json.dumps(report, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
