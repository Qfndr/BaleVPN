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
                        assert response.headers["Referrer-Policy"] == "no-referrer"
                        assert "connect-src 'self'" in response.headers["Content-Security-Policy"]
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
                for font in ("Vazirmatn.woff2", "InterVariable.woff2"):
                    with urllib.request.urlopen(base + "/fonts/" + font, timeout=5) as response:
                        assert response.headers.get_content_type() == "font/woff2"
                        assert response.read(4) == b"wOF2"
                try:
                    urllib.request.urlopen(base + "/fonts/unknown.woff2", timeout=5)
                except urllib.error.HTTPError as error:
                    assert error.code == 404
                else:
                    raise AssertionError("Unknown font path must not be served")
                assert request(base, "/config")["mode"] is None
                settings = request(base, "/settings")
                public_code = settings["publicCode"]
                assert public_code.startswith("bvp1:")
                preferences = settings["preferences"]
                assert preferences["secureMode"] is True
                preferences["serverCode"] = public_code
                preferences["clientCodes"] = [public_code]
                assert request(base, "/settings", preferences)["ok"] is True
                try:
                    request(base, "/settings", {**preferences, "secureMode": False}, origin="https://attacker.invalid")
                except urllib.error.HTTPError as error:
                    assert error.code == 403
                else:
                    raise AssertionError("Hostile Origin changed encryption settings")
                invalid_preferences = {**preferences, "serverCode": "bvp1:" + "☃" * 128}
                assert request(base, "/settings", invalid_preferences)["ok"] is False
                assert request(base, "/settings")["preferences"] == preferences
                diagnostics = request(base, "/diagnostics")
                for secret in ("token", "privateKey", "publicCode", "serverCode", "clientCodes", "phone"):
                    assert secret not in diagnostics
                # A second process must not migrate/replace keys in this data
                # directory, even if it tries another management port.
                with socket.socket() as probe:
                    probe.bind(("127.0.0.1", 0))
                    second_port = probe.getsockname()[1]
                second = subprocess.run([str(binary), "--headless", "--port", str(second_port),
                    "--config-dir", str(directory)], capture_output=True, timeout=10)
                assert second.returncode != 0
                assert request(base, "/settings")["publicCode"] == public_code
                # Refuse an occupied port before migrating credentials. Run
                # headless so a GUI build's user-facing startup error dialog
                # does not wait for input in unattended smoke tests.
                blocked = work / "blocked-start" / "data"
                occupied_port = base.rsplit(":", 1)[1]
                other = subprocess.run([str(binary), "--headless", "--port", occupied_port,
                    "--config-dir", str(blocked)], capture_output=True, timeout=20)
                assert other.returncode != 0
                assert not blocked.exists()
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
                    reply = request(base, "/server/call-privacy", {})
                    assert reply["ok"] is False and "Server mode" in reply["error"], reply
                state = request(base, "/state")
                assert state["traffic"]["processReceivedBytes"] == 0
                assert state["traffic"]["processSentBytes"] == 0
                assert state["traffic"]["sessionId"] is None
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
                assert request(base, "/settings")["publicCode"] == public_code
                assert request(base, "/settings")["preferences"] == preferences
                assert restored["mode"] == mode and restored["socks5_port"] == 1081
            print(f"PASS: fresh {mode} selection, repeated saves, restart, auth validation, Origin guard")
    report = {
        "version": version, "fresh_client_selection": True,
        "fresh_server_selection": True, "repeated_config_saves": True,
        "restart_persistence": True, "ui": True, "invalid_auth_rejected": True,
        "hostile_origin_rejected": True, "live_account_login_tested": False,
        "secure_defaults": True, "pairing_persistence": True,
        "malformed_pairing_rejected": True, "redacted_diagnostics": True,
        "client_privacy_change_rejected": True,
        "second_instance_rejected": True, "hostile_settings_downgrade_rejected": True,
    }
    if args.report:
        args.report.write_text(json.dumps(report, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
