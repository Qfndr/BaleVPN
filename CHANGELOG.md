# Changelog

## 2.1.4 — 2026-10-23

- Match the current Bale login request: default delivery, Telegram Gateway capability and six-digit OTP support instead of forcing SMS.
- Use one UTF-8 UUID device identity per auth client, including retries.
- Normalize Iranian local mobile numbers and Persian/Arabic digits; reject invalid input before network access.
- Reject missing login transactions and surface header-only gRPC errors instead of falsely reporting code delivery.
- Show the server-selected delivery channel and restore desktop retry after the server cooldown.
- Report Android start-auth errors through the coroutine error path.
- Add real HTTP login fixtures, browser auth regression tests and an opt-in live endpoint check using invalid phone 0.


## 2.1.3 — 2026-10-23

- Fix the contacts refresh button calling a nonexistent API endpoint.
- Fix fresh-install configuration defaults, saved HTTP port precedence, and `--config-dir` persistence.
- Save credentials through exclusive temporary files and atomic replacement; preserve malformed configuration for recovery.
- Reject cross-origin management requests and DNS-rebinding hostnames; disable framing of the management UI.
- Escape peer identifiers in UI text and event handlers to prevent stored script injection.
- Bind the desktop SOCKS5/HTTP CONNECT proxy to loopback by default; keep Android LAN sharing explicit.
- Reject private IPv4 destinations carried in IPv4-mapped IPv6 addresses.
- Reject overflowing protobuf values, invalid gRPC status codes, unsupported frame flags, and truncated response headers.
- Restart the active tunnel after changing the SOCKS5 port or NAT mode; reject invalid management settings.
- Disable Android credential backup and cleartext application traffic.
- Update TLS, QUIC, HTTP/2, Tokio, and certificate-root dependencies; remove unused LiveKit JWT/RSA features.
- Align desktop and Android development build versions and add continuous security regression checks.
