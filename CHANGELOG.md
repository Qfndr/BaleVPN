# Changelog

## 2.1.3 — 2026-10-23

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
