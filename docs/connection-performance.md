# Connection setup and recovery

The connection path now removes two avoidable waits and retries alternative
destination addresses when the first route is unusable.

## Bale signaling

- Handshake readiness is a watch notification. Desktop startup continues as soon
  as it receives readiness, instead of waiting for the next 250 ms polling tick.
  The existing 10-second startup wait remains bounded.
- Reconnection starts after one second. Consecutive failures back off through
  2, 4, 8, 16 and 30 seconds. A successful handshake resets this history, so a
  brief later interruption does not inherit a 30-second outage delay.
- DNS, TCP, TLS and the WebSocket upgrade have a combined 15-second timeout.
  TCP_NODELAY is enabled for small signaling messages. TLS verification stays
  enabled.

## Proxy destinations

SOCKS5 and HTTP CONNECT share a staggered connection race. DNS results are
deduplicated, filtered against the existing private-address restrictions, and
interleaved by IP family while retaining each family's resolver order.

The first destination starts immediately. Another address can start after
250 ms, or immediately after an explicit connection failure. The first
successful connection wins; dropping the other futures closes their sockets.
A healthy first address incurs no fallback delay.

Resource and time limits are explicit:

| Operation | Limit |
| --- | --- |
| DNS lookup | 10 seconds |
| One TCP connection attempt | 10 seconds |
| Entire destination connection race, after DNS | 20 seconds |
| Simultaneous connection attempts per proxy request | 4 |

Each dial uses an already-filtered numeric socket address. No second hostname
lookup occurs between the address check and connection.

## Validation

Virtual-time tests cover a stalled IPv6 attempt followed by a successful IPv4
fallback at 250 ms, immediate success without a fallback wait, immediate retry
after refusal, duplicate suppression, private-address filtering, cancellation,
the concurrency cap, readiness notifications and reconnection backoff reset.

The real local TCP/SOCKS5/QUIC round-trip tests also pass. These tests establish
the scheduling and transport behavior; they are not a measurement of internet
throughput or a two-account Bale connection benchmark.

```sh
cargo test --manifest-path lktunnel-rust/Cargo.toml --locked --workspace
cargo test --manifest-path bale-signaling-rust/Cargo.toml --locked --lib
cargo test --manifest-path bale-vpn-rust/Cargo.toml --locked --no-default-features
node --test scripts/test-ui-security.cjs
```
