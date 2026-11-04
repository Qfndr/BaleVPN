# Native publication ordering

The native iGap endpoint enables `TunnelOptions.wait_for_track_published`.
Other callers, including Bale, retain the default `false` behavior.

When enabled, the signal loop starts before publication. Each locally requested
track must receive a matching `TrackPublished` response before the publisher
offer is sent. A single 10-second deadline covers local track setup, signaling
writes, the ACK and the initial publisher offer. Subscriber SDP/ICE processing
continues while waiting. The ACK confirms only local SFU track publication; it
does not authorize a peer, prove remote readiness or relax certificate pairing.

This ordering is present in the pinned iGap Web SDK's publication code. The SDK
also has a concurrent negotiation branch when publish-video codecs are enabled,
so this is not presented as a universal requirement or proof of the cause of
the earlier native startup failure. Shared-controller deferred startup had
previously succeeded. After this correction, one ordinary independent native
startup test also succeeded without that shared media-start barrier: both peers
authenticated and HTTPS download/upload payload hashes matched. This is a
single-host functional result; sustained performance, VPS operation and recovery
remain unverified. See `native-endpoint-live-evidence-2026-11-04.json`.

Failed or cancelled startup aborts its event task, closes both PeerConnections,
and explicitly aborts local WebSocket I/O. The latter uses an additive vendor
hook because normal graceful WebSocket closure may wait indefinitely for a
silent peer. The existing graceful `close` method remains unchanged.
An additional pending-stream guard covers cancellation while the initial Join
or Reconnect response is still awaited, before an Engine can own the stream.

Local wire tests exercise the real SignalClient and real subscriber SDP,
including missing/wrong ACKs, timeouts, cancellation, silent-peer cleanup, and
the unchanged default path. See the adjacent evidence JSON for exact scope.
