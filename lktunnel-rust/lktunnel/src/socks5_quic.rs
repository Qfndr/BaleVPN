//! SOCKS5 / HTTP-CONNECT ↔ QUIC bridge.
//!
//! Client-side: the LAN-facing peer runs a single listener that
//! auto-detects the proxy protocol from the first byte — `0x05` is
//! SOCKS5, anything else is treated as an HTTP `CONNECT` request (the
//! two never collide: HTTP opens with an ASCII method verb). Each
//! accepted connection is mapped to a freshly-opened QUIC
//! bidirectional stream on the QUIC connection that runs over this
//! tunnel. The stream's first bytes carry a SOCKS5-style target
//! envelope; the rest is raw application bytes shuttled between the
//! proxy client TCP and the QUIC stream. Only the CONNECT method is
//! handled on the HTTP side (tunnelling — i.e. all HTTPS); plain
//! forward-proxying of `http://` requests is not supported, point
//! such clients at the SOCKS5 side instead.
//!
//! Server-side: the peer that bridges to the internet runs a QUIC
//! stream acceptor. For each incoming stream it reads the target
//! envelope, opens a real TCP connection on the host network, and
//! byte-copies between the QUIC stream and the host TCP.
//!
//! ## Wire format on each QUIC stream
//!
//! ```text
//!   ┌──────┬───────────────────┬──────────┐
//!   │ atyp │ addr (4/16/N+1)   │ port (2) │
//!   └──────┴───────────────────┴──────────┘
//!     u8     IPv4=4, IPv6=16,      u16 BE
//!            or 1 byte len + N
//! ```
//!
//! atyp matches SOCKS5's `ATYP` values: 0x01 IPv4, 0x03 domain,
//! 0x04 IPv6. After the envelope it's straight TCP-like bytes both
//! ways until either end closes the stream.

use std::io;
use std::collections::{HashSet, VecDeque};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::AbortHandle;
use tokio::time::{Duration, Instant};
use futures_util::{stream::FuturesUnordered, StreamExt};

use crate::LkTunnel;
use crate::quic_tunnel::QuicServer;

// ── SOCKS5 protocol constants ─────────────────────────────────────────

const SOCKS_VER: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_NO_ACCEPTABLE: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;
const RSV: u8 = 0x00;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const REP_SUCCEEDED: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_RULESET_BLOCKED: u8 = 0x02;
const REP_NETWORK_UNREACHABLE: u8 = 0x03;
const REP_HOST_UNREACHABLE: u8 = 0x04;
const REP_CONNECTION_REFUSED: u8 = 0x05;
const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const DNS_TIMEOUT: Duration = Duration::from_secs(10);
const ADDRESS_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DESTINATION_CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const ADDRESS_FALLBACK_DELAY: Duration = Duration::from_millis(250);
const MAX_PARALLEL_DIALS: usize = 4;
/// A protocol endpoint, never DNS-resolved or routed to arbitrary loopback ports.
pub const BOND_HOST: &str = "bond.balevpn.invalid";
static BOND_GATEWAY: Mutex<Option<(SocketAddr,[u8;32])>> = Mutex::new(None);
/// Installed only by the owning application. Credentials never cross the tunnel.
pub fn set_bond_gateway(value:Option<(SocketAddr,[u8;32])>) { *BOND_GATEWAY.lock()=value.filter(|(addr,_)|addr.ip().is_loopback()); }
fn bond_target(target:&Target)->bool { matches!(target,Target::Domain(host,443) if host==BOND_HOST) }

/// Process-global SSRF filter toggle. Defaults to `true` in
/// production. Integration tests that need to connect to a loopback
/// echo server call [`set_ssrf_filter_enabled(false)`] to disable.
/// Not exposed in any public API surface — only the integration
/// test reaches into this via `#[doc(hidden)]`.
static SSRF_FILTER_ENABLED: AtomicBool = AtomicBool::new(true);

/// Toggle the SSRF guard. **Tests only** — disabling this in
/// production is a security regression. The `#[doc(hidden)]` attribute
/// keeps it out of the generated docs.
#[doc(hidden)]
pub fn set_ssrf_filter_enabled(enabled: bool) {
    SSRF_FILTER_ENABLED.store(enabled, Ordering::Relaxed);
}

/// True if the destination should be refused. Honours the
/// `SSRF_FILTER_ENABLED` toggle.
fn ssrf_blocked(ip: IpAddr) -> bool {
    SSRF_FILTER_ENABLED.load(Ordering::Relaxed)
        && crate::nat::filter::is_blocked_dst(ip)
}

/// Is this `accept()` error something we can recover from with a
/// short sleep, or is the listening socket itself dead? Resource-
/// exhaustion errnos (too many open fds in the process or on the
/// host) are transient — backing off lets the system recover.
fn is_transient_accept_error(e: &io::Error) -> bool {
    if matches!(e.kind(), io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
        | io::ErrorKind::ConnectionAborted | io::ErrorKind::ConnectionReset
        | io::ErrorKind::NetworkDown | io::ErrorKind::NetworkUnreachable
        | io::ErrorKind::HostUnreachable | io::ErrorKind::OutOfMemory) { return true; }
    #[cfg(windows)]
    // WinSock uses WSA* numbers, not the C runtime errno values below.
    // https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2
    if matches!(e.raw_os_error(), Some(10024 | 10050 | 10051 | 10052 | 10053 | 10054 | 10055 | 10064 | 10065)) { return true; }
    matches!(e.raw_os_error(), Some(libc::EMFILE) | Some(libc::ENFILE)
                              | Some(libc::ENOBUFS) | Some(libc::ENOMEM)
                              | Some(libc::EAGAIN) | Some(libc::EINTR))
}

/// Map an `io::Error` from the host-TCP path to a SOCKS5 reply code.
/// Falls back to GENERAL_FAILURE for anything not in the standard
/// taxonomy.
fn io_err_to_socks5_rep(e: &io::Error) -> u8 {
    match e.kind() {
        io::ErrorKind::PermissionDenied   => REP_RULESET_BLOCKED,
        io::ErrorKind::ConnectionRefused  => REP_CONNECTION_REFUSED,
        io::ErrorKind::HostUnreachable    => REP_HOST_UNREACHABLE,
        io::ErrorKind::NetworkUnreachable => REP_NETWORK_UNREACHABLE,
        io::ErrorKind::NotFound           => REP_HOST_UNREACHABLE, // DNS NXDOMAIN
        _                                 => REP_GENERAL_FAILURE,
    }
}

/// Target the SOCKS5 client wants to reach. Domain is left
/// unresolved here so DNS happens on the *peer* (the one with the
/// uncensored upstream) rather than locally.
#[derive(Debug, Clone)]
pub(crate) enum Target {
    Ip(IpAddr, u16),
    Domain(String, u16),
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Target::Ip(ip, port)     => write!(f, "{ip}:{port}"),
            Target::Domain(d, port)  => write!(f, "{d}:{port}"),
        }
    }
}

// ── Errors ────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum Socks5Error {
    AlreadyEnabled,
    Bind(io::Error),
    Quic(crate::quic_tunnel::QuicEndpointError),
}

impl std::fmt::Display for Socks5Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyEnabled => f.write_str("socks5 server already enabled"),
            Self::Bind(e)        => write!(f, "socks5 bind: {e}"),
            Self::Quic(e)        => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Socks5Error {}

impl From<crate::quic_tunnel::QuicEndpointError> for Socks5Error {
    fn from(e: crate::quic_tunnel::QuicEndpointError) -> Self { Self::Quic(e) }
}

// ── Handles stashed on TunnelInner ────────────────────────────────────

/// Client-side handle: aborts the SOCKS5 listener task on drop /
/// `disable_socks5_server`. The QUIC client lives separately on
/// `TunnelInner::quic_client` and persists across SOCKS5 toggles.
pub(crate) struct Socks5Handle {
    /// Aborts the SOCKS5 accept loop. New incoming TCP connects fail
    /// after this fires; in-flight per-conn pump tasks are aborted
    /// separately via [`Self::conn_aborts`].
    pub(crate) listener_abort: AbortHandle,
    /// Local socket the listener is bound to — useful for surfacing
    /// in logs / UI.
    pub(crate) local_addr: SocketAddr,
    /// Per-connection pump task abort handles, populated by the
    /// accept loop on every new connection. `disable_socks5_server`
    /// walks this and aborts each so in-flight SOCKS5 streams die
    /// immediately — without this, apps holding HTTP keepalive
    /// sockets through the proxy would keep proxying after the
    /// user flipped the toggle off. Pruned of finished entries on
    /// every push so a long-lived listener doesn't accumulate
    /// dead handles unbounded.
    pub(crate) conn_aborts: Arc<Mutex<Vec<AbortHandle>>>,
}

impl Socks5Handle {
    /// Abort every in-flight per-conn pump task and clear the slot.
    /// Called from [`crate::LkTunnel::disable_socks5_server`] after
    /// `listener_abort.abort()` so existing SOCKS5 connections drop
    /// in lockstep with the listener.
    pub(crate) fn abort_all_conns(&self) {
        let mut g = self.conn_aborts.lock();
        let n = g.len();
        for a in g.drain(..) { a.abort(); }
        if n > 0 { log::info!("socks5: aborted {n} in-flight connections"); }
    }
}

/// Server-side handle: ties the QUIC stream-acceptor task lifetime
/// to the QUIC server endpoint.
pub(crate) struct QuicServerHandle {
    /// Aborts the per-connection accept loop.
    pub(crate) accept_abort: AbortHandle,
    /// Keeps the endpoint alive. Dropping closes incoming.
    #[allow(dead_code)]
    pub(crate) quic_server: QuicServer,
}

// ── Public entry points (pub(crate)) ──────────────────────────────────

/// Bring up the SOCKS5 listener. Each accept reads the *current*
/// `QuicClient` from `TunnelInner::quic_client` so the listener
/// transparently follows the reconnect keeper — a connection that
/// drops mid-session recovers without listener restart; old SOCKS5
/// streams die at the TCP level (their apps see a disconnect), new
/// SOCKS5 client requests pick up the freshly-reconnected QUIC.
pub(crate) async fn enable_listener(
    tunnel: Arc<LkTunnel>,
    bind_ip: Ipv4Addr,
    port:   u16,
) -> Result<Socks5Handle, Socks5Error> {
    // Use TcpSocket so we can set SO_REUSEADDR before bind.
    // Without it, a rapid disconnect→reconnect cycle hits
    // EADDRINUSE because the OS hasn't released the previous
    // listener's socket from TIME_WAIT / TCP-shutdown reap yet.
    // Observed on every client mode reconnect: session 1's
    // listener task gets aborted, but the bound socket lingers
    // a few seconds and session 2's bind fails until then.
    let bind_addr = SocketAddr::new(IpAddr::V4(bind_ip), port);
    let socket = tokio::net::TcpSocket::new_v4().map_err(Socks5Error::Bind)?;
    socket.set_reuseaddr(true).map_err(Socks5Error::Bind)?;
    socket.bind(bind_addr).map_err(Socks5Error::Bind)?;
    let listener = socket.listen(1024).map_err(Socks5Error::Bind)?;
    let local_addr = listener.local_addr().map_err(Socks5Error::Bind)?;
    log::info!("socks5: listening on {local_addr}");

    let weak_inner = std::sync::Arc::downgrade(&tunnel);
    let conn_aborts: Arc<Mutex<Vec<AbortHandle>>> = Arc::new(Mutex::new(Vec::new()));
    let conn_aborts_for_loop = conn_aborts.clone();
    let task = crate::runtime().spawn(async move {
        loop {
            match listener.accept().await {
                Ok((tcp, peer)) => {
                    log::debug!("socks5: accepted {peer}");
                    // Handle each connection in its own task so the accept
                    // loop stays responsive. The task snapshots the current
                    // QUIC connection (which may be a freshly-reconnected one
                    // if the keeper rotated). If QUIC isn't up yet — enable
                    // binds the listener before the background handshake
                    // finishes, or the keeper is mid-reconnect — wait briefly
                    // rather than refusing, so a client connecting right after
                    // enable doesn't get a spurious failure.
                    let weak  = weak_inner.clone();
                    let join  = crate::runtime().spawn(async move {
                        let mut conn = None;
                        for _ in 0..100 {  // up to ~10s (100 × 100 ms)
                            let Some(inner) = weak.upgrade() else { return };
                            if let Some(c) = inner.quic_client.lock().clone().filter(|c| c.connection.close_reason().is_none()) {
                                conn = Some(c.connection.clone());
                                break;
                            }
                            drop(inner);
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        }
                        let Some(conn) = conn else {
                            log::warn!("socks5: no QUIC connection after wait — refusing {peer}");
                            drop(tcp);
                            return;
                        };
                        let authenticated=weak.upgrade().is_some_and(|inner|inner.options.authenticated);
                        if let Err(e) = pump_conn(tcp, conn, authenticated).await {
                            log::debug!("socks5: per-conn ended: {e}");
                        }
                    });
                    // Register this connection's abort handle so
                    // `disable_socks5_server` can kill it. Prune
                    // finished entries while we hold the lock so the
                    // vec stays bounded over a long-lived listener.
                    let mut g = conn_aborts_for_loop.lock();
                    g.retain(|a| !a.is_finished());
                    g.push(join.abort_handle());
                }
                Err(e) if is_transient_accept_error(&e) => {
                    log::warn!("socks5: transient accept err {e} — backing off 250ms");
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                    continue;
                }
                Err(e) => {
                    log::warn!("socks5: fatal accept err: {e} — listener exiting");
                    if let Some(inner) = weak_inner.upgrade() {
                        inner.fail_transport("SOCKS5 listener stopped. Press Connect to rebuild the session.".into());
                    }
                    break;
                }
            }
        }
    });

    Ok(Socks5Handle {
        listener_abort: task.abort_handle(),
        local_addr,
        conn_aborts,
    })
}

/// Server-side: spawn the QUIC stream-acceptor that bridges each
/// incoming stream to a real host TCP socket. Caller is responsible
/// for keeping the returned handle alive.
pub(crate) fn spawn_server_acceptor(server: QuicServer, authenticated:bool) -> QuicServerHandle {
    let endpoint = server.endpoint.clone();
    let sessions = server.authenticated_sessions.clone();
    let task = crate::runtime().spawn(async move {
        loop {
            let Some(incoming) = endpoint.accept().await else {
                log::info!("socks5/server: quic endpoint closed");
                break;
            };
            let sessions=sessions.clone();
            crate::runtime().spawn(async move {
                let connection = match incoming.await {
                    Ok(c) => c,
                    Err(e) => { log::warn!("socks5/server: incoming err: {e}"); return; }
                };
                struct Guard(Arc<std::sync::atomic::AtomicUsize>);
                impl Drop for Guard {fn drop(&mut self){self.0.fetch_sub(1,Ordering::Relaxed);}}
                sessions.fetch_add(1,Ordering::Relaxed);let _guard=Guard(sessions);
                log::info!("socks5/server: quic connection established");
                loop {
                    let (send, recv) = match connection.accept_bi().await {
                        Ok(s) => s,
                        Err(quinn::ConnectionError::ApplicationClosed(_))
                        | Err(quinn::ConnectionError::ConnectionClosed(_))
                        | Err(quinn::ConnectionError::TimedOut)
                        | Err(quinn::ConnectionError::LocallyClosed)
                        // EndpointStopping covers the case where
                        // the LkTunnel is dropping its QUIC
                        // endpoint as part of normal teardown
                        // — the accept loop sees "endpoint
                        // driver future was dropped" which is a
                        // routine shutdown event, not a real
                        // error.
                        | Err(quinn::ConnectionError::Reset)
                        | Err(quinn::ConnectionError::TransportError(_)) => {
                            log::info!("socks5/server: connection closed");
                            break;
                        }
                        Err(quinn::ConnectionError::VersionMismatch) => {
                            log::warn!("socks5/server: accept_bi: version mismatch");
                            break;
                        }
                        Err(e) => {
                            log::debug!("socks5/server: accept_bi: {e}");
                            break;
                        }
                    };
                    crate::runtime().spawn(async move {
                        if let Err(e) = handle_quic_stream(send, recv,authenticated).await {
                            log::debug!("socks5/server: stream ended: {e}");
                        }
                    });
                }
            });
        }
    });
    QuicServerHandle {
        accept_abort: task.abort_handle(),
        quic_server: server,
    }
}

// ── Per-connection / per-stream pumps ─────────────────────────────────

/// Which proxy protocol a client connection spoke. Both end up at the
/// same QUIC dispatch; they differ only in how the local handshake is
/// parsed and how the connect result is reported back to the client.
#[derive(Clone, Copy)]
enum FrontProto { Socks5, HttpConnect }

impl FrontProto {
    /// The bytes to write back to the proxy client for a given server
    /// status (a SOCKS5 `REP_*` code). `REP_SUCCEEDED` means the byte
    /// copy is about to begin.
    fn reply(self, status: u8) -> Vec<u8> {
        match self {
            FrontProto::Socks5 => {
                vec![SOCKS_VER, status, RSV, ATYP_IPV4, 0, 0, 0, 0, 0, 0]
            }
            FrontProto::HttpConnect => http_connect_reply(status).to_vec(),
        }
    }
}

/// Per-connection entry point. Peeks the first byte (without consuming
/// it) to pick the proxy protocol, then hands off to the matching
/// front-end. `0x05` is the SOCKS5 version byte; every HTTP request
/// starts with an ASCII method verb, so there is no overlap.
async fn pump_conn(tcp: TcpStream, conn: quinn::Connection, authenticated:bool) -> io::Result<()> {
    let mut first = [0u8; 1];
    let n = tcp.peek(&mut first).await?;
    if n == 0 {
        return Ok(());  // client closed before sending anything
    }
    if first[0] == SOCKS_VER {
        pump_socks5_conn(tcp, conn,authenticated).await
    } else {
        pump_http_connect(tcp, conn,authenticated).await
    }
}

/// SOCKS5 front-end: handshake → `Target` → shared QUIC dispatch.
async fn pump_socks5_conn(
    mut tcp: TcpStream,
    conn:    quinn::Connection,
    authenticated:bool,
) -> io::Result<()> {
    let target = match read_socks5_request(&mut tcp).await {
        Ok(t) => t,
        Err(e) => {
            let _ = tcp.write_all(&[
                SOCKS_VER, REP_GENERAL_FAILURE, RSV, ATYP_IPV4,
                0, 0, 0, 0, 0, 0,
            ]).await;
            return Err(e);
        }
    };
    log::debug!("socks5: dispatching {target}");
    dispatch_target(tcp, conn, target, FrontProto::Socks5,authenticated).await
}

/// HTTP-CONNECT front-end: parse the `CONNECT host:port` request line
/// → `Target` → shared QUIC dispatch. Only the CONNECT method is
/// supported; anything else is answered with `400 Bad Request`.
async fn pump_http_connect(
    mut tcp: TcpStream,
    conn:    quinn::Connection,
    authenticated:bool,
) -> io::Result<()> {
    let target = match read_http_connect_request(&mut tcp).await {
        Ok(t) => t,
        Err(e) => {
            let _ = tcp.write_all(
                b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n",
            ).await;
            return Err(e);
        }
    };
    log::debug!("http-connect: dispatching {target}");
    dispatch_target(tcp, conn, target, FrontProto::HttpConnect,authenticated).await
}

/// Shared back half for both front-ends: open a QUIC bidi stream →
/// send the target envelope → **wait for the server's 1-byte status**
/// → report it back to the proxy client in its own dialect → byte-copy
/// both directions.
///
/// The server status byte uses SOCKS5's own `REP_*` codes so we can
/// translate verbatim without a mapping table:
///   0x00 = SUCCEEDED
///   0x01 = general failure
///   0x02 = blocked by ruleset (our SSRF guard)
///   0x03 = network unreachable
///   0x04 = host unreachable
///   0x05 = connection refused
///   0x07 = command not supported  (used here for "blocked target")
async fn dispatch_target(
    mut tcp: TcpStream,
    conn:    quinn::Connection,
    target:  Target,
    proto:   FrontProto,
    authenticated:bool,
) -> io::Result<()> {
    if bond_target(&target)&&!authenticated {tcp.write_all(&proto.reply(REP_RULESET_BLOCKED)).await?;return Ok(());}
    let (mut send, mut recv) = conn.open_bi().await
        .map_err(|e| io::Error::new(io::ErrorKind::ConnectionReset,
                                    format!("quic open_bi: {e}")))?;
    let env = encode_target(&target);
    send.write_all(&env).await
        .map_err(|e| io::Error::new(io::ErrorKind::Other,
                                    format!("quic write env: {e}")))?;

    // Wait for the server's 1-byte status BEFORE replying to the proxy
    // client. Reading from a quinn::RecvStream blocks until bytes
    // arrive or the stream resets; if the server fails before writing,
    // the read errors and we report failure faithfully.
    let mut status = [0u8; 1];
    let status_byte = match recv.read_exact(&mut status).await {
        Ok(()) => status[0],
        Err(_) => REP_GENERAL_FAILURE,  // server stream died → fail
    };
    tcp.write_all(&proto.reply(status_byte)).await?;
    if status_byte != REP_SUCCEEDED {
        // No host TCP on the other end — close the stream cleanly
        // and return without spawning the byte-copy tasks.
        let _ = send.finish();
        return Ok(());
    }

    let (mut tcp_r, mut tcp_w) = tcp.into_split();
    let to_quic = async move {
        let _ = tokio::io::copy(&mut tcp_r, &mut send).await;
        let _ = send.finish();
    };
    let from_quic = async move {
        let _ = tokio::io::copy(&mut recv, &mut tcp_w).await;
        let _ = tcp_w.shutdown().await;
    };
    tokio::join!(to_quic, from_quic);
    Ok(())
}

/// Server side: read target envelope, resolve, gate, dial,
/// **write a 1-byte SOCKS5-style status** so the client can reply to
/// its own SOCKS5 caller with a faithful code (not the optimistic
/// "succeeded then immediately closed" we used to send), then
/// byte-copy.
async fn handle_quic_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    authenticated:bool,
) -> io::Result<()> {
    let target = read_target(&mut recv).await?;
    if bond_target(&target){
        let gateway=if authenticated{*BOND_GATEWAY.lock()}else{None};
        let Some((address,key))=gateway else{let _=send.write_all(&[REP_RULESET_BLOCKED]).await;let _=send.finish();return Ok(());};
        let result=tokio::time::timeout(Duration::from_secs(3),async{
            let mut stream=TcpStream::connect(address).await?;stream.set_nodelay(true)?;
            stream.write_all(&key).await?;if stream.read_u8().await?!=0{return Err(io::Error::other("Bond relay disabled"));}Ok::<_,io::Error>(stream)
        }).await;
        let Ok(Ok(stream))=result else{let _=send.write_all(&[REP_RULESET_BLOCKED]).await;let _=send.finish();return Ok(());};
        send.write_all(&[REP_SUCCEEDED]).await?;
        let(mut read,mut write)=stream.into_split();
        tokio::join!(async{let _=tokio::io::copy(&mut recv,&mut write).await;let _=write.shutdown().await;},async{let _=tokio::io::copy(&mut read,&mut send).await;let _=send.finish();});return Ok(());
    }
    log::debug!("socks5/server: target {target}");

    let connect_result=connect_target(&target).await;
    let (addr, tcp) = match connect_result {
        Ok(pair) => {if send.write_all(&[REP_SUCCEEDED]).await.is_err(){return Ok(());}pair},
        Err(e) => {let status=io_err_to_socks5_rep(&e);let _=send.write_all(&[status]).await;let _=send.finish();return Err(e);}
    };
    log::debug!("socks5/server: connected to {addr}");
    let (mut tcp_r, mut tcp_w) = tcp.into_split();
    tokio::join!(async{let _=tokio::io::copy(&mut recv,&mut tcp_w).await;let _=tcp_w.shutdown().await;},async{let _=tokio::io::copy(&mut tcp_r,&mut send).await;let _=send.finish();});Ok(())
}
/// Same DNS, address racing and SSRF checks as ordinary proxy requests.
pub async fn connect_public_target(envelope:&[u8])->io::Result<TcpStream>{
    let mut bytes=envelope;let target=read_target(&mut bytes).await?;
    if !bytes.is_empty()||bond_target(&target){return Err(io::Error::new(io::ErrorKind::PermissionDenied,"Invalid bond destination"));}
    let addresses=resolve_target(&target).await?.into_iter().filter(|a|!crate::nat::filter::is_blocked_dst(a.ip())).collect();
    Ok(connect_public_addresses(addresses,|addr|TcpStream::connect(addr)).await?.1)
}
async fn connect_target(target:&Target)->io::Result<(SocketAddr,TcpStream)>{
    connect_public_addresses(resolve_target(target).await?,|addr|TcpStream::connect(addr)).await
}
async fn resolve_target(target:&Target)->io::Result<Vec<SocketAddr>>{
    // Keep every DNS candidate. Previously only the first address was tried,
    // so a broken IPv6 route (or one failed backend) made the whole domain fail.
    let addr_result: io::Result<Vec<SocketAddr>> = match &target {
        Target::Ip(ip, port) => Ok(vec![SocketAddr::new(*ip, *port)]),
        Target::Domain(name, port) => {
            match tokio::time::timeout(DNS_TIMEOUT,
                tokio::net::lookup_host((name.as_str(), *port))).await {
                Ok(Ok(iter)) => Ok(iter.collect()),
                Ok(Err(e)) => Err(io::Error::new(io::ErrorKind::NotFound,
                                             format!("dns: {e}"))),
                Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "dns: lookup timed out")),
            }
        }
    };

    addr_result
}

/// Staggered, bounded address racing. Start the other IP family after 250ms
/// instead of waiting for the OS TCP timeout. At most four sockets are in flight;
/// losing futures (and any sockets they own) are dropped when a winner returns.
async fn connect_public_addresses<T, F, Fut>(
    addresses: Vec<SocketAddr>, mut connect: F,
) -> io::Result<(SocketAddr, T)>
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: Future<Output = io::Result<T>>,
{
    let mut seen = HashSet::new();
    let mut allowed = addresses.into_iter().filter(|addr|
        !ssrf_blocked(addr.ip()) && seen.insert(*addr)).peekable();
    let first_v6 = allowed.peek().ok_or_else(||
        io::Error::new(io::ErrorKind::PermissionDenied, "no public destination address"))?.is_ipv6();
    let (mut first, mut other): (VecDeque<_>, VecDeque<_>) = allowed
        .partition(|addr| addr.is_ipv6() == first_v6);
    let mut candidates = VecDeque::new();
    while !first.is_empty() || !other.is_empty() {
        if let Some(addr) = first.pop_front() { candidates.push_back(addr); }
        if let Some(addr) = other.pop_front() { candidates.push_back(addr); }
    }

    tokio::time::timeout(DESTINATION_CONNECT_TIMEOUT, async {
        let mut pending = FuturesUnordered::new();
        let mut launch_at = Instant::now();
        let mut last_error = io::Error::new(io::ErrorKind::NotConnected, "no reachable address");
        loop {
            if candidates.is_empty() && pending.is_empty() { return Err(last_error); }
            tokio::select! {
                biased;
                Some((addr, result)) = pending.next(), if !pending.is_empty() => {
                    match result {
                        Ok(stream) => return Ok((addr, stream)),
                        Err(error) => last_error = error,
                    }
                    // A refused address need not incur the fallback delay.
                    launch_at = Instant::now();
                }
                _ = tokio::time::sleep_until(launch_at), if !candidates.is_empty() && pending.len() < MAX_PARALLEL_DIALS => {
                    let addr = candidates.pop_front().unwrap();
                    let dial = connect(addr);
                    pending.push(async move {
                        let result = tokio::time::timeout(ADDRESS_CONNECT_TIMEOUT, dial).await
                            .unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "TCP connect timed out")));
                        (addr, result)
                    });
                    launch_at = Instant::now() + ADDRESS_FALLBACK_DELAY;
                }
            }
        }
    }).await.unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "destination connect timed out")))
}

// ── SOCKS5 protocol helpers ───────────────────────────────────────────

/// Read SOCKS5 GREET + REQUEST from a stream. Generic over
/// `AsyncRead + AsyncWrite + Unpin` so unit tests can drive it via
/// `tokio::io::duplex` without spinning up a real TCP socket.
async fn read_socks5_request<S>(s: &mut S) -> io::Result<Target>
where S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin
{
    // GREET: VER, NMETHODS, METHODS[]
    let mut hdr = [0u8; 2];
    s.read_exact(&mut hdr).await?;
    if hdr[0] != SOCKS_VER {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not socks5"));
    }
    let n = hdr[1] as usize;
    let mut methods = vec![0u8; n];
    s.read_exact(&mut methods).await?;
    if !methods.contains(&METHOD_NO_AUTH) {
        let _ = s.write_all(&[SOCKS_VER, METHOD_NO_ACCEPTABLE]).await;
        return Err(io::Error::new(io::ErrorKind::PermissionDenied,
                                  "no acceptable auth method"));
    }
    s.write_all(&[SOCKS_VER, METHOD_NO_AUTH]).await?;

    // REQUEST: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT
    let mut req = [0u8; 4];
    s.read_exact(&mut req).await?;
    if req[0] != SOCKS_VER {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad req ver"));
    }
    if req[1] != CMD_CONNECT {
        // CONNECT is all we support for now. UDP ASSOCIATE / BIND
        // would need additional plumbing.
        let _ = s.write_all(&[SOCKS_VER, REP_COMMAND_NOT_SUPPORTED, RSV,
                              ATYP_IPV4, 0,0,0,0, 0,0]).await;
        return Err(io::Error::new(io::ErrorKind::Unsupported,
                                  "only CONNECT supported"));
    }
    let atyp = req[3];
    let target = match atyp {
        ATYP_IPV4 => {
            let mut o = [0u8; 4]; s.read_exact(&mut o).await?;
            let mut p = [0u8; 2]; s.read_exact(&mut p).await?;
            Target::Ip(IpAddr::V4(Ipv4Addr::from(o)), u16::from_be_bytes(p))
        }
        ATYP_IPV6 => {
            let mut o = [0u8; 16]; s.read_exact(&mut o).await?;
            let mut p = [0u8; 2]; s.read_exact(&mut p).await?;
            Target::Ip(IpAddr::V6(Ipv6Addr::from(o)), u16::from_be_bytes(p))
        }
        ATYP_DOMAIN => {
            let mut l = [0u8; 1]; s.read_exact(&mut l).await?;
            let mut name = vec![0u8; l[0] as usize];
            s.read_exact(&mut name).await?;
            let mut p = [0u8; 2]; s.read_exact(&mut p).await?;
            let domain = String::from_utf8(name)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData,
                                            "non-utf8 domain"))?;
            Target::Domain(domain, u16::from_be_bytes(p))
        }
        _ => {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                                      "bad atyp"));
        }
    };
    Ok(target)
}

fn encode_target(t: &Target) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32);
    match t {
        Target::Ip(IpAddr::V4(a), p) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&a.octets());
            buf.extend_from_slice(&p.to_be_bytes());
        }
        Target::Ip(IpAddr::V6(a), p) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&a.octets());
            buf.extend_from_slice(&p.to_be_bytes());
        }
        Target::Domain(d, p) => {
            // Invariant: every producer of Target::Domain caps the name
            // at 255 bytes (SOCKS5 / envelope length fields are one byte;
            // `parse_authority` rejects longer). `d.len() as u8` would
            // silently truncate otherwise and desync the server parse.
            debug_assert!(d.len() <= 255, "domain too long for envelope: {}", d.len());
            buf.push(ATYP_DOMAIN);
            buf.push(d.len() as u8);
            buf.extend_from_slice(d.as_bytes());
            buf.extend_from_slice(&p.to_be_bytes());
        }
    }
    buf
}

/// Parse the target envelope from any `AsyncRead`. quinn's
/// `RecvStream` implements `AsyncRead` so the production callsite
/// just passes `&mut recv`; tests pass a `tokio::io::duplex` half.
async fn read_target<R>(s: &mut R) -> io::Result<Target>
where R: tokio::io::AsyncRead + Unpin
{
    let mut atyp = [0u8; 1];
    s.read_exact(&mut atyp).await?;
    match atyp[0] {
        ATYP_IPV4 => {
            let mut o = [0u8; 4]; s.read_exact(&mut o).await?;
            let mut p = [0u8; 2]; s.read_exact(&mut p).await?;
            Ok(Target::Ip(IpAddr::V4(Ipv4Addr::from(o)), u16::from_be_bytes(p)))
        }
        ATYP_IPV6 => {
            let mut o = [0u8; 16]; s.read_exact(&mut o).await?;
            let mut p = [0u8; 2]; s.read_exact(&mut p).await?;
            Ok(Target::Ip(IpAddr::V6(Ipv6Addr::from(o)), u16::from_be_bytes(p)))
        }
        ATYP_DOMAIN => {
            let mut l = [0u8; 1]; s.read_exact(&mut l).await?;
            let mut name = vec![0u8; l[0] as usize];
            s.read_exact(&mut name).await?;
            let mut p = [0u8; 2]; s.read_exact(&mut p).await?;
            let domain = String::from_utf8(name)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData,
                                            "non-utf8 domain"))?;
            Ok(Target::Domain(domain, u16::from_be_bytes(p)))
        }
        b => Err(io::Error::new(io::ErrorKind::InvalidData,
                                format!("bad atyp 0x{b:02x}"))),
    }
}

// ── HTTP CONNECT helpers ──────────────────────────────────────────────

/// Cap on the request head we'll buffer before giving up. CONNECT
/// requests are tiny; anything past this is malformed or hostile.
const MAX_HTTP_HEAD: usize = 16 * 1024;

/// Read an HTTP request head up to the terminating `CRLFCRLF` and
/// parse a `CONNECT host:port` request line into a [`Target`]. Reads
/// one byte at a time so we never consume tunnel payload past the
/// header block — after a CONNECT the client waits for our `200`
/// before sending anything, but a byte-exact reader is robust either
/// way. Generic over the stream so unit tests can drive it via
/// `tokio::io::duplex`.
async fn read_http_connect_request<S>(s: &mut S) -> io::Result<Target>
where S: tokio::io::AsyncRead + Unpin
{
    let mut head = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    loop {
        let n = s.read(&mut byte).await?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof,
                                      "eof before end of http request head"));
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
        if head.len() > MAX_HTTP_HEAD {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                                      "http request head too large"));
        }
    }

    // Request line: METHOD SP request-target SP HTTP/x.y
    let line_end = head.windows(2).position(|w| w == b"\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                                      "no request line"))?;
    let line = std::str::from_utf8(&head[..line_end])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData,
                                    "non-utf8 request line"))?;
    let mut parts = line.split(' ');
    let method = parts.next().unwrap_or("");
    if !method.eq_ignore_ascii_case("CONNECT") {
        return Err(io::Error::new(io::ErrorKind::Unsupported,
                                  "only CONNECT supported"));
    }
    let authority = parts.next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                                      "missing CONNECT target"))?;
    parse_authority(authority)
}

/// Split a CONNECT authority (`host:port`, `[v6]:port`, or a bare host
/// defaulting to 443) into a [`Target`]. An IP literal becomes
/// `Target::Ip` so the server skips a needless DNS lookup; a name
/// becomes `Target::Domain` and is resolved on the far side.
fn parse_authority(authority: &str) -> io::Result<Target> {
    let bad = |m: &'static str| io::Error::new(io::ErrorKind::InvalidData, m);
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        // Bracketed IPv6 literal: [addr] or [addr]:port
        let close = rest.find(']').ok_or_else(|| bad("unterminated ipv6 literal"))?;
        let addr = &rest[..close];
        let port = match &rest[close + 1..] {
            "" => 443,
            after => after.strip_prefix(':')
                .ok_or_else(|| bad("junk after ipv6 literal"))?
                .parse::<u16>().map_err(|_| bad("bad port"))?,
        };
        (addr.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(),
                             p.parse::<u16>().map_err(|_| bad("bad port"))?),
            None => (authority.to_string(), 443),
        }
    };
    if host.is_empty() {
        return Err(bad("empty host"));
    }
    // The target envelope encodes a domain length in a single byte, so
    // anything over 255 bytes would silently truncate in `encode_target`
    // and desync the server's parse (it would read a short name, then
    // misread the rest of the hostname as the port + payload stream).
    // The SOCKS5 front-end can't produce this (its length field is one
    // byte); only an HTTP CONNECT authority can. Reject it here.
    if host.len() > 255 {
        return Err(bad("hostname too long"));
    }
    match host.parse::<IpAddr>() {
        Ok(ip) => Ok(Target::Ip(ip, port)),
        Err(_) => Ok(Target::Domain(host, port)),
    }
}

/// Map a server status byte (SOCKS5 `REP_*` code) to the HTTP response
/// we hand the CONNECT client. Success is the canonical
/// `200 Connection Established`; failures collapse to a few standard
/// gateway statuses.
fn http_connect_reply(status: u8) -> &'static [u8] {
    match status {
        REP_SUCCEEDED => b"HTTP/1.1 200 Connection Established\r\n\r\n",
        REP_RULESET_BLOCKED =>
            b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n",
        REP_NETWORK_UNREACHABLE | REP_HOST_UNREACHABLE =>
            b"HTTP/1.1 504 Gateway Timeout\r\nConnection: close\r\n\r\n",
        _ =>
            b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n",
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[cfg(windows)]
    #[test]
    fn temporary_winsock_failure_does_not_kill_the_listener() {
        for code in [10024,10050,10051,10052,10053,10054,10055,10064,10065] {
            assert!(is_transient_accept_error(&io::Error::from_raw_os_error(code)), "WSA error {code}");
        }
        assert!(!is_transient_accept_error(&io::Error::from_raw_os_error(10038))); // invalid socket
    }

    // All dials below are simulated. No requests are sent to these public IPs.
    #[tokio::test(start_paused = true)]
    async fn healthy_first_address_does_not_wait_for_the_fallback_timer() {
        let mut attempts = 0;
        let started = Instant::now();
        let result = connect_public_addresses(vec!["1.1.1.1:443".parse().unwrap(), "8.8.8.8:443".parse().unwrap()], |_| {
            attempts += 1;
            std::future::ready(Ok(()))
        }).await.unwrap();
        assert_eq!(result.0.to_string(), "1.1.1.1:443");
        assert_eq!(attempts, 1);
        assert_eq!(started.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn broken_ipv6_falls_back_to_ipv4_in_250ms_and_cancels_loser() {
        let addresses: Vec<SocketAddr> = ["[2001:4860:4860::8888]:443", "[2001:4860:4860::8844]:443", "1.1.1.1:443"]
            .iter().map(|a| a.parse().unwrap()).collect();
        let attempted = Arc::new(Mutex::new(Vec::new()));
        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        struct Guard(Arc<std::sync::atomic::AtomicUsize>);
        impl Drop for Guard { fn drop(&mut self) { self.0.fetch_sub(1, Ordering::SeqCst); } }
        let started = Instant::now();
        let result = connect_public_addresses(addresses, |addr| {
            attempted.lock().push(addr);
            let active = active.clone();
            async move {
                active.fetch_add(1, Ordering::SeqCst);
                let _guard = Guard(active);
                if addr.is_ipv6() { std::future::pending::<()>().await; }
                Ok(())
            }
        }).await.unwrap();
        assert!(result.0.is_ipv4());
        assert_eq!(started.elapsed(), Duration::from_millis(250));
        assert_eq!(attempted.lock().len(), 2);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn refused_addresses_retry_immediately_and_duplicates_are_not_redialed() {
        let addresses = vec!["1.1.1.1:443".parse().unwrap(), "1.1.1.1:443".parse().unwrap(), "8.8.8.8:443".parse().unwrap()];
        let mut attempts = Vec::new();
        let started = Instant::now();
        let result = connect_public_addresses(addresses, |addr| {
            attempts.push(addr);
            std::future::ready(Err::<(), _>(io::Error::from(io::ErrorKind::ConnectionRefused)))
        }).await;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionRefused);
        assert_eq!(attempts.len(), 2);
        assert_eq!(started.elapsed(), Duration::ZERO);
    }

    #[tokio::test]
    async fn every_dns_candidate_is_filtered_before_any_dial() {
        let blocked: Vec<SocketAddr> = ["127.0.0.1:80", "10.0.0.1:80", "[::ffff:169.254.169.254]:80", "[::1]:80"]
            .iter().map(|a| a.parse().unwrap()).collect();
        let error = connect_public_addresses(blocked.clone(), |_| {
            panic!("private destination was dialed");
            #[allow(unreachable_code)]
            std::future::ready(Ok(()))
        }).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        let mut mixed = blocked;
        mixed.push("1.1.1.1:443".parse().unwrap());
        let result = connect_public_addresses(mixed, |addr| {
            assert_eq!(addr.to_string(), "1.1.1.1:443");
            std::future::ready(Ok(()))
        }).await.unwrap();
        assert_eq!(result.0.to_string(), "1.1.1.1:443");
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_dials_have_bounded_concurrency_and_total_deadline() {
        use std::sync::atomic::AtomicUsize;
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        struct Guard(Arc<AtomicUsize>);
        impl Drop for Guard { fn drop(&mut self) { self.0.fetch_sub(1, Ordering::SeqCst); } }
        let addresses = (1..=20).map(|n| format!("1.1.1.{n}:443").parse().unwrap()).collect();
        let started = Instant::now();
        let error = connect_public_addresses(addresses, |_| {
            let active = active.clone();
            let peak = peak.clone();
            async move {
                let count = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(count, Ordering::SeqCst);
                let _guard = Guard(active);
                std::future::pending::<io::Result<()>>().await
            }
        }).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(started.elapsed(), DESTINATION_CONNECT_TIMEOUT);
        assert_eq!(peak.load(Ordering::SeqCst), 4);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    /// SOCKS5 GREET + REQUEST (IPv4) → parsed Target::Ip.
    #[tokio::test]
    async fn socks5_handshake_ipv4() {
        let (mut client, mut server) = tokio::io::duplex(128);

        // Client side: drive the protocol.
        let driver = tokio::spawn(async move {
            // GREET — ver=5, 1 method, no-auth.
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            // Read server's method-select response: ver + method.
            let mut buf = [0u8; 2];
            client.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, [0x05, 0x00]);
            // REQUEST — ver=5, cmd=CONNECT, rsv=0, atyp=IPv4, 192.0.2.1:443.
            client.write_all(&[0x05, 0x01, 0x00, 0x01,
                               192, 0, 2, 1, 0x01, 0xbb]).await.unwrap();
        });

        let t = read_socks5_request(&mut server).await.unwrap();
        driver.await.unwrap();
        match t {
            Target::Ip(IpAddr::V4(a), port) => {
                assert_eq!(a.octets(), [192, 0, 2, 1]);
                assert_eq!(port, 443);
            }
            other => panic!("unexpected target: {other:?}"),
        }
    }

    /// SOCKS5 with domain ATYP.
    #[tokio::test]
    async fn socks5_handshake_domain() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let driver = tokio::spawn(async move {
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut buf = [0u8; 2];
            client.read_exact(&mut buf).await.unwrap();
            // REQUEST — domain "example.com" port 80.
            let mut req = vec![0x05, 0x01, 0x00, 0x03];
            req.push(11);
            req.extend_from_slice(b"example.com");
            req.extend_from_slice(&80u16.to_be_bytes());
            client.write_all(&req).await.unwrap();
        });
        let t = read_socks5_request(&mut server).await.unwrap();
        driver.await.unwrap();
        match t {
            Target::Domain(d, port) => {
                assert_eq!(d, "example.com");
                assert_eq!(port, 80);
            }
            other => panic!("unexpected target: {other:?}"),
        }
    }

    /// SOCKS5 with IPv6 ATYP.
    #[tokio::test]
    async fn socks5_handshake_ipv6() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let driver = tokio::spawn(async move {
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut buf = [0u8; 2];
            client.read_exact(&mut buf).await.unwrap();
            let mut req = vec![0x05, 0x01, 0x00, 0x04];
            // 2001:db8::1
            req.extend_from_slice(&[
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
            ]);
            req.extend_from_slice(&53u16.to_be_bytes());
            client.write_all(&req).await.unwrap();
        });
        let t = read_socks5_request(&mut server).await.unwrap();
        driver.await.unwrap();
        match t {
            Target::Ip(IpAddr::V6(a), port) => {
                assert_eq!(a, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
                assert_eq!(port, 53);
            }
            other => panic!("unexpected target: {other:?}"),
        }
    }

    /// Rejected: SOCKS4 (wrong version byte).
    #[tokio::test]
    async fn socks5_rejects_socks4() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let driver = tokio::spawn(async move {
            // SOCKS4 starts with 0x04.
            client.write_all(&[0x04, 0x01, 0x00, 0x50,
                               192, 0, 2, 1, 0]).await.unwrap();
        });
        let err = read_socks5_request(&mut server).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        driver.await.unwrap();
    }

    /// Rejected: no acceptable auth method (we only offer no-auth).
    #[tokio::test]
    async fn socks5_rejects_auth_required() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let driver = tokio::spawn(async move {
            // 1 method = USERNAME/PASSWORD (0x02). We don't support it.
            client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
            // Server should reply with NO_ACCEPTABLE_METHODS (0xFF).
            let mut reply = [0u8; 2];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, [0x05, 0xFF]);
        });
        let err = read_socks5_request(&mut server).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        driver.await.unwrap();
    }

    /// Rejected: CMD other than CONNECT (we don't support BIND/UDP).
    #[tokio::test]
    async fn socks5_rejects_unsupported_cmd() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let driver = tokio::spawn(async move {
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut buf = [0u8; 2];
            client.read_exact(&mut buf).await.unwrap();
            // CMD = 0x03 (UDP ASSOCIATE). Not supported.
            client.write_all(&[0x05, 0x03, 0x00, 0x01,
                               192, 0, 2, 1, 0x01, 0xbb]).await.unwrap();
            // Server should reply with REP_COMMAND_NOT_SUPPORTED.
            let mut reply = [0u8; 10];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply[0], 0x05);
            assert_eq!(reply[1], 0x07);  // REP_COMMAND_NOT_SUPPORTED
        });
        let err = read_socks5_request(&mut server).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        driver.await.unwrap();
    }

    /// Envelope round-trip: encode each Target variant, parse it back,
    /// confirm equality.
    #[tokio::test]
    async fn target_envelope_round_trip_ipv4() {
        let original = Target::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 65535);
        let env = encode_target(&original);
        let mut cursor = std::io::Cursor::new(env);
        let parsed = read_target(&mut cursor).await.unwrap();
        match (original, parsed) {
            (Target::Ip(a, p1), Target::Ip(b, p2)) => {
                assert_eq!(a, b);
                assert_eq!(p1, p2);
            }
            _ => panic!("variant mismatch"),
        }
    }

    #[tokio::test]
    async fn target_envelope_round_trip_ipv6() {
        let addr: Ipv6Addr = "fe80::1234:5678:90ab:cdef".parse().unwrap();
        let original = Target::Ip(IpAddr::V6(addr), 8443);
        let env = encode_target(&original);
        let mut cursor = std::io::Cursor::new(env);
        let parsed = read_target(&mut cursor).await.unwrap();
        match (original, parsed) {
            (Target::Ip(IpAddr::V6(a), p1), Target::Ip(IpAddr::V6(b), p2)) => {
                assert_eq!(a, b);
                assert_eq!(p1, p2);
            }
            _ => panic!("variant mismatch"),
        }
    }

    #[tokio::test]
    async fn target_envelope_round_trip_domain() {
        let original = Target::Domain("example.com".to_string(), 443);
        let env = encode_target(&original);
        let mut cursor = std::io::Cursor::new(env);
        let parsed = read_target(&mut cursor).await.unwrap();
        match (original, parsed) {
            (Target::Domain(d1, p1), Target::Domain(d2, p2)) => {
                assert_eq!(d1, d2);
                assert_eq!(p1, p2);
            }
            _ => panic!("variant mismatch"),
        }
    }

    /// Boundary: 255-byte domain name (the protocol's hard max).
    #[tokio::test]
    async fn target_envelope_max_length_domain() {
        let long = "a".repeat(255);
        let original = Target::Domain(long.clone(), 1);
        let env = encode_target(&original);
        // 1 (atyp) + 1 (len) + 255 (name) + 2 (port) = 259 bytes.
        assert_eq!(env.len(), 259);
        let mut cursor = std::io::Cursor::new(env);
        let parsed = read_target(&mut cursor).await.unwrap();
        if let Target::Domain(d, p) = parsed {
            assert_eq!(d.len(), 255);
            assert_eq!(d, long);
            assert_eq!(p, 1);
        } else {
            panic!("variant mismatch");
        }
    }

    /// Unknown ATYP byte → error.
    #[tokio::test]
    async fn target_envelope_unknown_atyp() {
        let bad = vec![0x99, 0, 0, 0, 0, 0, 0];
        let mut cursor = std::io::Cursor::new(bad);
        let err = read_target(&mut cursor).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// HTTP CONNECT to a domain target with explicit port.
    #[tokio::test]
    async fn http_connect_domain() {
        let req = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        let mut cursor = std::io::Cursor::new(req.to_vec());
        match read_http_connect_request(&mut cursor).await.unwrap() {
            Target::Domain(d, port) => {
                assert_eq!(d, "example.com");
                assert_eq!(port, 443);
            }
            other => panic!("unexpected target: {other:?}"),
        }
    }

    /// HTTP CONNECT to a bracketed IPv6 literal → Target::Ip.
    #[tokio::test]
    async fn http_connect_ipv6_literal() {
        let req = b"CONNECT [2001:db8::1]:8443 HTTP/1.1\r\n\r\n";
        let mut cursor = std::io::Cursor::new(req.to_vec());
        match read_http_connect_request(&mut cursor).await.unwrap() {
            Target::Ip(IpAddr::V6(a), port) => {
                assert_eq!(a, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
                assert_eq!(port, 8443);
            }
            other => panic!("unexpected target: {other:?}"),
        }
    }

    /// Bare host with no port defaults to 443.
    #[tokio::test]
    async fn http_connect_default_port() {
        let target = parse_authority("example.com").unwrap();
        match target {
            Target::Domain(d, port) => {
                assert_eq!(d, "example.com");
                assert_eq!(port, 443);
            }
            other => panic!("unexpected target: {other:?}"),
        }
    }

    /// An IPv4 literal authority parses to Target::Ip (server skips DNS).
    #[tokio::test]
    async fn http_connect_ipv4_literal() {
        match parse_authority("192.0.2.7:993").unwrap() {
            Target::Ip(IpAddr::V4(a), port) => {
                assert_eq!(a.octets(), [192, 0, 2, 7]);
                assert_eq!(port, 993);
            }
            other => panic!("unexpected target: {other:?}"),
        }
    }

    /// A hostname longer than 255 bytes is rejected, not silently
    /// truncated into the envelope (which would desync the server parse).
    #[tokio::test]
    async fn http_connect_rejects_overlong_host() {
        let long_host = "a".repeat(256);
        let err = parse_authority(&format!("{long_host}:443")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        // 255 is exactly the max and must still be accepted.
        let ok_host = "b".repeat(255);
        match parse_authority(&format!("{ok_host}:443")).unwrap() {
            Target::Domain(d, p) => { assert_eq!(d.len(), 255); assert_eq!(p, 443); }
            other => panic!("unexpected target: {other:?}"),
        }
    }

    /// A non-CONNECT method is rejected as Unsupported.
    #[tokio::test]
    async fn http_connect_rejects_get() {
        let req = b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut cursor = std::io::Cursor::new(req.to_vec());
        let err = read_http_connect_request(&mut cursor).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    /// Success status maps to the canonical 200 line; failures don't.
    #[tokio::test]
    async fn http_connect_reply_mapping() {
        assert!(http_connect_reply(REP_SUCCEEDED).starts_with(b"HTTP/1.1 200"));
        assert!(http_connect_reply(REP_RULESET_BLOCKED).starts_with(b"HTTP/1.1 403"));
        assert!(http_connect_reply(REP_HOST_UNREACHABLE).starts_with(b"HTTP/1.1 504"));
        assert!(http_connect_reply(REP_CONNECTION_REFUSED).starts_with(b"HTTP/1.1 502"));
    }
}
