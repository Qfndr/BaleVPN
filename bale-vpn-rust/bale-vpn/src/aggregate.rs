//! Optional flow aggregation over independent, authenticated local tunnels.
//! No packet striping, direct-internet fallback, active speed probes or auto calls.
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{
    io,
    net::Ipv4Addr,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Instant,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task::{JoinHandle, JoinSet},
    time::{timeout, Duration},
};

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum Policy {
    #[default]
    LeastConnections,
    RoundRobin,
    Failover,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PathConfig {
    pub profile_id: u8,
    pub name: String,
    pub port: u16,
    pub management_port: u16,
    pub weight: u8,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    pub listen_port: u16,
    pub policy: Policy,
    pub paths: Vec<PathConfig>,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            listen_port: 1088,
            policy: Policy::LeastConnections,
            paths: (0..2)
                .map(|i| PathConfig {
                    profile_id: (i + 1) as u8,
                    name: format!("Tunnel {}", i + 1),
                    port: 1081 + i,
                    management_port: 37201 + i,
                    weight: 1,
                })
                .collect(),
        }
    }
}
impl Config {
    pub fn validate(&self, management: u16) -> io::Result<()> {
        let invalid = || {
            io::Error::new(io::ErrorKind::InvalidInput,"Use 1–8 paths, names of 1–48 characters, weights 1–16 and distinct nonzero pool, SOCKS and management ports")
        };
        if self.paths.is_empty() || self.paths.len() > 8 || self.listen_port == 0 || management == 0
        {
            return Err(invalid());
        }
        let mut ports = std::collections::HashSet::from([management]);
        let mut ids = std::collections::HashSet::new();
        if !ports.insert(self.listen_port) {
            return Err(invalid());
        }
        for p in &self.paths {
            if !(1..=8).contains(&p.profile_id)
                || !ids.insert(p.profile_id)
                || p.name.trim().is_empty()
                || p.name.chars().count() > 48
                || p.name.chars().any(char::is_control)
                || !(1..=16).contains(&p.weight)
                || p.port == 0
                || p.management_port == 0
                || !ports.insert(p.port)
                || !ports.insert(p.management_port)
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
}
struct Health {
    failures: u32,
    retry_at: Option<Instant>,
    error: Option<&'static str>,
}
pub struct PathState {
    config: PathConfig,
    active: AtomicUsize,
    received: AtomicU64,
    sent: AtomicU64,
    completed: AtomicU64,
    health: Mutex<Health>,
}
impl PathState {
    fn new(config: PathConfig) -> Self {
        Self {
            config,
            active: AtomicUsize::new(0),
            received: AtomicU64::new(0),
            sent: AtomicU64::new(0),
            completed: AtomicU64::new(0),
            health: Mutex::new(Health {
                failures: 0,
                retry_at: None,
                error: None,
            }),
        }
    }
    fn failed(&self) {
        let mut h = self.health.lock();
        h.failures = h.failures.saturating_add(1);
        h.retry_at = Some(
            Instant::now() + Duration::from_secs((2u64.saturating_pow(h.failures.min(4))) * 2),
        );
        h.error = Some("Local tunnel unavailable or SOCKS handshake failed");
    }
    fn healthy(&self) {
        let mut h = self.health.lock();
        h.failures = 0;
        h.retry_at = None;
        h.error = None;
    }
}
pub struct Runtime {
    instance: u64,
    config: Config,
    paths: Vec<Arc<PathState>>,
    cursor: AtomicUsize,
    admission: Mutex<()>,
    started: Instant,
}
impl Runtime {
    fn new(config: Config) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        Self {
            instance: NEXT.fetch_add(1, Ordering::Relaxed),
            paths: config
                .paths
                .iter()
                .cloned()
                .map(|p| Arc::new(PathState::new(p)))
                .collect(),
            config,
            cursor: AtomicUsize::new(0),
            admission: Mutex::new(()),
            started: Instant::now(),
        }
    }
    fn reserve(&self, tried: &[usize]) -> Option<Lease> {
        let _lock = self.admission.lock();
        let now = Instant::now();
        let mut available: Vec<usize> = (0..self.paths.len())
            .filter(|i| !tried.contains(i))
            .filter(|i| {
                self.paths[*i]
                    .health
                    .lock()
                    .retry_at
                    .is_none_or(|at| at <= now)
            })
            .collect();
        // If every path is cooling down, allow one passive recovery attempt. Never probe.
        if available.is_empty() {
            if !tried.is_empty() {
                return None;
            }
            available = (0..self.paths.len())
                .min_by_key(|i| self.paths[*i].health.lock().retry_at)
                .into_iter()
                .collect();
        }
        if available.is_empty() {
            return None;
        }
        let turn = self.cursor.fetch_add(1, Ordering::Relaxed);
        let index = match self.config.policy {
            Policy::Failover => available[0],
            Policy::RoundRobin => {
                let total: usize = available
                    .iter()
                    .map(|i| self.paths[*i].config.weight as usize)
                    .sum();
                let mut ticket = turn % total;
                let mut chosen = available[0];
                for i in available {
                    let w = self.paths[i].config.weight as usize;
                    if ticket < w {
                        chosen = i;
                        break;
                    }
                    ticket -= w;
                }
                chosen
            }
            Policy::LeastConnections => {
                let len = available.len();
                available.rotate_left(turn % len);
                *available
                    .iter()
                    .min_by(|a, b| {
                        let pa = &self.paths[**a];
                        let pb = &self.paths[**b];
                        (pa.active.load(Ordering::Relaxed) as u64 * pb.config.weight as u64).cmp(
                            &(pb.active.load(Ordering::Relaxed) as u64 * pa.config.weight as u64),
                        )
                    })
                    .unwrap()
            }
        };
        let path = self.paths[index].clone();
        path.active.fetch_add(1, Ordering::Relaxed);
        Some(Lease { path, index })
    }
    fn snapshot(&self) -> Snapshot {
        Snapshot {
            instance: self.instance,
            running: false,
            listen_port: self.config.listen_port,
            policy: self.config.policy.clone(),
            elapsed_ms: self.started.elapsed().as_millis() as u64,
            paths: self
                .paths
                .iter()
                .map(|p| {
                    let h = p.health.lock();
                    PathSnapshot {
                        profile_id: p.config.profile_id,
                        name: p.config.name.clone(),
                        port: p.config.port,
                        management_port: p.config.management_port,
                        weight: p.config.weight,
                        active: p.active.load(Ordering::Relaxed),
                        received_bytes: p.received.load(Ordering::Relaxed),
                        sent_bytes: p.sent.load(Ordering::Relaxed),
                        completed: p.completed.load(Ordering::Relaxed),
                        retry_after_seconds: h
                            .retry_at
                            .map(|at| {
                                at.saturating_duration_since(Instant::now())
                                    .as_millis()
                                    .div_ceil(1000) as u64
                            })
                            .unwrap_or(0),
                        error: h.error,
                    }
                })
                .collect(),
        }
    }
}
struct Lease {
    path: Arc<PathState>,
    index: usize,
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.path.active.fetch_sub(1, Ordering::Relaxed);
    }
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PathSnapshot {
    profile_id: u8,
    name: String,
    port: u16,
    management_port: u16,
    weight: u8,
    active: usize,
    received_bytes: u64,
    sent_bytes: u64,
    completed: u64,
    retry_after_seconds: u64,
    error: Option<&'static str>,
}
#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    instance: u64,
    running: bool,
    listen_port: u16,
    policy: Policy,
    elapsed_ms: u64,
    paths: Vec<PathSnapshot>,
}
struct Running {
    task: JoinHandle<()>,
    runtime: Arc<Runtime>,
}
pub struct Aggregate {
    shutting_down: AtomicBool,
    operation: tokio::sync::Mutex<()>,
    config: Mutex<Config>,
    running: Mutex<Option<Running>>,
    last: Mutex<Option<Arc<Runtime>>>,
    pub workers: Arc<crate::workers::Workers>,
    management_port: u16,
}
impl Aggregate {
    pub fn new(config: Config, directory: std::path::PathBuf, management_port: u16) -> Self {
        Self {
            shutting_down: AtomicBool::new(false),
            operation: tokio::sync::Mutex::new(()),
            config: Mutex::new(config),
            running: Mutex::new(None),
            last: Mutex::new(None),
            workers: Arc::new(crate::workers::Workers::new(directory)),
            management_port,
        }
    }
    pub fn config(&self) -> Config {
        self.config.lock().clone()
    }
    pub fn snapshot(&self) -> Snapshot {
        if let Some(r) = self.running.lock().as_ref() {
            let mut s = r.runtime.snapshot();
            s.running = !r.task.is_finished();
            return s;
        }
        if let Some(r) = self.last.lock().as_ref() {
            return r.snapshot();
        }
        Runtime::new(self.config()).snapshot()
    }
    pub async fn configure(
        &self,
        config: Config,
        file: &crate::config::ConfigFile,
    ) -> io::Result<()> {
        let _op = self.operation.lock().await;
        self.ensure_running_app()?;
        config.validate(self.management_port)?;
        let previous = self.config();
        let changes_running_profile = self.workers.snapshots().iter().filter(|w| w.running).any(|w| {
            let old = previous.paths.iter().find(|p| usize::from(p.profile_id) == w.slot);
            let new = config.paths.iter().find(|p| usize::from(p.profile_id) == w.slot);
            !matches!((old, new), (Some(a), Some(b)) if a.port == b.port && a.management_port == b.management_port)
        });
        if self.running.lock().is_some() || changes_running_profile {
            return Err(io::Error::other(
                "Stop the pool and managed workers before changing paths or ports",
            ));
        }
        file.update(|c| c.aggregate = config.clone())?;
        *self.config.lock() = config;
        *self.last.lock() = None;
        Ok(())
    }
    pub async fn start(&self) -> io::Result<()> {
        let _op = self.operation.lock().await;
        self.ensure_running_app()?;
        if self
            .running
            .lock()
            .as_ref()
            .is_some_and(|r| !r.task.is_finished())
        {
            return Err(io::Error::other("Pool already running"));
        }
        self.running.lock().take();
        let config = self.config();
        config.validate(self.management_port)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, config.listen_port)).await?;
        let runtime = Arc::new(Runtime::new(config));
        let clone = runtime.clone();
        let task = tokio::spawn(async move {
            serve(listener, clone).await;
        });
        *self.last.lock() = None;
        *self.running.lock() = Some(Running { task, runtime });
        Ok(())
    }
    pub async fn stop(&self) {
        let _op = self.operation.lock().await;
        let running = self.running.lock().take();
        if let Some(r) = running {
            r.task.abort();
            let _ = r.task.await;
            *self.last.lock() = Some(r.runtime);
        }
    }
    pub async fn worker(&self, slot: usize, start: bool) -> io::Result<()> {
        let _op = self.operation.lock().await;
        self.ensure_running_app()?;
        let config = self.config();
        config.validate(self.management_port)?;
        let path = config
            .paths
            .iter()
            .find(|p| p.profile_id as usize == slot)
            .cloned()
            .ok_or_else(|| io::Error::other("Unknown path"))?;
        let workers = self.workers.clone();
        tokio::task::spawn_blocking(move || {
            if start {
                workers.start(slot, path)
            } else {
                workers.stop(slot)
            }
        })
        .await
        .map_err(io::Error::other)?
    }
    fn ensure_running_app(&self) -> io::Result<()> {
        if self.shutting_down.load(Ordering::Relaxed) {
            Err(io::Error::other("Application is shutting down"))
        } else {
            Ok(())
        }
    }
    pub async fn shutdown(&self) {
        self.shutting_down.store(true, Ordering::Relaxed);
        self.stop().await;
        let w = self.workers.clone();
        let _ = tokio::task::spawn_blocking(move || w.stop_all()).await;
    }
}
impl Drop for Aggregate {
    fn drop(&mut self) {
        if let Some(r) = self.running.get_mut().take() {
            r.task.abort();
        }
    }
}

async fn serve(listener: TcpListener, runtime: Arc<Runtime>) {
    let cap = Arc::new(Semaphore::new(256));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
         accepted=listener.accept()=>match accepted {Ok((socket,_))=>{let Ok(permit)=cap.clone().try_acquire_owned()else{drop(socket);continue;};let r=runtime.clone();tasks.spawn(async move{let _permit=permit;let _=handle(socket,r).await;});},Err(e)=>{if matches!(e.kind(),io::ErrorKind::Interrupted|io::ErrorKind::ConnectionAborted|io::ErrorKind::WouldBlock){continue;}tokio::time::sleep(Duration::from_millis(100)).await;}},
         _=tasks.join_next(),if !tasks.is_empty()=>{},
        }
    }
}
async fn reply(socket: &mut TcpStream, code: u8) -> io::Result<()> {
    socket.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await
}
async fn request(socket: &mut TcpStream) -> io::Result<Vec<u8>> {
    let version = socket.read_u8().await?;
    let count = socket.read_u8().await?;
    if version != 5 || count == 0 {
        return Err(io::Error::other("SOCKS5 required"));
    }
    let mut methods = vec![0; count as usize];
    socket.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        socket.write_all(&[5, 255]).await?;
        return Err(io::Error::other("No supported SOCKS method"));
    }
    socket.write_all(&[5, 0]).await?;
    let mut header = [0; 4];
    socket.read_exact(&mut header).await?;
    if header[0] != 5 || header[2] != 0 || header[1] != 1 {
        reply(socket, 7).await?;
        return Err(io::Error::other("Only SOCKS CONNECT is supported"));
    }
    let mut target = header.to_vec();
    let count = match header[3] {
        1 => 4,
        4 => 16,
        3 => {
            let len = socket.read_u8().await?;
            if len == 0 {
                return Err(io::Error::other("Empty domain"));
            }
            target.push(len);
            len as usize
        }
        _ => {
            reply(socket, 8).await?;
            return Err(io::Error::other("Invalid address type"));
        }
    };
    let mut address = vec![0; count + 2];
    socket.read_exact(&mut address).await?;
    target.extend(address);
    Ok(target)
}
enum DialError {
    Unavailable,
    Target(u8),
}
async fn dial(port: u16, target: &[u8]) -> Result<TcpStream, DialError> {
    let future = async {
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .map_err(|_| DialError::Unavailable)?;
        stream
            .set_nodelay(true)
            .map_err(|_| DialError::Unavailable)?;
        stream
            .write_all(&[5, 1, 0])
            .await
            .map_err(|_| DialError::Unavailable)?;
        let mut method = [0; 2];
        stream
            .read_exact(&mut method)
            .await
            .map_err(|_| DialError::Unavailable)?;
        if method != [5, 0] {
            return Err(DialError::Unavailable);
        }
        stream
            .write_all(target)
            .await
            .map_err(|_| DialError::Unavailable)?;
        let mut header = [0; 4];
        stream
            .read_exact(&mut header)
            .await
            .map_err(|_| DialError::Unavailable)?;
        if header[0] != 5 || header[2] != 0 {
            return Err(DialError::Unavailable);
        }
        let len = match header[3] {
            1 => 4,
            4 => 16,
            3 => stream.read_u8().await.map_err(|_| DialError::Unavailable)? as usize,
            _ => return Err(DialError::Unavailable),
        };
        let mut tail = vec![0; len + 2];
        stream
            .read_exact(&mut tail)
            .await
            .map_err(|_| DialError::Unavailable)?;
        if header[1] != 0 {
            return Err(DialError::Target(header[1]));
        }
        Ok(stream)
    };
    timeout(Duration::from_secs(6), future)
        .await
        .unwrap_or(Err(DialError::Unavailable))
}
async fn handle(mut client: TcpStream, runtime: Arc<Runtime>) -> io::Result<()> {
    client.set_nodelay(true)?;
    let target = timeout(Duration::from_secs(10), request(&mut client))
        .await
        .map_err(io::Error::other)??;
    let mut tried = Vec::new();
    let mut error_code = 1;
    while let Some(lease) = runtime.reserve(&tried) {
        tried.push(lease.index);
        match dial(lease.path.config.port, &target).await {
            Ok(stream) => {
                lease.path.healthy();
                reply(&mut client, 0).await?;
                let mut upstream = Counted {
                    stream,
                    path: lease.path.clone(),
                };
                // Stream pinned to one tunnel for its entire lifetime; no packet reorder.
                let result = tokio::io::copy_bidirectional_with_sizes(
                    &mut client,
                    &mut upstream,
                    64 * 1024,
                    64 * 1024,
                )
                .await;
                lease.path.completed.fetch_add(1, Ordering::Relaxed);
                return result.map(|_| ());
            }
            Err(DialError::Unavailable) => lease.path.failed(),
            Err(DialError::Target(code)) => {
                lease.path.healthy();
                error_code = if (1..=8).contains(&code) { code } else { 1 };
            }
        }
    }
    reply(&mut client, error_code).await
}
struct Counted {
    stream: TcpStream,
    path: Arc<PathState>,
}
impl AsyncRead for Counted {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.stream).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(()))) {
            self.path
                .received
                .fetch_add((buf.filled().len() - before) as u64, Ordering::Relaxed);
        }
        result
    }
}
impl AsyncWrite for Counted {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut self.stream).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = r {
            self.path.sent.fetch_add(n as u64, Ordering::Relaxed);
        }
        r
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config(policy: Policy) -> Config {
        Config {
            listen_port: 1088,
            policy,
            paths: vec![
                PathConfig {
                    profile_id: 1,
                    name: "A".into(),
                    port: 1081,
                    management_port: 37201,
                    weight: 1,
                },
                PathConfig {
                    profile_id: 2,
                    name: "B".into(),
                    port: 1082,
                    management_port: 37202,
                    weight: 1,
                },
            ],
        }
    }
    #[test]
    fn rejects_loops_duplicate_ports_unknown_modes_and_oversized_pools() {
        let c = config(Policy::LeastConnections);
        assert!(c.validate(37126).is_ok());
        for field in 0..5 {
            let mut c = c.clone();
            match field {
                0 => c.paths[0].port = c.listen_port,
                1 => c.paths[1].management_port = 37126,
                2 => c.paths[0].weight = 0,
                3 => c.paths[0].name = "\n".into(),
                _ => c.paths = vec![c.paths[0].clone(); 9],
            };
            assert!(c.validate(37126).is_err());
        }
        assert!(serde_json::from_str::<Config>(
            r#"{"listenPort":1088,"policy":"striping","paths":[]}"#
        )
        .is_err());
    }
    #[test]
    fn weighted_round_robin_and_least_connections_reserve_fairly() {
        let mut c = config(Policy::RoundRobin);
        c.paths[0].weight = 3;
        let r = Runtime::new(c);
        let mut counts = [0; 2];
        for _ in 0..40 {
            let lease = r.reserve(&[]).unwrap();
            counts[lease.index] += 1;
        }
        assert_eq!(counts, [30, 10]);
        let r = Runtime::new(config(Policy::LeastConnections));
        let a = r.reserve(&[]).unwrap();
        let b = r.reserve(&[]).unwrap();
        assert_ne!(a.index, b.index);
        drop(a);
        drop(b);
        assert!(r
            .paths
            .iter()
            .all(|p| p.active.load(Ordering::Relaxed) == 0));
    }
    #[test]
    fn failover_prefers_primary_and_excludes_failed_paths_without_probes() {
        let r = Runtime::new(config(Policy::Failover));
        assert_eq!(r.reserve(&[]).unwrap().index, 0);
        r.paths[0].failed();
        assert_eq!(r.reserve(&[]).unwrap().index, 1);
        assert!(r.snapshot().paths[0].retry_after_seconds > 0);
        r.paths[0].healthy();
        assert_eq!(r.reserve(&[]).unwrap().index, 0);
    }
    async fn fake_proxy(code: u8) -> (u16, JoinHandle<()>, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let count = Arc::new(AtomicUsize::new(0));
        let hits = count.clone();
        let task = tokio::spawn(async move {
            let mut clients = JoinSet::new();
            loop {
                tokio::select! {accepted=listener.accept()=>{let(mut s,_)=accepted.unwrap();let hits=hits.clone();clients.spawn(async move{let mut head=[0;3];s.read_exact(&mut head).await.unwrap();assert_eq!(head,[5,1,0]);s.write_all(&[5,0]).await.unwrap();let mut head=[0;4];s.read_exact(&mut head).await.unwrap();let n=match head[3]{1=>4,4=>16,3=>s.read_u8().await.unwrap()as usize,_=>panic!("invalid type")};let mut target=vec![0;n+2];s.read_exact(&mut target).await.unwrap();hits.fetch_add(1,Ordering::Relaxed);reply(&mut s,code).await.unwrap();if code==0{let (mut read,mut write)=s.split();let _=tokio::io::copy(&mut read,&mut write).await;}});},_=clients.join_next(),if !clients.is_empty()=>{}}
            }
        });
        (port, task, count)
    }
    async fn pool(config: Config) -> (u16, JoinHandle<()>, Arc<Runtime>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let runtime = Arc::new(Runtime::new(config));
        let copy = runtime.clone();
        (
            port,
            tokio::spawn(async move {
                serve(listener, copy).await;
            }),
            runtime,
        )
    }
    async fn open(port: u16) -> (TcpStream, u8) {
        let mut s = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        s.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0; 2];
        s.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);
        s.write_all(&[
            5, 1, 0, 3, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'o', b'r', b'g', 1,
            187,
        ])
        .await
        .unwrap();
        let mut reply = [0; 10];
        s.read_exact(&mut reply).await.unwrap();
        (s, reply[1])
    }
    #[tokio::test]
    async fn simultaneous_flows_use_both_paths_preserve_bytes_half_close_and_live_totals() {
        let (a, ta, ha) = fake_proxy(0).await;
        let (b, tb, hb) = fake_proxy(0).await;
        let mut c = config(Policy::LeastConnections);
        c.paths[0].port = a;
        c.paths[1].port = b;
        let (port, task, r) = pool(c).await;
        let (mut first, code) = open(port).await;
        assert_eq!(code, 0);
        let (mut second, code) = open(port).await;
        assert_eq!(code, 0);
        assert_eq!(ha.load(Ordering::Relaxed), 1);
        assert_eq!(hb.load(Ordering::Relaxed), 1);
        let payload: Vec<u8> = (0..65536).map(|i| (i % 251) as u8).collect();
        for stream in [&mut first, &mut second] {
            stream.write_all(&payload).await.unwrap();
            let mut received = vec![0; payload.len()];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(received, payload);
            stream.shutdown().await.unwrap();
            assert_eq!(
                stream.read_u8().await.unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
        }
        assert_eq!(
            r.snapshot().paths.iter().map(|p| p.sent_bytes).sum::<u64>(),
            131072
        );
        assert_eq!(
            r.snapshot()
                .paths
                .iter()
                .map(|p| p.received_bytes)
                .sum::<u64>(),
            131072
        );
        task.abort();
        ta.abort();
        tb.abort();
    }
    #[tokio::test]
    async fn unavailable_primary_falls_back_without_direct_dial_or_payload_replay() {
        let unused = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead = unused.local_addr().unwrap().port();
        drop(unused);
        let (good, server, hits) = fake_proxy(0).await;
        let mut c = config(Policy::Failover);
        c.paths[0].port = dead;
        c.paths[1].port = good;
        let (port, task, r) = pool(c).await;
        let (mut stream, code) = open(port).await;
        assert_eq!(code, 0);
        stream.write_all(b"once").await.unwrap();
        let mut data = [0; 4];
        stream.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"once");
        assert_eq!(hits.load(Ordering::Relaxed), 1);
        assert!(r.snapshot().paths[0].error.is_some());
        drop(stream);
        task.abort();
        server.abort();
    }
    #[tokio::test]
    async fn target_rejection_is_not_a_path_failure_and_all_unavailable_fails_closed() {
        let (port, server, _) = fake_proxy(2).await;
        let mut c = config(Policy::Failover);
        c.paths.truncate(1);
        c.paths[0].port = port;
        let (front, task, r) = pool(c).await;
        assert_eq!(open(front).await.1, 2);
        assert!(r.snapshot().paths[0].error.is_none());
        assert!(r.snapshot().paths[0].retry_after_seconds == 0);
        server.abort();
        server.await.ok();
        assert_ne!(open(front).await.1, 0);
        task.abort();
    }
    #[tokio::test]
    async fn stop_closes_live_streams_and_releases_listener() {
        let (upstream, server, _) = fake_proxy(0).await;
        let mut c = config(Policy::Failover);
        c.paths[0].port = upstream;
        let (port, task, _) = pool(c).await;
        let (mut s, code) = open(port).await;
        assert_eq!(code, 0);
        task.abort();
        let _ = task.await;
        timeout(Duration::from_secs(2), async {
            let mut b = [0; 1];
            assert!(matches!(s.read(&mut b).await, Ok(0) | Err(_)));
        })
        .await
        .unwrap();
        let rebound = TcpListener::bind((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        drop(rebound);
        server.abort();
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_mutually_authenticated_tunnels_relay_concurrent_flows_and_keep_ssrf_guard() {
        let mut tunnels = Vec::new();
        let mut c = config(Policy::RoundRobin);
        for i in 0..2 {
            let client = lktunnel::security::Identity::generate().unwrap();
            let server = lktunnel::security::Identity::generate().unwrap();
            let (a, b) = lktunnel::connect_loopback_with_options(
                client
                    .options(&[server.certificate.clone()], false, false)
                    .unwrap(),
                server
                    .options(&[client.certificate.clone()], true, false)
                    .unwrap(),
            );
            b.start_server().unwrap();
            let port = a.enable_socks5_server(0).await.unwrap().port();
            timeout(Duration::from_secs(10), a.ensure_quic_client())
                .await
                .unwrap()
                .unwrap();
            assert!(a.is_peer_authenticated());
            c.paths[i].port = port;
            tunnels.push((a, b));
        }
        let (port, task, r) = pool(c).await;
        // Target is local: both authenticated upstreams must refuse it. No test-only SSRF disable.
        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut ack = [0; 2];
        client.read_exact(&mut ack).await.unwrap();
        client
            .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80])
            .await
            .unwrap();
        let mut reply = [0; 10];
        timeout(Duration::from_secs(10), client.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply[1], 2);
        assert!(r.snapshot().paths.iter().all(|p| p.error.is_none()));
        struct RestoreFilter;
        impl Drop for RestoreFilter {
            fn drop(&mut self) {
                lktunnel::socks5_quic::set_ssrf_filter_enabled(true);
            }
        }
        let _restore = RestoreFilter;
        lktunnel::socks5_quic::set_ssrf_filter_enabled(false);
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = echo.local_addr().unwrap().port();
        let echo_task = tokio::spawn(async move {
            let mut sessions = JoinSet::new();
            for _ in 0..2 {
                let (mut stream, _) = echo.accept().await.unwrap();
                sessions.spawn(async move {
                    let (mut read, mut write) = stream.split();
                    let _ = tokio::io::copy(&mut read, &mut write).await;
                });
            }
            while sessions.join_next().await.is_some() {}
        });
        let mut streams = Vec::new();
        for _ in 0..2 {
            let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                .await
                .unwrap();
            stream.write_all(&[5, 1, 0]).await.unwrap();
            let mut method = [0; 2];
            stream.read_exact(&mut method).await.unwrap();
            let [hi, lo] = target.to_be_bytes();
            stream
                .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, hi, lo])
                .await
                .unwrap();
            let mut response = [0; 10];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(response[1], 0);
            streams.push(stream);
        }
        assert!(r.snapshot().paths.iter().all(|p| p.active == 1));
        let transfers = streams
            .into_iter()
            .enumerate()
            .map(|(index, mut stream)| {
                tokio::spawn(async move {
                    let payload: Vec<u8> = (0..65536).map(|i| ((i + index) % 251) as u8).collect();
                    for _ in 0..8 {
                        stream.write_all(&payload).await.unwrap();
                        let mut got = vec![0; payload.len()];
                        stream.read_exact(&mut got).await.unwrap();
                        assert_eq!(got, payload);
                    }
                    stream.shutdown().await.unwrap();
                })
            })
            .collect::<Vec<_>>();
        for transfer in transfers {
            timeout(Duration::from_secs(15), transfer)
                .await
                .unwrap()
                .unwrap();
        }
        assert_eq!(
            r.snapshot()
                .paths
                .iter()
                .map(|p| p.received_bytes)
                .sum::<u64>(),
            1048576
        );
        echo_task.abort();
        task.abort();
        for (a, b) in tunnels {
            a.disconnect();
            b.disconnect();
        }
    }
}
