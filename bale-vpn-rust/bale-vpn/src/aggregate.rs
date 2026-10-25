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
    Adaptive,
    Latency,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_profiles: Option<Vec<u8>>,
    pub listen_port: u16,
    pub policy: Policy,
    pub paths: Vec<PathConfig>,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            primary_port: None,
            selected_profiles: None,
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
        if let Some(port) = self.primary_port {
            if port == 0 || !ports.insert(port) { return Err(invalid()); }
        }
        if let Some(selected) = &self.selected_profiles {
            let unique: std::collections::HashSet<_> = selected.iter().collect();
            if unique.len() != selected.len() || selected.iter().any(|id| !ids.contains(id)) {
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
// Passive observations, updated only at connection boundaries, never per packet.
// These are SOCKS setup latency and delivered bulk rate, not ICMP RTT/capacity.
#[derive(Default)]
struct Quality {
    setup_ms: Option<f64>,
    bulk_bps: Option<f64>,
    observed: Option<Instant>,
    bulk_observed: Option<Instant>,
}
impl Quality {
    fn setup(&mut self, elapsed: Duration) {
        let sample=elapsed.as_secs_f64().mul_add(1000.0,0.0).max(1.0);
        self.setup_ms=Some(self.setup_ms.map_or(sample,|old|sample.max(old*0.8+sample*0.2)));
        self.observed=Some(Instant::now());
    }
    fn bulk(&mut self, bytes:u64, elapsed:Duration) {
        // Short/app-limited exchanges cannot estimate useful transfer rate.
        if bytes<256*1024||elapsed<Duration::from_millis(200){return;}
        let sample=bytes as f64/elapsed.as_secs_f64();
        self.bulk_bps=Some(self.bulk_bps.map_or(sample,|old|old*0.75+sample*0.25));
        self.bulk_observed=Some(Instant::now());
    }
    fn cost(&self, active:usize,weight:u8,latency_only:bool,now:Instant)->f64 {
        let fresh=self.observed.is_some_and(|at|now.duration_since(at)<Duration::from_secs(60));
        let setup=if fresh{self.setup_ms.unwrap_or(200.0)}else{200.0};
        let bulk=if !latency_only&&self.bulk_observed.is_some_and(|at|now.duration_since(at)<Duration::from_secs(30)){
            // Time to deliver a reference block. Bound it: observations are not
            // link capacity and must not overwhelm the load/latency signals.
            (256.0*1024.0*1000.0/self.bulk_bps.unwrap_or(1.0)).clamp(1.0,2000.0)
        }else{250.0};
        (setup+if latency_only{0.0}else{bulk})*(active as f64+1.0)/f64::from(weight)
    }
}
pub struct PathState {
    config: PathConfig,
    active: AtomicUsize,
    received: AtomicU64,
    sent: AtomicU64,
    completed: AtomicU64,
    health: Mutex<Health>,
    quality: Mutex<Quality>,
}
impl PathState {
    fn new(config: PathConfig) -> Self {
        Self {
            config,
            active: AtomicUsize::new(0),
            received: AtomicU64::new(0),
            sent: AtomicU64::new(0),
            completed: AtomicU64::new(0),
            quality: Mutex::new(Quality::default()),
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
        *self.quality.lock()=Quality::default();
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
            Policy::Adaptive|Policy::Latency => {
                let len=available.len();available.rotate_left(turn%len);
                // Learn every unused path on actual traffic once. No synthetic
                // probe, login, call or destination data is generated.
                available.iter().copied().find(|i|self.paths[*i].active.load(Ordering::Relaxed)==0&&self.paths[*i].quality.lock().observed.is_none())
                    .unwrap_or_else(||*available.iter().min_by(|a,b|{
                        let cost=|i:usize|{let p=&self.paths[i];p.quality.lock().cost(p.active.load(Ordering::Relaxed),p.config.weight,self.config.policy==Policy::Latency,now)};
                        cost(**a).total_cmp(&cost(**b))
                    }).unwrap())
            }
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
                    let q=p.quality.lock();
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
                        setup_latency_ms:q.setup_ms,
                        observed_bulk_bytes_per_second:q.bulk_bps,
                        setup_observation_age_ms:q.observed.map(|at|at.elapsed().as_millis() as u64),
                        bulk_observation_age_ms:q.bulk_observed.map(|at|at.elapsed().as_millis() as u64),
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
    setup_latency_ms: Option<f64>,
    observed_bulk_bytes_per_second: Option<f64>,
    setup_observation_age_ms: Option<u64>,
    bulk_observation_age_ms: Option<u64>,
}
#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    instance: u64,
    pub running: bool,
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
    pub async fn maintenance(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.operation.lock().await
    }
    pub fn imported_config(&self,config:Config){*self.config.lock()=config;*self.last.lock()=None;}
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
        self.configure_locked(config,file)
    }
    pub async fn configure_account_ports(&self,slot:u8,port:u16,management:u16,primary:u16,file:&crate::config::ConfigFile)->io::Result<()>{
        let _op=self.operation.lock().await;
        let mut config=self.config();
        let path=config.paths.iter_mut().find(|p|p.profile_id==slot).ok_or_else(||io::Error::other("Account profile is unavailable"))?;
        let old=(path.port,path.management_port);path.port=port;path.management_port=management;
        config.validate(self.management_port)?;
        if config.listen_port==primary||config.paths.iter().any(|p|p.port==primary||p.management_port==primary){return Err(io::Error::other("Account ports must not overlap the main SOCKS port"));}
        if self.workers.snapshots().iter().any(|w|w.slot==usize::from(slot)&&w.running)||self.running.lock().is_some(){return Err(io::Error::other("Stop this account and the local pool before editing ports"));}
        // Only this managed-account endpoint reserves new ports. Generic
        // aggregation also accepts external SOCKS servers that already listen.
        let mut reservations=Vec::new();
        for (new,old) in [(port,old.0),(management,old.1)]{
            if new!=old {reservations.push(std::net::TcpListener::bind((Ipv4Addr::LOCALHOST,new)).map_err(|_|io::Error::other("The requested account port is already in use"))?);}
        }
        self.configure_locked(config,file)
    }
    fn configure_locked(&self,config:Config,file:&crate::config::ConfigFile)->io::Result<()>{
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
        let mut config = config;
        if let Some(selected) = &config.selected_profiles {
            config.paths.retain(|p| selected.contains(&p.profile_id));
        }
        if let Some(port) = config.primary_port {
            config.paths.push(PathConfig{profile_id:0,name:"Main account".into(),port,management_port:0,weight:1});
        }
        if config.paths.is_empty() {
            return Err(io::Error::other("Select at least one tunnel before starting the pool"));
        }
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
    let connected=if matches!(runtime.config.policy,Policy::Adaptive|Policy::Latency){
        timeout(Duration::from_secs(6),connect(&runtime,&target)).await.unwrap_or(Err(1))
    }else{connect(&runtime,&target).await};
    let (lease,stream)=match connected {
        Ok(value)=>value,
        Err(code)=>return reply(&mut client,code).await,
    };
    reply(&mut client, 0).await?;
    let mut upstream=Counted{stream,path:lease.path.clone()};
    let started=Instant::now();
    // Pin established byte streams to their winner. Never replay TLS, uploads
    // or non-idempotent application requests on another path after a failure.
    let result=tokio::io::copy_bidirectional_with_sizes(&mut client,&mut upstream,64*1024,64*1024).await;
    if let Ok((sent,received))=&result {lease.path.quality.lock().bulk((*sent).max(*received),started.elapsed());}
    lease.path.completed.fetch_add(1,Ordering::Relaxed);
    result.map(|_|())
}
async fn attempt(lease:Lease,target:Vec<u8>)->(Lease,Result<TcpStream,DialError>){
    let started=Instant::now();
    let result=dial(lease.path.config.port,&target).await;
    match &result {
        Ok(_)|Err(DialError::Target(_))=>{lease.path.healthy();lease.path.quality.lock().setup(started.elapsed());},
        Err(DialError::Unavailable)=>lease.path.failed(),
    }
    (lease,result)
}
async fn connect(runtime:&Arc<Runtime>,target:&[u8])->Result<(Lease,TcpStream),u8>{
    let mut tried=Vec::new();
    let mut error_code = 1;
    if runtime.config.policy==Policy::Latency {
        // Explicit opt-in hedging: race at most two SOCKS CONNECT handshakes,
        // only after 250ms without success. No application bytes are duplicated.
        let mut pending=JoinSet::new();
        if let Some(lease)=runtime.reserve(&tried){tried.push(lease.index);pending.spawn(attempt(lease,target.to_vec()));}
        let delay=tokio::time::sleep(Duration::from_millis(250));tokio::pin!(delay);
        let mut hedged=false;
        loop {
            if pending.is_empty(){break;}
            tokio::select! {
                result=pending.join_next(),if !pending.is_empty()=>{
                    if let Some(Ok((lease,result)))=result {
                        match result{Ok(stream)=>return Ok((lease,stream)),Err(DialError::Target(code))=>error_code=code,Err(DialError::Unavailable)=>{}}
                    }
                    if pending.is_empty(){break;}
                },
                _=&mut delay,if !hedged=>{
                    hedged=true;
                    if let Some(lease)=runtime.reserve(&tried){tried.push(lease.index);pending.spawn(attempt(lease,target.to_vec()));}
                }
            }
        }
        // Dropping JoinSet cancels the losing attempt and releases its lease.
    }
    while let Some(lease) = runtime.reserve(&tried) {
        tried.push(lease.index);
        let (lease,result)=attempt(lease,target.to_vec()).await;
        match result {
            Ok(stream) =>return Ok((lease,stream)),
            Err(DialError::Unavailable) => {},
            Err(DialError::Target(code)) => {
                error_code = if (1..=8).contains(&code) { code } else { 1 };
            }
        }
    }
    Err(if (1..=8).contains(&error_code){error_code}else{1})
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
            primary_port: None,
            selected_profiles: None,
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
    #[tokio::test]
    async fn account_port_updates_are_independent_and_occupied_ports_leave_saved_config_intact(){
        let dir=tempfile::tempdir().unwrap();let file=crate::config::ConfigFile::new(dir.path().to_owned());
        let aggregate=Aggregate::new(Config::default(),dir.path().to_owned(),37126);
        let occupied=std::net::TcpListener::bind((Ipv4Addr::LOCALHOST,0)).unwrap();let busy=occupied.local_addr().unwrap().port();
        let old=aggregate.config();
        assert!(aggregate.configure_account_ports(1,busy,37201,1080,&file).await.is_err());
        assert_eq!(serde_json::to_value(aggregate.config()).unwrap(),serde_json::to_value(&old).unwrap());assert_eq!(serde_json::to_value(file.load().aggregate).unwrap(),serde_json::to_value(&old).unwrap());
        assert!(aggregate.configure_account_ports(1,1080,37201,1080,&file).await.is_err());
        assert!(aggregate.configure_account_ports(1,1082,37201,1080,&file).await.is_err());
        let a=std::net::TcpListener::bind((Ipv4Addr::LOCALHOST,0)).unwrap();let b=std::net::TcpListener::bind((Ipv4Addr::LOCALHOST,0)).unwrap();let pa=a.local_addr().unwrap().port();let pb=b.local_addr().unwrap().port();drop(a);drop(b);
        let (one,two)=tokio::join!(aggregate.configure_account_ports(1,pa,37201,1080,&file),aggregate.configure_account_ports(2,pb,37202,1080,&file));one.unwrap();two.unwrap();
        let saved=file.load().aggregate;assert_eq!(saved.paths[0].port,pa);assert_eq!(saved.paths[1].port,pb);assert_eq!(serde_json::to_value(aggregate.config()).unwrap(),serde_json::to_value(saved).unwrap());
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
    fn selected_paths_and_primary_port_are_validated_without_changing_legacy_defaults() {
        let mut c=config(Policy::RoundRobin);
        assert!(c.selected_profiles.is_none());
        c.selected_profiles=Some(vec![2]);c.primary_port=Some(1080);
        assert!(c.validate(37128).is_ok());
        c.selected_profiles=Some(vec![2,2]);assert!(c.validate(37128).is_err());
        c.selected_profiles=Some(vec![8]);assert!(c.validate(37128).is_err());
        c.selected_profiles=Some(vec![2]);c.primary_port=Some(1081);assert!(c.validate(37128).is_err());
        c.primary_port=Some(0);assert!(c.validate(37128).is_err());
    }
    #[tokio::test]
    async fn pool_selection_preserves_unselected_profiles_and_can_include_main_proxy() {
        let(a,ta,ha)=fake_proxy(0).await;let(b,tb,hb)=fake_proxy(0).await;
        let reservation=TcpListener::bind("127.0.0.1:0").await.unwrap();let listen=reservation.local_addr().unwrap().port();drop(reservation);
        let mut c=config(Policy::RoundRobin);c.listen_port=listen;c.paths[0].port=a;c.paths[1].port=b;
        c.primary_port=Some(a); // Must not overlap even an unselected account's port.
        assert!(c.validate(37128).is_err());
        c.paths[0].port=1085;c.selected_profiles=Some(vec![2]);
        let dir=tempfile::tempdir().unwrap();let aggregate=Aggregate::new(c,dir.path().into(),37128);
        aggregate.start().await.unwrap();
        assert_eq!(aggregate.config().paths.len(),2);
        assert_eq!(aggregate.snapshot().paths.iter().map(|p|p.profile_id).collect::<Vec<_>>(),vec![2,0]);
        let(mut first,code)=open(listen).await;assert_eq!(code,0);let(mut second,code)=open(listen).await;assert_eq!(code,0);
        for stream in [&mut first,&mut second]{stream.write_all(b"selected-path-bytes").await.unwrap();let mut bytes=[0;19];stream.read_exact(&mut bytes).await.unwrap();assert_eq!(&bytes,b"selected-path-bytes");}
        assert_eq!(ha.load(Ordering::Relaxed),1);assert_eq!(hb.load(Ordering::Relaxed),1);
        aggregate.stop().await;assert!(!ta.is_finished());assert!(!tb.is_finished());assert!(aggregate.workers.snapshots().is_empty());ta.abort();tb.abort();
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
    #[test]
    fn adaptive_uses_observed_latency_bulk_rate_load_and_weights_without_rewriting_old_policy(){
        let r=Runtime::new(config(Policy::Adaptive));
        for (i,millis,rate) in [(0,20,2_000_000),(1,200,250_000)] {
            let mut q=r.paths[i].quality.lock();q.setup(Duration::from_millis(millis));q.bulk(rate,Duration::from_secs(1));
        }
        assert_eq!(r.reserve(&[]).unwrap().index,0);
        r.paths[0].active.store(32,Ordering::Relaxed);
        assert_eq!(r.reserve(&[]).unwrap().index,1);
        r.paths[0].active.store(0,Ordering::Relaxed);
        let mut q=r.paths[0].quality.lock();let before=q.bulk_bps;q.bulk(1024,Duration::from_secs(5));assert_eq!(q.bulk_bps,before);drop(q);
        assert_eq!(Config::default().policy,Policy::LeastConnections);
    }
    #[tokio::test]
    async fn latency_races_only_handshakes_and_cancels_loser_without_replaying_payload(){
        let(slow,st,sh)=fake_proxy_delay(0,Duration::from_secs(2)).await;
        let(fast,ft,fh)=fake_proxy(0).await;
        let mut c=config(Policy::Latency);c.paths[0].port=slow;c.paths[1].port=fast;
        let(port,task,r)=pool(c).await;let started=Instant::now();
        let(mut stream,code)=open(port).await;assert_eq!(code,0);assert!(started.elapsed()<Duration::from_millis(1500));
        stream.write_all(b"one-upload-only").await.unwrap();let mut bytes=[0;15];stream.read_exact(&mut bytes).await.unwrap();assert_eq!(&bytes,b"one-upload-only");
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(r.paths.iter().map(|p|p.active.load(Ordering::Relaxed)).sum::<usize>(),1);
        assert_eq!(r.paths[0].sent.load(Ordering::Relaxed),0);assert_eq!(r.paths[1].sent.load(Ordering::Relaxed),15);
        assert_eq!(sh.load(Ordering::Relaxed),1);assert_eq!(fh.load(Ordering::Relaxed),1);
        drop(stream);task.abort();st.abort();ft.abort();
    }
    #[tokio::test]
    async fn adaptive_learns_on_real_connections_and_skips_slow_path_for_later_requests(){
        let(a,ta,ha)=fake_proxy_delay(0,Duration::from_millis(120)).await;let(b,tb,hb)=fake_proxy(0).await;
        let mut c=config(Policy::Adaptive);c.paths[0].port=a;c.paths[1].port=b;
        let(port,task,_)=pool(c).await;
        for _ in 0..8{let(mut s,code)=open(port).await;assert_eq!(code,0);s.write_all(b"x").await.unwrap();assert_eq!(s.read_u8().await.unwrap(),b'x');s.shutdown().await.unwrap();assert!(s.read_u8().await.is_err());}
        assert_eq!(ha.load(Ordering::Relaxed),1);assert_eq!(hb.load(Ordering::Relaxed),7);task.abort();ta.abort();tb.abort();
    }
    #[tokio::test]
    async fn latency_fast_success_does_not_open_an_extra_destination_and_rejections_fail_closed(){
        let(a,ta,ha)=fake_proxy(0).await;let(b,tb,hb)=fake_proxy(0).await;
        let mut c=config(Policy::Latency);c.paths[0].port=a;c.paths[1].port=b;
        let(port,task,_)=pool(c).await;let(s,code)=open(port).await;assert_eq!(code,0);
        assert_eq!(ha.load(Ordering::Relaxed),1);assert_eq!(hb.load(Ordering::Relaxed),0);drop(s);task.abort();ta.abort();tb.abort();
        let(a,ta,_)=fake_proxy(2).await;let(b,tb,_)=fake_proxy(2).await;
        let mut c=config(Policy::Latency);c.paths[0].port=a;c.paths[1].port=b;
        let(port,task,r)=pool(c).await;assert_eq!(open(port).await.1,2);
        assert!(r.paths.iter().all(|p|p.active.load(Ordering::Relaxed)==0));
        task.abort();ta.abort();tb.abort();
    }
    async fn fake_proxy(code: u8) -> (u16, JoinHandle<()>, Arc<AtomicUsize>) {
        fake_proxy_delay(code,Duration::ZERO).await
    }
    async fn fake_proxy_delay(code:u8,delay:Duration)->(u16,JoinHandle<()>,Arc<AtomicUsize>){
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let count = Arc::new(AtomicUsize::new(0));
        let hits = count.clone();
        let task = tokio::spawn(async move {
            let mut clients = JoinSet::new();
            loop {
                tokio::select! {accepted=listener.accept()=>{let(mut s,_)=accepted.unwrap();let hits=hits.clone();clients.spawn(async move{let mut head=[0;3];s.read_exact(&mut head).await.unwrap();assert_eq!(head,[5,1,0]);s.write_all(&[5,0]).await.unwrap();let mut head=[0;4];s.read_exact(&mut head).await.unwrap();let n=match head[3]{1=>4,4=>16,3=>s.read_u8().await.unwrap()as usize,_=>panic!("invalid type")};let mut target=vec![0;n+2];s.read_exact(&mut target).await.unwrap();hits.fetch_add(1,Ordering::Relaxed);tokio::time::sleep(delay).await;reply(&mut s,code).await.unwrap();if code==0{let (mut read,mut write)=s.split();let _=tokio::io::copy(&mut read,&mut write).await;}});},_=clients.join_next(),if !clients.is_empty()=>{}}
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
