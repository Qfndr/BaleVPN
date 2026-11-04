//! Opt-in supervisor for one verified local Nasim endpoint kit.
use axum::{
    extract::{DefaultBodyLimit, Request, State},
    http::{header, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use ring::{
    digest,
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, ChildStdout, Command},
    sync::Mutex,
    time::timeout,
};
use zeroize::Zeroizing;

const LINE_LIMIT: usize = 65536;
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(20);
const STOP_TIMEOUT: Duration = Duration::from_secs(10);
const BRIDGE: &str = if cfg!(windows) {
    "nasim_relay_bridge.exe"
} else {
    "nasim_relay_bridge"
};
const ENDPOINT: &str = "nasim-asymmetric-endpoint.cjs";
const REQUIRED: &[&str] = &[
    ENDPOINT,
    BRIDGE,
    "build-info.json",
    "source/experiments/eitaa/client-profile.cjs",
    "source/experiments/eitaa/refresh-recovery.cjs",
    "source/experiments/eitaa/wire.cjs",
    "source/experiments/nasim/asymmetric-route.cjs",
    "source/experiments/nasim/auth-session.cjs",
    "source/experiments/nasim/call-codec.cjs",
    "source/experiments/nasim/call-session.cjs",
    "source/experiments/nasim/cleanup-intent.cjs",
    "source/experiments/nasim/http-client.cjs",
    "source/experiments/nasim/msgpack.cjs",
    "source/experiments/nasim/native-media-bridge.cjs",
    "source/experiments/nasim/official-call-gate.cjs",
    "source/experiments/nasim/official-web-reference.cjs",
    "source/experiments/nasim/server-clock.cjs",
    "source/experiments/nasim/signaling-connection.cjs",
    "source/experiments/nasim/sse-parser.cjs",
    "source/experiments/nasim/stream-cursor.cjs",
    "source/experiments/nasim/wire.cjs",
    "source/experiments/providers/countries.json",
    "source/experiments/providers/ice-diagnostics.cjs",
    "source/experiments/providers/phone.cjs",
    "source/experiments/providers/relay-media-bridge.cjs",
    "source/experiments/providers/session-vault.cjs",
    "source/experiments/rubika/call-recovery.cjs",
];

#[derive(Clone, Debug)]
pub(crate) struct Kit {
    pub directory: PathBuf,
    pub node: PathBuf,
    pub vault: PathBuf,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn is_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn certificate(value: &str) -> bool {
    (128..=16384).contains(&value.len()) && value.len() % 2 == 0 && is_hex(value)
}
fn regular(meta: &std::fs::Metadata, directory: bool) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return false;
        }
    }
    if directory {
        meta.is_dir()
    } else {
        meta.is_file()
    }
}

fn checked_path(path: &Path, directory: bool) -> Result<(), ()> {
    if !path.is_absolute() {
        return Err(());
    }
    // Inspect each ancestor as well as the leaf. In particular, a kit
    // directory or dependency cannot redirect through a junction/symlink.
    for (index, entry) in path.ancestors().enumerate() {
        let metadata = std::fs::symlink_metadata(entry).map_err(|_| ())?;
        if !regular(&metadata, index != 0 || directory) {
            return Err(());
        }
    }
    Ok(())
}

fn read_bounded(path: &Path, max: usize) -> Result<Vec<u8>, ()> {
    use std::io::Read;
    checked_path(path, false)?;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|_| ())?
        .take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() > max {
        return Err(());
    }
    Ok(bytes)
}

impl Kit {
    fn verify(&self) -> Result<String, ()> {
        checked_path(&self.directory, true)?;
        checked_path(&self.vault, true)?;
        checked_path(&self.node, false)?;
        let bytes = read_bounded(&self.directory.join("SHA256SUMS.txt"), 16384)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| ())?;
        let mut sums = std::collections::HashMap::new();
        for line in text.lines() {
            let (hash, file) = line.split_once("  ").ok_or(())?;
            if hash.len() != 64 || !is_hex(hash) || sums.insert(file, hash).is_some() {
                return Err(());
            }
        }
        for name in REQUIRED {
            let max = if *name == BRIDGE {
                32 * 1024 * 1024
            } else {
                512 * 1024
            };
            let file = read_bounded(&self.directory.join(name), max)?;
            if hex(digest::digest(&digest::SHA256, &file).as_ref()) != *sums.get(name).ok_or(())? {
                return Err(());
            }
        }
        let info: Value = serde_json::from_slice(&read_bounded(
            &self.directory.join("build-info.json"),
            16384,
        )?)
        .map_err(|_| ())?;
        let platform = if cfg!(windows) { "Windows" } else { "Linux" };
        let hash = *sums.get(BRIDGE).ok_or(())?;
        if info["platform"] != platform
            || info["architecture"] != "x86_64"
            || !info["sourceCommit"]
                .as_str()
                .is_some_and(|v| v.len() == 40 && is_hex(v))
            || !info["helpers"].as_array().is_some_and(|helpers| {
                helpers
                    .iter()
                    .filter(|item| item["provider"] == "nasim")
                    .count()
                    == 1
                    && helpers.iter().any(|item| {
                        item["provider"] == "nasim"
                            && item["file"] == BRIDGE
                            && item["sha256"] == hash
                    })
            })
        {
            return Err(());
        }
        Ok(hash.to_owned())
    }

    fn lock_vault(&self) -> Result<std::fs::File, ()> {
        let path = self.vault.join(".balevpn-nasim-endpoint.lock");
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = match options.open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                checked_path(&path, false)?;
                std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(path)
                    .map_err(|_| ())?
            }
            Err(_) => return Err(()),
        };
        file.try_lock().map_err(|_| ())?;
        Ok(file)
    }
}

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Role {
    Client,
    Server,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Start {
    role: Role,
    slot: u8,
    peer_user_id: String,
    socks_port: Option<u16>,
    vault_password: String,
}
impl Drop for Start {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.vault_password.zeroize();
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StartMessage<'a> {
    command: &'static str,
    role: Role,
    slot: u8,
    peer_user_id: &'a str,
    socks_port: u16,
    vault_directory: &'a Path,
    vault_password: &'a str,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Trust {
    public_certificate: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct QuicMetrics {
    rtt_ms: f64,
    lost_packets: u64,
    sent_packets: u64,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct CarrierMetrics {
    received_bytes: u64,
    sent_bytes: u64,
    quic: Option<QuicMetrics>,
}

fn metric_counter(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .filter(|count| *count <= 9_007_199_254_740_991)
}

impl CarrierMetrics {
    fn from_worker(value: &Value, client: bool) -> Option<Self> {
        let received_bytes = metric_counter(&value["receivedBytes"])?;
        let sent_bytes = metric_counter(&value["sentBytes"])?;
        let quic = if client {
            Self::quic_from_worker(&value["quic"])
        } else {
            None
        };
        Some(Self {
            received_bytes,
            sent_bytes,
            quic,
        })
    }

    fn quic_from_worker(value: &Value) -> Option<QuicMetrics> {
        let rtt_ms = value["rttMs"]
            .as_f64()
            .filter(|rtt| (0.0..=120_000.0).contains(rtt))?;
        let sent_packets = metric_counter(&value["sentPackets"])?;
        let lost_packets =
            metric_counter(&value["lostPackets"]).filter(|lost| *lost <= sent_packets)?;
        Some(QuicMetrics {
            rtt_ms,
            sent_packets,
            lost_packets,
        })
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Snapshot {
    phase: &'static str,
    role: Option<Role>,
    proxy_port: Option<u16>,
    public_certificate: Option<String>,
    route_proof: Option<&'static str>,
    peer_authenticated: bool,
    proxy_ready: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    metrics: Option<CarrierMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    termination: Option<&'static str>,
    cleanup_pending: bool,
    error: Option<&'static str>,
}
impl Default for Snapshot {
    fn default() -> Self {
        Self {
            phase: "idle",
            role: None,
            proxy_port: None,
            public_certificate: None,
            route_proof: None,
            peer_authenticated: false,
            proxy_ready: false,
            metrics: None,
            termination: None,
            cleanup_pending: false,
            error: None,
        }
    }
}

struct Worker {
    child: Child,
    input: Option<ChildStdin>,
    output: BufReader<ChildStdout>,
    _vault_lock: std::fs::File,
}
impl Worker {
    fn node_command(kit: &Kit) -> Command {
        let mut command = Command::new(&kit.node);
        command
            .current_dir(&kit.directory)
            .env_clear()
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        for key in ["SystemRoot", "TEMP", "TMP", "TMPDIR"] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        #[cfg(windows)]
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW
        command
    }

    async fn check_node(kit: &Kit) -> Result<(), ()> {
        timeout(Duration::from_secs(3), async {
            let mut child = Self::node_command(kit)
                .arg("--version")
                .stdin(Stdio::null())
                .spawn()
                .map_err(|_| ())?;
            let mut output = Vec::new();
            child
                .stdout
                .take()
                .ok_or(())?
                .take(64)
                .read_to_end(&mut output)
                .await
                .map_err(|_| ())?;
            if !child.wait().await.map_err(|_| ())?.success() {
                return Err(());
            }
            let version = std::str::from_utf8(&output).map_err(|_| ())?.trim();
            let major = version
                .strip_prefix('v')
                .and_then(|v| v.split_once('.'))
                .and_then(|(major, _)| major.parse::<u16>().ok())
                .ok_or(())?;
            if major < 22 {
                return Err(());
            }
            Ok(())
        })
        .await
        .map_err(|_| ())?
    }

    fn launch(kit: &Kit, hash: &str, vault_lock: std::fs::File) -> Result<Self, ()> {
        let mut command = Self::node_command(kit);
        command
            .arg(kit.directory.join(ENDPOINT))
            .arg("--run-once")
            .env("BALEVPN_NASIM_REPO", kit.directory.join("source"))
            .env("BALEVPN_NASIM_BRIDGE", kit.directory.join(BRIDGE))
            .env("BALEVPN_EXPECTED_NASIM_HELPER_SHA256", hash)
            .stdin(Stdio::piped());
        let mut child = command.spawn().map_err(|_| ())?;
        let input = child.stdin.take().ok_or(())?;
        let output = child.stdout.take().ok_or(())?;
        Ok(Self {
            child,
            input: Some(input),
            output: BufReader::new(output),
            _vault_lock: vault_lock,
        })
    }

    async fn receive(&mut self) -> Result<Value, ()> {
        let mut bytes = Vec::new();
        let count = (&mut self.output)
            .take(LINE_LIMIT as u64 + 1)
            .read_until(b'\n', &mut bytes)
            .await
            .map_err(|_| ())?;
        if count > LINE_LIMIT || bytes.last() != Some(&b'\n') {
            return Err(());
        }
        serde_json::from_slice(&bytes).map_err(|_| ())
    }

    async fn exchange(&mut self, bytes: &[u8]) -> Result<Value, ()> {
        timeout(EXCHANGE_TIMEOUT, async {
            let input = self.input.as_mut().ok_or(())?;
            input.write_all(bytes).await.map_err(|_| ())?;
            input.write_all(b"\n").await.map_err(|_| ())?;
            self.receive().await
        })
        .await
        .map_err(|_| ())?
    }

    async fn stop(mut self) -> bool {
        self.input.take();
        let result = timeout(STOP_TIMEOUT, async {
            // A timed-out exchange may still produce one result before EOF
            // is noticed. Drain bounded replies until the cleanup receipt.
            for _ in 0..3 {
                let event = self.receive().await?;
                if event["event"] == "closed" {
                    let status = self.child.wait().await.map_err(|_| ())?;
                    return Ok::<bool, ()>(status.success() && clean_closed(&event));
                }
            }
            Err(())
        })
        .await;
        if !matches!(result, Ok(Ok(_))) {
            self.kill_and_reap();
        }
        matches!(result, Ok(Ok(true)))
    }

    fn kill_and_reap(mut self) {
        self.input.take();
        let _ = self.child.start_kill();
        // A forced stop is uncertain. Keep the vault lock until the OS
        // confirms exit so a new worker cannot race an old one.
        tokio::spawn(async move {
            while self.child.wait().await.is_err() {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
    }
}

fn clean_closed(event: &Value) -> bool {
    event["event"] == "closed" && event["endCompleted"] == true && event["cleanupPending"] == false
}

#[derive(Default)]
struct Runtime {
    worker: Option<Worker>,
    snapshot: Snapshot,
}
impl Runtime {
    async fn stop(&mut self) -> bool {
        let clean = match self.worker.take() {
            Some(worker) => worker.stop().await,
            None => !self.snapshot.cleanup_pending,
        };
        self.snapshot = Snapshot {
            cleanup_pending: !clean,
            error: (!clean).then_some("cleanup_unconfirmed"),
            ..Snapshot::default()
        };
        clean
    }

    async fn failed(&mut self, event: Option<&Value>) -> Snapshot {
        let clean = if let Some(event) = event.filter(|event| event["event"] == "closed") {
            // The worker already emitted the cleanup result. Reap it without
            // trying to read a second result as a new response.
            if let Some(mut worker) = self.worker.take() {
                worker.input.take();
                match timeout(STOP_TIMEOUT, worker.child.wait()).await {
                    Ok(Ok(status)) => status.success() && clean_closed(event),
                    _ => {
                        worker.kill_and_reap();
                        false
                    }
                }
            } else {
                false
            }
        } else {
            self.stop().await
        };
        self.snapshot = Snapshot {
            phase: "failed",
            cleanup_pending: !clean,
            error: Some("endpoint_failed"),
            ..Snapshot::default()
        };
        self.snapshot.clone()
    }

    fn update(&mut self, event: &Value) -> Result<Snapshot, ()> {
        let phase = match event["phase"].as_str() {
            Some("prepared") => "prepared",
            Some("ready") => "ready",
            Some("incoming") => "incoming",
            Some("dialing") => "dialing",
            Some("outgoing") => "outgoing",
            Some("negotiating") => "negotiating",
            Some("connected") => "connected",
            Some("ended") => "ended",
            Some("uncertain") => "uncertain",
            Some("idle") => "idle",
            Some("failed") => "failed",
            _ => return Err(()),
        };
        let route_proof = match event["routeProof"].as_str() {
            Some("client-relay/server-public") => Some("client-relay/server-public"),
            Some("unverified") => Some("unverified"),
            _ => None,
        };
        let peer_authenticated = phase == "connected"
            && route_proof == Some("client-relay/server-public")
            && event["peerAuthenticated"] == true;
        self.snapshot.phase = phase;
        self.snapshot.route_proof = route_proof;
        self.snapshot.peer_authenticated = peer_authenticated;
        self.snapshot.proxy_ready = peer_authenticated && event["proxyReady"] == true;
        self.snapshot.metrics = match self.snapshot.role {
            Some(Role::Client) if self.snapshot.proxy_ready => {
                CarrierMetrics::from_worker(&event["metrics"], true)
            }
            Some(Role::Server) if peer_authenticated => {
                CarrierMetrics::from_worker(&event["metrics"], false)
            }
            _ => None,
        };
        self.snapshot.cleanup_pending = event["cleanupPending"] == true;
        self.snapshot.termination = if matches!(phase, "ended" | "uncertain" | "failed") {
            match event["termination"].as_str() {
                Some("bye") => Some("bye"),
                Some("reject") => Some("reject"),
                Some("busy") => Some("busy"),
                Some("other_device") => Some("other_device"),
                Some("media_failure") => Some("media_failure"),
                Some("stream_reset") => Some("stream_reset"),
                Some("event_stream_not_connected") => Some("event_stream_not_connected"),
                Some("call_connection_changed") => Some("call_connection_changed"),
                Some("cleanup_save_failed") => Some("cleanup_save_failed"),
                Some("call_timeout") => Some("call_timeout"),
                Some("transport_closed") => Some("transport_closed"),
                _ => None,
            }
        } else {
            None
        };
        self.snapshot.error = matches!(phase, "failed" | "uncertain").then_some("endpoint_failed");
        Ok(self.snapshot.clone())
    }
}

pub(crate) struct Service {
    kit: Kit,
    csrf: String,
    closing: AtomicBool,
    runtime: Arc<Mutex<Runtime>>,
}

impl Service {
    pub fn new(kit: Kit) -> Arc<Self> {
        let mut bytes = [0u8; 32];
        SystemRandom::new().fill(&mut bytes).expect("OS randomness");
        Arc::new(Self {
            kit,
            csrf: hex(&bytes),
            closing: AtomicBool::new(false),
            runtime: Arc::new(Mutex::default()),
        })
    }

    pub async fn disconnect(&self) -> bool {
        self.runtime.lock().await.stop().await
    }

    pub async fn shutdown(&self) {
        self.closing.store(true, Ordering::Release);
        self.disconnect().await;
    }

    async fn operation(self: Arc<Self>, operation: Operation) -> Reply {
        // The task owns the exchange even if the browser abandons its request.
        // A second request must not queue behind a hung child.
        let mut runtime = self
            .runtime
            .clone()
            .try_lock_owned()
            .map_err(|_| StatusCode::CONFLICT)?;
        if self.closing.load(Ordering::Acquire) {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        tokio::spawn(async move {
            let runtime = &mut *runtime;
            match operation {
                Operation::Start(start) => self.start(runtime, &start).await,
                Operation::Stop => {
                    runtime.stop().await;
                    Ok(Json(runtime.snapshot.clone()))
                }
                Operation::Command(command) => {
                    let allowed = match command["command"].as_str() {
                        Some("state") => true,
                        Some("trust") => {
                            runtime.snapshot.phase == "prepared"
                                && command["publicCertificate"].as_str()
                                    != runtime.snapshot.public_certificate.as_deref()
                        }
                        Some("dial") => {
                            runtime.snapshot.role == Some(Role::Client)
                                && runtime.snapshot.phase == "ready"
                        }
                        Some("accept") => {
                            runtime.snapshot.role == Some(Role::Server)
                                && runtime.snapshot.phase == "incoming"
                        }
                        _ => false,
                    };
                    if !allowed {
                        return Err(StatusCode::CONFLICT);
                    }
                    let Some(worker) = runtime.worker.as_mut() else {
                        return if command["command"] == "state" {
                            Ok(Json(runtime.snapshot.clone()))
                        } else {
                            Err(StatusCode::CONFLICT)
                        };
                    };
                    let encoded =
                        serde_json::to_vec(&command).map_err(|_| StatusCode::BAD_REQUEST)?;
                    let event = worker.exchange(&encoded).await;
                    if let Ok(event) = &event {
                        if event["event"] == "state" {
                            if let Ok(snapshot) = runtime.update(event) {
                                return Ok(Json(snapshot));
                            }
                        }
                    }
                    Ok(Json(runtime.failed(event.as_ref().ok()).await))
                }
            }
        })
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    }

    async fn start(&self, runtime: &mut Runtime, start: &Start) -> Reply {
        if runtime.worker.is_some() {
            return Err(StatusCode::CONFLICT);
        }
        let port = if start.role == Role::Server {
            0
        } else {
            start.socks_port.unwrap_or(1098)
        };
        if !matches!(start.slot, 1 | 2)
            || start.vault_password.is_empty()
            || start.vault_password.encode_utf16().count() > 1024
            || start.peer_user_id.starts_with('0')
            || !start.peer_user_id.bytes().all(|b| b.is_ascii_digit())
            || !start
                .peer_user_id
                .parse::<u64>()
                .is_ok_and(|id| (1..=9_007_199_254_740_991).contains(&id))
            || start.role == Role::Client && port < 1024
        {
            return Err(StatusCode::BAD_REQUEST);
        }
        let kit = self.kit.clone();
        let (hash, lock) = tokio::task::spawn_blocking(move || {
            let hash = kit.verify().map_err(|_| StatusCode::PRECONDITION_FAILED)?;
            let lock = kit.lock_vault().map_err(|_| StatusCode::CONFLICT)?;
            Ok::<_, StatusCode>((hash, lock))
        })
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)??;
        Worker::check_node(&self.kit)
            .await
            .map_err(|_| StatusCode::PRECONDITION_FAILED)?;
        if self.closing.load(Ordering::Acquire) {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        let message = StartMessage {
            command: "start",
            role: start.role,
            slot: start.slot,
            peer_user_id: &start.peer_user_id,
            socks_port: port,
            vault_directory: &self.kit.vault,
            vault_password: &start.vault_password,
        };
        let encoded =
            Zeroizing::new(serde_json::to_vec(&message).map_err(|_| StatusCode::BAD_REQUEST)?);
        let mut worker =
            Worker::launch(&self.kit, &hash, lock).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let event = worker.exchange(&encoded).await;
        runtime.worker = Some(worker);
        if let Ok(event) = &event {
            let role = if start.role == Role::Client {
                "client"
            } else {
                "server"
            };
            if event["event"] == "prepared" && event["role"] == role {
                if let Some(cert) = event["publicCertificate"]
                    .as_str()
                    .filter(|value| certificate(value))
                {
                    runtime.snapshot = Snapshot {
                        phase: "prepared",
                        role: Some(start.role),
                        proxy_port: (start.role == Role::Client).then_some(port),
                        public_certificate: Some(cert.to_owned()),
                        ..Snapshot::default()
                    };
                    return Ok(Json(runtime.snapshot.clone()));
                }
            }
        }
        Ok(Json(runtime.failed(event.as_ref().ok()).await))
    }
}

enum Operation {
    Start(Start),
    Stop,
    Command(Value),
}
type Reply = Result<Json<Snapshot>, StatusCode>;

async fn csrf(State(service): State<Arc<Service>>, request: Request, next: Next) -> Response {
    if service.closing.load(Ordering::Acquire) {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    if request.method() != Method::GET && request.method() != Method::HEAD {
        let token = request
            .headers()
            .get("x-provider-csrf")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let equal = token.len() == service.csrf.len()
            && token
                .bytes()
                .zip(service.csrf.bytes())
                .fold(0u8, |diff, (a, b)| diff | (a ^ b))
                == 0;
        if !equal {
            return StatusCode::FORBIDDEN.into_response();
        }
        if !request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.split(';').next() == Some("application/json"))
        {
            return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
        }
    }
    next.run(request).await
}
async fn info(State(s): State<Arc<Service>>) -> Json<Value> {
    Json(
        json!({"available":true,"csrfToken":s.csrf,"singleCall":true,"callLimitSeconds":90,"freshPairing":true}),
    )
}
async fn state(State(s): State<Arc<Service>>) -> Reply {
    s.operation(Operation::Command(json!({"command":"state"})))
        .await
}
async fn start(State(s): State<Arc<Service>>, Json(start): Json<Start>) -> Reply {
    s.operation(Operation::Start(start)).await
}
async fn trust(State(s): State<Arc<Service>>, Json(body): Json<Trust>) -> Reply {
    if !certificate(&body.public_certificate) {
        return Err(StatusCode::BAD_REQUEST);
    }
    s.operation(Operation::Command(
        json!({"command":"trust","publicCertificate":body.public_certificate}),
    ))
    .await
}
async fn dial(State(s): State<Arc<Service>>, Json(_): Json<Empty>) -> Reply {
    s.operation(Operation::Command(json!({"command":"dial"})))
        .await
}
async fn accept(State(s): State<Arc<Service>>, Json(_): Json<Empty>) -> Reply {
    s.operation(Operation::Command(json!({"command":"accept"})))
        .await
}
async fn stop(State(s): State<Arc<Service>>, Json(_): Json<Empty>) -> Reply {
    s.operation(Operation::Stop).await
}
pub(crate) fn router(service: Arc<Service>) -> Router {
    Router::new()
        .route(
            "/ui",
            get(|| async { axum::response::Html(include_str!("../assets/nasim.html")) }),
        )
        .route(
            "/ui.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("../assets/nasim-ui.js"),
                )
            }),
        )
        .route("/info", get(info))
        .route("/state", get(state))
        .route("/start", post(start))
        .route("/trust", post(trust))
        .route("/dial", post(dial))
        .route("/accept", post(accept))
        .route("/stop", post(stop))
        .layer(DefaultBodyLimit::max(LINE_LIMIT))
        .layer(middleware::from_fn_with_state(service.clone(), csrf))
        .with_state(service)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn management_rejects_mutations_without_provider_token_or_json() {
        use axum::body::Body;
        use tower::ServiceExt;
        let service = Service::new(Kit {
            directory: PathBuf::new(),
            node: PathBuf::new(),
            vault: PathBuf::new(),
        });
        let app = router(service.clone());
        for (token, content_type, status) in [
            (None, "application/json", StatusCode::FORBIDDEN),
            (
                Some(service.csrf.as_str()),
                "text/plain",
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ),
            (
                Some(service.csrf.as_str()),
                "application/json",
                StatusCode::OK,
            ),
        ] {
            let mut request = Request::builder()
                .method("POST")
                .uri("/stop")
                .header(header::CONTENT_TYPE, content_type);
            if let Some(token) = token {
                request = request.header("x-provider-csrf", token);
            }
            let response = app
                .clone()
                .oneshot(request.body(Body::from("{}")).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), status);
        }
    }

    #[test]
    fn worker_state_only_projects_redacted_values_and_requires_route_proof() {
        let mut runtime = Runtime::default();
        let mut event = json!({
            "event": "state", "phase": "connected", "routeProof": "unverified",
            "peerAuthenticated": true, "proxyReady": true, "cleanupPending": true,
            "private": "fixture-secret"
        });
        let state = runtime.update(&event).unwrap();
        assert!(!state.peer_authenticated && !state.proxy_ready && state.cleanup_pending);
        event["routeProof"] = json!("client-relay/server-public");
        let state = runtime.update(&event).unwrap();
        assert!(state.peer_authenticated && state.proxy_ready);
        assert!(!serde_json::to_string(&state)
            .unwrap()
            .contains("fixture-secret"));
        event["phase"] = json!("fixture-secret");
        assert!(runtime.update(&event).is_err());
    }

    #[test]
    fn terminal_state_preserves_only_fixed_diagnostic_codes() {
        let mut runtime = Runtime::default();
        let mut event = json!({"phase": "uncertain", "termination": "call_timeout"});
        let state = runtime.update(&event).unwrap();
        assert_eq!(state.phase, "uncertain");
        assert_eq!(state.termination, Some("call_timeout"));
        event["termination"] = json!("stream_reset");
        assert_eq!(
            runtime.update(&event).unwrap().termination,
            Some("stream_reset")
        );
        event["termination"] = json!("event_stream_not_connected");
        assert_eq!(
            runtime.update(&event).unwrap().termination,
            Some("event_stream_not_connected")
        );
        event["termination"] = json!("private provider response");
        assert!(runtime.update(&event).unwrap().termination.is_none());
        event["phase"] = json!("ready");
        event["termination"] = json!("busy");
        assert!(runtime.update(&event).unwrap().termination.is_none());
    }

    #[test]
    fn optional_carrier_metrics_follow_route_and_worker_compatibility() {
        let mut runtime = Runtime::default();
        runtime.snapshot.role = Some(Role::Client);
        let mut event = json!({
            "phase": "connected", "routeProof": "client-relay/server-public",
            "peerAuthenticated": true, "proxyReady": true
        });
        assert!(runtime.update(&event).unwrap().metrics.is_none());
        event["metrics"] = json!({
            "receivedBytes": 1024, "sentBytes": 512,
            "quic": {"rttMs": 12.5, "lostPackets": 1, "sentPackets": 10, "private": "ignored"}
        });
        let state = serde_json::to_value(runtime.update(&event).unwrap()).unwrap();
        assert_eq!(
            state["metrics"],
            json!({
                "receivedBytes": 1024, "sentBytes": 512,
                "quic": {"rttMs": 12.5, "lostPackets": 1, "sentPackets": 10}
            })
        );
        event["metrics"]["quic"]["lostPackets"] = json!(11);
        assert!(runtime
            .update(&event)
            .unwrap()
            .metrics
            .unwrap()
            .quic
            .is_none());
        event["metrics"]["sentBytes"] = json!(9_007_199_254_740_992_u64);
        assert!(runtime.update(&event).unwrap().metrics.is_none());
        event["metrics"]["sentBytes"] = json!(512);
        event["routeProof"] = json!("unverified");
        assert!(runtime.update(&event).unwrap().metrics.is_none());
    }

    #[test]
    fn only_confirmed_worker_close_reports_no_pending_cleanup() {
        let mut event = json!({"event":"closed","endCompleted":true,"cleanupPending":false});
        assert!(clean_closed(&event));
        event["endCompleted"] = json!(false);
        assert!(!clean_closed(&event));
        event["endCompleted"] = json!(true);
        event["cleanupPending"] = json!(true);
        assert!(!clean_closed(&event));
    }

    #[test]
    fn kit_verifies_every_required_file_and_rejects_tampering() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let kit = Kit {
            directory: root.clone(),
            node: root.join("node-fixture"),
            vault: root.join("vault-fixture"),
        };
        std::fs::write(&kit.node, b"node fixture").unwrap();
        std::fs::create_dir(&kit.vault).unwrap();
        let bridge_hash = hex(digest::digest(&digest::SHA256, b"fixture").as_ref());
        let mut sums = String::new();
        for name in REQUIRED {
            let path = root.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let bytes = if *name == "build-info.json" {
                serde_json::to_vec(&json!({
                    "sourceCommit": "1".repeat(40), "architecture": "x86_64",
                    "platform": if cfg!(windows) { "Windows" } else { "Linux" },
                    "helpers":[{"provider":"nasim","file":BRIDGE,"sha256":bridge_hash}]
                }))
                .unwrap()
            } else {
                b"fixture".to_vec()
            };
            std::fs::write(path, &bytes).unwrap();
            sums.push_str(&format!(
                "{}  {name}\n",
                hex(digest::digest(&digest::SHA256, &bytes).as_ref())
            ));
        }
        std::fs::write(root.join("SHA256SUMS.txt"), sums).unwrap();
        assert_eq!(kit.verify().unwrap(), bridge_hash);
        let lock = kit.lock_vault().unwrap();
        assert!(kit.lock_vault().is_err());
        drop(lock);
        assert!(kit.lock_vault().is_ok());
        std::fs::write(root.join(ENDPOINT), b"tampered").unwrap();
        assert!(kit.verify().is_err());
    }
}
