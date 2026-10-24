//! Explicitly started headless profiles with independent credentials and keys.
use parking_lot::Mutex;
use serde::Serialize;
use std::{
    collections::HashMap,
    io::{self, Read, Write},
    net::{Ipv4Addr, TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
struct Worker {
    child: Child,
    port: u16,
}
pub struct Workers {
    directory: PathBuf,
    children: Mutex<HashMap<usize, Worker>>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    slot: usize,
    running: bool,
    management_port: u16,
}
impl Workers {
    pub fn new(directory: PathBuf) -> Self {
        Self {
            directory,
            children: Mutex::new(HashMap::new()),
        }
    }
    pub fn snapshots(&self) -> Vec<Snapshot> {
        let mut children = self.children.lock();
        children
            .iter_mut()
            .map(|(slot, w)| Snapshot {
                slot: *slot,
                running: matches!(w.child.try_wait(), Ok(None)),
                management_port: w.port,
            })
            .collect()
    }
    pub fn any_running(&self) -> bool {
        self.snapshots().iter().any(|w| w.running)
    }
    pub fn start(&self, slot: usize, path: crate::aggregate::PathConfig) -> io::Result<()> {
        let mut children = self.children.lock();
        if let Some(w) = children.get_mut(&slot) {
            if w.child.try_wait()?.is_none() {
                return Err(io::Error::other("Worker already running"));
            }
        }
        children.remove(&slot);
        drop(children);
        // Verify both sockets before touching this profile's config.
        let http = TcpListener::bind((Ipv4Addr::LOCALHOST, path.management_port))?;
        let socks = TcpListener::bind((Ipv4Addr::LOCALHOST, path.port))?;
        let directory = self
            .directory
            .join("aggregate-profiles")
            .join(format!("path-{}", slot));
        let lock = crate::vault::lock_directory(&directory)?;
        let mut config = crate::config::Config::load(Some(&directory))?;
        config.port = path.management_port;
        config.socks5_port = path.port;
        config.save(Some(&directory))?;
        drop(lock);
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args([
                "--headless",
                "--managed-profile",
                "--port",
                &path.management_port.to_string(),
                "--config-dir",
            ])
            .arg(&directory)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        drop(http);
        drop(socks);
        let mut child = command.spawn()?;
        let started = Instant::now();
        loop {
            if let Some(_) = child.try_wait()? {
                return Err(io::Error::other(
                    "Worker exited during startup; check profile lock and ports",
                ));
            }
            if ready(path.management_port, child.id()) {
                break;
            }
            if started.elapsed() > Duration::from_secs(10) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Worker startup timed out",
                ));
            }
            std::thread::sleep(Duration::from_millis(80));
        }
        self.children.lock().insert(
            slot,
            Worker {
                child,
                port: path.management_port,
            },
        );
        Ok(())
    }
    pub fn stop(&self, slot: usize) -> io::Result<()> {
        let worker = self.children.lock().remove(&slot);
        if let Some(mut w) = worker {
            stop(&mut w);
        }
        Ok(())
    }
    pub fn stop_all(&self) {
        let workers: Vec<_> = self.children.lock().drain().map(|(_, w)| w).collect();
        std::thread::scope(|scope| {
            for mut worker in workers {
                scope.spawn(move || stop(&mut worker));
            }
        });
    }
}
impl Drop for Workers {
    fn drop(&mut self) {
        for (_, mut w) in self.children.get_mut().drain() {
            let _ = w.child.kill();
            let _ = w.child.wait();
        }
    }
}
fn connect(port: u16) -> io::Result<TcpStream> {
    let stream = TcpStream::connect_timeout(
        &std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        Duration::from_millis(300),
    )?;
    stream.set_read_timeout(Some(Duration::from_millis(500)))?;
    stream.set_write_timeout(Some(Duration::from_millis(500)))?;
    Ok(stream)
}
fn ready(port: u16, pid: u32) -> bool {
    let Ok(mut s) = connect(port) else {
        return false;
    };
    let req =
        format!("GET /instance HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    if s.write_all(req.as_bytes()).is_err() {
        return false;
    }
    let mut reply = String::new();
    if s.take(65536).read_to_string(&mut reply).is_err() {
        return false;
    }
    reply.starts_with("HTTP/1.1 200")
        && reply
            .split_once("\r\n\r\n")
            .and_then(|(_, body)| serde_json::from_str::<serde_json::Value>(body).ok())
            .and_then(|v| v["pid"].as_u64())
            == Some(pid as u64)
}
fn stop(w: &mut Worker) {
    if w.child.try_wait().ok().flatten().is_some() {
        return;
    }
    if ready(w.port, w.child.id()) {
        if let Ok(mut stream) = connect(w.port) {
            let request=format!("POST /shutdown HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nOrigin: http://127.0.0.1:{}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",w.port,w.port);
            let _ = stream.write_all(request.as_bytes());
        }
    }
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(3) {
        if w.child.try_wait().ok().flatten().is_some() {
            return;
        }
        std::thread::sleep(Duration::from_millis(40));
    }
    let _ = w.child.kill();
    let _ = w.child.wait();
}
