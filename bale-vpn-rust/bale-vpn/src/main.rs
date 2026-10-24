//! `bale-vpn` — single Rust binary replacing the Node app.
//!
//! Modes:
//!   - **client** (default): place a call to a configured peer,
//!     run a local SOCKS5 listener over the resulting QUIC channel.
//!   - **server**: accept incoming calls via Bale's admission flow,
//!     run a per-call NAT (kernel TUN on Linux/macOS, userspace on
//!     any OS) bridging IP packets to host sockets.
//!
//! HTTP UI on `127.0.0.1:<port>` for sign-in / status / settings.
//! See `ui.rs`. `--headless` skips opening the (future) native
//! webview but the HTTP server runs either way.

#![cfg_attr(all(windows, feature = "gui"), windows_subsystem = "windows")]

use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod client;
mod reconnect;
mod aggregate;
mod workers;
mod profiles;
mod backup;
mod device;
mod config;
mod vault;
mod settings;
mod daemon;
mod server;
// Kernel-TUN device open/configure — Unix-only (uses `std::os::fd::RawFd`
// + TUNSETIFF/utun ioctls). Windows server/client run userspace NAT and
// never touch a kernel TUN, so the module isn't compiled there.
#[cfg(unix)]
mod tun;
mod ui;

#[cfg(feature = "gui")]
mod ui_native;

/// Top-level CLI. Mode (server / client) is a subcommand so
/// per-mode args (`--nat-mode` for server, `--client-tun` for
/// client) only show up under the right branch — clap rejects
/// `bale-vpn server --client-tun` with a clear error.
///
/// Omit the subcommand to launch the daemon with mode unset; the
/// UI picker prompts on first run.
#[derive(Parser, Debug)]
#[command(name = "bale-vpn", version, about = "Bale VPN — Rust client/server.")]
struct Cli {
    /// HTTP UI port. Bound to 127.0.0.1.
    #[arg(long)]
    port: Option<u16>,

    /// Run without opening a native webview (GUI builds only).
    /// On builds without the `gui` feature this flag is a no-op.
    #[arg(long, default_value_t = false)]
    headless: bool,
    /// Internal: exit when the supervisor's stdin pipe closes.
    #[arg(long, hide = true)]
    managed_profile: bool,

    /// Config directory. Defaults to the directory of the binary.
    #[arg(long)]
    config_dir: Option<PathBuf>,

    /// Mode + its mode-specific args. Optional — without it the
    /// daemon starts with mode unset and waits for the UI picker.
    #[command(subcommand)]
    mode: Option<ModeCmd>,
}

#[derive(Subcommand, Debug)]
enum ModeCmd {
    /// Accept incoming calls and bridge them to host sockets.
    Server {
        /// NAT mode. `kernel` = TUN + iptables/pf (needs setup);
        /// `userspace` = in-process NAT (no privilege). Default:
        /// `userspace` on every OS.
        #[arg(long, value_enum)]
        nat_mode: Option<NatMode>,
    },
    /// Place a call to a configured peer and run a local SOCKS5
    /// listener over the resulting QUIC channel.
    Client {
        /// Also open a local TUN at `10.8.0.2/24` and route the
        /// peer's traffic through it. Needs `CAP_NET_ADMIN`
        /// (Linux) or root (macOS). Caller installs routes —
        /// e.g. `sudo ip route add default dev bale-c0` after
        /// the daemon is up. Without this flag, client mode
        /// runs SOCKS5 only (no system VPN).
        #[arg(long, default_value_t = false)]
        client_tun: bool,
    },
}

#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
enum NatMode { Kernel, Userspace }

fn main() {
    #[cfg(all(windows, feature="gui"))]
    if std::env::args().any(|arg| matches!(arg.as_str(),"--headless"|"--help"|"--version"|"-h"|"-V")) {
        #[link(name="kernel32")] extern "system" {fn AttachConsole(pid:u32)->i32;}
        unsafe {AttachConsole(u32::MAX);}
    }
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(
            // `quinn::endpoint=off` suppresses an ERROR-level
            // "I/O error: quic tunnel rx channel closed" that
            // fires on every normal client-disconnect — quinn
            // sees our intentional channel-close as a socket
            // error. The condition itself is fine; quinn just
            // logs noisily about it. Bump back to `warn` if you
            // need to debug a real quinn endpoint issue.
            "warn,lktunnel=warn,bale_signaling=warn,bale_vpn=warn,\
             webrtc=warn,livekit_api=warn,\
             quinn::endpoint=off",
        ),
    )
    .format_timestamp_millis()
    .init();

    let mut cli = Cli::parse();
    #[cfg(feature="gui")]
    if !cli.headless && cli.config_dir.is_none() {
        cli.config_dir=Some(desktop_directory());
    }

    // Flatten subcommand back into the merge-cli args. The
    // subcommand shape just gates which per-mode args are
    // accepted at the CLI; the daemon still consumes a flat
    // Resolved config.
    let (cli_mode, cli_nat, client_tun) = match &cli.mode {
        Some(ModeCmd::Server { nat_mode }) => (
            Some("server".to_string()),
            nat_mode.map(|m| match m { NatMode::Kernel => "kernel", NatMode::Userspace => "userspace" }.to_string()),
            false,
        ),
        Some(ModeCmd::Client { client_tun }) => (
            Some("client".to_string()),
            None,
            *client_tun,
        ),
        None => (None, None, false),
    };

    log::info!("bale-vpn starting (port={} mode={} nat={} headless={})",
        cli.port.unwrap_or(3001),
        cli_mode.clone().unwrap_or_else(|| "unset".into()),
        cli_nat .clone().unwrap_or_else(|| "default".into()),
        cli.headless);

    let cfg = config::Config::load(cli.config_dir.as_deref())
        .expect("failed to load config");
    #[cfg(feature="gui")]
    if !cli.headless&&cli.port.is_none(){cli.port=Some(if cfg.port==3001{37126}else{cfg.port});}
    let mut resolved = config::Resolved::merge_cli(
        &cfg,
        cli_mode,
        cli_nat,
        cli.port,
        client_tun,
    );
    if let Some(dir) = cli.config_dir {
        resolved.config_dir = dir;
    }
    resolved.managed_profile=cli.managed_profile;

    // GUI vs headless dispatch:
    //   - `gui` feature off:                  always headless
    //   - `gui` feature on  +  --headless:    headless (server deployments
    //                                         using the same binary)
    //   - `gui` feature on  + !--headless:    open a webview shell
    #[cfg(feature = "gui")]
    if !cli.headless {
        if let Err(e) = ui_native::run_gui(resolved) {
            log::error!("gui shell exited with error: {e}");
            #[cfg(windows)]{
                #[link(name="user32")]extern "system"{fn MessageBoxW(window:isize,text:*const u16,title:*const u16,flags:u32)->i32;}
                let message:Vec<u16>=format!("BaleVPN could not start.\n\n{e}\n\nCheck that the management port is free and the data folder is writable.").encode_utf16().chain(Some(0)).collect();
                let title:Vec<u16>="BaleVPN".encode_utf16().chain(Some(0)).collect();
                unsafe{MessageBoxW(0,message.as_ptr(),title.as_ptr(),0x10);}
            }
            std::process::exit(1);
        }
        return;
    }

    // Headless path — daemon owns the runtime directly.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("bale-vpn-rt")
        .build()
        .expect("tokio runtime");
    rt.block_on(async move {
        if let Err(e) = daemon::run(resolved).await {
            log::error!("daemon exited with error: {e}");
            std::process::exit(1);
        }
    });
}

#[cfg(feature="gui")]
fn desktop_directory()->PathBuf {
    let portable=std::env::current_exe().ok().and_then(|p|p.parent().map(|p|p.join("data")));
    if let Some(path)=&portable {if path.is_dir(){return path.clone();}}
    if let Some(path)=portable.as_ref().and_then(|p|p.parent()){if path.join(".bale-vpn_config.json").is_file(){return path.to_owned();}}
    #[cfg(windows)]{
        if let Some(path)=&portable {if std::fs::create_dir_all(path).is_ok(){return path.clone();}}
        if let Some(path)=std::env::var_os("LOCALAPPDATA"){return PathBuf::from(path).join("BaleVPN").join("data");}
    }
    #[cfg(target_os="macos")]
    if let Some(path)=std::env::var_os("HOME"){return PathBuf::from(path).join("Library/Application Support/BaleVPN");}
    #[cfg(target_os="linux")]{
        if let Some(path)=std::env::var_os("XDG_DATA_HOME"){return PathBuf::from(path).join("balevpn");}
        if let Some(path)=std::env::var_os("HOME"){return PathBuf::from(path).join(".local/share/balevpn");}
    }
    portable.unwrap_or_else(||PathBuf::from("data"))
}
