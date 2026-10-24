use crate::config::Resolved;
use serde::{Deserialize, Serialize};
use std::{cell::Cell, path::PathBuf, time::Duration};
use tao::{
    event::{Event, WindowEvent},
    event_loop::{ControlFlow, EventLoopBuilder},
    window::{ResizeDirection, Theme, WindowBuilder},
};
use tokio::sync::oneshot;
use tray_icon::{
    menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem},
    Icon, MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent,
};
use wry::WebViewBuilder;
static SHOW_WINDOW: std::sync::OnceLock<Box<dyn Fn() -> bool + Send + Sync>> =
    std::sync::OnceLock::new();
pub fn request_show() -> bool {
    SHOW_WINDOW.get().is_some_and(|show| show())
}
fn show_existing(port: u16) -> bool {
    use std::io::{Read, Write};
    let Ok(mut stream) = std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_millis(300),
    ) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
    if write!(stream,"POST /desktop/show HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: http://127.0.0.1:{port}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").is_err(){return false;}
    let mut reply = String::new();
    stream.take(4096).read_to_string(&mut reply).is_ok()
        && reply
            .split_once("\r\n\r\n")
            .and_then(|(_, body)| serde_json::from_str::<serde_json::Value>(body).ok())
            .is_some_and(|v| v["ok"] == true)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
struct DesktopSettings {
    close_to_tray: bool,
    start_minimized: bool,
    always_on_top: bool,
}
impl Default for DesktopSettings {
    fn default() -> Self {
        Self {
            close_to_tray: true,
            start_minimized: false,
            always_on_top: false,
        }
    }
}
#[derive(Debug)]
enum DesktopEvent {
    Quit,
    Show,
    Command(serde_json::Value),
    Menu(String),
    Download(bool),
}
fn icon() -> Icon {
    let mut rgba = vec![0; 32 * 32 * 4];
    for y in 0..32 {
        for x in 0..32 {
            let i = (y * 32 + x) * 4;
            let inside = (4..28).contains(&x) && (3..29).contains(&y);
            rgba[i..i + 4].copy_from_slice(if inside {
                &[31, 111, 235, 255]
            } else {
                &[0, 0, 0, 0]
            });
            if inside
                && ((x > 10 && x < 14 && y > 8 && y < 24)
                    || (x > 12 && x < 22 && (y == 9 || y == 16 || y == 23))
                    || (x == 22 && (10..23).contains(&y)))
            {
                rgba[i..i + 4].copy_from_slice(&[255, 255, 255, 255]);
            }
        }
    }
    Icon::from_rgba(rgba, 32, 32).unwrap()
}
pub fn run_gui(cfg: Resolved) -> Result<(), Box<dyn std::error::Error>> {
    let port = cfg.port;
    let settings_path = cfg.config_dir.join("desktop-settings.json");
    let mut preferences: DesktopSettings = std::fs::read(&settings_path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("bale-vpn-rt")
        .build()?;
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    let ready_error = ready_tx.clone();
    let (ended_tx, ended_rx) = oneshot::channel();
    let daemon_handle = rt.spawn(async move {
        if let Err(e) = crate::daemon::run_with_startup(cfg, shutdown_rx, Some(ready_tx)).await {
            let _ = ready_error.send(Err(e.to_string()));
            log::error!("desktop backend failed: {e}");
        }
        let _ = ended_tx.send(());
    });
    match ready_rx.recv_timeout(Duration::from_secs(15)) {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            if show_existing(port) {
                return Ok(());
            }
            return Err(error.into());
        }
        Err(_) => return Err("The local backend could not start".into()),
    }
    let event_loop = EventLoopBuilder::<DesktopEvent>::with_user_event().build();
    install_app_menu();
    let proxy = event_loop.create_proxy();
    let show_proxy = proxy.clone();
    let _ = SHOW_WINDOW.set(Box::new(move || {
        show_proxy.send_event(DesktopEvent::Show).is_ok()
    }));
    let menu_proxy = proxy.clone();
    MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
        let _ = menu_proxy.send_event(DesktopEvent::Menu(event.id.0));
    }));
    let tray_proxy = proxy.clone();
    TrayIconEvent::set_event_handler(Some(move |event| {
        if matches!(
            event,
            TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            }
        ) {
            let _ = tray_proxy.send_event(DesktopEvent::Show);
        }
    }));
    let menu = Menu::new();
    let mut labels = Vec::new();
    for (id, en, fa) in [
        ("show", "Open workspace", "باز کردن برنامه"),
        ("hide", "Hide window", "پنهان کردن پنجره"),
        ("connection", "Connection", "اتصال"),
        ("traffic", "Traffic & speed", "ترافیک و سرعت"),
        ("aggregate", "Accounts & pool", "حساب‌ها و تجمیع"),
        ("backup", "Session transfer", "انتقال نشست‌ها"),
        ("appearance", "Preferences", "تنظیمات ظاهری"),
        (
            "connect",
            "Connect configured accounts",
            "اتصال حساب‌های آماده",
        ),
        ("disconnect", "Disconnect all tunnels", "قطع همهٔ اتصال‌ها"),
        ("pool", "Start / stop local pool", "اجرای / توقف تجمیع"),
    ] {
        let item = MenuItem::with_id(id, en, true, None);
        menu.append(&item)?;
        labels.push((item, en, fa));
    }
    menu.append(&PredefinedMenuItem::separator())?;
    let close_item = CheckMenuItem::with_id(
        "closeToTray",
        "Close to tray",
        true,
        preferences.close_to_tray,
        None,
    );
    let startup_item = CheckMenuItem::with_id(
        "startMinimized",
        "Start minimized",
        true,
        preferences.start_minimized,
        None,
    );
    let top_item = CheckMenuItem::with_id(
        "alwaysOnTop",
        "Always on top",
        true,
        preferences.always_on_top,
        None,
    );
    menu.append_items(&[
        &close_item,
        &startup_item,
        &top_item,
        &PredefinedMenuItem::separator(),
    ])?;
    let quit = MenuItem::with_id("quit", "Quit and disconnect", true, None);
    menu.append(&quit)?;
    // Unique private temp directory avoids Linux appindicator icon collisions.
    let tray_dir = tempfile::Builder::new().prefix("balevpn-tray-").tempdir()?;
    let tray = TrayIconBuilder::new()
        .with_id(format!("balevpn-{}", std::process::id()))
        .with_menu(Box::new(menu))
        .with_icon(icon())
        .with_title("BaleVPN")
        .with_tooltip("BaleVPN")
        .with_temp_dir_path(tray_dir.path())
        .with_menu_on_left_click(false)
        .build()
        .map_err(|e| {
            log::warn!("Tray unavailable; window close will exit: {e}");
            e
        })
        .ok();
    let (width, height) = event_loop
        .primary_monitor()
        .map(|m| {
            let size = m.size().to_logical::<f64>(m.scale_factor());
            (
                (size.width * 0.8).clamp(760., 1320.),
                (size.height * 0.85).clamp(580., 960.),
            )
        })
        .unwrap_or((1180., 860.));
    let window = WindowBuilder::new()
        .with_title("BaleVPN")
        .with_decorations(false)
        .with_inner_size(tao::dpi::LogicalSize::new(width, height))
        .with_min_inner_size(tao::dpi::LogicalSize::new(380., 480.))
        .with_always_on_top(preferences.always_on_top)
        .with_visible(!(preferences.start_minimized && tray.is_some()))
        .build(&event_loop)?;
    let origin = format!("http://127.0.0.1:{port}");
    let navigation_origin = origin.clone();
    let ipc_proxy = proxy.clone();
    let download_origin = origin.clone();
    let completed_proxy = proxy.clone();
    let downloads = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .map(PathBuf::from)
        .map(|p| p.join("Downloads"))
        .filter(|p| p.is_dir())
        .unwrap_or_else(|| settings_path.parent().unwrap().join("exports"));
    let downloads = std::env::var_os("BALEVPN_EXPORT_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or(downloads);
    let native_downloads = downloads.clone();
    let save_proxy = event_loop.create_proxy();
    let webview = WebViewBuilder::new(&window)
        .with_url(&origin)
        .with_initialization_script("window.__BALE_DESKTOP__=true;")
        .with_navigation_handler(move |url| {
            url == navigation_origin
                || url.starts_with(&(navigation_origin.clone() + "/"))
                || url.starts_with(&("blob:".to_owned() + &navigation_origin + "/"))
                || url == "about:blank"
        })
        .with_new_window_req_handler(|_| false)
        .with_ipc_handler(move |request| {
            if request.uri().host() != Some("127.0.0.1")
                || request.uri().port_u16() != Some(port)
                || request.body().len() > 3 * 1024 * 1024
            {
                return;
            }
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(request.body()) {
                if request.body().len() > 8192 && value["cmd"] != "saveAccountArchive" {
                    return;
                }
                let _ = ipc_proxy.send_event(DesktopEvent::Command(value));
            }
        })
        .with_download_started_handler(move |url, path| {
            if !url.starts_with(&("blob:".to_string() + &download_origin + "/")) {
                return false;
            }
            if std::fs::create_dir_all(&downloads).is_err() {
                return false;
            }
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis();
            *path = downloads.join(format!("BaleVPN-accounts-{stamp}.balevault"));
            true
        })
        .with_download_completed_handler(move |_, _, success| {
            let _ = completed_proxy.send_event(DesktopEvent::Download(success));
        })
        .with_devtools(cfg!(debug_assertions))
        .build()?;
    if preferences.start_minimized && tray.is_some() {
        let _ = webview.evaluate_script("window.desktopVisibility?.(false)");
        let _ = webview.set_visible(false);
    }
    let ended_proxy = proxy.clone();
    rt.spawn(async move {
        let _ = ended_rx.await;
        let _ = ended_proxy.send_event(DesktopEvent::Quit);
    });
    rt.spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let _ = proxy.send_event(DesktopEvent::Quit);
        }
    });
    let shutdown_tx = Cell::new(Some(shutdown_tx));
    let daemon_handle = Cell::new(Some(daemon_handle));
    event_loop.run(move |event, _, flow| {
        *flow = ControlFlow::Wait;
        let mut action = String::new();
        let mut value = serde_json::Value::Null;
        match event {
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => action = "close".into(),
            Event::UserEvent(DesktopEvent::Quit) => action = "quit".into(),
            Event::UserEvent(DesktopEvent::Show) => action = "show".into(),
            Event::UserEvent(DesktopEvent::Menu(id)) => action = id,
            Event::UserEvent(DesktopEvent::Command(command)) => {
                action = command["cmd"].as_str().unwrap_or("").to_string();
                value = command;
            }
            Event::UserEvent(DesktopEvent::Download(success)) => {
                let _ = webview.evaluate_script(if success {
                    "window.desktopDownloadFinished?.(true)"
                } else {
                    "window.desktopDownloadFinished?.(false)"
                });
            }
            Event::WindowEvent {
                event: WindowEvent::Focused(true),
                ..
            } => {
                if window.is_visible() && !window.is_minimized() {
                    let _ = webview.set_visible(true);
                    let _ = webview.evaluate_script("window.desktopVisibility?.(true)");
                }
            }
            _ => {}
        }
        match action.as_str() {
            "saveAccountArchive" => {
                let bytes = crate::backup::encode_archive(value["archive"].take());
                let directory = native_downloads.clone();
                let proxy = save_proxy.clone();
                rt.spawn_blocking(move || {
                    use std::io::Write;
                    let result = (|| -> std::io::Result<()> {
                        let bytes = bytes?;
                        std::fs::create_dir_all(&directory)?;
                        let mut file = tempfile::NamedTempFile::new_in(&directory)?;
                        file.write_all(&bytes)?;
                        file.as_file().sync_all()?;
                        let stamp = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_nanos();
                        file.persist_noclobber(
                            directory.join(format!("BaleVPN-accounts-{stamp}.balevault")),
                        )
                        .map_err(|e| e.error)?;
                        Ok(())
                    })();
                    let _ = proxy.send_event(DesktopEvent::Download(result.is_ok()));
                });
            }
            "show" => {
                window.set_visible(true);
                let _ = webview.set_visible(true);
                let _ = webview.evaluate_script("window.desktopVisibility?.(true)");
                window.set_minimized(false);
                window.set_focus();
                let _ = webview.evaluate_script("window.pollState?.()");
            }
            "hide" => {
                if tray.is_some() {
                    let _ = webview.evaluate_script("window.desktopVisibility?.(false)");
                    let _ = webview.set_visible(false);
                    window.set_visible(false);
                } else {
                    window.set_minimized(true);
                }
            }
            "minimize" => {
                let _ = webview.evaluate_script("window.desktopVisibility?.(false)");
                let _ = webview.set_visible(false);
                window.set_minimized(true);
            }
            "maximize" => window.set_maximized(!window.is_maximized()),
            "drag" => {
                let _ = window.drag_window();
            }
            "resize" => {
                let d = match value["edge"].as_str() {
                    Some("n") => Some(ResizeDirection::North),
                    Some("s") => Some(ResizeDirection::South),
                    Some("e") => Some(ResizeDirection::East),
                    Some("w") => Some(ResizeDirection::West),
                    Some("ne") => Some(ResizeDirection::NorthEast),
                    Some("nw") => Some(ResizeDirection::NorthWest),
                    Some("se") => Some(ResizeDirection::SouthEast),
                    Some("sw") => Some(ResizeDirection::SouthWest),
                    _ => None,
                };
                if let Some(d) = d {
                    let _ = window.drag_resize_window(d);
                }
            }
            "appearance" | "connection" | "traffic" | "aggregate" | "backup" => {
                window.set_visible(true);
                let _ = webview.set_visible(true);
                let _ = webview.evaluate_script("window.desktopVisibility?.(true)");
                window.set_minimized(false);
                window.set_focus();
                let _ = webview.evaluate_script(&format!(
                    "window.setWorkspaceTab?.({})",
                    serde_json::to_string(&action).unwrap()
                ));
            }
            "connect" => {
                let _ = webview.evaluate_script("window.desktopConnect?.()");
            }
            "disconnect" => {
                let _ = webview.evaluate_script("window.desktopDisconnectAll?.()");
            }
            "pool" => {
                let _ = webview.evaluate_script("window.desktopTogglePool?.()");
            }
            "closeToTray" | "startMinimized" | "alwaysOnTop" | "desktopSettings" => {
                match action.as_str() {
                    "closeToTray" => preferences.close_to_tray = close_item.is_checked(),
                    "startMinimized" => preferences.start_minimized = startup_item.is_checked(),
                    "alwaysOnTop" => preferences.always_on_top = top_item.is_checked(),
                    _ => {
                        if let Some(v) = value["settings"].as_object() {
                            if let Some(v) = v.get("closeToTray").and_then(|v| v.as_bool()) {
                                preferences.close_to_tray = v;
                            }
                            if let Some(v) = v.get("startMinimized").and_then(|v| v.as_bool()) {
                                preferences.start_minimized = v;
                            }
                            if let Some(v) = v.get("alwaysOnTop").and_then(|v| v.as_bool()) {
                                preferences.always_on_top = v;
                            }
                        }
                    }
                }
                window.set_always_on_top(preferences.always_on_top);
                close_item.set_checked(preferences.close_to_tray);
                startup_item.set_checked(preferences.start_minimized);
                top_item.set_checked(preferences.always_on_top);
                if let Ok(bytes) = serde_json::to_vec(&preferences) {
                    if let Err(e) = crate::vault::private_write(&settings_path, &bytes) {
                        log::error!("Desktop preferences were not saved: {e}");
                    }
                }
                let _ = webview.evaluate_script(&format!(
                    "window.desktopSettingsReceived?.({})",
                    serde_json::to_string(&preferences).unwrap()
                ));
            }
            "desktopReady" | "theme" => {
                let fa = value["language"] == "fa";
                for (item, en, fa_text) in &labels {
                    item.set_text(if fa { fa_text } else { en });
                }
                close_item.set_text(if fa {
                    "بستن در ناحیهٔ اعلان"
                } else {
                    "Close to tray"
                });
                startup_item.set_text(if fa {
                    "شروع با پنجرهٔ پنهان"
                } else {
                    "Start minimized"
                });
                top_item.set_text(if fa {
                    "همیشه روی پنجره‌های دیگر"
                } else {
                    "Always on top"
                });
                quit.set_text(if fa {
                    "خروج و قطع اتصال‌ها"
                } else {
                    "Quit and disconnect"
                });
                let dark = value["dark"].as_bool().unwrap_or(false);
                window.set_theme(Some(if dark { Theme::Dark } else { Theme::Light }));
                let color = if dark {
                    (15, 23, 36, 255)
                } else {
                    (247, 249, 252, 255)
                };
                window.set_background_color(Some(color));
                let _ = webview.set_background_color(color);
                let _ = webview.evaluate_script(if window.is_visible() && !window.is_minimized() {
                    "window.desktopVisibility?.(true)"
                } else {
                    "window.desktopVisibility?.(false)"
                });
                let mut p = serde_json::to_value(&preferences).unwrap();
                p["trayAvailable"] = tray.is_some().into();
                let _ = webview.evaluate_script(&format!("window.desktopSettingsReceived?.({p})"));
            }
            "close" if preferences.close_to_tray && tray.is_some() => {
                let _ = webview.evaluate_script("window.desktopVisibility?.(false)");
                let _ = webview.set_visible(false);
                window.set_visible(false);
            }
            "close" | "quit" => {
                if let Some(tx) = shutdown_tx.take() {
                    let _ = tx.send(());
                    if let Some(handle) = daemon_handle.take() {
                        let _ = rt.block_on(async {
                            tokio::time::timeout(Duration::from_secs(5), handle).await
                        });
                    }
                }
                *flow = ControlFlow::Exit;
            }
            _ => {}
        }
    });
    #[allow(unreachable_code)]
    Ok(())
}

/// Install an app-level menubar with the standard Edit items.
/// macOS only for now — on Windows / Linux the per-window
/// shortcuts already work inside wry, and `init_for_hwnd` /
/// `init_for_gtk_window` would need raw window handles we
/// don't pipe in. (Trivial to add when we need it.)
fn install_app_menu() {
    #[cfg(target_os = "macos")]
    {
        use muda::{AboutMetadata, Menu, PredefinedMenuItem, Submenu};

        // About menu item dropped: muda 0.13.5's About handler
        // on macOS crashes both paths (the metadata path with
        // explicit `icon: None` hits a corrupt-Icon panic in
        // `to_png`; the no-metadata path's
        // `orderFrontStandardAboutPanel:` also crashes,
        // probably because we're an unbundled binary with no
        // Info.plist). Until muda fixes the icon path or we
        // ship as a proper `.app` bundle, omit it. The Hide /
        // Quit items still work; Cmd+C/V are wired through the
        // Edit menu below.

        let menu = Menu::new();

        // macOS "App" submenu — must be first. Hide / Quit
        // live here.
        let app_menu = Submenu::new("Bale VPN", true);
        let _ = app_menu.append_items(&[
            &PredefinedMenuItem::hide(None),
            &PredefinedMenuItem::hide_others(None),
            &PredefinedMenuItem::show_all(None),
            &PredefinedMenuItem::separator(),
            &muda::MenuItem::with_id(
                "quit",
                "Quit BaleVPN",
                true,
                Some(muda::accelerator::Accelerator::new(
                    Some(muda::accelerator::Modifiers::SUPER),
                    muda::accelerator::Code::KeyQ,
                )),
            ),
        ]);
        let _ = menu.append(&app_menu);

        let edit_menu = Submenu::new("Edit", true);
        let _ = edit_menu.append_items(&[
            &PredefinedMenuItem::undo(None),
            &PredefinedMenuItem::redo(None),
            &PredefinedMenuItem::separator(),
            &PredefinedMenuItem::cut(None),
            &PredefinedMenuItem::copy(None),
            &PredefinedMenuItem::paste(None),
            &PredefinedMenuItem::select_all(None),
        ]);
        let _ = menu.append(&edit_menu);

        menu.init_for_nsapp();
    }
}
