mod cabinet;
mod config;
mod core;
mod hwid;
mod process;
mod profile;
mod service;
mod sysproxy;

use serde_json::Value;
use std::sync::Arc;
use tauri::{Emitter, Manager};

type Eng<'a> = tauri::State<'a, Arc<core::Engine>>;
type Cab<'a> = tauri::State<'a, cabinet::Cabinet>;
struct AccountGate(std::sync::Mutex<()>);
type Gate<'a> = tauri::State<'a, AccountGate>;

#[tauri::command(async)]
fn cabinet_boot(c: Cab, e: Eng) -> Result<Value, String> {
    c.set_proxy(e.proxy_port());
    c.boot()
}

/// Opens the provider in the system browser and returns the code to type on the callback page.
#[tauri::command(async)]
fn cabinet_oauth_start(c: Cab, e: Eng, provider: String) -> Result<Value, String> {
    c.set_proxy(e.proxy_port());
    let (url, answer) = c.oauth_start(&provider)?;
    if let Err(error) = open_https(&url) {
        c.oauth_cancel();
        return Err(error);
    }
    Ok(answer)
}
/// One look at the browser sign-in; a session it brings replaces the previous account's subscription.
#[tauri::command(async)]
fn cabinet_oauth_poll(c: Cab, e: Eng, gate: Gate) -> Result<Value, String> {
    let _guard = gate.0.lock().map_err(|_| "Account operation failed.")?;
    c.set_proxy(e.proxy_port());
    let result = c.oauth_poll()?;
    if result["status"] == "signed_in" {
        let stopped = e.disconnect();
        let forgotten = e.forget_subscription();
        stopped?;
        forgotten?;
    }
    Ok(result)
}
#[tauri::command(async)]
fn cabinet_oauth_cancel(c: Cab) {
    c.oauth_cancel();
}
#[tauri::command(async)]
fn cabinet_request(
    c: Cab,
    e: Eng,
    method: String,
    path: String,
    body: Option<Value>,
) -> Result<Value, String> {
    c.set_proxy(e.proxy_port());
    c.request(&method, &path, body)
}
#[tauri::command(async)]
fn cabinet_auth(c: Cab, e: Eng, gate: Gate, action: String, body: Value) -> Result<Value, String> {
    let _guard = gate
        .0
        .lock()
        .map_err(|_| "Something went wrong. Try again later.")?;
    let result = c.auth(&action, body)?;
    if result.get("me").is_some() {
        let stopped = e.disconnect();
        let forgotten = e.forget_subscription();
        stopped?;
        forgotten?;
    }
    Ok(result)
}
#[tauri::command(async)]
fn cabinet_logout(c: Cab, e: Eng, gate: Gate) -> Result<Value, String> {
    let _guard = gate.0.lock().map_err(|_| "Account operation failed.")?;
    let stopped = e.disconnect();
    let result = c.logout();
    let forgotten = e.forget_subscription();
    stopped?;
    forgotten?;
    result
}
#[tauri::command(async)]
fn cabinet_use_subscription(c: Cab, e: Eng, gate: Gate, sub_id: u64) -> Result<Value, String> {
    let _guard = gate.0.lock().map_err(|_| "Account operation failed.")?;
    let result = c.request("GET", &format!("/subscription/link?sub_id={sub_id}"), None)?;
    let url = result["link"]
        .as_str()
        .ok_or("The subscription link is missing.")?;
    e.set_subscription(url)?;
    e.set_subscription_id(sub_id)
}
#[tauri::command(async)]
fn clear_subscription(e: Eng, gate: Gate, expected_sub_id: Option<u64>) -> Result<(), String> {
    let _guard = gate.0.lock().map_err(|_| "Account operation failed.")?;
    if let Some(id) = expected_sub_id {
        if e.boot()?["sub_id"].as_u64() != Some(id) {
            return Ok(());
        }
    }
    let stopped = e.disconnect();
    let forgotten = e.forget_subscription();
    stopped?;
    forgotten
}
#[tauri::command(async)]
fn open_external(url: String) -> Result<(), String> {
    open_https(&url::Url::parse(&url).map_err(|_| "Invalid link.")?)
}
fn open_https(parsed: &url::Url) -> Result<(), String> {
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err("Only HTTPS links can be opened.".into());
    }
    let status = std::process::Command::new("/usr/bin/open")
        .arg(parsed.as_str())
        .status()
        .map_err(|_| "Could not open the browser.")?;
    if !status.success() {
        return Err("Could not open the browser.".into());
    }
    Ok(())
}

// Every command runs off the UI thread: the window never freezes while the core starts or a server is slow.
#[tauri::command(async)]
fn boot(e: Eng) -> Result<Value, String> {
    e.boot()
}
#[tauri::command(async)]
fn set_subscription(e: Eng, gate: Gate, url: String) -> Result<Value, String> {
    let _guard = gate.0.lock().map_err(|_| "Account operation failed.")?;
    e.set_subscription(&url)
}
#[tauri::command(async)]
fn refresh_subscription(e: Eng, gate: Gate) -> Result<Value, String> {
    let _guard = gate
        .0
        .lock()
        .map_err(|_| "Something went wrong. Try again later.")?;
    e.refresh_subscription()
}
#[tauri::command(async)]
fn connect(e: Eng, c: Cab, gate: Gate, app: tauri::AppHandle) -> Result<Value, String> {
    let _guard = gate.0.lock().map_err(|_| "Account operation failed.")?;
    c.require_session()?;
    let result = e.inner().connect(app.clone());
    tray_sync(&app);
    result
}
#[tauri::command(async)]
fn disconnect(e: Eng, app: tauri::AppHandle) -> Result<Value, String> {
    let result = e.disconnect();
    tray_sync(&app);
    result
}

struct TrayToggle(tauri::menu::MenuItem<tauri::Wry>);

/// The tray reads the engine's real state, so its label cannot drift from what the core is doing.
fn tray_sync(app: &tauri::AppHandle) {
    let app = app.clone();
    std::thread::spawn(move || {
        let connected = app
            .state::<Arc<core::Engine>>()
            .boot()
            .map(|v| v["connected"] == true)
            .unwrap_or(false);
        if let Some(item) = app.try_state::<TrayToggle>() {
            let _ = item
                .0
                .set_text(if connected { "Disconnect" } else { "Connect" });
        }
        if let Some(tray) = app.tray_by_id("main") {
            let _ = tray.set_tooltip(Some(if connected {
                "akimov vpn · connected"
            } else {
                "akimov vpn · not connected"
            }));
        }
    });
}

fn show_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn build_tray(app: &tauri::App) -> tauri::Result<()> {
    use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
    use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
    let open = MenuItem::with_id(app, "open", "Open akimov vpn", true, None::<&str>)?;
    let toggle = MenuItem::with_id(app, "toggle", "Connect", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(
        app,
        &[&open, &toggle, &PredefinedMenuItem::separator(app)?, &quit],
    )?;
    app.manage(TrayToggle(toggle));
    let mut tray = TrayIconBuilder::with_id("main")
        .tooltip("akimov vpn · not connected")
        .menu(&menu)
        .show_menu_on_left_click(true)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => show_window(app),
            // the window owns the connect flow (consent, errors, animation); the tray only asks it to run
            "toggle" => {
                let _ = app.emit("tray-toggle", ());
            }
            "quit" => {
                let app = app.clone();
                std::thread::spawn(move || {
                    app.state::<Arc<core::Engine>>().shutdown();
                    app.exit(0);
                });
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            // Refresh without waiting on an in-progress connection; a left click also shows the window.
            if matches!(
                event,
                TrayIconEvent::Click { .. } | TrayIconEvent::DoubleClick { .. }
            ) {
                tray_sync(tray.app_handle());
            }
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_window(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        tray = tray.icon(icon.clone());
    }
    tray.build(app)?;
    Ok(())
}
#[tauri::command(async)]
fn proxies(e: Eng) -> Result<Value, String> {
    e.proxies()
}
#[tauri::command(async)]
fn select_node(e: Eng, name: String) -> Result<Value, String> {
    e.select_node(name)
}
#[tauri::command(async)]
fn test_latency(
    e: Eng,
    gate: Gate,
    on_result: tauri::ipc::Channel<Value>,
) -> Result<Value, String> {
    let _guard = gate.0.lock().map_err(|_| "Account operation failed.")?;
    e.test_latency(|value| {
        let _ = on_result.send(value);
    })
}
#[tauri::command(async)]
fn set_rules(e: Eng, rules: Vec<config::Rule>) -> Result<Value, String> {
    e.set_rules(rules)
}
#[tauri::command(async)]
fn set_mode(e: Eng, mode: String) -> Result<Value, String> {
    e.set_mode(mode)
}

#[tauri::command(async)]
fn set_close_to_tray(e: Eng, on: bool) -> Result<Value, String> {
    e.set_close_to_tray(on)
}

#[tauri::command(async)]
fn close_connections(e: Eng, id: Option<String>, process: Option<String>) -> Result<Value, String> {
    e.close_connections(id, process)
}
#[tauri::command(async)]
fn watch(e: Eng, on: bool) -> Result<(), String> {
    e.watch(on);
    Ok(())
}

/// WebKit keeps page rendering near 60 fps by default; ProMotion displays can refresh at 120 Hz.
/// The flag is WebKit's own feature switch (the one Safari exposes); older WebKit without it is left as is.
unsafe fn full_frame_rate(webview: *mut std::ffi::c_void) {
    use objc2::runtime::{AnyClass, AnyObject, Bool};
    use objc2::{msg_send, sel};
    let Some(class) = AnyClass::get(c"WKPreferences") else {
        return;
    };
    let webview = webview.cast::<AnyObject>();
    // `_features` is a class method, so ask the class object itself.
    let listed: Bool = msg_send![class, respondsToSelector: sel!(_features)];
    if webview.is_null() || !listed.as_bool() {
        return;
    }
    let config: *mut AnyObject = msg_send![webview, configuration];
    let prefs: *mut AnyObject = msg_send![config, preferences];
    let features: *mut AnyObject = msg_send![class, _features];
    let settable: Bool = msg_send![prefs, respondsToSelector: sel!(_setEnabled:forFeature:)];
    if prefs.is_null() || features.is_null() || !settable.as_bool() {
        return;
    }
    let count: usize = msg_send![features, count];
    for i in 0..count {
        let feature: *mut AnyObject = msg_send![features, objectAtIndex: i];
        let key: *mut AnyObject = msg_send![feature, key];
        let name: *const std::ffi::c_char = msg_send![key, UTF8String];
        if !name.is_null()
            && std::ffi::CStr::from_ptr(name).to_bytes()
                == b"PreferPageRenderingUpdatesNear60FPSEnabled"
        {
            let _: () = msg_send![prefs, _setEnabled: Bool::NO, forFeature: feature];
        }
    }
}

fn main() {
    if let Some(result) = service::early_main() {
        if let Err(error) = result {
            eprintln!("{error}");
            std::process::exit(1);
        }
        return;
    }
    // Profiles and temporary credentials are private to this macOS user.
    unsafe {
        libc::umask(0o077);
    }
    let engine = Arc::new(core::Engine::new());
    let on_close = engine.clone();
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _, _| {
            show_window(app)
        }))
        .manage(engine)
        .manage(cabinet::Cabinet::new(core::data_dir()))
        .manage(AccountGate(std::sync::Mutex::new(())))
        .invoke_handler(tauri::generate_handler![
            boot,
            cabinet_boot,
            cabinet_oauth_start,
            cabinet_oauth_poll,
            cabinet_oauth_cancel,
            cabinet_auth,
            cabinet_request,
            cabinet_logout,
            cabinet_use_subscription,
            clear_subscription,
            open_external,
            set_subscription,
            refresh_subscription,
            connect,
            disconnect,
            close_connections,
            proxies,
            select_node,
            test_latency,
            set_rules,
            set_mode,
            set_close_to_tray,
            watch
        ])
        .setup(|app| {
            build_tray(app)?;
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.with_webview(|webview| unsafe { full_frame_rate(webview.inner()) });
            }
            Ok(())
        })
        // closing the window hides it to the tray by default; with that setting off it quits:
        // restore the system proxy, close every connection, stop the core
        .on_window_event(move |window, event| {
            if window.label() != "main" {
                return;
            }
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                if on_close.close_to_tray() {
                    let _ = window.hide();
                    return;
                }
                let engine = on_close.clone();
                let app = window.app_handle().clone();
                std::thread::spawn(move || {
                    engine.shutdown();
                    app.exit(0);
                });
            }
        })
        .build(tauri::generate_context!())
        .expect("failed to start akimov vpn")
        .run(|app, event| {
            if let tauri::RunEvent::Reopen { .. } = event {
                show_window(app);
            }
            if let tauri::RunEvent::Exit = event {
                app.state::<Arc<core::Engine>>().shutdown();
            }
        });
}
