use super::{allowed_api, mixed_port, MAX_MESSAGE, PROTOCOL};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Read, Write},
    net::Shutdown,
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        io::AsRawFd,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex, OnceLock, Weak},
    time::{Duration, Instant},
};

// shortcut: one macOS user owns this helper; namespace services if multi-user installs are needed.
const ROOT: &str = "/Library/Application Support/vpn.akimov.macos";
const PLIST: &str = "/Library/LaunchDaemons/vpn.akimov.helper.plist";
const LABEL: &str = "vpn.akimov.helper";
type Connection = Mutex<BufReader<UnixStream>>;
type Routes = HashMap<u16, (String, Weak<Connection>, String)>;
static ROUTES: OnceLock<Mutex<Routes>> = OnceLock::new();

pub struct Session(Arc<Connection>);
impl Session {
    fn request(&self, value: &Value) -> Result<Value, String> {
        exchange(
            &mut *self.0.lock().map_err(|_| "Helper connection failed.")?,
            value,
        )
    }
    pub fn stop(&self) -> Result<(), String> {
        let result = self.request(&json!({"op":"stop"})).map(|_| ());
        if let Ok(connection) = self.0.lock() {
            let _ = connection.get_ref().shutdown(Shutdown::Both);
        }
        result
    }
    pub fn alive(&self) -> Result<bool, String> {
        self.request(&json!({"op":"alive"})).map(|v| v == true)
    }
}

fn send(stream: &mut UnixStream, value: &Value) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_MESSAGE {
        return Err("Helper message is too large.".into());
    }
    stream
        .write_all(&bytes)
        .and_then(|_| stream.write_all(b"\n"))
        .map_err(|e| e.to_string())
}
fn receive(reader: &mut BufReader<UnixStream>) -> Result<Value, String> {
    let mut line = Vec::new();
    reader
        .take(MAX_MESSAGE as u64 + 1)
        .read_until(b'\n', &mut line)
        .map_err(|e| e.to_string())?;
    if line.len() > MAX_MESSAGE || line.last() != Some(&b'\n') {
        return Err("Invalid helper message.".into());
    }
    serde_json::from_slice(&line).map_err(|_| "Invalid helper message.".into())
}
fn exchange(reader: &mut BufReader<UnixStream>, request: &Value) -> Result<Value, String> {
    send(reader.get_mut(), request)?;
    let response = receive(reader)?;
    if let Some(error) = response["error"].as_str() {
        return Err(error.to_string());
    }
    response
        .get("value")
        .cloned()
        .ok_or_else(|| "Invalid helper response.".into())
}
fn peer(stream: &UnixStream) -> Result<u32, String> {
    let (mut uid, mut gid) = (0, 0);
    if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
        return Err("Cannot authenticate the helper connection.".into());
    }
    Ok(uid)
}
fn connect() -> Result<Session, String> {
    let stream =
        UnixStream::connect(Path::new(ROOT).join("control.sock")).map_err(|e| e.to_string())?;
    if peer(&stream)? != 0 {
        return Err("The VPN helper is not owned by root.".into());
    }
    stream
        .set_read_timeout(Some(Duration::from_secs(45)))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    Ok(Session(Arc::new(Mutex::new(BufReader::new(stream)))))
}
fn digest(path: &Path) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    let mut file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let n = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}
fn ensure() -> Result<Session, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let hash = digest(&exe)?;
    if let Ok(session) = connect() {
        if session
            .request(&json!({"op":"hello"}))
            .is_ok_and(|v| v["protocol"] == PROTOCOL && v["binary"] == hash)
        {
            return Ok(session);
        }
    }
    install(&exe)?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(session) = connect() {
            if session
                .request(&json!({"op":"hello"}))
                .is_ok_and(|v| v["protocol"] == PROTOCOL && v["binary"] == hash)
            {
                return Ok(session);
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err("The VPN helper did not start. Reinstall the app and try again.".into())
}
fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
fn install(exe: &Path) -> Result<(), String> {
    let uid = unsafe { libc::getuid() };
    if uid == 0 {
        return Err("Open the app as your regular macOS user.".into());
    }
    let core = crate::core::core_exe()?;
    let files = [
        (exe.to_path_buf(), "helper"),
        (core.clone(), "mihomo"),
        (core.with_file_name("geoip.metadb"), "geoip.metadb"),
        (core.with_file_name("GeoSite.dat"), "GeoSite.dat"),
    ];
    for (source, _) in &files {
        if !source.is_file() {
            return Err("The VPN install is incomplete.".into());
        }
    }
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>Label</key><string>{LABEL}</string><key>ProgramArguments</key><array><string>{ROOT}/helper</string><string>--vpn-helper</string><string>{uid}</string></array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>Umask</key><integer>63</integer><key>ThrottleInterval</key><integer>5</integer></dict></plist>"#
    );
    let mut script = String::from("set -eu\numask 077\nstage=$(/usr/bin/mktemp -d '/Library/Application Support/.akimov-install.XXXXXX')\ntrap '/bin/rm -rf \"$stage\"' EXIT\n");
    for (source, name) in files {
        script.push_str(&format!(
            "/bin/cp {} \"$stage/{name}\"\n",
            quote(source.to_str().ok_or("Invalid app path.")?)
        ));
    }
    script.push_str(&format!("/bin/chmod 755 \"$stage/helper\" \"$stage/mihomo\"\n/bin/chmod 644 \"$stage/geoip.metadb\" \"$stage/GeoSite.dat\"\n/bin/chmod 755 \"$stage\"\n/usr/sbin/chown -R root:wheel \"$stage\"\n/usr/bin/printf %s {} > \"$stage/daemon.plist\"\n/bin/launchctl bootout system/{} >/dev/null 2>&1 || true\n", quote(&plist), LABEL));
    script.push_str(&format!("if [ -e {root} ]; then [ -d {root} ] && [ ! -L {root} ]; fi\n/bin/mkdir -p {root}\n/usr/sbin/chown root:wheel {root}\n/bin/chmod 755 {root}\nfor file in helper mihomo geoip.metadb GeoSite.dat; do /bin/mv -f \"$stage/$file\" {root}/; done\n/usr/bin/install -o root -g wheel -m 644 \"$stage/daemon.plist\" {plist}\n/bin/launchctl bootstrap system {plist}\n",root=quote(ROOT),plist=quote(PLIST)));
    let apple = format!("do shell script {} with administrator privileges with prompt \"akimov vpn needs permission to install its protected network helper.\"", serde_json::to_string(&script).map_err(|e| e.to_string())?);
    let output = Command::new("/usr/bin/osascript")
        .args(["-e", &apple])
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        if String::from_utf8_lossy(&output.stderr).contains("-128") {
            return Err("elevation_cancelled".into());
        }
        return Err(
            "macOS could not install the VPN helper. Try again from an administrator account."
                .into(),
        );
    }
    Ok(())
}

pub fn start(yaml: &str) -> Result<Session, String> {
    let parsed: serde_yaml::Value =
        serde_yaml::from_str(yaml).map_err(|_| "Invalid core configuration.")?;
    let ctl = parsed["external-controller"]
        .as_str()
        .and_then(|s| s.strip_prefix("127.0.0.1:"))
        .and_then(|s| s.parse::<u16>().ok())
        .filter(|p| *p > 0)
        .ok_or("Invalid controller.")?;
    let token = parsed["secret"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or("Missing controller secret.")?
        .to_string();
    let session = ensure()?;
    let started = session.request(&json!({"op":"start","yaml":yaml}))?;
    let capability = started["session"]
        .as_str()
        .ok_or("Invalid helper session.")?
        .to_string();
    let mut routes = ROUTES
        .get_or_init(Default::default)
        .lock()
        .map_err(|_| "Helper routing failed.")?;
    routes.retain(|_, (_, connection, _)| connection.strong_count() > 0);
    routes.insert(ctl, (token, Arc::downgrade(&session.0), capability));
    Ok(session)
}
pub fn proxy(port: u16) -> Result<Session, String> {
    let session = ensure()?;
    session.request(&json!({"op":"proxy","port":port}))?;
    Ok(session)
}
pub fn api(
    ctl: u16,
    secret: &str,
    method: &str,
    path: &str,
    body: Option<&Value>,
    wait: u64,
) -> Option<Result<Value, String>> {
    let routes = ROUTES.get_or_init(Default::default).lock().ok()?;
    let (token, connection, capability) = routes.get(&ctl)?;
    let _owner = connection.upgrade()?;
    if token != secret {
        return Some(Err("Invalid controller authentication.".into()));
    }
    let capability = capability.clone();
    drop(routes);
    // The owner socket is only a lifetime lease; slow probes must not queue UI, traffic or stop.
    Some(connect().and_then(|session| session.request(&json!({"op":"api","session":capability,"method":method,"path":path,"body":body,"wait":wait}))))
}

pub fn clear_cache() -> Result<(), String> {
    if !Path::new(ROOT).join("control.sock").exists() {
        return Ok(());
    }
    let session = connect()?;
    if session.request(&json!({"op":"hello"}))?["protocol"]
        .as_u64()
        .unwrap_or(0)
        < 2
    {
        return Ok(());
    }
    session.request(&json!({"op":"forget"})).map(|_| ())
}

pub fn early_main() -> Option<Result<(), String>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    match args.first().and_then(|s| s.to_str()) {
        Some("--core-supervisor") => Some(crate::process::supervise(&args[1..])),
        Some("--remove-helper") => Some(uninstall()),
        Some("--vpn-helper") => Some((|| {
            let uid = args
                .get(1)
                .and_then(|s| s.to_str())
                .and_then(|s| s.parse::<u32>().ok())
                .filter(|uid| *uid > 0)
                .ok_or("Invalid helper owner.")?;
            if unsafe { libc::geteuid() } != 0 {
                return Err("The helper must run as root.".into());
            }
            serve(uid)
        })()),
        _ => None,
    }
}

fn uninstall() -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("Run uninstall-helper.sh with administrator permission.".into());
    }
    protected(Path::new(ROOT))?;
    // Keep the idle lease until launchd stops the helper, so a connection cannot race removal.
    let session = connect()?;
    session.request(&json!({"op":"maintenance"}))?;
    let status = Command::new("/bin/launchctl")
        .args(["bootout", &format!("system/{LABEL}")])
        .status()
        .map_err(|e| e.to_string())?;
    if !status.success() {
        return Err("Could not unload the VPN helper.".into());
    }
    std::fs::remove_file(PLIST).map_err(|e| e.to_string())?;
    std::fs::remove_dir_all(ROOT).map_err(|e| e.to_string())?;
    println!("Removed the akimov vpn network helper.");
    Ok(())
}

fn protected(path: &Path) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if metadata.file_type().is_symlink() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err("The helper installation is not protected.".into());
    }
    Ok(())
}
fn serve(uid: u32) -> Result<(), String> {
    unsafe {
        libc::umask(0o077);
    }
    let root = Path::new(ROOT);
    for path in [
        root.to_path_buf(),
        root.join("helper"),
        root.join("mihomo"),
        root.join("geoip.metadb"),
        root.join("GeoSite.dat"),
    ] {
        protected(&path)?;
    }
    let binary = digest(&root.join("helper"))?;
    crate::sysproxy::recover_root(&root.join("network-recovery.json"))?;
    let runtime = root.join("runtime");
    if runtime.exists() {
        protected(&runtime)?;
        std::fs::remove_dir_all(&runtime).map_err(|e| e.to_string())?;
    }
    std::fs::create_dir(&runtime).map_err(|e| e.to_string())?;
    let socket = root.join("control.sock");
    if socket.exists() {
        std::fs::remove_file(&socket).map_err(|e| e.to_string())?;
    }
    let listener = UnixListener::bind(&socket).map_err(|e| e.to_string())?;
    let path =
        std::ffi::CString::new(socket.as_os_str().as_encoded_bytes()).map_err(|e| e.to_string())?;
    if unsafe { libc::chown(path.as_ptr(), uid, u32::MAX) } != 0 {
        return Err("Cannot secure the helper socket.".into());
    }
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| e.to_string())?;
    let active = Arc::new(Mutex::new(()));
    for stream in listener.incoming() {
        let Ok(stream) = stream else {
            continue;
        };
        if !peer(&stream).is_ok_and(|peer| peer == uid || peer == 0) {
            continue;
        }
        let (active, binary) = (active.clone(), binary.clone());
        std::thread::spawn(move || {
            let _ = handle(stream, active, &binary);
        });
    }
    Ok(())
}

struct Controller {
    log: PathBuf,
    ctl: u16,
    token: String,
    mixed: u16,
    agent: ureq::Agent,
}
static CONTROLLERS: OnceLock<Mutex<HashMap<String, Weak<Controller>>>> = OnceLock::new();
fn controller(capability: &str) -> Result<Arc<Controller>, String> {
    CONTROLLERS
        .get_or_init(Default::default)
        .lock()
        .map_err(|_| "Helper routing failed.")?
        .get(capability)
        .and_then(Weak::upgrade)
        .ok_or_else(|| "The core is not running.".into())
}
struct Runtime {
    process: crate::process::Process,
    dir: PathBuf,
    control: Arc<Controller>,
    capability: String,
}
impl Drop for Runtime {
    fn drop(&mut self) {
        if let Ok(mut routes) = CONTROLLERS.get_or_init(Default::default).lock() {
            routes.remove(&self.capability);
        }
        let _ = self.process.kill();
        let _ = self.process.wait();
        let _ = copy_cache(
            &self.dir.join("providers"),
            &Path::new(ROOT).join("provider-cache"),
        );
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
fn copy_cache(source: &Path, target: &Path) -> Result<(), String> {
    let entries = match std::fs::read_dir(source) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.to_string()),
    };
    std::fs::create_dir_all(target).map_err(|e| e.to_string())?;
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        if !entry.file_type().map_err(|e| e.to_string())?.is_file()
            || entry.path().extension().is_none_or(|e| e != "yaml")
        {
            continue;
        }
        let temporary = target.join(format!("{}.tmp", crate::core::random_hex()));
        let modified = entry
            .metadata()
            .and_then(|m| m.modified())
            .map_err(|e| e.to_string())?;
        std::fs::copy(entry.path(), &temporary)
            .and_then(|_| {
                std::fs::File::open(&temporary)?
                    .set_times(std::fs::FileTimes::new().set_modified(modified))
            })
            .and_then(|_| std::fs::rename(&temporary, target.join(entry.file_name())))
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn free_port() -> Result<u16, String> {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .map_err(|e| e.to_string())
}
fn run_core(yaml: &str) -> Result<Runtime, String> {
    let mixed = mixed_port(yaml)?;
    let mut ctl = free_port()?;
    while ctl == mixed {
        ctl = free_port()?;
    }
    let token = crate::core::random_hex();
    let yaml = crate::config::privileged_config(yaml, ctl, &token)?;
    let dir = Path::new(ROOT)
        .join("runtime")
        .join(crate::core::random_hex());
    std::fs::create_dir(&dir).map_err(|e| e.to_string())?;
    let result = (|| {
        for name in ["geoip.metadb", "GeoSite.dat"] {
            std::fs::copy(Path::new(ROOT).join(name), dir.join(name)).map_err(|e| e.to_string())?;
        }
        copy_cache(
            &Path::new(ROOT).join("provider-cache"),
            &dir.join("providers"),
        )?;
        std::fs::write(dir.join("config.yaml"), yaml).map_err(|e| e.to_string())?;
        let process = crate::process::Process::spawn(
            &Path::new(ROOT).join("mihomo"),
            &dir,
            &dir.join("config.yaml"),
            &dir.join("core.log"),
            false,
        )?;
        let control = Arc::new(Controller {
            log: dir.join("core.log"),
            ctl,
            token,
            mixed,
            agent: ureq::AgentBuilder::new().try_proxy_from_env(false).build(),
        });
        let capability = crate::core::random_hex();
        CONTROLLERS
            .get_or_init(Default::default)
            .lock()
            .map_err(|_| "Helper routing failed.")?
            .insert(capability.clone(), Arc::downgrade(&control));
        Ok(Runtime {
            process,
            dir: dir.clone(),
            control,
            capability,
        })
    })();
    if result.is_err() {
        let _ = std::fs::remove_dir_all(dir);
    }
    result
}
fn core_api(run: &Controller, request: &Value) -> Result<Value, String> {
    let method = request["method"].as_str().unwrap_or("");
    let path = request["path"].as_str().unwrap_or("");
    let mut body = request.get("body").filter(|v| !v.is_null()).cloned();
    if !allowed_api(method, path, &body) {
        return Err("This helper operation is not allowed.".into());
    }
    if method == "PUT" && path == "/configs?force=false" {
        let yaml = body
            .as_ref()
            .and_then(|v| v["payload"].as_str())
            .ok_or("Invalid reload.")?;
        if mixed_port(yaml)? != run.mixed {
            return Err("The proxy port cannot change during reload.".into());
        }
        body =
            Some(json!({"payload":crate::config::privileged_config(yaml, run.ctl, &run.token)?}));
    }
    let req = run
        .agent
        .request(method, &format!("http://127.0.0.1:{}{}", run.ctl, path))
        .set("Authorization", &format!("Bearer {}", run.token))
        .timeout(Duration::from_secs(
            request["wait"].as_u64().unwrap_or(4).clamp(1, 30),
        ));
    let response = match body {
        Some(value) => req.send_json(value),
        None => req.call(),
    }
    .map_err(|e| e.to_string())?;
    if response.status() == 204 {
        return Ok(Value::Null);
    }
    if path == "/traffic" {
        let mut line = String::new();
        BufReader::new(response.into_reader())
            .take(MAX_MESSAGE as u64)
            .read_line(&mut line)
            .map_err(|e| e.to_string())?;
        return serde_json::from_str(&line).map_err(|e| e.to_string());
    }
    let mut value: Value = serde_json::from_reader(response.into_reader().take(MAX_MESSAGE as u64))
        .map_err(|e| e.to_string())?;
    if path == "/version" {
        if let Ok(file) = std::fs::File::open(&run.log) {
            if let Some(line) = BufReader::new(file)
                .lines()
                .take(100)
                .filter_map(Result::ok)
                .find(|line| line.contains("Start TUN listening error:"))
            {
                value["tun_error"] = line.chars().take(1024).collect::<String>().into();
            }
        }
    }
    Ok(value)
}
fn handle(stream: UnixStream, active: Arc<Mutex<()>>, binary: &str) -> Result<(), String> {
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(stream);
    let mut run = None;
    let mut network = None;
    let mut lease = None;
    while let Ok(request) = receive(&mut reader) {
        let op = request["op"].as_str().unwrap_or("");
        let result = (|| -> Result<Value, String> {
            match op {
                "hello" => Ok(json!({"protocol":PROTOCOL,"binary":binary})),
                "maintenance" if lease.is_none() => {
                    lease = Some(active.try_lock().map_err(|_| {
                        "Disconnect and quit akimov vpn before removing its helper."
                    })?);
                    crate::sysproxy::recover_root(&Path::new(ROOT).join("network-recovery.json"))?;
                    Ok(Value::Null)
                }
                "forget" if lease.is_none() => {
                    let _idle = active
                        .try_lock()
                        .map_err(|_| "Disconnect before clearing the provider cache.")?;
                    let cache = Path::new(ROOT).join("provider-cache");
                    if cache.exists() {
                        protected(&cache)?;
                        std::fs::remove_dir_all(cache).map_err(|e| e.to_string())?;
                    }
                    Ok(Value::Null)
                }
                "start" | "proxy" if lease.is_none() => {
                    lease = Some(
                        active
                            .try_lock()
                            .map_err(|_| "Another VPN session is already using the helper.")?,
                    );
                    crate::sysproxy::recover_root(&Path::new(ROOT).join("network-recovery.json"))?;
                    if op == "start" {
                        run = Some(run_core(
                            request["yaml"].as_str().ok_or("Missing configuration.")?,
                        )?);
                        network = Some(crate::sysproxy::apply_root(
                            None,
                            &Path::new(ROOT).join("network-recovery.json"),
                        )?);
                    } else {
                        let port = request["port"]
                            .as_u64()
                            .and_then(|p| u16::try_from(p).ok())
                            .filter(|p| *p > 0)
                            .ok_or("Invalid proxy port.")?;
                        network = Some(crate::sysproxy::apply_root(
                            Some(port),
                            &Path::new(ROOT).join("network-recovery.json"),
                        )?);
                    }
                    Ok(run
                        .as_ref()
                        .map(|run| json!({"session":run.capability}))
                        .unwrap_or(Value::Null))
                }
                "api" => {
                    let control = if let Some(run) = &run {
                        run.control.clone()
                    } else {
                        controller(request["session"].as_str().unwrap_or(""))?
                    };
                    core_api(&control, &request)
                }
                "alive" => Ok(json!(run.as_mut().is_some_and(|r| r
                    .process
                    .try_wait()
                    .ok()
                    == Some(None)))),
                "stop" => {
                    // DNS is restored after the TUN core has removed its routes.
                    run.take();
                    if let Some(backup) = &network {
                        crate::sysproxy::restore_root(
                            backup,
                            &Path::new(ROOT).join("network-recovery.json"),
                        )?;
                    }
                    network.take();
                    lease.take();
                    Ok(Value::Null)
                }
                _ => Err("Unknown helper operation.".into()),
            }
        })();
        let failed_start = result.is_err() && ["start", "proxy"].contains(&op);
        let reply = match result {
            Ok(value) => json!({"value":value}),
            Err(error) => json!({"error":error}),
        };
        if send(reader.get_mut(), &reply).is_err() || op == "stop" || failed_start {
            break;
        }
    }
    run.take();
    if let Some(backup) = network {
        // Keep ownership until restoration succeeds, including after the app has quit.
        while crate::sysproxy::restore_root(&backup, &Path::new(ROOT).join("network-recovery.json"))
            .is_err()
        {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    drop(lease);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn framing_rejects_truncation_and_shell_arguments_are_quoted() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        sender.write_all(b"{\"op\":\"hello\"}").unwrap();
        sender.shutdown(Shutdown::Write).unwrap();
        assert!(receive(&mut BufReader::new(receiver)).is_err());
        assert_eq!(quote("a'b;$(x)"), "'a'\\''b;$(x)'");
    }
    #[test]
    fn idle_protocol_rejects_mutation_and_concurrent_sessions() {
        let (client, server) = UnixStream::pair().unwrap();
        let active = Arc::new(Mutex::new(()));
        let held = active.lock().unwrap();
        let server_active = active.clone();
        let worker = std::thread::spawn(move || handle(server, server_active, "fixture-only"));
        let mut reader = BufReader::new(client);
        let hello = exchange(&mut reader, &json!({"op":"hello"})).unwrap();
        assert_eq!(hello["protocol"], PROTOCOL);
        assert!(exchange(
            &mut reader,
            &json!({"op":"api","method":"POST","path":"/upgrade"})
        )
        .is_err());
        assert!(
            exchange(&mut reader, &json!({"op":"start","yaml":"untrusted"}))
                .unwrap_err()
                .contains("Another VPN session")
        );
        drop(held);
        assert!(worker.join().unwrap().is_ok());
        assert!(active.try_lock().is_ok());
    }
    #[test]
    fn provider_cache_copies_regular_files_without_following_symlinks() {
        let dir = std::env::temp_dir().join(format!("akimov-cache-{}", crate::core::random_hex()));
        let source = dir.join("source");
        let target = dir.join("target");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::create_dir_all(&target).unwrap();
        let outside = dir.join("outside");
        std::fs::write(&outside, "keep").unwrap();
        std::fs::write(source.join("rules.yaml"), "payload: []").unwrap();
        let old = std::time::UNIX_EPOCH + Duration::from_secs(12345);
        std::fs::File::open(source.join("rules.yaml"))
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(old))
            .unwrap();
        std::os::unix::fs::symlink(&outside, source.join("symlink.yaml")).unwrap();
        std::os::unix::fs::symlink(&outside, target.join("rules.yaml")).unwrap();
        copy_cache(&source, &target).unwrap();
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "keep");
        assert_eq!(
            std::fs::read_to_string(target.join("rules.yaml")).unwrap(),
            "payload: []"
        );
        assert!(!target.join("symlink.yaml").exists());
        assert_eq!(
            std::fs::metadata(target.join("rules.yaml"))
                .unwrap()
                .modified()
                .unwrap(),
            old
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn a_slow_probe_does_not_hold_the_control_channel_or_keep_a_dead_session_alive() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (started, start) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let released = Arc::new(Mutex::new(released));
        let http = std::thread::spawn(move || {
            let mut workers = Vec::new();
            for stream in listener.incoming().take(2) {
                let mut stream = stream.unwrap();
                let started = started.clone();
                let released = released.clone();
                workers.push(std::thread::spawn(move || {
                    let mut line = String::new(); let mut reader = BufReader::new(stream.try_clone().unwrap());
                    reader.read_line(&mut line).unwrap();
                    if line.contains("/delay?") { started.send(()).unwrap(); released.lock().unwrap().recv().unwrap(); }
                    let body = r#"{"ready":true,"delay":1}"#;
                    write!(stream, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", body.len(), body).unwrap();
                }));
            }
            for worker in workers {
                worker.join().unwrap();
            }
        });
        let control = Arc::new(Controller {
            log: PathBuf::new(),
            ctl: port,
            token: "fixture".into(),
            mixed: port,
            agent: ureq::AgentBuilder::new().try_proxy_from_env(false).build(),
        });
        let capability = crate::core::random_hex();
        CONTROLLERS
            .get_or_init(Default::default)
            .lock()
            .unwrap()
            .insert(capability.clone(), Arc::downgrade(&control));
        let active = Arc::new(Mutex::new(()));
        let (slow_client, slow_server) = UnixStream::pair().unwrap();
        let (fast_client, fast_server) = UnixStream::pair().unwrap();
        fast_client
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let owner = active.clone();
        let slow_handle = std::thread::spawn(move || handle(slow_server, owner, "test"));
        let fast_handle = std::thread::spawn(move || handle(fast_server, active, "test"));
        let slow_cap = capability.clone();
        let slow = std::thread::spawn(move || {
            exchange(
                &mut BufReader::new(slow_client),
                &json!({"op":"api","session":slow_cap,"method":"GET","path":"/proxies/Slow/delay?url=https%3A%2F%2Fexample.com&timeout=2000&expected=204"}),
            )
        });
        start.recv_timeout(Duration::from_secs(2)).unwrap();
        let mut fast_reader = BufReader::new(fast_client);
        let fast = exchange(
            &mut fast_reader,
            &json!({"op":"api","session":capability,"method":"GET","path":"/version"}),
        );
        release.send(()).unwrap();
        assert_eq!(fast.unwrap()["ready"], true);
        assert!(slow.join().unwrap().is_ok());
        drop(fast_reader);
        slow_handle.join().unwrap().unwrap();
        fast_handle.join().unwrap().unwrap();
        http.join().unwrap();
        drop(control);
        assert!(controller(&capability).is_err());
        CONTROLLERS
            .get()
            .unwrap()
            .lock()
            .unwrap()
            .remove(&capability);
    }
    #[test]
    fn oversized_messages_never_reach_the_socket() {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        assert!(send(&mut sender, &json!("x".repeat(MAX_MESSAGE))).is_err());
        receiver.set_nonblocking(true).unwrap();
        assert_eq!(
            receiver.read(&mut [0]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
    #[test]
    fn messages_round_trip_and_peers_are_authenticated() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        assert_eq!(peer(&receiver).unwrap(), unsafe { libc::getuid() });
        send(&mut sender, &json!({"op":"hello"})).unwrap();
        assert_eq!(
            receive(&mut BufReader::new(receiver)).unwrap()["op"],
            "hello"
        );
    }
}
