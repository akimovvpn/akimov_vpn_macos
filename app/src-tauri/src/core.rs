//! Owns the mihomo process. The core runs while connected or testing latency, so an idle app costs no core memory,
//! Local supervisors and the privileged broker stop their cores when the app exits.
use crate::{config, sysproxy};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::BufRead;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::Emitter;

#[derive(Default, Serialize, Deserialize)]
struct Settings {
    #[serde(default)]
    profile: crate::profile::Metadata,
    #[serde(default)]
    sub_id: Option<u64>,
    #[serde(default = "default_mode")]
    mode: String,
    #[serde(default)]
    sub_url: String,
    #[serde(default)]
    rules: Vec<config::Rule>,
    #[serde(default)]
    node: String,
    #[serde(default)]
    last_proxy: String,
    #[serde(default)]
    hwid: String,
    #[serde(default)]
    profile_hwid: String,
    // stored inverted so a missing setting means "close to the tray", the default
    #[serde(default)]
    quit_on_close: bool,
}

struct Run {
    tun: bool,
    child: crate::process::Process,
    ctl: u16,
    mixed: u16,
    secret: String,
    main: String,
    since: Instant,
    prev: Option<sysproxy::Saved>,
}

struct ProbeDir {
    path: PathBuf,
    base: PathBuf,
}
impl Drop for ProbeDir {
    fn drop(&mut self) {
        if let Ok(path) = self.path.canonicalize() {
            if path.parent() == Some(self.base.as_path()) {
                let _ = std::fs::remove_dir_all(path);
            }
        }
    }
}
struct Probe {
    run: Run,
    _files: ProbeDir,
}
struct Testing<'a>(&'a AtomicBool);
impl Drop for Testing<'_> {
    fn drop(&mut self) {
        self.0.store(false, SeqCst);
    }
}

fn default_mode() -> String {
    "tun".into()
}

pub fn is_admin() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn tun_ready() -> bool {
    std::process::Command::new("/sbin/ifconfig")
        .output()
        .is_ok_and(|out| {
            out.status.success()
                && String::from_utf8_lossy(&out.stdout).contains("inet 198.19.0.1 ")
        })
}

impl Drop for Run {
    fn drop(&mut self) {
        if let Some(saved) = &self.prev {
            let _ = sysproxy::restore(saved, &data_dir().join("proxy-recovery.json"));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct St {
    settings: Settings,
    run: Option<Run>,
}

struct Latency {
    revision: u64,
    results: HashMap<String, Value>,
}
impl Latency {
    fn fresh(&self, revision: u64) -> bool {
        self.revision == revision
    }
}

pub struct Engine {
    st: Mutex<St>,
    gen: AtomicU64,
    watch: AtomicBool,
    local: ureq::Agent,
    closing: AtomicBool,
    quit_on_close: AtomicBool,
    testing: AtomicBool,
    latency: Mutex<Option<Latency>>,
    profile_revision: AtomicU64,
}

pub(crate) fn data_dir() -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let base = std::env::var_os("HOME")
        .map(PathBuf::from)
        .expect("macOS must provide a user home directory")
        .join("Library/Application Support");
    let d = base.join("akimov-vpn");
    std::fs::create_dir_all(d.join("core")).expect("Cannot create the app data directory");
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700))
        .expect("Cannot secure the app data directory");
    d
}

fn save(s: &Settings) -> Result<(), String> {
    let text = serde_json::to_vec_pretty(s).map_err(|e| e.to_string())?;
    let path = data_dir().join("settings.json");
    let temp = path.with_extension("tmp");
    std::fs::write(&temp, text)
        .and_then(|_| std::fs::rename(temp, path))
        .map_err(|e| e.to_string())
}

fn clear_provider_cache() -> Result<(), String> {
    let base = data_dir().canonicalize().map_err(|e| e.to_string())?;
    let providers = base.join("core/providers");
    if providers.exists() {
        let resolved = providers.canonicalize().map_err(|e| e.to_string())?;
        if !resolved.starts_with(&base) {
            return Err("Provider cache is outside the app directory.".into());
        }
        std::fs::remove_dir_all(resolved).map_err(|e| e.to_string())?;
    }
    Ok(())
}

pub(crate) fn core_exe() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let here = exe.parent().map(PathBuf::from).unwrap_or_default();
    let dev = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("core");
    [
        here.join("../Resources/core/mihomo"),
        here.join("core/mihomo"),
        dev.join("mihomo"),
    ]
    .into_iter()
    .find(|p| p.exists())
    .ok_or_else(|| "The core is missing from this install.".to_string())
}

/// The subscription's GEOIP and GEOSITE rules need these before the core can start. Left to
/// itself the core downloads them at that moment, which fails on a restricted network or
/// behind another VPN, so the installed copies are put in place first.
// shortcut: copied only when missing, so a newer app does not refresh them; compare versions if stale data ever matters.
fn seed_geodata() {
    let Some(bundled) = core_exe()
        .ok()
        .and_then(|exe| exe.parent().map(PathBuf::from))
    else {
        return;
    };
    let target = data_dir().join("core");
    for name in ["geoip.metadb", "GeoSite.dat"] {
        if !target.join(name).is_file() {
            let _ = std::fs::copy(bundled.join(name), target.join(name));
        }
    }
}

fn free_port() -> Result<u16, String> {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .map_err(|e| e.to_string())
}

/// The operating system supplies cryptographic randomness.
pub(crate) fn random_hex() -> String {
    use std::io::Read;
    let mut bytes = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .expect("macOS random generator failed");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn connection_ids(
    snapshot: &Value,
    id: Option<&str>,
    process: Option<&str>,
) -> Result<Vec<String>, String> {
    match (id, process) {
        (Some(id), None) if !id.is_empty() => {}
        (None, Some(process)) if !process.is_empty() => {}
        _ => return Err("Choose a connection or process to close.".into()),
    }
    let connections = snapshot["connections"]
        .as_array()
        .ok_or("Could not read the core's connections.")?;
    Ok(connections
        .iter()
        .filter(|c| {
            if let Some(id) = id {
                return c["id"] == id;
            }
            let name = c["metadata"]["process"]
                .as_str()
                .unwrap_or("")
                .rsplit(['\\', '/'])
                .next()
                .filter(|name| !name.is_empty())
                .unwrap_or("Unknown process");
            process.is_some_and(|process| name.to_lowercase() == process)
        })
        .filter_map(|c| c["id"].as_str().map(str::to_string))
        .collect())
}

fn node_health(
    name: &str,
    all: &Value,
    seen: &mut std::collections::HashSet<String>,
    measurements: Option<&HashMap<String, Value>>,
) -> Value {
    if !seen.insert(name.to_string()) {
        return json!({"delay":null,"status":"unknown"});
    }
    let p = &all[name];
    let kind = p["type"]
        .as_str()
        .unwrap_or("")
        .to_ascii_lowercase()
        .replace('-', "");
    let selected = p["now"].as_str();
    let measured = measurements.and_then(|values| values.get(name));
    let mut result = if let Some(health) = measured.filter(|health| health["status"] == "ok") {
        health.clone()
    } else if let Some(now) = selected {
        let mut result = node_health(now, all, seen, measurements);
        result["now"] = json!(now);
        result
    } else if measurements.is_some() {
        measured
            .cloned()
            .unwrap_or_else(|| json!({"delay":null,"status":"unknown"}))
    } else {
        match p["history"]
            .as_array()
            .and_then(|h| h.last())
            .and_then(|h| h["delay"].as_u64())
        {
            Some(delay) if delay > 0 => json!({"delay":delay,"status":"ok"}),
            Some(_) => json!({"delay":null,"status":"timeout"}),
            None => json!({"delay":null,"status":"unknown"}),
        }
    };
    if ["urltest", "fallback", "loadbalance"].contains(&kind.as_str()) && result["status"] != "ok" {
        let children: Vec<_> = p["all"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(|n| (n, node_health(n, all, seen, measurements)))
            .collect();
        if let Some((now, health)) = children
            .iter()
            .filter(|(_, h)| h["status"] == "ok")
            .min_by_key(|(_, h)| h["delay"].as_u64())
        {
            result = health.clone();
            result["now"] = json!(now);
        } else if !children.is_empty() && children.iter().all(|(_, h)| h["status"] == "timeout") {
            result = json!({"delay":null,"status":"timeout"});
        } else {
            result = json!({"delay":null,"status":"unknown"});
        }
    }
    if result["status"] != "ok" {
        if let Some(health) = measured {
            result = health.clone();
        }
    }
    if result.get("now").is_none() && !measured.is_some_and(|health| health["status"] == "ok") {
        if let Some(now) = selected {
            result["now"] = json!(now);
        }
    }
    seen.remove(name);
    result
}

fn proxy_snapshot(v: &Value, main: &str) -> Value {
    let all = &v["proxies"];
    let group = &all[main];
    let nodes: Vec<_> = group["all"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(|name| {
            let mut health = node_health(name, all, &mut std::collections::HashSet::new(), None);
            health["name"] = json!(name);
            health["type"] = all[name]["type"].clone();
            health
        })
        .collect();
    json!({"main":main,"now":group["now"],"nodes":nodes})
}

fn apply_url_measurements(snapshot: &mut Value, measurements: Option<&HashMap<String, Value>>) {
    if let Some(nodes) = snapshot["nodes"].as_array_mut() {
        for node in nodes {
            let measured =
                measurements.and_then(|values| values.get(node["name"].as_str().unwrap_or("")));
            node["delay"] = measured.map_or(Value::Null, |value| value["delay"].clone());
            node["status"] = measured.map_or(json!("unknown"), |value| value["status"].clone());
            node["url"] = measured.map_or(Value::Null, |value| value["url"].clone());
            if let Some(now) = measured.and_then(|value| value.get("now")) {
                node["now"] = now.clone();
            }
        }
    }
}

fn record_group_members(snapshot: &Value, results: &mut HashMap<String, Value>) {
    for (name, measured) in results {
        let group = &snapshot["proxies"][name];
        if group["type"] == "URLTest" && measured["status"] == "ok" && measured.get("now").is_none()
        {
            measured["now"] = group["now"].clone();
        }
    }
}

fn selection_available(snapshot: &Value, group: &str, member: &str) -> bool {
    snapshot["proxies"][group]["all"]
        .as_array()
        .is_some_and(|members| members.iter().any(|value| value == member))
}

fn seed_automatic_groups(
    yaml: &str,
    measurements: Option<&HashMap<String, Value>>,
) -> Result<(String, Vec<(String, String)>), String> {
    let Some(measurements) = measurements else {
        return Ok((yaml.to_string(), Vec::new()));
    };
    let mut config: serde_yaml::Value = serde_yaml::from_str(yaml).map_err(|e| e.to_string())?;
    let mut selections = Vec::new();
    for group in config["proxy-groups"]
        .as_sequence_mut()
        .into_iter()
        .flatten()
    {
        if group["type"].as_str() != Some("url-test") {
            continue;
        }
        let Some(name) = group["name"].as_str() else {
            continue;
        };
        let Some(measured) = measurements
            .get(name)
            .filter(|value| value["status"] == "ok")
        else {
            continue;
        };
        let (Some(member), Some(url)) = (measured["now"].as_str(), measured["url"].as_str()) else {
            continue;
        };
        selections.push((name.to_string(), member.to_string()));
        // Selection and automatic failover must use the URL that the manual test proved works.
        group["url"] = url.into();
        group["expected-status"] = "204".into();
    }
    let yaml = if selections.is_empty() {
        yaml.to_string()
    } else {
        serde_yaml::to_string(&config).map_err(|e| e.to_string())?
    };
    Ok((yaml, selections))
}

fn cached_proxy_snapshot(
    text: &str,
    rules: &[config::Rule],
    selected: &str,
) -> Result<Value, String> {
    let sub = config::parse(text)?;
    let built = config::build(&sub, rules, 1, 2, "", false)?;
    let profile = config::picker_profile(&built.yaml, &built.main)?;
    let group = profile["proxy-groups"]
        .as_sequence()
        .into_iter()
        .flatten()
        .find(|g| g["name"].as_str() == Some(&built.main))
        .ok_or("No servers are available in this subscription.")?;
    let names: Vec<_> = group["proxies"]
        .as_sequence()
        .into_iter()
        .flatten()
        .filter_map(serde_yaml::Value::as_str)
        .collect();
    let now = names
        .iter()
        .copied()
        .find(|n| *n == selected)
        .or_else(|| names.first().copied());
    let nodes: Vec<_> = names
        .iter()
        .map(|name| json!({"name":name,"delay":null,"status":"unknown"}))
        .collect();
    Ok(json!({"main":built.main,"now":now,"nodes":nodes}))
}

impl Engine {
    pub fn new() -> Self {
        let mut settings: Settings = std::fs::read_to_string(data_dir().join("settings.json"))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        let hardware_id = crate::hwid::read().unwrap_or_default();
        if settings.hwid != hardware_id {
            settings.hwid = hardware_id;
            let _ = save(&settings);
        }
        let local = ureq::AgentBuilder::new()
            .try_proxy_from_env(false)
            .timeout_connect(Duration::from_millis(200))
            .timeout(Duration::from_secs(4))
            .build();
        let quit_on_close = AtomicBool::new(settings.quit_on_close);
        Engine {
            st: Mutex::new(St {
                settings,
                run: None,
            }),
            gen: AtomicU64::new(0),
            watch: AtomicBool::new(false),
            local,
            closing: AtomicBool::new(false),
            quit_on_close,
            testing: AtomicBool::new(false),
            latency: Mutex::new(None),
            profile_revision: AtomicU64::new(0),
        }
    }

    fn api(
        &self,
        ctl: u16,
        secret: &str,
        method: &str,
        path: &str,
        body: Option<Value>,
        wait: u64,
    ) -> Result<Value, String> {
        if let Some(result) = crate::service::api(ctl, secret, method, path, body.as_ref(), wait) {
            return result;
        }
        let req = self
            .local
            .request(method, &format!("http://127.0.0.1:{ctl}{path}"))
            .set("Authorization", &format!("Bearer {secret}"))
            .timeout(Duration::from_secs(wait));
        let resp = match body {
            Some(b) => req.send_json(b),
            None => req.call(),
        }
        .map_err(|e| e.to_string())?;
        if resp.status() == 204 {
            return Ok(Value::Null);
        }
        if path == "/traffic" {
            let mut line = String::new();
            std::io::BufReader::new(resp.into_reader())
                .read_line(&mut line)
                .map_err(|e| e.to_string())?;
            return serde_json::from_str(&line).map_err(|e| e.to_string());
        }
        Ok(resp.into_json().unwrap_or(Value::Null))
    }

    fn running(&self) -> Option<(u16, String, String, Instant)> {
        let st = self.st.lock().unwrap();
        st.run
            .as_ref()
            .map(|r| (r.ctl, r.secret.clone(), r.main.clone(), r.since))
    }

    pub fn boot(&self) -> Result<Value, String> {
        let st = self.st.lock().unwrap();
        if st.run.is_none() {
            sysproxy::recover(&data_dir().join("proxy-recovery.json"))
                .map_err(|e| format!("Could not recover the macOS proxy: {e}"))?;
        }
        Ok(json!({
            "has_sub": data_dir().join("sub.yaml").exists(),
            "sub_url": st.settings.sub_url,
            "connected": st.run.is_some(),
            "secs": st.run.as_ref().map(|r| r.since.elapsed().as_secs()).unwrap_or(0),
            "rules": st.settings.rules,
            "node": st.settings.node,
            "mode": if st.settings.mode.is_empty() { "tun" } else { &st.settings.mode },
            "close_to_tray": !st.settings.quit_on_close,
            "admin": is_admin(),
            "hwid": st.settings.hwid,
            "hwid_required": true,
            "hwid_available": crate::hwid::valid(&st.settings.hwid),
            "sub_id": st.settings.sub_id,
            "version": env!("CARGO_PKG_VERSION"),
            "profile": st.settings.profile,
        }))
    }

    pub fn set_subscription(&self, url: &str) -> Result<Value, String> {
        let url = url.trim();
        if !url.starts_with("https://") {
            return Err("The link must start with https://".into());
        }
        let hwid = {
            let st = self.st.lock().unwrap();
            if st.run.is_some() {
                return Err("Disconnect before updating the subscription.".into());
            }
            st.settings.hwid.clone()
        };
        let (text, metadata) = crate::profile::fetch(url, &hwid)?;
        let sub = config::parse(&text)?;
        let built = config::build(&sub, &[], 1, 1, "x", false)?; // proves the profile can be turned into a config before we keep it
        let mut st = self.st.lock().unwrap();
        if st.run.is_some() || self.closing.load(SeqCst) {
            return Err("Disconnect before updating the subscription.".into());
        }
        let temp = data_dir().join("sub.tmp");
        std::fs::write(&temp, &text)
            .and_then(|_| std::fs::rename(temp, data_dir().join("sub.yaml")))
            .map_err(|e| e.to_string())?;
        st.settings.sub_url = url.to_string();
        st.settings.profile = metadata;
        self.invalidate_latency();
        st.settings.profile_hwid = hwid;
        save(&st.settings)?;
        Ok(json!({ "ok": true, "nodes": built.nodes }))
    }

    pub fn refresh_subscription(&self) -> Result<Value, String> {
        let (url, hwid) = {
            let st = self.st.lock().unwrap();
            (st.settings.sub_url.clone(), st.settings.hwid.clone())
        };
        if url.is_empty() {
            return Err("Choose a plan before connecting.".into());
        }
        let (text, metadata) = crate::profile::fetch(&url, &hwid)?;
        let sub = config::parse(&text)?;
        let mut st = self.st.lock().unwrap();
        if st.settings.sub_url != url || st.settings.hwid != hwid {
            return Err("The subscription changed. Try again.".into());
        }
        if self.closing.load(SeqCst) {
            return Err("The app is closing.".into());
        }
        let path = data_dir().join("sub.yaml");
        let old = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
        let cfg = data_dir().join("core/config.yaml");
        let mut rollback = None;
        let mut main = None;
        if let Some(run) = st.run.as_ref() {
            let built = config::build(
                &sub,
                &st.settings.rules,
                run.mixed,
                run.ctl,
                &run.secret,
                run.tun,
            )?;
            let old_cfg = std::fs::read_to_string(&cfg).map_err(|e| e.to_string())?;
            std::fs::write(&cfg, &built.yaml).map_err(|e| e.to_string())?;
            let reloaded = if text == old {
                self.reload_config(run.ctl, &run.secret, &built.yaml)
            } else {
                self.api(
                    run.ctl,
                    &run.secret,
                    "PUT",
                    "/configs?force=false",
                    Some(json!({"payload":built.yaml})),
                    10,
                )
                .map(|_| ())
            };
            if let Err(error) = reloaded {
                std::fs::write(&cfg, &old_cfg).map_err(|e| e.to_string())?;
                self.reload_config(run.ctl, &run.secret, &old_cfg)?;
                return Err(error);
            }
            main = Some(built.main);
            rollback = Some((old_cfg, run.ctl, run.secret.clone()));
        } else {
            config::build(
                &sub,
                &st.settings.rules,
                1,
                2,
                "validation",
                st.settings.mode == "tun",
            )?;
        }
        let old_metadata = std::mem::replace(&mut st.settings.profile, metadata);
        let old_profile_hwid = std::mem::replace(&mut st.settings.profile_hwid, hwid);
        let temp = path.with_extension("tmp");
        let result = std::fs::write(&temp, &text)
            .and_then(|_| std::fs::rename(&temp, &path))
            .map_err(|e| e.to_string())
            .and_then(|_| save(&st.settings));
        if let Err(error) = result {
            st.settings.profile = old_metadata;
            st.settings.profile_hwid = old_profile_hwid;
            std::fs::write(&path, old).map_err(|e| e.to_string())?;
            if let Some((old_cfg, ctl, secret)) = rollback {
                std::fs::write(&cfg, &old_cfg).map_err(|e| e.to_string())?;
                self.reload_config(ctl, &secret, &old_cfg)?;
            }
            return Err(error);
        }
        if text != old {
            self.invalidate_latency();
        }
        if let (Some(run), Some(main)) = (st.run.as_mut(), main) {
            run.main = main;
        }
        drop(st);
        self.boot()
    }

    fn ensure_profile_hwid(&self) -> Result<(), String> {
        let needs_refresh = {
            let st = self.st.lock().unwrap();
            if !crate::hwid::valid(&st.settings.hwid) {
                return Err(crate::hwid::UNAVAILABLE.into());
            }
            !st.settings.sub_url.is_empty() && st.settings.profile_hwid != st.settings.hwid
        };
        if needs_refresh {
            self.refresh_subscription()?;
        }
        Ok(())
    }

    pub fn connect(self: &Arc<Self>, app: tauri::AppHandle) -> Result<Value, String> {
        let attempt = self.gen.load(SeqCst);
        self.ensure_profile_hwid()?;
        let (result, generation) = self.start_attempt(attempt)?;
        if let Some(gen) = generation {
            if self.gen.load(SeqCst) != gen {
                return Err("Connection cancelled.".into());
            }
            let me = self.clone();
            std::thread::spawn(move || me.ticker(app, gen));
        }
        Ok(result)
    }

    fn start_attempt(&self, attempt: u64) -> Result<(Value, Option<u64>), String> {
        let t0 = Instant::now();
        let mut st = self.st.lock().unwrap();
        if !crate::hwid::valid(&st.settings.hwid) {
            return Err(crate::hwid::UNAVAILABLE.into());
        }
        if self.closing.load(SeqCst) {
            return Err("The app is closing.".into());
        }
        if self.gen.load(SeqCst) != attempt {
            return Err("Connection cancelled.".into());
        }
        if st.run.is_some() {
            return Ok((json!({ "ok": true, "ms": 0 }), None));
        }
        let dir = data_dir();
        let tun = st.settings.mode == "tun" || st.settings.mode.is_empty();
        sysproxy::recover(&dir.join("proxy-recovery.json")).map_err(|e| e.to_string())?;
        let text = std::fs::read_to_string(dir.join("sub.yaml"))
            .map_err(|_| "no_subscription".to_string())?;
        let sub = config::parse(&text)?;
        let mixed = free_port()?;
        let mut ctl = free_port()?;
        while ctl == mixed {
            ctl = free_port()?;
        }
        let secret = random_hex();
        let built = config::build(&sub, &st.settings.rules, mixed, ctl, &secret, tun)?;
        seed_geodata();
        let cfg = dir.join("core").join("config.yaml");
        let (yaml, mut selections) = self.measured_config(&built.yaml)?;
        let yaml = config::initial_selection(&yaml, &built.main, &st.settings.node)?;
        std::fs::write(&cfg, yaml).map_err(|e| e.to_string())?;
        let mut child = crate::process::Process::spawn(
            &core_exe()?,
            &dir.join("core"),
            &cfg,
            &dir.join("core/core.log"),
            tun && !is_admin(),
        )?;
        // connected means the controller answers; poll fast so a warm start takes a fraction of a second
        let deadline = Instant::now() + Duration::from_secs(25);
        loop {
            if self.closing.load(SeqCst) || self.gen.load(SeqCst) != attempt {
                let _ = child.kill();
                let _ = child.wait();
                return Err("Connection cancelled.".into());
            }
            if let Ok(version) = self.api(ctl, &secret, "GET", "/version", None, 1) {
                if let Some(error) = version["tun_error"].as_str().filter(|_| tun) {
                    return Err(format!("The macOS TUN adapter could not start: {error}"));
                }
                if version["ready"] == true && (!tun || tun_ready()) {
                    break;
                }
            }
            if let Ok(Some(code)) = child.try_wait() {
                return Err(format!(
                    "The core stopped while starting ({code}). The profile may be invalid."
                ));
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                let details =
                    std::fs::read_to_string(dir.join("core/core.log")).unwrap_or_default();
                let last = details
                    .lines()
                    .rev()
                    .find(|line| line.contains("error") || line.contains("Error"))
                    .unwrap_or("The adapter or controller did not become ready.");
                return Err(format!("The core did not start: {last}"));
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        if self.closing.load(SeqCst) || self.gen.load(SeqCst) != attempt {
            let _ = child.kill();
            let _ = child.wait();
            return Err("Connection cancelled.".into());
        }
        if !st.settings.node.is_empty() {
            selections.push((built.main.clone(), st.settings.node.clone()));
        }
        if let Err(error) = self.restore_selections(ctl, &secret, selections) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("Could not select the saved server: {error}"));
        }
        let prev = if tun {
            None
        } else {
            match sysproxy::set(mixed, &dir.join("proxy-recovery.json")) {
                Ok(saved) => Some(saved),
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("Could not set the macOS proxy: {e}"));
                }
            }
        };
        st.settings.last_proxy = sysproxy::ours(mixed);
        let _ = save(&st.settings);
        st.run = Some(Run {
            tun,
            child,
            ctl,
            mixed,
            secret,
            main: built.main.clone(),
            since: Instant::now(),
            prev,
        });
        let gen = self.gen.fetch_add(1, SeqCst) + 1;
        drop(st);
        Ok((
            json!({ "ok": true, "ms": t0.elapsed().as_millis() as u64, "nodes": built.nodes, "main": built.main }),
            Some(gen),
        ))
    }

    /// Order matters: restore the macOS proxy, close every open connection, then stop the core.
    pub fn disconnect(&self) -> Result<Value, String> {
        self.gen.fetch_add(1, SeqCst);
        self.stop(None)
    }

    pub fn close_connections(
        &self,
        id: Option<String>,
        process: Option<String>,
    ) -> Result<Value, String> {
        let Some((ctl, secret, _, _)) = self.running() else {
            return Ok(json!({"ok": true}));
        };
        let snapshot = self.api(ctl, &secret, "GET", "/connections", None, 4)?;
        for id in connection_ids(&snapshot, id.as_deref(), process.as_deref())? {
            self.api(
                ctl,
                &secret,
                "DELETE",
                &format!("/connections/{}", enc(&id)),
                None,
                4,
            )?;
        }
        Ok(json!({"ok": true}))
    }

    /// Local port of the running core, 0 when disconnected. Lets account requests fall back to the VPN route.
    pub fn proxy_port(&self) -> u16 {
        let st = self.st.lock().unwrap();
        st.run.as_ref().map(|r| r.mixed).unwrap_or(0)
    }

    pub fn shutdown(&self) {
        self.closing.store(true, SeqCst);
        let _ = self.disconnect();
    }

    fn stop(&self, expected: Option<u64>) -> Result<Value, String> {
        let mut st = self.st.lock().unwrap();
        if expected.is_some_and(|g| self.gen.load(SeqCst) != g) {
            return Ok(json!({"ok": true}));
        }
        self.gen.fetch_add(1, SeqCst);
        if let Some(mut r) = st.run.take() {
            let mut restored = Ok(());
            if let Some(p) = &r.prev {
                restored = sysproxy::restore(p, &data_dir().join("proxy-recovery.json"));
            }
            if r.tun {
                let _ = self.api(
                    r.ctl,
                    &r.secret,
                    "PATCH",
                    "/configs",
                    Some(json!({"tun":{"enable":false}})),
                    3,
                );
            }
            // Stop explicitly so helper DNS/proxy recovery failures reach the UI.
            let stopped = r.child.kill().and_then(|_| r.child.wait());
            drop(r);
            st.settings.last_proxy.clear();
            let _ = save(&st.settings);
            restored.map_err(|e| {
                format!("The core stopped, but macOS proxy recovery is needed: {e}")
            })?;
            stopped.map_err(|e| {
                format!("The core stopped, but network recovery is still being retried: {e}")
            })?;
        }
        Ok(json!({ "ok": true }))
    }

    pub fn set_rules(&self, rules: Vec<config::Rule>) -> Result<Value, String> {
        let mut st = self.st.lock().unwrap();
        let text = std::fs::read_to_string(data_dir().join("sub.yaml"))
            .map_err(|_| "Add a subscription first.".to_string())?;
        let sub = config::parse(&text)?;
        let mut rollback = None;
        if let Some(run) = st.run.as_mut() {
            let built = config::build(&sub, &rules, run.mixed, run.ctl, &run.secret, run.tun)?;
            let cfg = data_dir().join("core/config.yaml");
            let old = std::fs::read_to_string(&cfg).map_err(|e| e.to_string())?;
            std::fs::write(&cfg, &built.yaml).map_err(|e| e.to_string())?;
            if let Err(e) = self.reload_config(run.ctl, &run.secret, &built.yaml) {
                std::fs::write(&cfg, &old).map_err(|e| e.to_string())?;
                self.reload_config(run.ctl, &run.secret, &old)?;
                return Err(e);
            }
            rollback = Some((cfg, old, run.ctl, run.secret.clone()));
        } else {
            config::build(&sub, &rules, 1, 2, "validation", false)?;
        }
        let before = std::mem::replace(&mut st.settings.rules, rules);
        if let Err(e) = save(&st.settings) {
            st.settings.rules = before;
            if let Some((cfg, old, ctl, secret)) = rollback {
                std::fs::write(&cfg, &old).map_err(|e| e.to_string())?;
                self.reload_config(ctl, &secret, &old)?;
            }
            return Err(e);
        }
        Ok(json!({"ok": true}))
    }

    pub fn close_to_tray(&self) -> bool {
        !self.quit_on_close.load(SeqCst)
    }

    pub fn set_close_to_tray(&self, on: bool) -> Result<Value, String> {
        let mut st = self.st.lock().unwrap();
        st.settings.quit_on_close = !on;
        save(&st.settings)?;
        self.quit_on_close.store(!on, SeqCst);
        Ok(json!({"ok": true, "close_to_tray": on}))
    }

    pub fn set_mode(&self, mode: String) -> Result<Value, String> {
        if !["tun", "proxy"].contains(&mode.as_str()) {
            return Err("Unknown connection mode.".into());
        }
        let mut st = self.st.lock().unwrap();
        if st.run.is_some() {
            return Err("Disconnect before changing mode.".into());
        }
        st.settings.mode = mode;
        save(&st.settings)?;
        Ok(json!({"ok":true, "mode":st.settings.mode}))
    }

    pub fn set_subscription_id(&self, id: u64) -> Result<Value, String> {
        let mut st = self.st.lock().unwrap();
        if st.run.is_some() {
            return Err("Disconnect before switching subscriptions.".into());
        }
        if st.settings.sub_id != Some(id) {
            clear_provider_cache()?;
        }
        st.settings.sub_id = Some(id);
        st.settings.node.clear();
        save(&st.settings)?;
        drop(st);
        self.boot()
    }

    pub fn forget_subscription(&self) -> Result<(), String> {
        crate::service::clear_cache()?;
        let mut st = self.st.lock().unwrap();
        if st.run.is_some() {
            return Err("Disconnect before signing out.".into());
        }
        for path in [
            data_dir().join("sub.yaml"),
            data_dir().join("core/config.yaml"),
            data_dir().join("core/cache.db"),
            data_dir().join("core/core.log"),
        ] {
            match std::fs::remove_file(path) {
                Ok(()) => (),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                Err(e) => return Err(e.to_string()),
            }
        }
        clear_provider_cache()?;
        st.settings.sub_id = None;
        st.settings.sub_url.clear();
        self.invalidate_latency();
        st.settings.profile = crate::profile::Metadata::default();
        st.settings.node.clear();
        save(&st.settings)
    }

    pub fn proxies(&self) -> Result<Value, String> {
        let Some((ctl, secret, main, _)) = self.running() else {
            let st = self.st.lock().unwrap();
            let text = std::fs::read_to_string(data_dir().join("sub.yaml"))
                .map_err(|_| "Choose a subscription to load its servers.")?;
            let mut snapshot = cached_proxy_snapshot(&text, &st.settings.rules, &st.settings.node)?;
            drop(st);
            self.measured_snapshot(&mut snapshot);
            return Ok(snapshot);
        };
        let v = self.api(ctl, &secret, "GET", "/proxies", None, 4)?;
        let mut snapshot = proxy_snapshot(&v, &main);
        self.order_nodes(&mut snapshot);
        self.measured_snapshot(&mut snapshot);
        Ok(snapshot)
    }

    fn order_nodes(&self, snapshot: &mut Value) {
        let st = self.st.lock().unwrap();
        let Ok(text) = std::fs::read_to_string(data_dir().join("sub.yaml")) else {
            return;
        };
        let Ok(cached) = cached_proxy_snapshot(&text, &st.settings.rules, &st.settings.node) else {
            return;
        };
        let positions: HashMap<_, _> = cached["nodes"]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
            .filter_map(|(i, n)| Some((n["name"].as_str()?.to_string(), i)))
            .collect();
        if let Some(nodes) = snapshot["nodes"].as_array_mut() {
            nodes.sort_by_key(|n| {
                positions
                    .get(n["name"].as_str().unwrap_or(""))
                    .copied()
                    .unwrap_or(usize::MAX)
            });
        }
    }

    fn start_probe(&self) -> Result<Probe, String> {
        self.ensure_profile_hwid()?;
        if self.closing.load(SeqCst) {
            return Err("The app is closing.".into());
        }
        let (rules, selected) = {
            let st = self.st.lock().unwrap();
            (st.settings.rules.clone(), st.settings.node.clone())
        };
        let directory = data_dir();
        let base = directory.canonicalize().map_err(|e| e.to_string())?;
        let text = std::fs::read_to_string(directory.join("sub.yaml"))
            .map_err(|_| "Choose a subscription to load its servers.")?;
        let mixed = free_port()?;
        let mut ctl = free_port()?;
        while ctl == mixed {
            ctl = free_port()?;
        }
        let secret = random_hex();
        let built = config::build(&config::parse(&text)?, &rules, mixed, ctl, &secret, false)?;
        let path = directory.join(format!("latency-{}", random_hex()));
        std::fs::create_dir(&path).map_err(|e| e.to_string())?;
        let files = ProbeDir { path, base };
        seed_geodata();
        for name in ["geoip.metadb", "Country.mmdb", "GeoIP.dat", "GeoSite.dat"] {
            let cached = directory.join("core").join(name);
            if cached.is_file() {
                std::fs::copy(cached, files.path.join(name))
                    .map_err(|_| "Could not prepare the server test.")?;
            }
        }
        let cfg = files.path.join("config.yaml");
        let mut profile = config::picker_profile(&built.yaml, &built.main)?;
        profile.as_mapping_mut().unwrap().remove("rule-providers");
        profile.as_mapping_mut().unwrap().remove("sub-rules");
        profile["rules"] =
            serde_yaml::Value::Sequence(vec![format!("MATCH,{}", built.main).into()]);
        let yaml = serde_yaml::to_string(&profile).map_err(|e| e.to_string())?;
        let yaml = config::initial_selection(&yaml, &built.main, &selected)?;
        std::fs::write(&cfg, yaml).map_err(|e| e.to_string())?;
        let child = crate::process::Process::spawn(
            &core_exe()?,
            &files.path,
            &cfg,
            &data_dir().join("core/latency.log"),
            false,
        )?;
        let mut probe = Probe {
            run: Run {
                tun: false,
                child,
                ctl,
                mixed,
                secret,
                main: built.main,
                since: Instant::now(),
                prev: None,
            },
            _files: files,
        };
        while probe.run.since.elapsed() < Duration::from_secs(25) {
            if self.closing.load(SeqCst) {
                return Err("The app is closing.".into());
            }
            if probe
                .run
                .child
                .try_wait()
                .map_err(|e| e.to_string())?
                .is_some()
            {
                break;
            }
            if self
                .api(ctl, &probe.run.secret, "GET", "/version", None, 1)
                .is_ok_and(|v| v["ready"] == true)
            {
                if !selected.is_empty() {
                    let _ = self.api(
                        ctl,
                        &probe.run.secret,
                        "PUT",
                        &format!("/proxies/{}", enc(&probe.run.main)),
                        Some(json!({"name":selected})),
                        2,
                    );
                }
                return Ok(probe);
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        Err("Could not test servers. Try again later.".into())
    }

    pub fn select_node(&self, name: String) -> Result<Value, String> {
        let mut st = self.st.lock().unwrap();
        if let Some(run) = &st.run {
            self.api(
                run.ctl,
                &run.secret,
                "PUT",
                &format!("/proxies/{}", enc(&run.main)),
                Some(json!({ "name": name })),
                4,
            )?;
        } else {
            let text = std::fs::read_to_string(data_dir().join("sub.yaml"))
                .map_err(|_| "Choose a subscription to load its servers.")?;
            let snapshot = cached_proxy_snapshot(&text, &st.settings.rules, &st.settings.node)?;
            if !snapshot["nodes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|n| n["name"] == name)
            {
                return Err(
                    "This server is no longer in your subscription. Update it and try again."
                        .into(),
                );
            }
        }
        let previous = st.settings.node.clone();
        st.settings.node = name;
        if let Err(error) = save(&st.settings) {
            st.settings.node = previous;
            return Err(error);
        }
        Ok(json!({ "ok": true }))
    }

    fn invalidate_latency(&self) {
        let mut saved = self.latency.lock().unwrap();
        self.profile_revision.fetch_add(1, SeqCst);
        *saved = None;
    }
    fn measured_snapshot(&self, snapshot: &mut Value) {
        let saved = self.latency.lock().unwrap();
        let fresh = saved
            .as_ref()
            .filter(|values| values.fresh(self.profile_revision.load(SeqCst)));
        apply_url_measurements(snapshot, fresh.map(|values| &values.results));
    }

    fn measured_config(&self, yaml: &str) -> Result<(String, Vec<(String, String)>), String> {
        let saved = self.latency.lock().unwrap();
        let fresh = saved
            .as_ref()
            .filter(|values| values.fresh(self.profile_revision.load(SeqCst)));
        seed_automatic_groups(yaml, fresh.map(|values| &values.results))
    }

    fn reload_config(&self, ctl: u16, secret: &str, yaml: &str) -> Result<(), String> {
        let (yaml, selections) = self.measured_config(yaml)?;
        self.api(
            ctl,
            secret,
            "PUT",
            "/configs?force=false",
            Some(json!({"payload":yaml})),
            10,
        )?;
        self.restore_selections(ctl, secret, selections)
    }

    fn restore_selections(
        &self,
        ctl: u16,
        secret: &str,
        selections: Vec<(String, String)>,
    ) -> Result<(), String> {
        if selections.is_empty() {
            return Ok(());
        }
        let snapshot = self.api(ctl, secret, "GET", "/proxies", None, 4)?;
        for (group, member) in selections {
            if !selection_available(&snapshot, &group, &member) {
                continue;
            }
            self.api(
                ctl,
                secret,
                "PUT",
                &format!("/proxies/{}", enc(&group)),
                Some(json!({"name":member})),
                2,
            )?;
        }
        Ok(())
    }

    fn measure_proxy(&self, ctl: u16, secret: &str, name: &str) -> Value {
        for url in [
            "https://www.gstatic.com/generate_204",
            "https://cp.cloudflare.com/generate_204",
        ] {
            if let Ok(result) = self.api(
                ctl,
                secret,
                "GET",
                &format!(
                    "/proxies/{}/delay?url={}&timeout=2000&expected=204",
                    enc(name),
                    enc(url)
                ),
                None,
                3,
            ) {
                if result["delay"].as_u64().is_some_and(|delay| delay > 0) {
                    return json!({"delay":result["delay"],"status":"ok","url":url});
                }
            }
        }
        json!({"delay":null,"status":"failed","url":null})
    }

    pub fn test_latency(&self, progress: impl Fn(Value) + Sync) -> Result<Value, String> {
        if self.testing.swap(true, SeqCst) {
            return Err("A latency test is already running.".into());
        }
        let _testing = Testing(&self.testing);
        self.ensure_profile_hwid()?;
        let generation = self.gen.load(SeqCst);
        let revision = self.profile_revision.load(SeqCst);
        let probe;
        let (ctl, secret, main) = if let Some((ctl, secret, main, _)) = self.running() {
            (ctl, secret, main)
        } else {
            probe = self.start_probe()?;
            (
                probe.run.ctl,
                probe.run.secret.clone(),
                probe.run.main.clone(),
            )
        };
        let snapshot = self.api(ctl, &secret, "GET", "/proxies", None, 4)?;
        let all = &snapshot["proxies"];
        let visible: Vec<String> = all[&main]["all"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect();
        let mut pending = visible;
        let mut seen = std::collections::HashSet::new();
        let mut leaves = Vec::new();
        let mut groups = Vec::new();
        while let Some(name) = pending.pop() {
            if !seen.insert(name.clone()) {
                continue;
            }
            if let Some(members) = all[&name]["all"].as_array() {
                groups.push(name.clone());
                pending.extend(members.iter().filter_map(Value::as_str).map(str::to_string));
            } else {
                leaves.push(name);
            }
        }
        let results = Mutex::new(HashMap::new());
        // Test each leaf once; slow hosts do not hold up the next available worker.
        for targets in [&leaves, &groups] {
            let next = std::sync::atomic::AtomicUsize::new(0);
            std::thread::scope(|scope| {
                for _ in 0..16.min(targets.len()) {
                    let (next, results, secret, progress) = (&next, &results, &secret, &progress);
                    scope.spawn(move || loop {
                        if self.closing.load(SeqCst)
                            || self.gen.load(SeqCst) != generation
                            || self.profile_revision.load(SeqCst) != revision
                        {
                            break;
                        }
                        let Some(name) = targets.get(next.fetch_add(1, SeqCst)) else {
                            break;
                        };
                        let measured = self.measure_proxy(ctl, secret, name);
                        if self.closing.load(SeqCst)
                            || self.gen.load(SeqCst) != generation
                            || self.profile_revision.load(SeqCst) != revision
                        {
                            break;
                        }
                        let mut saved = results.lock().unwrap();
                        saved.insert(name.clone(), measured);
                        let mut measured = node_health(
                            name,
                            all,
                            &mut std::collections::HashSet::new(),
                            Some(&saved),
                        );
                        measured["name"] = json!(name);
                        saved.insert(name.clone(), measured.clone());
                        drop(saved);
                        progress(measured);
                    });
                }
            });
        }
        if self.closing.load(SeqCst) || self.gen.load(SeqCst) != generation {
            return Err("Test cancelled.".into());
        }
        let mut results = results.into_inner().unwrap();
        let refreshed = self.api(ctl, &secret, "GET", "/proxies", None, 4)?;
        record_group_members(&refreshed, &mut results);
        let mut result = proxy_snapshot(&refreshed, &main);
        apply_url_measurements(&mut result, Some(&results));
        self.order_nodes(&mut result);
        let mut saved = self.latency.lock().unwrap();
        if self.profile_revision.load(SeqCst) != revision {
            return Err("Test cancelled.".into());
        }
        *saved = Some(Latency { revision, results });
        drop(saved);
        let st = self.st.lock().unwrap();
        if self.gen.load(SeqCst) != generation || self.profile_revision.load(SeqCst) != revision {
            return Err("Test cancelled.".into());
        }
        if let Some(run) = &st.run {
            let cfg = data_dir().join("core/config.yaml");
            let yaml = std::fs::read_to_string(&cfg).map_err(|e| e.to_string())?;
            if let Err(error) = self.reload_config(run.ctl, &run.secret, &yaml) {
                self.api(
                    run.ctl,
                    &run.secret,
                    "PUT",
                    "/configs?force=false",
                    Some(json!({"payload":yaml})),
                    10,
                )?;
                return Err(error);
            }
        }
        Ok(result)
    }

    pub fn watch(&self, on: bool) {
        self.watch.store(on, SeqCst);
    }

    /// Read one traffic sample per second; only materialize connection details on their screen.
    fn ticker(self: Arc<Self>, app: tauri::AppHandle, gen: u64) {
        let mut last: HashMap<String, (u64, u64)> = HashMap::new();
        let mut misses = 0;
        while self.gen.load(SeqCst) == gen {
            let Some((ctl, secret, _, since)) = self.running() else {
                break;
            };
            let tick_start = Instant::now();
            let sample = self.api(ctl, &secret, "GET", "/traffic", None, 2);
            match sample {
                Ok(v) => {
                    misses = 0;
                    let mut conns = Value::Null;
                    if self.watch.load(SeqCst) {
                        if let Ok(list) = self.api(ctl, &secret, "GET", "/connections", None, 2) {
                            let mut now = HashMap::new();
                            let mut rows = Vec::new();
                            for c in list["connections"]
                                .as_array()
                                .into_iter()
                                .flatten()
                                .take(300)
                            {
                                let id = c["id"].as_str().unwrap_or("").to_string();
                                let (d, u) = (
                                    c["download"].as_u64().unwrap_or(0),
                                    c["upload"].as_u64().unwrap_or(0),
                                );
                                let (od, ou) = last.get(&id).copied().unwrap_or((d, u));
                                let m = &c["metadata"];
                                let host = ["host", "sniffHost", "destinationIP"]
                                    .iter()
                                    .filter_map(|k| m[*k].as_str())
                                    .find(|s| !s.is_empty())
                                    .unwrap_or("");
                                rows.push(json!({ "id": id, "host": host, "port": m["destinationPort"], "proc": m["process"], "dn": d.saturating_sub(od), "up": u.saturating_sub(ou), "chains": c["chains"], "rule": c["rule"], "payload": c["rulePayload"] }));
                                now.insert(id, (d, u));
                            }
                            last = now;
                            conns = Value::Array(rows);
                        }
                    } else {
                        last.clear();
                    }
                    if self.gen.load(SeqCst) != gen {
                        break;
                    }
                    let _ = app.emit("tick", json!({ "dn": v["down"], "up": v["up"], "secs": since.elapsed().as_secs(), "conns": conns }));
                }
                Err(_) => {
                    misses += 1;
                    if misses >= 3 {
                        let _ = self.stop(Some(gen));
                        if self.gen.load(SeqCst) == gen + 1 {
                            let _ = app.emit("dropped", Value::Null);
                        }
                        break;
                    }
                }
            }
            std::thread::sleep(Duration::from_secs(1).saturating_sub(tick_start.elapsed()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn window_close_does_not_wait_for_a_connection_holding_the_engine_lock() {
        let engine = Arc::new(Engine::new());
        let state = engine.st.lock().unwrap();
        let expected = !state.settings.quit_on_close;
        let other = engine.clone();
        let (send, receive) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let _ = send.send(other.close_to_tray());
        });
        let result = receive.recv_timeout(Duration::from_millis(100));
        drop(state);
        worker.join().unwrap();
        assert_eq!(
            result.ok(),
            Some(expected),
            "window-close must never block on network work"
        );
    }

    #[test]
    fn restoring_choices_skips_removed_or_renamed_profile_and_provider_members() {
        let snapshot = json!({"proxies":{
            "Main":{"all":["Replacement","Auto"]},
            "Auto":{"all":["New provider member"]}
        }});
        assert!(!selection_available(&snapshot, "Main", "Removed server"));
        assert!(!selection_available(
            &snapshot,
            "Auto",
            "Old provider member"
        ));
        assert!(!selection_available(
            &snapshot,
            "Removed group",
            "Replacement"
        ));
        assert!(selection_available(&snapshot, "Main", "Replacement"));
        assert!(selection_available(
            &snapshot,
            "Auto",
            "New provider member"
        ));
    }
    #[test]
    fn nested_automatic_group_selects_its_direct_member() {
        let all = json!({
            "Outer":{"type":"URLTest","now":"Inner","all":["Inner"]},
            "Inner":{"type":"URLTest","now":"Live","all":["Live"]},
            "Live":{"type":"Vless"}
        });
        let measured = HashMap::from([
            ("Outer".to_string(), json!({"status":"failed"})),
            ("Inner".to_string(), json!({"status":"failed"})),
            (
                "Live".to_string(),
                json!({"status":"ok","delay":21,"url":"https://www.gstatic.com/generate_204"}),
            ),
        ]);
        let health = node_health(
            "Outer",
            &all,
            &mut std::collections::HashSet::new(),
            Some(&measured),
        );
        assert_eq!(health["now"], "Inner");
        assert_eq!(health["status"], "ok");
        let results = HashMap::from([("Outer".to_string(), health)]);
        let (_, selections) = seed_automatic_groups(
            "proxy-groups: [{name: Outer, type: url-test, proxies: [Inner]}]",
            Some(&results),
        )
        .unwrap();
        assert_eq!(selections, [("Outer".into(), "Inner".into())]);
    }
    #[test]
    fn closing_a_connection_uses_its_core_id_and_leaves_other_sockets_alone() {
        let snapshot = json!({"connections":[
            {"id":"one","metadata":{"process":"chrome.exe"}},
            {"id":"two","metadata":{"process":"chrome.exe"}}
        ]});
        assert_eq!(
            connection_ids(&snapshot, Some("two"), None).unwrap(),
            ["two"]
        );
        assert!(connection_ids(&snapshot, Some("already-closed"), None)
            .unwrap()
            .is_empty());
    }
    #[test]
    fn closing_a_process_matches_the_group_beyond_the_display_limit() {
        let mut connections: Vec<_> = (0..305)
            .map(|id| json!({"id":id.to_string(),"metadata":{"process":"Chrome.exe"}}))
            .collect();
        connections.push(json!({"id":"path","metadata":{"process":"C:\\Apps\\chrome.exe"}}));
        connections.push(json!({"id":"other","metadata":{"process":"chromedriver.exe"}}));
        connections.push(json!({"id":"unknown","metadata":{}}));
        let snapshot = json!({"connections":connections});
        let ids = connection_ids(&snapshot, None, Some("chrome.exe")).unwrap();
        assert_eq!(ids.len(), 306);
        assert_eq!(ids[305], "path");
        assert!(!ids.contains(&"other".to_string()));
        assert_eq!(
            connection_ids(&snapshot, None, Some("unknown process")).unwrap(),
            ["unknown"]
        );
    }
    #[test]
    fn closing_connections_requires_one_explicit_target_and_a_valid_snapshot() {
        let snapshot = json!({"connections":[]});
        for (id, process) in [
            (None, None),
            (Some("one"), Some("chrome.exe")),
            (Some(""), None),
            (None, Some("")),
        ] {
            assert!(connection_ids(&snapshot, id, process).is_err());
        }
        assert!(connection_ids(&json!({}), Some("one"), None).is_err());
    }
    #[test]
    fn latency_from_a_previous_profile_is_never_reused() {
        let old = Latency {
            revision: 1,
            results: HashMap::new(),
        };
        assert!(old.fresh(1));
        assert!(
            !old.fresh(2),
            "a new profile must not inherit results for reused node names"
        );
    }
    #[test]
    fn fresh_url_results_replace_unrelated_background_timeouts() {
        let mut snapshot = json!({"nodes":[{"name":"Working","delay":null,"status":"timeout"},{"name":"Unmeasured","delay":12,"status":"ok"}]});
        let measured = HashMap::from([(
            "Working".to_string(),
            json!({"delay":29,"status":"ok","url":"https://example.invalid/check"}),
        )]);
        apply_url_measurements(&mut snapshot, Some(&measured));
        assert_eq!(snapshot["nodes"][0]["delay"], 29);
        assert_eq!(snapshot["nodes"][0]["status"], "ok");
        assert_eq!(snapshot["nodes"][1]["status"], "unknown");
        apply_url_measurements(&mut snapshot, None);
        assert_eq!(snapshot["nodes"][0]["status"], "unknown");
    }
    #[test]
    fn cached_picker_preserves_groups_order_and_saved_choice_without_starting_core() {
        let sub = "proxies:\n- {name: First, type: direct}\n- {name: Second, type: direct}\nproxy-groups:\n- {name: Main, type: select, proxies: [First, Second]}\nrules: ['MATCH,Main']";
        let v = cached_proxy_snapshot(sub, &[], "Second").unwrap();
        assert_eq!(v["now"], "Second");
        assert_eq!(v["nodes"][0]["name"], "First");
        assert_eq!(v["nodes"][0]["status"], "unknown");
        assert_eq!(
            cached_proxy_snapshot(sub, &[], "Removed").unwrap()["now"],
            "First"
        );
    }
    #[test]
    fn successful_group_probe_keeps_the_refreshed_core_selection() {
        let all = json!({"Estonia":{"type":"URLTest","now":"LTE 1","all":["LTE 1","LTE 4"]}});
        let mut measured = HashMap::from([(
            "Estonia".to_string(),
            json!({"delay":39,"status":"ok","url":"https://cp.cloudflare.com/generate_204"}),
        )]);
        let health = node_health(
            "Estonia",
            &all,
            &mut std::collections::HashSet::new(),
            Some(&measured),
        );
        assert!(
            health.get("now").is_none(),
            "a direct probe does not identify which member the core chose"
        );
        measured.insert("Estonia".into(), health);
        let mut refreshed = json!({"nodes":[{"name":"Estonia","now":"LTE 4"}]});
        apply_url_measurements(&mut refreshed, Some(&measured));
        assert_eq!(refreshed["nodes"][0]["now"], "LTE 4");
        assert_eq!(refreshed["nodes"][0]["delay"], 39);
    }
    #[test]
    fn manual_success_seeds_automatic_health_url_and_member_only() {
        let yaml = "proxy-groups:\n- {name: Estonia, type: url-test, proxies: [Dead, Live], url: 'https://health.invalid', expected-status: '200'}\n- {name: Manual, type: select, proxies: [Dead, Live]}\nrules: ['MATCH,Manual']\n";
        let results = HashMap::from([
            (
                "Estonia".to_string(),
                json!({"status":"ok","now":"Live","url":"https://cp.cloudflare.com/generate_204"}),
            ),
            (
                "Manual".to_string(),
                json!({"status":"ok","now":"Live","url":"https://cp.cloudflare.com/generate_204"}),
            ),
        ]);
        let (seeded, selections) = seed_automatic_groups(yaml, Some(&results)).unwrap();
        let value: serde_yaml::Value = serde_yaml::from_str(&seeded).unwrap();
        assert_eq!(
            value["proxy-groups"][0]["url"].as_str(),
            Some("https://cp.cloudflare.com/generate_204")
        );
        assert_eq!(
            value["proxy-groups"][0]["expected-status"].as_str(),
            Some("204")
        );
        assert_eq!(value["proxy-groups"][0]["type"].as_str(), Some("url-test"));
        assert!(value["proxy-groups"][1]["url"].is_null());
        assert_eq!(value["rules"][0].as_str(), Some("MATCH,Manual"));
        assert_eq!(selections, [("Estonia".to_string(), "Live".to_string())]);
        assert_eq!(
            seed_automatic_groups(yaml, None).unwrap(),
            (yaml.to_string(), vec![])
        );
        let failed = HashMap::from([(
            "Estonia".to_string(),
            json!({"status":"failed","now":"Live","url":"https://cp.cloudflare.com/generate_204"}),
        )]);
        assert_eq!(
            seed_automatic_groups(yaml, Some(&failed)).unwrap(),
            (yaml.to_string(), vec![])
        );
    }
    #[test]
    fn direct_group_success_records_real_member_and_keeps_measured_fallback() {
        let snapshot = json!({"proxies":{
            "Direct":{"type":"URLTest","now":"Current"},
            "Fallback":{"type":"URLTest","now":"Dead"},
            "Manual":{"type":"Selector","now":"Current"}
        }});
        let mut results = HashMap::from([
            ("Direct".to_string(), json!({"status":"ok"})),
            ("Fallback".to_string(), json!({"status":"ok","now":"Live"})),
            ("Manual".to_string(), json!({"status":"ok"})),
        ]);
        record_group_members(&snapshot, &mut results);
        assert_eq!(results["Direct"]["now"], "Current");
        assert_eq!(results["Fallback"]["now"], "Live");
        assert!(results["Manual"].get("now").is_none());
    }
    #[test]
    fn automatic_group_keeps_the_only_fresh_working_member_when_its_probe_fails() {
        let all = json!({
            "Estonia":{"type":"URLTest","now":"LTE 1","all":["LTE 1","LTE 2","LTE 3","LTE 4"],"testUrl":"https://speed.cloudflare.com/__down?bytes=50000"},
            "LTE 1":{"type":"Vless","history":[{"delay":0}]},
            "LTE 2":{"type":"Vless","history":[{"delay":0}]},
            "LTE 3":{"type":"Vless","history":[{"delay":0}]},
            "LTE 4":{"type":"Vless","history":[{"delay":0}]}
        });
        let mut measured = HashMap::new();
        for name in ["Estonia", "LTE 1", "LTE 2", "LTE 3"] {
            measured.insert(
                name.to_string(),
                json!({"delay":null,"status":"failed","url":null}),
            );
        }
        measured.insert(
            "LTE 4".into(),
            json!({"delay":42,"status":"ok","url":"https://cp.cloudflare.com/generate_204"}),
        );
        let health = node_health(
            "Estonia",
            &all,
            &mut std::collections::HashSet::new(),
            Some(&measured),
        );
        assert_eq!(health["status"], "ok");
        assert_eq!(health["delay"], 42);
        assert_eq!(health["now"], "LTE 4");
        assert_eq!(health["url"], "https://cp.cloudflare.com/generate_204");
        measured.insert("Estonia".into(), health);
        let mut snapshot = json!({"nodes":[{"name":"Estonia","now":"LTE 1"}]});
        apply_url_measurements(&mut snapshot, Some(&measured));
        assert_eq!(snapshot["nodes"][0]["now"], "LTE 4");
        assert_eq!(snapshot["nodes"][0]["delay"], 42);
        let mut selector = all.clone();
        selector["Estonia"]["type"] = json!("Selector");
        measured.insert("Estonia".into(), json!({"delay":null,"status":"failed"}));
        assert_eq!(
            node_health(
                "Estonia",
                &selector,
                &mut std::collections::HashSet::new(),
                Some(&measured)
            )["status"],
            "failed"
        );
        measured.insert("LTE 4".into(), json!({"delay":null,"status":"failed"}));
        assert_eq!(
            node_health(
                "Estonia",
                &all,
                &mut std::collections::HashSet::new(),
                Some(&measured)
            )["status"],
            "failed"
        );
    }
    #[test]
    fn automatic_group_uses_working_member_and_unknown_is_not_timeout() {
        let v = json!({"proxies":{
            "Main":{"type":"Selector","now":"Finland","all":["Finland","Unknown","Dead"]},
            "Finland":{"type":"URLTest","now":"Dead","all":["Dead","Live"]},
            "Dead":{"type":"Vless","history":[{"delay":0}]},
            "Live":{"type":"Vless","history":[{"delay":42}]},
            "Unknown":{"type":"Vless","history":[]}
        }});
        let result = proxy_snapshot(&v, "Main");
        assert_eq!(result["nodes"][0]["status"], "ok");
        assert_eq!(result["nodes"][0]["delay"], 42);
        assert_eq!(result["nodes"][0]["now"], "Live");
        assert_eq!(result["nodes"][1]["status"], "unknown");
        assert_eq!(result["nodes"][2]["status"], "timeout");
    }
    #[test]
    #[ignore = "Uses the signed-in user's cached subscription for real latency requests; changes no routes"]
    fn macos_cached_subscription_latency() {
        let engine = Engine::new();
        let snapshot = engine
            .test_latency(|_| {})
            .expect("Cached subscription latency startup failed");
        let nodes = snapshot["nodes"].as_array().unwrap();
        let working = nodes.iter().filter(|node| node["status"] == "ok").count();
        println!("Measured {} servers; {working} working routes", nodes.len());
        println!(
            "Selected route health: {}",
            nodes
                .iter()
                .find(|node| node["name"] == snapshot["now"])
                .map(|node| node["status"].clone())
                .unwrap_or(Value::Null)
        );
        assert!(working > 0, "No working route in the cached subscription");
        assert!(
            engine.st.lock().unwrap().run.is_none(),
            "Latency must leave the VPN disconnected"
        );
    }
}
