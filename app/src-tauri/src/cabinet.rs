use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs,
    io::{Read, Write},
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};
use url::Url;

// These are deployment preferences, never panel/admin credentials.
#[derive(Deserialize, Serialize)]
struct Saved {
    base_url: String,
    cabinet_url: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    protected_refresh: Vec<u8>,
}

impl Default for Saved {
    fn default() -> Self {
        Self {
            base_url: "https://api.akimov.bid/api/v1".into(),
            cabinet_url: "https://akimov.bid".into(),
            protected_refresh: Vec::new(),
        }
    }
}

#[derive(Deserialize)]
struct Tokens {
    access_token: String,
    refresh_token: String,
    token_type: String,
}

struct State {
    saved: Saved,
    access: String,
    refresh: String,
    load_error: Option<String>,
    // The browser hand-off in progress; its request token never leaves Rust.
    oauth: Option<OAuthRequest>,
    // A new email address's consent ticket, kept here so the window never sees it.
    ticket: String,
}

pub struct Cabinet {
    dir: PathBuf,
    agent: Result<ureq::Agent, String>,
    // Local port of the running VPN core, 0 when it is not running. Used only as a fallback route.
    proxy: std::sync::atomic::AtomicU16,
    // The direct route failed and the VPN route worked: skip the direct attempt while the VPN is up.
    via_vpn: std::sync::atomic::AtomicBool,
    // Holding this lock through HTTP also serializes refresh and account changes.
    state: Mutex<State>,
}

// Internal markers for "the request never reached the cabinet", which makes a second route safe for any method.
const EDGE_BLOCKED: &str = "edge_blocked";
const UNSENT: &str = "unsent";
const UNREACHABLE: &str = "Cabinet connection failed. Check your internet and API address.";

/// The edge in front of the API rejects some networks before the cabinet sees the request.
/// Its answer names the caller's address; the cabinet's own 403 ("Banned") does not.
fn edge_blocked(status: u16, value: &Value) -> bool {
    status == 403 && value["error"] == "forbidden" && value["ip"].is_string()
}

fn build_agent(proxy_port: u16) -> Result<ureq::Agent, String> {
    let tls = native_tls::TlsConnector::new().map_err(|_| "macOS TLS is unavailable.")?;
    let mut builder = ureq::AgentBuilder::new()
        .tls_connector(Arc::new(tls))
        .redirects(0) // Never forward credentials to a redirect destination.
        .max_idle_connections(0) // Avoid ureq's automatic retries of stale pooled connections.
        .timeout_connect(Duration::from_secs(6))
        .timeout(Duration::from_secs(25));
    if proxy_port != 0 {
        let proxy = ureq::Proxy::new(format!("http://127.0.0.1:{proxy_port}"))
            .map_err(|_| "The VPN route is unavailable.")?;
        builder = builder.proxy(proxy);
    }
    Ok(builder.build())
}

impl Cabinet {
    pub fn new(dir: PathBuf) -> Self {
        let loaded = (|| -> Result<(Saved, String), String> {
            let bytes = match fs::read(dir.join("cabinet.json")) {
                Ok(bytes) => bytes,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Ok((Saved::default(), String::new()))
                }
                Err(_) => return Err("Could not read cabinet preferences.".into()),
            };
            if bytes.len() > 128 * 1024 {
                return Err("Cabinet preferences are invalid.".into());
            }
            let saved: Saved =
                serde_json::from_slice(&bytes).map_err(|_| "Cabinet preferences are invalid.")?;
            let fixed = Saved::default();
            if saved.base_url != fixed.base_url || saved.cabinet_url != fixed.cabinet_url {
                // Saved for an earlier account service: its session means nothing here. Start signed out.
                return Ok((fixed, String::new()));
            }
            if !saved.base_url.is_empty() {
                if origin(&saved.base_url, true)? != saved.base_url
                    || origin(&saved.cabinet_url, false)? != saved.cabinet_url
                {
                    return Err("Cabinet preferences are invalid.".into());
                }
            } else if !saved.protected_refresh.is_empty() {
                return Err("Cabinet session has no API origin.".into());
            }
            let refresh = if saved.protected_refresh.is_empty() {
                String::new()
            } else {
                let decrypted = protect(&dir, &saved.protected_refresh, false)?;
                let session: Value = serde_json::from_slice(&decrypted)
                    .map_err(|_| "Saved cabinet session is invalid.")?;
                if session["base_url"].as_str() != Some(saved.base_url.as_str()) {
                    return Err("Saved session belongs to another API origin.".into());
                }
                session["refresh_token"]
                    .as_str()
                    .filter(|s| valid_token(s))
                    .ok_or("Saved cabinet session is invalid.")?
                    .to_owned()
            };
            Ok((saved, refresh))
        })();
        let (saved, refresh, load_error) = match loaded {
            Ok((saved, refresh)) => (saved, refresh, None),
            Err(error) => (Saved::default(), String::new(), Some(error)),
        };
        let agent = build_agent(0);
        Self {
            dir,
            agent,
            proxy: std::sync::atomic::AtomicU16::new(0),
            via_vpn: std::sync::atomic::AtomicBool::new(false),
            state: Mutex::new(State {
                saved,
                access: String::new(),
                refresh,
                load_error,
                oauth: None,
                ticket: String::new(),
            }),
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, State>, String> {
        self.state
            .lock()
            .map_err(|_| "Cabinet session is unavailable. Restart the app.".into())
    }

    pub fn require_session(&self) -> Result<(), String> {
        if self.lock()?.refresh.is_empty() {
            return Err("Please sign in again.".into());
        }
        Ok(())
    }

    /// Answers from what is saved on this computer, without the network: an unreachable
    /// account service must not hold the window on its startup screen.
    pub fn boot(&self) -> Result<Value, String> {
        let state = self.lock()?;
        Ok(json!({
            "configured": !state.saved.base_url.is_empty(),
            "signed_in": !state.refresh.is_empty(),
            "base_url": state.saved.base_url,
            "cabinet_url": state.saved.cabinet_url,
            "error": state.load_error,
        }))
    }

    /// Starts a sign-in through the system browser. Returns the provider page to open; the
    /// cabinet's callback page sends the result back through akimovvpn:// (see `oauth_finish`).
    pub fn oauth_start(&self, provider: &str) -> Result<(Url, Value), String> {
        const UNAVAILABLE: &str = "This sign-in method is unavailable right now.";
        if !OAUTH_PROVIDERS.contains(&provider) {
            return Err("Unknown sign-in method.".into());
        }
        let mut state = self.lock()?;
        state.oauth = None;
        let value = self
            .http(
                &state.saved.base_url,
                "POST",
                "/auth/oauth/request",
                None,
                Some(&json!({"provider": provider, "client": "app"})),
            )
            .map_err(|e| {
                if e.status == 0 {
                    e.message
                } else {
                    UNAVAILABLE.into()
                }
            })?;
        let request =
            OAuthRequest::parse(provider, &value, &state.saved.cabinet_url).ok_or(UNAVAILABLE)?;
        let answer = json!({"expires_in": request.expires});
        let url = request.url.clone();
        state.oauth = Some(request);
        Ok((url, answer))
    }

    /// Finishes the browser sign-in this app started, from the akimovvpn:// link the cabinet's
    /// callback page opens. `None`: the link is not for the sign-in in progress and changes nothing.
    pub fn oauth_finish(&self, link: &Url) -> Result<Option<Value>, String> {
        const FAILED: &str = "Sign-in was not completed. Try again.";
        if link.scheme() != "akimovvpn"
            || link.host_str() != Some("oauth")
            || link.path() != "/callback"
        {
            return Ok(None);
        }
        let mut params = std::collections::HashMap::new();
        for (key, value) in link.query_pairs() {
            if params
                .insert(key.into_owned(), value.into_owned())
                .is_some()
            {
                return Ok(None);
            }
        }
        let get = |key: &str| params.get(key).map(String::as_str).unwrap_or("");
        let (provider, code, error) = (get("provider"), get("code"), get("error"));
        let mut state = self.lock()?;
        let Some(request) = state.oauth.as_ref() else {
            return Ok(None);
        };
        let code_ok = code.len() <= 4096 && code.bytes().all(|b| b.is_ascii_graphic());
        if request.provider != provider
            || request.state != get("state")
            || code.is_empty() == error.is_empty()
            || !code_ok
        {
            return Ok(None);
        }
        let Some(request) = state.oauth.take() else {
            return Ok(None);
        };
        if !error.is_empty() {
            return Err("Sign-in was cancelled in the browser.".into());
        }
        if std::time::Instant::now() >= request.deadline {
            return Err("The sign-in request expired. Start again.".into());
        }
        let body = json!({"provider": request.provider, "token": request.token, "state": request.state, "code": code});
        let value = self
            .http(
                &state.saved.base_url,
                "POST",
                "/auth/oauth/complete",
                None,
                Some(&body),
            )
            .map_err(|e| {
                if e.status == 0 {
                    e.message
                } else {
                    FAILED.into()
                }
            })?;
        let me = self.adopt(&mut state, value).map_err(|_| FAILED)?;
        Ok(Some(
            json!({"status": "signed_in", "provider": request.provider, "me": me}),
        ))
    }

    pub fn oauth_cancel(&self) {
        if let Ok(mut state) = self.lock() {
            state.oauth = None;
        }
    }

    /// Email sign-in by code: send it, check it, and (new address only) open the account.
    pub fn auth(&self, action: &str, body: Value) -> Result<Value, String> {
        let email = body["email"].as_str().unwrap_or("").trim();
        let valid_email =
            email.len() <= 320 && email.contains('@') && !email.contains(char::is_whitespace);
        let mut state = self.lock()?;
        let (path, request) = match action {
            "email-code" if valid_email => ("/auth/email/code", json!({"email": email})),
            "email-verify" if valid_email => {
                let code = body["code"].as_str().unwrap_or("");
                if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
                    return Err("Enter the six-digit code from your email.".into());
                }
                ("/auth/email/verify", json!({"email": email, "code": code}))
            }
            "email-create" => {
                if body["accept_terms"] != true || body["accept_personal_data"] != true {
                    return Err("Please accept both agreements to create an account.".into());
                }
                // The server uses the ticket up on any attempt, so it is never sent twice.
                let ticket = std::mem::take(&mut state.ticket);
                if ticket.is_empty() {
                    return Err(SIGNUP_EXPIRED.into());
                }
                let request =
                    json!({"ticket": ticket, "accept_terms": true, "accept_personal_data": true});
                ("/auth/email/create", request)
            }
            "email-code" | "email-verify" => return Err("Enter a valid email address.".into()),
            _ => return Err("Something went wrong. Try again later.".into()),
        };
        let mut result = match self.http(&state.saved.base_url, "POST", path, None, Some(&request))
        {
            Ok(result) => result,
            // A code already went out less than a minute ago: let it be typed in.
            Err(e) if action == "email-code" && e.message == CODE_WAIT => {
                return Ok(json!({"status": "code_sent"}))
            }
            Err(e) => return Err(e.message),
        };
        if result.get("access_token").is_none() {
            return match (action, result["status"].as_str()) {
                ("email-code", Some("code_sent")) => Ok(json!({"status": "code_sent"})),
                ("email-verify", Some("consent_required")) => {
                    state.ticket =
                        take_ticket(&mut result).ok_or("Something went wrong. Try again later.")?;
                    Ok(result)
                }
                _ => Err("Something went wrong. Try again later.".into()),
            };
        }
        state.ticket.clear();
        let me = self.adopt(&mut state, result)?;
        Ok(json!({"status": "signed_in", "me": me}))
    }

    /// Checks a fresh session against /me before it replaces the saved one.
    fn adopt(&self, state: &mut State, value: Value) -> Result<Value, String> {
        let tokens = parse_tokens(value)?;
        let me = self
            .http(
                &state.saved.base_url,
                "GET",
                "/me",
                Some(&tokens.access_token),
                None,
            )
            .map_err(|e| e.message)?;
        validate_me(&me)?;
        self.set_tokens(state, tokens)?;
        Ok(me)
    }

    pub fn logout(&self) -> Result<Value, String> {
        let mut state = self.lock()?;
        self.clear_session(&mut state)?;
        Ok(json!({"ok": true}))
    }

    pub fn request(&self, method: &str, path: &str, body: Option<Value>) -> Result<Value, String> {
        let method = method.to_ascii_uppercase();
        validate_request(&method, path, body.as_ref())?;
        let mut state = self.lock()?;
        if method == "GET" && matches!(path, "/legal" | "/auth/methods") {
            return self
                .http(&state.saved.base_url, "GET", path, None, None)
                .map_err(|e| e.message);
        }
        self.authenticated(&mut state, &method, path, body.as_ref())
    }

    fn authenticated(
        &self,
        state: &mut State,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, String> {
        if state.refresh.is_empty() {
            return Err("Sign in to your cabinet first.".into());
        }
        if state.access.is_empty() {
            self.refresh(state)?;
        }
        match self.http(
            &state.saved.base_url,
            method,
            path,
            Some(&state.access),
            body,
        ) {
            Ok(value) => Ok(value),
            Err(error) if error.status == 401 => {
                self.refresh(state)?;
                match self.http(
                    &state.saved.base_url,
                    method,
                    path,
                    Some(&state.access),
                    body,
                ) {
                    Ok(value) => Ok(value),
                    Err(error) => {
                        if error.status == 401 {
                            self.clear_session(state)?;
                        }
                        Err(error.message)
                    }
                }
            }
            Err(error) => Err(error.message),
        }
    }

    fn refresh(&self, state: &mut State) -> Result<(), String> {
        match self.http(
            &state.saved.base_url,
            "POST",
            "/auth/refresh",
            None,
            Some(&json!({"refresh_token": state.refresh})),
        ) {
            Ok(value) => self.set_tokens(state, parse_tokens(value)?),
            Err(error) => {
                if error.status == 401 {
                    self.clear_session(state)?;
                }
                Err(error.message)
            }
        }
    }

    fn set_tokens(&self, state: &mut State, tokens: Tokens) -> Result<(), String> {
        let session = serde_json::to_vec(
            &json!({"base_url": state.saved.base_url, "refresh_token": tokens.refresh_token}),
        )
        .map_err(|_| "Could not encode cabinet session.")?;
        let encrypted = protect(&self.dir, &session, true)?;
        let saved = Saved {
            base_url: state.saved.base_url.clone(),
            cabinet_url: state.saved.cabinet_url.clone(),
            protected_refresh: encrypted,
        };
        self.save(&saved)?;
        state.saved = saved;
        state.access = tokens.access_token;
        state.refresh = tokens.refresh_token;
        state.load_error = None;
        Ok(())
    }

    fn clear_session(&self, state: &mut State) -> Result<(), String> {
        state.access.clear();
        state.refresh.clear();
        clear_keychain(&self.dir)?;
        state.saved.protected_refresh.clear();
        self.save(&state.saved)
    }

    fn save(&self, saved: &Saved) -> Result<(), String> {
        fs::create_dir_all(&self.dir)
            .map_err(|_| "Could not create cabinet preferences directory.")?;
        let path = self.dir.join("cabinet.json");
        let temporary = self.dir.join(format!("cabinet.{}.tmp", std::process::id()));
        let bytes =
            serde_json::to_vec(saved).map_err(|_| "Could not encode cabinet preferences.")?;
        let write = (|| -> std::io::Result<()> {
            let mut file = fs::File::create(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temporary, &path)
        })();
        if write.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        write.map_err(|_| "Could not save cabinet preferences securely.".into())
    }

    /// Tell the cabinet client where the running VPN core listens (0 when it is not running).
    pub fn set_proxy(&self, port: u16) {
        self.proxy.store(port, std::sync::atomic::Ordering::Relaxed);
    }

    /// Direct first. If the request provably never reached the cabinet and the VPN is up, go through the VPN once.
    fn http(
        &self,
        base: &str,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> Result<Value, HttpError> {
        use std::sync::atomic::Ordering::Relaxed;
        let unsent = |e: &HttpError| e.message == EDGE_BLOCKED || e.message == UNSENT;
        let agent = self.agent.as_ref().map_err(|e| HttpError::local(e))?;
        let port = self.proxy.load(Relaxed);
        let vpn_first = port != 0 && self.via_vpn.load(Relaxed);
        let direct = if vpn_first {
            Err(HttpError::local(UNSENT))
        } else {
            self.http_via(agent, base, method, path, token, body)
        };
        let result = match direct {
            Err(e) if port != 0 && unsent(&e) => {
                let via_vpn = build_agent(port).map_err(|e| HttpError::local(&e))?;
                let answer = self.http_via(&via_vpn, base, method, path, token, body);
                // A direct attempt costs a full connect timeout; remember which route answers.
                self.via_vpn
                    .store(!matches!(&answer, Err(e) if unsent(e)), Relaxed);
                answer
            }
            other => other,
        };
        result.map_err(|e| {
            if e.message == EDGE_BLOCKED || e.message == UNSENT {
                HttpError::local(UNREACHABLE)
            } else {
                e
            }
        })
    }

    fn http_via(
        &self,
        agent: &ureq::Agent,
        base: &str,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> Result<Value, HttpError> {
        if base.is_empty() {
            return Err(HttpError::local("Set your cabinet API address first."));
        }
        let tunnel = matches!(method, "PATCH" | "DELETE");
        let mut request = agent
            .request(
                if tunnel { "POST" } else { method },
                &format!("{base}{path}"),
            )
            .set("Accept", "application/json")
            .set("X-Cabinet-Client", "web");
        if tunnel {
            request = request.set("X-Cabinet-Verb", method);
        }
        if let Some(token) = token {
            request = request.set("Authorization", &format!("Bearer {token}"));
        }
        let result = match body {
            Some(body) => request.send_json(body),
            None if method == "POST" || method == "PATCH" => request.send_json(json!({})),
            None => request.call(),
        };
        let (response, status) = match result {
            Ok(response) => {
                let status = response.status();
                (response, status)
            }
            Err(ureq::Error::Status(status, response)) => (response, status),
            // Transport diagnostics may include a URL; keep tokens/links out of errors.
            Err(ureq::Error::Transport(transport)) => {
                // Only a failure to resolve or connect proves nothing was sent.
                let unsent = matches!(
                    transport.kind(),
                    ureq::ErrorKind::Dns | ureq::ErrorKind::ConnectionFailed
                );
                return Err(HttpError::local(if unsent { UNSENT } else { UNREACHABLE }));
            }
        };
        let mut bytes = Vec::new();
        response.into_reader().take(2 * 1024 * 1024 + 1).read_to_end(&mut bytes)
            .map_err(|_| HttpError { status, message: "Cabinet response could not be read. The operation may have completed; refresh before retrying.".into() })?;
        if bytes.len() > 2 * 1024 * 1024 {
            return Err(HttpError {
                status,
                message: "Cabinet response is too large.".into(),
            });
        }
        let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        if edge_blocked(status, &value) {
            return Err(HttpError::local(EDGE_BLOCKED));
        }
        if !(200..300).contains(&status) {
            return Err(api_error(status, &value));
        }
        if value.is_null() {
            return Err(HttpError { status, message: "Cabinet returned an invalid JSON response. Refresh before retrying an operation.".into() });
        }
        Ok(value)
    }
}

const OAUTH_PROVIDERS: [&str; 3] = ["telegram", "google", "yandex"];
const CODE_WAIT: &str = "You can request a new code in a minute.";
const SIGNUP_EXPIRED: &str = "This sign-up has expired. Request a new code.";

/// A browser sign-in the cabinet started for this app.
pub struct OAuthRequest {
    provider: String,
    token: String,
    state: String,
    url: Url,
    expires: u64,
    deadline: std::time::Instant,
}

impl OAuthRequest {
    /// Accepts only the provider's own HTTPS page, sending the person back to this
    /// cabinet's callback for that provider with PKCE; anything else is never opened.
    fn parse(provider: &str, value: &Value, site: &str) -> Option<Self> {
        let endpoint = match provider {
            "telegram" => "https://oauth.telegram.org/auth",
            "google" => "https://accounts.google.com/o/oauth2/v2/auth",
            "yandex" => "https://oauth.yandex.ru/authorize",
            _ => return None,
        };
        let token = value["token"].as_str()?;
        let state = value["state"].as_str()?;
        let expires = value["expires_in"].as_u64()?;
        if !valid_token(token)
            || !valid_token(state)
            || token == state
            || state.len() > 512
            || !state.starts_with("app.")
            || expires == 0
            || origin(site, false).ok()?.as_str() != site
        {
            return None;
        }
        let url = Url::parse(value["authorization_url"].as_str()?).ok()?;
        let expected = Url::parse(endpoint).ok()?;
        if url.origin() != expected.origin()
            || url.path() != expected.path()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return None;
        }
        let mut params = std::collections::HashMap::new();
        for (key, value) in url.query_pairs() {
            if params
                .insert(key.into_owned(), value.into_owned())
                .is_some()
            {
                return None;
            }
        }
        let callback = format!("{site}/auth/{provider}/callback");
        let required = [
            ("response_type", "code"),
            ("redirect_uri", callback.as_str()),
            ("state", state),
            ("code_challenge_method", "S256"),
        ];
        let proof = params.get("code_challenge")?;
        if required
            .iter()
            .any(|(k, v)| params.get(*k).map(String::as_str) != Some(*v))
            || params.contains_key("client_secret")
            || params.contains_key("code_verifier")
            || params
                .get("client_id")
                .is_none_or(|id| id.is_empty() || id == token)
            || proof.len() != 43
            || !proof
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        {
            return None;
        }
        Some(Self {
            provider: provider.into(),
            token: token.into(),
            state: state.into(),
            url,
            expires: expires.min(300),
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(expires.min(300)),
        })
    }
}

/// Removes the consent ticket from a server answer; the window gets the rest.
fn take_ticket(answer: &mut Value) -> Option<String> {
    let ticket = answer.as_object_mut()?.remove("ticket")?;
    ticket
        .as_str()
        .filter(|t| valid_token(t))
        .map(str::to_owned)
}

struct HttpError {
    status: u16,
    message: String,
}
impl HttpError {
    fn local(message: &str) -> Self {
        Self {
            status: 0,
            message: message.into(),
        }
    }
}

fn api_error(status: u16, value: &Value) -> HttpError {
    let fallback = match status {
        401 => "Please sign in again.",
        402 => "Insufficient balance.",
        403 => "Access to this account is restricted.",
        429 => "Too many requests. Please wait and try again.",
        409 => "This email is already registered. Try signing in.",
        410 => "This code or reset link has expired. Request a new one.",
        400 => "Check the details and try again.",
        _ => "Something went wrong. Try again later.",
    };
    // The server writes Russian; this app speaks English, so known failures go by their code.
    let coded = match value["code"].as_str().unwrap_or("") {
        "code_wait" => Some(CODE_WAIT),
        "code_invalid" => Some("That code is not right. Check it and try again."),
        "code_expired" => Some("This code has expired. Request a new one."),
        "code_locked" => Some("Too many attempts. Request a new code."),
        "code_limit" => {
            Some("Too many codes today. Try again tomorrow or use another sign-in method.")
        }
        "signup_closed" => Some("New accounts by email are closed. Use another sign-in method."),
        "signup_expired" => Some(SIGNUP_EXPIRED),
        _ => None,
    };
    if let Some(message) = coded {
        return HttpError {
            status,
            message: message.into(),
        };
    }
    let raw = value["error"].as_str().unwrap_or("").to_lowercase();
    let message = if status == 400 && (raw.contains("код") || raw.contains("code")) {
        "That code is incorrect. Try again."
    } else {
        fallback
    };
    HttpError {
        status,
        message: message.to_string(),
    }
}

fn valid_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 16384
        && token
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

fn parse_tokens(value: Value) -> Result<Tokens, String> {
    let tokens: Tokens = serde_json::from_value(value)
        .map_err(|_| "Cabinet returned an invalid sign-in response.")?;
    if tokens.token_type != "bearer"
        || !valid_token(&tokens.access_token)
        || !valid_token(&tokens.refresh_token)
    {
        return Err("Cabinet returned an invalid sign-in response.".into());
    }
    Ok(tokens)
}

fn validate_me(value: &Value) -> Result<(), String> {
    if value["id"].as_i64().is_none()
        || !value["subscriptions"].is_array()
        || value["balance"].as_i64().is_none()
    {
        return Err("Cabinet returned an invalid account response.".into());
    }
    Ok(())
}

fn origin(input: &str, api: bool) -> Result<String, String> {
    let input = input.trim();
    let error =
        "Use an HTTPS origin, for example https://cabinet.example.com (API may end with /api/v1).";
    if input.len() > 2048 || input.contains('\\') || input.chars().any(|c| c.is_control()) {
        return Err(error.into());
    }
    let mut url = Url::parse(input).map_err(|_| error)?;
    let authority = input
        .strip_prefix("https://")
        .and_then(|s| s.split('/').next())
        .ok_or(error)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || authority.contains('@')
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
        || !(url.path() == "/" || api && matches!(url.path(), "/api/v1" | "/api/v1/"))
    {
        return Err(error.into());
    }
    // Reject paths URL parsing would otherwise normalize (e.g. /admin/../).
    let raw_path = input
        .strip_prefix("https://")
        .and_then(|s| s.find('/').map(|i| &s[i..]))
        .unwrap_or("");
    if !matches!(raw_path, "" | "/") && !(api && matches!(raw_path, "/api/v1" | "/api/v1/")) {
        return Err(error.into());
    }
    url.set_path(if api { "/api/v1" } else { "/" });
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

fn positive_id(s: &str) -> bool {
    !s.starts_with('0')
        && s.bytes().all(|c| c.is_ascii_digit())
        && s.parse::<u64>()
            .map(|n| n > 0 && n <= i64::MAX as u64)
            .unwrap_or(false)
}

fn uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}

fn validate_request(method: &str, path: &str, body: Option<&Value>) -> Result<(), String> {
    let error = "This cabinet endpoint or request is not supported.";
    if path.len() > 1024
        || !path.is_ascii()
        || path.bytes().any(|c| c.is_ascii_control())
        || path.contains(['#', '\\'])
        || path.contains("//")
    {
        return Err(error.into());
    }
    let (route, query) = path
        .split_once('?')
        .map_or((path, None), |(p, q)| (p, Some(q)));
    let parts: Vec<&str> = route.split('/').collect();
    let sub_query = matches!(
        route,
        "/devices" | "/subscription/link" | "/subscription/connect-info"
    ) || parts.len() == 3 && parts[1] == "devices";
    if let Some(query) = query {
        if !sub_query
            || !query
                .strip_prefix("sub_id=")
                .map(positive_id)
                .unwrap_or(false)
        {
            return Err(error.into());
        }
    }
    let subscription = parts.len() >= 3 && parts[1] == "subscription" && positive_id(parts[2]);
    let checkout = method == "POST"
        && (route == "/buy"
            || subscription
                && parts.len() == 4
                && matches!(parts[3], "renew" | "extra-devices" | "extra-gb"));
    let device = parts.len() == 3 && parts[1] == "devices" && {
        let hwid = parts[2].replace("%3D", "=").replace("%3d", "=");
        (10..=64).contains(&hwid.len())
            && hwid
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'=' | b'-'))
    };
    let allowed = match method {
        "GET" => {
            matches!(
                route,
                "/me"
                    | "/legal"
                    | "/auth/methods"
                    | "/me/traffic"
                    | "/me/transactions"
                    | "/tariffs"
                    | "/trial"
                    | "/devices"
                    | "/subscription/link"
                    | "/subscription/connect-info"
                    | "/notifications"
                    | "/referral"
                    | "/referral/users"
            ) || parts.len() == 3 && parts[1] == "checkout" && uuid(parts[2])
        }
        "POST" => {
            checkout
                || matches!(
                    route,
                    "/trial" | "/topup" | "/promo" | "/me/notifications" | "/notifications/read"
                )
                || subscription && parts.len() == 4 && parts[3] == "auto-renew"
        }
        "PATCH" => device,
        "DELETE" => device || route == "/notifications" || subscription && parts.len() == 3,
        _ => false,
    };
    if !allowed {
        return Err(error.into());
    }
    if let Some(body) = body {
        if !body.is_object()
            || matches!(method, "GET" | "DELETE")
            || serde_json::to_vec(body).map_err(|_| error)?.len() > 65536
        {
            return Err(error.into());
        }
    }
    if checkout
        && !body
            .and_then(|b| b["request_id"].as_str())
            .map(uuid)
            .unwrap_or(false)
    {
        return Err("Checkout requires a request_id UUID. Keep the same ID when retrying an unfinished payment.".into());
    }
    if method == "PATCH"
        && !body
            .and_then(|b| b["name"].as_str())
            .map(|name| !name.trim().is_empty() && name.chars().count() <= 64)
            .unwrap_or(false)
    {
        return Err("Device name must contain 1 to 64 characters.".into());
    }
    Ok(())
}

const KEYCHAIN_SERVICE: &str = "vpn.akimov.macos.cabinet";
fn keychain_account(dir: &std::path::Path) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(dir.as_os_str().as_encoded_bytes()))
}
fn protect(dir: &std::path::Path, bytes: &[u8], encrypt: bool) -> Result<Vec<u8>, String> {
    use security_framework::passwords::{get_generic_password, set_generic_password};
    const MARKER: &[u8] = b"macos-keychain:v1";
    let account = keychain_account(dir);
    let error = |_| {
        "macOS Keychain could not secure or unlock the saved session. Unlock your login keychain and sign in again.".to_string()
    };
    if encrypt {
        set_generic_password(KEYCHAIN_SERVICE, &account, bytes).map_err(error)?;
        Ok(MARKER.to_vec())
    } else if bytes == MARKER {
        get_generic_password(KEYCHAIN_SERVICE, &account).map_err(error)
    } else {
        Err("Saved cabinet session is invalid. Sign in again.".into())
    }
}
fn clear_keychain(dir: &std::path::Path) -> Result<(), String> {
    match security_framework::passwords::delete_generic_password(
        KEYCHAIN_SERVICE,
        &keychain_account(dir),
    ) {
        Ok(()) => Ok(()),
        Err(error) if error.code() == -25300 => Ok(()),
        Err(_) => Err("macOS Keychain could not remove the saved session.".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("akimov-cabinet-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_session_saved_for_another_service_starts_signed_out_without_an_error() {
        let dir = scratch("moved");
        fs::write(
            dir.join("cabinet.json"),
            r#"{"base_url":"https://api.example.com/api/v1","cabinet_url":"https://cabinet.example.com","protected_refresh":[1,2,3]}"#,
        )
        .unwrap();
        let boot = Cabinet::new(dir.clone()).boot().unwrap();
        assert_eq!(boot["signed_in"], false);
        assert!(boot["error"].is_null());
        assert_eq!(boot["base_url"], Saved::default().base_url);
        let _ = fs::remove_dir_all(dir);
    }

    fn oauth_value(provider: &str) -> Value {
        let endpoint = match provider {
            "telegram" => "https://oauth.telegram.org/auth",
            "google" => "https://accounts.google.com/o/oauth2/v2/auth",
            _ => "https://oauth.yandex.ru/authorize",
        };
        let mut url = Url::parse(endpoint).unwrap();
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", "client-1")
            .append_pair(
                "redirect_uri",
                &format!("https://akimov.bid/auth/{provider}/callback"),
            )
            .append_pair("state", "app.server-random-state")
            .append_pair("code_challenge", &"a".repeat(43))
            .append_pair("code_challenge_method", "S256");
        json!({"token":"one-time-request", "state":"app.server-random-state", "expires_in":300, "authorization_url":url.as_str()})
    }

    #[test]
    fn oauth_request_accepts_only_registered_providers_and_callbacks() {
        for provider in ["telegram", "google", "yandex"] {
            let request =
                OAuthRequest::parse(provider, &oauth_value(provider), "https://akimov.bid")
                    .unwrap_or_else(|| panic!("{provider} refused"));
            assert_eq!(request.token, "one-time-request");
            assert_eq!(request.state, "app.server-random-state");
            let url = oauth_value(provider)["authorization_url"]
                .as_str()
                .unwrap()
                .to_owned();
            let other = if provider == "google" {
                "yandex"
            } else {
                "google"
            };
            let bad_urls = [
                url.replace("https:", "http:"),
                url.replace("https://", "https://user@"),
                url.clone() + "#x",
                url.clone() + "&state=app.server-random-state",
                url.clone() + "&client_secret=s",
                url.clone() + "&code_verifier=v",
                url.replace("%2Fauth%2F", "%2Fother%2F"),
                url.replace(&format!("%2F{provider}%2F"), &format!("%2F{other}%2F")),
                url.replace("code_challenge_method=S256", "code_challenge_method=plain"),
                url.replace(&"a".repeat(43), "short"),
                url.replace("client_id=client-1", "client_id=one-time-request"),
                url.replace("https://", "https://attacker.example/?"),
            ];
            for bad in bad_urls {
                let mut value = oauth_value(provider);
                value["authorization_url"] = json!(bad);
                assert!(
                    OAuthRequest::parse(provider, &value, "https://akimov.bid").is_none(),
                    "{bad}"
                );
            }
            for patch in [
                json!({"state":"server-random-state"}),
                json!({"state":"one-time-request"}),
                json!({"token":"bad token"}),
                json!({"expires_in":0}),
            ] {
                let mut value = oauth_value(provider);
                for (k, v) in patch.as_object().unwrap() {
                    value[k] = v.clone();
                }
                assert!(
                    OAuthRequest::parse(provider, &value, "https://akimov.bid").is_none(),
                    "{patch}"
                );
            }
            assert!(
                OAuthRequest::parse(provider, &oauth_value(provider), "https://other.example")
                    .is_none()
            );
            let mut longer = oauth_value(provider);
            longer["expires_in"] = json!(600);
            let capped = OAuthRequest::parse(provider, &longer, "https://akimov.bid").unwrap();
            assert_eq!(
                capped.expires, 300,
                "a longer server timeout is capped, not refused"
            );
        }
        assert!(
            OAuthRequest::parse("github", &oauth_value("google"), "https://akimov.bid").is_none()
        );
    }

    #[test]
    fn app_link_finishes_only_the_sign_in_this_app_started() {
        let dir = scratch("oauth-link");
        let cabinet = Cabinet::new(dir.clone());
        let link = |q: &str| Url::parse(&format!("akimovvpn://oauth/callback?{q}")).unwrap();
        let ours = "provider=google&state=app.server-random-state&code=c";
        let start = || {
            let mut state = cabinet.lock().unwrap();
            state.oauth =
                OAuthRequest::parse("google", &oauth_value("google"), "https://akimov.bid");
            state.saved.base_url = "https://127.0.0.1:9/api/v1".into();
        };
        assert_eq!(
            cabinet.oauth_finish(&link(ours)),
            Ok(None),
            "nothing started"
        );
        start();
        for bad in [
            "provider=yandex&state=app.server-random-state&code=c",
            "provider=google&state=app.other&code=c",
            "provider=google&state=app.server-random-state",
            "provider=google&state=app.server-random-state&code=c&code=d",
            "provider=google&state=app.server-random-state&code=bad%20code",
            "provider=google&state=app.server-random-state&code=c&error=access_denied",
        ] {
            assert_eq!(cabinet.oauth_finish(&link(bad)), Ok(None), "{bad}");
        }
        for other in [
            "akimovvpn://other/callback?provider=google&state=app.server-random-state&code=c",
            "https://akimov.bid/oauth/callback?provider=google&state=app.server-random-state&code=c",
        ] {
            assert_eq!(cabinet.oauth_finish(&Url::parse(other).unwrap()), Ok(None), "{other}");
        }
        assert!(
            cabinet.lock().unwrap().oauth.is_some(),
            "a foreign link must not end the sign-in"
        );
        let refused = link("provider=google&state=app.server-random-state&error=access_denied");
        assert!(cabinet.oauth_finish(&refused).is_err());
        assert!(cabinet.lock().unwrap().oauth.is_none(), "a refusal ends it");
        start();
        cabinet.oauth_cancel();
        assert_eq!(cabinet.oauth_finish(&link(ours)), Ok(None), "cancelled");
        start();
        assert!(
            cabinet.oauth_finish(&link(ours)).is_err(),
            "server unreachable here"
        );
        assert!(
            cabinet.lock().unwrap().oauth.is_none(),
            "the code is used once"
        );
        assert!(cabinet.oauth_start("github").is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn email_errors_map_machine_codes_to_english() {
        for (code, words) in [
            ("code_wait", "a minute"),
            ("code_invalid", "not right"),
            ("code_expired", "expired"),
            ("code_locked", "Too many attempts"),
            ("code_limit", "today"),
            ("signup_closed", "closed"),
            ("signup_expired", "expired"),
        ] {
            let error = api_error(400, &json!({"error":"Русский текст","code":code}));
            assert!(error.message.contains(words), "{code}: {}", error.message);
            assert!(!error.message.contains("Русский"));
        }
    }

    #[test]
    fn email_actions_validate_input_and_keep_the_ticket_private() {
        let dir = scratch("email");
        let cabinet = Cabinet::new(dir.clone());
        for (action, body) in [
            ("email-code", json!({"email":"not-an-email"})),
            ("email-verify", json!({"email":"a@b.test","code":"12345"})),
            ("email-verify", json!({"email":"a@b.test","code":"12a456"})),
            (
                "email-create",
                json!({"accept_terms":true,"accept_personal_data":false}),
            ),
            (
                "email-create",
                json!({"accept_terms":true,"accept_personal_data":true}),
            ),
            (
                "register",
                json!({"email":"a@b.test","password":"password1"}),
            ),
            ("reset", json!({"token":"t","password":"password1"})),
        ] {
            assert!(
                cabinet.auth(action, body.clone()).is_err(),
                "{action} {body}"
            );
        }
        let mut answer = json!({"status":"consent_required","ticket":"private-ticket"});
        assert_eq!(take_ticket(&mut answer).as_deref(), Some("private-ticket"));
        assert_eq!(answer, json!({"status":"consent_required"}));
        assert_eq!(
            take_ticket(&mut json!({"status":"consent_required","ticket":"bad ticket"})),
            None
        );
        // The server uses the ticket up on any attempt, so the app never retries with it.
        {
            let mut state = cabinet.lock().unwrap();
            state.ticket = "private-ticket".into();
            state.saved.base_url = "https://127.0.0.1:9/api/v1".into();
        }
        let both = json!({"accept_terms":true,"accept_personal_data":true});
        assert!(cabinet.auth("email-create", both).is_err());
        assert!(cabinet.lock().unwrap().ticket.is_empty());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn only_the_edge_refusal_counts_as_blocked() {
        assert!(edge_blocked(
            403,
            &json!({"error": "forbidden", "ip": "203.0.113.7"})
        ));
        // The cabinet's own refusals must never be retried through another route.
        assert!(!edge_blocked(403, &json!({"error": "Banned"})));
        assert!(!edge_blocked(403, &json!({"error": "forbidden"})));
        assert!(!edge_blocked(
            401,
            &json!({"error": "forbidden", "ip": "203.0.113.7"})
        ));
        assert!(!edge_blocked(403, &Value::Null));
    }

    #[test]
    fn origins_allow_only_https_without_credentials_or_paths() {
        assert_eq!(
            origin("https://cabinet.example.com/", true).unwrap(),
            "https://cabinet.example.com/api/v1"
        );
        assert_eq!(
            origin("https://api.example.com/api/v1/", true).unwrap(),
            "https://api.example.com/api/v1"
        );
        for bad in [
            "http://example.com",
            "https://user:secret@example.com",
            "https://@example.com",
            "https://example.com?x=1",
            "https://example.com/#fragment",
            "https://example.com/admin",
            "https://example.com/admin/../",
            "https://example.com\\@evil.test",
            "https://example.com/%2e%2e/",
        ] {
            assert!(origin(bad, true).is_err(), "{bad}");
        }
    }

    #[test]
    fn whitelist_excludes_admin_traversal_and_unimplemented_routes() {
        assert!(validate_request("GET", "/legal", None).is_ok());
        assert!(validate_request("POST", "/legal", None).is_err());
        assert!(validate_request("GET", "/me/transactions", None).is_ok());
        assert!(validate_request("GET", "/devices?sub_id=42", None).is_ok());
        assert!(validate_request("DELETE", "/devices/abcdefghij%3D?sub_id=42", None).is_ok());
        for bad in [
            "/admin/users",
            "/api/v1/me",
            "//evil.test/me",
            "/devices/../../admin/users",
            "/devices/%2e%2e",
            "/me?url=https://evil.test",
            "/devices?sub_id=1&sub_id=2",
            "/devices?sub_id=-1",
            "/devices?sub_id=1#fragment",
            "/app/config",
            "/checkout/quote",
            "/auth/login",
            "/subscription/1/../2",
        ] {
            assert!(validate_request("GET", bad, None).is_err(), "{bad}");
        }
        assert!(validate_request("POST", "/buy", Some(&json!({"tariff_id": 1}))).is_err());
        assert!(validate_request(
            "POST",
            "/buy",
            Some(&json!({"request_id":"fa438c74-c00f-493c-9e23-86748a899047","tariff_id":1}))
        )
        .is_ok());
        assert!(validate_request(
            "PATCH",
            "/devices/abcdefghij",
            Some(&json!({"name":"Laptop"}))
        )
        .is_ok());
    }

    #[test]
    fn auth_shapes_and_public_error_envelopes_are_checked() {
        assert!(parse_tokens(
            json!({"access_token":"a.b.c","refresh_token":"d.e.f","token_type":"bearer"})
        )
        .is_ok());
        assert!(parse_tokens(json!({"access_token":"a.b.c","refresh_token":"d.e.f"})).is_err());
        assert!(parse_tokens(
            json!({"access_token":"a\r\nb","refresh_token":"d","token_type":"bearer"})
        )
        .is_err());
        assert!(validate_me(&json!({"id":-2,"subscriptions":[],"balance":12300})).is_ok());
        assert_eq!(
            api_error(402, &json!({"error":"Недостаточно средств"})).message,
            "Insufficient balance."
        );
        assert_eq!(
            api_error(401, &Value::Null).message,
            "Please sign in again."
        );
        assert_eq!(
            api_error(503, &json!({"error":"database failed, internal exception"})).message,
            "Something went wrong. Try again later."
        );
    }

    #[test]
    fn public_auth_rejects_invalid_input_before_sending_any_request() {
        let cabinet = Cabinet::new(std::env::temp_dir().join("akimov-auth-validation-only"));
        assert!(cabinet
            .auth(
                "email-create",
                json!({"accept_terms":true,"accept_personal_data":false})
            )
            .unwrap_err()
            .contains("agreements"));
        assert!(cabinet
            .auth(
                "email-verify",
                json!({"email":"test@example.invalid","code":"12"})
            )
            .unwrap_err()
            .contains("six-digit"));
        assert!(cabinet
            .auth("email-code", json!({"email":"no address"}))
            .unwrap_err()
            .contains("valid email"));
        assert!(cabinet.auth("admin", Value::Null).is_err());
    }

    #[test]
    #[ignore = "Writes a temporary session to the login Keychain; requires an unlocked login keychain"]
    fn saved_sessions_restore_without_exposing_tokens_and_logout_removes_them() {
        let dir = std::env::temp_dir().join(format!(
            "moonlight-cabinet-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let cabinet = Cabinet::new(dir.clone());
        assert!(cabinet.require_session().is_err());
        cabinet
            .set_tokens(
                &mut cabinet.lock().unwrap(),
                Tokens {
                    access_token: "private-access-value".into(),
                    refresh_token: "private-refresh-value".into(),
                    token_type: "bearer".into(),
                },
            )
            .unwrap();
        let saved = fs::read_to_string(dir.join("cabinet.json")).unwrap();
        assert!(!saved.contains("private-access-value"));
        assert!(!saved.contains("private-refresh-value"));
        let restored = Cabinet::new(dir.clone());
        assert!(restored.require_session().is_ok());
        assert_eq!(restored.lock().unwrap().refresh, "private-refresh-value");
        assert!(restored.lock().unwrap().access.is_empty());
        restored.logout().unwrap();
        assert!(!fs::read_to_string(dir.join("cabinet.json"))
            .unwrap()
            .contains("protected_refresh"));
        assert!(Cabinet::new(dir.clone()).lock().unwrap().refresh.is_empty());
        let altered = Saved {
            base_url: "https://other.example/api/v1".into(),
            ..Saved::default()
        };
        fs::write(
            dir.join("cabinet.json"),
            serde_json::to_vec(&altered).unwrap(),
        )
        .unwrap();
        let locked = Cabinet::new(dir.clone());
        assert_eq!(
            locked.lock().unwrap().saved.base_url,
            Saved::default().base_url
        );
        // A file saved for another account service starts clean rather than failing.
        assert!(locked.lock().unwrap().load_error.is_none());
        assert!(locked.lock().unwrap().refresh.is_empty());
        fs::remove_file(dir.join("cabinet.json")).unwrap();
        fs::remove_dir(dir).unwrap();
    }
}
