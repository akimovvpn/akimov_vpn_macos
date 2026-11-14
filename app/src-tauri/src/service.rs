//! Installed whole-device broker. Its IPC accepts data and fixed operations, never privileged paths.
use serde_json::Value;

const PROTOCOL: u32 = 2;
mod macos;
pub use macos::{api, clear_cache, early_main, proxy, start, Session};
const MAX_MESSAGE: usize = 4 * 1024 * 1024;

fn allowed_api(method: &str, path: &str, body: &Option<Value>) -> bool {
    fn segment(value: &str, proxy_name: bool) -> bool {
        if value.is_empty()
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.~%".contains(&b))
        {
            return false;
        }
        let mut decoded = Vec::new();
        let mut bytes = value.bytes();
        while let Some(byte) = bytes.next() {
            if byte == b'%' {
                let Some(high) = bytes.next().and_then(|b| (b as char).to_digit(16)) else {
                    return false;
                };
                let Some(low) = bytes.next().and_then(|b| (b as char).to_digit(16)) else {
                    return false;
                };
                decoded.push((high * 16 + low) as u8);
            } else {
                decoded.push(byte);
            }
        }
        decoded != b"."
            && decoded != b".."
            && !decoded
                .iter()
                .any(|b| b.is_ascii_control() || *b == b'\\' || (!proxy_name && *b == b'/'))
    }
    if method == "GET" && body.is_none() {
        if ["/version", "/proxies", "/connections", "/traffic"].contains(&path) {
            return true;
        }
        if let Some((node, query)) = path
            .strip_prefix("/proxies/")
            .and_then(|p| p.split_once("/delay?"))
        {
            let fields: Vec<_> = url::form_urlencoded::parse(query.as_bytes()).collect();
            return segment(node, true)
                && query.len() <= 4096
                && fields.len() == 3
                && fields.iter().filter(|(key, _)| key == "url").count() == 1
                && fields.iter().any(|(key, value)| {
                    key == "url"
                        && url::Url::parse(value).is_ok_and(|url| {
                            ["http", "https"].contains(&url.scheme())
                                && url.host_str().is_some()
                                && url.username().is_empty()
                                && url.password().is_none()
                        })
                })
                && fields
                    .iter()
                    .any(|(key, value)| key == "timeout" && value == "2000")
                && fields
                    .iter()
                    .any(|(key, value)| key == "expected" && value == "204");
        }
    }
    if method == "DELETE" && body.is_none() {
        return path
            .strip_prefix("/connections/")
            .is_some_and(|name| segment(name, false));
    }
    if method == "PATCH" && path == "/configs" {
        return body.as_ref() == Some(&serde_json::json!({"tun":{"enable":false}}));
    }
    let Some(object) = body
        .as_ref()
        .and_then(Value::as_object)
        .filter(|o| o.len() == 1)
    else {
        return false;
    };
    if method == "PUT" && path == "/configs?force=false" {
        return object
            .get("payload")
            .and_then(Value::as_str)
            .is_some_and(|s| s.len() < MAX_MESSAGE);
    }
    method == "PUT"
        && path
            .strip_prefix("/proxies/")
            .is_some_and(|name| segment(name, true))
        && object
            .get("name")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty() && s.len() <= 4096)
}

fn mixed_port(yaml: &str) -> Result<u16, String> {
    let config: serde_yaml::Value =
        serde_yaml::from_str(yaml).map_err(|_| "Invalid VPN configuration.")?;
    config["mixed-port"]
        .as_u64()
        .and_then(|p| u16::try_from(p).ok())
        .filter(|p| *p > 0)
        .ok_or_else(|| "Invalid VPN proxy port.".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn broker_allows_only_the_operations_used_by_the_app() {
        assert!(allowed_api("GET", "/version", &None));
        assert!(allowed_api("GET", "/proxies", &None));
        assert!(allowed_api("GET", "/connections", &None));
        assert!(allowed_api("GET", "/traffic", &None));
        assert!(allowed_api(
            "GET",
            "/proxies/Node%201/delay?url=https%3A%2F%2Fexample.com&timeout=2000&expected=204",
            &None
        ));
        assert!(allowed_api(
            "PUT",
            "/proxies/Node%201",
            &Some(json!({"name":"A"}))
        ));
        assert!(allowed_api("DELETE", "/connections/connection-id", &None));
        assert!(allowed_api(
            "PATCH",
            "/configs",
            &Some(json!({"tun":{"enable":false}}))
        ));
        assert!(allowed_api(
            "PUT",
            "/configs?force=false",
            &Some(json!({"payload":"proxies: []"}))
        ));
        for path in [
            "/upgrade",
            "/restart",
            "/configs/geo",
            "//upgrade",
            "/connections",
            "/proxies/../configs",
            "/proxies/x?z=/upgrade",
        ] {
            assert!(!allowed_api("POST", path, &None), "{path}");
        }
        assert!(!allowed_api(
            "PUT",
            "/configs?force=false",
            &Some(json!({"path":"C:\\evil.yaml"}))
        ));
        assert!(!allowed_api(
            "PATCH",
            "/configs",
            &Some(json!({"tun":{"enable":false},"allow-lan":true}))
        ));
        assert!(!allowed_api(
            "PUT",
            "/proxies/A",
            &Some(json!({"name":"B","extra":"x"}))
        ));
        assert!(!allowed_api("GET", "/version", &Some(json!({}))));
        for node in [
            "Germany%20%231",
            "Name%3F",
            "100%25",
            "%252e",
            "Auto%20WiFi%2FLTE%20%231%3F100%25",
        ] {
            assert!(
                allowed_api(
                    "PUT",
                    &format!("/proxies/{node}"),
                    &Some(json!({"name":"B"}))
                ),
                "{node}"
            );
        }
        for node in [".", "..", "%2e", "%2e%2e", "%2F", "%5C", "%", "%0a"] {
            assert!(
                !allowed_api("DELETE", &format!("/connections/{node}"), &None),
                "{node}"
            );
            if node != "%2F" {
                assert!(
                    !allowed_api(
                        "PUT",
                        &format!("/proxies/{node}"),
                        &Some(json!({"name":"B"}))
                    ),
                    "{node}"
                );
            }
        }
        assert!(!allowed_api(
            "GET",
            "/proxies/A/delay?url=file%3A%2F%2FC%3A%2Fsecret&timeout=2000&expected=204",
            &None
        ));
        assert!(!allowed_api(
            "GET",
            "/proxies/A/delay?url=https%3A%2F%2Fexample.com&timeout=2000&expected=204&extra=x",
            &None
        ));
    }

    #[test]
    fn broker_rejects_invalid_proxy_ports_before_start_or_reload() {
        assert_eq!(mixed_port("mixed-port: 12345").unwrap(), 12345);
        for yaml in [
            "mixed-port: 0",
            "mixed-port: 65536",
            "mixed-port: -1",
            "mixed-port: '12345'",
            "mixed-port: []",
            "port: 12345",
        ] {
            assert!(mixed_port(yaml).is_err(), "{yaml}");
        }
    }
}
