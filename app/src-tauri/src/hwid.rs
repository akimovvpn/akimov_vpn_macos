use sha2::{Digest, Sha256};

pub const UNAVAILABLE: &str = "Device identification is unavailable. Restart macOS and try again.";

pub fn valid(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn fingerprint(output: &str) -> Option<String> {
    let uuid = output.lines().find_map(|line| {
        let (key, value) = line.trim().split_once(" = ")?;
        (key == "\"IOPlatformUUID\"").then(|| value.trim_matches('"'))
    })?;
    if uuid.len() != 36
        || !uuid.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
    {
        return None;
    }
    let normalized = uuid.replace('-', "").to_ascii_lowercase();
    if normalized.bytes().all(|b| b == b'0') || normalized.bytes().all(|b| b == b'f') {
        return None;
    }
    let mut hash = Sha256::new();
    hash.update(b"akimov-vpn/hwid/macos/v1\0");
    hash.update(normalized.as_bytes());
    Some(format!("{:x}", hash.finalize()))
}

pub fn read() -> Result<String, String> {
    let output = std::process::Command::new("/usr/sbin/ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .map_err(|_| UNAVAILABLE)?;
    if !output.status.success() {
        return Err(UNAVAILABLE.into());
    }
    fingerprint(&String::from_utf8_lossy(&output.stdout)).ok_or_else(|| UNAVAILABLE.into())
}

pub fn os_version() -> String {
    std::process::Command::new("/usr/bin/sw_vers")
        .arg("-productVersion")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "macOS".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hardware_uuid_is_validated_and_hashed() {
        let fixture = "  \"IOPlatformUUID\" = \"12345678-1234-1234-1234-123456789ABC\"";
        let id = fingerprint(fixture).unwrap();
        assert!(valid(&id));
        assert_eq!(
            fingerprint(
                fixture
                    .to_lowercase()
                    .replace("ioplatformuuid", "IOPlatformUUID")
                    .as_str()
            ),
            Some(id)
        );
        for bad in [
            "",
            "\"IOPlatformUUID\" = \"00000000-0000-0000-0000-000000000000\"",
            "\"IOPlatformUUID\" = \"ffffffff-ffff-ffff-ffff-ffffffffffff\"",
            "\"IOPlatformUUID\" = \"../../not-a-uuid\"",
        ] {
            assert!(fingerprint(bad).is_none());
        }
    }
    #[test]
    fn real_hardware_identity_is_stable_without_printing_it() {
        let id = read().unwrap();
        assert!(valid(&id));
        assert_eq!(read().unwrap(), id);
    }
}
