//! SystemConfiguration changes are made only by the root-owned helper.
use core_foundation::{
    array::CFArray,
    base::{CFRelease, CFType, CFTypeRef, TCFType},
    data::CFData,
    dictionary::{CFDictionary, CFDictionaryRef},
    number::CFNumber,
    propertylist::{
        create_data, create_with_data, kCFPropertyListImmutable, kCFPropertyListXMLFormat_v1_0,
    },
    string::{CFString, CFStringRef},
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, io, path::Path};

type Dict = CFDictionary<CFString, CFType>;
type PrefsRef = *const std::ffi::c_void;
#[link(name = "SystemConfiguration", kind = "framework")]
extern "C" {
    fn SCPreferencesCreate(allocator: CFTypeRef, name: CFStringRef, id: CFStringRef) -> PrefsRef;
    fn SCPreferencesLock(prefs: PrefsRef, wait: u8) -> u8;
    fn SCPreferencesUnlock(prefs: PrefsRef) -> u8;
    fn SCPreferencesPathGetValue(prefs: PrefsRef, path: CFStringRef) -> CFDictionaryRef;
    fn SCPreferencesPathSetValue(prefs: PrefsRef, path: CFStringRef, value: CFDictionaryRef) -> u8;
    fn SCPreferencesPathRemoveValue(prefs: PrefsRef, path: CFStringRef) -> u8;
    fn SCPreferencesCommitChanges(prefs: PrefsRef) -> u8;
    fn SCPreferencesApplyChanges(prefs: PrefsRef) -> u8;
}
struct Prefs(PrefsRef);
impl Prefs {
    fn new() -> Result<Self, String> {
        let name = CFString::new("akimov vpn");
        let ptr = unsafe {
            SCPreferencesCreate(
                std::ptr::null(),
                name.as_concrete_TypeRef(),
                std::ptr::null(),
            )
        };
        if ptr.is_null() {
            return Err("macOS network preferences are unavailable.".into());
        }
        if unsafe { SCPreferencesLock(ptr, 0) } == 0 {
            unsafe {
                CFRelease(ptr);
            }
            return Err("macOS network preferences are busy. Try again.".into());
        }
        Ok(Self(ptr))
    }
    fn get(&self, path: &str) -> Option<Dict> {
        let path = CFString::new(path);
        let ptr = unsafe { SCPreferencesPathGetValue(self.0, path.as_concrete_TypeRef()) };
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { Dict::wrap_under_get_rule(ptr) })
        }
    }
    fn put(&self, path: &str, value: Option<&Dict>) -> Result<(), String> {
        let path = CFString::new(path);
        let ok = unsafe {
            match value {
                Some(dict) => SCPreferencesPathSetValue(
                    self.0,
                    path.as_concrete_TypeRef(),
                    dict.as_concrete_TypeRef(),
                ),
                None => SCPreferencesPathRemoveValue(self.0, path.as_concrete_TypeRef()),
            }
        };
        if ok == 0 {
            Err("Could not change macOS network preferences.".into())
        } else {
            Ok(())
        }
    }
    fn commit(&self) -> Result<(), String> {
        if unsafe {
            SCPreferencesCommitChanges(self.0) != 0 && SCPreferencesApplyChanges(self.0) != 0
        } {
            Ok(())
        } else {
            Err(
                "Could not apply macOS network preferences. Network recovery will be retried."
                    .into(),
            )
        }
    }
}
impl Drop for Prefs {
    fn drop(&mut self) {
        unsafe {
            SCPreferencesUnlock(self.0);
            CFRelease(self.0);
        }
    }
}
fn fields(dict: &Dict) -> BTreeMap<String, CFType> {
    let (keys, values) = dict.get_keys_and_values();
    keys.into_iter()
        .zip(values)
        .map(|(key, value)| unsafe {
            (
                CFString::wrap_under_get_rule(key.cast()).to_string(),
                CFType::wrap_under_get_rule(value),
            )
        })
        .collect()
}
fn dictionary(fields: BTreeMap<String, CFType>) -> Dict {
    Dict::from_CFType_pairs(
        &fields
            .into_iter()
            .map(|(key, value)| (CFString::new(&key), value))
            .collect::<Vec<_>>(),
    )
}
fn encode(dict: &Dict) -> Result<Vec<u8>, String> {
    create_data(dict.as_CFTypeRef(), kCFPropertyListXMLFormat_v1_0)
        .map(|data| data.bytes().to_vec())
        .map_err(|_| "Cannot save network preferences.".into())
}
fn decode(bytes: &[u8]) -> Result<Dict, String> {
    let (ptr, _) = create_with_data(CFData::from_buffer(bytes), kCFPropertyListImmutable)
        .map_err(|_| "Invalid network recovery record.")?;
    let value = unsafe { CFType::wrap_under_create_rule(ptr) };
    value
        .downcast::<CFDictionary>()
        .map(|dict| unsafe { Dict::wrap_under_get_rule(dict.as_concrete_TypeRef()) })
        .ok_or_else(|| "Invalid network recovery dictionary.".into())
}

#[derive(Serialize, Deserialize)]
pub struct Backup {
    changes: Vec<Change>,
}
#[derive(Serialize, Deserialize)]
struct Change {
    path: String,
    before: Option<Vec<u8>>,
    installed: Vec<u8>,
}

fn restore_fields(current: &Dict, before: Option<&Dict>, installed: &Dict) -> Dict {
    let mut current = fields(current);
    let before = before.map(fields).unwrap_or_default();
    let installed = fields(installed);
    let foreign: Vec<_> = ["HTTP", "HTTPS", "SOCKS"]
        .into_iter()
        .filter(|prefix| {
            ["Enable", "Proxy", "Port"].into_iter().any(|suffix| {
                let key = format!("{prefix}{suffix}");
                installed.contains_key(&key) && current.get(&key) != installed.get(&key)
            })
        })
        .collect();
    for (key, value) in installed {
        if foreign.iter().any(|prefix| {
            ["Enable", "Proxy", "Port"]
                .iter()
                .any(|suffix| key == format!("{prefix}{suffix}"))
        }) {
            continue;
        }
        // Restore each field only while we still own it; preserve another app's edits.
        if before.get(&key) != Some(&value) && current.get(&key) == Some(&value) {
            match before.get(&key) {
                Some(value) => {
                    current.insert(key, value.clone());
                }
                None => {
                    current.remove(&key);
                }
            }
        }
    }
    dictionary(current)
}

pub fn apply_root(port: Option<u16>, recovery: &Path) -> Result<Backup, String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("Network changes require the protected helper.".into());
    }
    if recovery.exists() {
        return Err("Previous network settings need recovery. Restart the app.".into());
    }
    let prefs = Prefs::new()?;
    let services = prefs
        .get("/NetworkServices")
        .ok_or("No macOS network services were found.")?;
    let mut backup = Backup {
        changes: Vec::new(),
    };
    for id in fields(&services).keys() {
        if id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err("Invalid network service identifier.".into());
        }
        let path = format!(
            "/NetworkServices/{id}/{}",
            if port.is_some() { "Proxies" } else { "DNS" }
        );
        let before = prefs.get(&path);
        let mut values = before.as_ref().map(fields).unwrap_or_default();
        if let Some(port) = port {
            for prefix in ["HTTP", "HTTPS", "SOCKS"] {
                values.insert(format!("{prefix}Enable"), CFNumber::from(1i32).as_CFType());
                values.insert(
                    format!("{prefix}Proxy"),
                    CFString::new("127.0.0.1").as_CFType(),
                );
                values.insert(
                    format!("{prefix}Port"),
                    CFNumber::from(i32::from(port)).as_CFType(),
                );
            }
            for key in ["ProxyAutoConfigEnable", "ProxyAutoDiscoveryEnable"] {
                values.insert(key.into(), CFNumber::from(0i32).as_CFType());
            }
        } else {
            let servers =
                CFArray::from_CFTypes(&[CFString::new("1.1.1.1"), CFString::new("8.8.8.8")]);
            values.insert("ServerAddresses".into(), servers.as_CFType());
        }
        backup.changes.push(Change {
            path,
            before: before.as_ref().map(encode).transpose()?,
            installed: encode(&dictionary(values))?,
        });
    }
    // Write and fsync the recovery record before any persistent preference changes.
    let bytes = serde_json::to_vec(&backup).map_err(|e| e.to_string())?;
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(recovery)
        .map_err(|e| e.to_string())?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())?;
    let result = (|| {
        for change in &backup.changes {
            prefs.put(&change.path, Some(&decode(&change.installed)?))?;
        }
        prefs.commit()
    })();
    drop(prefs);
    if let Err(error) = result {
        let _ = restore_root(&backup, recovery);
        return Err(error);
    }
    Ok(backup)
}
pub fn restore_root(backup: &Backup, recovery: &Path) -> Result<(), String> {
    let prefs = Prefs::new()?;
    for change in &backup.changes {
        if !change.path.starts_with("/NetworkServices/") {
            return Err("Invalid network recovery path.".into());
        }
        let Some(current) = prefs.get(&change.path) else {
            continue;
        };
        let before = change.before.as_deref().map(decode).transpose()?;
        let installed = decode(&change.installed)?;
        let restored = restore_fields(&current, before.as_ref(), &installed);
        if restored.is_empty() && before.is_none() {
            prefs.put(&change.path, None)?;
        } else {
            prefs.put(&change.path, Some(&restored))?;
        }
    }
    prefs.commit()?;
    match std::fs::remove_file(recovery) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result.map_err(|e| e.to_string()),
    }
}
pub fn recover_root(path: &Path) -> Result<(), String> {
    match std::fs::read(path) {
        Ok(bytes) => restore_root(
            &serde_json::from_slice(&bytes).map_err(|_| "Invalid network recovery record.")?,
            path,
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

pub struct Saved(crate::service::Session);
pub fn ours(port: u16) -> String {
    format!("127.0.0.1:{port}")
}
pub fn set(port: u16, _: &Path) -> io::Result<Saved> {
    crate::service::proxy(port)
        .map(Saved)
        .map_err(io::Error::other)
}
pub fn restore(saved: &Saved, _: &Path) -> io::Result<()> {
    saved.0.stop().map_err(io::Error::other)
}
pub fn recover(_: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recovery_preserves_other_apps_changes_and_restores_absent_fields() {
        let before = dictionary(BTreeMap::from([(
            "HTTPEnable".into(),
            CFNumber::from(0i32).as_CFType(),
        )]));
        let installed = dictionary(BTreeMap::from([
            ("HTTPEnable".into(), CFNumber::from(1i32).as_CFType()),
            ("HTTPPort".into(), CFNumber::from(1234i32).as_CFType()),
        ]));
        let round_trip = decode(&encode(&installed).unwrap()).unwrap();
        assert_eq!(fields(&round_trip), fields(&installed));
        assert_eq!(
            fields(&restore_fields(&installed, Some(&before), &installed)),
            fields(&before)
        );
        let mut changed = fields(&installed);
        changed.insert("HTTPPort".into(), CFNumber::from(9999i32).as_CFType());
        let restored = fields(&restore_fields(
            &dictionary(changed),
            Some(&before),
            &installed,
        ));
        assert_eq!(restored["HTTPPort"], CFNumber::from(9999i32).as_CFType());
        assert_eq!(restored["HTTPEnable"], CFNumber::from(1i32).as_CFType());
        assert!(restore_fields(&installed, None, &installed).is_empty());
    }
}
