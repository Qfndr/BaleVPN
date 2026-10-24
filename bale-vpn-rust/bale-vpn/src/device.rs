//! Per-installation account identity, preserved by encrypted session transfer.
use crate::vault::Vault;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::{io, path::Path};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceIdentity {
    pub hash: String,
    pub label: String,
    #[serde(default)]
    pub used: bool,
}
impl DeviceIdentity {
    pub fn validate(&self) -> io::Result<()> {
        if self.hash.len() != 36
            || !self.hash.bytes().enumerate().all(|(i, c)| {
                if [8, 13, 18, 23].contains(&i) {
                    c == b'-'
                } else {
                    c.is_ascii_hexdigit()
                }
            })
            || self.label.is_empty()
            || self.label.len() > 64
            || self.label.chars().any(char::is_control)
        {
            return Err(io::Error::other("Invalid account device identity"));
        }
        Ok(())
    }
}
pub fn identity(directory: &Path) -> io::Result<DeviceIdentity> {
    let vault = Vault::new(directory);
    if let Some(bytes) = vault.read("device.bin")? {
        let value: DeviceIdentity = serde_json::from_slice(&bytes)?;
        value.validate()?;
        return Ok(value);
    }
    generate(directory, directory.join("token.bin").is_file())
}
fn generate(directory: &Path, used: bool) -> io::Result<DeviceIdentity> {
    let vault = Vault::new(directory);
    let mut bytes = [0u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| io::Error::other("Invalid or unavailable account data"))?;
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let words = [
        "Cedar", "Pearl", "Maple", "River", "Amber", "Cloud", "Olive", "Silver",
    ];
    let value = DeviceIdentity {
        used,
        hash: format!(
            "{}-{}-{}-{}-{}",
            &hex[..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..]
        ),
        label: format!(
            "{}-{}-{}",
            words[(bytes[0] & 7) as usize],
            words[(bytes[1] & 7) as usize],
            &hex[16..28]
        ),
    };
    vault.write("device.bin", &serde_json::to_vec(&value)?)?;
    Ok(value)
}
pub fn prepare_login(directory: &Path) -> io::Result<DeviceIdentity> {
    let value = identity(directory)?;
    if value.used {
        generate(directory, false)
    } else {
        Ok(value)
    }
}
pub fn mark_used(directory: &Path) -> io::Result<()> {
    let mut value = identity(directory)?;
    value.used = true;
    Vault::new(directory).write("device.bin", &serde_json::to_vec(&value)?)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn devices_are_independent_and_survive_restart() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let first = identity(a.path()).unwrap();
        assert_eq!(first.hash, identity(a.path()).unwrap().hash);
        assert_eq!(first.label, identity(a.path()).unwrap().label);
        assert_ne!(first.hash, identity(b.path()).unwrap().hash);
        first.validate().unwrap();
        mark_used(a.path()).unwrap();
        let next = prepare_login(a.path()).unwrap();
        assert_ne!(next.hash, first.hash);
        assert_eq!(
            next.hash,
            prepare_login(a.path()).unwrap().hash,
            "OTP retries keep one device identity"
        );
    }
}
