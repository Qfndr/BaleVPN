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
    #[serde(default, skip_serializing_if="Option::is_none")]
    pub login_phone: Option<String>,
    #[serde(default, skip_serializing_if="Option::is_none")]
    pub login_token_hash: Option<String>,
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
            || self.login_phone.as_ref().is_some_and(|p|p.len()<8||p.len()>16||!p.starts_with('+')||!p[1..].bytes().all(|b|b.is_ascii_digit()))
            || self.login_token_hash.as_ref().is_some_and(|h|h.len()!=64||!h.bytes().all(|b|b.is_ascii_hexdigit()))
            || self.login_phone.is_some()!=self.login_token_hash.is_some()
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
    let model_index=u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize % 512;
    let label=include_str!("../assets/device-models.tsv").lines().nth(model_index)
        .and_then(|line|line.split('\t').next()).ok_or_else(||io::Error::other("Invalid device catalog"))?;
    let value = DeviceIdentity {
        used,
        login_phone: None,
        login_token_hash: None,
        hash: format!(
            "{}-{}-{}-{}-{}",
            &hex[..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..]
        ),
        label: label.to_owned(),
    };
    vault.write("device.bin", &serde_json::to_vec(&value)?)?;
    Ok(value)
}
pub fn model_details(label:&str)->Option<(&'static str,&'static str,&'static str)> {
    include_str!("../assets/device-models.tsv").lines().find_map(|line|{
        let mut fields=line.split('\t');
        if fields.next()?!=label{return None;}
        Some((fields.next()?,fields.next()?,fields.next()?))
    })
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
pub fn mark_authenticated(directory: &Path, phone: Option<String>, token: &[u8]) -> io::Result<()> {
    let mut value=identity(directory)?;
    value.used=true;
    value.login_phone=phone;
    value.login_token_hash=value.login_phone.as_ref().map(|_|crate::settings::hex(ring::digest::digest(&ring::digest::SHA256,token).as_ref()));
    value.validate()?;
    Vault::new(directory).write("device.bin", &serde_json::to_vec(&value)?)
}
pub fn phone_for_session(value: &DeviceIdentity, token: &[u8]) -> Option<String> {
    let hash=crate::settings::hex(ring::digest::digest(&ring::digest::SHA256,token).as_ref());
    if value.login_token_hash.as_deref()==Some(hash.as_str()){value.login_phone.clone()}else{None}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn login_phone_is_encrypted_and_bound_to_the_original_session() {
        let dir=tempfile::tempdir().unwrap();
        mark_authenticated(dir.path(),Some("+10000000001".into()),b"fixture-session").unwrap();
        let saved=identity(dir.path()).unwrap();
        assert_eq!(phone_for_session(&saved,b"fixture-session").as_deref(),Some("+10000000001"));
        assert!(phone_for_session(&saved,b"different-session").is_none());
        assert!(!std::fs::read(dir.path().join("device.bin")).unwrap().windows(12).any(|b|b==b"+10000000001"));
        let next=prepare_login(dir.path()).unwrap();assert!(next.login_phone.is_none());
        // Old device records without metadata remain readable.
        let mut old=serde_json::to_value(&saved).unwrap();old.as_object_mut().unwrap().remove("login_phone");old.as_object_mut().unwrap().remove("login_token_hash");
        let old:DeviceIdentity=serde_json::from_value(old).unwrap();old.validate().unwrap();assert!(old.login_phone.is_none());
    }
    #[test]
    fn devices_are_independent_and_survive_restart() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let first = identity(a.path()).unwrap();
        assert_eq!(first.hash, identity(a.path()).unwrap().hash);
        assert_eq!(first.label, identity(a.path()).unwrap().label);
        assert_ne!(first.hash, identity(b.path()).unwrap().hash);
        first.validate().unwrap();
        assert!(model_details(&first.label).is_some());
        let models:Vec<_>=include_str!("../assets/device-models.tsv").lines().collect();
        assert_eq!(models.len(),512);
        assert_eq!(models.iter().collect::<std::collections::HashSet<_>>().len(),512);
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
