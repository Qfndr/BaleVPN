//! Provider-separated headless configuration. No login, I/O or automatic dialing.
use igap_signaling::auth::{canonical_id, Profile, RegistrationProfile, SessionRecord};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fmt};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderId {
    Bale,
    Igap,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Client,
    Server,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    InvalidFormat,
    WrongProvider,
    InvalidPeer,
    InvalidPort,
    InvalidTrust,
    NotReady,
    InvalidSession,
}
impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidFormat => "invalid_provider_format",
            Self::WrongProvider => "wrong_provider",
            Self::InvalidPeer => "invalid_provider_peer",
            Self::InvalidPort => "invalid_provider_port",
            Self::InvalidTrust => "invalid_provider_trust",
            Self::NotReady => "provider_not_configured",
            Self::InvalidSession => "invalid_provider_session",
        })
    }
}
impl std::error::Error for ConfigError {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", try_from = "RawConfig")]
pub struct NativeProviderConfig {
    pub format: u8,
    pub provider: ProviderId,
    pub mode: Option<Role>,
    pub peer_id: Option<String>,
    pub socks5_port: u16,
    pub trusted_certificates: Vec<String>,
    pub throughput: bool,
}
pub type Config = NativeProviderConfig;

fn default_port() -> u16 {
    18080
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawConfig {
    format: u8,
    provider: ProviderId,
    #[serde(default)]
    mode: Option<Role>,
    #[serde(default)]
    peer_id: Option<String>,
    #[serde(default = "default_port")]
    socks5_port: u16,
    #[serde(default)]
    trusted_certificates: Vec<String>,
    #[serde(default)]
    throughput: bool,
}
impl Default for NativeProviderConfig {
    fn default() -> Self {
        Self {
            format: 1,
            provider: ProviderId::Igap,
            mode: None,
            peer_id: None,
            socks5_port: default_port(),
            trusted_certificates: vec![],
            throughput: false,
        }
    }
}
impl TryFrom<RawConfig> for NativeProviderConfig {
    type Error = ConfigError;
    fn try_from(raw: RawConfig) -> Result<Self, Self::Error> {
        let result = Self {
            format: raw.format,
            provider: raw.provider,
            mode: raw.mode,
            peer_id: raw.peer_id,
            socks5_port: raw.socks5_port,
            trusted_certificates: raw.trusted_certificates,
            throughput: raw.throughput,
        };
        result.validate()?;
        Ok(result)
    }
}
impl NativeProviderConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.format != 1 {
            return Err(ConfigError::InvalidFormat);
        }
        if self.provider != ProviderId::Igap {
            return Err(ConfigError::WrongProvider);
        }
        if self
            .peer_id
            .as_ref()
            .is_some_and(|id| canonical_id(id).is_none())
        {
            return Err(ConfigError::InvalidPeer);
        }
        if self.socks5_port < 1024 {
            return Err(ConfigError::InvalidPort);
        }
        self.trusted_der()?;
        Ok(())
    }
    /// The counterpart is also mandatory in server mode: this foundation only
    /// admits one explicitly pinned peer, never every incoming caller.
    pub fn validate_ready(&self) -> Result<(), ConfigError> {
        self.validate()?;
        if self.mode.is_none() || self.peer_id.is_none() || self.trusted_certificates.is_empty() {
            return Err(ConfigError::NotReady);
        }
        Ok(())
    }
    /// Decode bounded public certificate bytes. The runtime must additionally
    /// validate DER/trust anchors using Identity::options before connection.
    pub fn trusted_der(&self) -> Result<Vec<Vec<u8>>, ConfigError> {
        if self.trusted_certificates.len() > 8 {
            return Err(ConfigError::InvalidTrust);
        }
        let mut seen = HashSet::new();
        self.trusted_certificates
            .iter()
            .map(|value| {
                if value.len() < 128
                    || value.len() > 16384
                    || value.len() % 2 != 0
                    || !value
                        .bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                    || !seen.insert(value.as_str())
                {
                    return Err(ConfigError::InvalidTrust);
                }
                value
                    .as_bytes()
                    .chunks_exact(2)
                    .map(|pair| {
                        let digit = |c| if c <= b'9' { c - b'0' } else { c - b'a' + 10 };
                        Ok(digit(pair[0]) * 16 + digit(pair[1]))
                    })
                    .collect()
            })
            .collect()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(try_from = "RawEnvelope")]
pub struct IgapSessionEnvelope {
    pub format: u8,
    pub provider: ProviderId,
    pub record: SessionRecord,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEnvelope {
    format: u8,
    provider: ProviderId,
    record: RawRecord,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawRecord {
    provider: String,
    user_id: String,
    token: String,
    profile: RawProfile,
    #[serde(default)]
    login_phone: String,
    #[serde(default)]
    needs_profile: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawProfile {
    #[serde(default)]
    registration_profile: Option<RegistrationProfile>,
    app_id: u32,
    app_build: u32,
    app_version: String,
    app_name: String,
    platform: u32,
    platform_version: String,
    device: u32,
    device_name: String,
    language: u32,
}
impl TryFrom<RawEnvelope> for IgapSessionEnvelope {
    type Error = ConfigError;
    fn try_from(raw: RawEnvelope) -> Result<Self, Self::Error> {
        let p = raw.record.profile;
        let record = SessionRecord {
            provider: raw.record.provider,
            user_id: raw.record.user_id,
            token: raw.record.token,
            login_phone: raw.record.login_phone,
            needs_profile: raw.record.needs_profile,
            profile: Profile {
                registration_profile: p.registration_profile,
                app_id: p.app_id,
                app_build: p.app_build,
                app_version: p.app_version,
                app_name: p.app_name,
                platform: p.platform,
                platform_version: p.platform_version,
                device: p.device,
                device_name: p.device_name,
                language: p.language,
            },
        };
        let result = Self {
            format: raw.format,
            provider: raw.provider,
            record,
        };
        result.validate()?;
        Ok(result)
    }
}
impl IgapSessionEnvelope {
    pub fn new(record: SessionRecord) -> Result<Self, ConfigError> {
        let result = Self {
            format: 1,
            provider: ProviderId::Igap,
            record,
        };
        result.validate()?;
        Ok(result)
    }
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.format != 1 {
            return Err(ConfigError::InvalidFormat);
        }
        if self.provider != ProviderId::Igap {
            return Err(ConfigError::WrongProvider);
        }
        self.record
            .validate()
            .map_err(|_| ConfigError::InvalidSession)
    }
    pub fn into_record(self) -> SessionRecord {
        self.record
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record() -> SessionRecord {
        SessionRecord {
            provider: "igap".into(),
            user_id: "41".into(),
            token: "fixture-private-token".into(),
            login_phone: String::new(),
            needs_profile: false,
            profile: Profile {
                registration_profile: None,
                app_id: 67291,
                app_build: 1,
                app_version: "0.1.0".into(),
                app_name: "Desktop".into(),
                platform: 4,
                platform_version: "win32".into(),
                device: 1,
                device_name: "fixture-device".into(),
                language: 1,
            },
        }
    }
    #[test]
    fn unconfigured_default_is_valid_but_cannot_connect() {
        let config = Config::default();
        assert_eq!(config.validate(), Ok(()));
        assert_eq!(config.validate_ready(), Err(ConfigError::NotReady));
        assert!(!config.throughput);
        assert_eq!(config.socks5_port, 18080);
        let copy: Config = serde_json::from_value(serde_json::to_value(config).unwrap()).unwrap();
        assert!(copy.mode.is_none() && copy.peer_id.is_none());
    }
    #[test]
    fn only_explicit_provider_format_and_known_fields_are_accepted() {
        for value in [
            serde_json::json!({}),
            serde_json::json!({"format":1,"provider":"bale"}),
            serde_json::json!({"format":2,"provider":"igap"}),
            serde_json::json!({"format":1,"provider":"rubika"}),
            serde_json::json!({"format":1,"provider":"igap","token":"bale-token"}),
        ] {
            assert!(serde_json::from_value::<Config>(value).is_err());
        }
    }
    #[test]
    fn peer_and_port_boundaries_are_validated_for_both_roles() {
        for role in [Role::Client, Role::Server] {
            let mut config = Config {
                mode: Some(role),
                peer_id: Some("18446744073709551615".into()),
                trusted_certificates: vec!["ab".repeat(64)],
                ..Config::default()
            };
            assert!(config.validate_ready().is_ok());
            for bad in ["", "0", "01", "+1", " 1", "18446744073709551616"] {
                config.peer_id = Some(bad.into());
                assert_eq!(config.validate(), Err(ConfigError::InvalidPeer));
            }
            config.peer_id = Some("42".into());
            for port in [0, 1, 1023] {
                config.socks5_port = port;
                assert_eq!(config.validate(), Err(ConfigError::InvalidPort));
            }
            for port in [1024, 65535] {
                config.socks5_port = port;
                assert!(config.validate_ready().is_ok());
            }
        }
    }
    #[test]
    fn public_trust_is_bounded_distinct_hex_and_decoded_exactly() {
        let mut config = Config {
            trusted_certificates: vec!["ab".repeat(64)],
            ..Config::default()
        };
        assert_eq!(config.trusted_der().unwrap(), vec![vec![0xab; 64]]);
        for bad in [
            vec!["".into()],
            vec!["AB".repeat(64)],
            vec!["gg".repeat(64)],
            vec!["a".repeat(129)],
            vec!["aa".repeat(8193)],
            vec!["aa".repeat(64); 2],
            vec!["aa".repeat(64); 9],
        ] {
            config.trusted_certificates = bad;
            assert_eq!(config.validate(), Err(ConfigError::InvalidTrust));
        }
    }
    #[test]
    fn session_roundtrip_preserves_absent_legacy_registration_profile() {
        let envelope = IgapSessionEnvelope::new(record()).unwrap();
        let encoded = serde_json::to_value(&envelope).unwrap();
        assert!(encoded["record"]["profile"]
            .get("registrationProfile")
            .is_none());
        let decoded: IgapSessionEnvelope = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded.record.profile.registration_profile, None);
        assert_eq!(decoded.into_record().token, "fixture-private-token");
        assert!(!format!("{envelope:?}").contains("fixture-private"));
    }
    #[test]
    fn session_rejects_cross_provider_and_unknown_nested_fields() {
        let base = serde_json::to_value(IgapSessionEnvelope::new(record()).unwrap()).unwrap();
        let mut variants = vec![];
        let mut value = base.clone();
        value["provider"] = "bale".into();
        variants.push(value);
        let mut value = base.clone();
        value["record"]["provider"] = "bale".into();
        variants.push(value);
        let mut value = base.clone();
        value["record"]["unknown"] = true.into();
        variants.push(value);
        let mut value = base.clone();
        value["record"]["profile"]["unknown"] = true.into();
        variants.push(value);
        let mut value = base.clone();
        value["record"]["profile"]["registrationProfile"] = "web-v3-compat".into();
        variants.push(value);
        let mut value = base.clone();
        value["record"]["token"] = "".into();
        variants.push(value);
        variants.push(serde_json::json!({"token":"bale-access-cookie"}));
        for value in variants {
            assert!(serde_json::from_value::<IgapSessionEnvelope>(value).is_err());
        }
    }
}
