use crate::vault::Vault;
use lktunnel::security::{Identity, TunnelOptions};
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Preferences {
    pub auto_reconnect: bool,
    pub secure_mode: bool,
    pub server_code: String,
    pub client_codes: Vec<String>,
    pub profile: String,
    pub retry_delay_secs: u64,
    pub max_calls_per_minute: usize,
}
impl Default for Preferences {
    fn default() -> Self {
        Self {
            auto_reconnect: false,
            secure_mode: true,
            server_code: String::new(),
            client_codes: vec![],
            profile: "balanced".into(),
            retry_delay_secs: 10,
            max_calls_per_minute: 3,
        }
    }
}
pub fn code(bytes: &[u8]) -> String {
    format!("bvp1:{}", hex(bytes))
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn decode(code: &str) -> Result<Vec<u8>, String> {
    let compact: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    let value = compact
        .strip_prefix("bvp1:")
        .ok_or("Public pairing code must begin with bvp1:")?;
    if !value.is_ascii() || value.len() < 128 || value.len() > 8192 || value.len() % 2 != 0 {
        return Err("Invalid public pairing code length".into());
    }
    (0..value.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&value[i..i + 2], 16)
                .map_err(|_| "Invalid public pairing code".into())
        })
        .collect()
}
impl Preferences {
    /// Accept wrapped clipboard codes and multiple codes in one paste without
    /// treating visual line wraps as new identities. Keep only distinct pins.
    pub fn normalize_codes(&mut self) -> Result<(), String> {
        let compact: String = self.client_codes.join("").chars().filter(|c| !c.is_whitespace()).collect();
        if !compact.is_empty() && !compact.starts_with("bvp1:") {
            return Err("Public pairing code must begin with bvp1:".into());
        }
        let mut codes = Vec::new();
        for part in compact.split("bvp1:").skip(1) {
            let normalized = code(&decode(&format!("bvp1:{part}"))?);
            if !codes.contains(&normalized) { codes.push(normalized); }
            if codes.len() > 64 { return Err("At most 64 trusted client codes are supported".into()); }
        }
        self.client_codes = codes;
        if !self.server_code.trim().is_empty() { self.server_code=code(&decode(&self.server_code)?); }
        Ok(())
    }
    pub fn validate(&self, identity: &Identity) -> Result<(), String> {
        if !matches!(self.profile.as_str(), "balanced" | "throughput")
            || !(5..=120).contains(&self.retry_delay_secs)
            || !(1..=6).contains(&self.max_calls_per_minute)
            || self.client_codes.len() > 64
        {
            return Err("Invalid performance profile or retry limits".into());
        }
        for c in self
            .client_codes
            .iter()
            .chain(std::iter::once(&self.server_code))
            .filter(|c| !c.is_empty())
        {
            identity.options(&[decode(c)?], false, false)?;
        }
        Ok(())
    }
    pub fn options(&self, identity: &Identity, server: bool) -> Result<TunnelOptions, String> {
        if !self.secure_mode {
            return Ok(TunnelOptions::default());
        }
        let trusted = if server {
            self.client_codes
                .iter()
                .map(|s| decode(s))
                .collect::<Result<Vec<_>, _>>()?
        } else {
            vec![decode(&self.server_code)
                .map_err(|_| "Paste and save the server's public pairing code before Connect")?]
        };
        identity.options(&trusted, server, self.profile == "throughput")
    }
}

#[derive(Serialize, Deserialize)]
struct StoredIdentity {
    certificate: Vec<u8>,
    private_key: Vec<u8>,
}
pub fn identity(directory: &Path) -> std::io::Result<Arc<Identity>> {
    let vault = Vault::new(directory);
    let stored = match vault.read("identity.bin")? {
        Some(bytes) => {
            serde_json::from_slice::<StoredIdentity>(&bytes).map_err(std::io::Error::other)?
        }
        None => {
            let identity = Identity::generate().map_err(std::io::Error::other)?;
            let stored = StoredIdentity {
                certificate: identity.certificate,
                private_key: identity.private_key,
            };
            vault.write("identity.bin", &serde_json::to_vec(&stored)?)?;
            stored
        }
    };
    // Validate that the persisted certificate and key actually match; never
    // silently replace a damaged identity and defeat previously paired pins.
    let identity = Identity {
        certificate: stored.certificate,
        private_key: stored.private_key,
    };
    identity
        .options(&[], true, false)
        .map_err(std::io::Error::other)?;
    Ok(Arc::new(identity))
}

#[derive(Default)]
pub struct Attempts {
    calls: VecDeque<Instant>,
    blocked_until: Option<Instant>,
}
impl Attempts {
    pub fn remaining(&self, p: &Preferences, now: Instant) -> u64 {
        let interval = self
            .calls
            .back()
            .map(|t| {
                p.retry_delay_secs
                    .saturating_sub(now.duration_since(*t).as_secs())
            })
            .unwrap_or(0);
        let recent: Vec<_> = self
            .calls
            .iter()
            .filter(|t| now.duration_since(**t) < Duration::from_secs(60))
            .collect();
        let window = if recent.len() >= p.max_calls_per_minute {
            60 - now.duration_since(*recent[0]).as_secs()
        } else {
            0
        };
        let blocked = self
            .blocked_until
            .map(|until| {
                let wait = until.saturating_duration_since(now);
                wait.as_secs() + u64::from(wait.subsec_nanos() > 0)
            })
            .unwrap_or(0);
        interval.max(window).max(blocked)
    }
    pub fn failed(&mut self, error: &str, now: Instant) {
        let lower = error.to_ascii_lowercase();
        if [
            "flood",
            "too many requests",
            "rate limit",
            "code=8",
            "code=429",
            "http 429",
        ]
        .iter()
        .any(|s| lower.contains(s))
        {
            let seconds = ["flood_wait_", "retry after "]
                .iter()
                .find_map(|prefix| {
                    lower
                        .split_once(prefix)
                        .and_then(|(_, s)| s.split(|c: char| !c.is_ascii_digit()).next())
                        .and_then(|s| s.parse::<u64>().ok())
                })
                .unwrap_or(60)
                .clamp(60, 86400);
            self.blocked_until = Some(now + Duration::from_secs(seconds));
        }
    }
    pub fn admit(&mut self, p: &Preferences, now: Instant) -> Result<(), String> {
        while self
            .calls
            .front()
            .is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(60))
        {
            self.calls.pop_front();
        }
        let remaining = self.remaining(p, now);
        if remaining > 0 {
            return Err(format!("Wait {remaining}s before another call attempt"));
        }
        self.calls.push_back(now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pasted_trust_codes_handle_wraps_duplicates_and_keep_every_identity() {
        let a=Identity::generate().unwrap(); let b=Identity::generate().unwrap();
        let ac=code(&a.certificate); let bc=code(&b.certificate);
        let mut p=Preferences::default();
        p.client_codes=vec![ac[..70].into(),ac[70..].into(),format!("\n{bc}\n{ac}")];
        p.normalize_codes().unwrap();
        assert_eq!(p.client_codes,vec![ac,bc]);
        p.validate(&a).unwrap();p.options(&a,true).unwrap();
        p.client_codes.push("not a public code".into());
        assert!(p.normalize_codes().is_err());
    }
    #[test]
    fn identity_survives_restart_and_invalid_codes_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let a = identity(dir.path()).unwrap();
        let b = identity(dir.path()).unwrap();
        assert_eq!(a.certificate, b.certificate);
        assert_eq!(decode(&code(&a.certificate)).unwrap(), a.certificate);
        assert!(Preferences::default().options(&a, false).is_err());
        assert!(decode("bvp1:bad").is_err());
    }
    #[test]
    fn call_budget_blocks_bursts_without_affecting_live_streams() {
        let now = Instant::now();
        let p = Preferences::default();
        let mut a = Attempts::default();
        a.admit(&p, now).unwrap();
        assert!(a.admit(&p, now).is_err());
        a.admit(&p, now + Duration::from_secs(10)).unwrap();
        a.admit(&p, now + Duration::from_secs(20)).unwrap();
        assert!(a.admit(&p, now + Duration::from_secs(30)).is_err());
        a.admit(&p, now + Duration::from_secs(61)).unwrap();
    }
    #[test]
    fn rate_limit_response_stops_new_calls_for_the_reported_interval() {
        let now = Instant::now();
        let p = Preferences::default();
        let mut attempts = Attempts::default();
        attempts.failed("StartCall: FLOOD_WAIT_120", now);
        assert!(attempts.admit(&p, now + Duration::from_secs(61)).is_err());
        attempts.admit(&p, now + Duration::from_secs(121)).unwrap();
    }
}
