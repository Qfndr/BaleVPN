//! Bounded iGap v3 authentication codecs. Secrets are never included in Debug.
//! The owner must encrypt `SessionRecord` through its account-specific store.
use crate::wire;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::Zeroize;

pub const INDEPENDENT_APP_ID: u32 = 67291;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistrationProfile {
    #[default]
    #[serde(rename = "independent")]
    Independent,
    #[serde(rename = "web-v3-compat")]
    WebV3Compatibility,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    /// Omitted on legacy independent profiles; preserve that omission on export.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_profile: Option<RegistrationProfile>,
    pub app_id: u32,
    pub app_build: u32,
    pub app_version: String,
    pub app_name: String,
    pub platform: u32,
    pub platform_version: String,
    pub device: u32,
    pub device_name: String,
    pub language: u32,
}
impl fmt::Debug for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Profile")
            .field("registration_profile", &self.registration_profile)
            .field("app_id", &self.app_id)
            .field("platform", &self.platform)
            .finish_non_exhaustive()
    }
}
impl Profile {
    pub fn new(mode: RegistrationProfile) -> Self {
        let mut random = [0u8; 4];
        rand::rngs::OsRng.fill_bytes(&mut random);
        let device_suffix = random
            .iter()
            .map(|v| format!("{v:02x}"))
            .collect::<String>();
        let (platform, platform_version) = if cfg!(target_os = "windows") {
            (4, "win32")
        } else if cfg!(target_os = "linux") {
            (5, "linux")
        } else if cfg!(target_os = "macos") {
            (3, "darwin")
        } else {
            (0, std::env::consts::OS)
        };
        Self {
            registration_profile: Some(mode),
            app_id: match mode {
                RegistrationProfile::Independent => INDEPENDENT_APP_ID,
                RegistrationProfile::WebV3Compatibility => 1,
            },
            app_build: 1,
            app_version: "0.1.0".into(),
            app_name: "Desktop".into(),
            platform,
            platform_version: platform_version.into(),
            device: 1,
            device_name: format!("Desktop {device_suffix}"),
            language: 1,
        }
    }
    pub fn mode(&self) -> Result<RegistrationProfile, AuthError> {
        match (self.registration_profile, self.app_id) {
            (Some(RegistrationProfile::WebV3Compatibility), 1) => {
                Ok(RegistrationProfile::WebV3Compatibility)
            }
            (None | Some(RegistrationProfile::Independent), 1000..=100000) => {
                Ok(RegistrationProfile::Independent)
            }
            _ => Err(AuthError::InvalidProfile),
        }
    }
    pub fn validate(&self) -> Result<(), AuthError> {
        self.mode()?;
        if self.platform > 6
            || self.device != 1
            || self.language != 1
            || [
                &self.app_version,
                &self.app_name,
                &self.platform_version,
                &self.device_name,
            ]
            .iter()
            .any(|s| s.len() > 64)
        {
            return Err(AuthError::InvalidProfile);
        }
        Ok(())
    }
}
impl Default for Profile {
    fn default() -> Self {
        Self::new(RegistrationProfile::Independent)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRecord {
    pub provider: String,
    pub user_id: String,
    pub token: String,
    pub profile: Profile,
    #[serde(default)]
    pub login_phone: String,
    #[serde(default)]
    pub needs_profile: bool,
}
impl Drop for SessionRecord {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}
impl fmt::Debug for SessionRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionRecord")
            .field("provider", &"igap")
            .field("needs_profile", &self.needs_profile)
            .finish_non_exhaustive()
    }
}
impl SessionRecord {
    pub fn validate(&self) -> Result<(), AuthError> {
        if self.provider != "igap"
            || canonical_id(&self.user_id).is_none()
            || self.token.is_empty()
            || self.token.len() > 16384
            || (!self.login_phone.is_empty() && !valid_international(&self.login_phone))
        {
            return Err(AuthError::InvalidSavedSession);
        }
        self.profile
            .validate()
            .map_err(|_| AuthError::InvalidSavedSession)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthError {
    InvalidProfile,
    InvalidPhone,
    InvalidResponse,
    InvalidCodeFormat,
    InvalidPasswordFormat,
    InvalidProfileName,
    InvalidSavedSession,
    ClientVersionRejected,
}
impl AuthError {
    pub fn reason(self) -> &'static str {
        match self {
            Self::InvalidProfile => "invalid_profile",
            Self::InvalidPhone => "invalid_phone",
            Self::InvalidResponse => "invalid_auth_response",
            Self::InvalidCodeFormat => "invalid_code_format",
            Self::InvalidPasswordFormat => "invalid_password_format",
            Self::InvalidProfileName => "invalid_profile_name",
            Self::InvalidSavedSession => "invalid_saved_session",
            Self::ClientVersionRejected => "client_version_rejected",
        }
    }
}
impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}
impl std::error::Error for AuthError {}

#[derive(Clone)]
pub struct Challenge {
    pub user_id: String,
    pub username: String,
    pub delivery_method: u8,
    pub digits: u8,
    pub retry_after: u32,
}
impl Drop for Challenge {
    fn drop(&mut self) {
        self.username.zeroize();
    }
}
impl fmt::Debug for Challenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Challenge")
            .field("delivery_method", &self.delivery_method)
            .field("digits", &self.digits)
            .field("retry_after", &self.retry_after)
            .finish_non_exhaustive()
    }
}
#[derive(Clone)]
pub struct Verified {
    pub token: String,
    pub needs_profile: bool,
}
impl fmt::Debug for Verified {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Verified")
            .field("needs_profile", &self.needs_profile)
            .finish_non_exhaustive()
    }
}

pub fn canonical_id(value: &str) -> Option<u64> {
    if value.is_empty()
        || value.len() > 20
        || value.starts_with('0')
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    value.parse::<u64>().ok().filter(|v| *v != 0)
}
pub fn valid_international(value: &str) -> bool {
    value.starts_with('+')
        && (7..=16).contains(&value.len())
        && value.as_bytes()[1] != b'0'
        && value.as_bytes()[1..].iter().all(u8::is_ascii_digit)
}

pub fn register_fields(
    country: &str,
    national: &str,
    profile: &Profile,
) -> Result<Vec<u8>, AuthError> {
    profile.validate()?;
    if country.len() != 2
        || !country.bytes().all(|b| b.is_ascii_uppercase())
        || !(5..=15).contains(&national.len())
        || !national.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(AuthError::InvalidPhone);
    }
    let phone = national
        .parse::<u64>()
        .map_err(|_| AuthError::InvalidPhone)?;
    if phone == 0 {
        return Err(AuthError::InvalidPhone);
    }
    let mut output = wire::uint_field(2, phone).map_err(|_| AuthError::InvalidResponse)?;
    output.extend(wire::string_field(3, country, 2).map_err(|_| AuthError::InvalidPhone)?);
    output.extend(wire::uint_field(4, 0).map_err(|_| AuthError::InvalidResponse)?);
    output.extend(
        wire::uint_field(5, profile.app_id as u64).map_err(|_| AuthError::InvalidResponse)?,
    );
    Ok(output)
}
fn outbound_label(value: &str, app: bool) -> std::borrow::Cow<'_, str> {
    if !value.to_ascii_lowercase().contains("balevpn") {
        return std::borrow::Cow::Borrowed(value);
    }
    if app {
        return std::borrow::Cow::Borrowed("Desktop");
    }
    let suffix = Sha256::digest(value.as_bytes())
        .iter()
        .take(4)
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    std::borrow::Cow::Owned(format!("Desktop {suffix}"))
}
pub fn profile_fields(profile: &Profile, verify: bool) -> Result<Vec<u8>, AuthError> {
    profile.validate()?;
    let offset = if verify { 2 } else { 0 };
    let app_name = outbound_label(&profile.app_name, true);
    let device_name = outbound_label(&profile.device_name, false);
    let mut out =
        wire::string_field(3 + offset, &app_name, 64).map_err(|_| AuthError::InvalidProfile)?;
    out.extend(
        wire::uint_field(4 + offset, profile.app_id as u64)
            .map_err(|_| AuthError::InvalidProfile)?,
    );
    out.extend(
        wire::uint_field(5 + offset, profile.app_build as u64)
            .map_err(|_| AuthError::InvalidProfile)?,
    );
    out.extend(
        wire::string_field(6 + offset, &profile.app_version, 64)
            .map_err(|_| AuthError::InvalidProfile)?,
    );
    out.extend(
        wire::uint_field(7 + offset, profile.platform as u64)
            .map_err(|_| AuthError::InvalidProfile)?,
    );
    out.extend(
        wire::string_field(8 + offset, &profile.platform_version, 64)
            .map_err(|_| AuthError::InvalidProfile)?,
    );
    out.extend(
        wire::uint_field(9 + offset, profile.device as u64)
            .map_err(|_| AuthError::InvalidProfile)?,
    );
    out.extend(
        wire::string_field(10 + offset, &device_name, 64).map_err(|_| AuthError::InvalidProfile)?,
    );
    out.extend(
        wire::uint_field(11 + offset, profile.language as u64)
            .map_err(|_| AuthError::InvalidProfile)?,
    );
    Ok(out)
}
pub fn parse_register(fields: &wire::Fields) -> Result<Challenge, AuthError> {
    let uid = wire::number(fields, 3, u64::MAX).map_err(|_| AuthError::InvalidResponse)?;
    let username = wire::text(fields, 2, 256)
        .map_err(|_| AuthError::InvalidResponse)?
        .to_owned();
    let method = wire::number(fields, 5, 3).map_err(|_| AuthError::InvalidResponse)?;
    let digits =
        wire::number(fields, 9, u32::MAX as u64).map_err(|_| AuthError::InvalidResponse)?;
    let digits = if digits == 0 { 5 } else { digits };
    let delay = wire::number(fields, 6, u32::MAX as u64)
        .map_err(|_| AuthError::InvalidResponse)?
        .min(3600);
    if uid == 0 || username.is_empty() || !(3..=9).contains(&digits) {
        return Err(AuthError::InvalidResponse);
    }
    Ok(Challenge {
        user_id: uid.to_string(),
        username,
        delivery_method: method as u8,
        digits: digits as u8,
        retry_after: delay as u32,
    })
}
pub fn verify_fields(
    code: &str,
    challenge: &Challenge,
    profile: &Profile,
) -> Result<Vec<u8>, AuthError> {
    if canonical_id(&challenge.user_id).is_none()
        || challenge.username.is_empty()
        || challenge.username.len() > 256
    {
        return Err(AuthError::InvalidResponse);
    }
    if code.len() != challenge.digits as usize
        || !(3..=9).contains(&challenge.digits)
        || !code.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(AuthError::InvalidCodeFormat);
    }
    let code = code
        .parse::<u64>()
        .map_err(|_| AuthError::InvalidCodeFormat)?;
    let mut out = wire::uint_field(2, code).map_err(|_| AuthError::InvalidResponse)?;
    out.extend(
        wire::string_field(3, &challenge.username, 256).map_err(|_| AuthError::InvalidResponse)?,
    );
    out.extend(wire::string_field(4, "", 0).map_err(|_| AuthError::InvalidResponse)?);
    out.extend(profile_fields(profile, true)?);
    Ok(out)
}
pub fn parse_verify(fields: &wire::Fields) -> Result<Verified, AuthError> {
    let token = wire::text(fields, 2, 16384)
        .map_err(|_| AuthError::InvalidResponse)?
        .to_owned();
    let needs_profile = wire::number(fields, 3, 1).map_err(|_| AuthError::InvalidResponse)? != 0;
    if token.is_empty() {
        return Err(AuthError::InvalidResponse);
    }
    Ok(Verified {
        token,
        needs_profile,
    })
}
/// Field 12 is deliberately absent: the secure RPC owner adds its actual key.
pub fn login_fields(token: &str, profile: &Profile) -> Result<Vec<u8>, AuthError> {
    if token.is_empty() || token.len() > 16384 {
        return Err(AuthError::InvalidSavedSession);
    }
    let mut out =
        wire::string_field(2, token, 16384).map_err(|_| AuthError::InvalidSavedSession)?;
    out.extend(profile_fields(profile, false)?);
    Ok(out)
}
pub fn parse_login(fields: &wire::Fields) -> Result<String, AuthError> {
    if wire::number(fields, 2, 1).map_err(|_| AuthError::InvalidResponse)? != 0 {
        return Err(AuthError::ClientVersionRejected);
    }
    let uid = wire::number(fields, 14, u64::MAX).map_err(|_| AuthError::InvalidResponse)?;
    if uid == 0 {
        return Err(AuthError::InvalidResponse);
    }
    Ok(uid.to_string())
}
pub fn password_fields(password: &str) -> Result<Vec<u8>, AuthError> {
    if password.is_empty() || password.len() > 1024 {
        return Err(AuthError::InvalidPasswordFormat);
    }
    wire::string_field(2, password, 1024).map_err(|_| AuthError::InvalidPasswordFormat)
}
pub fn password_hint(fields: &wire::Fields) -> Result<String, AuthError> {
    wire::text(fields, 4, 256)
        .map(str::to_owned)
        .map_err(|_| AuthError::InvalidResponse)
}
pub fn complete_profile_fields(name: &str) -> Result<Vec<u8>, AuthError> {
    let name = name.trim();
    if name.is_empty() || name.len() > 128 {
        return Err(AuthError::InvalidProfileName);
    }
    wire::string_field(2, name, 128).map_err(|_| AuthError::InvalidProfileName)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn n(id: u32, value: u64) -> Vec<u8> {
        wire::uint_field(id, value).unwrap()
    }
    fn text(id: u32, value: &str) -> Vec<u8> {
        wire::string_field(id, value, 20000).unwrap()
    }
    fn challenge() -> Challenge {
        Challenge {
            user_id: "41".into(),
            username: "fixture-private-username".into(),
            delivery_method: 0,
            digits: 5,
            retry_after: 60,
        }
    }
    #[test]
    fn retained_project_labels_are_neutral_only_in_outbound_display_fields() {
        let mut profile = Profile::new(RegistrationProfile::WebV3Compatibility);
        profile.app_name = "BaleVPN Provider Lab".into();
        profile.device_name = "BaleVPN Lab ab123456".into();
        let retained = serde_json::to_vec(&profile).unwrap();
        let packed = profile_fields(&profile, false).unwrap();
        let fields = wire::parse(&packed).unwrap();
        assert_eq!(wire::text(&fields, 3, 64).unwrap(), "Desktop");
        let name = wire::text(&fields, 10, 64).unwrap();
        assert!(name.starts_with("Desktop ") && !name.to_ascii_lowercase().contains("vpn"));
        assert_eq!(wire::number(&fields, 4, u64::MAX).unwrap(), 1);
        assert_eq!(wire::number(&fields, 9, u64::MAX).unwrap(), 1);
        assert_eq!(packed, profile_fields(&profile, false).unwrap());
        assert_eq!(serde_json::to_vec(&profile).unwrap(), retained);
    }
    #[test]
    fn registration_profiles_are_explicit_honest_and_legacy_ids_are_retained() {
        let independent = Profile::default();
        assert_eq!(independent.app_id, 67291);
        assert_eq!(
            independent.mode().unwrap(),
            RegistrationProfile::Independent
        );
        assert_eq!(independent.device, 1);
        assert_eq!(
            independent.platform,
            if cfg!(target_os = "windows") {
                4
            } else if cfg!(target_os = "linux") {
                5
            } else if cfg!(target_os = "macos") {
                3
            } else {
                0
            }
        );
        let compatibility = Profile::new(RegistrationProfile::WebV3Compatibility);
        assert_eq!(compatibility.app_id, 1);
        assert_eq!(compatibility.app_name, "Desktop");
        assert_eq!(compatibility.app_version, "0.1.0");
        let mut legacy = independent.clone();
        legacy.registration_profile = None;
        legacy.app_id = 54321;
        let encoded = serde_json::to_value(&legacy).unwrap();
        assert!(encoded.get("registrationProfile").is_none());
        let restored: Profile = serde_json::from_value(encoded.clone()).unwrap();
        restored.validate().unwrap();
        assert_eq!(serde_json::to_value(restored).unwrap(), encoded);
        legacy.app_id = 1;
        assert_eq!(legacy.validate(), Err(AuthError::InvalidProfile));
        legacy.registration_profile = Some(RegistrationProfile::WebV3Compatibility);
        legacy.validate().unwrap();
        legacy.device = 3;
        assert_eq!(legacy.validate(), Err(AuthError::InvalidProfile));
    }
    #[test]
    fn registration_request_matches_verified_js_wire_without_preference_fallback() {
        let profile = Profile::new(RegistrationProfile::WebV3Compatibility);
        let bytes = register_fields("IR", "9120000001", &profile).unwrap();
        let expected = [n(2, 9120000001), text(3, "IR"), n(4, 0), n(5, 1)].concat();
        assert_eq!(bytes, expected);
        let f = wire::parse(&bytes).unwrap();
        assert_eq!(wire::number(&f, 4, 2).unwrap(), 0);
        assert_eq!(wire::number(&f, 5, 100000).unwrap(), 1);
        assert_eq!(
            register_fields("IR", "00000", &profile),
            Err(AuthError::InvalidPhone)
        );
        for (country, number) in [
            ("ir", "9120000001"),
            ("IR", "+989120000001"),
            ("IR", "۱۲۳۴۵"),
            ("IR", "1234"),
            ("IR", "1234567890123456"),
        ] {
            assert!(register_fields(country, number, &profile).is_err());
        }
    }
    #[test]
    fn registration_response_retains_all_delivery_methods_uint64_and_bounded_resend() {
        for method in 0..=3 {
            let fields = wire::parse(
                &[
                    text(2, "fixture-private-username"),
                    n(3, u64::MAX),
                    n(5, method),
                    n(6, 9999),
                    n(9, 6),
                ]
                .concat(),
            )
            .unwrap();
            let challenge = parse_register(&fields).unwrap();
            assert_eq!(challenge.user_id, u64::MAX.to_string());
            assert_eq!(challenge.delivery_method, method as u8);
            assert_eq!(challenge.digits, 6);
            assert_eq!(challenge.retry_after, 3600);
            assert!(!format!("{challenge:?}").contains("fixture-private"));
        }
        let defaults =
            wire::parse(&[text(2, "fixture-private-username"), n(3, 41)].concat()).unwrap();
        let c = parse_register(&defaults).unwrap();
        assert_eq!((c.delivery_method, c.digits, c.retry_after), (0, 5, 0));
        for extra in [n(5, 4), n(9, 2), n(9, 10), n(3, 41), text(2, "duplicate")] {
            let mut body = [text(2, "fixture-private-username"), n(3, 41)].concat();
            body.extend(extra);
            assert_eq!(
                parse_register(&wire::parse(&body).unwrap()).err(),
                Some(AuthError::InvalidResponse)
            );
        }
        assert!(parse_register(&wire::Fields::new()).is_err());
    }
    #[test]
    fn verification_login_password_and_profile_use_exact_documented_fields() {
        let profile = Profile::new(RegistrationProfile::WebV3Compatibility);
        let challenge = challenge();
        let verify = wire::parse(&verify_fields("01234", &challenge, &profile).unwrap()).unwrap();
        assert_eq!(wire::number(&verify, 2, u64::MAX).unwrap(), 1234);
        assert_eq!(wire::text(&verify, 3, 256).unwrap(), challenge.username);
        assert_eq!(wire::text(&verify, 4, 0).unwrap(), "");
        assert_eq!(wire::number(&verify, 6, 100000).unwrap(), 1);
        assert_eq!(wire::text(&verify, 5, 64).unwrap(), profile.app_name);
        assert!(!verify.contains_key(&1));
        for code in ["1234", "123456", "۱۲۳۴۵", "abcde"] {
            assert_eq!(
                verify_fields(code, &challenge, &profile),
                Err(AuthError::InvalidCodeFormat)
            );
        }
        let login = wire::parse(&login_fields("fixture-secret-token", &profile).unwrap()).unwrap();
        assert_eq!(wire::text(&login, 2, 100).unwrap(), "fixture-secret-token");
        assert_eq!(wire::number(&login, 4, 100000).unwrap(), 1);
        assert!(!login.contains_key(&12));
        assert!(!login.contains_key(&1));
        assert_eq!(
            parse_login(&wire::parse(&n(14, 41)).unwrap()).unwrap(),
            "41"
        );
        assert_eq!(
            parse_login(&wire::parse(&[n(2, 1), n(14, 41)].concat()).unwrap()),
            Err(AuthError::ClientVersionRejected)
        );
        assert!(parse_login(&wire::Fields::new()).is_err());
        assert_eq!(password_fields("test").unwrap(), text(2, "test"));
        assert!(password_fields("").is_err());
        assert!(password_fields(&"a".repeat(1025)).is_err());
        assert_eq!(
            complete_profile_fields("  Test  ").unwrap(),
            text(2, "Test")
        );
        assert!(complete_profile_fields(" ").is_err());
    }
    #[test]
    fn tokens_are_bounded_and_never_appear_in_debug_or_fixed_errors() {
        let fields = wire::parse(&[text(2, "fixture-secret-token"), n(3, 1)].concat()).unwrap();
        let verified = parse_verify(&fields).unwrap();
        assert!(verified.needs_profile);
        assert_eq!(verified.token, "fixture-secret-token");
        assert!(!format!("{verified:?}").contains("fixture-secret"));
        assert!(parse_verify(&wire::Fields::new()).is_err());
        assert!(parse_verify(&wire::parse(&[text(2, "ok"), n(3, 2)].concat()).unwrap()).is_err());
        let record = SessionRecord {
            provider: "igap".into(),
            user_id: "41".into(),
            token: "fixture-secret-token".into(),
            profile: Profile::default(),
            login_phone: "+989120000001".into(),
            needs_profile: false,
        };
        record.validate().unwrap();
        let debug = format!("{record:?}");
        for secret in [
            &record.token,
            &record.user_id,
            &record.login_phone,
            &record.profile.device_name,
        ] {
            assert!(!debug.contains(secret));
        }
        let json = serde_json::to_vec(&record).unwrap();
        let restored: SessionRecord = serde_json::from_slice(&json).unwrap();
        restored.validate().unwrap();
        assert_eq!(restored.token, record.token);
        let mut invalid = record.clone();
        invalid.provider = "bale".into();
        assert_eq!(invalid.validate(), Err(AuthError::InvalidSavedSession));
        invalid = record.clone();
        invalid.user_id = "18446744073709551616".into();
        assert!(invalid.validate().is_err());
        invalid = record;
        invalid.token = "a".repeat(16385);
        assert!(invalid.validate().is_err());
    }
}
