//! Non-secret presentation preferences. Never touch transport or account settings.
use serde_json::Value;

pub fn validate(value: &Value) -> Result<(), &'static str> {
    let fields = value.as_object().ok_or("Invalid appearance preferences")?;
    for (key, value) in fields {
        let choices: &[&str] = match key.as_str() {
            "layout" => &["classic", "nova", "orbit"],
            "language" => &["en", "fa", "auto"],
            "theme" => &["light", "dark", "system"],
            "palette" => &["ocean", "teal", "violet", "rose", "amber", "custom"],
            "font" => &["modern", "system"],
            "size" => &["90", "100", "110", "120"],
            "width" => &["compact", "standard", "wide"],
            "density" => &["comfortable", "compact"],
            "corners" => &["0", "10", "20"],
            "units" => &["bytes", "bits"],
            "range" => &["60", "300", "900"],
            "gradient" | "metrics" | "motion" => {
                if !value.is_boolean() { return Err("Invalid appearance switch"); }
                continue;
            }
            "accent" => {
                let s = value.as_str().ok_or("Invalid appearance color")?;
                if s.len() != 7 || !s.starts_with('#') || !s.as_bytes()[1..].iter().all(u8::is_ascii_hexdigit) {
                    return Err("Invalid appearance color");
                }
                continue;
            }
            _ => return Err("Unknown appearance preference"),
        };
        if !value.as_str().is_some_and(|s| choices.contains(&s)) {
            return Err("Invalid appearance choice");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn appearance_survives_restart_without_changing_account_settings() {
        let dir = tempfile::tempdir().unwrap();
        let file = crate::config::ConfigFile::new(dir.path().into());
        let value = serde_json::json!({"layout":"orbit","language":"fa","theme":"dark","accent":"#4a83ff","motion":false});
        validate(&value).unwrap();
        file.update(|c| { c.appearance = Some(value.clone()); c.peer_id = Some("test-peer".into()); }).unwrap();
        let restarted = crate::config::ConfigFile::new(dir.path().into());
        assert_eq!(restarted.load().appearance, Some(value));
        assert_eq!(restarted.load().peer_id.as_deref(), Some("test-peer"));
        assert!(restarted.load().preferences.secure_mode);
    }
    #[test]
    fn untrusted_fields_and_css_are_rejected() {
        for value in [serde_json::json!([]), serde_json::json!({"token":"secret"}), serde_json::json!({"layout":"unknown"}), serde_json::json!({"accent":"url(evil)"}), serde_json::json!({"metrics":"yes"}), serde_json::json!({"size":"100000"})] {
            assert!(validate(&value).is_err());
        }
    }
}
