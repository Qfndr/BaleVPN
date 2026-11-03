//! Exact call-only privacy request/response codecs. No global ALL rule writes.
use crate::wire::{self, Fields};
use serde::Serialize;
use std::fmt;

pub const GET: u16 = 143;
pub const SET: u16 = 144;
pub const VOICE: u32 = 4;
pub const VIDEO: u32 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivacyError {
    InvalidType,
    InvalidLevel,
    InvalidResponse,
    NotApplied,
}
impl PrivacyError {
    pub fn reason(self) -> &'static str {
        match self {
            Self::InvalidType => "invalid_privacy_type",
            Self::InvalidLevel => "invalid_privacy_level",
            Self::InvalidResponse => "invalid_privacy_response",
            Self::NotApplied => "privacy_not_applied",
        }
    }
}
impl fmt::Display for PrivacyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}
impl std::error::Error for PrivacyError {}

fn call_type(kind: u32) -> Result<(), PrivacyError> {
    if [VOICE, VIDEO].contains(&kind) {
        Ok(())
    } else {
        Err(PrivacyError::InvalidType)
    }
}
pub fn get_fields(kind: u32) -> Result<Vec<u8>, PrivacyError> {
    call_type(kind)?;
    wire::uint_field(2, u64::from(kind)).map_err(|_| PrivacyError::InvalidType)
}
pub fn set_fields(kind: u32, level: u8) -> Result<Vec<u8>, PrivacyError> {
    call_type(kind)?;
    if level > 2 {
        return Err(PrivacyError::InvalidLevel);
    }
    let mut out = get_fields(kind)?;
    out.extend(wire::uint_field(3, u64::from(level)).map_err(|_| PrivacyError::InvalidLevel)?);
    Ok(out)
}
/// Live service returns legacy type2/level3; current Web descriptors have
/// repeated nested rules4 with level1/type2. Reject ambiguous/missing rules.
pub fn rule(fields: &Fields, kind: u32) -> Result<u8, PrivacyError> {
    call_type(kind)?;
    if fields.contains_key(&2) || fields.contains_key(&3) {
        if fields.contains_key(&4)
            || wire::number(fields, 2, 8).map_err(|_| PrivacyError::InvalidResponse)?
                != u64::from(kind)
        {
            return Err(PrivacyError::InvalidResponse);
        }
        return wire::number(fields, 3, 2)
            .map(|v| v as u8)
            .map_err(|_| PrivacyError::InvalidResponse);
    }
    let items =
        wire::repeated_bytes(fields, 4, 16, 1024).map_err(|_| PrivacyError::InvalidResponse)?;
    let mut rules = std::collections::BTreeMap::new();
    for bytes in items {
        let nested = wire::parse(bytes).map_err(|_| PrivacyError::InvalidResponse)?;
        let key = wire::number(&nested, 2, 8).map_err(|_| PrivacyError::InvalidResponse)?;
        let level = wire::number(&nested, 1, 2).map_err(|_| PrivacyError::InvalidResponse)?;
        if rules.insert(key, level as u8).is_some() {
            return Err(PrivacyError::InvalidResponse);
        }
    }
    rules
        .get(&u64::from(kind))
        .copied()
        .ok_or(PrivacyError::InvalidResponse)
}
pub fn parse_set(fields: &Fields, kind: u32, level: u8) -> Result<(), PrivacyError> {
    call_type(kind)?;
    if level > 2 {
        return Err(PrivacyError::InvalidLevel);
    }
    if fields.contains_key(&4)
        || wire::number(fields, 2, 8).map_err(|_| PrivacyError::InvalidResponse)? != u64::from(kind)
        || wire::number(fields, 3, 2).map_err(|_| PrivacyError::InvalidResponse)?
            != u64::from(level)
    {
        return Err(PrivacyError::InvalidResponse);
    }
    Ok(())
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Snapshot {
    pub voice: u8,
    pub video: u8,
}
impl Snapshot {
    pub fn new(voice: u8, video: u8) -> Result<Self, PrivacyError> {
        if voice > 2 || video > 2 {
            return Err(PrivacyError::InvalidLevel);
        }
        Ok(Self { voice, video })
    }
    pub fn everyone(self) -> bool {
        self.voice == 0 && self.video == 0
    }
    pub fn require_everyone(self) -> Result<(), PrivacyError> {
        if self.everyone() {
            Ok(())
        } else {
            Err(PrivacyError::NotApplied)
        }
    }
    pub fn changes(self) -> Vec<u32> {
        let mut out = Vec::new();
        if self.voice != 0 {
            out.push(VOICE);
        }
        if self.video != 0 {
            out.push(VIDEO);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn n(id: u32, value: u64) -> Vec<u8> {
        wire::uint_field(id, value).unwrap()
    }
    fn legacy(kind: u64, level: u64) -> Fields {
        wire::parse(&[n(2, kind), n(3, level)].concat()).unwrap()
    }
    fn nested(kind: u64, level: u64) -> Vec<u8> {
        wire::bytes_field(4, &[n(1, level), n(2, kind)].concat()).unwrap()
    }
    #[test]
    fn exact_call_fields_and_both_response_shapes() {
        assert_eq!(get_fields(VOICE).unwrap(), [16, 4]);
        assert_eq!(set_fields(VIDEO, 0).unwrap(), [16, 5, 24, 0]);
        for kind in [VOICE, VIDEO] {
            for level in 0..=2 {
                assert_eq!(
                    rule(&legacy(kind as u64, level), kind).unwrap(),
                    level as u8
                );
                assert_eq!(
                    rule(&wire::parse(&nested(kind as u64, level)).unwrap(), kind).unwrap(),
                    level as u8
                );
                parse_set(&legacy(kind as u64, level), kind, level as u8).unwrap();
            }
        }
    }
    #[test]
    fn proto3_omitted_zero_level_requires_exact_present_type() {
        assert_eq!(rule(&wire::parse(&n(2, 4)).unwrap(), VOICE).unwrap(), 0);
        for bytes in [Vec::new(), n(3, 0), n(2, 5), n(2, 8)] {
            assert_eq!(
                rule(&wire::parse(&bytes).unwrap(), VOICE),
                Err(PrivacyError::InvalidResponse)
            );
        }
    }
    #[test]
    fn duplicate_mixed_and_malformed_rules_never_authorize_write() {
        for bytes in [
            [n(2, 4), n(2, 4)].concat(),
            [n(2, 4), n(3, 3)].concat(),
            [nested(4, 0), nested(4, 0)].concat(),
            [n(2, 4), nested(4, 0)].concat(),
            wire::string_field(4, "private data", 100).unwrap(),
            nested(4, 3),
        ] {
            assert!(rule(&wire::parse(&bytes).unwrap(), VOICE).is_err());
        }
        assert!(get_fields(8).is_err());
        assert!(set_fields(0, 0).is_err());
        assert!(set_fields(4, 3).is_err());
        assert!(parse_set(&legacy(5, 0), 4, 0).is_err());
        assert!(parse_set(&Fields::new(), 4, 0).is_err());
    }
    #[test]
    fn readback_requires_both_and_does_not_change_non_call_types() {
        let snapshot = Snapshot::new(1, 2).unwrap();
        assert_eq!(snapshot.changes(), vec![4, 5]);
        assert_eq!(snapshot.require_everyone(), Err(PrivacyError::NotApplied));
        assert!(Snapshot::new(0, 0).unwrap().changes().is_empty());
        assert!(Snapshot::new(0, 0).unwrap().require_everyone().is_ok());
        assert!(Snapshot::new(0, 3).is_err());
    }
}
