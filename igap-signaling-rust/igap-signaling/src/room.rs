//! Strict, provider-specific room codecs and claim context binding.
use crate::{wire as w, Error};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
pub const LIVEKIT_URL: &str = "wss://call.igap.net/";
pub fn id(value: &str) -> Result<u64, Error> {
    if value.is_empty()
        || value.starts_with('0')
        || value.len() > 20
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(Error::InvalidInput);
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|n| *n > 0)
        .ok_or(Error::InvalidInput)
}
pub fn create() -> Result<Vec<u8>, Error> {
    let mut b = w::uint_field(2, 0)?;
    b.extend(w::uint_field(3, 0)?);
    Ok(b)
}
pub fn offer(peer: &str, room: &str) -> Result<Vec<u8>, Error> {
    let mut b = w::uint_field(2, id(peer)?)?;
    b.extend(w::uint_field(3, id(room)?)?);
    Ok(b)
}
pub fn join(room: &str) -> Result<Vec<u8>, Error> {
    Ok(w::uint_field(2, id(room)?)?)
}
pub fn leave() -> Result<Vec<u8>, Error> {
    Ok(w::uint_field(2, 0)?)
}
pub fn response_id(fields: &w::Fields, n: u32) -> Result<String, Error> {
    let value = w::number(fields, n, u64::MAX)?;
    if value == 0 {
        return Err(Error::InvalidResponse);
    }
    Ok(value.to_string())
}
pub fn incoming(fields: &w::Fields, self_id: &str) -> Result<(String, String), Error> {
    if w::number(fields, 5, 1)? != 0 || w::number(fields, 8, 2)? != 0 {
        return Err(Error::NotSupported);
    }
    let peer = response_id(fields, 2)?;
    let room = response_id(fields, 3)?;
    if peer == self_id {
        return Err(Error::InvalidResponse);
    }
    if let Some(values) = fields.get(&4) {
        let mut count = 0;
        for value in values {
            let ids = match value {
                w::Value::Varint(n) => vec![*n],
                w::Value::Bytes(bytes) => {
                    let mut parsed = Vec::new();
                    let mut n = 0u64;
                    let mut shift = 0;
                    for byte in bytes {
                        if shift >= 64 || (shift == 63 && *byte > 1) {
                            return Err(Error::InvalidPacket);
                        }
                        n |= ((*byte & 127) as u64) << shift;
                        if byte & 128 == 0 {
                            parsed.push(n);
                            n = 0;
                            shift = 0;
                        } else {
                            shift += 7;
                        }
                    }
                    if shift != 0 {
                        return Err(Error::InvalidPacket);
                    }
                    parsed
                }
            };
            for n in ids {
                count += 1;
                if count > 64 || (n.to_string() != self_id && n.to_string() != peer) {
                    return Err(Error::InvalidResponse);
                }
            }
        }
    }
    Ok((peer, room))
}
/// No signature trust is inferred from decoding claims. The pinned service
/// channel supplies credentials; LiveKit verifies signatures at connection.
pub fn bound_token(fields: &w::Fields, self_id: &str, room: &str) -> Result<String, Error> {
    if response_id(fields, 3)? != self_id {
        return Err(Error::InvalidResponse);
    }
    let token = w::text(fields, 2, 16384)?;
    let parts: Vec<_> = token.split('.').collect();
    if parts.len() != 3
        || parts.iter().any(|v| {
            v.is_empty()
                || !v
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
    {
        return Err(Error::InvalidResponse);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| Error::InvalidResponse)?;
    if bytes.len() > 12000 || URL_SAFE_NO_PAD.encode(&bytes) != parts[1] {
        return Err(Error::InvalidResponse);
    }
    let claims: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| Error::InvalidResponse)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::InvalidResponse)?
        .as_secs();
    if claims["sub"].as_str() != Some(self_id)
        || claims["video"]["room"].as_str() != Some(room)
        || claims["video"]["roomJoin"].as_bool() != Some(true)
        || claims["exp"].as_u64().filter(|exp| *exp > now).is_none()
        || claims
            .get("nbf")
            .is_some_and(|v| v.as_u64().filter(|n| *n <= now + 5).is_none())
    {
        return Err(Error::InvalidResponse);
    }
    Ok(token.to_owned())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_ids() {
        for bad in ["0", "01", "-1", "18446744073709551616"] {
            assert!(id(bad).is_err())
        }
        assert_eq!(id("18446744073709551615").unwrap(), u64::MAX);
    }
    #[test]
    fn rejects_missing_cross_room_expired_claims() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        for (room, exp, valid) in [
            ("99", now + 60, true),
            ("100", now + 60, false),
            ("99", 0, false),
        ] {
            let token=format!("header.{}.signature",URL_SAFE_NO_PAD.encode(serde_json::to_vec(&serde_json::json!({"sub":"41","video":{"room":room,"roomJoin":true},"exp":exp})).unwrap()));
            let mut b = w::string_field(2, &token, 16384).unwrap();
            b.extend(w::uint_field(3, 41).unwrap());
            assert_eq!(
                bound_token(&w::parse(&b).unwrap(), "41", "99").is_ok(),
                valid
            );
        }
    }
}
