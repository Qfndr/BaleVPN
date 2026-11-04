//! Experimental H.264 user_data_unregistered carrier, independent of production.
//!
//! This module handles complete naked type-6 NAL units, not Annex-B framing or
//! RTP fragmentation. A valid coded picture and parameter sets remain necessary.
//! SEI is optional metadata: a provider can remove it without breaking video.
use std::fmt;

/// Public application UUID, with RFC 4122 version-4 and variant bits.
pub const CARRIER_UUID: [u8; 16] = [
    0xf5, 0x29, 0x6d, 0x8a, 0xe7, 0x31, 0x48, 0x5c, 0xa9, 0x46, 0x66, 0x7f, 0xa2, 0x76, 0xe2, 0x21,
];
pub const MAX_PAYLOAD: usize = 16 * 1024;
// Local parser budgets, not limits imposed by the H.264 specification.
const MAX_RBSP_SIZE: usize = MAX_PAYLOAD + 512;
const MAX_MESSAGES: usize = 16;
pub const MAX_NAL_SIZE: usize = 1 + MAX_RBSP_SIZE + MAX_RBSP_SIZE / 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeiError {
    PayloadTooLarge,
    InvalidHeader,
    MalformedRbsp,
    DuplicatePayload,
}
impl fmt::Display for SeiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PayloadTooLarge => "payload_too_large",
            Self::InvalidHeader => "invalid_header",
            Self::MalformedRbsp => "malformed_rbsp",
            Self::DuplicatePayload => "duplicate_payload",
        })
    }
}
impl std::error::Error for SeiError {}

fn write_ff_value(mut value: usize, bytes: &mut Vec<u8>) {
    while value >= 255 {
        bytes.push(255);
        value -= 255;
    }
    bytes.push(value as u8);
}

fn escape_rbsp(rbsp: &[u8]) -> Vec<u8> {
    let mut nal = Vec::with_capacity(1 + rbsp.len() + rbsp.len() / 2);
    nal.push(0x06); // forbidden_zero_bit=0, nal_ref_idc=0, nal_unit_type=6.
    let mut zeros = 0;
    for &byte in rbsp {
        if zeros == 2 && byte <= 3 {
            nal.push(3);
            zeros = 0;
        }
        nal.push(byte);
        zeros = if byte == 0 { zeros + 1 } else { 0 };
    }
    nal
}

/// Build one complete type-6 NAL containing one unregistered-data UUID message.
/// The SEI payload size includes the UUID, before emulation-prevention escaping.
pub fn encode_nal(payload: &[u8]) -> Result<Vec<u8>, SeiError> {
    if payload.len() > MAX_PAYLOAD {
        return Err(SeiError::PayloadTooLarge);
    }
    let mut rbsp = Vec::with_capacity(payload.len() + 96);
    write_ff_value(5, &mut rbsp);
    write_ff_value(CARRIER_UUID.len() + payload.len(), &mut rbsp);
    rbsp.extend_from_slice(&CARRIER_UUID);
    rbsp.extend_from_slice(payload);
    rbsp.push(0x80); // rbsp_stop_one_bit followed by byte-alignment zero bits.
    let nal = escape_rbsp(&rbsp);
    rbsp.fill(0);
    Ok(nal)
}

fn unescape_rbsp(nal: &[u8]) -> Result<Vec<u8>, SeiError> {
    if nal.first() != Some(&0x06) {
        return Err(SeiError::InvalidHeader);
    }
    if nal.len() > MAX_NAL_SIZE {
        return Err(SeiError::PayloadTooLarge);
    }
    let bytes = &nal[1..];
    let mut rbsp = Vec::with_capacity(bytes.len().min(MAX_RBSP_SIZE));
    let mut zeros = 0;
    let mut offset = 0;
    while offset < bytes.len() {
        let byte = bytes[offset];
        if zeros == 2 {
            if byte <= 2 {
                rbsp.fill(0);
                return Err(SeiError::MalformedRbsp);
            }
            if byte == 3 {
                // A prevention byte must be followed by a byte in 0..=3.
                if bytes.get(offset + 1).is_none_or(|next| *next > 3) {
                    rbsp.fill(0);
                    return Err(SeiError::MalformedRbsp);
                }
                zeros = 0;
                offset += 1;
                continue;
            }
        }
        if rbsp.len() == MAX_RBSP_SIZE {
            rbsp.fill(0);
            return Err(SeiError::PayloadTooLarge);
        }
        rbsp.push(byte);
        zeros = if byte == 0 { zeros + 1 } else { 0 };
        offset += 1;
    }
    Ok(rbsp)
}

fn read_ff_value(rbsp: &[u8], offset: &mut usize) -> Result<usize, SeiError> {
    let mut value: usize = 0;
    loop {
        let byte = *rbsp.get(*offset).ok_or(SeiError::MalformedRbsp)?;
        *offset += 1;
        value = value
            .checked_add(byte as usize)
            .ok_or(SeiError::MalformedRbsp)?;
        if byte != 255 {
            return Ok(value);
        }
    }
}

/// Extract only this application's UUID from a complete SEI NAL. Foreign
/// UUIDs and other SEI types are skipped without exposing their contents.
/// More than one matching message is rejected rather than chosen implicitly.
/// Unrelated SEI payload semantics are outside this bounded carrier parser.
pub fn decode_nal(nal: &[u8]) -> Result<Option<Vec<u8>>, SeiError> {
    let mut rbsp = unescape_rbsp(nal)?;
    let result = (|| {
        let mut offset = 0;
        let mut messages = 0;
        let mut payload = None;
        loop {
            if rbsp.get(offset) == Some(&0x80) && offset + 1 == rbsp.len() {
                return if messages > 0 {
                    Ok(payload)
                } else {
                    Err(SeiError::MalformedRbsp)
                };
            }
            if messages == MAX_MESSAGES {
                return Err(SeiError::MalformedRbsp);
            }
            messages += 1;
            let kind = read_ff_value(&rbsp, &mut offset)?;
            let size = read_ff_value(&rbsp, &mut offset)?;
            let end = offset.checked_add(size).ok_or(SeiError::MalformedRbsp)?;
            let bytes = rbsp.get(offset..end).ok_or(SeiError::MalformedRbsp)?;
            if kind == 5 {
                if bytes.len() < CARRIER_UUID.len() {
                    return Err(SeiError::MalformedRbsp);
                }
                if bytes.len() - CARRIER_UUID.len() > MAX_PAYLOAD {
                    return Err(SeiError::PayloadTooLarge);
                }
                if bytes.starts_with(&CARRIER_UUID) {
                    if payload.is_some() {
                        return Err(SeiError::DuplicatePayload);
                    }
                    payload = Some(bytes[CARRIER_UUID.len()..].to_vec());
                }
            }
            offset = end;
        }
    })();
    rbsp.fill(0);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_exact_empty_and_escape_vectors_follow_sei_syntax() {
        let mut empty = vec![0x06, 0x05, 0x10];
        empty.extend_from_slice(&CARRIER_UUID);
        empty.push(0x80);
        assert_eq!(encode_nal(&[]).unwrap(), empty);
        assert_eq!(decode_nal(&empty).unwrap(), Some(Vec::new()));
        let data = [0, 0, 0, 1, 0, 0, 2, 0, 0, 3, 0, 0, 4];
        let mut expected = vec![0x06, 0x05, 0x1d];
        expected.extend_from_slice(&CARRIER_UUID);
        expected.extend_from_slice(&[0, 0, 3, 0, 1, 0, 0, 3, 2, 0, 0, 3, 3, 0, 0, 4, 0x80]);
        assert_eq!(encode_nal(&data).unwrap(), expected);
        assert_eq!(decode_nal(&expected).unwrap(), Some(data.to_vec()));
    }

    #[test]
    fn arbitrary_binary_and_zero_rich_maximum_payloads_round_trip() {
        for data in [
            (0..=255).cycle().take(4096).collect::<Vec<u8>>(),
            vec![0; MAX_PAYLOAD],
        ] {
            let encoded = encode_nal(&data).unwrap();
            assert!(encoded.len() <= MAX_NAL_SIZE);
            assert!(!encoded
                .windows(3)
                .any(|window| window == [0, 0, 0] || window == [0, 0, 1] || window == [0, 0, 2]));
            assert_eq!(decode_nal(&encoded).unwrap(), Some(data));
        }
    }

    #[test]
    fn size_255_continuations_count_uuid_and_unescaped_payload_bytes() {
        for (length, prefix) in [
            (238, vec![5, 254]),
            (239, vec![5, 255, 0]),
            (494, vec![5, 255, 255, 0]),
        ] {
            let encoded = encode_nal(&vec![0x7f; length]).unwrap();
            assert_eq!(&encoded[1..1 + prefix.len()], prefix.as_slice());
            assert_eq!(decode_nal(&encoded).unwrap(), Some(vec![0x7f; length]));
        }
    }

    #[test]
    fn foreign_uuids_and_other_messages_are_ignored_but_duplicate_carriers_are_rejected() {
        let mut foreign = vec![5, 17];
        foreign.extend_from_slice(&[0x11; 16]);
        foreign.push(0x42);
        foreign.push(0x80);
        assert_eq!(decode_nal(&escape_rbsp(&foreign)).unwrap(), None);
        let mut mixed = vec![200, 0, 5, 17];
        mixed.extend_from_slice(&CARRIER_UUID);
        mixed.extend_from_slice(&[0x42, 0x80]);
        assert_eq!(decode_nal(&escape_rbsp(&mixed)).unwrap(), Some(vec![0x42]));
        mixed.pop();
        mixed.extend_from_slice(&[5, 16]);
        mixed.extend_from_slice(&CARRIER_UUID);
        mixed.push(0x80);
        assert_eq!(
            decode_nal(&escape_rbsp(&mixed)),
            Err(SeiError::DuplicatePayload)
        );
    }

    #[test]
    fn invalid_headers_trailing_bits_sizes_and_emulation_prevention_fail_closed() {
        for invalid in [vec![], vec![0x65, 0x80], vec![0x86, 0x80], vec![0x26, 0x80]] {
            assert_eq!(decode_nal(&invalid), Err(SeiError::InvalidHeader));
        }
        for invalid in [
            vec![6],
            vec![6, 0x80],
            vec![6, 5, 15, 0x80],
            vec![6, 255],
            vec![6, 5, 255, 255],
            vec![6, 5, 20, 0x11, 0x80],
            vec![6, 200, 0],
            vec![6, 200, 0, 0x00],
            vec![6, 0, 0, 0],
            vec![6, 0, 0, 1],
            vec![6, 0, 0, 2],
            vec![6, 0, 0, 3],
            vec![6, 0, 0, 3, 4],
        ] {
            assert!(decode_nal(&invalid).is_err());
        }
        let mut valid = encode_nal(&[0x80]).unwrap();
        valid.pop();
        assert!(decode_nal(&valid).is_err()); // A payload 0x80 cannot replace the RBSP trailing bits.
        let mut short_uuid = vec![5, 15];
        short_uuid.extend_from_slice(&[0x11; 15]);
        short_uuid.push(0x80);
        assert_eq!(
            decode_nal(&escape_rbsp(&short_uuid)),
            Err(SeiError::MalformedRbsp)
        );
        assert_eq!(
            encode_nal(&vec![0; MAX_PAYLOAD + 1]),
            Err(SeiError::PayloadTooLarge)
        );
        assert_eq!(
            decode_nal(&vec![6; MAX_NAL_SIZE + 1]),
            Err(SeiError::PayloadTooLarge)
        );
        let mut oversized = vec![5];
        write_ff_value(16 + MAX_PAYLOAD + 1, &mut oversized);
        oversized.extend_from_slice(&CARRIER_UUID);
        oversized.extend_from_slice(&vec![0x11; MAX_PAYLOAD + 1]);
        oversized.push(0x80);
        assert_eq!(
            decode_nal(&escape_rbsp(&oversized)),
            Err(SeiError::PayloadTooLarge)
        );
    }

    #[test]
    fn message_and_mutation_budgets_prevent_unbounded_parsing_or_panics() {
        let mut many = vec![];
        for _ in 0..MAX_MESSAGES + 1 {
            many.extend_from_slice(&[200, 0]);
        }
        many.push(0x80);
        assert_eq!(
            decode_nal(&escape_rbsp(&many)),
            Err(SeiError::MalformedRbsp)
        );
        let original = encode_nal(&(0..=255).collect::<Vec<_>>()).unwrap();
        for index in 0..original.len() {
            let mut changed = original.clone();
            changed[index] ^= 0xff;
            let _ = decode_nal(&changed);
        }
    }
}
