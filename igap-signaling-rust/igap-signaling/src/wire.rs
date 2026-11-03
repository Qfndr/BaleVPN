//! Bounded protobuf wire primitives for the inspected iGap v3 protocol.
use std::collections::BTreeMap;
use std::fmt;

pub const MAX_FRAME: usize = 50 * 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error;
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid iGap protocol packet")
    }
}
impl std::error::Error for Error {}
#[derive(Clone, PartialEq, Eq)]
pub enum Value {
    Varint(u64),
    Bytes(Vec<u8>),
}
// Field contents may contain account credentials; deliberately omit Debug.
pub type Fields = BTreeMap<u32, Vec<Value>>;

pub fn varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(10);
    loop {
        let mut byte = (value & 127) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 128;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
    out
}
fn tag(id: u32, wire: u8) -> Result<Vec<u8>, Error> {
    if id == 0 || id > 0x1fff_ffff {
        return Err(Error);
    }
    Ok(varint((u64::from(id) << 3) | u64::from(wire)))
}
pub fn uint_field(id: u32, value: u64) -> Result<Vec<u8>, Error> {
    let mut out = tag(id, 0)?;
    out.extend(varint(value));
    Ok(out)
}
pub fn bytes_field(id: u32, value: &[u8]) -> Result<Vec<u8>, Error> {
    if value.len() > MAX_FRAME {
        return Err(Error);
    }
    let mut out = tag(id, 2)?;
    out.extend(varint(value.len() as u64));
    out.extend(value);
    Ok(out)
}
pub fn string_field(id: u32, value: &str, max: usize) -> Result<Vec<u8>, Error> {
    if value.len() > max {
        return Err(Error);
    }
    bytes_field(id, value.as_bytes())
}
pub fn frame(action: u16, payload: &[u8]) -> Result<Vec<u8>, Error> {
    if payload.len() > MAX_FRAME - 2 {
        return Err(Error);
    }
    let mut out = Vec::with_capacity(payload.len() + 2);
    out.extend(action.to_le_bytes());
    out.extend(payload);
    Ok(out)
}
fn read_varint(input: &[u8], at: &mut usize) -> Result<u64, Error> {
    let mut out = 0u64;
    for index in 0..10 {
        let byte = *input.get(*at).ok_or(Error)?;
        *at += 1;
        if index == 9 && byte > 1 {
            return Err(Error);
        }
        out |= u64::from(byte & 127) << (7 * index);
        if byte & 128 == 0 {
            return Ok(out);
        }
    }
    Err(Error)
}
pub fn parse(input: &[u8]) -> Result<Fields, Error> {
    if input.len() > MAX_FRAME {
        return Err(Error);
    }
    let mut out = Fields::new();
    let mut at = 0;
    let mut count = 0;
    while at < input.len() {
        count += 1;
        if count > 2048 {
            return Err(Error);
        }
        let raw = read_varint(input, &mut at)?;
        let id = u32::try_from(raw >> 3).map_err(|_| Error)?;
        if id == 0 || id > 0x1fff_ffff {
            return Err(Error);
        }
        let value = match raw & 7 {
            0 => Value::Varint(read_varint(input, &mut at)?),
            2 => {
                let length = usize::try_from(read_varint(input, &mut at)?).map_err(|_| Error)?;
                let end = at.checked_add(length).ok_or(Error)?;
                let bytes = input.get(at..end).ok_or(Error)?.to_vec();
                at = end;
                Value::Bytes(bytes)
            }
            1 | 5 => {
                let end = at
                    .checked_add(if raw & 7 == 1 { 8 } else { 4 })
                    .ok_or(Error)?;
                input.get(at..end).ok_or(Error)?;
                at = end;
                continue;
            }
            _ => return Err(Error),
        };
        out.entry(id).or_default().push(value);
    }
    Ok(out)
}
pub fn packet(input: &[u8]) -> Result<(u16, Fields), Error> {
    if !(2..=MAX_FRAME).contains(&input.len()) {
        return Err(Error);
    }
    Ok((
        u16::from_le_bytes([input[0], input[1]]),
        parse(&input[2..])?,
    ))
}
pub fn number(fields: &Fields, id: u32, max: u64) -> Result<u64, Error> {
    match fields.get(&id) {
        None => Ok(0),
        Some(values) => match values.as_slice() {
            [Value::Varint(value)] if *value <= max => Ok(*value),
            _ => Err(Error),
        },
    }
}
pub fn bytes(fields: &Fields, id: u32, max: usize) -> Result<&[u8], Error> {
    match fields.get(&id) {
        None => Ok(&[]),
        Some(values) => match values.as_slice() {
            [Value::Bytes(value)] if value.len() <= max => Ok(value),
            _ => Err(Error),
        },
    }
}
pub fn text(fields: &Fields, id: u32, max: usize) -> Result<&str, Error> {
    std::str::from_utf8(bytes(fields, id, max)?).map_err(|_| Error)
}
pub fn repeated_bytes(
    fields: &Fields,
    id: u32,
    max_count: usize,
    max_item_bytes: usize,
) -> Result<Vec<&[u8]>, Error> {
    let Some(values) = fields.get(&id) else {
        return Ok(Vec::new());
    };
    if values.len() > max_count {
        return Err(Error);
    }
    values
        .iter()
        .map(|value| match value {
            Value::Bytes(bytes) if bytes.len() <= max_item_bytes => Ok(bytes.as_slice()),
            _ => Err(Error),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_wire_parity_and_u64() {
        let bytes = uint_field(2, u64::MAX).unwrap();
        assert_eq!(
            bytes,
            vec![16, 255, 255, 255, 255, 255, 255, 255, 255, 255, 1]
        );
        let mut body = bytes;
        body.extend(string_field(3, "IR", 2).unwrap());
        let packet = frame(100, &body).unwrap();
        assert_eq!(&packet[..2], &[100, 0]);
        let (action, fields) = super::packet(&packet).unwrap();
        assert_eq!(action, 100);
        assert_eq!(number(&fields, 2, u64::MAX).unwrap(), u64::MAX);
        assert_eq!(text(&fields, 3, 2).unwrap(), "IR");
        assert_eq!(number(&fields, 9, 0).unwrap(), 0);
    }
    #[test]
    fn malformed_and_duplicate_fields_fail() {
        for bytes in [
            vec![128],
            vec![0],
            vec![10, 255, 255, 255, 255, 255, 255, 255, 255, 255, 2],
            vec![10, 3, 1],
            vec![15],
        ] {
            assert!(parse(&bytes).is_err());
        }
        let mut bytes = uint_field(2, 4).unwrap();
        bytes.extend(uint_field(2, 5).unwrap());
        assert!(number(&parse(&bytes).unwrap(), 2, 8).is_err());
        assert!(text(&parse(&[10, 1, 255]).unwrap(), 1, 8).is_err());
        assert!(parse(&vec![0; MAX_FRAME + 1]).is_err());
        assert!(frame(1, &vec![0; MAX_FRAME]).is_err());
        assert!(uint_field(0, 1).is_err());
    }
    #[test]
    fn skip_unknown_fixed_fields_and_bound_field_count() {
        assert_eq!(
            number(&parse(&[13, 0, 0, 0, 0, 16, 1]).unwrap(), 2, 1).unwrap(),
            1
        );
        assert!(parse(&vec![8; 2049]).is_err());
        let bytes = [8, 0].repeat(2049);
        assert!(parse(&bytes).is_err());
    }
}
