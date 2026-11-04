//! Bounded reader/writer for bincode 1.3's fixed-int little-endian
//! SerializedState layout. This is local state, not a DTLS packet format.
use super::{Error, SerializedState, HANDSHAKE_RANDOM_LENGTH};

const MAX_STATE_BYTES: usize = 16 * 1024 * 1024;
const MAX_CERTIFICATES: usize = 4096;
const LENGTH_BYTES: usize = size_of::<u64>();
const FIXED_BYTES: usize = 4 + 2 * HANDSHAKE_RANDOM_LENGTH + 2 + 8 + 2 + 3 * LENGTH_BYTES + 1;

fn invalid() -> Error {
    Error::Other("invalid DTLS state snapshot".into())
}

fn write_bytes(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    output.extend_from_slice(bytes);
}

pub(super) fn encoded_size(
    master_secret: &[u8],
    peer_certificates: &[Vec<u8>],
    identity_hint: &[u8],
) -> Result<usize, Error> {
    if peer_certificates.len() > MAX_CERTIFICATES {
        return Err(invalid());
    }
    let mut size = FIXED_BYTES
        .checked_add(master_secret.len())
        .and_then(|size| size.checked_add(identity_hint.len()))
        .ok_or_else(invalid)?;
    for certificate in peer_certificates {
        size = size
            .checked_add(LENGTH_BYTES)
            .and_then(|size| size.checked_add(certificate.len()))
            .ok_or_else(invalid)?;
    }
    if size > MAX_STATE_BYTES {
        return Err(invalid());
    }
    Ok(size)
}

pub(super) fn encode(state: &SerializedState) -> Result<Vec<u8>, Error> {
    let size = encoded_size(
        &state.master_secret,
        &state.peer_certificates,
        &state.identity_hint,
    )?;
    let mut output = Vec::new();
    output.try_reserve_exact(size).map_err(|_| invalid())?;
    output.extend_from_slice(&state.local_epoch.to_le_bytes());
    output.extend_from_slice(&state.remote_epoch.to_le_bytes());
    output.extend_from_slice(&state.local_random);
    output.extend_from_slice(&state.remote_random);
    output.extend_from_slice(&state.cipher_suite_id.to_le_bytes());
    write_bytes(&mut output, &state.master_secret);
    output.extend_from_slice(&state.sequence_number.to_le_bytes());
    output.extend_from_slice(&state.srtp_protection_profile.to_le_bytes());
    output.extend_from_slice(&(state.peer_certificates.len() as u64).to_le_bytes());
    for certificate in &state.peer_certificates {
        write_bytes(&mut output, certificate);
    }
    write_bytes(&mut output, &state.identity_hint);
    output.push(u8::from(state.is_client));
    Ok(output)
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        let (value, rest) = self.0.split_at_checked(length).ok_or_else(invalid)?;
        self.0 = rest;
        Ok(value)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| invalid())
    }

    fn length(&mut self) -> Result<usize, Error> {
        usize::try_from(u64::from_le_bytes(self.fixed()?)).map_err(|_| invalid())
    }

    fn bytes(&mut self) -> Result<Vec<u8>, Error> {
        let length = self.length()?;
        let bytes = self.take(length)?;
        let mut value = Vec::new();
        value.try_reserve_exact(length).map_err(|_| invalid())?;
        value.extend_from_slice(bytes);
        Ok(value)
    }
}

pub(super) fn decode(input: &[u8]) -> Result<SerializedState, Error> {
    // Legacy decoding tolerates bytes after a valid snapshot. Limit the
    // parsed prefix, leaving any trailing bytes outside the allocation budget.
    let mut reader = Reader(&input[..input.len().min(MAX_STATE_BYTES)]);
    let local_epoch = u16::from_le_bytes(reader.fixed()?);
    let remote_epoch = u16::from_le_bytes(reader.fixed()?);
    let local_random = reader.fixed()?;
    let remote_random = reader.fixed()?;
    let cipher_suite_id = u16::from_le_bytes(reader.fixed()?);
    let master_secret = reader.bytes()?;
    let sequence_number = u64::from_le_bytes(reader.fixed()?);
    let srtp_protection_profile = u16::from_le_bytes(reader.fixed()?);
    let count = reader.length()?;
    if count > MAX_CERTIFICATES || count > reader.0.len() / LENGTH_BYTES {
        return Err(invalid());
    }
    let mut peer_certificates = Vec::new();
    peer_certificates
        .try_reserve_exact(count)
        .map_err(|_| invalid())?;
    for _ in 0..count {
        peer_certificates.push(reader.bytes()?);
    }
    let identity_hint = reader.bytes()?;
    let is_client = match reader.fixed()? {
        [0] => false,
        [1] => true,
        _ => return Err(invalid()),
    };
    Ok(SerializedState {
        local_epoch,
        remote_epoch,
        local_random,
        remote_random,
        cipher_suite_id,
        master_secret,
        sequence_number,
        srtp_protection_profile,
        peer_certificates,
        identity_hint,
        is_client,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // bincode 1.3.3 output for the mixed snapshot below.
    const LEGACY_HEX: &str = concat!(
        "34124523",
        "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
        "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5",
        "2bc00300000000000000010203080706050403020107000200000000000000",
        "00000000000000000100000000000000300200000000000000778801",
    );

    fn legacy_bytes() -> Vec<u8> {
        LEGACY_HEX
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn fixture() -> SerializedState {
        SerializedState {
            local_epoch: 0x1234,
            remote_epoch: 0x2345,
            local_random: [0x5a; HANDSHAKE_RANDOM_LENGTH],
            remote_random: [0xa5; HANDSHAKE_RANDOM_LENGTH],
            cipher_suite_id: 0xc02b,
            master_secret: vec![1, 2, 3],
            sequence_number: 0x0102030405060708,
            srtp_protection_profile: 7,
            peer_certificates: vec![vec![], vec![0x30]],
            identity_hint: vec![0x77, 0x88],
            is_client: true,
        }
    }

    #[test]
    fn matches_legacy_bytes_and_tolerates_trailing_data() {
        let mut legacy = legacy_bytes();
        let mut expected = fixture();
        assert_eq!(encode(&expected).unwrap(), legacy);
        assert_eq!(decode(&legacy).unwrap(), expected);
        *legacy.last_mut().unwrap() = 0;
        expected.is_client = false;
        assert_eq!(encode(&expected).unwrap(), legacy);
        legacy.extend_from_slice(&[0x31, 0x32, 0x33]);
        assert_eq!(decode(&legacy).unwrap(), expected);
    }

    #[test]
    fn rejects_truncated_snapshots_and_non_boolean_values() {
        let mut legacy = legacy_bytes();
        for length in 0..legacy.len() {
            assert!(decode(&legacy[..length]).is_err());
        }
        *legacy.last_mut().unwrap() = 2;
        assert!(decode(&legacy).is_err());
    }

    #[test]
    fn rejects_unbounded_lengths_and_certificate_counts() {
        let master_length = 4 + 2 * HANDSHAKE_RANDOM_LENGTH + 2;
        let certificate_count = master_length + LENGTH_BYTES + 3 + 8 + 2;
        let legacy = legacy_bytes();
        for offset in [
            master_length,
            certificate_count,
            certificate_count + LENGTH_BYTES,
        ] {
            let mut bytes = legacy.clone();
            bytes[offset..offset + LENGTH_BYTES].copy_from_slice(&u64::MAX.to_le_bytes());
            assert!(decode(&bytes).is_err());
        }

        let mut state = fixture();
        state
            .peer_certificates
            .resize_with(MAX_CERTIFICATES + 1, Vec::new);
        assert!(encode(&state).is_err());
        let mut excessive = legacy[..certificate_count].to_vec();
        excessive.extend_from_slice(&((MAX_CERTIFICATES + 1) as u64).to_le_bytes());
        excessive.resize(excessive.len() + (MAX_CERTIFICATES + 1) * LENGTH_BYTES, 0);
        excessive.extend_from_slice(&[0; LENGTH_BYTES + 1]);
        assert!(decode(&excessive).is_err());
    }

    #[test]
    fn limits_the_snapshot_prefix_in_both_directions() {
        let mut state = fixture();
        state.master_secret = vec![0; MAX_STATE_BYTES];
        assert!(encode(&state).is_err());
        let master_length = 4 + 2 * HANDSHAKE_RANDOM_LENGTH + 2;
        let mut oversized = legacy_bytes()[..master_length].to_vec();
        oversized.extend_from_slice(&(MAX_STATE_BYTES as u64).to_le_bytes());
        oversized.extend_from_slice(&state.master_secret);
        assert!(decode(&oversized).is_err());
    }
}
