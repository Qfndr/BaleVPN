//! Connection-security primitives only. TLS remains required at the WS layer.
use crate::wire::{self, Error, Fields, MAX_FRAME};
use aes::Aes256;
use aes_gcm::{
    aead::{
        consts::{U12, U16},
        Aead, KeyInit,
    },
    AesGcm,
};
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use rand::{rngs::OsRng, RngCore};
use rsa::{pkcs8::DecodePublicKey, traits::PublicKeyParts, Pkcs1v15Encrypt, RsaPublicKey};

pub const ROOT_KEY:&str="-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo+inlAfd8Qior8IMKaJ+\nBREJcEc9J9RhHgh6g/LvHKsnMaiEbAL70jQBQTLpCRu5Cnpj20+isOi++Wtf/pIP\nFdJbD/1H+5jS+ja0RA6unp93DnBuYZ2JjV60vF3Ynj6F4Vr1ts5Xg5dJlEaOcOO2\nYzOU97ZGP0ozrXIT5S+Y0BC4M9ieQmlGREzt3UZlTBbyUYPS4mMFh88YcT3QTiTA\nk897qlJLxkYxVyAgwAD/0ihmWEkBQe9IxwVT/x5/QbixGSl4Zvd+5d+9sTZcSZQS\niJInT4E6DcmgAVYu5jFMWJDTEuurOQZ1W4nbmGyoY1bZXaFoiMPfzy72VIddkoHg\nmwIDAQAB\n-----END PUBLIC KEY-----";
#[derive(Clone)]
pub struct Greeting {
    pub public_key: String,
    pub key_length: usize,
    pub chunk_size: usize,
    pub heartbeat_seconds: u32,
}
impl std::fmt::Debug for Greeting {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Greeting")
            .field("key_length", &self.key_length)
            .field("chunk_size", &self.chunk_size)
            .field("heartbeat_seconds", &self.heartbeat_seconds)
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cipher {
    Cbc,
    Gcm12,
    Gcm16,
}
impl Cipher {
    pub fn iv_size(self) -> usize {
        match self {
            Self::Cbc | Self::Gcm16 => 16,
            Self::Gcm12 => 12,
        }
    }
}
fn expected_packet(input: &[u8], expected: u16) -> Result<Fields, Error> {
    let (action, fields) = wire::packet(input)?;
    if action != expected {
        return Err(Error);
    }
    Ok(fields)
}
pub fn decode_greeting(input: &[u8]) -> Result<Greeting, Error> {
    let fields = expected_packet(input, 30001)?;
    let public_key = wire::text(&fields, 2, 8192)?.to_owned();
    let key_length = wire::number(&fields, 3, u32::MAX.into())? as usize;
    let chunk_size = wire::number(&fields, 6, u32::MAX.into())? as usize;
    if key_length != 32 || !(1..=245).contains(&chunk_size) {
        return Err(Error);
    }
    let key = RsaPublicKey::from_public_key_pem(&public_key).map_err(|_| Error)?;
    if !(1024..=4096).contains(&key.n().bits()) {
        return Err(Error);
    }
    Ok(Greeting {
        public_key,
        key_length,
        chunk_size,
        heartbeat_seconds: wire::number(&fields, 4, u32::MAX.into())? as u32,
    })
}
pub fn decode_accepted(input: &[u8]) -> Result<Cipher, Error> {
    let fields = expected_packet(input, 30002)?;
    if wire::number(&fields, 2, 1)? != 1 || wire::number(&fields, 5, 1)? != 0 {
        return Err(Error);
    }
    match (wire::text(&fields, 3, 64)?, wire::number(&fields, 4, 16)?) {
        ("AES-256-CBC", 16) => Ok(Cipher::Cbc),
        ("AES-256-GCM", 12) => Ok(Cipher::Gcm12),
        ("AES-256-GCM", 16) => Ok(Cipher::Gcm16),
        _ => Err(Error),
    }
}
pub fn key_exchange(greeting: &Greeting, key: &[u8; 32]) -> Result<Vec<u8>, Error> {
    key_exchange_with_root(greeting, key, ROOT_KEY)
}
fn key_exchange_with_root(
    greeting: &Greeting,
    key: &[u8; 32],
    root: &str,
) -> Result<Vec<u8>, Error> {
    if greeting.key_length != 32 || !(1..=245).contains(&greeting.chunk_size) {
        return Err(Error);
    }
    let inner = RsaPublicKey::from_public_key_pem(&greeting.public_key).map_err(|_| Error)?;
    let root = RsaPublicKey::from_public_key_pem(root).map_err(|_| Error)?;
    if !(1024..=4096).contains(&inner.n().bits())
        || root.n().bits() != 2048
        || greeting.chunk_size > root.size() - 11
    {
        return Err(Error);
    }
    let encrypted = inner
        .encrypt(&mut OsRng, Pkcs1v15Encrypt, key)
        .map_err(|_| Error)?;
    let mut outer = Vec::new();
    for chunk in encrypted.chunks(greeting.chunk_size) {
        outer.extend(
            root.encrypt(&mut OsRng, Pkcs1v15Encrypt, chunk)
                .map_err(|_| Error)?,
        );
    }
    let mut body = wire::bytes_field(1, &[])?;
    body.extend(wire::bytes_field(2, &outer)?);
    body.extend(wire::uint_field(3, 2)?);
    wire::frame(2, &body)
}
pub fn encrypt(plain: &[u8], key: &[u8; 32], cipher: Cipher) -> Result<Vec<u8>, Error> {
    let mut iv = vec![0; cipher.iv_size()];
    OsRng.fill_bytes(&mut iv);
    encrypt_with_iv(plain, key, cipher, &iv)
}
fn encrypt_with_iv(
    plain: &[u8],
    key: &[u8; 32],
    cipher: Cipher,
    iv: &[u8],
) -> Result<Vec<u8>, Error> {
    if plain.len() > MAX_FRAME || iv.len() != cipher.iv_size() {
        return Err(Error);
    }
    let encrypted = match cipher {
        Cipher::Cbc => {
            let mut buffer = vec![0; plain.len() + 16];
            buffer[..plain.len()].copy_from_slice(plain);
            cbc::Encryptor::<Aes256>::new_from_slices(key, iv)
                .map_err(|_| Error)?
                .encrypt_padded_mut::<Pkcs7>(&mut buffer, plain.len())
                .map_err(|_| Error)?
                .to_vec()
        }
        Cipher::Gcm12 => AesGcm::<Aes256, U12>::new_from_slice(key)
            .map_err(|_| Error)?
            .encrypt(iv.into(), plain)
            .map_err(|_| Error)?,
        Cipher::Gcm16 => AesGcm::<Aes256, U16>::new_from_slice(key)
            .map_err(|_| Error)?
            .encrypt(iv.into(), plain)
            .map_err(|_| Error)?,
    };
    let mut out = iv.to_vec();
    out.extend(encrypted);
    Ok(out)
}
pub fn decrypt(input: &[u8], key: &[u8; 32], cipher: Cipher) -> Result<Vec<u8>, Error> {
    let iv_size = cipher.iv_size();
    let tag_size = if cipher == Cipher::Cbc { 0 } else { 16 };
    if input.len() < iv_size + tag_size + 1 || input.len() > MAX_FRAME + 64 {
        return Err(Error);
    }
    let (iv, encrypted) = input.split_at(iv_size);
    let plain = match cipher {
        Cipher::Cbc => {
            let mut buffer = encrypted.to_vec();
            cbc::Decryptor::<Aes256>::new_from_slices(key, iv)
                .map_err(|_| Error)?
                .decrypt_padded_mut::<Pkcs7>(&mut buffer)
                .map_err(|_| Error)?
                .to_vec()
        }
        Cipher::Gcm12 => AesGcm::<Aes256, U12>::new_from_slice(key)
            .map_err(|_| Error)?
            .decrypt(iv.into(), encrypted)
            .map_err(|_| Error)?,
        Cipher::Gcm16 => AesGcm::<Aes256, U16>::new_from_slice(key)
            .map_err(|_| Error)?
            .decrypt(iv.into(), encrypted)
            .map_err(|_| Error)?,
    };
    if plain.len() > MAX_FRAME {
        return Err(Error);
    }
    Ok(plain)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pin_is_valid_and_accepted_cipher_is_exact() {
        assert_eq!(
            RsaPublicKey::from_public_key_pem(ROOT_KEY)
                .unwrap()
                .n()
                .bits(),
            2048
        );
        for (method, iv, cipher) in [
            ("AES-256-CBC", 16, Cipher::Cbc),
            ("AES-256-GCM", 12, Cipher::Gcm12),
            ("AES-256-GCM", 16, Cipher::Gcm16),
        ] {
            let mut body = wire::uint_field(2, 1).unwrap();
            body.extend(wire::string_field(3, method, 64).unwrap());
            body.extend(wire::uint_field(4, iv).unwrap());
            assert_eq!(
                decode_accepted(&wire::frame(30002, &body).unwrap()).unwrap(),
                cipher
            );
            body.extend(wire::uint_field(5, 1).unwrap());
            assert!(decode_accepted(&wire::frame(30002, &body).unwrap()).is_err());
        }
        assert!(decode_accepted(&[50, 117]).is_err());
    }
    #[test]
    fn encrypted_roundtrip_random_iv_and_gcm_tamper() {
        for cipher in [Cipher::Cbc, Cipher::Gcm12, Cipher::Gcm16] {
            let key = [0x31; 32];
            let plain = b"fixture-private-protocol-data";
            let a = encrypt(plain, &key, cipher).unwrap();
            let b = encrypt(plain, &key, cipher).unwrap();
            assert_ne!(a, b);
            assert_eq!(decrypt(&a, &key, cipher).unwrap(), plain);
            assert!(decrypt(&a[..5], &key, cipher).is_err());
            if cipher != Cipher::Cbc {
                let mut bad = a;
                *bad.last_mut().unwrap() ^= 1;
                assert!(decrypt(&bad, &key, cipher).is_err());
            }
        }
    }
    #[test]
    fn handshake_is_bounded_and_errors_are_redacted() {
        let mut fields = wire::string_field(2, ROOT_KEY, 8192).unwrap();
        fields.extend(wire::uint_field(3, 32).unwrap());
        fields.extend(wire::uint_field(6, 245).unwrap());
        let greeting = decode_greeting(&wire::frame(30001, &fields).unwrap()).unwrap();
        let packet = key_exchange(&greeting, &[5; 32]).unwrap();
        let (action, fields) = wire::packet(&packet).unwrap();
        assert_eq!(action, 2);
        assert_eq!(wire::number(&fields, 3, 2).unwrap(), 2);
        assert_eq!(wire::bytes(&fields, 2, 1024).unwrap().len(), 512);
        assert!(!format!("{greeting:?}").contains("BEGIN"));
        assert_eq!(Error.to_string(), "invalid iGap protocol packet");
    }
    #[test]
    fn exact_node_crypto_cipher_vectors() {
        fn hex(value: &str) -> Vec<u8> {
            value
                .as_bytes()
                .chunks_exact(2)
                .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
                .collect()
        }
        for(cipher,expected)in[(Cipher::Cbc,"23232323232323232323232323232323034e955db458fa4a71e227196796d97dc75241a4da6e4cf3a9e6894bcaafbd6e"),(Cipher::Gcm12,"2323232323232323232323237f0dfa7651287a710fe8e6b7f3e346e9c772b98de3ab98bba39c7e3b2666883d5e410760af5707811a9459966f"),(Cipher::Gcm16,"232323232323232323232323232323231b09cb6720e11f638ef24251334c4e6c962785204103605f70f610ed6ffc000e9de85c12211be61ad83f2e3aa1")]{let expected=hex(expected);let encoded=encrypt_with_iv(b"fixture-private-protocol-data",&[0x31;32],cipher,&vec![0x23;cipher.iv_size()]).unwrap();assert_eq!(encoded,expected);assert_eq!(decrypt(&expected,&[0x31;32],cipher).unwrap(),b"fixture-private-protocol-data");}
    }
    #[test]
    fn nested_rsa_chunk_exchange_recovers_exact_fresh_session_key() {
        use rsa::{
            pkcs8::{EncodePublicKey, LineEnding},
            RsaPrivateKey,
        };
        let inner = RsaPrivateKey::new(&mut OsRng, 1024).unwrap();
        let outer = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let greeting = Greeting {
            public_key: inner
                .to_public_key()
                .to_public_key_pem(LineEnding::LF)
                .unwrap(),
            key_length: 32,
            chunk_size: 64,
            heartbeat_seconds: 30,
        };
        let root = outer
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        let bytes = key_exchange_with_root(&greeting, &[0x37; 32], &root).unwrap();
        let (_, fields) = wire::packet(&bytes).unwrap();
        let encrypted = wire::bytes(&fields, 2, 1024).unwrap();
        assert_eq!(encrypted.len(), 512);
        let mut combined = Vec::new();
        for chunk in encrypted.chunks(256) {
            combined.extend(outer.decrypt(Pkcs1v15Encrypt, chunk).unwrap());
        }
        assert_eq!(combined.len(), 128);
        assert_eq!(
            inner.decrypt(Pkcs1v15Encrypt, &combined).unwrap(),
            [0x37; 32]
        );
    }
}
