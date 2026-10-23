//! Encrypted at rest. Windows uses user-bound DPAPI; Unix supports an external
//! master-key file (including systemd LoadCredential), or a private local key.
#[cfg(not(windows))]
use ring::{
    aead,
    rand::{SecureRandom, SystemRandom},
};
use std::{
    fs, io,
    path::{Path, PathBuf},
};

pub struct Vault {
    directory: PathBuf,
}

pub fn lock_directory(directory: &Path) -> io::Result<fs::File> {
    fs::create_dir_all(directory)?;
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        options.mode(0o600);
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    }
    let lock = options.open(directory.join("instance.lock"))?;
    lock.try_lock().map_err(|_| {
        io::Error::other("Another BaleVPN process is already using this data directory")
    })?;
    Ok(lock)
}
fn failure() -> io::Error {
    io::Error::other(
        "Cannot unlock protected credentials; keep the original OS user and master key",
    )
}

pub fn private_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path.parent().ok_or_else(failure)?;
    fs::create_dir_all(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    use std::io::Write;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|e| e.error)?;
    Ok(())
}

impl Vault {
    pub fn new(directory: &Path) -> Self {
        Self {
            directory: directory.to_owned(),
        }
    }
    #[cfg(not(windows))]
    fn key(&self) -> io::Result<aead::LessSafeKey> {
        let external = std::env::var_os("BALEVPN_MASTER_KEY_FILE").or_else(|| {
            std::env::var_os("CREDENTIALS_DIRECTORY")
                .map(PathBuf::from)
                .map(|p| p.join("balevpn-master.key"))
                .filter(|p| p.is_file())
                .map(|p| p.into_os_string())
        });
        let path = external
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(|| self.directory.join("master.key"));
        if !path.exists() && external.is_none() {
            fs::create_dir_all(&self.directory)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&self.directory, fs::Permissions::from_mode(0o700))?;
            }
            let mut bytes = [0; 32];
            SystemRandom::new()
                .fill(&mut bytes)
                .map_err(|_| failure())?;
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            use std::io::Write;
            match options.open(&path) {
                Ok(mut file) => {
                    file.write_all(&bytes)?;
                    file.sync_all()?;
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if fs::metadata(&path)?.permissions().mode() & 0o077 != 0 {
                return Err(failure());
            }
        }
        let bytes = fs::read(path)?;
        Ok(aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, &bytes).map_err(|_| failure())?,
        ))
    }
    pub fn read(&self, name: &str) -> io::Result<Option<Vec<u8>>> {
        let path = self.directory.join(name);
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        #[cfg(windows)]
        {
            return dpapi(&bytes, name.as_bytes(), false).map(Some);
        }
        #[cfg(not(windows))]
        {
            if bytes.len() < 12 {
                return Err(failure());
            }
            let nonce =
                aead::Nonce::try_assume_unique_for_key(&bytes[..12]).map_err(|_| failure())?;
            let mut content = bytes[12..].to_vec();
            let plain = self
                .key()?
                .open_in_place(nonce, aead::Aad::from(name.as_bytes()), &mut content)
                .map_err(|_| failure())?;
            Ok(Some(plain.to_vec()))
        }
    }
    pub fn write(&self, name: &str, plaintext: &[u8]) -> io::Result<()> {
        #[cfg(windows)]
        let bytes = dpapi(plaintext, name.as_bytes(), true)?;
        #[cfg(not(windows))]
        let bytes = {
            let mut nonce = [0; 12];
            SystemRandom::new()
                .fill(&mut nonce)
                .map_err(|_| failure())?;
            let mut bytes = plaintext.to_vec();
            self.key()?
                .seal_in_place_append_tag(
                    aead::Nonce::assume_unique_for_key(nonce),
                    aead::Aad::from(name.as_bytes()),
                    &mut bytes,
                )
                .map_err(|_| failure())?;
            [nonce.as_slice(), &bytes].concat()
        };
        private_write(&self.directory.join(name), &bytes)
    }
    pub fn clear(&self, name: &str) -> io::Result<()> {
        match fs::remove_file(self.directory.join(name)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }
}

#[cfg(windows)]
fn dpapi(bytes: &[u8], entropy: &[u8], encrypt: bool) -> io::Result<Vec<u8>> {
    #[repr(C)]
    struct Blob {
        length: u32,
        data: *mut u8,
    }
    #[link(name = "crypt32")]
    extern "system" {
        fn CryptProtectData(
            input: *const Blob,
            description: *const u16,
            entropy: *const Blob,
            reserved: *const u8,
            prompt: *const u8,
            flags: u32,
            output: *mut Blob,
        ) -> i32;
        fn CryptUnprotectData(
            input: *const Blob,
            description: *mut *mut u16,
            entropy: *const Blob,
            reserved: *const u8,
            prompt: *const u8,
            flags: u32,
            output: *mut Blob,
        ) -> i32;
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn LocalFree(memory: *mut u8) -> *mut u8;
    }
    let input = Blob {
        length: bytes.len().try_into().map_err(|_| failure())?,
        data: bytes.as_ptr() as *mut u8,
    };
    let extra = Blob {
        length: entropy.len() as u32,
        data: entropy.as_ptr() as *mut u8,
    };
    let mut output = Blob {
        length: 0,
        data: std::ptr::null_mut(),
    };
    // All input buffers outlive the OS call; output is copied then freed with
    // LocalFree as required by DPAPI. UI prompts are explicitly prohibited.
    unsafe {
        let ok = if encrypt {
            CryptProtectData(
                &input,
                std::ptr::null(),
                &extra,
                std::ptr::null(),
                std::ptr::null(),
                1,
                &mut output,
            )
        } else {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                &extra,
                std::ptr::null(),
                std::ptr::null(),
                1,
                &mut output,
            )
        };
        if ok == 0 {
            return Err(failure());
        }
        let result = std::slice::from_raw_parts(output.data, output.length as usize).to_vec();
        LocalFree(output.data);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn data_directory_has_only_one_writer() {
        let dir = tempfile::tempdir().unwrap();
        let lock = lock_directory(dir.path()).unwrap();
        assert!(lock_directory(dir.path()).is_err());
        drop(lock);
        assert!(lock_directory(dir.path()).is_ok());
    }
    #[test]
    fn roundtrip_tampering_and_context_binding() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::new(dir.path());
        vault.write("token.bin", b"fixture-secret").unwrap();
        assert_eq!(vault.read("token.bin").unwrap().unwrap(), b"fixture-secret");
        let path = dir.path().join("token.bin");
        let mut bytes = fs::read(&path).unwrap();
        assert!(!bytes.windows(14).any(|v| v == b"fixture-secret"));
        fs::write(dir.path().join("identity.bin"), &bytes).unwrap();
        assert!(vault.read("identity.bin").is_err());
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(path, bytes).unwrap();
        assert!(vault.read("token.bin").is_err());
        vault.clear("token.bin").unwrap();
        assert!(vault.read("token.bin").unwrap().is_none());
    }
}
