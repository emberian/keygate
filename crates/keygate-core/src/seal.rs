//! Sealing at rest: one `ChaCha20Poly1305` blob per row under a `0600`
//! master key, bound to its table by the AAD `("keygate-seal/v1", ns, row)`.
//!
//! A blob moved to another row name or to the other namespace's directory
//! fails authentication, so the two tables cannot be confused on disk.

use crate::secret::SecretBytes;
use crate::{valid_name, Namespace};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

const SEAL_LABEL: &[u8] = b"keygate-seal/v1";
const MAGIC: &[u8; 4] = b"KGS1";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const MASTER_KEY_LEN: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum SealError {
    #[error("invalid row name")]
    InvalidRow,
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("{path}: mode {mode:o} is accessible to group/other; expected 0600")]
    LooseMode { path: PathBuf, mode: u32 },
    #[error("{0}: master key must be exactly 32 bytes")]
    BadMasterKey(PathBuf),
    #[error("sealed blob for {ns}/{row} is malformed")]
    Malformed { ns: Namespace, row: String },
    #[error(
        "sealed blob for {ns}/{row} failed authentication (wrong key, wrong row, or tampered)"
    )]
    Unauthentic { ns: Namespace, row: String },
}

/// The broker's root secret. Sub-keys are derived per purpose so the sealing
/// key and the macaroon root key are independent.
pub struct MasterKey(SecretBytes);

impl MasterKey {
    /// Create a fresh key file. Refuses to overwrite an existing one.
    pub fn generate(path: &Path) -> Result<Self, SealError> {
        let key = SecretBytes::random(MASTER_KEY_LEN)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(key.expose())?;
        file.sync_all()?;
        sync_parent(path)?;
        Ok(MasterKey(key))
    }

    pub fn load(path: &Path) -> Result<Self, SealError> {
        let mut file = open_read_nofollow(path)?;
        let mode = file.metadata()?.mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(SealError::LooseMode {
                path: path.to_owned(),
                mode,
            });
        }
        let mut buf = Vec::with_capacity(MASTER_KEY_LEN + 1);
        file.read_to_end(&mut buf)?;
        let key = SecretBytes::new(buf);
        if key.len() != MASTER_KEY_LEN {
            return Err(SealError::BadMasterKey(path.to_owned()));
        }
        Ok(MasterKey(key))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        MasterKey(SecretBytes::new(bytes.to_vec()))
    }

    /// A 32-byte sub-key for `context` (a hardcoded, globally unique string).
    pub fn derive(&self, context: &str) -> SecretBytes {
        let mut out = blake3::derive_key(context, self.0.expose());
        let key = SecretBytes::new(out.to_vec());
        out.zeroize();
        key
    }
}

/// What a sealed row file holds. `secret` is `None` for a revoked row, which
/// keeps its epoch counters so generations stay monotonic across restarts.
pub struct SealedRow {
    pub generation: u64,
    pub revoked_floor: u64,
    pub secret: Option<SecretBytes>,
}

fn aad(ns: Namespace, row: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(SEAL_LABEL.len() + row.len() + 24);
    for part in [SEAL_LABEL, ns.as_str().as_bytes(), row.as_bytes()] {
        out.extend_from_slice(&(part.len() as u32).to_le_bytes());
        out.extend_from_slice(part);
    }
    out
}

/// The directory of sealed rows, one sub-directory per namespace.
pub struct SealStore {
    root: PathBuf,
    key: SecretBytes,
}

impl SealStore {
    pub fn new(root: &Path, master: &MasterKey) -> Self {
        SealStore {
            root: root.to_owned(),
            key: master.derive("keygate-seal/v1 aead key"),
        }
    }

    pub fn path(&self, ns: Namespace, row: &str) -> Result<PathBuf, SealError> {
        check_row(row)?;
        Ok(self.root.join(ns.dir()).join(format!("{row}.sealed")))
    }

    fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(Key::from_slice(self.key.expose()))
    }

    pub fn seal(&self, ns: Namespace, row: &str, sealed: &SealedRow) -> Result<Vec<u8>, SealError> {
        check_row(row)?;
        let secret = sealed
            .secret
            .as_ref()
            .map(SecretBytes::expose)
            .unwrap_or(&[]);
        // Reserve the tag up front so appending it cannot reallocate and
        // strand a plaintext copy in freed memory.
        let mut buf = Vec::with_capacity(17 + secret.len() + TAG_LEN);
        buf.extend_from_slice(&sealed.generation.to_le_bytes());
        buf.extend_from_slice(&sealed.revoked_floor.to_le_bytes());
        buf.push(u8::from(sealed.secret.is_some()));
        buf.extend_from_slice(secret);

        let mut nonce = [0u8; NONCE_LEN];
        crate::random_bytes(&mut nonce)?;
        if self
            .cipher()
            .encrypt_in_place(Nonce::from_slice(&nonce), &aad(ns, row), &mut buf)
            .is_err()
        {
            buf.zeroize();
            return Err(SealError::Malformed {
                ns,
                row: row.to_owned(),
            });
        }
        let mut blob = Vec::with_capacity(MAGIC.len() + NONCE_LEN + buf.len());
        blob.extend_from_slice(MAGIC);
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&buf);
        Ok(blob)
    }

    pub fn open(&self, ns: Namespace, row: &str, blob: &[u8]) -> Result<SealedRow, SealError> {
        check_row(row)?;
        let malformed = || SealError::Malformed {
            ns,
            row: row.to_owned(),
        };
        if blob.len() < MAGIC.len() + NONCE_LEN + 17 + TAG_LEN || &blob[..4] != MAGIC {
            return Err(malformed());
        }
        let nonce = Nonce::from_slice(&blob[4..4 + NONCE_LEN]);
        let mut buf = blob[4 + NONCE_LEN..].to_vec();
        if self
            .cipher()
            .decrypt_in_place(nonce, &aad(ns, row), &mut buf)
            .is_err()
        {
            buf.zeroize();
            return Err(SealError::Unauthentic {
                ns,
                row: row.to_owned(),
            });
        }
        let generation = u64::from_le_bytes(buf[0..8].try_into().expect("length checked"));
        let revoked_floor = u64::from_le_bytes(buf[8..16].try_into().expect("length checked"));
        let secret = match buf[16] {
            0 if buf.len() == 17 => None,
            1 => Some(SecretBytes::new(buf[17..].to_vec())),
            _ => {
                buf.zeroize();
                return Err(malformed());
            }
        };
        buf.zeroize();
        Ok(SealedRow {
            generation,
            revoked_floor,
            secret,
        })
    }

    /// Seal and durably replace the row file (tmp + fsync + rename + dir fsync).
    pub fn write(&self, ns: Namespace, row: &str, sealed: &SealedRow) -> Result<(), SealError> {
        let blob = self.seal(ns, row, sealed)?;
        let path = self.path(ns, row)?;
        let dir = path.parent().expect("row path has a parent");
        fs::create_dir_all(dir)?;
        write_atomic(&path, &blob)?;
        Ok(())
    }

    pub fn read(&self, ns: Namespace, row: &str) -> Result<Option<SealedRow>, SealError> {
        match open_read_nofollow(&self.path(ns, row)?) {
            Ok(mut file) => {
                let mut blob = Vec::new();
                file.read_to_end(&mut blob)?;
                self.open(ns, row, &blob).map(Some)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

fn check_row(row: &str) -> Result<(), SealError> {
    if valid_name(row) {
        Ok(())
    } else {
        Err(SealError::InvalidRow)
    }
}

pub(crate) fn open_read_nofollow(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

/// A privately owned temporary name in the destination's directory. Never
/// unlink another writer's temporary file, including after a collision.
pub(crate) struct AtomicTemp {
    path: Option<PathBuf>,
}

impl AtomicTemp {
    pub(crate) fn create(destination: &Path) -> io::Result<(Self, File)> {
        loop {
            let mut nonce = [0u8; 8];
            crate::random_bytes(&mut nonce)?;
            let mut name = destination.as_os_str().to_owned();
            name.push(format!(".tmp.{}", hex::encode(nonce)));
            let path = PathBuf::from(name);
            match OpenOptions::new()
                .append(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&path)
            {
                Ok(file) => return Ok((Self { path: Some(path) }, file)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
    }

    pub(crate) fn install(mut self, destination: &Path) -> io::Result<()> {
        fs::rename(
            self.path.as_ref().expect("temporary name owned"),
            destination,
        )?;
        self.path = None;
        Ok(())
    }
}

impl Drop for AtomicTemp {
    fn drop(&mut self) {
        if let Some(path) = &self.path {
            let _ = fs::remove_file(path);
        }
    }
}

/// Durable whole-file replace with mode `0600`.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let (tmp, mut file) = AtomicTemp::create(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    tmp.install(path)?;
    sync_parent(path)
}

pub fn sync_parent(path: &Path) -> io::Result<()> {
    match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => File::open(dir)?.sync_all(),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(dir: &Path) -> SealStore {
        SealStore::new(dir, &MasterKey::from_bytes([7u8; 32]))
    }

    fn row(secret: &[u8]) -> SealedRow {
        SealedRow {
            generation: 3,
            revoked_floor: 1,
            secret: Some(SecretBytes::new(secret.to_vec())),
        }
    }

    #[test]
    fn round_trip_and_tombstone() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        s.write(
            Namespace::Provider,
            "anthropic",
            &row(b"sk-ant-secret12345"),
        )
        .unwrap();
        let back = s.read(Namespace::Provider, "anthropic").unwrap().unwrap();
        assert_eq!((back.generation, back.revoked_floor), (3, 1));
        assert_eq!(back.secret.unwrap().expose(), b"sk-ant-secret12345");

        s.write(
            Namespace::Provider,
            "anthropic",
            &SealedRow {
                generation: 3,
                revoked_floor: 4,
                secret: None,
            },
        )
        .unwrap();
        let back = s.read(Namespace::Provider, "anthropic").unwrap().unwrap();
        assert!(back.secret.is_none());
        assert_eq!(back.revoked_floor, 4);
        assert!(s.read(Namespace::Service, "anthropic").unwrap().is_none());
    }

    /// #tooth: a sealed blob is bound to its namespace and row by the AAD.
    #[test]
    fn tooth_blob_cannot_cross_namespace_or_row() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        let blob = s
            .seal(Namespace::Provider, "shared", &row(b"provider-secret-1"))
            .unwrap();
        assert!(s.open(Namespace::Provider, "shared", &blob).is_ok());
        assert!(matches!(
            s.open(Namespace::Service, "shared", &blob),
            Err(SealError::Unauthentic { .. })
        ));
        assert!(matches!(
            s.open(Namespace::Provider, "other", &blob),
            Err(SealError::Unauthentic { .. })
        ));

        let mut flipped = blob.clone();
        *flipped.last_mut().unwrap() ^= 1;
        assert!(matches!(
            s.open(Namespace::Provider, "shared", &flipped),
            Err(SealError::Unauthentic { .. })
        ));

        let other_key = SealStore::new(dir.path(), &MasterKey::from_bytes([8u8; 32]));
        assert!(other_key
            .open(Namespace::Provider, "shared", &blob)
            .is_err());
    }

    #[test]
    fn ciphertext_does_not_contain_secret() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        let blob = s
            .seal(Namespace::Service, "gh", &row(b"ghp_plaintext_token"))
            .unwrap();
        assert!(!blob.windows(8).any(|w| w == b"ghp_plai"));
    }

    #[test]
    fn master_key_file_is_0600_and_loose_modes_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("master.key");
        MasterKey::generate(&path).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert!(MasterKey::generate(&path).is_err(), "must not overwrite");
        assert!(MasterKey::load(&path).is_ok());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            MasterKey::load(&path),
            Err(SealError::LooseMode { .. })
        ));
    }

    /// #tooth: custody reads never follow a substituted final-component symlink.
    #[test]
    fn tooth_nofollow_and_invalid_row_names() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("master.key");
        MasterKey::generate(&master).unwrap();
        let link = dir.path().join("link");
        symlink(&master, &link).unwrap();
        assert!(MasterKey::load(&link).is_err());
        let s = store(dir.path());
        s.write(Namespace::Service, "good", &row(b"secret-0123456789"))
            .unwrap();
        symlink(
            s.path(Namespace::Service, "good").unwrap(),
            s.path(Namespace::Service, "link").unwrap(),
        )
        .unwrap();
        assert!(s.read(Namespace::Service, "link").is_err());
        for bad in ["", "/tmp/escape", "../escape", "a/b", ".", ".."] {
            assert!(s.path(Namespace::Service, bad).is_err());
            assert!(s
                .seal(Namespace::Service, bad, &row(b"secret-0123456789"))
                .is_err());
            assert!(s.open(Namespace::Service, bad, b"").is_err());
            assert!(s
                .write(Namespace::Service, bad, &row(b"secret-0123456789"))
                .is_err());
            assert!(s.read(Namespace::Service, bad).is_err());
        }
    }

    /// #tooth: competing atomic writers each own a distinct 0600 temporary.
    #[test]
    fn tooth_atomic_writers_do_not_unlink_each_other() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("row.sealed");
        let fixed = dest.with_extension("tmp");
        fs::write(&fixed, b"owned by someone else").unwrap();
        let (a, fa) = AtomicTemp::create(&dest).unwrap();
        let (b, fb) = AtomicTemp::create(&dest).unwrap();
        assert_ne!(a.path, b.path);
        for (tmp, file) in [(&a, &fa), (&b, &fb)] {
            let name = tmp
                .path
                .as_ref()
                .unwrap()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap();
            let suffix = name.strip_prefix("row.sealed.tmp.").unwrap();
            assert_eq!(suffix.len(), 16);
            assert!(suffix.bytes().all(|b| b.is_ascii_hexdigit()));
            assert_eq!(file.metadata().unwrap().mode() & 0o777, 0o600);
        }
        drop(a);
        assert!(b.path.as_ref().unwrap().exists());
        drop(b);
        std::thread::scope(|scope| {
            for byte in 0..16u8 {
                let dest = &dest;
                scope.spawn(move || {
                    for _ in 0..8 {
                        write_atomic(dest, &vec![byte; 4096]).unwrap();
                    }
                });
            }
        });
        let data = fs::read(&dest).unwrap();
        assert_eq!(data.len(), 4096);
        assert!(data.iter().all(|b| *b == data[0]));
        assert_eq!(fs::read(&fixed).unwrap(), b"owned by someone else");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
    }
}
