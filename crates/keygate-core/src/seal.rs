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
/// Format 1: `generation | revoked_floor | has_secret | secret`.
const MAGIC_V1: &[u8; 4] = b"KGS1";
/// Format 2 adds length prefixes and the retired, guard-only secrets.
const MAGIC: &[u8; 4] = b"KGS2";
/// Retired secrets kept per row for the response guard.
pub const MAX_RETIRED: usize = 8;
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
        (&mut file)
            .take(MASTER_KEY_LEN as u64 + 1)
            .read_to_end(&mut buf)?;
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
    /// Earlier secrets of this row. They are never sent anywhere; they are
    /// kept (sealed like the active one) only so the response guard keeps
    /// withholding them while they may still be valid upstream. The
    /// operator drops them with `forget`.
    pub retired: Vec<RetiredSecret>,
}

pub struct RetiredSecret {
    pub generation: u64,
    pub secret: SecretBytes,
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
        if sealed.retired.len() > MAX_RETIRED {
            return Err(SealError::Malformed {
                ns,
                row: row.to_owned(),
            });
        }
        let secret = sealed
            .secret
            .as_ref()
            .map(SecretBytes::expose)
            .unwrap_or(&[]);
        let retired_len: usize = sealed.retired.iter().map(|r| 12 + r.secret.len()).sum();
        // Reserve everything, tag included, up front so nothing here can
        // reallocate and strand a plaintext copy in freed memory.
        let mut buf = Vec::with_capacity(25 + secret.len() + retired_len + TAG_LEN);
        buf.extend_from_slice(&sealed.generation.to_le_bytes());
        buf.extend_from_slice(&sealed.revoked_floor.to_le_bytes());
        buf.push(u8::from(sealed.secret.is_some()));
        buf.extend_from_slice(&(secret.len() as u32).to_le_bytes());
        buf.extend_from_slice(secret);
        buf.extend_from_slice(&(sealed.retired.len() as u32).to_le_bytes());
        for retired in &sealed.retired {
            buf.extend_from_slice(&retired.generation.to_le_bytes());
            buf.extend_from_slice(&(retired.secret.len() as u32).to_le_bytes());
            buf.extend_from_slice(retired.secret.expose());
        }

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
        if blob.len() < MAGIC.len() + NONCE_LEN + 17 + TAG_LEN {
            return Err(malformed());
        }
        let v1 = match &blob[..4] {
            magic if magic == MAGIC => false,
            magic if magic == MAGIC_V1 => true,
            _ => return Err(malformed()),
        };
        let nonce = Nonce::from_slice(&blob[4..4 + NONCE_LEN]);
        let mut buf = zeroize::Zeroizing::new(blob[4 + NONCE_LEN..].to_vec());
        if self
            .cipher()
            .decrypt_in_place(nonce, &aad(ns, row), &mut *buf)
            .is_err()
        {
            return Err(SealError::Unauthentic {
                ns,
                row: row.to_owned(),
            });
        }
        struct Cursor<'a>(&'a [u8]);
        impl<'a> Cursor<'a> {
            fn take(&mut self, n: usize) -> Option<&'a [u8]> {
                if self.0.len() < n {
                    return None;
                }
                let (head, tail) = self.0.split_at(n);
                self.0 = tail;
                Some(head)
            }
            fn u64(&mut self) -> Option<u64> {
                Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
            }
            fn len(&mut self) -> Option<usize> {
                Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?) as usize)
            }
        }
        let mut cursor = Cursor(&buf);
        let mut parse = || -> Option<SealedRow> {
            let generation = cursor.u64()?;
            let revoked_floor = cursor.u64()?;
            let has_secret = match cursor.take(1)?[0] {
                0 => false,
                1 => true,
                _ => return None,
            };
            let mut retired = Vec::new();
            let secret_bytes = if v1 {
                cursor.take(cursor.0.len())?
            } else {
                let len = cursor.len()?;
                let secret = cursor.take(len)?;
                let count = cursor.len()?;
                if count > MAX_RETIRED {
                    return None;
                }
                for _ in 0..count {
                    let generation = cursor.u64()?;
                    let len = cursor.len()?;
                    retired.push(RetiredSecret {
                        generation,
                        secret: SecretBytes::new(cursor.take(len)?.to_vec()),
                    });
                }
                secret
            };
            if !cursor.0.is_empty() || (!has_secret && !secret_bytes.is_empty()) {
                return None;
            }
            Some(SealedRow {
                generation,
                revoked_floor,
                secret: has_secret.then(|| SecretBytes::new(secret_bytes.to_vec())),
                retired,
            })
        };
        parse().ok_or_else(malformed)
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
                (&mut file)
                    .take(MAX_SEALED_BYTES + 1)
                    .read_to_end(&mut blob)?;
                if blob.len() as u64 > MAX_SEALED_BYTES {
                    return Err(SealError::Malformed {
                        ns,
                        row: row.to_owned(),
                    });
                }
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

/// Open a custody file for reading: never through a symlink, never
/// blocking on a FIFO planted at the path, and only if what was opened is a
/// regular file. The checks are on the descriptor, not on the name.
pub(crate) fn open_read_nofollow(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    require_regular(path, &file)?;
    Ok(file)
}

pub(crate) fn require_regular(path: &Path, file: &File) -> io::Result<()> {
    if file.metadata()?.is_file() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        ))
    }
}

/// Largest sealed row read: a full secret, eight retired ones, overhead.
const MAX_SEALED_BYTES: u64 = 128 << 10;

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
            retired: Vec::new(),
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
                retired: Vec::new(),
            },
        )
        .unwrap();
        let back = s.read(Namespace::Provider, "anthropic").unwrap().unwrap();
        assert!(back.secret.is_none());
        assert_eq!(back.revoked_floor, 4);
        assert!(s.read(Namespace::Service, "anthropic").unwrap().is_none());
    }

    /// Retired secrets ride in the same authenticated blob, and blobs
    /// written by format 1 still open.
    #[test]
    fn retired_secrets_round_trip_and_format_1_still_opens() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        let mut sealed = row(b"current-secret-0003");
        sealed.retired = vec![
            RetiredSecret {
                generation: 1,
                secret: SecretBytes::new(b"retired-secret-0001".to_vec()),
            },
            RetiredSecret {
                generation: 2,
                secret: SecretBytes::new(b"retired-secret-0002".to_vec()),
            },
        ];
        s.write(Namespace::Service, "api", &sealed).unwrap();
        let back = s.read(Namespace::Service, "api").unwrap().unwrap();
        assert_eq!(back.secret.unwrap().expose(), b"current-secret-0003");
        let retired: Vec<(u64, &[u8])> = back
            .retired
            .iter()
            .map(|r| (r.generation, r.secret.expose()))
            .collect();
        assert_eq!(
            retired,
            vec![
                (1, b"retired-secret-0001".as_slice()),
                (2, b"retired-secret-0002")
            ]
        );
        let on_disk = fs::read(s.path(Namespace::Service, "api").unwrap()).unwrap();
        assert!(
            !on_disk.windows(7).any(|w| w == b"retired"),
            "retired secrets are sealed too"
        );

        // A revoked row keeps its retired secrets and no active one.
        sealed.secret = None;
        let blob = s.seal(Namespace::Service, "api", &sealed).unwrap();
        let back = s.open(Namespace::Service, "api", &blob).unwrap();
        assert!(back.secret.is_none());
        assert_eq!(back.retired.len(), 2);

        // More than the cap is refused at seal time.
        sealed.retired = (0..=MAX_RETIRED as u64)
            .map(|g| RetiredSecret {
                generation: g,
                secret: SecretBytes::new(b"retired-secret-xxxx".to_vec()),
            })
            .collect();
        assert!(s.seal(Namespace::Service, "api", &sealed).is_err());

        // Format 1, as written before retired secrets existed.
        let mut plain = Vec::new();
        plain.extend_from_slice(&7u64.to_le_bytes());
        plain.extend_from_slice(&2u64.to_le_bytes());
        plain.push(1);
        plain.extend_from_slice(b"format-one-secret");
        let nonce = [5u8; NONCE_LEN];
        s.cipher()
            .encrypt_in_place(
                Nonce::from_slice(&nonce),
                &aad(Namespace::Provider, "old"),
                &mut plain,
            )
            .unwrap();
        let v1 = [MAGIC_V1.as_slice(), &nonce, &plain].concat();
        let back = s.open(Namespace::Provider, "old", &v1).unwrap();
        assert_eq!((back.generation, back.revoked_floor), (7, 2));
        assert_eq!(back.secret.unwrap().expose(), b"format-one-secret");
        assert!(back.retired.is_empty());
        // Truncated or padded plaintext is malformed, not silently accepted.
        let mut cut = blob.clone();
        cut.truncate(cut.len() - 1);
        assert!(s.open(Namespace::Service, "api", &cut).is_err());
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
