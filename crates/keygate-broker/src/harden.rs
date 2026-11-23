//! The OS-level half of the custody boundary.
//!
//! Macaroons and peer credentials decide which *request* is served. They
//! cannot protect the broker from a process that can read its files or its
//! memory. That boundary is the operating system's: the broker runs under
//! its own uid, its state directory is private to that uid, and its memory
//! is not dumpable. This module applies and checks the parts of that which
//! a process can apply and check for itself.

use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// The uid this process acts as.
pub fn effective_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// What [`harden_process`] managed to apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hardening {
    /// `PR_SET_DUMPABLE = 0`: no core dumps, and another process of the
    /// same uid can neither `ptrace` this one nor read `/proc/<pid>/mem`.
    pub not_dumpable: bool,
    /// `RLIMIT_CORE = 0`.
    pub no_core: bool,
}

/// Make this process's memory unavailable to its own uid and keep its
/// files private: umask `077`, `RLIMIT_CORE = 0`, `PR_SET_DUMPABLE = 0`.
/// Call once at startup, before any secret is loaded.
pub fn harden_process() -> Hardening {
    rustix::process::umask(rustix::fs::Mode::from_bits_truncate(0o077));
    let no_core = rustix::process::setrlimit(
        rustix::process::Resource::Core,
        rustix::process::Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .is_ok();
    Hardening {
        not_dumpable: set_not_dumpable(),
        no_core,
    }
}

#[cfg(target_os = "linux")]
fn set_not_dumpable() -> bool {
    use rustix::process::{dumpable_behavior, set_dumpable_behavior, DumpableBehavior};
    set_dumpable_behavior(DumpableBehavior::NotDumpable).is_ok()
        && matches!(dumpable_behavior(), Ok(DumpableBehavior::NotDumpable))
}

#[cfg(not(target_os = "linux"))]
fn set_not_dumpable() -> bool {
    // No equivalent is applied here; a separated deployment refuses to
    // start without it.
    false
}

fn refuse(path: &Path, why: String) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("{}: {why}", path.display()),
    )
}

/// Every directory from `/` down to `dir` inclusive must be one that only
/// `uid` or root can rearrange. A private leaf does not protect its own
/// directory entry: whoever can write an ancestor can rename the leaf away
/// and put another in its place (substituting a state directory, or
/// rolling sealed rows and the journal back to an older copy).
///
/// A directory passes if it is owned by `uid` or root and is not group- or
/// world-writable. A sticky directory (`/tmp`) passes while writable,
/// because only an entry's owner may rename or delete it there; the entry
/// below it is then held to the same ownership rule by the next step.
///
/// `dir` must already be canonical: a symlink in the path would be resolved
/// through a directory this function never looked at.
pub fn check_trusted_dirs(dir: &Path, uid: u32) -> io::Result<()> {
    if std::fs::canonicalize(dir)? != dir {
        return Err(refuse(dir, "the path is not canonical".into()));
    }
    for ancestor in dir.ancestors() {
        let meta = std::fs::symlink_metadata(ancestor)?;
        if !meta.is_dir() {
            return Err(refuse(ancestor, "not a directory".into()));
        }
        if meta.uid() != uid && meta.uid() != 0 {
            return Err(refuse(
                ancestor,
                format!(
                    "this directory on the path belongs to uid {}, who can replace what is below it",
                    meta.uid()
                ),
            ));
        }
        let mode = meta.mode() & 0o7777;
        if mode & 0o022 != 0 && mode & 0o1000 == 0 {
            return Err(refuse(
                ancestor,
                format!(
                    "this directory on the path has mode {mode:o}: others can write it and it is \
                     not sticky, so they can replace what is below it"
                ),
            ));
        }
    }
    Ok(())
}

/// The state directory holds the master key, so it must be a real
/// directory owned by the broker's uid, closed to everyone else, and
/// reached only through directories nobody else can rearrange. Returns the
/// canonical path, which is the one the broker must use from then on.
pub fn check_state_dir(dir: &Path, broker_uid: u32) -> io::Result<PathBuf> {
    let meta = std::fs::symlink_metadata(dir)?;
    if !meta.is_dir() {
        return Err(refuse(
            dir,
            "the state directory is not a directory (symlinks are not followed)".into(),
        ));
    }
    let canonical = std::fs::canonicalize(dir)?;
    let meta = std::fs::symlink_metadata(&canonical)?;
    if meta.uid() != broker_uid {
        return Err(refuse(
            dir,
            format!(
                "the state directory is owned by uid {}, but the broker runs as uid {broker_uid}",
                meta.uid()
            ),
        ));
    }
    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(refuse(
            dir,
            format!(
                "the state directory has mode {mode:o}; it holds the master key and must be 0700"
            ),
        ));
    }
    if let Some(parent) = canonical.parent() {
        check_trusted_dirs(parent, broker_uid)?;
    }
    Ok(canonical)
}

pub const STATE_LOCK_FILE: &str = "broker.lock";

/// Exclusive ownership of a state directory across all `Broker` clones. The
/// lockfile is a stable inode that is never renamed or unlinked (locking the
/// replaceable WAL inode would fail to exclude a competing compaction). Keep
/// this descriptor open until every mutable state handle has been dropped.
pub(crate) struct StateLock {
    file: File,
}

impl Drop for StateLock {
    fn drop(&mut self) {
        // A concurrent spawn can hold a duplicate until exec closes its fds.
        // This owner has finished dropping every mutable state handle.
        while let Err(rustix::io::Errno::INTR) =
            rustix::fs::flock(&self.file, rustix::fs::FlockOperation::Unlock)
        {}
    }
}

impl StateLock {
    pub(crate) fn acquire(state: &Path, broker_uid: u32) -> io::Result<Self> {
        let path = state.join(STATE_LOCK_FILE);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)?;
        let meta = file.metadata()?;
        if !meta.is_file()
            || meta.uid() != broker_uid
            || meta.mode() & 0o077 != 0
            || meta.nlink() != 1
        {
            return Err(refuse(
                &path,
                "state lock must be a private, singly linked regular file owned by the broker"
                    .into(),
            ));
        }
        loop {
            match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => break,
                Err(rustix::io::Errno::INTR) => continue,
                Err(rustix::io::Errno::WOULDBLOCK) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        format!(
                            "{}: state directory is already owned by a running broker",
                            state.display()
                        ),
                    ));
                }
                Err(e) => return Err(io::Error::from(e)),
            }
        }
        Ok(StateLock { file })
    }
}

/// Whether another live `Broker` handle currently holds `<state>/broker.lock`.
#[doc(hidden)]
pub fn state_is_locked(state: &Path) -> bool {
    matches!(
        StateLock::acquire(state, effective_uid()),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock
    )
}

/// Read an optional private custody file inside an already-checked state
/// directory (`seats.json`): no symlink traversal, nonblocking, regular file,
/// `0600` owned by the broker, and bounded in size.
pub(crate) fn read_state_file(
    path: &Path,
    broker_uid: u32,
    max_bytes: u64,
) -> io::Result<Option<Vec<u8>>> {
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(refuse(path, "state file is not a regular file".into()));
    }
    if meta.uid() != broker_uid {
        return Err(refuse(
            path,
            format!(
                "state file belongs to uid {}, expected broker uid {broker_uid}",
                meta.uid()
            ),
        ));
    }
    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(refuse(
            path,
            format!("state file has mode {mode:o}; expected 0600"),
        ));
    }
    let mut bytes = Vec::new();
    file.take(max_bytes + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(refuse(
            path,
            format!("state file exceeds {max_bytes}-byte limit"),
        ));
    }
    Ok(Some(bytes))
}

/// Largest config file read.
const MAX_CONFIG_BYTES: u64 = 1 << 20;

/// Read a config file whose contents decide where secrets are sent. It
/// must be a regular file (no symlink), owned by the broker's uid or root,
/// writable by nobody else, and in a directory nobody else can rearrange.
pub fn read_config(path: &Path, broker_uid: u32) -> io::Result<String> {
    let name = path
        .file_name()
        .ok_or_else(|| refuse(path, "not a file path".into()))?;
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let dir = std::fs::canonicalize(parent.unwrap_or(Path::new(".")))?;
    check_trusted_dirs(&dir, broker_uid)?;
    // Non-blocking so a FIFO planted at the path cannot hang startup; the
    // checks below are on the opened descriptor, not on the name.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(dir.join(name))?;
    check_config_file(path, &file, broker_uid)?;
    let mut text = String::new();
    file.take(MAX_CONFIG_BYTES + 1).read_to_string(&mut text)?;
    if text.len() as u64 > MAX_CONFIG_BYTES {
        return Err(refuse(path, "the config is larger than 1 MiB".into()));
    }
    Ok(text)
}

fn check_config_file(path: &Path, file: &File, broker_uid: u32) -> io::Result<()> {
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(refuse(path, "the config is not a regular file".into()));
    }
    if meta.uid() != broker_uid && meta.uid() != 0 {
        return Err(refuse(
            path,
            format!("the config is owned by uid {}; it must belong to the broker (uid {broker_uid}) or root", meta.uid()),
        ));
    }
    let mode = meta.mode() & 0o777;
    if mode & 0o022 != 0 {
        return Err(refuse(
            path,
            format!("the config has mode {mode:o}; whoever can write it chooses where secrets are sent, so it must not be group- or world-writable"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn chmod(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// #tooth: a state directory open to others, owned by someone else, or
    /// reached through a symlink is refused.
    #[test]
    fn tooth_state_dir_custody() {
        let uid = effective_uid();
        let parent = tempfile::tempdir().unwrap();
        chmod(parent.path(), 0o755);
        let dir = parent.path().join("state");
        std::fs::create_dir(&dir).unwrap();
        chmod(&dir, 0o700);
        check_state_dir(&dir, uid).unwrap();
        for loose in [0o750, 0o705, 0o777, 0o701] {
            chmod(&dir, loose);
            assert!(check_state_dir(&dir, uid).is_err(), "{loose:o}");
        }
        chmod(&dir, 0o700);
        assert!(
            check_state_dir(&dir, uid + 1).is_err(),
            "someone else's directory"
        );
        let link = parent.path().join("link");
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        assert!(check_state_dir(&link, uid).is_err(), "symlink");
        assert!(check_state_dir(&parent.path().join("missing"), uid).is_err());
    }

    /// #tooth: a config that others can write, or that is not the broker's,
    /// or a symlink, is refused before it is parsed.
    #[test]
    fn tooth_config_custody() {
        let uid = effective_uid();
        let dir = tempfile::tempdir().unwrap();
        chmod(dir.path(), 0o755);
        let path = dir.path().join("keygate.toml");
        std::fs::write(&path, "x = 1\n").unwrap();
        for ok in [0o600, 0o640, 0o644, 0o400] {
            chmod(&path, ok);
            assert_eq!(read_config(&path, uid).unwrap(), "x = 1\n", "{ok:o}");
        }
        for writable in [0o660, 0o606, 0o666, 0o622] {
            chmod(&path, writable);
            let err = read_config(&path, uid).unwrap_err();
            assert!(err.to_string().contains("writable"), "{writable:o}: {err}");
        }
        chmod(&path, 0o600);
        assert!(
            read_config(&path, uid + 1).is_err(),
            "someone else's config"
        );
        let link = dir.path().join("link.toml");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read_config(&link, uid).is_err(), "symlink");
        assert!(read_config(dir.path(), uid).is_err(), "directory");
    }

    /// #tooth (parent K-P2): a private state directory under an ancestor
    /// that others can write is refused, because they could rename it away
    /// and substitute another. Sticky ancestors and private ones pass.
    /// The check never changes any mode.
    #[test]
    fn tooth_untrusted_ancestors_are_refused() {
        let uid = effective_uid();
        let top = tempfile::tempdir().unwrap();
        chmod(top.path(), 0o755);
        let top_path = std::fs::canonicalize(top.path()).unwrap();
        let middle = top_path.join("shared");
        let state = middle.join("deeper").join("state");
        std::fs::create_dir_all(&state).unwrap();
        chmod(&state, 0o700);
        chmod(&middle.join("deeper"), 0o755);
        let config = middle.join("deeper").join("keygate.toml");
        std::fs::write(&config, "x = 1\n").unwrap();
        chmod(&config, 0o600);
        let mode = |p: &Path| std::fs::metadata(p).unwrap().mode() & 0o7777;

        for (ancestor_mode, trusted) in [
            (0o755, true),
            (0o700, true),
            (0o1777, true),
            (0o1775, true),
            (0o777, false),
            (0o775, false),
            (0o757, false),
        ] {
            chmod(&middle, ancestor_mode);
            assert_eq!(
                check_state_dir(&state, uid).is_ok(),
                trusted,
                "state under {ancestor_mode:o}"
            );
            assert_eq!(
                read_config(&config, uid).is_ok(),
                trusted,
                "config under {ancestor_mode:o}"
            );
            assert_eq!(
                check_trusted_dirs(&middle.join("deeper"), uid).is_ok(),
                trusted
            );
            assert_eq!(mode(&middle), ancestor_mode, "the check changed a mode");
            assert_eq!(mode(&state), 0o700);
        }
        chmod(&middle, 0o777);
        let err = check_state_dir(&state, uid).unwrap_err().to_string();
        assert!(
            err.contains("shared") && err.contains("not sticky"),
            "{err}"
        );
        // Someone else's directory on the path is refused whatever its mode.
        chmod(&middle, 0o755);
        assert!(check_trusted_dirs(&middle, uid + 1).is_err());
        // The canonical path comes back, and a path through a symlink is
        // judged by where it really leads.
        assert_eq!(check_state_dir(&state, uid).unwrap(), state);
        let alias = top_path.join("alias");
        std::os::unix::fs::symlink(&middle, &alias).unwrap();
        assert_eq!(
            check_state_dir(&alias.join("deeper").join("state"), uid).unwrap(),
            state
        );
        assert!(
            check_trusted_dirs(&alias.join("deeper"), uid).is_err(),
            "not canonical"
        );
        chmod(&middle, 0o777);
        assert!(check_state_dir(&alias.join("deeper").join("state"), uid).is_err());
        chmod(&middle, 0o755);
    }

    /// #tooth (parent K-P2): a FIFO planted where the config should be
    /// does not hang startup.
    #[test]
    fn tooth_fifo_config_does_not_block() {
        let uid = effective_uid();
        let dir = tempfile::tempdir().unwrap();
        chmod(dir.path(), 0o755);
        let path = dir.path().join("keygate.toml");
        let made = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap();
        assert!(made.success());
        let started = std::time::Instant::now();
        let err = read_config(&path, uid).unwrap_err();
        assert!(err.to_string().contains("not a regular file"), "{err}");
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    /// #tooth (K-A3): `StateLock` excludes a second opener until dropped and
    /// refuses symlinks, loose modes and additional hard links.
    #[test]
    fn tooth_state_lock_is_exclusive_and_validates_custody() {
        let uid = effective_uid();
        let dir = tempfile::tempdir().unwrap();
        chmod(dir.path(), 0o700);
        let first = StateLock::acquire(dir.path(), uid).unwrap();
        let err = StateLock::acquire(dir.path(), uid).err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        let inherited = first.file.try_clone().unwrap();
        drop(first);
        let second = StateLock::acquire(dir.path(), uid).unwrap();
        drop(inherited);
        drop(second);

        let lock_path = dir.path().join(STATE_LOCK_FILE);
        chmod(&lock_path, 0o640);
        assert!(StateLock::acquire(dir.path(), uid).is_err());
        chmod(&lock_path, 0o600);

        let hard = dir.path().join("extra.link");
        std::fs::hard_link(&lock_path, &hard).unwrap();
        assert!(StateLock::acquire(dir.path(), uid).is_err());
        std::fs::remove_file(&hard).unwrap();
        std::fs::remove_file(&lock_path).unwrap();

        let target = dir.path().join("target");
        std::fs::write(&target, b"").unwrap();
        chmod(&target, 0o600);
        std::os::unix::fs::symlink(&target, &lock_path).unwrap();
        assert!(StateLock::acquire(dir.path(), uid).is_err());
    }
}
