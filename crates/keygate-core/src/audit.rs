//! The audit log: append-only JSON lines in a `0600` file, each one
//! `fdatasync`ed before `append` returns.
//!
//! The broker appends `Begin` *before* any upstream I/O and refuses the call
//! if that append fails, so there is no upstream effect without a durable
//! record of who caused it.

use crate::journal::{ErrorClass, StreamSummary, TicketId};
use crate::Namespace;
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Debug, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AuditEvent<'a> {
    /// About to transmit an upstream request.
    Begin {
        ticket: TicketId,
        seat: &'a str,
        uid: Option<u32>,
        namespace: Namespace,
        row: &'a str,
        method: &'a str,
        path: &'a str,
        stream: bool,
        generation: u64,
        request_digest: String,
        request_bytes: usize,
    },
    /// A buffered exchange finished.
    End {
        ticket: TicketId,
        status: u16,
        bytes: u64,
        withheld: bool,
    },
    /// A stream closed.
    StreamEnd {
        ticket: TicketId,
        summary: &'a StreamSummary,
    },
    /// An exchange ended without a usable reply. `error_class` is set when
    /// the HTTP client reported a transport failure.
    Failed {
        ticket: TicketId,
        reason: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        error_class: Option<ErrorClass>,
    },
    /// Operator action (`set`, `revoke`, `mint`, `revoke-seat`).
    Admin {
        action: &'a str,
        uid: Option<u32>,
        namespace: Option<Namespace>,
        target: &'a str,
        detail: &'a str,
    },
}

#[derive(Serialize)]
struct Line<'a> {
    ts_unix_ms: u64,
    #[serde(flatten)]
    event: &'a AuditEvent<'a>,
}

pub struct AuditLog {
    inner: Mutex<Inner>,
}

/// Maximum serialized audit record, including its trailing newline. Bounds
/// recovery memory as well; larger records are refused before modifying disk.
const MAX_RECORD_BYTES: usize = 128 << 10;

struct Inner {
    file: File,
    /// File length after the last complete, synced record.
    good_len: u64,
    /// Set when rollback or `fdatasync` leaves durability uncertain.
    poisoned: Option<String>,
    faults: Option<Arc<AuditFaults>>,
}

/// Fault injection for the audit log's storage calls (tests only).
#[doc(hidden)]
#[derive(Debug)]
pub struct AuditFaults {
    /// Write only this many bytes of the next record, then fail with
    /// `ENOSPC`. One-shot; `u64::MAX` means off.
    pub short_write_after: AtomicU64,
    pub fail_sync: AtomicBool,
    pub fail_truncate: AtomicBool,
}

impl Default for AuditFaults {
    fn default() -> Self {
        AuditFaults {
            short_write_after: AtomicU64::new(u64::MAX),
            fail_sync: AtomicBool::new(false),
            fail_truncate: AtomicBool::new(false),
        }
    }
}

fn injected(what: &str) -> io::Error {
    io::Error::other(format!("injected audit {what} failure"))
}

fn truncate_file(file: &File, len: u64, faults: Option<&AuditFaults>) -> io::Result<()> {
    if faults.is_some_and(|f| f.fail_truncate.load(Ordering::SeqCst)) {
        return Err(injected("ftruncate"));
    }
    file.set_len(len)
}

fn sync_all_file(file: &File, faults: Option<&AuditFaults>) -> io::Result<()> {
    if faults.is_some_and(|f| f.fail_sync.load(Ordering::SeqCst)) {
        return Err(injected("fsync"));
    }
    file.sync_all()
}

/// Validate complete records from byte 0, truncate an unterminated final
/// record (crash mid-append), and sync before allowing new effects. A
/// newline-terminated malformed line is corruption, including at EOF: never
/// silently discard a complete record.
fn recover(file: &mut File, faults: Option<&AuditFaults>) -> io::Result<u64> {
    file.seek(SeekFrom::Start(0))?;
    let mut good_len = 0u64;
    let mut truncated = false;
    {
        let mut reader = BufReader::new(&mut *file);
        let mut line = Vec::new();
        loop {
            line.clear();
            let n = (&mut reader)
                .take((MAX_RECORD_BYTES + 1) as u64)
                .read_until(b'\n', &mut line)?;
            if n == 0 {
                break;
            }
            if n > MAX_RECORD_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "audit record exceeds recovery size bound",
                ));
            }
            if line.last() != Some(&b'\n') {
                truncated = true;
                break;
            }
            let record: serde_json::Value = serde_json::from_slice(&line).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("corrupt audit record at byte {good_len}: {e}"),
                )
            })?;
            let valid_envelope = record.is_object()
                && record.get("event").and_then(|v| v.as_str()).is_some()
                && record.get("ts_unix_ms").and_then(|v| v.as_u64()).is_some();
            if !valid_envelope {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid audit envelope at byte {good_len}"),
                ));
            }
            good_len += n as u64;
        }
    }
    if truncated {
        truncate_file(file, good_len, faults)?;
    }
    // Persist any tail truncation and resolve any prior unsynced tail before
    // acknowledging new audit-before-effect appends.
    sync_all_file(file, faults)?;
    file.seek(SeekFrom::Start(good_len))?;
    Ok(good_len)
}

impl AuditLog {
    /// Open (creating `0600`) for readable append, recover any crash-torn
    /// tail, and sync both the file and its parent directory entry. An
    /// existing log readable by group or other is refused.
    pub fn open(path: &Path) -> io::Result<Self> {
        AuditLog::open_with_faults(path, None)
    }

    #[doc(hidden)]
    pub fn open_with_faults(path: &Path, faults: Option<Arc<AuditFaults>>) -> io::Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        crate::seal::require_regular(path, &file)?;
        let mode = file.metadata()?.mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{}: mode {mode:o} is accessible to group/other; expected 0600",
                    path.display()
                ),
            ));
        }
        let good_len = recover(&mut file, faults.as_deref())?;
        // File fsync alone does not persist a newly created directory entry.
        // Sync unconditionally in case an earlier creator died before doing so.
        crate::seal::sync_parent(path)?;
        Ok(AuditLog {
            inner: Mutex::new(Inner {
                file,
                good_len,
                poisoned: None,
                faults,
            }),
        })
    }

    /// Adopt an already-open descriptor. Recovery failures poison this writer
    /// so subsequent appends fail closed; also used by deliberately failing
    /// read-only test descriptors.
    pub fn from_file(mut file: File) -> Self {
        let recovered = crate::seal::require_regular(Path::new("audit descriptor"), &file)
            .and_then(|()| recover(&mut file, None));
        let (good_len, poisoned) = match recovered {
            Ok(len) => (len, None),
            Err(e) => (0, Some(format!("audit descriptor recovery failed: {e}"))),
        };
        AuditLog {
            inner: Mutex::new(Inner {
                file,
                good_len,
                poisoned,
                faults: None,
            }),
        }
    }

    /// Why appends are being refused, if this writer is poisoned.
    pub fn poisoned(&self) -> Option<String> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .poisoned
            .clone()
    }

    /// Append one event and force it to stable storage. Failed writes are
    /// rolled back and synced; an uncertain rollback or failed `fdatasync`
    /// poisons all subsequent appends until reopen.
    pub fn append(&self, event: &AuditEvent<'_>) -> io::Result<()> {
        let ts_unix_ms = crate::unix_time_ms().map_err(io::Error::other)?;
        let mut line = serde_json::to_vec(&Line { ts_unix_ms, event })?;
        line.push(b'\n');
        if line.len() > MAX_RECORD_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "audit record exceeds size bound",
            ));
        }
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(why) = &inner.poisoned {
            return Err(io::Error::other(format!(
                "audit log is poisoned and refuses appends until restart: {why}"
            )));
        }
        if let Err(e) = inner.write(&line) {
            // Do not leave half a line for the next event to be glued to; if
            // rollback cannot be guaranteed, poison the writer.
            if let Err(cut) = inner.rollback() {
                inner.poison(format!(
                    "append failed ({e}) and the partial record could not be removed ({cut})"
                ));
            }
            return Err(e);
        }
        if let Err(e) = inner.sync() {
            inner.poison(format!("fdatasync failed: {e}"));
            return Err(e);
        }
        inner.good_len += line.len() as u64;
        Ok(())
    }
}

impl Inner {
    fn poison(&mut self, why: String) {
        eprintln!("keygate: audit log poisoned: {why}");
        self.poisoned.get_or_insert(why);
    }

    fn write(&mut self, line: &[u8]) -> io::Result<()> {
        if let Some(faults) = &self.faults {
            let cut = faults.short_write_after.swap(u64::MAX, Ordering::SeqCst);
            if cut != u64::MAX {
                let cut = (cut as usize).min(line.len());
                self.file.write_all(&line[..cut])?;
                return Err(io::Error::from_raw_os_error(libc::ENOSPC));
            }
        }
        self.file.write_all(line)
    }

    fn sync(&self) -> io::Result<()> {
        if self
            .faults
            .as_ref()
            .is_some_and(|f| f.fail_sync.load(Ordering::SeqCst))
        {
            return Err(injected("fdatasync"));
        }
        self.file.sync_data()
    }

    fn rollback(&mut self) -> io::Result<()> {
        truncate_file(&self.file, self.good_len, self.faults.as_deref())?;
        self.sync()?;
        self.file.seek(SeekFrom::Start(self.good_len))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appends_durable_lines_at_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let log = AuditLog::open(&path).unwrap();
        log.append(&AuditEvent::Admin {
            action: "set",
            uid: Some(1),
            namespace: Some(Namespace::Service),
            target: "gh",
            detail: "",
        })
        .unwrap();
        log.append(&AuditEvent::Failed {
            ticket: TicketId::from_bytes([1; 16]),
            reason: "x",
            error_class: None,
        })
        .unwrap();
        drop(log);
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<serde_json::Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["event"], "admin");
        assert_eq!(lines[1]["ticket"], "01010101010101010101010101010101");
        assert!(lines[0]["ts_unix_ms"].as_u64().unwrap() > 0);
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);

        // Reopening appends; it never truncates.
        AuditLog::open(&path)
            .unwrap()
            .append(&AuditEvent::Failed {
                ticket: TicketId::from_bytes([2; 16]),
                reason: "y",
                error_class: None,
            })
            .unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 3);
    }

    #[test]
    fn read_only_descriptor_fails_append() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        drop(AuditLog::open(&path).unwrap());
        let log = AuditLog::from_file(File::open(&path).unwrap());
        assert!(log
            .append(&AuditEvent::Failed {
                ticket: TicketId::from_bytes([0; 16]),
                reason: "x",
                error_class: None,
            })
            .is_err());
    }

    #[test]
    fn loose_mode_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        drop(AuditLog::open(&path).unwrap());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(AuditLog::open(&path).is_err());
    }

    /// #tooth: opening an audit symlink cannot append into its target.
    #[test]
    fn tooth_audit_refuses_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        drop(AuditLog::open(&target).unwrap());
        let link = dir.path().join("audit.log");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(AuditLog::open(&link).is_err());
        assert!(std::fs::read(&target).unwrap().is_empty());
    }

    /// #tooth (K-A4, K-A6): reopen truncates and syncs an unterminated crash
    /// tail so the next `Begin` starts on a clean line; complete malformed
    /// lines (mid-file or at EOF) fail closed; short writes roll back cleanly
    /// unless rollback or `fdatasync` fails, which poisons the writer; and
    /// initial open syncs the parent directory.
    #[test]
    fn tooth_audit_torn_tail_recovery_poisoning_and_parent_sync() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");

        // Parent sync is performed on creation and its failure fails open.
        crate::seal::durability_probe::take();
        let log = AuditLog::open(&path).unwrap();
        assert_eq!(
            crate::seal::durability_probe::take(),
            vec![dir.path().to_path_buf()]
        );
        log.append(&AuditEvent::Admin {
            action: "init",
            uid: Some(0),
            namespace: None,
            target: "root",
            detail: "",
        })
        .unwrap();
        drop(log);
        let intact = std::fs::read(&path).unwrap();

        crate::seal::durability_probe::fail_dir(Some(dir.path().to_path_buf()));
        let parent_fail = AuditLog::open(&path);
        crate::seal::durability_probe::fail_dir(None);
        assert!(parent_fail.is_err());

        // Crash mid-append: unterminated tail is truncated before next Begin.
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(br#"{"ts_unix_ms":1,"event":"begin","ticket":"torn"#)
            .unwrap();
        let log = AuditLog::open(&path).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), intact);
        log.append(&AuditEvent::Begin {
            ticket: TicketId::from_bytes([1; 16]),
            seat: "a",
            uid: None,
            namespace: Namespace::Provider,
            row: "llm",
            method: "POST",
            path: "/v1/responses",
            stream: false,
            generation: 1,
            request_digest: "fixture".into(),
            request_bytes: 2,
        })
        .unwrap();
        drop(log);
        let parsed: Vec<serde_json::Value> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[1]["event"], "begin");

        // Complete malformed records (mid-file or at EOF) are never silently truncated.
        let two_lines = std::fs::read(&path).unwrap();
        let mut bad_eof = two_lines.clone();
        bad_eof.extend_from_slice(b"not-json\n");
        std::fs::write(&path, &bad_eof).unwrap();
        assert!(AuditLog::open(&path).is_err());
        let mut bad_mid = b"{\"broken\":true}\n".to_vec();
        bad_mid.extend_from_slice(&two_lines);
        std::fs::write(&path, &bad_mid).unwrap();
        assert!(AuditLog::open(&path).is_err());
        std::fs::write(&path, &two_lines).unwrap();

        // Short write rolls back cleanly; unremovable short write or failed sync poisons.
        let faults = Arc::new(AuditFaults::default());
        let log = AuditLog::open_with_faults(&path, Some(faults.clone())).unwrap();
        faults.short_write_after.store(12, Ordering::SeqCst);
        let err = log
            .append(&AuditEvent::Failed {
                ticket: TicketId::from_bytes([2; 16]),
                reason: "short",
                error_class: None,
            })
            .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ENOSPC));
        assert!(log.poisoned().is_none());
        assert_eq!(std::fs::read(&path).unwrap(), two_lines);

        faults.short_write_after.store(12, Ordering::SeqCst);
        faults.fail_truncate.store(true, Ordering::SeqCst);
        assert!(log
            .append(&AuditEvent::Failed {
                ticket: TicketId::from_bytes([3; 16]),
                reason: "unremovable",
                error_class: None,
            })
            .is_err());
        faults.fail_truncate.store(false, Ordering::SeqCst);
        assert!(log.poisoned().is_some());
        assert!(log
            .append(&AuditEvent::Failed {
                ticket: TicketId::from_bytes([4; 16]),
                reason: "blocked-by-poison",
                error_class: None,
            })
            .is_err());
        drop(log);

        // Reopen cuts the unremoved 12-byte tail; then fdatasync failure poisons too.
        let faults = Arc::new(AuditFaults::default());
        let log = AuditLog::open_with_faults(&path, Some(faults.clone())).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), two_lines);
        faults.fail_sync.store(true, Ordering::SeqCst);
        assert!(log
            .append(&AuditEvent::Failed {
                ticket: TicketId::from_bytes([5; 16]),
                reason: "unsynced",
                error_class: None,
            })
            .is_err());
        faults.fail_sync.store(false, Ordering::SeqCst);
        assert!(log.poisoned().unwrap().contains("fdatasync"));
        assert!(log
            .append(&AuditEvent::Failed {
                ticket: TicketId::from_bytes([6; 16]),
                reason: "still-poisoned",
                error_class: None,
            })
            .is_err());

        // `from_file` with a non-zero seek offset still validates from byte 0.
        let mut cursor_at_end = OpenOptions::new()
            .read(true)
            .append(true)
            .open(&path)
            .unwrap();
        cursor_at_end.seek(SeekFrom::End(0)).unwrap();
        let adopted = AuditLog::from_file(cursor_at_end);
        assert!(adopted.poisoned().is_none());
    }
}
