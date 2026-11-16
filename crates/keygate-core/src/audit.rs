//! The audit log: append-only JSON lines in a `0600` file, each one
//! `fdatasync`ed before `append` returns.
//!
//! The broker appends `Begin` *before* any upstream I/O and refuses the call
//! if that append fails, so there is no upstream effect without a durable
//! record of who caused it.

use crate::journal::{StreamSummary, TicketId};
use crate::Namespace;
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::Mutex;

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
    /// An exchange ended without a usable reply.
    Failed { ticket: TicketId, reason: &'a str },
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
    file: Mutex<File>,
}

impl AuditLog {
    /// Open (creating `0600`) for append. An existing log readable by
    /// group or other is refused rather than silently tightened.
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(path)?;
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
        Ok(AuditLog::from_file(file))
    }

    /// Adopt an already-open descriptor (must be in append mode).
    pub fn from_file(file: File) -> Self {
        AuditLog {
            file: Mutex::new(file),
        }
    }

    /// Append one event and force it to stable storage.
    pub fn append(&self, event: &AuditEvent<'_>) -> io::Result<()> {
        let mut line = serde_json::to_vec(&Line {
            ts_unix_ms: crate::now_unix_ms(),
            event,
        })?;
        line.push(b'\n');
        let mut file = self
            .file
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        file.write_all(&line)?;
        file.sync_data()
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
                reason: "x"
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
}
