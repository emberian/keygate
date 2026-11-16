//! `#tooth`: the journal and audit log on a filesystem that is actually
//! full.
//!
//! The unit tests inject short writes; this one gets them from the kernel.
//! The test re-executes itself inside a `bwrap` sandbox whose only writable
//! filesystem is a 192 KiB tmpfs, fills it, and checks that every failed
//! append left the files parseable and the in-memory state unchanged.
//! Without `bwrap` (or without unprivileged user namespaces) it reports
//! that it was skipped.

use keygate_core::audit::{AuditEvent, AuditLog};
use keygate_core::journal::{
    Begin, CallKind, Charge, Journal, JournalError, NewTicket, TicketId, TicketState,
};
use keygate_core::Namespace;
use std::path::Path;
use std::process::Command;

const INSIDE: &str = "KEYGATE_ENOSPC_SANDBOX_DIR";
const TMPFS_BYTES: &str = "196608";
const ENOSPC: i32 = 28;

fn ticket(n: u32) -> NewTicket {
    let mut digest = [0u8; 32];
    digest[..4].copy_from_slice(&n.to_le_bytes());
    NewTicket {
        seat: "seat".into(),
        digest,
        namespace: Namespace::Provider,
        row: "llm".into(),
        kind: CallKind::Buffered,
        charges: vec![Charge {
            key: "k".into(),
            cap_micro_usd: Some(u64::MAX),
        }],
        reserve_micro_usd: 1,
        now_unix_s: keygate_core::unix_time().unwrap(),
        live_ttl_s: 3600,
    }
}

fn is_enospc(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(ENOSPC)
}

fn inside(dir: &Path) {
    // Space that can be given back later.
    let filler = dir.join("filler");
    std::fs::write(&filler, vec![0u8; 64 << 10]).unwrap();

    // The audit log first: fill the disk with events.
    let audit_path = dir.join("audit.log");
    let audit = AuditLog::open(&audit_path).unwrap();
    let mut written = 0u32;
    let err = loop {
        let event = AuditEvent::Failed {
            ticket: TicketId::from_bytes([7; 16]),
            reason: "filling the disk with audit lines until the filesystem refuses",
        };
        match audit.append(&event) {
            Ok(()) => written += 1,
            Err(e) => break e,
        }
        assert!(written < 100_000, "the tmpfs never filled");
    };
    assert!(is_enospc(&err), "expected ENOSPC, got {err}");
    let log = std::fs::read(&audit_path).unwrap();
    assert_eq!(log.last(), Some(&b'\n'), "audit log ends in half a line");
    let lines: Vec<&[u8]> = log
        .split(|&b| b == b'\n')
        .filter(|l| !l.is_empty())
        .collect();
    assert_eq!(
        lines.len() as u32,
        written,
        "only acknowledged events are in the log"
    );
    for line in lines {
        serde_json::from_slice::<serde_json::Value>(line).expect("every audit line is whole");
    }
    drop(audit);
    std::fs::remove_file(&audit_path).unwrap();

    // Now the journal, with no compaction to rescue it.
    let path = dir.join("journal.wal");
    let journal = Journal::open(&path, u64::MAX, 3600).unwrap();
    let mut acked = Vec::new();
    let err = loop {
        match journal.authorize(ticket(acked.len() as u32)) {
            Ok((ticket, existing)) => {
                assert!(!existing);
                acked.push(ticket.id);
            }
            Err(e) => break e,
        }
        assert!(acked.len() < 100_000, "the tmpfs never filled");
    };
    assert!(
        matches!(&err, JournalError::Io(e) if is_enospc(e)),
        "expected ENOSPC, got {err}"
    );
    assert!(
        acked.len() > 50,
        "only {} tickets fit; the test needs a real fill",
        acked.len()
    );

    let check = |journal: &Journal, tickets: usize| {
        assert_eq!(
            journal.poisoned(),
            None,
            "a short write that was cut back does not poison"
        );
        assert_eq!(journal.stats().tickets, tickets);
        assert_eq!(
            journal.spent("k"),
            tickets as u64,
            "a refused reservation was charged"
        );
        let file = std::fs::read(&path).unwrap();
        assert_eq!(file.last(), Some(&b'\n'), "journal ends in a torn record");
        assert_eq!(file.iter().filter(|&&b| b == b'\n').count(), tickets);
    };
    check(&journal, acked.len());

    // Still full: every kind of commit keeps failing, and keeps failing
    // cleanly.
    let full = std::fs::read(&path).unwrap();
    for attempt in 0..20u32 {
        let err = journal.authorize(ticket(1_000_000 + attempt)).unwrap_err();
        assert!(matches!(&err, JournalError::Io(e) if is_enospc(e)), "{err}");
    }
    assert!(journal.begin(acked[0]).is_err_and(|e| is_enospc(&e)));
    assert_eq!(
        journal.get(acked[0]).unwrap().state,
        TicketState::Live,
        "the claim was not acknowledged"
    );
    assert_eq!(
        std::fs::read(&path).unwrap(),
        full,
        "failed appends left bytes behind"
    );
    check(&journal, acked.len());

    // Space comes back: the same journal carries on where it left off.
    std::fs::remove_file(&filler).unwrap();
    let (later, _) = journal.authorize(ticket(acked.len() as u32)).unwrap();
    assert!(matches!(journal.begin(acked[0]).unwrap(), Begin::Started));
    drop(journal);

    // And it boots. Before the fix a torn record in mid-file made this
    // `Corrupt` and the broker would not start.
    let journal = Journal::open(&path, u64::MAX, 3600).expect("journal replays after ENOSPC");
    assert_eq!(journal.stats().tickets, acked.len() + 1);
    assert_eq!(journal.spent("k"), acked.len() as u64 + 1);
    assert_eq!(journal.get(later.id).unwrap().state, TicketState::Live);
    assert_eq!(journal.get(acked[0]).unwrap().state, TicketState::Uncertain);
    println!(
        "enospc: {} tickets and {written} audit lines fit; all failures were clean",
        acked.len()
    );
}

#[test]
fn tooth_real_enospc_leaves_journal_and_audit_log_whole() {
    if let Ok(dir) = std::env::var(INSIDE) {
        return inside(Path::new(&dir));
    }
    // Any existing directory will do as the mount point; the root itself
    // is read-only inside the sandbox.
    let Some(mount) = ["/mnt", "/media", "/srv"]
        .into_iter()
        .find(|d| Path::new(d).is_dir())
    else {
        eprintln!("SKIPPED: no mount point for the sandbox tmpfs");
        return;
    };
    let sandbox = |program: &std::ffi::OsStr, args: &[&str]| {
        let mut command = Command::new("bwrap");
        command
            .args(["--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc"])
            .args(["--size", TMPFS_BYTES, "--tmpfs", mount])
            .arg(program)
            .args(args)
            .env(INSIDE, mount);
        command
    };
    match sandbox("true".as_ref(), &[]).env_remove(INSIDE).output() {
        Ok(probe) if probe.status.success() => {}
        Ok(probe) => {
            eprintln!(
                "SKIPPED: bwrap cannot build the sandbox here: {}",
                String::from_utf8_lossy(&probe.stderr).trim()
            );
            return;
        }
        Err(e) => {
            eprintln!("SKIPPED: bwrap is not available: {e}");
            return;
        }
    }
    let exe = std::env::current_exe().unwrap();
    let run = sandbox(
        exe.as_os_str(),
        &[
            "tooth_real_enospc_leaves_journal_and_audit_log_whole",
            "--exact",
            "--nocapture",
        ],
    )
    .output()
    .unwrap();
    let stdout = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success() && stdout.contains("all failures were clean"),
        "sandboxed run failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&run.stderr)
    );
    println!(
        "{}",
        stdout
            .lines()
            .find(|l| l.starts_with("enospc:"))
            .unwrap_or("enospc: ran")
    );
}
