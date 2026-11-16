//! The ticket journal: an append-only WAL with an in-memory
//! `(SeatId, RequestDigest32) -> TicketId` index.
//!
//! Every authorized request has exactly one ticket. Looking one up is a
//! hash probe, never a directory scan. Each state change is one JSON line,
//! `fdatasync`ed before it takes effect in memory, so after a crash the
//! journal replays to the state every caller was told about. A ticket that
//! was in flight at the crash comes back `Uncertain`: its request may have
//! reached the upstream, so it is never sent again.
//!
//! Write failures never leave the file unparseable or the memory ahead of
//! the disk. A short write (`ENOSPC`) is cut back to the last committed
//! byte and only that operation fails. If the cut-back fails, or `fdatasync`
//! or a directory sync fails, the journal is *poisoned*: every later commit
//! is refused until the broker is restarted, because the kernel no longer
//! tells us what is durable.
//!
//! The journal also carries the spend ledger (per-row and per-seat daily
//! totals, and cumulative macaroon spend scopes) because reserving budget
//! and opening a ticket must be one atomic step.

use crate::Namespace;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

pub type SeatId = String;
pub type RequestDigest32 = [u8; 32];

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TicketId(#[serde(with = "crate::hexser")] [u8; 16]);

impl TicketId {
    pub fn random() -> io::Result<Self> {
        let mut id = [0u8; 16];
        crate::random_bytes(&mut id)?;
        Ok(TicketId(id))
    }

    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        TicketId(bytes)
    }
}

impl fmt::Display for TicketId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for TicketId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TicketId({self})")
    }
}

impl FromStr for TicketId {
    type Err = hex::FromHexError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut id = [0u8; 16];
        hex::decode_to_slice(s, &mut id)?;
        Ok(TicketId(id))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallKind {
    Buffered,
    Stream,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClosedBy {
    UpstreamEof,
    UpstreamError,
    Revoked,
    Withheld,
    CallerDisconnect,
    /// The token's `ExpiresAtUnixS` passed while the stream was open.
    Expired,
    /// The broker was shutting down.
    Shutdown,
}

/// How a stream ended. Retained on its ticket so a retry of a spent stream
/// learns the outcome instead of opening a duplicate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamSummary {
    pub status: u16,
    /// Body bytes delivered to the caller.
    pub bytes: u64,
    /// The upstream reached a clean end of body and all of it was delivered.
    pub complete: bool,
    /// `EchoGuard` cut the stream.
    pub withheld: bool,
    /// The row's secret was revoked mid-stream.
    pub revoked: bool,
    pub closed_by: ClosedBy,
}

/// A buffered reply kept for exact replay.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Retained {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    #[serde(with = "crate::b64")]
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketState {
    /// Authorized, budget reserved, nothing sent.
    Live,
    /// The upstream request is (or at a crash, was) in progress.
    InFlight,
    /// Buffered call finished; the reply replays on exact retry.
    Replayable(Retained),
    /// The request may have reached the upstream but no reply was
    /// delivered. Never re-sent.
    Uncertain,
    /// A buffered reply contained a guarded secret and was dropped.
    Withheld { status: u16 },
    /// Stream finished.
    Closed(StreamSummary),
}

impl TicketState {
    pub const fn name(&self) -> &'static str {
        match self {
            TicketState::Live => "live",
            TicketState::InFlight => "in_flight",
            TicketState::Replayable(_) => "replayable",
            TicketState::Uncertain => "uncertain",
            TicketState::Withheld { .. } => "withheld",
            TicketState::Closed(_) => "closed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ticket {
    pub id: TicketId,
    pub seat: SeatId,
    #[serde(with = "crate::hexser")]
    pub digest: RequestDigest32,
    pub namespace: Namespace,
    pub row: String,
    pub kind: CallKind,
    pub state: TicketState,
    pub expires_unix_s: u64,
    /// Ledger keys this ticket's reservation was charged to.
    pub ledger_keys: Vec<String>,
    pub reserved_micro_usd: u64,
}

/// A ledger key to charge, with the ceiling it must stay under (if any).
#[derive(Clone, Debug)]
pub struct Charge {
    pub key: String,
    pub cap_micro_usd: Option<u64>,
}

pub struct NewTicket {
    pub seat: SeatId,
    pub digest: RequestDigest32,
    pub namespace: Namespace,
    pub row: String,
    pub kind: CallKind,
    pub charges: Vec<Charge>,
    pub reserve_micro_usd: u64,
    pub now_unix_s: u64,
    pub live_ttl_s: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    #[error("journal io: {0}")]
    Io(#[from] io::Error),
    #[error("budget {key}: {spent} spent + {want} requested exceeds {cap} micro-USD")]
    Budget {
        key: String,
        cap: u64,
        spent: u64,
        want: u64,
    },
    #[error("journal is corrupt at line {line}: {problem}")]
    Corrupt { line: usize, problem: String },
    #[error(transparent)]
    Clock(#[from] crate::ClockError),
}

/// Fault injection for the journal's storage calls. Production brokers
/// never construct one; tests use it to make the next append fall short,
/// or `fdatasync`, truncation or the directory sync fail.
#[doc(hidden)]
#[derive(Debug)]
pub struct JournalFaults {
    /// Write only this many bytes of the next record, then fail with
    /// `ENOSPC`. One-shot; `u64::MAX` means off.
    pub short_write_after: AtomicU64,
    pub fail_sync: AtomicBool,
    pub fail_truncate: AtomicBool,
    pub fail_dir_sync: AtomicBool,
}

impl Default for JournalFaults {
    fn default() -> Self {
        JournalFaults {
            short_write_after: AtomicU64::new(u64::MAX),
            fail_sync: AtomicBool::new(false),
            fail_truncate: AtomicBool::new(false),
            fail_dir_sync: AtomicBool::new(false),
        }
    }
}

fn injected(what: &str) -> io::Error {
    io::Error::other(format!("injected {what} failure"))
}

pub fn utc_day(now_unix_s: u64) -> u64 {
    now_unix_s / 86_400
}

pub fn row_day_key(row: &str, day: u64) -> String {
    format!("rd:{row}:{day}")
}

pub fn seat_day_key(row: &str, seat: &str, day: u64) -> String {
    format!("sd:{row}:{seat}:{day}")
}

pub fn scope_key(scope: &[u8; 32]) -> String {
    format!("sc:{}", hex::encode(scope))
}

/// One WAL line. Each is a complete, self-contained state change.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Rec {
    /// New ticket; charges its reservation to its ledger keys.
    Open(Ticket),
    /// Ticket carried over by compaction; no ledger effect.
    Snap(Ticket),
    State {
        id: TicketId,
        state: TicketState,
        expires_unix_s: u64,
    },
    /// Replace the reservation with the metered actual cost.
    Settle { id: TicketId, actual_micro_usd: u64 },
    /// Drop a ticket; refunds its reservation if it was never used.
    Expire { id: TicketId },
    /// Ledger total carried over by compaction.
    Ledger { key: String, total: u64 },
}

#[derive(Clone, Default)]
struct State {
    tickets: HashMap<TicketId, Ticket>,
    index: HashMap<(SeatId, RequestDigest32), TicketId>,
    ledger: HashMap<String, u64>,
    // Expiry index avoids scanning every retained reply on each admission.
    live_expiries: BTreeSet<(u64, TicketId)>,
}

impl State {
    fn apply(&mut self, rec: Rec) {
        match rec {
            Rec::Open(ticket) => {
                for key in &ticket.ledger_keys {
                    let total = self.ledger.entry(key.clone()).or_default();
                    *total = total.saturating_add(ticket.reserved_micro_usd);
                }
                self.insert(ticket);
            }
            Rec::Snap(ticket) => self.insert(ticket),
            Rec::State {
                id,
                state,
                expires_unix_s,
            } => {
                if let Some(ticket) = self.tickets.get_mut(&id) {
                    self.live_expiries.remove(&(ticket.expires_unix_s, id));
                    if state == TicketState::Live {
                        self.live_expiries.insert((expires_unix_s, id));
                    }
                    ticket.state = state;
                    ticket.expires_unix_s = expires_unix_s;
                }
            }
            Rec::Settle {
                id,
                actual_micro_usd,
            } => {
                if let Some(ticket) = self.tickets.get_mut(&id) {
                    for key in &ticket.ledger_keys {
                        let total = self.ledger.entry(key.clone()).or_default();
                        *total = total
                            .saturating_sub(ticket.reserved_micro_usd)
                            .saturating_add(actual_micro_usd);
                    }
                    ticket.reserved_micro_usd = actual_micro_usd;
                }
            }
            Rec::Expire { id } => {
                if let Some(ticket) = self.tickets.remove(&id) {
                    self.live_expiries.remove(&(ticket.expires_unix_s, id));
                    let slot = (ticket.seat, ticket.digest);
                    if self.index.get(&slot) == Some(&id) {
                        self.index.remove(&slot);
                    }
                    if ticket.state == TicketState::Live {
                        for key in &ticket.ledger_keys {
                            if let Some(total) = self.ledger.get_mut(key) {
                                *total = total.saturating_sub(ticket.reserved_micro_usd);
                            }
                        }
                    }
                }
            }
            Rec::Ledger { key, total } => {
                self.ledger.insert(key, total);
            }
        }
    }

    fn insert(&mut self, ticket: Ticket) {
        if ticket.state == TicketState::Live {
            self.live_expiries
                .insert((ticket.expires_unix_s, ticket.id));
        }
        self.index
            .insert((ticket.seat.clone(), ticket.digest), ticket.id);
        self.tickets.insert(ticket.id, ticket);
    }
}

struct Inner {
    path: PathBuf,
    file: File,
    /// Length of the file up to and including the last committed record.
    good_len: u64,
    /// Set when durability can no longer be vouched for.
    poisoned: Option<String>,
    faults: Option<Arc<JournalFaults>>,
    state: State,
    appended: u64,
    compact_every: u64,
}

pub struct Journal {
    inner: Mutex<Inner>,
}

/// Result of trying to move a ticket from `Live` to `InFlight`.
#[derive(Debug)]
pub enum Begin {
    Started,
    /// The ticket was not `Live`; here is what it is instead.
    NotLive(Ticket),
    Missing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalStats {
    pub tickets: usize,
    pub ledger_keys: usize,
    pub appended_since_compaction: u64,
    /// Commits are being refused after a storage failure; restart needed.
    #[serde(default)]
    pub poisoned: bool,
}

fn open_append(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .append(true)
        .read(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    crate::seal::require_regular(path, &file)?;
    Ok(file)
}

impl Journal {
    /// Open and replay. A torn final line (crash mid-append) is cut off;
    /// damage anywhere else is an error. Tickets found `InFlight` are
    /// durably demoted to `Uncertain`.
    pub fn open(path: &Path, compact_every: u64, retention_s: u64) -> Result<Self, JournalError> {
        Journal::open_with_faults(path, compact_every, retention_s, None)
    }

    #[doc(hidden)]
    pub fn open_with_faults(
        path: &Path,
        compact_every: u64,
        retention_s: u64,
        faults: Option<Arc<JournalFaults>>,
    ) -> Result<Self, JournalError> {
        let now_unix_s = crate::unix_time()?;
        let mut state = State::default();
        let mut good_len = 0u64;
        let mut appended = 0u64;
        let file = open_append(path)?;
        {
            let mut reader = BufReader::new(&file);
            let mut line = Vec::new();
            let mut line_no = 0usize;
            loop {
                line.clear();
                let n = reader.read_until(b'\n', &mut line)?;
                if n == 0 {
                    break;
                }
                line_no += 1;
                let complete = line.last() == Some(&b'\n');
                match serde_json::from_slice::<Rec>(&line) {
                    Ok(rec) if complete => {
                        state.apply(rec);
                        good_len += n as u64;
                        appended += 1;
                    }
                    // Unterminated or unparsable tail: a torn append.
                    _ if reader.fill_buf()?.is_empty() => break,
                    Ok(_) => unreachable!("an unterminated line is always the last"),
                    Err(e) => {
                        return Err(JournalError::Corrupt {
                            line: line_no,
                            problem: e.to_string(),
                        })
                    }
                }
            }
            if file.metadata()?.len() != good_len {
                file.set_len(good_len)?;
                file.sync_all()?;
            }
        }
        crate::seal::sync_parent(path)?;
        let mut inner = Inner {
            path: path.to_owned(),
            file,
            good_len,
            poisoned: None,
            faults,
            state,
            appended,
            compact_every: compact_every.max(1),
        };

        let stranded: Vec<TicketId> = inner
            .state
            .tickets
            .values()
            .filter(|t| t.state == TicketState::InFlight)
            .map(|t| t.id)
            .collect();
        let expires_unix_s = now_unix_s.saturating_add(retention_s);
        for id in stranded {
            inner.commit(Rec::State {
                id,
                state: TicketState::Uncertain,
                expires_unix_s,
            })?;
        }
        Ok(Journal {
            inner: Mutex::new(inner),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Find the ticket for `(seat, digest)` or open one, reserving budget.
    /// Returns the ticket and whether it already existed. An exact retry
    /// gets the same ticket back and is not charged again.
    pub fn authorize(&self, new: NewTicket) -> Result<(Ticket, bool), JournalError> {
        let mut inner = self.lock();
        while let Some(&(expires, id)) = inner.state.live_expiries.first() {
            if expires > new.now_unix_s {
                break;
            }
            inner.commit(Rec::Expire { id })?;
        }
        let slot = (new.seat, new.digest);
        if let Some(&id) = inner.state.index.get(&slot) {
            let ticket = &inner.state.tickets[&id];
            if ticket.state == TicketState::InFlight || ticket.expires_unix_s > new.now_unix_s {
                return Ok((ticket.clone(), true));
            }
            inner.commit(Rec::Expire { id })?;
        }
        if new.reserve_micro_usd > 0 {
            for charge in &new.charges {
                let Some(cap) = charge.cap_micro_usd else {
                    continue;
                };
                let spent = inner.state.ledger.get(&charge.key).copied().unwrap_or(0);
                if spent.saturating_add(new.reserve_micro_usd) > cap {
                    return Err(JournalError::Budget {
                        key: charge.key.clone(),
                        cap,
                        spent,
                        want: new.reserve_micro_usd,
                    });
                }
            }
        }
        let ticket = Ticket {
            id: TicketId::random()?,
            seat: slot.0,
            digest: slot.1,
            namespace: new.namespace,
            row: new.row,
            kind: new.kind,
            state: TicketState::Live,
            expires_unix_s: new.now_unix_s.saturating_add(new.live_ttl_s),
            ledger_keys: if new.reserve_micro_usd > 0 {
                new.charges.into_iter().map(|c| c.key).collect()
            } else {
                Vec::new()
            },
            reserved_micro_usd: new.reserve_micro_usd,
        };
        inner.commit(Rec::Open(ticket.clone()))?;
        Ok((ticket, false))
    }

    /// Atomically claim a `Live` ticket for sending.
    pub fn begin(&self, id: TicketId) -> io::Result<Begin> {
        let mut inner = self.lock();
        let Some(ticket) = inner.state.tickets.get(&id) else {
            return Ok(Begin::Missing);
        };
        if ticket.state != TicketState::Live {
            return Ok(Begin::NotLive(ticket.clone()));
        }
        let expires_unix_s = ticket.expires_unix_s;
        inner.commit(Rec::State {
            id,
            state: TicketState::InFlight,
            expires_unix_s,
        })?;
        Ok(Begin::Started)
    }

    /// Record a new state; the ticket is then retained until `expires_unix_s`.
    pub fn transition(
        &self,
        id: TicketId,
        state: TicketState,
        expires_unix_s: u64,
    ) -> io::Result<()> {
        self.lock().commit(Rec::State {
            id,
            state,
            expires_unix_s,
        })
    }

    /// Replace a ticket's reservation with its metered cost.
    pub fn settle(&self, id: TicketId, actual_micro_usd: u64) -> io::Result<()> {
        self.lock().commit(Rec::Settle {
            id,
            actual_micro_usd,
        })
    }

    pub fn get(&self, id: TicketId) -> Option<Ticket> {
        self.lock().state.tickets.get(&id).cloned()
    }

    pub fn spent(&self, key: &str) -> u64 {
        self.lock().state.ledger.get(key).copied().unwrap_or(0)
    }

    pub fn stats(&self) -> JournalStats {
        let inner = self.lock();
        JournalStats {
            tickets: inner.state.tickets.len(),
            ledger_keys: inner.state.ledger.len(),
            appended_since_compaction: inner.appended,
            poisoned: inner.poisoned.is_some(),
        }
    }

    /// Why commits are being refused, if they are.
    pub fn poisoned(&self) -> Option<String> {
        self.lock().poisoned.clone()
    }

    /// Rewrite the journal as a snapshot now, dropping expired tickets.
    pub fn compact(&self, now_unix_s: u64) -> io::Result<()> {
        let mut inner = self.lock();
        inner.check_poison()?;
        inner.compact(now_unix_s)
    }
}

impl Inner {
    fn check_poison(&self) -> io::Result<()> {
        match &self.poisoned {
            Some(why) => Err(io::Error::other(format!(
                "journal is poisoned and refuses commits until restart: {why}"
            ))),
            None => Ok(()),
        }
    }

    fn poison(&mut self, why: String) {
        eprintln!("keygate: journal poisoned: {why}");
        self.poisoned.get_or_insert(why);
    }

    fn fault(&self) -> Option<&JournalFaults> {
        self.faults.as_deref()
    }

    fn append(&mut self, line: &[u8]) -> io::Result<()> {
        if let Some(faults) = self.fault() {
            let cut = faults.short_write_after.swap(u64::MAX, Ordering::SeqCst);
            if cut != u64::MAX {
                let cut = (cut as usize).min(line.len());
                self.file.write_all(&line[..cut])?;
                return Err(io::Error::from_raw_os_error(libc::ENOSPC));
            }
        }
        self.file.write_all(line)
    }

    fn sync(&mut self) -> io::Result<()> {
        if self
            .fault()
            .is_some_and(|f| f.fail_sync.load(Ordering::SeqCst))
        {
            return Err(injected("fdatasync"));
        }
        self.file.sync_data()
    }

    fn truncate_to_good(&mut self) -> io::Result<()> {
        if self
            .fault()
            .is_some_and(|f| f.fail_truncate.load(Ordering::SeqCst))
        {
            return Err(injected("ftruncate"));
        }
        self.file.set_len(self.good_len)
    }

    /// Durably append, then apply. Nothing changes in memory if the write
    /// fails, and the file never keeps a torn record ahead of later ones.
    fn commit(&mut self, rec: Rec) -> io::Result<()> {
        self.check_poison()?;
        let mut line = serde_json::to_vec(&rec)?;
        line.push(b'\n');
        if let Err(e) = self.append(&line) {
            // Part of the record may be in the file. The descriptor is in
            // append mode, so cutting back to the last committed byte puts
            // the next record exactly where this one would have started.
            if let Err(cut) = self.truncate_to_good() {
                self.poison(format!(
                    "append failed ({e}) and the partial record could not be removed ({cut})"
                ));
            }
            return Err(e);
        }
        if let Err(e) = self.sync() {
            // After a failed fsync the kernel may have dropped the dirty
            // pages or may still write them; neither can be assumed.
            self.poison(format!("fdatasync failed: {e}"));
            return Err(e);
        }
        self.good_len += line.len() as u64;
        self.state.apply(rec);
        self.appended += 1;
        if self.appended >= self.compact_every {
            // The record above is already durable; a failed compaction only
            // postpones the rewrite (or poisons, if it failed after install).
            let compacted = crate::unix_time()
                .map_err(io::Error::other)
                .and_then(|now| self.compact(now));
            if let Err(e) = compacted {
                eprintln!("keygate: journal compaction failed (will retry): {e}");
                self.appended = 0;
            }
        }
        Ok(())
    }

    fn compact(&mut self, now_unix_s: u64) -> io::Result<()> {
        let mut snapshot = self.state.clone();
        let expired: Vec<TicketId> = snapshot
            .tickets
            .values()
            .filter(|t| t.state != TicketState::InFlight && t.expires_unix_s <= now_unix_s)
            .map(|t| t.id)
            .collect();
        for id in expired {
            snapshot.apply(Rec::Expire { id });
        }
        // Daily counters older than yesterday can no longer be charged.
        let today = utc_day(now_unix_s);
        snapshot.ledger.retain(|key, total| {
            let daily = key.starts_with("rd:") || key.starts_with("sd:");
            let day = key.rsplit(':').next().and_then(|d| d.parse::<u64>().ok());
            match (daily, day) {
                (true, Some(day)) => day + 1 >= today,
                _ => *total > 0,
            }
        });

        let (tmp, file) = crate::seal::AtomicTemp::create(&self.path)?;
        let mut out = io::BufWriter::new(file);
        for (key, total) in &snapshot.ledger {
            serde_json::to_writer(
                &mut out,
                &Rec::Ledger {
                    key: key.clone(),
                    total: *total,
                },
            )?;
            out.write_all(b"\n")?;
        }
        for ticket in snapshot.tickets.values() {
            serde_json::to_writer(&mut out, &Rec::Snap(ticket.clone()))?;
            out.write_all(b"\n")?;
        }
        let file = out.into_inner().map_err(|e| e.into_error())?;
        file.sync_all()?;
        let good_len = file.metadata()?.len();
        tmp.install(&self.path)?;
        // From here the new file is the journal. Until the rename itself is
        // durable, a crash could bring the old file back without anything
        // committed after this point, so a failed directory sync poisons.
        self.file = file;
        self.good_len = good_len;
        self.state = snapshot;
        self.appended = 0;
        let synced = if self
            .fault()
            .is_some_and(|f| f.fail_dir_sync.load(Ordering::SeqCst))
        {
            Err(injected("directory fsync"))
        } else {
            crate::seal::sync_parent(&self.path)
        };
        if let Err(e) = &synced {
            self.poison(format!(
                "compaction installed but its directory sync failed: {e}"
            ));
        }
        synced
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const NOW: u64 = 1_700_000_000;

    fn new(seat: &str, digest: u8, reserve: u64, charges: Vec<Charge>) -> NewTicket {
        NewTicket {
            seat: seat.into(),
            digest: [digest; 32],
            namespace: Namespace::Provider,
            row: "llm".into(),
            kind: CallKind::Buffered,
            charges,
            reserve_micro_usd: reserve,
            now_unix_s: NOW,
            live_ttl_s: 60,
        }
    }

    fn capped(key: &str, cap: u64) -> Vec<Charge> {
        vec![Charge {
            key: key.into(),
            cap_micro_usd: Some(cap),
        }]
    }

    fn journal(dir: &Path) -> Journal {
        Journal::open(&dir.join("journal.wal"), 1_000_000, 60).unwrap()
    }

    fn reply() -> TicketState {
        TicketState::Replayable(Retained {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: b"{\"ok\":true}\0\xff".to_vec(),
        })
    }

    /// #tooth: an exact retry of authorize returns the live ticket and does
    /// not charge the budget twice.
    #[test]
    fn tooth_authorize_retry_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let j = journal(dir.path());
        let (first, existing) = j
            .authorize(new("a", 1, 40, capped("rd:llm:1", 100)))
            .unwrap();
        assert!(!existing);
        let (again, existing) = j
            .authorize(new("a", 1, 40, capped("rd:llm:1", 100)))
            .unwrap();
        assert!(existing);
        assert_eq!(again.id, first.id);
        assert_eq!(j.spent("rd:llm:1"), 40);

        // Another seat with the same digest is a different ticket.
        let (other, existing) = j
            .authorize(new("b", 1, 40, capped("rd:llm:1", 100)))
            .unwrap();
        assert!(!existing);
        assert_ne!(other.id, first.id);
        assert_eq!(j.spent("rd:llm:1"), 80);

        // And the cap holds: 80 + 40 > 100.
        let err = j
            .authorize(new("c", 1, 40, capped("rd:llm:1", 100)))
            .unwrap_err();
        assert!(matches!(
            err,
            JournalError::Budget {
                spent: 80,
                want: 40,
                cap: 100,
                ..
            }
        ));
        assert_eq!(j.stats().tickets, 2, "a refused request leaves no ticket");
    }

    #[test]
    fn begin_claims_once() {
        let dir = tempfile::tempdir().unwrap();
        let j = journal(dir.path());
        let (t, _) = j.authorize(new("a", 1, 0, vec![])).unwrap();
        assert!(matches!(j.begin(t.id).unwrap(), Begin::Started));
        assert!(
            matches!(j.begin(t.id).unwrap(), Begin::NotLive(t) if t.state == TicketState::InFlight)
        );
        assert!(matches!(
            j.begin(TicketId::from_bytes([0; 16])).unwrap(),
            Begin::Missing
        ));
    }

    /// #tooth: replay after restart restores replies, ledger and index, and
    /// demotes a ticket that was in flight at the crash to `Uncertain`.
    #[test]
    fn tooth_replay_restores_state_and_strands_in_flight_as_uncertain() {
        let dir = tempfile::tempdir().unwrap();
        let (done, flying, idle);
        {
            let j = journal(dir.path());
            done = j
                .authorize(new("a", 1, 10, capped("rd:llm:1", 100)))
                .unwrap()
                .0
                .id;
            j.begin(done).unwrap();
            j.transition(done, reply(), NOW + 60).unwrap();
            j.settle(done, 7).unwrap();
            flying = j
                .authorize(new("a", 2, 10, capped("rd:llm:1", 100)))
                .unwrap()
                .0
                .id;
            j.begin(flying).unwrap();
            idle = j
                .authorize(new("a", 3, 10, capped("rd:llm:1", 100)))
                .unwrap()
                .0
                .id;
        }
        for _ in 0..2 {
            let j = journal(dir.path());
            assert_eq!(j.get(done).unwrap().state, reply());
            assert_eq!(j.get(flying).unwrap().state, TicketState::Uncertain);
            assert_eq!(j.get(idle).unwrap().state, TicketState::Live);
            assert_eq!(j.spent("rd:llm:1"), 27);
            let (t, existing) = j
                .authorize(new("a", 1, 10, capped("rd:llm:1", 100)))
                .unwrap();
            assert!(existing);
            assert_eq!(t.id, done);
        }
    }

    #[test]
    fn torn_tail_is_cut_and_mid_file_damage_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.wal");
        let id = {
            let j = journal(dir.path());
            j.authorize(new("a", 1, 0, vec![])).unwrap().0.id
        };
        let intact = fs::read(&path).unwrap();

        let mut torn = intact.clone();
        torn.extend_from_slice(b"{\"state\":{\"id\":\"00");
        fs::write(&path, &torn).unwrap();
        let j = journal(dir.path());
        assert!(j.get(id).is_some());
        drop(j);
        assert_eq!(fs::read(&path).unwrap(), intact, "torn tail truncated away");

        let mut damaged = b"not json\n".to_vec();
        damaged.extend_from_slice(&intact);
        fs::write(&path, &damaged).unwrap();
        assert!(matches!(
            Journal::open(&path, 1000, 60),
            Err(JournalError::Corrupt { line: 1, .. })
        ));
    }

    #[test]
    fn expiry_refunds_unused_reservations_only() {
        let dir = tempfile::tempdir().unwrap();
        let j = journal(dir.path());
        let unused = j.authorize(new("a", 1, 30, capped("k", 100))).unwrap().0.id;
        let used = j.authorize(new("a", 2, 30, capped("k", 100))).unwrap().0.id;
        j.begin(used).unwrap();
        j.transition(used, reply(), NOW + 60).unwrap();
        assert_eq!(j.spent("k"), 60);

        // Past retention, the same request opens a fresh ticket.
        let mut late = new("a", 1, 30, capped("k", 100));
        late.now_unix_s = NOW + 61;
        let (fresh, existing) = j.authorize(late).unwrap();
        assert!(!existing);
        assert_ne!(fresh.id, unused);
        assert_eq!(
            j.spent("k"),
            60,
            "unused reservation refunded, new one charged"
        );

        let mut late = new("a", 2, 30, capped("k", 100));
        late.now_unix_s = NOW + 61;
        let (fresh, _) = j.authorize(late).unwrap();
        assert_ne!(fresh.id, used);
        assert_eq!(j.spent("k"), 90, "a used ticket's spend is never refunded");
    }

    #[test]
    fn compaction_preserves_live_state_and_drops_the_expired() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.wal");
        let j = Journal::open(&path, 1_000_000, 60).unwrap();
        let keep = j
            .authorize(new(
                "a",
                1,
                5,
                capped(&row_day_key("llm", utc_day(NOW)), 100),
            ))
            .unwrap()
            .0
            .id;
        j.begin(keep).unwrap();
        j.transition(keep, reply(), NOW + 1_000).unwrap();
        let gone = j
            .authorize(new("a", 2, 5, capped("sc:ab", 100)))
            .unwrap()
            .0
            .id;
        j.begin(gone).unwrap();
        j.transition(gone, TicketState::Uncertain, NOW + 10)
            .unwrap();
        let stale_day = row_day_key("llm", utc_day(NOW) - 5);
        j.authorize(new("a", 3, 5, capped(&stale_day, 100)))
            .unwrap();

        let before = fs::metadata(&path).unwrap().len();
        j.compact(NOW + 500).unwrap();
        assert!(fs::metadata(&path).unwrap().len() < before);
        assert_eq!(j.stats().appended_since_compaction, 0);

        for j in [j, Journal::open(&path, 1_000_000, 60).unwrap()] {
            assert_eq!(j.get(keep).unwrap().state, reply());
            assert!(j.get(gone).is_none());
            assert_eq!(
                j.spent("sc:ab"),
                5,
                "macaroon scope spend outlives its ticket"
            );
            assert_eq!(j.spent(&stale_day), 0, "old daily counters are dropped");
            assert_eq!(j.spent(&row_day_key("llm", utc_day(NOW))), 5);
        }
    }

    #[test]
    fn automatic_compaction_bounds_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.wal");
        let j = Journal::open(&path, 8, 60).unwrap();
        for i in 0..50u8 {
            let mut n = new("a", i, 0, vec![]);
            n.now_unix_s = crate::unix_time().unwrap() - 1_000; // already expired
            j.authorize(n).unwrap();
        }
        assert!(j.stats().tickets <= 8);
        assert!(fs::read_to_string(&path).unwrap().lines().count() <= 16);
    }

    #[test]
    fn journal_file_is_0600() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let j = journal(dir.path());
        j.compact(NOW).unwrap();
        assert_eq!(
            fs::metadata(dir.path().join("journal.wal")).unwrap().mode() & 0o777,
            0o600
        );
    }

    /// #tooth: a different digest can reclaim expired Live budget without
    /// compaction; InFlight and terminal spend are never refunded.
    #[test]
    fn tooth_authorize_sweeps_expired_live_reservations_durably() {
        let dir = tempfile::tempdir().unwrap();
        let j = journal(dir.path());
        let live = j.authorize(new("a", 1, 40, capped("k", 100))).unwrap().0.id;
        let flying = j.authorize(new("a", 2, 20, capped("k", 100))).unwrap().0.id;
        j.begin(flying).unwrap();
        let used = j.authorize(new("a", 3, 20, capped("k", 100))).unwrap().0.id;
        j.begin(used).unwrap();
        j.transition(used, reply(), NOW + 1000).unwrap();
        // Exercise expiry-index removal and reinsertion on connect rollback.
        j.begin(live).unwrap();
        j.transition(live, TicketState::Live, NOW + 10).unwrap();
        let mut retry = new("b", 4, 60, capped("k", 100));
        retry.now_unix_s = NOW + 10;
        let fresh = j.authorize(retry).unwrap().0;
        assert_eq!(j.spent("k"), 100);
        assert!(j.get(live).is_none());
        assert_eq!(j.stats().appended_since_compaction, 10);
        drop(j);
        let j = journal(dir.path());
        assert!(j.get(live).is_none());
        assert_eq!(j.spent("k"), 100);
        assert_eq!(j.get(fresh.id).unwrap().state, TicketState::Live);
        assert_eq!(j.get(flying).unwrap().state, TicketState::Uncertain);
        assert_eq!(j.get(used).unwrap().state, reply());
    }

    /// #tooth: journal recovery cannot truncate a symlink target; compaction
    /// leaves another writer's old fixed temporary name alone.
    #[test]
    fn tooth_journal_nofollow_and_private_compaction_temp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.wal");
        let target = dir.path().join("target");
        fs::write(&target, b"do not truncate").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(Journal::open(&path, 100, 60).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"do not truncate");
        fs::remove_file(&path).unwrap();
        let fixed = path.with_extension("compact");
        fs::write(&fixed, b"another writer").unwrap();
        let j = journal(dir.path());
        j.compact(NOW).unwrap();
        assert_eq!(fs::read(&fixed).unwrap(), b"another writer");
    }
    /// #tooth: after a long flight crashes, the short Live TTL must not
    /// permit immediate resend of a request whose upstream effect is unknown.
    #[test]
    fn tooth_crash_recovery_uses_terminal_retention() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.wal");
        let old = crate::unix_time().unwrap() - 1000;
        let id = {
            let j = Journal::open(&path, 1_000_000, 600).unwrap();
            let mut n = new("seat", 1, 10, capped("k", 100));
            n.now_unix_s = old;
            n.live_ttl_s = 7;
            let id = j.authorize(n).unwrap().0.id;
            j.begin(id).unwrap();
            id
        };
        let before = crate::unix_time().unwrap();
        let j = Journal::open(&path, 1_000_000, 600).unwrap();
        let recovered = j.get(id).unwrap();
        assert_eq!(recovered.state, TicketState::Uncertain);
        assert!(recovered.expires_unix_s >= before + 600);
        let mut retry = new("seat", 1, 10, capped("k", 100));
        retry.now_unix_s = crate::unix_time().unwrap();
        let (same, existing) = j.authorize(retry).unwrap();
        assert!(existing);
        assert_eq!(same.id, id);
        assert_eq!(j.spent("k"), 10);
    }

    fn faulty(dir: &Path) -> (Journal, Arc<JournalFaults>) {
        let faults = Arc::new(JournalFaults::default());
        let journal = Journal::open_with_faults(
            &dir.join("journal.wal"),
            1_000_000,
            60,
            Some(faults.clone()),
        )
        .unwrap();
        (journal, faults)
    }

    /// #tooth: a short write (ENOSPC mid-record) is cut back. The failed
    /// operation changes nothing, the next one lands on a clean line, and
    /// the journal still boots. Before the fix the torn record stayed in
    /// the middle of the file and the broker refused to start (`Corrupt`).
    #[test]
    fn tooth_short_write_is_rolled_back_and_the_journal_stays_bootable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.wal");
        let (j, faults) = faulty(dir.path());
        let kept = j.authorize(new("a", 1, 10, capped("k", 100))).unwrap().0.id;
        let intact = fs::read(&path).unwrap();

        for cut in [0u64, 1, 17, 60] {
            faults.short_write_after.store(cut, Ordering::SeqCst);
            let err = j.authorize(new("a", 2, 10, capped("k", 100))).unwrap_err();
            assert!(
                matches!(&err, JournalError::Io(e) if e.raw_os_error() == Some(libc::ENOSPC)),
                "{err}"
            );
            assert_eq!(
                fs::read(&path).unwrap(),
                intact,
                "cut {cut}: torn bytes left behind"
            );
            assert_eq!(
                j.spent("k"),
                10,
                "cut {cut}: a failed reservation was charged"
            );
            assert_eq!(j.stats().tickets, 1);
            assert!(j.poisoned().is_none());
        }

        // Space is back: the same request now succeeds on a clean line.
        let later = j.authorize(new("a", 2, 10, capped("k", 100))).unwrap().0.id;
        j.begin(later).unwrap();
        faults.short_write_after.store(5, Ordering::SeqCst);
        assert!(j.transition(later, reply(), NOW + 60).is_err());
        assert_eq!(
            j.get(later).unwrap().state,
            TicketState::InFlight,
            "memory never runs ahead of disk"
        );
        drop(j);

        let j = journal(dir.path());
        assert_eq!(j.get(kept).unwrap().state, TicketState::Live);
        assert_eq!(j.get(later).unwrap().state, TicketState::Uncertain);
        assert_eq!(j.spent("k"), 20);
    }

    /// #tooth: if the torn record cannot be removed, the journal stops
    /// accepting commits rather than appending after garbage.
    #[test]
    fn tooth_unremovable_torn_record_poisons_the_journal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.wal");
        let (j, faults) = faulty(dir.path());
        let kept = j.authorize(new("a", 1, 10, capped("k", 100))).unwrap().0.id;
        let intact = fs::read(&path).unwrap();

        faults.short_write_after.store(9, Ordering::SeqCst);
        faults.fail_truncate.store(true, Ordering::SeqCst);
        assert!(j.authorize(new("a", 2, 10, capped("k", 100))).is_err());
        assert!(j.poisoned().unwrap().contains("could not be removed"));
        assert!(j.stats().poisoned);
        faults.fail_truncate.store(false, Ordering::SeqCst);

        // Every kind of commit is refused, and nothing more is written.
        let torn = fs::read(&path).unwrap();
        assert_eq!(torn.len(), intact.len() + 9);
        let refused = j.authorize(new("a", 3, 10, capped("k", 100))).unwrap_err();
        assert!(refused.to_string().contains("poisoned"));
        assert!(j.begin(kept).is_err());
        assert!(j
            .transition(kept, TicketState::Uncertain, NOW + 60)
            .is_err());
        assert!(j.settle(kept, 1).is_err());
        assert!(j.compact(NOW).is_err());
        assert_eq!(fs::read(&path).unwrap(), torn);
        assert_eq!(
            j.get(kept).unwrap().state,
            TicketState::Live,
            "reads still work"
        );
        drop(j);

        // The garbage is at the tail, so a restart recovers by cutting it.
        let j = journal(dir.path());
        assert!(j.poisoned().is_none());
        assert_eq!(fs::read(&path).unwrap(), intact);
        assert_eq!(j.spent("k"), 10);
        j.authorize(new("a", 2, 10, capped("k", 100))).unwrap();
    }

    /// #tooth: a failed fdatasync is not retried or ignored. The operation
    /// fails, memory is unchanged, and the journal is poisoned.
    #[test]
    fn tooth_fsync_failure_poisons_and_memory_does_not_advance() {
        let dir = tempfile::tempdir().unwrap();
        let (j, faults) = faulty(dir.path());
        let id = j.authorize(new("a", 1, 10, capped("k", 100))).unwrap().0.id;

        faults.fail_sync.store(true, Ordering::SeqCst);
        assert!(j.begin(id).is_err());
        assert_eq!(
            j.get(id).unwrap().state,
            TicketState::Live,
            "the claim was not acknowledged"
        );
        assert!(j.poisoned().unwrap().contains("fdatasync"));
        // The fault clearing does not un-poison: only a restart re-reads
        // what actually reached the disk.
        faults.fail_sync.store(false, Ordering::SeqCst);
        assert!(j.begin(id).is_err());
        assert!(j.authorize(new("a", 2, 10, capped("k", 100))).is_err());
        assert_eq!(j.spent("k"), 10);
        drop(j);

        // Here the unsynced record did reach the file, so the restart sees
        // a ticket claimed but never sent on, and refuses to send it: the
        // safe direction for a record of unknown durability.
        let j = journal(dir.path());
        assert_eq!(j.get(id).unwrap().state, TicketState::Uncertain);
        assert_eq!(j.spent("k"), 10);
    }

    /// #tooth: a compaction whose rename could not be made durable poisons
    /// instead of taking commits a crash could silently drop.
    #[test]
    fn tooth_compaction_directory_sync_failure_poisons() {
        let dir = tempfile::tempdir().unwrap();
        let (j, faults) = faulty(dir.path());
        let id = j.authorize(new("a", 1, 10, capped("k", 100))).unwrap().0.id;
        faults.fail_dir_sync.store(true, Ordering::SeqCst);
        assert!(j.compact(NOW).is_err());
        assert!(j.poisoned().unwrap().contains("directory sync"));
        assert!(j.authorize(new("a", 2, 10, capped("k", 100))).is_err());
        drop(j);
        let j = journal(dir.path());
        assert_eq!(j.get(id).unwrap().state, TicketState::Live);
        assert_eq!(j.spent("k"), 10);
    }

    /// #tooth: a compaction that fails before the rename leaves the old
    /// journal fully in charge and usable.
    #[test]
    fn tooth_failed_compaction_before_install_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.wal");
        let j = Journal::open(&path, 1_000_000, 60).unwrap();
        j.authorize(new("a", 1, 10, capped("k", 100))).unwrap();
        // Make the directory read-only so the temporary cannot be created.
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500)).unwrap();
        let blocked = j.compact(NOW);
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(blocked.is_err());
        assert!(j.poisoned().is_none());
        j.authorize(new("a", 2, 10, capped("k", 100))).unwrap();
        j.authorize(new("a", 3, 10, capped("k", 100))).unwrap();
        drop(j);
        assert_eq!(journal(dir.path()).spent("k"), 30);
    }
}
