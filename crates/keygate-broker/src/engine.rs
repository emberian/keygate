//! The broker engine: admission, ticketing, audit-before-effect, and the
//! upstream exchange for both buffered and streaming calls.
//!
//! Order of operations for every call, none of which may be reordered:
//!
//! 0. (transports) verify the macaroon and the route before reading a body;
//! 1. verify the macaroon and admit the request against row policy and caveats;
//! 2. find or open the ticket (reserving budget) in the journal;
//! 3. claim the ticket `Live -> InFlight` (durable);
//! 4. append `Begin` to the audit log (durable) and stop here if that fails;
//! 5. only now touch the network.

use crate::provider::{
    admit_provider, metered_cost, stream_requested, ProviderAdmission, UsageSniffer,
};
use crate::vault::{ActiveSecret, Prices, RowEpoch, Upstream, Vault};
use crate::BootError;
use bytes::Bytes;
use keygate_core::audit::{AuditEvent, AuditLog};
use keygate_core::config::{header_is_reserved, BrokerCfg, Config, Deployment};
use keygate_core::echo::{EchoAutomaton, EchoGuard};
use keygate_core::journal::{
    self, Begin, CallKind, Charge, ClosedBy, Journal, JournalError, JournalFaults, NewTicket,
    RequestDigest32, Retained, StreamSummary, Ticket, TicketId, TicketState,
};
use keygate_core::macaroon::{self, Caveat, Facts, MacaroonV1, RootId, Verified, TOKEN_PREFIX};
use keygate_core::path::{check_query, PlainPath};
use keygate_core::proto::{Call, Code, Refusal, RowInfo, StatusInfo};
use keygate_core::seal::{write_atomic, MasterKey, SealStore};
use keygate_core::secret::SecretBytes;
use keygate_core::{unix_time, valid_name, Namespace};
use reqwest::header::{
    HeaderMap, HeaderName, HeaderValue, ACCEPT_ENCODING, CONNECTION, CONTENT_ENCODING,
};
use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch, Semaphore};
use zeroize::Zeroize;

/// Caller headers forwarded on every row without configuration.
const SAFE_CALLER_HEADERS: &[&str] = &["accept", "content-type"];
const LAST_EVENT_ID: &str = "last-event-id";
const STREAM_CHANNEL_DEPTH: usize = 32;

pub const MASTER_KEY_FILE: &str = "master.key";
pub const CONFIG_FILE: &str = "keygate.toml";
pub const JOURNAL_FILE: &str = "journal.wal";
pub const AUDIT_FILE: &str = "audit.log";
const SEATS_FILE: &str = "seats.json";

/// Who is on the other end of the transport.
#[derive(Clone, Copy, Debug)]
pub struct Caller {
    /// Peer uid from `SO_PEERCRED` / `getpeereid`. `None` on the HTTP
    /// gateway, where TCP gives no peer identity; uid-bound macaroons are
    /// therefore refused there.
    pub uid: Option<u32>,
}

/// What to do with a caller header the row does not allow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderMode {
    /// Refuse the request (the socket protocol: callers say what they mean).
    Strict,
    /// Drop it (the HTTP gateway: unmodified SDKs send many headers).
    Filter,
}

#[derive(Debug)]
pub struct Authorized {
    pub ticket: TicketId,
    pub state: &'static str,
    pub existing: bool,
    pub reserved_micro_usd: u64,
}

#[derive(Debug)]
pub struct BufferedReply {
    pub ticket: TicketId,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub replayed: bool,
}

#[derive(Debug)]
pub enum StreamItem {
    Chunk(Bytes),
    /// Always the last item.
    End(StreamSummary),
}

#[derive(Debug)]
pub struct LiveStream {
    pub ticket: TicketId,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    /// Dropping this aborts the upstream request.
    pub items: mpsc::Receiver<StreamItem>,
}

#[derive(Debug)]
pub enum StreamOutcome {
    Live(LiveStream),
    /// This exact stream request already ran; here is how it ended.
    Spent {
        ticket: TicketId,
        summary: StreamSummary,
    },
}

#[derive(Default)]
pub struct BrokerOptions {
    /// Use this audit log instead of opening `<state>/audit.log`.
    pub audit: Option<AuditLog>,
    /// Storage fault injection for the ticket journal (tests only).
    #[doc(hidden)]
    pub journal_faults: Option<Arc<JournalFaults>>,
}

struct Inner {
    cfg: BrokerCfg,
    state_dir: PathBuf,
    vault: Vault,
    journal: Journal,
    audit: AuditLog,
    http: reqwest::Client,
    root_key: SecretBytes,
    operator_uids: Vec<u32>,
    /// The uid this process runs as: the uid that can read the master key.
    broker_uid: u32,
    seats: watch::Sender<Arc<BTreeMap<String, u64>>>,
    seat_admin: Mutex<()>,
    disk_slots: Arc<Semaphore>,
    /// Flips to `true` once; every flight and stream watches it.
    shutdown: watch::Sender<bool>,
    /// Calls between a claimed ticket and its recorded outcome.
    flights: watch::Sender<usize>,
    started: Instant,
}

/// Async exchanges isolate durable operations on a bounded blocking pool.
/// Synchronous operator/diagnostic methods also perform disk I/O or acquire
/// its locks; embedders should call those from a blocking thread.
#[derive(Clone)]
pub struct Broker {
    inner: Arc<Inner>,
}

/// A request that passed every stateless check.
struct Prepared {
    ns: Namespace,
    row: String,
    kind: CallKind,
    seat: String,
    root_epoch: u64,
    uid: Option<u32>,
    digest: RequestDigest32,
    method: reqwest::Method,
    path: String,
    url: reqwest::Url,
    headers: HeaderMap,
    body: Bytes,
    reserve_micro_usd: u64,
    charges: Vec<Charge>,
    /// Token prices, present when the reply's usage should settle the reservation.
    prices: Option<Prices>,
    /// The token's earliest `ExpiresAtUnixS`, and the clock reading it was
    /// admitted against.
    expires_at_unix_s: Option<u64>,
    admitted_unix_s: u64,
}

/// A claimed ticket with its `Begin` audited: the network may now be used.
struct Flight {
    guard: FlightGuard,
    secret: Arc<ActiveSecret>,
    watch: CutWatch,
    automaton: Arc<EchoAutomaton>,
}

/// Why an exchange in progress must stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cut {
    /// The row's secret or the token's seat was revoked.
    Revoked,
    /// The token's expiry passed (streams only).
    Expired,
    /// The broker is shutting down.
    Shutdown,
}

/// Everything that can cut a flight short. Waiting on it is pure in-memory
/// notification plus, for a stream with an expiring token, one timer; it
/// never polls and never touches disk.
struct CutWatch {
    epoch: watch::Receiver<RowEpoch>,
    generation: u64,
    seats: watch::Receiver<Arc<BTreeMap<String, u64>>>,
    seat: String,
    root_epoch: u64,
    shutdown: watch::Receiver<bool>,
    expires: Option<tokio::time::Instant>,
}

impl CutWatch {
    async fn cut(&mut self) -> Cut {
        loop {
            if self.epoch.borrow_and_update().revoked_floor > self.generation
                || self
                    .seats
                    .borrow_and_update()
                    .get(&self.seat)
                    .copied()
                    .unwrap_or(0)
                    > self.root_epoch
            {
                return Cut::Revoked;
            }
            if *self.shutdown.borrow_and_update() {
                return Cut::Shutdown;
            }
            let expiry = async {
                match self.expires {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                // A dropped sender means the broker itself is going away.
                result = self.epoch.changed() => if result.is_err() { return Cut::Shutdown; },
                result = self.seats.changed() => if result.is_err() { return Cut::Shutdown; },
                result = self.shutdown.changed() => if result.is_err() { return Cut::Shutdown; },
                _ = expiry => return Cut::Expired,
            }
        }
    }
}

/// Decrements the in-flight count when the flight's outcome is on disk.
struct InFlight(Broker);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0
            .inner
            .flights
            .send_modify(|n| *n = n.saturating_sub(1));
    }
}

/// Owns an `InFlight` ticket. If it is dropped without an explicit outcome
/// (the caller hung up and the exchange future was cancelled), the ticket
/// becomes `Uncertain`.
struct FlightGuard {
    broker: Broker,
    id: TicketId,
    armed: bool,
    counted: Option<InFlight>,
}

impl FlightGuard {
    async fn finish(mut self, state: TicketState) -> Result<(), Refusal> {
        let broker = self.broker.clone();
        broker
            .disk(move |_| {
                self.armed = false;
                self.broker.record(self.id, state)
            })
            .await
    }
}

impl Drop for FlightGuard {
    fn drop(&mut self) {
        if self.armed {
            let broker = self.broker.clone();
            let id = self.id;
            let counted = self.counted.take();
            // Cancellation must never block a relay worker. Until this durable
            // cleanup runs the ticket stays InFlight and cannot be re-sent.
            tokio::spawn(async move {
                broker
                    .disk(move |broker| {
                        if let Err(e) = broker.record(id, TicketState::Uncertain) {
                            eprintln!("keygate: ticket {id} abandoned and not journaled: {e}");
                        }
                        broker.audit_lossy(&AuditEvent::Failed {
                            ticket: id,
                            reason: "abandoned mid-flight; marked uncertain",
                        });
                    })
                    .await;
                drop(counted);
            });
        }
    }
}

enum ExchangeError {
    /// The TCP/TLS connection was never established: nothing was sent.
    Connect(String),
    Upstream(String),
    TooLarge,
    Withheld {
        status: u16,
    },
    Cut(Cut),
}

impl Broker {
    /// Create the state directory skeleton and a fresh master key.
    pub fn init_state(state_dir: &Path) -> Result<(), BootError> {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(state_dir)?;
        // The directory may have existed already, with a wider mode.
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(state_dir, std::fs::Permissions::from_mode(0o700))?;
        MasterKey::generate(&state_dir.join(MASTER_KEY_FILE))?;
        Ok(())
    }

    pub fn open(
        state_dir: &Path,
        config: Config,
        options: BrokerOptions,
    ) -> Result<Self, BootError> {
        config.validate()?;
        let broker_uid = crate::harden::effective_uid();
        // From here on only the canonical path is used: it is the one whose
        // every ancestor was just checked.
        let state_dir = &crate::harden::check_state_dir(state_dir, broker_uid)?;
        let master = MasterKey::load(&state_dir.join(MASTER_KEY_FILE))?;
        let vault = Vault::open(&config, SealStore::new(state_dir, &master))?;
        let journal = Journal::open_with_faults(
            &state_dir.join(JOURNAL_FILE),
            config.broker.compact_every,
            config.broker.retention_s,
            options.journal_faults,
        )?;
        journal.set_max_uncertain(config.broker.max_uncertain_tickets);
        let audit = match options.audit {
            Some(audit) => audit,
            None => AuditLog::open(&state_dir.join(AUDIT_FILE))?,
        };
        let seats = match std::fs::read(state_dir.join(SEATS_FILE)) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| BootError::Config(format!("{SEATS_FILE}: {e}")))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e.into()),
        };
        // `validate` guarantees a separated deployment lists its operators;
        // only a development broker falls back to the state dir's owner.
        // The journal keeps its own copy of each seat's revocation floor,
        // because it decides from it when a no-resend record may be
        // dropped. Reconcile it with the seat file in case an earlier
        // revocation was persisted there but not journaled.
        let seats: BTreeMap<String, u64> = seats;
        for (seat, epoch) in &seats {
            if journal.seat_floor(seat) < *epoch {
                journal
                    .revoke_seat(seat, *epoch)
                    .map_err(keygate_core::journal::JournalError::Io)?;
            }
        }
        let operator_uids = if config.broker.operator_uids.is_empty() {
            vec![std::fs::metadata(state_dir)?.uid()]
        } else {
            config.broker.operator_uids.clone()
        };
        // No redirects: a 3xx must never carry the injected credential to
        // another origin. No ambient proxy: the origin in the row is the
        // only place the secret goes.
        let http = reqwest::Client::builder()
            .use_rustls_tls()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(Duration::from_millis(config.broker.connect_timeout_ms))
            .build()
            .map_err(|e| BootError::Config(format!("http client: {e}")))?;
        Ok(Broker {
            inner: Arc::new(Inner {
                cfg: config.broker,
                state_dir: state_dir.to_owned(),
                vault,
                journal,
                audit,
                http,
                root_key: master.derive(macaroon::ROOT_KEY_CONTEXT),
                operator_uids,
                broker_uid,
                seats: watch::Sender::new(Arc::new(seats)),
                seat_admin: Mutex::new(()),
                disk_slots: Arc::new(Semaphore::new(16)),
                shutdown: watch::Sender::new(false),
                flights: watch::Sender::new(0),
                started: Instant::now(),
            }),
        })
    }

    /// Bound queued durable work before using Tokio's blocking pool. The
    /// permit remains owned by the job even if its async caller is cancelled.
    pub(crate) async fn disk<T: Send + 'static>(
        &self,
        work: impl FnOnce(&Broker) -> T + Send + 'static,
    ) -> T {
        let permit = self
            .inner
            .disk_slots
            .clone()
            .acquire_owned()
            .await
            .expect("disk semaphore stays open");
        let broker = self.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            work(&broker)
        })
        .await
        .expect("broker disk job panicked")
    }

    pub fn config(&self) -> &BrokerCfg {
        &self.inner.cfg
    }

    pub fn state_dir(&self) -> &Path {
        &self.inner.state_dir
    }

    pub fn is_operator(&self, uid: u32) -> bool {
        self.inner.operator_uids.contains(&uid)
    }

    pub fn namespaces(&self) -> Vec<Namespace> {
        let mut out = Vec::new();
        if self.inner.vault.provider_rows().is_some() {
            out.push(Namespace::Provider);
        }
        if self.inner.vault.service_rows().is_some() {
            out.push(Namespace::Service);
        }
        out
    }

    fn root_key(&self) -> &[u8; 32] {
        self.inner
            .root_key
            .expose()
            .try_into()
            .expect("derived keys are 32 bytes")
    }

    fn seat_epoch(&self, seat: &str) -> u64 {
        self.inner.seats.borrow().get(seat).copied().unwrap_or(0)
    }

    pub fn deployment(&self) -> Deployment {
        self.inner.cfg.deployment
    }

    /// The deployment as it is named on the wire.
    pub fn status_deployment(&self) -> &'static str {
        deployment_name(self.inner.cfg.deployment)
    }

    /// May a peer with this uid make calls? In a separated deployment a
    /// peer running as the broker's own uid is refused: it could read the
    /// master key directly, so serving it would only disguise a deployment
    /// with no boundary at all.
    pub fn may_call(&self, uid: Option<u32>) -> bool {
        self.inner.cfg.deployment == Deployment::Development || uid != Some(self.inner.broker_uid)
    }

    /// The wall clock, or a refusal. There is no fallback reading: with no
    /// clock, expiries and daily budgets cannot be evaluated.
    fn now(&self) -> Result<u64, Refusal> {
        unix_time().map_err(|e| Refusal::new(Code::ClockFailed, e.to_string()))
    }

    fn record(&self, id: TicketId, state: TicketState) -> Result<(), Refusal> {
        // An outcome must be recorded even if the clock has just broken;
        // then the ticket is simply kept until a compaction with a working
        // clock, which errs on the side of never re-sending.
        let ttl = if state == TicketState::Live {
            self.inner.cfg.live_ttl_s
        } else {
            self.inner.cfg.retention_s
        };
        let deadline = unix_time().map_or(u64::MAX, |now| now.saturating_add(ttl));
        self.inner
            .journal
            .transition(id, state, deadline)
            .map_err(|e| Refusal::new(Code::JournalFailed, format!("journal write failed: {e}")))
    }

    /// For audit records written after the effect, where there is nothing
    /// left to fail closed.
    fn audit_lossy(&self, event: &AuditEvent<'_>) {
        if let Err(e) = self.inner.audit.append(event) {
            eprintln!("keygate: audit append failed after the fact: {e}");
        }
    }

    fn settle(&self, id: TicketId, actual: Option<u64>) {
        if let Some(actual) = actual {
            if let Err(e) = self.inner.journal.settle(id, actual) {
                eprintln!("keygate: ticket {id} keeps its reservation; settling failed: {e}");
            }
        }
    }

    // ----- operator surface -------------------------------------------------

    /// Mint a root macaroon for `seat`, optionally bound to a peer uid and
    /// pre-attenuated with `caveats`.
    pub fn mint(
        &self,
        seat: &str,
        allowed_uid: Option<u32>,
        caveats: Vec<Caveat>,
        by: Caller,
    ) -> Result<String, Refusal> {
        if !valid_name(seat) {
            return Err(Refusal::new(
                Code::BadRequest,
                "seat must match [A-Za-z0-9][A-Za-z0-9_.-]{0,63}",
            ));
        }
        let mut nonce = [0u8; 16];
        keygate_core::random_bytes(&mut nonce)
            .map_err(|e| Refusal::new(Code::Internal, e.to_string()))?;
        let root = RootId {
            seat: seat.to_owned(),
            allowed_uid,
            root_epoch: self.seat_epoch(seat),
            nonce,
        };
        self.inner
            .audit
            .append(&AuditEvent::Admin {
                action: "mint",
                uid: by.uid,
                namespace: None,
                target: seat,
                detail: &format!("{} caveats", caveats.len()),
            })
            .map_err(audit_refusal)?;
        let mut token = MacaroonV1::mint(self.root_key(), root);
        for caveat in caveats {
            token = token
                .attenuate(caveat)
                .map_err(|e| Refusal::new(Code::BadRequest, e.to_string()))?;
        }
        Ok(token.encode())
    }

    /// Append caveats to a token. Keyless; identical to doing it offline.
    pub fn attenuate(token: &str, caveats: Vec<Caveat>) -> Result<String, Refusal> {
        let mut token =
            MacaroonV1::decode(token).map_err(|e| Refusal::new(Code::BadToken, e.to_string()))?;
        for caveat in caveats {
            token = token
                .attenuate(caveat)
                .map_err(|e| Refusal::new(Code::BadRequest, e.to_string()))?;
        }
        Ok(token.encode())
    }

    /// Load or rotate a row's secret (audited first; fails closed). The
    /// previous secret stays a retired guard pattern unless `forget_retired`.
    pub fn set(
        &self,
        ns: Namespace,
        row: &str,
        secret: SecretBytes,
        cut_existing: bool,
        forget_retired: bool,
        by: Caller,
    ) -> Result<RowEpoch, Refusal> {
        self.inner.vault.upstream(ns, row)?;
        let detail = match (cut_existing, forget_retired) {
            (true, true) => "cut-existing, forget-retired",
            (true, false) => "cut-existing",
            (false, true) => "rotate, forget-retired",
            (false, false) => "rotate",
        };
        self.inner
            .audit
            .append(&AuditEvent::Admin {
                action: "set",
                uid: by.uid,
                namespace: Some(ns),
                target: row,
                detail,
            })
            .map_err(audit_refusal)?;
        self.inner
            .vault
            .set(ns, row, secret, cut_existing, forget_retired)
    }

    /// Stop using a row's secret and cut its streams. Revocation is the one
    /// effect that happens *before* its audit record: failing to log must
    /// not keep a compromised key alive. The secret is kept sealed as a
    /// retired guard pattern unless `forget`.
    pub fn revoke(
        &self,
        ns: Namespace,
        row: &str,
        forget: bool,
        by: Caller,
    ) -> Result<RowEpoch, Refusal> {
        let epoch = self.inner.vault.revoke(ns, row, forget)?;
        self.inner
            .audit
            .append(&AuditEvent::Admin {
                action: "revoke",
                uid: by.uid,
                namespace: Some(ns),
                target: row,
                detail: if forget { "forget" } else { "" },
            })
            .map_err(|e| {
                Refusal::new(
                    Code::AuditFailed,
                    format!("{ns}/{row} IS revoked, but the audit record failed: {e}"),
                )
            })?;
        Ok(epoch)
    }

    /// Drop a row's retired secrets (audited first; fails closed). Returns
    /// how many were dropped.
    pub fn forget(&self, ns: Namespace, row: &str, by: Caller) -> Result<usize, Refusal> {
        self.inner.vault.upstream(ns, row)?;
        self.inner
            .audit
            .append(&AuditEvent::Admin {
                action: "forget",
                uid: by.uid,
                namespace: Some(ns),
                target: row,
                detail: "",
            })
            .map_err(audit_refusal)?;
        self.inner.vault.forget(ns, row)
    }

    /// Invalidate every macaroon minted for `seat` so far.
    pub fn revoke_seat(&self, seat: &str, by: Caller) -> Result<u64, Refusal> {
        if !valid_name(seat) {
            return Err(Refusal::new(Code::BadRequest, "invalid seat name"));
        }
        let _admin = self
            .inner
            .seat_admin
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let mut next = (**self.inner.seats.borrow()).clone();
        let epoch = next
            .get(seat)
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| Refusal::new(Code::Internal, "seat epoch exhausted"))?;
        next.insert(seat.to_owned(), epoch);
        // Cut live calls before disk I/O, just like row revocation.
        self.inner.seats.send_replace(Arc::new(next.clone()));
        let bytes = serde_json::to_vec_pretty(&next)
            .map_err(|e| Refusal::new(Code::Internal, e.to_string()))?;
        let persisted = write_atomic(&self.inner.state_dir.join(SEATS_FILE), &bytes);
        // Only once this floor is durable in the journal may the old
        // tokens' no-resend records be dropped. If it cannot be written
        // they are simply kept; the next start reconciles.
        let journaled = self.inner.journal.revoke_seat(seat, epoch);
        let audited = self.inner.audit.append(&AuditEvent::Admin {
            action: "revoke-seat",
            uid: by.uid,
            namespace: None,
            target: seat,
            detail: "",
        });
        persisted.map_err(|e| {
            Refusal::new(
                Code::Internal,
                format!("seat IS revoked in memory, but persisting its epoch failed: {e}"),
            )
        })?;
        audited.map_err(|e| {
            Refusal::new(
                Code::AuditFailed,
                format!("seat IS revoked, but the audit record failed: {e}"),
            )
        })?;
        journaled.map_err(|e| {
            Refusal::new(
                Code::JournalFailed,
                format!("seat IS revoked, but journaling its floor failed: {e}"),
            )
        })?;
        Ok(epoch)
    }

    pub fn rows(&self) -> Vec<RowInfo> {
        self.inner.vault.rows()
    }

    pub fn status(&self) -> StatusInfo {
        StatusInfo {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            uptime_s: self.inner.started.elapsed().as_secs(),
            provider_rows: self.inner.vault.provider_rows(),
            service_rows: self.inner.vault.service_rows(),
            guarded_secrets: self.inner.vault.guarded_secrets(),
            guard_pattern_bytes: self.inner.vault.guard_pattern_bytes(),
            deployment: deployment_name(self.inner.cfg.deployment).to_owned(),
            in_flight: *self.inner.flights.borrow(),
            journal: self.inner.journal.stats(),
            http_listen: self.inner.cfg.http_listen.map(|a| a.to_string()),
        }
    }

    /// Look at a ticket (tests and diagnostics).
    pub fn ticket(&self, id: TicketId) -> Option<Ticket> {
        self.inner.journal.get(id)
    }

    /// Micro-USD charged so far against a ledger key (see `journal::*_key`).
    pub fn spent(&self, ledger_key: &str) -> u64 {
        self.inner.journal.spent(ledger_key)
    }

    /// Calls currently between a claimed ticket and its recorded outcome.
    pub fn in_flight(&self) -> usize {
        *self.inner.flights.borrow()
    }

    /// Stop taking calls, cut every stream and in-flight exchange, and wait
    /// up to `grace` for their outcomes to reach the journal. Returns how
    /// many flights were still unrecorded at the deadline; those stay
    /// `InFlight` on disk and come back `Uncertain` at the next start.
    pub async fn shutdown(&self, grace: Duration) -> usize {
        self.inner.shutdown.send_replace(true);
        let mut flights = self.inner.flights.subscribe();
        let _ = tokio::time::timeout(grace, flights.wait_for(|open| *open == 0)).await;
        self.in_flight()
    }

    // ----- admission --------------------------------------------------------

    /// Decide whether a call should be handled as a stream: a provider call
    /// whose JSON body says `"stream": true`, or a service call whose path
    /// lies under the row's `stream_paths`. Used by the HTTP gateway, where
    /// the caller cannot say which operation it means.
    pub fn classify(
        &self,
        ns: Namespace,
        row: &str,
        path: &str,
        body: &[u8],
    ) -> Result<CallKind, Refusal> {
        match ns {
            Namespace::Provider => {
                self.inner.vault.provider(row)?;
                Ok(Broker::provider_kind(body))
            }
            Namespace::Service => {
                let service = self.inner.vault.service(row)?;
                let path = PlainPath::parse(path)
                    .map_err(|e| Refusal::new(Code::PathRefused, e.to_string()))?;
                Ok(if path.under_any(&service.stream_paths) {
                    CallKind::Stream
                } else {
                    CallKind::Buffered
                })
            }
        }
    }

    /// Which operation a provider body asks for.
    pub fn provider_kind(body: &[u8]) -> CallKind {
        if stream_requested(body) {
            CallKind::Stream
        } else {
            CallKind::Buffered
        }
    }

    /// Everything about a token that does not depend on the request:
    /// signature, seat epoch, uid binding, and whether this peer may call.
    fn verify_token(&self, token: &str, caller: Caller) -> Result<Verified, Refusal> {
        if *self.inner.shutdown.borrow() {
            return Err(Refusal::new(
                Code::ShuttingDown,
                "the broker is shutting down and takes no new calls",
            ));
        }
        if !self.may_call(caller.uid) {
            return Err(Refusal::new(
                Code::Denied,
                "this peer runs as the broker's own uid, which can read the master key directly. \
                 A separated deployment does not serve it as a caller; run callers under another \
                 uid, or declare the deployment \"development\"",
            ));
        }
        let token =
            MacaroonV1::decode(token).map_err(|e| Refusal::new(Code::BadToken, e.to_string()))?;
        let verified = token
            .verify(self.root_key())
            .map_err(|e| Refusal::new(Code::BadToken, e.to_string()))?;
        let seat = &verified.root.seat;
        if verified.root.root_epoch < self.seat_epoch(seat) {
            return Err(Refusal::new(
                Code::Denied,
                format!("seat {seat:?} was revoked after this token was minted"),
            ));
        }
        if let Some(bound) = verified.root.allowed_uid {
            match caller.uid {
                Some(uid) if uid == bound => {}
                Some(uid) => {
                    return Err(Refusal::new(
                        Code::Denied,
                        format!("token is bound to uid {bound}; peer is uid {uid}"),
                    ))
                }
                None => {
                    return Err(Refusal::new(
                        Code::Denied,
                        "token is uid-bound and this transport has no peer credentials",
                    ))
                }
            }
        }
        Ok(verified)
    }

    /// Step 0, for transports: check the token and the route before any
    /// request body is read. Returns the largest body this caller may send
    /// to this row. Touches neither disk nor network.
    pub fn preauthorize(
        &self,
        ns: Namespace,
        row: &str,
        token: &str,
        caller: Caller,
    ) -> Result<usize, Refusal> {
        let now = self.now()?;
        let verified = self.verify_token(token, caller)?;
        let upstream = self.inner.vault.upstream(ns, row)?;
        verified
            .admit_route(ns, row, now)
            .map_err(|e| Refusal::new(Code::Denied, e.to_string()))?;
        Ok(upstream
            .max_request_bytes
            .min(verified.max_request_bytes().unwrap_or(usize::MAX)))
    }

    /// Largest request body any row accepts.
    pub fn max_request_bytes(&self) -> usize {
        self.inner.vault.max_request_bytes()
    }

    fn prepare(
        &self,
        ns: Namespace,
        caller: Caller,
        call: Call,
        kind: CallKind,
        mode: HeaderMode,
    ) -> Result<Prepared, Refusal> {
        let vault = &self.inner.vault;
        let now = self.now()?;
        let verified = self.verify_token(&call.token, caller)?;
        let seat = verified.root.seat.clone();

        let path = PlainPath::parse(&call.path)
            .map_err(|e| Refusal::new(Code::PathRefused, e.to_string()))?;
        let query = call.query.as_deref().filter(|q| !q.is_empty());
        if let Some(query) = query {
            check_query(query).map_err(|e| Refusal::new(Code::PathRefused, e.to_string()))?;
        }
        let method: reqwest::Method = match call.method.as_str() {
            "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" => {
                call.method.parse().expect("standard method")
            }
            other => {
                return Err(Refusal::new(
                    Code::MethodRefused,
                    format!("method {other:?} is not supported (methods are uppercase)"),
                ))
            }
        };

        let (upstream, admission) = match ns {
            Namespace::Provider => {
                let row = vault.provider(&call.row)?;
                if call.body.len() > row.upstream.max_request_bytes {
                    return Err(too_large(
                        ns,
                        &call.row,
                        call.body.len(),
                        row.upstream.max_request_bytes,
                    ));
                }
                let admission = admit_provider(row, &seat, &method, &path, &call.body, kind, now)?;
                if !verified.spend_scopes.is_empty()
                    && admission.model.is_some()
                    && row.prices.is_zero()
                {
                    return Err(Refusal::new(
                        Code::Denied,
                        format!(
                            "this token carries MaxSpendMicroUsd, but provider/{} has no token \
                             prices, so its calls cost nothing here and the cap could not bind",
                            call.row
                        ),
                    ));
                }
                (&row.upstream, admission)
            }
            Namespace::Service => {
                let row = vault.service(&call.row)?;
                if !row.methods.iter().any(|m| m == method.as_str()) {
                    return Err(Refusal::new(
                        Code::MethodRefused,
                        format!("{ns}/{} does not allow {method}", call.row),
                    ));
                }
                let (paths, what) = match kind {
                    CallKind::Buffered => (&row.buffered_paths, "buffered_paths"),
                    CallKind::Stream => (&row.stream_paths, "stream_paths"),
                };
                if !path.under_any(paths) {
                    return Err(Refusal::new(
                        Code::PathRefused,
                        format!("{path} is not under {ns}/{}'s {what}", call.row),
                    ));
                }
                if call.body.len() > row.upstream.max_request_bytes {
                    return Err(too_large(
                        ns,
                        &call.row,
                        call.body.len(),
                        row.upstream.max_request_bytes,
                    ));
                }
                (&row.upstream, ProviderAdmission::default())
            }
        };

        verified
            .admit(&Facts {
                seat: &seat,
                namespace: ns,
                row: &call.row,
                method: method.as_str(),
                path: &path,
                model: admission.model.as_deref(),
                request_bytes: call.body.len(),
                now_unix_s: now,
            })
            .map_err(|e| Refusal::new(Code::Denied, e.to_string()))?;

        let headers = forwarded_headers(upstream, &call, mode)?;
        token_stays_home(&call, query, &headers)?;

        let mut url = format!("{}{}", upstream.origin, path);
        if let Some(query) = query {
            url.push('?');
            url.push_str(query);
        }
        let url = reqwest::Url::parse(&url)
            .map_err(|e| Refusal::new(Code::PathRefused, format!("url: {e}")))?;
        // The URL library must agree byte-for-byte with what was admitted.
        if url.path() != path.as_str() || url.query() != query {
            return Err(Refusal::new(
                Code::PathRefused,
                "path or query does not survive URL parsing unchanged",
            ));
        }

        let mut charges = admission.charges;
        if admission.reserve_micro_usd > 0 {
            charges.extend(verified.spend_scopes.iter().map(|scope| Charge {
                key: journal::scope_key(&scope.id),
                cap_micro_usd: Some(scope.cap_micro_usd),
            }));
        }

        let digest = request_digest(ns, kind, &call, method.as_str(), query, &headers, &verified);
        Ok(Prepared {
            ns,
            row: call.row,
            kind,
            seat,
            root_epoch: verified.root.root_epoch,
            uid: caller.uid,
            digest,
            method,
            path: call.path,
            url,
            headers,
            body: Bytes::from(call.body),
            reserve_micro_usd: admission.reserve_micro_usd,
            charges,
            prices: admission.prices,
            expires_at_unix_s: verified.expires_at_unix_s(),
            admitted_unix_s: now,
        })
    }

    fn open_ticket(&self, p: &Prepared) -> Result<(Ticket, bool), Refusal> {
        self.inner
            .journal
            .authorize(NewTicket {
                seat: p.seat.clone(),
                digest: p.digest,
                namespace: p.ns,
                row: p.row.clone(),
                kind: p.kind,
                charges: p.charges.clone(),
                reserve_micro_usd: p.reserve_micro_usd,
                now_unix_s: p.admitted_unix_s,
                live_ttl_s: self.inner.cfg.live_ttl_s,
                owner_expires_unix_s: p.expires_at_unix_s,
                root_epoch: p.root_epoch,
            })
            .map_err(|e| match e {
                JournalError::Budget { .. } => Refusal::new(Code::BudgetExceeded, e.to_string()),
                JournalError::UncertainFull { .. } => {
                    Refusal::new(Code::NoResendLedgerFull, e.to_string())
                }
                other => Refusal::new(Code::JournalFailed, other.to_string()),
            })
    }

    /// Check a call and reserve its ticket without sending anything.
    pub fn authorize(
        &self,
        ns: Namespace,
        caller: Caller,
        call: Call,
        kind: CallKind,
    ) -> Result<Authorized, Refusal> {
        let p = self.prepare(ns, caller, call, kind, HeaderMode::Strict)?;
        let (ticket, existing) = self.open_ticket(&p)?;
        Ok(Authorized {
            ticket: ticket.id,
            state: ticket.state.name(),
            existing,
            reserved_micro_usd: ticket.reserved_micro_usd,
        })
    }

    /// Steps 3 and 4: claim the ticket and audit `Begin`. No network yet.
    fn begin(&self, p: &Prepared, id: TicketId) -> Result<Flight, Refusal> {
        let upstream = self.inner.vault.upstream(p.ns, &p.row)?;
        let Some((secret, automaton)) = self.inner.vault.snapshot(upstream) else {
            let epoch = upstream.epoch();
            return Err(if epoch.revoked_floor > epoch.generation {
                Refusal::new(
                    Code::Revoked,
                    format!("{}/{} is revoked; `keygate set` a new secret", p.ns, p.row),
                )
            } else {
                Refusal::new(
                    Code::NoSecret,
                    format!(
                        "{}/{} has no secret; load one with `keygate set`",
                        p.ns, p.row
                    ),
                )
            });
        };
        let epoch = upstream.watch();

        match self.inner.journal.begin(id) {
            Ok(Begin::Started) => {}
            Ok(Begin::NotLive(ticket)) => return Err(not_live(&ticket)),
            Ok(Begin::Missing) => {
                return Err(Refusal::new(
                    Code::Internal,
                    "ticket vanished before it could be claimed",
                ))
            }
            Err(e) => {
                return Err(Refusal::new(
                    Code::JournalFailed,
                    format!("journal write failed: {e}"),
                ))
            }
        }
        self.inner
            .flights
            .send_modify(|open| *open = open.saturating_add(1));
        let mut guard = FlightGuard {
            broker: self.clone(),
            id,
            armed: true,
            counted: Some(InFlight(self.clone())),
        };

        let audited = self.inner.audit.append(&AuditEvent::Begin {
            ticket: id,
            seat: &p.seat,
            uid: p.uid,
            namespace: p.ns,
            row: &p.row,
            method: p.method.as_str(),
            path: &p.path,
            stream: p.kind == CallKind::Stream,
            generation: secret.generation,
            request_digest: blake3::Hash::from(p.digest).to_hex().to_string(),
            request_bytes: p.body.len(),
        });
        if let Err(e) = audited {
            // Nothing has been sent, so the ticket goes back to `Live`.
            guard.armed = false;
            self.record(id, TicketState::Live)?;
            return Err(audit_refusal(e));
        }
        // Only streams are cut at expiry; a buffered call is already
        // bounded by `buffered_timeout_ms`.
        let expires = p
            .expires_at_unix_s
            .filter(|_| p.kind == CallKind::Stream)
            .and_then(|at| {
                let left = Duration::from_secs(at.saturating_sub(p.admitted_unix_s));
                tokio::time::Instant::now().checked_add(left)
            });
        let watch = CutWatch {
            epoch,
            generation: secret.generation,
            seats: self.inner.seats.subscribe(),
            seat: p.seat.clone(),
            root_epoch: p.root_epoch,
            shutdown: self.inner.shutdown.subscribe(),
            expires,
        };
        Ok(Flight {
            guard,
            secret,
            watch,
            automaton,
        })
    }

    async fn send(
        &self,
        p: &Prepared,
        secret: &ActiveSecret,
        upstream: &Upstream,
    ) -> Result<reqwest::Response, ExchangeError> {
        let mut headers = p.headers.clone();
        let mut value = Vec::with_capacity(upstream.auth_prefix.len() + secret.expose().len());
        value.extend_from_slice(upstream.auth_prefix.as_bytes());
        value.extend_from_slice(secret.expose());
        let auth = HeaderValue::from_bytes(&value);
        value.zeroize();
        let mut auth = auth
            .map_err(|_| ExchangeError::Connect("secret is not a valid header value".to_owned()))?;
        auth.set_sensitive(true);
        headers.insert(upstream.auth_header.clone(), auth);
        // EchoGuard scans plaintext; a compressed echo would slip past it.
        headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));

        let mut request = self
            .inner
            .http
            .request(p.method.clone(), p.url.clone())
            .headers(headers);
        if !p.body.is_empty() {
            request = request.body(p.body.clone());
        }
        if p.kind == CallKind::Buffered {
            request = request.timeout(Duration::from_millis(self.inner.cfg.buffered_timeout_ms));
        }
        request.send().await.map_err(|e| {
            if e.is_connect() {
                ExchangeError::Connect(e.without_url().to_string())
            } else {
                ExchangeError::Upstream(e.without_url().to_string())
            }
        })
    }

    async fn prepare_flight(
        &self,
        ns: Namespace,
        caller: Caller,
        call: Call,
        kind: CallKind,
        mode: HeaderMode,
    ) -> Result<(Prepared, Ticket, Option<Flight>), Refusal> {
        self.disk(move |broker| {
            let p = broker.prepare(ns, caller, call, kind, mode)?;
            let (ticket, _) = broker.open_ticket(&p)?;
            let flight = if ticket.state == TicketState::Live {
                Some(broker.begin(&p, ticket.id)?)
            } else {
                None
            };
            Ok((p, ticket, flight))
        })
        .await
    }

    // ----- buffered ---------------------------------------------------------

    /// Send a buffered call, or replay its retained reply on exact retry.
    pub async fn forward(
        &self,
        ns: Namespace,
        caller: Caller,
        call: Call,
        mode: HeaderMode,
    ) -> Result<BufferedReply, Refusal> {
        let (p, ticket, flight) = self
            .prepare_flight(ns, caller, call, CallKind::Buffered, mode)
            .await?;
        match ticket.state {
            TicketState::Live => {}
            TicketState::Replayable(retained) => {
                return Ok(BufferedReply {
                    ticket: ticket.id,
                    status: retained.status,
                    headers: retained.headers,
                    body: retained.body,
                    replayed: true,
                })
            }
            _ => return Err(not_live(&ticket)),
        }

        let mut flight = flight.expect("Live ticket was claimed");
        let upstream = self.inner.vault.upstream(p.ns, &p.row)?;
        let outcome = tokio::select! {
            biased;
            cut = flight.watch.cut() => Err(ExchangeError::Cut(cut)),
            outcome = self.buffered_exchange(&p, &flight.secret, upstream, &flight.automaton) => outcome,
        };

        let id = ticket.id;
        match outcome {
            Ok(retained) => {
                let reply = BufferedReply {
                    ticket: id,
                    status: retained.status,
                    headers: retained.headers.clone(),
                    body: retained.body.clone(),
                    replayed: false,
                };
                flight
                    .guard
                    .finish(TicketState::Replayable(retained))
                    .await?;
                let actual = p
                    .prices
                    .and_then(|prices| metered_cost(&reply.body, prices));
                let status = reply.status;
                let bytes = reply.body.len() as u64;
                self.disk(move |broker| {
                    broker.settle(id, actual);
                    broker.audit_lossy(&AuditEvent::End {
                        ticket: id,
                        status,
                        bytes,
                        withheld: false,
                    });
                })
                .await;
                Ok(reply)
            }
            Err(ExchangeError::Connect(why)) => {
                flight.guard.finish(TicketState::Live).await?;
                self.disk(move |b| {
                    b.audit_lossy(&AuditEvent::Failed {
                        ticket: id,
                        reason: "connect failed; nothing sent",
                    })
                })
                .await;
                Err(Refusal::new(
                    Code::UpstreamFailed,
                    format!(
                        "could not connect to upstream (nothing was sent; retry is safe): {why}"
                    ),
                ))
            }
            Err(ExchangeError::Withheld { status }) => {
                flight
                    .guard
                    .finish(TicketState::Withheld { status })
                    .await?;
                self.disk(move |b| {
                    b.audit_lossy(&AuditEvent::End {
                        ticket: id,
                        status,
                        bytes: 0,
                        withheld: true,
                    })
                })
                .await;
                Err(withheld_refusal())
            }
            Err(failure) => {
                let (code, reason) = match failure {
                    ExchangeError::Cut(cut) => (cut.code(), cut.reason().to_owned()),
                    ExchangeError::TooLarge => (
                        Code::TooLarge,
                        format!(
                            "upstream reply exceeds {} bytes",
                            self.inner.cfg.max_response_bytes
                        ),
                    ),
                    ExchangeError::Upstream(why) => (Code::UpstreamFailed, why),
                    ExchangeError::Connect(_) | ExchangeError::Withheld { .. } => {
                        unreachable!("handled above")
                    }
                };
                flight.guard.finish(TicketState::Uncertain).await?;
                let audit_reason = reason.clone();
                self.disk(move |b| {
                    b.audit_lossy(&AuditEvent::Failed {
                        ticket: id,
                        reason: &audit_reason,
                    })
                })
                .await;
                Err(Refusal::new(
                    code,
                    format!(
                        "{reason} (the request may have reached the upstream; ticket is uncertain)"
                    ),
                ))
            }
        }
    }

    async fn buffered_exchange(
        &self,
        p: &Prepared,
        secret: &ActiveSecret,
        upstream: &Upstream,
        automaton: &EchoAutomaton,
    ) -> Result<Retained, ExchangeError> {
        let mut response = self.send(p, secret, upstream).await?;
        let status = response.status().as_u16();
        if !head_is_clean(automaton, &response) {
            return Err(ExchangeError::Withheld { status });
        }
        let headers = caller_visible_headers(response.headers());
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| ExchangeError::Upstream(e.without_url().to_string()))?
        {
            if body.len() + chunk.len() > self.inner.cfg.max_response_bytes {
                body.zeroize();
                return Err(ExchangeError::TooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        if automaton.contains(&body) {
            body.zeroize();
            return Err(ExchangeError::Withheld { status });
        }
        Ok(Retained {
            status,
            headers,
            body,
        })
    }

    // ----- streaming --------------------------------------------------------

    /// Open a stream, or report how this exact stream request already ended.
    pub async fn stream(
        &self,
        ns: Namespace,
        caller: Caller,
        call: Call,
        mode: HeaderMode,
    ) -> Result<StreamOutcome, Refusal> {
        let (p, ticket, flight) = self
            .prepare_flight(ns, caller, call, CallKind::Stream, mode)
            .await?;
        let id = ticket.id;
        match ticket.state {
            TicketState::Live => {}
            TicketState::Closed(summary) => {
                return Ok(StreamOutcome::Spent {
                    ticket: id,
                    summary,
                })
            }
            _ => return Err(not_live(&ticket)),
        }

        let mut flight = flight.expect("Live ticket was claimed");
        let upstream = self.inner.vault.upstream(p.ns, &p.row)?;
        let sent = tokio::select! {
            biased;
            cut = flight.watch.cut() => Err(ExchangeError::Cut(cut)),
            sent = self.send(&p, &flight.secret, upstream) => sent,
        };
        let response = match sent {
            Ok(response) => response,
            Err(ExchangeError::Connect(why)) => {
                flight.guard.finish(TicketState::Live).await?;
                self.disk(move |b| {
                    b.audit_lossy(&AuditEvent::Failed {
                        ticket: id,
                        reason: "connect failed; nothing sent",
                    })
                })
                .await;
                return Err(Refusal::new(
                    Code::UpstreamFailed,
                    format!(
                        "could not connect to upstream (nothing was sent; retry is safe): {why}"
                    ),
                ));
            }
            Err(ExchangeError::Cut(cut)) => {
                let summary = cut_summary(0, cut.closed_by());
                return Err(self
                    .close_refused(flight, summary, cut.code(), cut.reason())
                    .await);
            }
            Err(ExchangeError::Upstream(why)) => {
                flight.guard.finish(TicketState::Uncertain).await?;
                let audit_reason = why.clone();
                self.disk(move |b| {
                    b.audit_lossy(&AuditEvent::Failed {
                        ticket: id,
                        reason: &audit_reason,
                    })
                })
                .await;
                return Err(Refusal::new(
                    Code::UpstreamFailed,
                    format!(
                        "{why} (the request may have reached the upstream; ticket is uncertain)"
                    ),
                ));
            }
            Err(ExchangeError::TooLarge | ExchangeError::Withheld { .. }) => {
                unreachable!("send does not read the reply")
            }
        };

        let status = response.status().as_u16();
        if !head_is_clean(&flight.automaton, &response) {
            drop(response);
            let summary = cut_summary(status, ClosedBy::Withheld);
            return Err(self
                .close_refused(
                    flight,
                    summary,
                    Code::Withheld,
                    "the upstream reply head contained a guarded secret; stream withheld",
                )
                .await);
        }
        let headers = caller_visible_headers(response.headers());

        let (items_tx, items) = mpsc::channel(STREAM_CHANNEL_DEPTH);
        tokio::spawn(
            self.clone()
                .relay(flight, response, p.prices, status, items_tx),
        );
        Ok(StreamOutcome::Live(LiveStream {
            ticket: id,
            status,
            headers,
            items,
        }))
    }

    /// Close a stream ticket that never produced a head, and refuse.
    async fn close_refused(
        &self,
        flight: Flight,
        summary: StreamSummary,
        code: Code,
        message: &str,
    ) -> Refusal {
        let id = flight.guard.id;
        if let Err(refusal) = flight
            .guard
            .finish(TicketState::Closed(summary.clone()))
            .await
        {
            return refusal;
        }
        let audit_summary = summary.clone();
        self.disk(move |b| {
            b.audit_lossy(&AuditEvent::StreamEnd {
                ticket: id,
                summary: &audit_summary,
            })
        })
        .await;
        Refusal {
            code,
            message: message.to_owned(),
            summary: Some(summary),
        }
    }

    /// The stream relay. One task per open stream; it parks in `select!`
    /// and performs no I/O other than the two sockets. It wakes for a cut
    /// (row or seat revocation, token expiry, shutdown), for the caller
    /// going away, and for the next upstream chunk.
    async fn relay(
        self,
        mut flight: Flight,
        mut response: reqwest::Response,
        prices: Option<Prices>,
        status: u16,
        items: mpsc::Sender<StreamItem>,
    ) {
        let id = flight.guard.id;
        let mut guard = EchoGuard::new(flight.automaton.clone());
        let mut usage = prices.map(|_| UsageSniffer::default());
        let mut delivered = 0u64;
        let mut safe = Vec::new();

        let closed_by = loop {
            tokio::select! {
                biased;
                cut = flight.watch.cut() => break cut.closed_by(),
                _ = items.closed() => break ClosedBy::CallerDisconnect,
                chunk = response.chunk() => {
                    let last = match chunk {
                        Ok(Some(chunk)) => {
                            if let Some(usage) = &mut usage { usage.push(&chunk); }
                            if guard.push(&chunk, &mut safe).is_err() {
                                break ClosedBy::Withheld;
                            }
                            false
                        }
                        Ok(None) => {
                            if guard.finish(&mut safe).is_err() {
                                break ClosedBy::Withheld;
                            }
                            true
                        }
                        Err(_) => break ClosedBy::UpstreamError,
                    };
                    if !safe.is_empty() {
                        let len = safe.len() as u64;
                        let data = Bytes::from(std::mem::take(&mut safe));
                        let sent = tokio::select! {
                            biased;
                            cut = flight.watch.cut() => Err(cut.closed_by()),
                            sent = items.send(StreamItem::Chunk(data)) => sent.map_err(|_| ClosedBy::CallerDisconnect),
                        };
                        match sent {
                            Ok(()) => delivered += len,
                            Err(by) => break by,
                        }
                    }
                    if last {
                        break ClosedBy::UpstreamEof;
                    }
                }
            }
        };
        // Dropping the response aborts the upstream request.
        drop(response);
        drop(guard);
        safe.zeroize();

        let summary = StreamSummary {
            status,
            bytes: delivered,
            complete: closed_by == ClosedBy::UpstreamEof,
            withheld: closed_by == ClosedBy::Withheld,
            revoked: closed_by == ClosedBy::Revoked,
            closed_by,
        };
        if let Err(e) = flight
            .guard
            .finish(TicketState::Closed(summary.clone()))
            .await
        {
            eprintln!("keygate: stream ticket {id} closed but not journaled: {e}");
        }
        let actual = if summary.complete {
            usage.and_then(|u| u.cost(prices.expect("sniffer requires prices")))
        } else {
            None
        };
        let audit_summary = summary.clone();
        self.disk(move |b| {
            b.settle(id, actual);
            b.audit_lossy(&AuditEvent::StreamEnd {
                ticket: id,
                summary: &audit_summary,
            });
        })
        .await;
        let _ = items.send(StreamItem::End(summary)).await;
    }
}

impl Cut {
    fn closed_by(self) -> ClosedBy {
        match self {
            Cut::Revoked => ClosedBy::Revoked,
            Cut::Expired => ClosedBy::Expired,
            Cut::Shutdown => ClosedBy::Shutdown,
        }
    }

    fn code(self) -> Code {
        match self {
            Cut::Revoked => Code::Revoked,
            Cut::Expired => Code::Denied,
            Cut::Shutdown => Code::ShuttingDown,
        }
    }

    fn reason(self) -> &'static str {
        match self {
            Cut::Revoked => "secret or seat revoked mid-flight",
            Cut::Expired => "the token expired while the stream was open",
            Cut::Shutdown => "the broker shut down mid-flight",
        }
    }
}

fn deployment_name(deployment: Deployment) -> &'static str {
    match deployment {
        Deployment::Separated => "separated",
        Deployment::Development => "development",
    }
}

fn too_large(ns: Namespace, row: &str, have: usize, max: usize) -> Refusal {
    Refusal::new(
        Code::TooLarge,
        format!("request body is {have} bytes; {ns}/{row} allows {max}"),
    )
}

fn cut_summary(status: u16, closed_by: ClosedBy) -> StreamSummary {
    StreamSummary {
        status,
        bytes: 0,
        complete: false,
        withheld: closed_by == ClosedBy::Withheld,
        revoked: closed_by == ClosedBy::Revoked,
        closed_by,
    }
}

fn audit_refusal(e: std::io::Error) -> Refusal {
    Refusal::new(
        Code::AuditFailed,
        format!("audit log is not writable; refusing before any upstream I/O: {e}"),
    )
}

fn withheld_refusal() -> Refusal {
    Refusal::new(
        Code::Withheld,
        "the upstream reply contained a guarded secret and was withheld",
    )
}

/// Why a ticket that is not `Live` cannot be sent.
fn not_live(ticket: &Ticket) -> Refusal {
    match &ticket.state {
        TicketState::InFlight => Refusal::new(Code::InFlight, "an identical request is in flight; use a distinct request_id for a deliberate repeat"),
        TicketState::Uncertain => Refusal::new(
            Code::Uncertain,
            "an earlier attempt of this exact request may have reached the upstream and its reply was lost; it will not be re-sent, now or later, while this token is valid. To send it again deliberately, give it a new request id (Idempotency-Key)",
        ),
        TicketState::Withheld { .. } => withheld_refusal(),
        TicketState::Closed(summary) => {
            Refusal { code: Code::BadRequest, message: "this ticket is a finished stream".to_owned(), summary: Some(summary.clone()) }
        }
        TicketState::Live | TicketState::Replayable(_) => Refusal::new(Code::Internal, "ticket state changed underneath the request; retry"),
    }
}

/// Scan the status line and every header, whole, before anything is
/// forwarded. Also refuses encoded bodies, which the guard cannot read.
fn head_is_clean(automaton: &EchoAutomaton, response: &reqwest::Response) -> bool {
    let encoded = response
        .headers()
        .get_all(CONTENT_ENCODING)
        .iter()
        .any(|v| !v.as_bytes().eq_ignore_ascii_case(b"identity"));
    if encoded {
        return false;
    }
    let mut head = Vec::with_capacity(512);
    head.extend_from_slice(response.status().as_str().as_bytes());
    head.push(b' ');
    head.extend_from_slice(
        response
            .status()
            .canonical_reason()
            .unwrap_or("")
            .as_bytes(),
    );
    for (name, value) in response.headers() {
        head.extend_from_slice(b"\r\n");
        head.extend_from_slice(name.as_str().as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(value.as_bytes());
    }
    let clean = !automaton.contains(&head);
    head.zeroize();
    clean
}

/// Upstream reply headers a caller gets to see. Dropped: hop-by-hop
/// headers, including any the upstream names in `Connection`; and anything
/// in keygate's own `x-keygate-*` namespace, which only keygate may set.
fn caller_visible_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    let hop_by_hop: Vec<String> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .collect();
    headers
        .iter()
        .filter(|(name, _)| {
            !header_is_reserved(name.as_str()) && !hop_by_hop.iter().any(|h| h == name.as_str())
        })
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect()
}

/// A keygate token is a credential for keygate only. Refuse a request that
/// would carry one to the upstream in its query, a forwarded header, or
/// (the presented token itself) its body.
fn token_stays_home(call: &Call, query: Option<&str>, headers: &HeaderMap) -> Result<(), Refusal> {
    let marker = TOKEN_PREFIX.as_bytes();
    let has = |hay: &[u8], needle: &[u8]| hay.windows(needle.len()).any(|w| w == needle);
    if query.is_some_and(|q| has(q.as_bytes(), marker)) {
        return Err(Refusal::new(
            Code::PathRefused,
            "the query contains a keygate token (kgm_); tokens are never forwarded upstream",
        ));
    }
    if let Some((name, _)) = headers.iter().find(|(_, v)| has(v.as_bytes(), marker)) {
        return Err(Refusal::new(
            Code::HeaderRefused,
            format!("header {name:?} contains a keygate token (kgm_); tokens are never forwarded upstream"),
        ));
    }
    if has(&call.body, call.token.as_bytes()) {
        return Err(Refusal::new(
            Code::BadRequest,
            "the request body contains the presented keygate token; it would be sent upstream",
        ));
    }
    Ok(())
}

fn forwarded_headers(
    upstream: &Upstream,
    call: &Call,
    mode: HeaderMode,
) -> Result<HeaderMap, Refusal> {
    let allowed = |name: &str| {
        SAFE_CALLER_HEADERS.contains(&name) || upstream.caller_headers.iter().any(|h| h == name)
    };
    let value = |name: &str, raw: &str| {
        HeaderValue::from_str(raw).map_err(|_| {
            Refusal::new(
                Code::HeaderRefused,
                format!("header {name:?} has an invalid value"),
            )
        })
    };
    let mut headers = HeaderMap::new();
    for (name, raw) in &call.headers {
        let lower = name.to_ascii_lowercase();
        if !allowed(&lower) {
            match mode {
                HeaderMode::Strict => {
                    return Err(Refusal::new(
                        Code::HeaderRefused,
                        format!(
                            "header {lower:?} is not in {}/{}'s caller_headers",
                            upstream.namespace, upstream.name
                        ),
                    ))
                }
                HeaderMode::Filter => continue,
            }
        }
        let header = HeaderName::from_bytes(lower.as_bytes()).map_err(|_| {
            Refusal::new(
                Code::HeaderRefused,
                format!("header name {lower:?} is invalid"),
            )
        })?;
        headers.append(header, value(&lower, raw)?);
    }
    if let Some(id) = &call.last_event_id {
        if !allowed(LAST_EVENT_ID) {
            return Err(Refusal::new(
                Code::HeaderRefused,
                format!(
                    "{}/{} does not allow last-event-id; add it to caller_headers",
                    upstream.namespace, upstream.name
                ),
            ));
        }
        headers.insert(
            HeaderName::from_static(LAST_EVENT_ID),
            value(LAST_EVENT_ID, id)?,
        );
    }
    for (name, fixed) in &upstream.fixed_headers {
        headers.insert(name.clone(), fixed.clone());
    }
    Ok(headers)
}

/// Identity of a request: two calls with equal digests are the same
/// request from the same token, and the second is a retry.
fn request_digest(
    ns: Namespace,
    kind: CallKind,
    call: &Call,
    method: &str,
    query: Option<&str>,
    headers: &HeaderMap,
    verified: &Verified,
) -> RequestDigest32 {
    fn field(hasher: &mut blake3::Hasher, bytes: &[u8]) {
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    let mut hasher = blake3::Hasher::new_derive_key("keygate-request/v2 digest");
    // Tickets belong to the exact token that opened them: a different
    // token, even of the same seat and even one attenuated from this one,
    // gets its own ticket, its own reservation and no view of this reply.
    field(&mut hasher, &verified.owner);
    let mut scopes: Vec<&[u8; 32]> = verified.spend_scopes.iter().map(|s| &s.id).collect();
    scopes.sort_unstable();
    hasher.update(&(scopes.len() as u64).to_le_bytes());
    for scope in scopes {
        field(&mut hasher, scope);
    }
    field(&mut hasher, ns.as_str().as_bytes());
    field(
        &mut hasher,
        if kind == CallKind::Stream {
            b"stream"
        } else {
            b"buffered"
        },
    );
    field(&mut hasher, call.row.as_bytes());
    field(&mut hasher, method.as_bytes());
    field(&mut hasher, call.path.as_bytes());
    field(&mut hasher, query.unwrap_or("").as_bytes());
    let mut pairs: Vec<(&str, &[u8])> = headers
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_bytes()))
        .collect();
    pairs.sort_unstable();
    hasher.update(&(pairs.len() as u64).to_le_bytes());
    for (name, value) in pairs {
        field(&mut hasher, name.as_bytes());
        field(&mut hasher, value);
    }
    field(&mut hasher, &call.body);
    field(
        &mut hasher,
        call.request_id.as_deref().unwrap_or("").as_bytes(),
    );
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn read_request_head(socket: &mut tokio::net::TcpStream) {
        use tokio::io::AsyncReadExt;
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            assert!(head.len() < 8192);
            let mut byte = [0];
            socket.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
    }

    fn test_broker(origin: &str) -> (tempfile::TempDir, Broker) {
        let dir = tempfile::tempdir().unwrap();
        Broker::init_state(dir.path()).unwrap();
        let cfg = Config::parse(&format!(
            r#"
[broker]
deployment = "development"

[services.api]
origin = "{origin}"
buffered_paths = ["/"]
stream_paths = ["/events"]
"#
        ))
        .unwrap();
        let broker = Broker::open(dir.path(), cfg, BrokerOptions::default()).unwrap();
        broker
            .set(
                Namespace::Service,
                "api",
                SecretBytes::new(b"old-secret-123456".to_vec()),
                false,
                false,
                Caller { uid: None },
            )
            .unwrap();
        (dir, broker)
    }

    /// #tooth: capture g, rotate, then exchange; the response must still be
    /// checked against g, even though the shared guard now covers only g+1.
    #[tokio::test]
    async fn tooth_flight_snapshot_survives_rotation_before_buffered_exchange() {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (_dir, broker) = test_broker(&format!("http://{}", listener.local_addr().unwrap()));
        let caller = Caller { uid: None };
        let token = broker.mint("seat", None, vec![], caller).unwrap();
        let call = Call {
            token,
            row: "api".into(),
            method: "GET".into(),
            path: "/".into(),
            query: None,
            headers: vec![],
            body: vec![],
            request_id: None,
            last_event_id: None,
        };
        let (p, flight) = broker
            .disk(move |b| {
                let p = b
                    .prepare(
                        Namespace::Service,
                        caller,
                        call,
                        CallKind::Buffered,
                        HeaderMode::Strict,
                    )
                    .unwrap();
                let ticket = b.open_ticket(&p).unwrap().0;
                let flight = b.begin(&p, ticket.id).unwrap();
                (p, flight)
            })
            .await;
        broker
            .disk(|b| {
                b.set(
                    Namespace::Service,
                    "api",
                    SecretBytes::new(b"new-secret-123456".to_vec()),
                    false,
                    false,
                    Caller { uid: None },
                )
            })
            .await
            .unwrap();
        let upstream = broker.inner.vault.upstream(p.ns, &p.row).unwrap();
        let shared = |b: &Broker| b.inner.vault.snapshot(upstream).unwrap().1;
        // Rotation retires the old secret into the shared guard...
        assert!(shared(&broker).contains(flight.secret.expose()));
        // ...and once the operator forgets it, only this flight's own
        // snapshot still guards the secret it was actually sent with.
        let forgotten = broker
            .disk(|b| b.forget(Namespace::Service, "api", Caller { uid: None }))
            .await
            .unwrap();
        assert_eq!(forgotten, 1);
        assert!(!shared(&broker).contains(flight.secret.expose()));
        let serve = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            read_request_head(&mut socket).await;
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\nConnection: close\r\n\r\nold-secret-123456").await.unwrap();
        });
        assert!(matches!(
            broker
                .buffered_exchange(&p, &flight.secret, upstream, &flight.automaton)
                .await,
            Err(ExchangeError::Withheld { .. })
        ));
        flight
            .guard
            .finish(TicketState::Withheld { status: 200 })
            .await
            .unwrap();
        serve.await.unwrap();
    }

    fn cut_watch(
        row: &watch::Sender<RowEpoch>,
        seats: &watch::Sender<Arc<BTreeMap<String, u64>>>,
        shutdown: &watch::Sender<bool>,
        expires: Option<tokio::time::Instant>,
    ) -> CutWatch {
        CutWatch {
            epoch: row.subscribe(),
            generation: 1,
            seats: seats.subscribe(),
            seat: "seat".into(),
            root_epoch: 0,
            shutdown: shutdown.subscribe(),
            expires,
        }
    }

    /// #tooth: every cut source wakes the same pending wait by in-memory
    /// notification, and a condition that already holds is seen on the
    /// first poll. The 100 microsecond bound is a measurement of the wake
    /// itself (send to ready), not of a whole stream teardown.
    #[tokio::test]
    async fn tooth_cut_sources_wake_without_io() {
        use std::future::Future;
        use std::task::Poll;
        let row = watch::Sender::new(RowEpoch {
            generation: 1,
            revoked_floor: 0,
        });
        let seats = watch::Sender::new(Arc::new(BTreeMap::new()));
        let shutdown = watch::Sender::new(false);

        let wake = |fire: &dyn Fn()| {
            let mut watch = cut_watch(&row, &seats, &shutdown, None);
            let mut wait = Box::pin(async move { watch.cut().await });
            let waker = std::task::Waker::noop();
            let mut cx = std::task::Context::from_waker(waker);
            assert!(wait.as_mut().poll(&mut cx).is_pending());
            let start = Instant::now();
            fire();
            let Poll::Ready(cut) = wait.as_mut().poll(&mut cx) else {
                panic!("cut source did not wake the wait")
            };
            (cut, start.elapsed())
        };
        let (cut, elapsed) = wake(&|| {
            seats.send_replace(Arc::new(BTreeMap::from([("seat".into(), 1)])));
        });
        assert_eq!(cut, Cut::Revoked);
        assert!(
            elapsed < Duration::from_micros(100),
            "seat wake took {elapsed:?}"
        );
        seats.send_replace(Arc::new(BTreeMap::new()));

        let (cut, elapsed) = wake(&|| {
            row.send_replace(RowEpoch {
                generation: 1,
                revoked_floor: 2,
            });
        });
        assert_eq!(cut, Cut::Revoked);
        assert!(
            elapsed < Duration::from_micros(100),
            "row wake took {elapsed:?}"
        );
        row.send_replace(RowEpoch {
            generation: 1,
            revoked_floor: 0,
        });

        let (cut, _) = wake(&|| {
            shutdown.send_replace(true);
        });
        assert_eq!(cut, Cut::Shutdown);

        // Already cut: no send can start.
        let mut watch = cut_watch(&row, &seats, &shutdown, None);
        tokio::select! {
            biased;
            cut = watch.cut() => assert_eq!(cut, Cut::Shutdown),
            _ = std::future::ready(()) => panic!("a shut-down broker could start an upstream send"),
        }
    }

    /// #tooth: a stream's wait ends at the token's expiry, by timer, and
    /// not before it.
    #[tokio::test(start_paused = true)]
    async fn tooth_cut_watch_expires_on_the_token_deadline() {
        let row = watch::Sender::new(RowEpoch {
            generation: 1,
            revoked_floor: 0,
        });
        let seats = watch::Sender::new(Arc::new(BTreeMap::new()));
        let shutdown = watch::Sender::new(false);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut watch = cut_watch(&row, &seats, &shutdown, Some(deadline));
        assert!(tokio::time::timeout(Duration::from_secs(29), watch.cut())
            .await
            .is_err());
        assert_eq!(watch.cut().await, Cut::Expired);
        assert!(tokio::time::Instant::now() >= deadline);
        // Without an expiry there is no timer at all.
        let mut forever = cut_watch(&row, &seats, &shutdown, None);
        assert!(
            tokio::time::timeout(Duration::from_secs(86_400 * 365), forever.cut())
                .await
                .is_err()
        );
    }

    /// #tooth: even a stalled disk job cannot occupy the sole async worker.
    /// A live stream still relays bytes while durable work waits on a gate.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn tooth_blocked_disk_work_does_not_starve_relay() {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (_dir, broker) = test_broker(&format!("http://{}", listener.local_addr().unwrap()));
        let (send, receive) = tokio::sync::oneshot::channel();
        let upstream = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            read_request_head(&mut socket).await;
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                .await
                .unwrap();
            receive.await.unwrap();
            socket
                .write_all(b"9\r\ndata: x\n\n\r\n0\r\n\r\n")
                .await
                .unwrap();
        });
        let caller = Caller { uid: None };
        let token = broker.mint("seat", None, vec![], caller).unwrap();
        let call = Call {
            token,
            row: "api".into(),
            method: "GET".into(),
            path: "/events".into(),
            query: None,
            headers: vec![],
            body: vec![],
            request_id: None,
            last_event_id: None,
        };
        let StreamOutcome::Live(mut live) = broker
            .stream(Namespace::Service, caller, call, HeaderMode::Strict)
            .await
            .unwrap()
        else {
            panic!()
        };
        let (started, mut ready) = tokio::sync::mpsc::unbounded_channel();
        let mut releases = Vec::new();
        let mut jobs = Vec::new();
        for _ in 0..16 {
            let (release, gate) = std::sync::mpsc::channel();
            releases.push(release);
            let broker = broker.clone();
            let started = started.clone();
            jobs.push(tokio::spawn(async move {
                broker
                    .disk(move |_| {
                        started.send(()).unwrap();
                        // Bounded blocking waits stand in for stalled fdatasync.
                        gate.recv_timeout(Duration::from_secs(5)).unwrap();
                    })
                    .await;
            }));
        }
        for _ in 0..16 {
            ready.recv().await.unwrap();
        }
        assert_eq!(broker.inner.disk_slots.available_permits(), 0);
        send.send(()).unwrap();
        let next = tokio::time::timeout(Duration::from_secs(1), live.items.recv()).await;
        for release in releases {
            release.send(()).unwrap();
        }
        assert!(
            matches!(next.unwrap().unwrap(), StreamItem::Chunk(bytes) if bytes == b"data: x\n\n".as_slice())
        );
        for job in jobs {
            job.await.unwrap();
        }
        upstream.await.unwrap();
        assert!(
            matches!(live.items.recv().await, Some(StreamItem::End(summary)) if summary.complete)
        );
    }
}
