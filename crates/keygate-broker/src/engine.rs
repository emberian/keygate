//! The broker engine: admission, ticketing, audit-before-effect, and the
//! upstream exchange for both buffered and streaming calls.
//!
//! Order of operations for every call, none of which may be reordered:
//!
//! 1. verify the macaroon and admit the request against row policy and caveats;
//! 2. find or open the ticket (reserving budget) in the journal;
//! 3. claim the ticket `Live -> InFlight` (durable);
//! 4. append `Begin` to the audit log (durable) and stop here if that fails;
//! 5. only now touch the network.

use crate::vault::{ActiveSecret, ProviderRow, RowEpoch, Upstream, Vault};
use crate::BootError;
use bytes::Bytes;
use keygate_core::audit::{AuditEvent, AuditLog};
use keygate_core::config::{BrokerCfg, Config, RESERVED_HEADERS};
use keygate_core::echo::{EchoAutomaton, EchoGuard};
use keygate_core::journal::{
    self, Begin, CallKind, Charge, ClosedBy, Journal, JournalError, NewTicket, RequestDigest32,
    Retained, StreamSummary, Ticket, TicketId, TicketState,
};
use keygate_core::macaroon::{self, Caveat, Facts, MacaroonV1, RootId};
use keygate_core::path::{check_query, PlainPath};
use keygate_core::proto::{Call, Code, Refusal, RowInfo, StatusInfo};
use keygate_core::seal::{write_atomic, MasterKey, SealStore};
use keygate_core::secret::SecretBytes;
use keygate_core::{now_unix_s, valid_name, Namespace};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, ACCEPT_ENCODING, CONTENT_ENCODING};
use serde::de::{Deserializer, IgnoredAny, MapAccess, Visitor};
use serde::Deserialize;
use std::collections::{BTreeMap, HashSet};
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
    seats: watch::Sender<Arc<BTreeMap<String, u64>>>,
    seat_admin: Mutex<()>,
    disk_slots: Arc<Semaphore>,
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
    prices: Option<(u64, u64)>,
}

/// A claimed ticket with its `Begin` audited: the network may now be used.
struct Flight {
    guard: FlightGuard,
    secret: Arc<ActiveSecret>,
    epoch: watch::Receiver<RowEpoch>,
    seat_epoch: watch::Receiver<Arc<BTreeMap<String, u64>>>,
    seat: String,
    root_epoch: u64,
    automaton: Arc<EchoAutomaton>,
}

/// Owns an `InFlight` ticket. If it is dropped without an explicit outcome
/// (the caller hung up and the exchange future was cancelled), the ticket
/// becomes `Uncertain`.
struct FlightGuard {
    broker: Broker,
    id: TicketId,
    armed: bool,
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
    Revoked,
}

impl Broker {
    /// Create the state directory skeleton and a fresh master key.
    pub fn init_state(state_dir: &Path) -> Result<(), BootError> {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(state_dir)?;
        MasterKey::generate(&state_dir.join(MASTER_KEY_FILE))?;
        Ok(())
    }

    pub fn open(
        state_dir: &Path,
        config: Config,
        options: BrokerOptions,
    ) -> Result<Self, BootError> {
        config.validate()?;
        let master = MasterKey::load(&state_dir.join(MASTER_KEY_FILE))?;
        let vault = Vault::open(&config, SealStore::new(state_dir, &master))?;
        let journal = Journal::open(
            &state_dir.join(JOURNAL_FILE),
            config.broker.compact_every,
            config.broker.retention_s,
        )?;
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
                seats: watch::Sender::new(Arc::new(seats)),
                seat_admin: Mutex::new(()),
                disk_slots: Arc::new(Semaphore::new(16)),
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

    fn retention_deadline(&self) -> u64 {
        now_unix_s().saturating_add(self.inner.cfg.retention_s)
    }

    fn record(&self, id: TicketId, state: TicketState) -> Result<(), Refusal> {
        let deadline = if state == TicketState::Live {
            now_unix_s().saturating_add(self.inner.cfg.live_ttl_s)
        } else {
            self.retention_deadline()
        };
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

    /// Load or rotate a row's secret (audited first; fails closed).
    pub fn set(
        &self,
        ns: Namespace,
        row: &str,
        secret: SecretBytes,
        cut_existing: bool,
        by: Caller,
    ) -> Result<RowEpoch, Refusal> {
        self.inner.vault.upstream(ns, row)?;
        let detail = if cut_existing {
            "cut-existing"
        } else {
            "rotate"
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
        self.inner.vault.set(ns, row, secret, cut_existing)
    }

    /// Destroy a row's secret and cut its streams. Revocation is the one
    /// effect that happens *before* its audit record: failing to log must
    /// not keep a compromised key alive.
    pub fn revoke(&self, ns: Namespace, row: &str, by: Caller) -> Result<RowEpoch, Refusal> {
        let epoch = self.inner.vault.revoke(ns, row)?;
        self.inner
            .audit
            .append(&AuditEvent::Admin {
                action: "revoke",
                uid: by.uid,
                namespace: Some(ns),
                target: row,
                detail: "",
            })
            .map_err(|e| {
                Refusal::new(
                    Code::AuditFailed,
                    format!("{ns}/{row} IS revoked, but the audit record failed: {e}"),
                )
            })?;
        Ok(epoch)
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
                let stream = serde_json::from_slice::<TopLevel>(body)
                    .map(|t| t.stream)
                    .unwrap_or(false);
                Ok(if stream {
                    CallKind::Stream
                } else {
                    CallKind::Buffered
                })
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

    fn prepare(
        &self,
        ns: Namespace,
        caller: Caller,
        call: Call,
        kind: CallKind,
        mode: HeaderMode,
    ) -> Result<Prepared, Refusal> {
        let vault = &self.inner.vault;
        let now = now_unix_s();

        let token = MacaroonV1::decode(&call.token)
            .map_err(|e| Refusal::new(Code::BadToken, e.to_string()))?;
        let verified = token
            .verify(self.root_key())
            .map_err(|e| Refusal::new(Code::BadToken, e.to_string()))?;
        let seat = verified.root.seat.clone();
        if verified.root.root_epoch < self.seat_epoch(&seat) {
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

        let (upstream, methods, allowed_paths, admission) = match ns {
            Namespace::Provider => {
                let row = vault.provider(&call.row)?;
                let admission = admit_provider(row, &seat, &method, &call.body, kind, now)?;
                (&row.upstream, &row.methods, &row.paths, admission)
            }
            Namespace::Service => {
                let row = vault.service(&call.row)?;
                let paths = match kind {
                    CallKind::Buffered => &row.buffered_paths,
                    CallKind::Stream => &row.stream_paths,
                };
                (
                    &row.upstream,
                    &row.methods,
                    paths,
                    ProviderAdmission::default(),
                )
            }
        };
        if !methods.iter().any(|m| m == method.as_str()) {
            return Err(Refusal::new(
                Code::MethodRefused,
                format!("{ns}/{} does not allow {method}", call.row),
            ));
        }
        if !path.under_any(allowed_paths) {
            let what = match (ns, kind) {
                (Namespace::Provider, _) => "paths",
                (Namespace::Service, CallKind::Buffered) => "buffered_paths",
                (Namespace::Service, CallKind::Stream) => "stream_paths",
            };
            return Err(Refusal::new(
                Code::PathRefused,
                format!("{path} is not under {ns}/{}'s {what}", call.row),
            ));
        }
        if call.body.len() > upstream.max_request_bytes {
            return Err(Refusal::new(
                Code::TooLarge,
                format!(
                    "request body is {} bytes; {ns}/{} allows {}",
                    call.body.len(),
                    call.row,
                    upstream.max_request_bytes
                ),
            ));
        }

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

        let digest = request_digest(ns, kind, &call, method.as_str(), query, &headers);
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
                now_unix_s: now_unix_s(),
                live_ttl_s: self.inner.cfg.live_ttl_s,
            })
            .map_err(|e| match e {
                JournalError::Budget { .. } => Refusal::new(Code::BudgetExceeded, e.to_string()),
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
        let mut guard = FlightGuard {
            broker: self.clone(),
            id,
            armed: true,
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
        Ok(Flight {
            guard,
            secret,
            epoch,
            seat_epoch: self.inner.seats.subscribe(),
            seat: p.seat.clone(),
            root_epoch: p.root_epoch,
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
        let generation = flight.secret.generation;
        let outcome = tokio::select! {
            biased;
            _ = wait_revoked(&mut flight.epoch, generation, &mut flight.seat_epoch, &flight.seat, flight.root_epoch) => Err(ExchangeError::Revoked),
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
                    ExchangeError::Revoked => {
                        (Code::Revoked, "secret revoked mid-flight".to_owned())
                    }
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
        let generation = flight.secret.generation;
        let sent = tokio::select! {
            biased;
            _ = wait_revoked(&mut flight.epoch, generation, &mut flight.seat_epoch, &flight.seat, flight.root_epoch) => Err(ExchangeError::Revoked),
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
            Err(ExchangeError::Revoked) => {
                let summary = cut_summary(0, ClosedBy::Revoked);
                return Err(self
                    .close_refused(
                        flight,
                        summary,
                        Code::Revoked,
                        "secret revoked before the stream opened",
                    )
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
    /// on four wakers and performs no I/O other than the two sockets:
    /// row and seat epochs (revocation), the caller going away, and the next
    /// upstream chunk.
    async fn relay(
        self,
        mut flight: Flight,
        mut response: reqwest::Response,
        prices: Option<(u64, u64)>,
        status: u16,
        items: mpsc::Sender<StreamItem>,
    ) {
        let id = flight.guard.id;
        let generation = flight.secret.generation;
        let mut guard = EchoGuard::new(flight.automaton.clone());
        let mut usage = prices.map(|_| UsageSniffer::default());
        let mut delivered = 0u64;
        let mut safe = Vec::new();

        let closed_by = loop {
            tokio::select! {
                biased;
                _ = wait_revoked(&mut flight.epoch, generation, &mut flight.seat_epoch, &flight.seat, flight.root_epoch) => break ClosedBy::Revoked,
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
                            _ = wait_revoked(&mut flight.epoch, generation, &mut flight.seat_epoch, &flight.seat, flight.root_epoch) => Err(ClosedBy::Revoked),
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

/// Pure in-memory notification for either revocation domain; no timers or disk.
async fn wait_revoked(
    epoch: &mut watch::Receiver<RowEpoch>,
    generation: u64,
    seats: &mut watch::Receiver<Arc<BTreeMap<String, u64>>>,
    seat: &str,
    root_epoch: u64,
) {
    loop {
        if epoch.borrow_and_update().revoked_floor > generation
            || seats.borrow_and_update().get(seat).copied().unwrap_or(0) > root_epoch
        {
            return;
        }
        tokio::select! {
            result = epoch.changed() => if result.is_err() { return; },
            result = seats.changed() => if result.is_err() { return; },
        }
    }
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
            "an earlier attempt of this exact request may have reached the upstream and its reply was lost; it will not be re-sent. Use a new request_id to send again deliberately",
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

fn caller_visible_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|(name, _)| !RESERVED_HEADERS.contains(&name.as_str()))
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect()
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

/// Identity of a request: two calls with equal digests (for one seat) are
/// the same request, and the second is a retry.
fn request_digest(
    ns: Namespace,
    kind: CallKind,
    call: &Call,
    method: &str,
    query: Option<&str>,
    headers: &HeaderMap,
) -> RequestDigest32 {
    fn field(hasher: &mut blake3::Hasher, bytes: &[u8]) {
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    let mut hasher = blake3::Hasher::new_derive_key("keygate-request/v1 digest");
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

// ----- provider policy -------------------------------------------------------

#[derive(Default)]
struct ProviderAdmission {
    model: Option<String>,
    reserve_micro_usd: u64,
    charges: Vec<Charge>,
    prices: Option<(u64, u64)>,
}

/// The top level of an LLM request body, parsed strictly: a duplicated key
/// is refused, because keygate and the upstream could disagree about which
/// occurrence wins and the model allowlist would be checking the wrong one.
#[derive(Default)]
struct TopLevel {
    model: Option<String>,
    output_caps: Vec<u64>,
    n: Option<u64>,
    stream: bool,
}

impl<'de> Deserialize<'de> for TopLevel {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TopVisitor;
        impl<'de> Visitor<'de> for TopVisitor {
            type Value = TopLevel;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<TopLevel, A::Error> {
                let mut top = TopLevel::default();
                let mut seen = HashSet::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !seen.insert(key.clone()) {
                        return Err(serde::de::Error::custom(format!("duplicate key {key:?}")));
                    }
                    match key.as_str() {
                        "model" => top.model = Some(map.next_value()?),
                        "max_tokens" | "max_output_tokens" | "max_completion_tokens" => {
                            top.output_caps.push(map.next_value()?)
                        }
                        "n" => top.n = Some(map.next_value()?),
                        "stream" => top.stream = map.next_value()?,
                        _ => {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                Ok(top)
            }
        }
        deserializer.deserialize_map(TopVisitor)
    }
}

fn micro_usd(tokens_in: u64, tokens_out: u64, (price_in, price_out): (u64, u64)) -> u64 {
    // Each product fits in u128; their sum may not.
    let total = (u128::from(tokens_in) * u128::from(price_in))
        .saturating_add(u128::from(tokens_out) * u128::from(price_out));
    u64::try_from(total.div_ceil(1_000_000)).unwrap_or(u64::MAX)
}

fn admit_provider(
    row: &ProviderRow,
    seat: &str,
    method: &reqwest::Method,
    body: &[u8],
    kind: CallKind,
    now: u64,
) -> Result<ProviderAdmission, Refusal> {
    let name = &row.upstream.name;
    if *method != reqwest::Method::POST {
        if kind == CallKind::Stream {
            return Err(Refusal::new(
                Code::BadRequest,
                "provider streams are POST requests with \"stream\": true",
            ));
        }
        if !body.is_empty() {
            return Err(Refusal::new(
                Code::BadRequest,
                format!("{method} to a provider must not carry a body"),
            ));
        }
        return Ok(ProviderAdmission::default());
    }

    let top: TopLevel = serde_json::from_slice(body).map_err(|e| {
        Refusal::new(
            Code::BadRequest,
            format!("provider request body must be a JSON object: {e}"),
        )
    })?;
    let Some(model) = top.model else {
        return Err(Refusal::new(
            Code::ModelRefused,
            "request body names no model",
        ));
    };
    if !row.models.contains(&model) {
        return Err(Refusal::new(
            Code::ModelRefused,
            format!("model {model:?} is not allowed on provider/{name}"),
        ));
    }
    match (kind, top.stream) {
        (CallKind::Buffered, true) => {
            return Err(Refusal::new(
                Code::BadRequest,
                "body sets \"stream\": true; use provider-stream",
            ))
        }
        (CallKind::Stream, false) => {
            return Err(Refusal::new(
                Code::BadRequest,
                "provider-stream requires \"stream\": true in the body",
            ))
        }
        _ => {}
    }
    let Some(cap) = top.output_caps.iter().copied().max() else {
        return Err(Refusal::new(
            Code::TokenCapRefused,
            format!(
                "request must set max_tokens (at most {}); an uncapped call cannot be budgeted",
                row.max_output_tokens
            ),
        ));
    };
    let n = top.n.unwrap_or(1);
    if !(1..=16).contains(&n) {
        return Err(Refusal::new(
            Code::TokenCapRefused,
            "n must be between 1 and 16",
        ));
    }
    let cap = cap
        .checked_mul(n)
        .ok_or_else(|| Refusal::new(Code::TokenCapRefused, "output token cap times n overflows"))?;
    if cap > row.max_output_tokens {
        return Err(Refusal::new(
            Code::TokenCapRefused,
            format!(
                "aggregate output token cap {cap} exceeds provider/{name}'s limit {}",
                row.max_output_tokens
            ),
        ));
    }

    // Reservation: the output cap is exact; input is estimated at one token
    // per three body bytes. Complete replies settle to metered usage.
    let prices = (row.input_micro_usd_per_mtok, row.output_micro_usd_per_mtok);
    let reserve = micro_usd(body.len().div_ceil(3) as u64, cap, prices);
    if let Some(limit) = row.per_call_micro_usd {
        if reserve > limit {
            return Err(Refusal::new(
                Code::BudgetExceeded,
                format!("call would reserve {reserve} micro-USD; per-call limit is {limit}"),
            ));
        }
    }
    let day = journal::utc_day(now);
    Ok(ProviderAdmission {
        model: Some(model),
        reserve_micro_usd: reserve,
        charges: vec![
            Charge {
                key: journal::row_day_key(name, day),
                cap_micro_usd: row.per_day_micro_usd,
            },
            Charge {
                key: journal::seat_day_key(name, seat, day),
                cap_micro_usd: row.per_seat_day_micro_usd,
            },
        ],
        prices: (reserve > 0).then_some(prices),
    })
}

/// Both APIs report cumulative usage; OpenAI prompt_tokens already includes
/// its cached tokens. Anthropic's cache counters are additional input tokens.
#[derive(Deserialize)]
struct Usage {
    #[serde(alias = "prompt_tokens")]
    input_tokens: Option<u64>,
    #[serde(alias = "completion_tokens")]
    output_tokens: Option<u64>,
    #[serde(default)]
    cache_creation_input_tokens: u64,
    #[serde(default)]
    cache_read_input_tokens: u64,
}

impl Usage {
    fn input(&self) -> Option<u64> {
        Some(
            self.input_tokens?
                .saturating_add(self.cache_creation_input_tokens)
                .saturating_add(self.cache_read_input_tokens),
        )
    }

    fn cost(&self, prices: (u64, u64)) -> Option<u64> {
        Some(micro_usd(self.input()?, self.output_tokens?, prices))
    }
}

fn metered_cost(body: &[u8], prices: (u64, u64)) -> Option<u64> {
    #[derive(Deserialize)]
    struct Reply {
        usage: Usage,
    }
    serde_json::from_slice::<Reply>(body)
        .ok()?
        .usage
        .cost(prices)
}

/// Bounded SSE observation only: it never rewrites or delays stream bytes.
/// Oversized/malformed events invalidate metering, preserving the reservation.
#[derive(Default)]
struct UsageSniffer {
    line: zeroize::Zeroizing<Vec<u8>>,
    data: zeroize::Zeroizing<Vec<u8>>,
    after_cr: bool,
    invalid: bool,
    input: Option<u64>,
    output: Option<u64>,
}

impl UsageSniffer {
    const MAX_EVENT: usize = 64 * 1024;

    fn push(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            if self.invalid {
                return;
            }
            if self.after_cr && byte == b'\n' {
                self.after_cr = false;
                continue;
            }
            self.after_cr = byte == b'\r';
            if matches!(byte, b'\r' | b'\n') {
                self.line_end();
            } else if self.line.len() + self.data.len() < Self::MAX_EVENT {
                self.line.push(byte);
            } else {
                self.invalid = true;
                self.line.zeroize();
                self.data.zeroize();
            }
        }
    }

    fn line_end(&mut self) {
        if self.line.is_empty() {
            if !self.data.is_empty() {
                self.event();
            }
            self.data.zeroize();
        } else if self.line.as_slice() == b"data" || self.line.starts_with(b"data:") {
            let value = self.line.get(5..).unwrap_or_default();
            let value = value.strip_prefix(b" ").unwrap_or(value);
            self.data.extend_from_slice(value);
            self.data.push(b'\n');
        }
        self.line.zeroize();
    }

    fn event(&mut self) {
        if self.data.as_slice() == b"[DONE]\n" {
            return;
        }
        let Ok(event) = serde_json::from_slice::<serde_json::Value>(&self.data) else {
            self.invalid = true;
            return;
        };
        let kind = event.get("type").and_then(|v| v.as_str());
        if kind == Some("error") || event.get("error").is_some() {
            self.invalid = true;
            return;
        }
        let usage = match kind {
            Some("message_start") => event.get("message").and_then(|v| v.get("usage")),
            Some("response.completed") => event.get("response").and_then(|v| v.get("usage")),
            _ => event.get("usage"),
        };
        let Some(usage) = usage.filter(|v| !v.is_null()) else {
            return;
        };
        let Ok(usage) = serde_json::from_value::<Usage>(usage.clone()) else {
            self.invalid = true;
            return;
        };
        if let Some(input) = usage.input() {
            self.input = Some(self.input.unwrap_or(0).max(input));
        }
        // message_start's output count is provisional, not final usage.
        if kind != Some("message_start") {
            if let Some(output) = usage.output_tokens {
                self.output = Some(self.output.unwrap_or(0).max(output));
            }
        }
    }

    fn cost(self, prices: (u64, u64)) -> Option<u64> {
        if self.invalid || !self.line.is_empty() || !self.data.is_empty() {
            return None;
        }
        Some(micro_usd(self.input?, self.output?, prices))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn top_level_refuses_duplicate_keys() {
        let ok: TopLevel = serde_json::from_str(
            r#"{"model":"m","max_tokens":5,"stream":true,"messages":[{"model":"x"}]}"#,
        )
        .unwrap();
        assert_eq!(ok.model.as_deref(), Some("m"));
        assert_eq!(ok.output_caps, vec![5]);
        assert!(ok.stream);
        assert!(serde_json::from_str::<TopLevel>(r#"{"model":"cheap","model":"dear"}"#).is_err());
        assert!(
            serde_json::from_str::<TopLevel>(r#"{"max_tokens":1,"max_tokens":999999}"#).is_err()
        );
        assert!(serde_json::from_str::<TopLevel>(r#"["model"]"#).is_err());
        assert!(serde_json::from_str::<TopLevel>(r#"{"max_tokens":-1}"#).is_err());
    }

    #[test]
    fn pricing_rounds_up_and_does_not_overflow() {
        assert_eq!(micro_usd(1, 0, (1, 0)), 1);
        assert_eq!(
            micro_usd(1_000_000, 1_000_000, (3_000_000, 15_000_000)),
            18_000_000
        );
        assert_eq!(micro_usd(0, 0, (5, 5)), 0);
        assert_eq!(
            micro_usd(u64::MAX, u64::MAX, (u64::MAX, u64::MAX)),
            u64::MAX
        );
    }

    #[test]
    fn usage_is_read_in_both_dialects() {
        let prices = (1_000_000, 2_000_000);
        assert_eq!(
            metered_cost(
                br#"{"usage":{"input_tokens":10,"output_tokens":5}}"#,
                prices
            ),
            Some(20)
        );
        assert_eq!(
            metered_cost(
                br#"{"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}"#,
                prices
            ),
            Some(20)
        );
        assert_eq!(metered_cost(br#"{"error":"x"}"#, prices), None);
    }

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
                    Caller { uid: None },
                )
            })
            .await
            .unwrap();
        let upstream = broker.inner.vault.upstream(p.ns, &p.row).unwrap();
        assert!(!broker
            .inner
            .vault
            .snapshot(upstream)
            .unwrap()
            .1
            .contains(flight.secret.expose()));
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

    /// #tooth: revocation wakes the same pending wait on either domain and
    /// already-revoked seats are detected on the very first poll.
    #[tokio::test]
    async fn tooth_seat_epoch_wakes_without_io_or_timer() {
        use std::future::Future;
        use std::task::Poll;
        let row = watch::Sender::new(RowEpoch {
            generation: 1,
            revoked_floor: 0,
        });
        let seats = watch::Sender::new(Arc::new(BTreeMap::new()));
        let mut r = row.subscribe();
        let mut s = seats.subscribe();
        let wait = wait_revoked(&mut r, 1, &mut s, "seat", 0);
        tokio::pin!(wait);
        std::future::poll_fn(|cx| {
            assert!(wait.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        let start = Instant::now();
        seats.send_replace(Arc::new(BTreeMap::from([("seat".into(), 1)])));
        std::future::poll_fn(|cx| {
            assert!(wait.as_mut().poll(cx).is_ready());
            Poll::Ready(())
        })
        .await;
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_micros(100),
            "seat notification took {elapsed:?}"
        );
        let mut r = row.subscribe();
        let mut s = seats.subscribe();
        tokio::select! {
            biased;
            _ = wait_revoked(&mut r, 1, &mut s, "seat", 0) => {},
            _ = std::future::ready(()) => panic!("revoked seat could start an upstream send"),
        }
    }

    /// #tooth: SSE parsing is chunk-independent, bounded, and requires
    /// complete input/output usage; partial final events cannot settle.
    #[test]
    fn tooth_usage_sniffer_bounds_and_partial_events() {
        let event =
            b"data: {\"usage\":\ndata: {\"prompt_tokens\":3,\"completion_tokens\":2}}\r\n\r\n";
        for width in 1..=event.len() {
            let mut sniff = UsageSniffer::default();
            for chunk in event.chunks(width) {
                sniff.push(chunk);
            }
            assert_eq!(sniff.cost((1_000_000, 2_000_000)), Some(7));
        }
        for bad in [
            b"data: {\"usage\":{\"input_tokens\":1,\"output_tokens\":2}}".as_slice(),
            b"data: {\"usage\":{\"input_tokens\":1}}\n\n",
            b"data: {\"usage\":{\"input_tokens\":-1,\"output_tokens\":2}}\n\n",
        ] {
            let mut sniff = UsageSniffer::default();
            sniff.push(bad);
            assert_eq!(sniff.cost((1, 1)), None);
        }
        let mut sniff = UsageSniffer::default();
        sniff.push(&vec![b'x'; UsageSniffer::MAX_EVENT + 1]);
        assert!(sniff.invalid);
        assert!(sniff.line.is_empty() && sniff.data.is_empty());
        sniff.push(event);
        assert_eq!(sniff.cost((1, 1)), None);
        assert_eq!(metered_cost(br#"{"usage":{"input_tokens":1,"cache_read_input_tokens":18446744073709551615,"cache_creation_input_tokens":1,"output_tokens":0}}"#, (1_000_000, 0)), Some(u64::MAX));
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
