//! The in-memory credential tables.
//!
//! `providers` and `services` are separate maps of separate row types. Each
//! row owns its decrypted secret, its retired (guard-only) secrets, its
//! epoch channel and its policy. After boot the only disk I/O here is
//! `set`, `revoke` and `forget` writing a sealed row; request and stream
//! paths read memory only and never wait on those operations.

use crate::BootError;
use keygate_core::config::{Allowance, Config, Dialect, ProviderCfg, ServiceCfg, UpstreamRef};
use keygate_core::echo::{EchoAutomaton, MIN_SECRET_LEN};
use keygate_core::path::PlainPath;
use keygate_core::proto::{Code, Refusal, RowInfo};
use keygate_core::seal::{RetiredSecret, SealStore, SealedRow, MAX_RETIRED};
use keygate_core::secret::SecretBytes;
use keygate_core::Namespace;
use reqwest::header::{HeaderName, HeaderValue};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock};
use tokio::sync::watch;

pub const MAX_SECRET_LEN: usize = 8192;

/// A row's revocation clock. A secret of generation `g` is usable while
/// `g >= revoked_floor`. `set` bumps `generation`; `revoke` (and
/// `set --cut-existing`) raise `revoked_floor`, which every open stream on
/// the row observes through its `watch::Receiver` without touching disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RowEpoch {
    pub generation: u64,
    pub revoked_floor: u64,
}

pub struct ActiveSecret {
    pub generation: u64,
    bytes: SecretBytes,
}

impl ActiveSecret {
    pub fn expose(&self) -> &[u8] {
        self.bytes.expose()
    }
}

#[derive(Default)]
struct RowSecrets {
    /// What new requests are sent with.
    active: Option<Arc<ActiveSecret>>,
    /// Earlier secrets: never sent, only withheld from responses.
    retired: Vec<Arc<ActiveSecret>>,
}

/// What both row types share: where to send, how to authenticate, and the
/// live secret.
pub struct Upstream {
    pub namespace: Namespace,
    pub name: String,
    pub origin: String,
    pub auth_header: HeaderName,
    pub auth_prefix: String,
    pub caller_headers: Vec<String>,
    pub fixed_headers: Vec<(HeaderName, HeaderValue)>,
    pub max_request_bytes: usize,
    epoch: watch::Sender<RowEpoch>,
    secrets: RwLock<RowSecrets>,
}

/// Token prices of a provider row, micro-USD per million tokens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prices {
    pub input: u64,
    pub output: u64,
    pub cache_write: u64,
    pub cache_read: u64,
}

impl Prices {
    pub fn is_zero(&self) -> bool {
        self.input == 0 && self.output == 0
    }

    /// The most an input token can cost: plain, or written to the cache.
    pub fn worst_input(&self) -> u64 {
        self.input.max(self.cache_write).max(self.cache_read)
    }
}

pub struct ProviderRow {
    pub upstream: Upstream,
    pub dialect: Dialect,
    /// The one path generation requests may be `POST`ed to.
    pub endpoint: PlainPath,
    /// Prefixes that may be read with `GET`/`HEAD`.
    pub read_paths: Vec<PlainPath>,
    pub models: Vec<String>,
    pub max_output_tokens: u64,
    pub allow: Vec<Allowance>,
    pub prices: Prices,
    pub per_call_micro_usd: Option<u64>,
    pub per_day_micro_usd: Option<u64>,
    pub per_seat_day_micro_usd: Option<u64>,
}

pub struct ServiceRow {
    pub upstream: Upstream,
    pub methods: Vec<String>,
    pub buffered_paths: Vec<PlainPath>,
    pub stream_paths: Vec<PlainPath>,
}

pub struct Vault {
    providers: Option<BTreeMap<String, ProviderRow>>,
    services: Option<BTreeMap<String, ServiceRow>>,
    store: SealStore,
    /// The automaton over every active and retired secret. Readers clone
    /// the `Arc` and never hold the lock across a build.
    guard: RwLock<Arc<EchoAutomaton>>,
    /// Serializes `set` / `revoke` / `forget` so sealed files, epochs and
    /// the guard move together. Request paths never take it.
    admin: Mutex<()>,
}

fn read<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn write<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn prefixes(raw: &[String]) -> Vec<PlainPath> {
    raw.iter()
        .map(|p| PlainPath::parse(p).expect("config was validated"))
        .collect()
}

impl Upstream {
    fn load(
        ns: Namespace,
        name: &str,
        cfg: UpstreamRef<'_>,
        store: &SealStore,
    ) -> Result<Self, BootError> {
        let (epoch, secrets) = match store.read(ns, name)? {
            Some(SealedRow {
                generation: u64::MAX,
                ..
            }) => {
                return Err(BootError::Config(format!(
                    "{ns}/{name}: sealed generation counter is exhausted"
                )))
            }
            Some(SealedRow {
                generation,
                revoked_floor,
                secret,
                retired,
            }) => {
                let active = secret
                    .filter(|_| generation >= revoked_floor)
                    .map(|bytes| Arc::new(ActiveSecret { generation, bytes }));
                let retired = retired
                    .into_iter()
                    .map(|r| {
                        Arc::new(ActiveSecret {
                            generation: r.generation,
                            bytes: r.secret,
                        })
                    })
                    .collect();
                (
                    RowEpoch {
                        generation,
                        revoked_floor,
                    },
                    RowSecrets { active, retired },
                )
            }
            None => (
                RowEpoch {
                    generation: 0,
                    revoked_floor: 0,
                },
                RowSecrets::default(),
            ),
        };
        let header = |name: &str| {
            HeaderName::from_bytes(name.as_bytes())
                .map_err(|e| BootError::Config(format!("header {name:?}: {e}")))
        };
        let mut fixed_headers = Vec::new();
        for (key, value) in cfg.fixed_headers {
            let value = HeaderValue::from_str(value)
                .map_err(|e| BootError::Config(format!("header {key:?}: {e}")))?;
            fixed_headers.push((header(key)?, value));
        }
        Ok(Upstream {
            namespace: ns,
            name: name.to_owned(),
            origin: cfg.origin.to_owned(),
            auth_header: header(cfg.auth_header)?,
            auth_prefix: cfg.effective_auth_prefix().to_owned(),
            caller_headers: cfg.caller_headers.to_vec(),
            fixed_headers,
            max_request_bytes: cfg.max_request_bytes,
            epoch: watch::Sender::new(epoch),
            secrets: RwLock::new(secrets),
        })
    }

    /// The secret new requests should use, if the row has one.
    pub fn secret(&self) -> Option<Arc<ActiveSecret>> {
        read(&self.secrets).active.clone()
    }

    pub fn retired(&self) -> usize {
        read(&self.secrets).retired.len()
    }

    pub fn epoch(&self) -> RowEpoch {
        *self.epoch.borrow()
    }

    /// Subscribe to epoch changes (for stream relay loops).
    pub fn watch(&self) -> watch::Receiver<RowEpoch> {
        self.epoch.subscribe()
    }

    fn info(&self) -> RowInfo {
        let epoch = self.epoch();
        let secrets = read(&self.secrets);
        let state = match secrets.active {
            Some(_) => "active",
            None if epoch.revoked_floor > epoch.generation => "revoked",
            None => "unset",
        };
        RowInfo {
            namespace: self.namespace,
            row: self.name.clone(),
            origin: self.origin.clone(),
            state: state.to_owned(),
            generation: epoch.generation,
            revoked_floor: epoch.revoked_floor,
            retired: secrets.retired.len(),
        }
    }

    fn sealed(epoch: RowEpoch, secrets: &RowSecrets) -> SealedRow {
        SealedRow {
            generation: epoch.generation,
            revoked_floor: epoch.revoked_floor,
            secret: secrets.active.as_ref().map(|s| s.bytes.duplicate()),
            retired: secrets
                .retired
                .iter()
                .map(|r| RetiredSecret {
                    generation: r.generation,
                    secret: r.bytes.duplicate(),
                })
                .collect(),
        }
    }
}

impl ProviderRow {
    fn load(name: &str, cfg: &ProviderCfg, store: &SealStore) -> Result<Self, BootError> {
        Ok(ProviderRow {
            upstream: Upstream::load(Namespace::Provider, name, cfg.upstream(), store)?,
            dialect: cfg.dialect,
            endpoint: PlainPath::parse(cfg.endpoint()).expect("config was validated"),
            read_paths: prefixes(&cfg.read_paths),
            models: cfg.models.clone(),
            max_output_tokens: cfg.max_output_tokens,
            allow: cfg.allow.clone(),
            prices: Prices {
                input: cfg.input_micro_usd_per_mtok,
                output: cfg.output_micro_usd_per_mtok,
                cache_write: cfg
                    .cache_write_micro_usd_per_mtok
                    .unwrap_or(cfg.input_micro_usd_per_mtok.saturating_mul(2)),
                cache_read: cfg
                    .cache_read_micro_usd_per_mtok
                    .unwrap_or(cfg.input_micro_usd_per_mtok),
            },
            per_call_micro_usd: cfg.per_call_micro_usd,
            per_day_micro_usd: cfg.per_day_micro_usd,
            per_seat_day_micro_usd: cfg.per_seat_day_micro_usd,
        })
    }

    pub fn allows(&self, what: Allowance) -> bool {
        self.allow.contains(&what)
    }
}

impl ServiceRow {
    fn load(name: &str, cfg: &ServiceCfg, store: &SealStore) -> Result<Self, BootError> {
        Ok(ServiceRow {
            upstream: Upstream::load(Namespace::Service, name, cfg.upstream(), store)?,
            methods: cfg.methods.clone(),
            buffered_paths: prefixes(&cfg.buffered_paths),
            stream_paths: prefixes(&cfg.stream_paths),
        })
    }
}

impl Vault {
    pub fn open(config: &Config, store: SealStore) -> Result<Self, BootError> {
        let providers = match &config.providers {
            Some(rows) if !rows.is_empty() => Some(
                rows.iter()
                    .map(|(name, cfg)| Ok((name.clone(), ProviderRow::load(name, cfg, &store)?)))
                    .collect::<Result<BTreeMap<_, _>, BootError>>()?,
            ),
            _ => None,
        };
        let services = match &config.services {
            Some(rows) if !rows.is_empty() => Some(
                rows.iter()
                    .map(|(name, cfg)| Ok((name.clone(), ServiceRow::load(name, cfg, &store)?)))
                    .collect::<Result<BTreeMap<_, _>, BootError>>()?,
            ),
            _ => None,
        };
        let vault = Vault {
            providers,
            services,
            store,
            guard: RwLock::new(Arc::new(EchoAutomaton::empty())),
            admin: Mutex::new(()),
        };
        let automaton = vault.build_guard(None).map_err(|e| {
            BootError::Config(format!("sealed secrets cannot be guarded: {}", e.message))
        })?;
        *write(&vault.guard) = automaton;
        Ok(vault)
    }

    pub fn provider_rows(&self) -> Option<usize> {
        self.providers.as_ref().map(BTreeMap::len)
    }

    pub fn service_rows(&self) -> Option<usize> {
        self.services.as_ref().map(BTreeMap::len)
    }

    pub fn provider(&self, row: &str) -> Result<&ProviderRow, Refusal> {
        self.providers
            .as_ref()
            .ok_or_else(|| {
                Refusal::new(
                    Code::NamespaceDisabled,
                    "this broker has no providers table",
                )
            })?
            .get(row)
            .ok_or_else(|| Refusal::new(Code::UnknownRow, format!("no provider row {row:?}")))
    }

    pub fn service(&self, row: &str) -> Result<&ServiceRow, Refusal> {
        self.services
            .as_ref()
            .ok_or_else(|| {
                Refusal::new(Code::NamespaceDisabled, "this broker has no services table")
            })?
            .get(row)
            .ok_or_else(|| Refusal::new(Code::UnknownRow, format!("no service row {row:?}")))
    }

    pub fn upstream(&self, ns: Namespace, row: &str) -> Result<&Upstream, Refusal> {
        match ns {
            Namespace::Provider => self.provider(row).map(|r| &r.upstream),
            Namespace::Service => self.service(row).map(|r| &r.upstream),
        }
    }

    fn upstreams(&self) -> impl Iterator<Item = &Upstream> {
        let providers = self
            .providers
            .iter()
            .flat_map(|rows| rows.values().map(|r| &r.upstream));
        let services = self
            .services
            .iter()
            .flat_map(|rows| rows.values().map(|r| &r.upstream));
        providers.chain(services)
    }

    pub fn rows(&self) -> Vec<RowInfo> {
        self.upstreams().map(Upstream::info).collect()
    }

    /// Largest request body any row accepts.
    pub fn max_request_bytes(&self) -> usize {
        self.upstreams()
            .map(|u| u.max_request_bytes)
            .max()
            .unwrap_or(0)
    }

    /// The row's active secret together with a guard that covers it.
    ///
    /// The pair is read under the guard lock, and every writer that
    /// changes both (`set`, `revoke`) publishes them under that same lock,
    /// so a caller never gets a secret with a guard built without it. This
    /// matters most for `set --forget-retired`, whose new guard no longer
    /// contains the old secret. The lock is held only across two pointer
    /// reads here and two pointer writes there: never across sealing,
    /// `fsync` or an automaton build. The flight keeps both `Arc`s until
    /// its exchange ends.
    pub fn snapshot(&self, upstream: &Upstream) -> Option<(Arc<ActiveSecret>, Arc<EchoAutomaton>)> {
        self.snapshot_pausing(upstream, || {})
    }

    /// `snapshot`, with a hook between selecting the secret and taking the
    /// guard. Tests use it to hold a reader at exactly the point where a
    /// rotation used to slip in.
    fn snapshot_pausing(
        &self,
        upstream: &Upstream,
        between: impl FnOnce(),
    ) -> Option<(Arc<ActiveSecret>, Arc<EchoAutomaton>)> {
        let guard = read(&self.guard);
        let secret = upstream.secret()?;
        between();
        Some((secret, guard.clone()))
    }

    pub fn guarded_secrets(&self) -> usize {
        read(&self.guard).secrets()
    }

    pub fn guard_pattern_bytes(&self) -> usize {
        read(&self.guard).pattern_bytes()
    }

    /// Build the guard over every row's active and retired secrets, with
    /// one row's secrets optionally replaced by a prospective set. Runs
    /// without any lock that a request path takes.
    fn build_guard(
        &self,
        replace: Option<(&Upstream, &RowSecrets)>,
    ) -> Result<Arc<EchoAutomaton>, Refusal> {
        let mut all: Vec<Arc<ActiveSecret>> = Vec::new();
        let mut add = |secrets: &RowSecrets| {
            for secret in secrets.active.iter().chain(&secrets.retired) {
                if !all.iter().any(|seen| seen.expose() == secret.expose()) {
                    all.push(secret.clone());
                }
            }
        };
        for upstream in self.upstreams() {
            match replace {
                Some((row, secrets)) if std::ptr::eq(row, upstream) => add(secrets),
                _ => add(&read(&upstream.secrets)),
            }
        }
        EchoAutomaton::build(all.iter().map(|s| s.expose()))
            .map(Arc::new)
            .map_err(|e| Refusal::new(Code::BadRequest, e.to_string()))
    }

    /// Load or rotate a row's secret. New requests use it at once. Streams
    /// already open keep running on the old one unless `cut_existing`. The
    /// old secret becomes a retired guard pattern unless `forget_retired`.
    /// Nothing changes if the result could not be guarded or sealed.
    pub fn set(
        &self,
        ns: Namespace,
        row: &str,
        secret: SecretBytes,
        cut_existing: bool,
        forget_retired: bool,
    ) -> Result<RowEpoch, Refusal> {
        let upstream = self.upstream(ns, row)?;
        check_secret(upstream, &secret)?;
        let _admin = self
            .admin
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let current = upstream.epoch();
        // u64::MAX is left unused so `revoke` can always raise the floor
        // one past the generation.
        let generation = current
            .generation
            .checked_add(1)
            .filter(|next| *next < u64::MAX)
            .ok_or_else(|| {
                Refusal::new(
                    Code::Internal,
                    format!("{ns}/{row} has exhausted its generation counter; nothing changed"),
                )
            })?;
        let next = RowEpoch {
            generation,
            revoked_floor: if cut_existing {
                generation
            } else {
                current.revoked_floor
            },
        };
        let mut retired = Vec::new();
        if !forget_retired {
            let before = read(&upstream.secrets);
            for old in before.retired.iter().chain(&before.active) {
                if old.expose() != secret.expose() {
                    retired.push(old.clone());
                }
            }
        }
        if retired.len() > MAX_RETIRED {
            return Err(Refusal::new(
                Code::BadRequest,
                format!(
                    "{ns}/{row} already has {MAX_RETIRED} retired secrets still being withheld \
                     from responses. Once the old keys are invalid upstream, run `keygate forget \
                     {ns} {row}` (or `set --forget-retired`); nothing changed"
                ),
            ));
        }
        let secrets = RowSecrets {
            active: Some(Arc::new(ActiveSecret {
                generation,
                bytes: secret,
            })),
            retired,
        };
        let automaton = self.build_guard(Some((upstream, &secrets)))?;
        self.store
            .write(ns, row, &Upstream::sealed(next, &secrets))
            .map_err(|e| {
                Refusal::new(
                    Code::Internal,
                    format!("sealing {ns}/{row} failed; nothing changed: {e}"),
                )
            })?;

        // The guard and the secret change together (see `snapshot`), then
        // the epoch.
        {
            let mut guard = write(&self.guard);
            *write(&upstream.secrets) = secrets;
            *guard = automaton;
        }
        upstream.epoch.send_replace(next);
        Ok(next)
    }

    /// Stop using a row's secret. The epoch moves first, in memory, so open
    /// streams are cut before any disk I/O happens. The secret stays as a
    /// retired guard pattern (sealed) unless `forget`.
    pub fn revoke(&self, ns: Namespace, row: &str, forget: bool) -> Result<RowEpoch, Refusal> {
        let upstream = self.upstream(ns, row)?;
        let _admin = self
            .admin
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let current = upstream.epoch();
        let next = RowEpoch {
            generation: current.generation,
            revoked_floor: current.generation.saturating_add(1),
        };
        upstream.epoch.send_replace(next);
        let tombstone = {
            // Under the guard lock: a reader holds either the secret with
            // the guard that contains it, or no secret at all.
            let _guard = write(&self.guard);
            let mut secrets = write(&upstream.secrets);
            let revoked = secrets.active.take();
            if forget {
                secrets.retired.clear();
            } else if let Some(revoked) = revoked {
                // Revocation is never refused for lack of room: the oldest
                // retired pattern makes way.
                if secrets.retired.len() >= MAX_RETIRED {
                    secrets.retired.remove(0);
                }
                secrets.retired.push(revoked);
            }
            Upstream::sealed(next, &secrets)
        };
        // A smaller pattern set always builds; if it somehow did not, the
        // previous guard (a superset) stays in place.
        if let Ok(automaton) = self.build_guard(None) {
            *write(&self.guard) = automaton;
        }

        if let Err(e) = self.store.write(ns, row, &tombstone) {
            // Revoked in memory regardless. Make sure the sealed secret
            // cannot come back as active at the next start.
            let removed = self
                .store
                .path(ns, row)
                .map_err(std::io::Error::other)
                .and_then(std::fs::remove_file);
            return Err(Refusal::new(
                Code::Internal,
                format!("{ns}/{row} is revoked in memory, but writing the tombstone failed ({e}); removing the sealed file: {removed:?}"),
            ));
        }
        Ok(next)
    }

    /// Drop a row's retired secrets: they are no longer withheld from
    /// responses and no longer on disk. Returns how many were dropped.
    pub fn forget(&self, ns: Namespace, row: &str) -> Result<usize, Refusal> {
        let upstream = self.upstream(ns, row)?;
        let _admin = self
            .admin
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let kept = RowSecrets {
            active: upstream.secret(),
            retired: Vec::new(),
        };
        let dropped = upstream.retired();
        self.store
            .write(ns, row, &Upstream::sealed(upstream.epoch(), &kept))
            .map_err(|e| {
                Refusal::new(
                    Code::Internal,
                    format!("sealing {ns}/{row} failed; nothing changed: {e}"),
                )
            })?;
        // The active secret is unchanged and in both guards, so readers
        // are consistent whichever they see.
        *write(&upstream.secrets) = kept;
        if let Ok(automaton) = self.build_guard(None) {
            *write(&self.guard) = automaton;
        }
        Ok(dropped)
    }
}

fn check_secret(upstream: &Upstream, secret: &SecretBytes) -> Result<(), Refusal> {
    let bad = |why: &str| {
        Err(Refusal::new(
            Code::BadRequest,
            format!("secret refused: {why}"),
        ))
    };
    let bytes = secret.expose();
    if bytes.len() < MIN_SECRET_LEN {
        return bad("shorter than 8 bytes, too short to guard against echo");
    }
    if bytes.len() > MAX_SECRET_LEN {
        return bad("longer than 8192 bytes");
    }
    if !bytes.iter().all(|b| (0x20..0x7f).contains(b))
        || bytes[0] == b' '
        || bytes[bytes.len() - 1] == b' '
    {
        return bad("must be printable ASCII with no surrounding whitespace (it is sent as an HTTP header value)");
    }
    debug_assert!(upstream.auth_prefix.is_ascii());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use keygate_core::seal::MasterKey;
    use std::sync::mpsc;
    use std::time::Duration;

    const CONFIG: &str = r#"
[broker]
deployment = "development"

[services.api]
origin = "https://api.example.com"
buffered_paths = ["/"]
"#;

    fn vault(dir: &std::path::Path) -> Vault {
        let store = SealStore::new(dir, &MasterKey::from_bytes([3u8; 32]));
        Vault::open(&Config::parse(CONFIG).unwrap(), store).unwrap()
    }

    fn secret(s: &str) -> SecretBytes {
        SecretBytes::new(s.as_bytes().to_vec())
    }

    /// #tooth (parent K-P1): a reader that has selected secret A cannot be
    /// handed a guard published by a rotation that forgot A. The reader is
    /// paused exactly between the two reads; the rotation must wait for it.
    /// Before: `snapshot` read the secret, released, then read the global
    /// guard, and `set --forget-retired` could publish a guard without A in
    /// between, leaving a flight sent with A unguarded against A.
    #[test]
    fn tooth_snapshot_pairs_the_secret_with_a_guard_that_contains_it() {
        const A: &str = "sk-first-secret-AAAAAAAA";
        const B: &str = "sk-second-secret-BBBBBBB";
        for forget_by in ["set", "revoke"] {
            let dir = tempfile::tempdir().unwrap();
            let vault = Arc::new(vault(dir.path()));
            vault
                .set(Namespace::Service, "api", secret(A), false, false)
                .unwrap();

            let (selected_tx, selected_rx) = mpsc::channel();
            let (resume_tx, resume_rx) = mpsc::channel::<()>();
            let reader = std::thread::spawn({
                let vault = vault.clone();
                move || {
                    let upstream = vault.upstream(Namespace::Service, "api").unwrap();
                    vault.snapshot_pausing(upstream, || {
                        selected_tx.send(()).unwrap();
                        resume_rx.recv().unwrap();
                    })
                }
            });
            selected_rx.recv().unwrap();

            // The reader now holds A. Rotate (or revoke) and forget A.
            let (done_tx, done_rx) = mpsc::channel();
            let writer = std::thread::spawn({
                let vault = vault.clone();
                move || {
                    match forget_by {
                        "set" => vault
                            .set(Namespace::Service, "api", secret(B), false, true)
                            .map(|_| ()),
                        _ => vault.revoke(Namespace::Service, "api", true).map(|_| ()),
                    }
                    .unwrap();
                    done_tx.send(()).unwrap();
                }
            });
            assert!(
                done_rx.recv_timeout(Duration::from_millis(150)).is_err(),
                "{forget_by}: a guard without A was published while a reader held A"
            );
            resume_tx.send(()).unwrap();
            let (held, guard) = reader
                .join()
                .unwrap()
                .expect("the reader selected a secret");
            assert_eq!(held.expose(), A.as_bytes());
            assert!(
                guard.contains(A.as_bytes()),
                "{forget_by}: flight on A got a guard without A"
            );
            done_rx
                .recv_timeout(Duration::from_secs(10))
                .expect("the writer finishes once the reader is done");
            writer.join().unwrap();

            // Afterwards A really is forgotten, and new readers are consistent.
            let upstream = vault.upstream(Namespace::Service, "api").unwrap();
            assert_eq!(upstream.retired(), 0);
            match vault.snapshot(upstream) {
                Some((now, guard)) => {
                    assert_eq!(now.expose(), B.as_bytes());
                    assert!(guard.contains(B.as_bytes()) && !guard.contains(A.as_bytes()));
                }
                None => assert_eq!(forget_by, "revoke"),
            }
        }
    }

    /// #tooth: generation counters fail closed at their limit instead of
    /// wrapping to a generation an old revocation floor would accept.
    #[test]
    fn tooth_generation_counter_does_not_wrap() {
        let dir = tempfile::tempdir().unwrap();
        let store = SealStore::new(dir.path(), &MasterKey::from_bytes([3u8; 32]));
        let near = |generation: u64| SealedRow {
            generation,
            revoked_floor: 0,
            secret: Some(secret("sk-near-the-limit-000001")),
            retired: Vec::new(),
        };
        store
            .write(Namespace::Service, "api", &near(u64::MAX - 2))
            .unwrap();
        let v = vault(dir.path());
        let epoch = v
            .set(
                Namespace::Service,
                "api",
                secret("sk-near-the-limit-000002"),
                false,
                false,
            )
            .unwrap();
        assert_eq!(epoch.generation, u64::MAX - 1);
        let refused = v
            .set(
                Namespace::Service,
                "api",
                secret("sk-near-the-limit-000003"),
                false,
                false,
            )
            .unwrap_err();
        assert!(refused.message.contains("exhausted"), "{}", refused.message);
        assert_eq!(
            v.upstream(Namespace::Service, "api")
                .unwrap()
                .epoch()
                .generation,
            u64::MAX - 1
        );
        // Revocation still works at the last generation.
        let revoked = v.revoke(Namespace::Service, "api", true).unwrap();
        assert_eq!(revoked.revoked_floor, u64::MAX);
        assert!(v
            .upstream(Namespace::Service, "api")
            .unwrap()
            .secret()
            .is_none());
        drop(v);
        // A row sealed at the unusable maximum does not boot.
        store
            .write(Namespace::Service, "api", &near(u64::MAX))
            .unwrap();
        let config = Config::parse(CONFIG).unwrap();
        let again = SealStore::new(dir.path(), &MasterKey::from_bytes([3u8; 32]));
        assert!(Vault::open(&config, again).is_err());
    }
}
