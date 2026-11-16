//! The in-memory credential tables.
//!
//! `providers` and `services` are separate maps of separate row types. Each
//! row owns its decrypted secret, its epoch channel and its policy. After
//! boot the only disk I/O here is `set` and `revoke` writing a sealed row;
//! request and stream paths read memory only.

use crate::BootError;
use keygate_core::config::{Config, ProviderCfg, ServiceCfg, UpstreamRef};
use keygate_core::echo::{EchoAutomaton, MIN_SECRET_LEN};
use keygate_core::path::PlainPath;
use keygate_core::proto::{Code, Refusal, RowInfo};
use keygate_core::seal::{SealStore, SealedRow};
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
    secret: RwLock<Option<Arc<ActiveSecret>>>,
}

pub struct ProviderRow {
    pub upstream: Upstream,
    pub methods: Vec<String>,
    pub paths: Vec<PlainPath>,
    pub models: Vec<String>,
    pub max_output_tokens: u64,
    pub input_micro_usd_per_mtok: u64,
    pub output_micro_usd_per_mtok: u64,
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

struct Guarded {
    automaton: Arc<EchoAutomaton>,
    secrets: usize,
}

pub struct Vault {
    providers: Option<BTreeMap<String, ProviderRow>>,
    services: Option<BTreeMap<String, ServiceRow>>,
    store: SealStore,
    guarded: RwLock<Guarded>,
    /// Serializes `set` / `revoke` so sealed files and epochs move together.
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
        let sealed = store.read(ns, name)?;
        let (epoch, secret) = match sealed {
            Some(SealedRow {
                generation,
                revoked_floor,
                secret,
            }) => {
                let live = secret
                    .filter(|_| generation >= revoked_floor)
                    .map(|bytes| Arc::new(ActiveSecret { generation, bytes }));
                (
                    RowEpoch {
                        generation,
                        revoked_floor,
                    },
                    live,
                )
            }
            None => (
                RowEpoch {
                    generation: 0,
                    revoked_floor: 0,
                },
                None,
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
            secret: RwLock::new(secret),
        })
    }

    /// The secret new requests should use, if the row has one.
    pub fn secret(&self) -> Option<Arc<ActiveSecret>> {
        read(&self.secret).clone()
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
        let state = match self.secret() {
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
        }
    }
}

impl ProviderRow {
    fn load(name: &str, cfg: &ProviderCfg, store: &SealStore) -> Result<Self, BootError> {
        Ok(ProviderRow {
            upstream: Upstream::load(Namespace::Provider, name, cfg.upstream(), store)?,
            methods: cfg.methods.clone(),
            paths: prefixes(&cfg.paths),
            models: cfg.models.clone(),
            max_output_tokens: cfg.max_output_tokens,
            input_micro_usd_per_mtok: cfg.input_micro_usd_per_mtok,
            output_micro_usd_per_mtok: cfg.output_micro_usd_per_mtok,
            per_call_micro_usd: cfg.per_call_micro_usd,
            per_day_micro_usd: cfg.per_day_micro_usd,
            per_seat_day_micro_usd: cfg.per_seat_day_micro_usd,
        })
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
            guarded: RwLock::new(Guarded {
                automaton: Arc::new(EchoAutomaton::build([])),
                secrets: 0,
            }),
            admin: Mutex::new(()),
        };
        vault.rebuild_guard();
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

    /// The automaton over every currently active secret. A stream keeps the
    /// `Arc` it started with, so it stays guarded against the secret it was
    /// actually sent with even after a rotation.
    pub fn guard(&self) -> Arc<EchoAutomaton> {
        read(&self.guarded).automaton.clone()
    }

    pub fn guarded_secrets(&self) -> usize {
        read(&self.guarded).secrets
    }

    fn rebuild_guard(&self) {
        let secrets: Vec<Arc<ActiveSecret>> =
            self.upstreams().filter_map(Upstream::secret).collect();
        let automaton = Arc::new(EchoAutomaton::build(secrets.iter().map(|s| s.expose())));
        *write(&self.guarded) = Guarded {
            automaton,
            secrets: secrets.len(),
        };
    }

    /// Load or rotate a row's secret. New requests use it at once. Streams
    /// already open keep running on the old one unless `cut_existing`.
    pub fn set(
        &self,
        ns: Namespace,
        row: &str,
        secret: SecretBytes,
        cut_existing: bool,
    ) -> Result<RowEpoch, Refusal> {
        let upstream = self.upstream(ns, row)?;
        check_secret(upstream, &secret)?;
        let _admin = self
            .admin
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let current = upstream.epoch();
        let generation = current.generation + 1;
        let next = RowEpoch {
            generation,
            revoked_floor: if cut_existing {
                generation
            } else {
                current.revoked_floor
            },
        };
        let sealed = SealedRow {
            generation,
            revoked_floor: next.revoked_floor,
            secret: Some(secret),
        };
        self.store.write(ns, row, &sealed).map_err(|e| {
            Refusal::new(
                Code::Internal,
                format!("sealing {ns}/{row} failed; nothing changed: {e}"),
            )
        })?;
        let bytes = sealed.secret.expect("constructed with a secret");

        *write(&upstream.secret) = Some(Arc::new(ActiveSecret { generation, bytes }));
        self.rebuild_guard();
        upstream.epoch.send_replace(next);
        Ok(next)
    }

    /// Destroy a row's secret. The epoch moves first, in memory, so open
    /// streams are cut before any disk I/O happens.
    pub fn revoke(&self, ns: Namespace, row: &str) -> Result<RowEpoch, Refusal> {
        let upstream = self.upstream(ns, row)?;
        let _admin = self
            .admin
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let current = upstream.epoch();
        let next = RowEpoch {
            generation: current.generation,
            revoked_floor: current.generation + 1,
        };
        upstream.epoch.send_replace(next);
        *write(&upstream.secret) = None;
        self.rebuild_guard();

        let tombstone = SealedRow {
            generation: next.generation,
            revoked_floor: next.revoked_floor,
            secret: None,
        };
        if let Err(e) = self.store.write(ns, row, &tombstone) {
            // Revoked in memory regardless. Make sure the sealed secret
            // cannot come back at the next start.
            let removed = std::fs::remove_file(self.store.path(ns, row));
            return Err(Refusal::new(
                Code::Internal,
                format!("{ns}/{row} is revoked in memory, but writing the tombstone failed ({e}); removing the sealed file: {removed:?}"),
            ));
        }
        Ok(next)
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
