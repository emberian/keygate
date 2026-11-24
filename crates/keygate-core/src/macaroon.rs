//! `MacaroonV1`: attenuable capability tokens with chained BLAKE3 MACs.
//!
//! ```text
//! tag_0     = BLAKE3-keyed(root_key, "keygate-macaroon/v1\0root"   || enc(root))
//! tag_{i+1} = BLAKE3-keyed(tag_i,    "keygate-macaroon/v1\0caveat" || enc(caveat_i))
//! token     = "kgm_" || base64url(version || enc(root) || caveats || tag_n)
//! ```
//!
//! Holding `tag_n` lets anyone append a caveat (compute `tag_{n+1}`) but not
//! remove one (that needs `tag_{n-1}`, which a one-way MAC hides). Every
//! caveat is a predicate over the request and all must hold, so appending
//! can only narrow. The caveat set is the first-order wire subset of
//! `Obend.Vault.Form` residual predicates.

use crate::path::PlainPath;
use crate::Namespace;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

pub const TOKEN_PREFIX: &str = "kgm_";
const VERSION: u8 = 1;
const ROOT_DOMAIN: &[u8] = b"keygate-macaroon/v1\0root";
const CAVEAT_DOMAIN: &[u8] = b"keygate-macaroon/v1\0caveat";
const SCOPE_CONTEXT: &str = "keygate-macaroon/v1 spend scope id";
const OWNER_CONTEXT: &str = "keygate-macaroon/v1 ticket owner id";
/// Context for deriving the macaroon root key from the master key.
pub const ROOT_KEY_CONTEXT: &str = "keygate-macaroon/v1 root key";

pub const MAX_TOKEN_LEN: usize = 16 * 1024;
pub const MAX_CAVEATS: usize = 64;
const MAX_LIST: usize = 256;
const MAX_STR: usize = 2048;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MacaroonError {
    #[error("token does not start with \"kgm_\"")]
    Prefix,
    #[error("token is malformed: {0}")]
    Malformed(&'static str),
    #[error("token signature does not verify")]
    BadSignature,
    #[error("too many caveats (limit {MAX_CAVEATS})")]
    TooManyCaveats,
}

/// A narrowing predicate. All caveats on a token must hold.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Caveat {
    WorkerRoutes(WorkerRoutes),
    GitRef {
        repo: String,
        reference: String,
    },
    /// The token's seat is exactly this one.
    Seat(String),
    Namespace(Namespace),
    /// The row is one of these.
    Rows(Vec<String>),
    /// The HTTP method (uppercase) is one of these.
    Methods(Vec<String>),
    /// The path lies under one of these plain-path prefixes (segment-wise).
    PathPrefixes(Vec<String>),
    /// The request names a model and it is one of these.
    Models(Vec<String>),
    MaxRequestBytes(usize),
    /// Cumulative spend through this caveat, across the token and every
    /// token attenuated from it, stays within this many micro-USD.
    MaxSpendMicroUsd(u64),
    ExpiresAtUnixS(u64),
}

/// Exact service rows for the four buffered worker operations. A missing
/// row denies that operation, even when land and reconcile name the same CAS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerRoutes {
    pub claim: Option<String>,
    pub done: Option<String>,
    pub land: Option<String>,
    pub reconcile: Option<String>,
}

/// The broker selects this from its entry point before checking the token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invocation {
    Forward(crate::journal::CallKind),
    Reconcile,
}

impl WorkerRoutes {
    fn admits(&self, facts: &Facts<'_>, invocation: Invocation) -> bool {
        use crate::journal::CallKind::Buffered;
        if facts.namespace != Namespace::Service || facts.method != "POST" {
            return false;
        }
        let row = match (invocation, facts.path.as_str()) {
            (Invocation::Forward(Buffered), "/pod/claim") => &self.claim,
            (Invocation::Forward(Buffered), "/pod/done") => &self.done,
            (Invocation::Forward(Buffered), "/git/land") => &self.land,
            (Invocation::Reconcile, "/git/land") => &self.reconcile,
            _ => return false,
        };
        row.as_deref() == Some(facts.row)
    }
}

/// What the operator binds at mint time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootId {
    pub seat: String,
    /// When set, only a Unix-socket peer with this uid may use the token.
    pub allowed_uid: Option<u32>,
    /// The seat's epoch at mint; bumping the seat epoch kills older tokens.
    pub root_epoch: u64,
    pub nonce: [u8; 16],
}

#[derive(Clone, PartialEq, Eq)]
pub struct MacaroonV1 {
    root: RootId,
    caveats: Vec<Caveat>,
    tag: [u8; 32],
}

/// The facts a request presents to the caveats.
#[derive(Debug)]
pub struct Facts<'a> {
    pub seat: &'a str,
    pub namespace: Namespace,
    pub row: &'a str,
    pub method: &'a str,
    pub path: &'a PlainPath,
    pub model: Option<&'a str>,
    pub request_bytes: usize,
    pub now_unix_s: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("caveat {index} refuses the request: {reason}")]
pub struct CaveatDenied {
    pub index: usize,
    pub reason: String,
}

/// A cumulative spend ceiling, identified by the chain position it was
/// appended at. The id is a hash of the chain tag, never the tag itself:
/// the tag is a bearer credential for the less-attenuated token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendScope {
    pub id: [u8; 32],
    pub cap_micro_usd: u64,
}

/// A macaroon whose MAC chain verified under the broker's root key.
#[derive(Clone, Debug)]
pub struct Verified {
    pub root: RootId,
    pub caveats: Vec<Caveat>,
    pub spend_scopes: Vec<SpendScope>,
    /// Identifies this exact token (root binding and every caveat): a hash
    /// of the verified final tag. Tickets are owned by it, so a different
    /// token of the same seat can neither find nor replay them.
    pub owner: [u8; 32],
    /// Only for reconciliation: the matching land-only sibling with the
    /// identical parent and pod routes, when the final caveat splits Git use.
    pub reconcile_owner: Option<[u8; 32]>,
}

impl MacaroonV1 {
    pub fn mint(root_key: &[u8; 32], root: RootId) -> Self {
        let tag = mac(root_key, ROOT_DOMAIN, &encode_root(&root));
        MacaroonV1 {
            root,
            caveats: Vec::new(),
            tag,
        }
    }

    /// Append a caveat. Needs no key: this is the offline attenuation step.
    pub fn attenuate(mut self, caveat: Caveat) -> Result<Self, MacaroonError> {
        if self.caveats.len() >= MAX_CAVEATS {
            return Err(MacaroonError::TooManyCaveats);
        }
        self.tag = mac(&self.tag, CAVEAT_DOMAIN, &encode_caveat(&caveat)?);
        self.caveats.push(caveat);
        Ok(self)
    }

    pub fn root(&self) -> &RootId {
        &self.root
    }

    pub fn caveats(&self) -> &[Caveat] {
        &self.caveats
    }

    pub fn encode(&self) -> String {
        let mut w = Zeroizing::new(Vec::with_capacity(128));
        w.push(VERSION);
        w.extend_from_slice(&encode_root(&self.root));
        put_u32(&mut w, self.caveats.len() as u32);
        for caveat in &self.caveats {
            let enc =
                encode_caveat(caveat).expect("caveats were validated when appended or decoded");
            put_bytes(&mut w, &enc);
        }
        w.extend_from_slice(&self.tag);
        format!("{TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(&*w))
    }

    pub fn decode(token: &str) -> Result<Self, MacaroonError> {
        let body = token
            .strip_prefix(TOKEN_PREFIX)
            .ok_or(MacaroonError::Prefix)?;
        if body.len() > MAX_TOKEN_LEN {
            return Err(MacaroonError::Malformed("too long"));
        }
        let raw = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(body)
                .map_err(|_| MacaroonError::Malformed("not base64url"))?,
        );
        let mut r = Reader(&raw);
        if r.u8()? != VERSION {
            return Err(MacaroonError::Malformed("unknown version"));
        }
        let root = decode_root(&mut r)?;
        let count = r.u32()? as usize;
        if count > MAX_CAVEATS {
            return Err(MacaroonError::TooManyCaveats);
        }
        let mut caveats = Vec::with_capacity(count);
        for _ in 0..count {
            let enc = r.bytes()?;
            let caveat = decode_caveat(enc)?;
            // Canonical form only: the MAC covers the re-encoding.
            if encode_caveat(&caveat)? != enc {
                return Err(MacaroonError::Malformed("non-canonical caveat"));
            }
            caveats.push(caveat);
        }
        let tag: [u8; 32] = r.take(32)?.try_into().expect("took 32");
        if !r.0.is_empty() {
            return Err(MacaroonError::Malformed("trailing bytes"));
        }
        Ok(MacaroonV1 { root, caveats, tag })
    }

    /// Recompute the chain under `root_key` and compare in constant time.
    pub fn verify(&self, root_key: &[u8; 32]) -> Result<Verified, MacaroonError> {
        let mut tag = Zeroizing::new(mac(root_key, ROOT_DOMAIN, &encode_root(&self.root)));
        let mut spend_scopes = Vec::new();
        let mut reconcile_owner = None;
        for (index, caveat) in self.caveats.iter().enumerate() {
            if index + 1 == self.caveats.len() {
                if let Caveat::WorkerRoutes(routes) = caveat {
                    if routes.land.is_none() && routes.reconcile.is_some() {
                        let mut sibling = routes.clone();
                        sibling.land = sibling.reconcile.take();
                        let encoded = encode_caveat(&Caveat::WorkerRoutes(sibling))?;
                        let sibling_tag = Zeroizing::new(mac(&tag, CAVEAT_DOMAIN, &encoded));
                        reconcile_owner = Some(blake3::derive_key(OWNER_CONTEXT, &*sibling_tag));
                    }
                }
            }
            *tag = mac(&tag, CAVEAT_DOMAIN, &encode_caveat(caveat)?);
            if let Caveat::MaxSpendMicroUsd(cap) = caveat {
                spend_scopes.push(SpendScope {
                    id: blake3::derive_key(SCOPE_CONTEXT, &*tag),
                    cap_micro_usd: *cap,
                });
            }
        }
        if blake3::Hash::from(*tag) != blake3::Hash::from(self.tag) {
            return Err(MacaroonError::BadSignature);
        }
        Ok(Verified {
            root: self.root.clone(),
            caveats: self.caveats.clone(),
            spend_scopes,
            reconcile_owner,
            owner: blake3::derive_key(OWNER_CONTEXT, &*tag),
        })
    }
}

impl Zeroize for MacaroonV1 {
    fn zeroize(&mut self) {
        self.tag.zeroize();
    }
}

impl Drop for MacaroonV1 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl std::fmt::Debug for MacaroonV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MacaroonV1")
            .field("root", &self.root)
            .field("caveats", &self.caveats)
            .field("tag", &"<redacted>")
            .finish()
    }
}

impl Verified {
    /// The earliest `ExpiresAtUnixS` on the token, if it has one.
    pub fn expires_at_unix_s(&self) -> Option<u64> {
        self.caveats
            .iter()
            .filter_map(|c| match c {
                Caveat::ExpiresAtUnixS(at) => Some(*at),
                _ => None,
            })
            .min()
    }

    /// Check the caveats that depend only on who is calling which row and
    /// when: `Seat`, `Namespace`, `Rows`, `ExpiresAtUnixS`. Transports use
    /// this to turn a caller away before reading its request body; the
    /// full [`Verified::admit`] still runs afterwards.
    pub fn admit_route(
        &self,
        namespace: Namespace,
        row: &str,
        now_unix_s: u64,
    ) -> Result<(), CaveatDenied> {
        for (index, caveat) in self.caveats.iter().enumerate() {
            let reason = match caveat {
                Caveat::Seat(seat) if *seat != self.root.seat => format!("seat is not {seat:?}"),
                Caveat::Namespace(ns) if *ns != namespace => format!("namespace is not {ns}"),
                Caveat::Rows(rows) if !rows.iter().any(|r| r == row) => {
                    format!("row {row:?} not in {rows:?}")
                }
                Caveat::ExpiresAtUnixS(at) if now_unix_s >= *at => format!("expired at {at}"),
                _ => continue,
            };
            return Err(CaveatDenied { index, reason });
        }
        Ok(())
    }

    /// The tightest `MaxRequestBytes` on the token, if it has one.
    pub fn max_request_bytes(&self) -> Option<usize> {
        self.caveats
            .iter()
            .filter_map(|c| match c {
                Caveat::MaxRequestBytes(max) => Some(*max),
                _ => None,
            })
            .min()
    }

    /// Check every stateless caveat against `facts`. Spend ceilings are
    /// stateful and are enforced by the ticket journal via `spend_scopes`.
    pub fn admit(&self, facts: &Facts<'_>) -> Result<(), CaveatDenied> {
        self.admit_with_git(facts, None)
    }

    pub fn admit_with_git(
        &self,
        facts: &Facts<'_>,
        git_land: Option<&crate::git_land::GitLand>,
    ) -> Result<(), CaveatDenied> {
        self.admit_invocation(
            facts,
            git_land,
            Invocation::Forward(crate::journal::CallKind::Buffered),
        )
    }

    pub fn admit_invocation(
        &self,
        facts: &Facts<'_>,
        git_land: Option<&crate::git_land::GitLand>,
        invocation: Invocation,
    ) -> Result<(), CaveatDenied> {
        for (index, caveat) in self.caveats.iter().enumerate() {
            let deny = |reason: String| Err(CaveatDenied { index, reason });
            match caveat {
                Caveat::WorkerRoutes(routes) if !routes.admits(facts, invocation) => {
                    return deny("worker operation or row outside grant".into())
                }
                Caveat::GitRef { repo, reference }
                    if !git_land.is_some_and(|g| &g.repo == repo && &g.reference == reference) =>
                {
                    return deny("Git repository or ref is outside the capability".into())
                }
                Caveat::Seat(seat) if seat != facts.seat => {
                    return deny(format!("seat is not {seat:?}"))
                }
                Caveat::Namespace(ns) if *ns != facts.namespace => {
                    return deny(format!("namespace is not {ns}"))
                }
                Caveat::Rows(rows) if !rows.iter().any(|r| r == facts.row) => {
                    return deny(format!("row {:?} not in {rows:?}", facts.row))
                }
                Caveat::Methods(methods) if !methods.iter().any(|m| m == facts.method) => {
                    return deny(format!("method {} not in {methods:?}", facts.method))
                }
                Caveat::PathPrefixes(prefixes) => {
                    let covered = prefixes
                        .iter()
                        .filter_map(|p| PlainPath::parse(p).ok())
                        .any(|p| facts.path.starts_with(&p));
                    if !covered {
                        return deny(format!("path {} not under {prefixes:?}", facts.path));
                    }
                }
                Caveat::Models(models) => match facts.model {
                    Some(model) if models.iter().any(|m| m == model) => {}
                    Some(model) => return deny(format!("model {model:?} not in {models:?}")),
                    None => return deny("request names no model".to_owned()),
                },
                Caveat::MaxRequestBytes(max) if facts.request_bytes > *max => {
                    return deny(format!(
                        "request is {} bytes, limit {max}",
                        facts.request_bytes
                    ))
                }
                Caveat::ExpiresAtUnixS(at) if facts.now_unix_s >= *at => {
                    return deny(format!("expired at {at}"))
                }
                _ => {}
            }
        }
        Ok(())
    }
}

fn mac(key: &[u8; 32], domain: &[u8], message: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(domain);
    hasher.update(message);
    *hasher.finalize().as_bytes()
}

fn put_u32(w: &mut Vec<u8>, v: u32) {
    w.extend_from_slice(&v.to_le_bytes());
}

fn put_u64(w: &mut Vec<u8>, v: u64) {
    w.extend_from_slice(&v.to_le_bytes());
}

fn put_bytes(w: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(w, bytes.len() as u32);
    w.extend_from_slice(bytes);
}

fn put_list(w: &mut Vec<u8>, items: &[String]) -> Result<(), MacaroonError> {
    if items.is_empty() || items.len() > MAX_LIST {
        return Err(MacaroonError::Malformed(
            "list must be nonempty and within the limit",
        ));
    }
    put_u32(w, items.len() as u32);
    for item in items {
        put_str(w, item)?;
    }
    Ok(())
}

fn put_str(w: &mut Vec<u8>, s: &str) -> Result<(), MacaroonError> {
    if s.len() > MAX_STR {
        return Err(MacaroonError::Malformed("string too long"));
    }
    put_bytes(w, s.as_bytes());
    Ok(())
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], MacaroonError> {
        if self.0.len() < n {
            return Err(MacaroonError::Malformed("truncated"));
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, MacaroonError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, MacaroonError> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("took 4"),
        ))
    }

    fn u64(&mut self) -> Result<u64, MacaroonError> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("took 8"),
        ))
    }

    fn bytes(&mut self) -> Result<&'a [u8], MacaroonError> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    fn string(&mut self) -> Result<String, MacaroonError> {
        let bytes = self.bytes()?;
        if bytes.len() > MAX_STR {
            return Err(MacaroonError::Malformed("string too long"));
        }
        String::from_utf8(bytes.to_vec())
            .map_err(|_| MacaroonError::Malformed("string is not utf-8"))
    }

    fn list(&mut self) -> Result<Vec<String>, MacaroonError> {
        let count = self.u32()? as usize;
        if count > MAX_LIST {
            return Err(MacaroonError::Malformed("list too long"));
        }
        (0..count).map(|_| self.string()).collect()
    }
}

fn encode_root(root: &RootId) -> Vec<u8> {
    let mut w = Vec::with_capacity(root.seat.len() + 40);
    put_bytes(&mut w, root.seat.as_bytes());
    match root.allowed_uid {
        None => w.push(0),
        Some(uid) => {
            w.push(1);
            put_u32(&mut w, uid);
        }
    }
    put_u64(&mut w, root.root_epoch);
    w.extend_from_slice(&root.nonce);
    w
}

fn decode_root(r: &mut Reader<'_>) -> Result<RootId, MacaroonError> {
    let seat = r.string()?;
    let allowed_uid = match r.u8()? {
        0 => None,
        1 => Some(r.u32()?),
        _ => return Err(MacaroonError::Malformed("bad uid marker")),
    };
    let root_epoch = r.u64()?;
    let nonce = r.take(16)?.try_into().expect("took 16");
    Ok(RootId {
        seat,
        allowed_uid,
        root_epoch,
        nonce,
    })
}

fn encode_caveat(caveat: &Caveat) -> Result<Vec<u8>, MacaroonError> {
    let mut w = Vec::with_capacity(32);
    match caveat {
        Caveat::WorkerRoutes(routes) => {
            w.push(11);
            for row in [&routes.claim, &routes.done, &routes.land, &routes.reconcile] {
                if row.as_ref().is_some_and(|row| !crate::valid_name(row)) {
                    return Err(MacaroonError::Malformed("invalid worker row"));
                }
                // Empty is the canonical encoding of an absent row.
                put_str(&mut w, row.as_deref().unwrap_or_default())?;
            }
        }
        Caveat::GitRef { repo, reference } => {
            w.push(10);
            put_str(&mut w, repo)?;
            put_str(&mut w, reference)?;
        }
        Caveat::Seat(seat) => {
            if !crate::valid_name(seat) {
                return Err(MacaroonError::Malformed("invalid seat"));
            }
            w.push(1);
            put_str(&mut w, seat)?;
        }
        Caveat::Namespace(ns) => {
            w.push(2);
            w.push(match ns {
                Namespace::Provider => 0,
                Namespace::Service => 1,
            });
        }
        Caveat::Rows(items) => {
            if items.iter().any(|r| !crate::valid_name(r)) {
                return Err(MacaroonError::Malformed("invalid row"));
            }
            w.push(3);
            put_list(&mut w, items)?;
        }
        Caveat::Methods(items) => {
            if items.iter().any(|m| {
                !matches!(
                    m.as_str(),
                    "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE"
                )
            }) {
                return Err(MacaroonError::Malformed("unsupported method"));
            }
            w.push(4);
            put_list(&mut w, items)?;
        }
        Caveat::PathPrefixes(items) => {
            if items.iter().any(|p| PlainPath::parse(p).is_err()) {
                return Err(MacaroonError::Malformed("invalid plain path"));
            }
            w.push(5);
            put_list(&mut w, items)?;
        }
        Caveat::Models(items) => {
            w.push(6);
            put_list(&mut w, items)?;
        }
        Caveat::MaxRequestBytes(n) => {
            w.push(7);
            put_u64(&mut w, *n as u64);
        }
        Caveat::MaxSpendMicroUsd(n) => {
            w.push(8);
            put_u64(&mut w, *n);
        }
        Caveat::ExpiresAtUnixS(n) => {
            w.push(9);
            put_u64(&mut w, *n);
        }
    }
    Ok(w)
}

fn decode_caveat(enc: &[u8]) -> Result<Caveat, MacaroonError> {
    let mut r = Reader(enc);
    let caveat = match r.u8()? {
        1 => Caveat::Seat(r.string()?),
        2 => Caveat::Namespace(match r.u8()? {
            0 => Namespace::Provider,
            1 => Namespace::Service,
            _ => return Err(MacaroonError::Malformed("bad namespace")),
        }),
        3 => Caveat::Rows(r.list()?),
        4 => Caveat::Methods(r.list()?),
        5 => Caveat::PathPrefixes(r.list()?),
        6 => Caveat::Models(r.list()?),
        7 => Caveat::MaxRequestBytes(
            usize::try_from(r.u64()?)
                .map_err(|_| MacaroonError::Malformed("size exceeds platform usize"))?,
        ),
        8 => Caveat::MaxSpendMicroUsd(r.u64()?),
        9 => Caveat::ExpiresAtUnixS(r.u64()?),
        10 => Caveat::GitRef {
            repo: r.string()?,
            reference: r.string()?,
        },
        11 => {
            let mut row = || -> Result<Option<String>, MacaroonError> {
                let value = r.string()?;
                Ok((!value.is_empty()).then_some(value))
            };
            Caveat::WorkerRoutes(WorkerRoutes {
                claim: row()?,
                done: row()?,
                land: row()?,
                reconcile: row()?,
            })
        }
        // An unknown caveat is a restriction this broker cannot evaluate;
        // ignoring it would widen the token.
        _ => return Err(MacaroonError::Malformed("unknown caveat kind")),
    };
    if !r.0.is_empty() {
        return Err(MacaroonError::Malformed("trailing bytes in caveat"));
    }
    Ok(caveat)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [42u8; 32];

    fn root() -> RootId {
        RootId {
            seat: "seat-a".into(),
            allowed_uid: Some(1000),
            root_epoch: 2,
            nonce: [9u8; 16],
        }
    }

    fn facts<'a>(path: &'a PlainPath) -> Facts<'a> {
        Facts {
            seat: "seat-a",
            namespace: Namespace::Provider,
            row: "anthropic",
            method: "POST",
            path,
            model: Some("claude-fable-5-2"),
            request_bytes: 100,
            now_unix_s: 1_000,
        }
    }

    fn all_caveats() -> Vec<Caveat> {
        vec![
            Caveat::Seat("seat-a".into()),
            Caveat::Namespace(Namespace::Provider),
            Caveat::Rows(vec!["anthropic".into(), "openai".into()]),
            Caveat::Methods(vec!["POST".into()]),
            Caveat::PathPrefixes(vec!["/v1/messages".into()]),
            Caveat::Models(vec!["claude-fable-5-2".into()]),
            Caveat::MaxRequestBytes(4096),
            Caveat::MaxSpendMicroUsd(5_000_000),
            Caveat::ExpiresAtUnixS(2_000),
        ]
    }

    fn build(caveats: Vec<Caveat>) -> MacaroonV1 {
        caveats
            .into_iter()
            .fold(MacaroonV1::mint(&KEY, root()), |m, c| {
                m.attenuate(c).unwrap()
            })
    }

    #[test]
    fn round_trip_every_caveat() {
        let m = build(all_caveats());
        let token = m.encode();
        assert!(token.starts_with("kgm_"));
        let back = MacaroonV1::decode(&token).unwrap();
        assert_eq!(back, m);
        let v = back.verify(&KEY).unwrap();
        assert_eq!(v.root, root());
        assert_eq!(v.spend_scopes.len(), 1);
        assert_eq!(v.spend_scopes[0].cap_micro_usd, 5_000_000);
        let path = PlainPath::parse("/v1/messages").unwrap();
        v.admit(&facts(&path)).unwrap();
    }

    /// #tooth: offline attenuation is accepted and actually narrows.
    #[test]
    fn tooth_offline_attenuation_narrows_path_and_ttl() {
        let token = MacaroonV1::mint(&KEY, root()).encode();
        // The holder has only the token string, no key.
        let narrowed = MacaroonV1::decode(&token)
            .unwrap()
            .attenuate(Caveat::PathPrefixes(vec!["/v1/messages".into()]))
            .unwrap()
            .attenuate(Caveat::ExpiresAtUnixS(1_500))
            .unwrap()
            .encode();
        let v = MacaroonV1::decode(&narrowed).unwrap().verify(&KEY).unwrap();

        let ok = PlainPath::parse("/v1/messages/batches").unwrap();
        v.admit(&facts(&ok)).unwrap();

        let outside = PlainPath::parse("/v1/files").unwrap();
        assert_eq!(v.admit(&facts(&outside)).unwrap_err().index, 0);

        let mut late = facts(&ok);
        late.now_unix_s = 1_500;
        assert_eq!(v.admit(&late).unwrap_err().index, 1);
    }

    /// #tooth: stripping a caveat invalidates the chain.
    #[test]
    fn tooth_stripping_a_caveat_is_rejected() {
        let m = build(vec![
            Caveat::Rows(vec!["anthropic".into()]),
            Caveat::ExpiresAtUnixS(2_000),
        ]);
        for strip in 0..2 {
            let mut forged = m.clone();
            forged.caveats.remove(strip);
            let forged = MacaroonV1::decode(&forged.encode()).unwrap();
            assert_eq!(
                forged.verify(&KEY).unwrap_err(),
                MacaroonError::BadSignature,
                "strip {strip}"
            );
        }
        let mut bare = m.clone();
        bare.caveats.clear();
        assert_eq!(bare.verify(&KEY).unwrap_err(), MacaroonError::BadSignature);
    }

    /// #tooth: editing a caveat in place (widening the spend cap) is rejected.
    #[test]
    fn tooth_widening_max_spend_is_rejected() {
        let m = build(vec![Caveat::MaxSpendMicroUsd(1_000)]);
        let mut forged = m.clone();
        forged.caveats[0] = Caveat::MaxSpendMicroUsd(1_000_000_000);
        assert_eq!(
            forged.verify(&KEY).unwrap_err(),
            MacaroonError::BadSignature
        );

        // Appending a *larger* cap is legal but does not widen: both scopes bind.
        let stacked = m
            .attenuate(Caveat::MaxSpendMicroUsd(1_000_000_000))
            .unwrap();
        let v = stacked.verify(&KEY).unwrap();
        assert_eq!(
            v.spend_scopes.iter().map(|s| s.cap_micro_usd).min(),
            Some(1_000)
        );
    }

    /// #tooth: the root binding (seat, uid, epoch) cannot be edited either.
    #[test]
    fn tooth_root_binding_is_authenticated() {
        let m = build(vec![]);
        let edits: [fn(&mut RootId); 4] = [
            |r| r.seat = "seat-b".into(),
            |r| r.allowed_uid = None,
            |r| r.root_epoch += 1,
            |r| r.nonce[0] ^= 1,
        ];
        for edit in edits {
            let mut forged = m.clone();
            edit(&mut forged.root);
            assert_eq!(
                forged.verify(&KEY).unwrap_err(),
                MacaroonError::BadSignature
            );
        }
        assert_eq!(
            m.verify(&[43u8; 32]).unwrap_err(),
            MacaroonError::BadSignature
        );
    }

    #[test]
    fn each_caveat_denies_its_own_violation() {
        let v = build(all_caveats()).verify(&KEY).unwrap();
        let path = PlainPath::parse("/v1/messages").unwrap();
        let other = PlainPath::parse("/v1/complete").unwrap();
        let denied = |f: Facts<'_>| v.admit(&f).unwrap_err().index;

        assert_eq!(
            denied(Facts {
                seat: "seat-b",
                ..facts(&path)
            }),
            0
        );
        assert_eq!(
            denied(Facts {
                namespace: Namespace::Service,
                ..facts(&path)
            }),
            1
        );
        assert_eq!(
            denied(Facts {
                row: "gemini",
                ..facts(&path)
            }),
            2
        );
        assert_eq!(
            denied(Facts {
                method: "DELETE",
                ..facts(&path)
            }),
            3
        );
        assert_eq!(denied(facts(&other)), 4);
        assert_eq!(
            denied(Facts {
                model: Some("gpt-9"),
                ..facts(&path)
            }),
            5
        );
        assert_eq!(
            denied(Facts {
                model: None,
                ..facts(&path)
            }),
            5
        );
        assert_eq!(
            denied(Facts {
                request_bytes: 4097,
                ..facts(&path)
            }),
            6
        );
        assert_eq!(
            denied(Facts {
                now_unix_s: 2_000,
                ..facts(&path)
            }),
            8
        );
    }

    #[test]
    fn spend_scope_ids_are_shared_by_descendants_and_hide_the_tag() {
        let parent = build(vec![Caveat::MaxSpendMicroUsd(10)]);
        let child = parent
            .clone()
            .attenuate(Caveat::Methods(vec!["POST".into()]))
            .unwrap();
        let sibling = build(vec![Caveat::MaxSpendMicroUsd(10)]);
        let p = parent.verify(&KEY).unwrap().spend_scopes;
        let c = child.verify(&KEY).unwrap().spend_scopes;
        assert_eq!(p, c);
        assert_eq!(
            p,
            sibling.verify(&KEY).unwrap().spend_scopes,
            "same root + same caveat = same scope"
        );
        assert_ne!(p[0].id, parent.tag);

        let other_root = MacaroonV1::mint(
            &KEY,
            RootId {
                nonce: [1u8; 16],
                ..root()
            },
        )
        .attenuate(Caveat::MaxSpendMicroUsd(10))
        .unwrap();
        assert_ne!(p, other_root.verify(&KEY).unwrap().spend_scopes);
    }

    /// #tooth: the ticket-owner id is per exact token. Attenuating changes
    /// it, re-deriving the same token reproduces it, and it is not the tag.
    #[test]
    fn tooth_owner_id_is_per_token_and_hides_the_tag() {
        let parent = build(vec![Caveat::MaxSpendMicroUsd(10)]);
        let child = parent
            .clone()
            .attenuate(Caveat::Methods(vec!["POST".into()]))
            .unwrap();
        let p = parent.verify(&KEY).unwrap();
        let c = child.verify(&KEY).unwrap();
        assert_ne!(p.owner, c.owner);
        assert_eq!(
            p.spend_scopes, c.spend_scopes,
            "spend scope is shared, ownership is not"
        );
        assert_eq!(
            p.owner,
            MacaroonV1::decode(&parent.encode())
                .unwrap()
                .verify(&KEY)
                .unwrap()
                .owner
        );
        assert_ne!(p.owner, parent.tag);
        assert_ne!(p.owner, p.spend_scopes[0].id);
        let other_root = MacaroonV1::mint(
            &KEY,
            RootId {
                nonce: [1u8; 16],
                ..root()
            },
        )
        .attenuate(Caveat::MaxSpendMicroUsd(10))
        .unwrap();
        assert_ne!(p.owner, other_root.verify(&KEY).unwrap().owner);

        let t = build(vec![
            Caveat::ExpiresAtUnixS(900),
            Caveat::MaxRequestBytes(50),
            Caveat::ExpiresAtUnixS(700),
            Caveat::MaxRequestBytes(80),
        ]);
        let v = t.verify(&KEY).unwrap();
        assert_eq!(
            (v.expires_at_unix_s(), v.max_request_bytes()),
            (Some(700), Some(50))
        );
        assert_eq!((p.expires_at_unix_s(), p.max_request_bytes()), (None, None));

        let routed = build(vec![
            Caveat::Namespace(Namespace::Service),
            Caveat::Rows(vec!["gh".into()]),
            Caveat::Models(vec!["m".into()]),
            Caveat::ExpiresAtUnixS(900),
        ])
        .verify(&KEY)
        .unwrap();
        assert!(
            routed.admit_route(Namespace::Service, "gh", 899).is_ok(),
            "body caveats wait for the body"
        );
        assert_eq!(
            routed
                .admit_route(Namespace::Provider, "gh", 899)
                .unwrap_err()
                .index,
            0
        );
        assert_eq!(
            routed
                .admit_route(Namespace::Service, "api", 899)
                .unwrap_err()
                .index,
            1
        );
        assert_eq!(
            routed
                .admit_route(Namespace::Service, "gh", 900)
                .unwrap_err()
                .index,
            3
        );
    }

    #[test]
    fn malformed_tokens() {
        assert_eq!(
            MacaroonV1::decode("sk-ant-xyz").unwrap_err(),
            MacaroonError::Prefix
        );
        assert!(MacaroonV1::decode("kgm_!!!").is_err());
        assert!(MacaroonV1::decode("kgm_").is_err());
        let token = build(all_caveats()).encode();
        assert!(MacaroonV1::decode(&token[..token.len() - 3]).is_err());
        let mut raw = URL_SAFE_NO_PAD.decode(&token[4..]).unwrap();
        raw.push(0);
        assert!(MacaroonV1::decode(&format!("kgm_{}", URL_SAFE_NO_PAD.encode(raw))).is_err());
    }

    #[test]
    fn debug_redacts_tag() {
        let m = build(vec![]);
        assert!(format!("{m:?}").contains("<redacted>"));
    }

    /// #tooth: unusable restrictions fail at attenuation, not first use.
    #[test]
    fn tooth_invalid_caveats_fail_eagerly() {
        let bad = vec![
            Caveat::Seat("../seat".into()),
            Caveat::Seat("".into()),
            Caveat::Rows(vec!["ok".into(), "a/b".into()]),
            Caveat::Rows(vec![]),
            Caveat::Methods(vec!["get".into()]),
            Caveat::Methods(vec!["CONNECT".into()]),
            Caveat::Methods(vec!["BOGUS".into()]),
            Caveat::Methods(vec![]),
            Caveat::PathPrefixes(vec!["/ok".into(), "/a/../b".into()]),
            Caveat::PathPrefixes(vec!["/%2e".into()]),
            Caveat::PathPrefixes(vec![]),
        ];
        for caveat in bad {
            assert!(
                MacaroonV1::mint(&KEY, root())
                    .attenuate(caveat.clone())
                    .is_err(),
                "{caveat:?}"
            );
        }
        assert!(MacaroonV1::mint(&KEY, root())
            .attenuate(Caveat::PathPrefixes(vec!["/".into()]))
            .is_ok());
        // Exercise the wiping implementation used by Drop without reading
        // freed storage. Verify that the type needs destruction too.
        let mut token = build(all_caveats());
        assert_ne!(token.tag, [0; 32]);
        assert!(std::mem::needs_drop::<MacaroonV1>());
        token.zeroize();
        assert_eq!(token.tag, [0; 32]);
    }
}
