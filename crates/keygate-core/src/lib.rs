//! `keygate-core`: the synchronous, network-free custody primitives.
//!
//! Everything here is deterministic given its inputs and the filesystem:
//! sealing at rest, macaroon capability tokens, the `EchoGuard` stream
//! scrubber, `plain_path` canonicalization, the ticket journal and the audit
//! log. The async broker lives in `keygate-broker`.

pub mod audit;
pub mod config;
pub mod echo;
pub mod journal;
pub mod macaroon;
pub mod path;
pub mod proto;
pub mod seal;
pub mod secret;

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The two credential tables. They share no rows, no directory and no
/// sealing AAD: a row named `x` may exist in both and they are unrelated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Namespace {
    Provider,
    Service,
}

impl Namespace {
    pub const fn as_str(self) -> &'static str {
        match self {
            Namespace::Provider => "provider",
            Namespace::Service => "service",
        }
    }

    /// Directory under the state dir holding this namespace's sealed rows.
    pub const fn dir(self) -> &'static str {
        match self {
            Namespace::Provider => "providers",
            Namespace::Service => "services",
        }
    }
}

impl fmt::Display for Namespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Namespace {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "provider" | "providers" => Ok(Namespace::Provider),
            "service" | "services" => Ok(Namespace::Service),
            other => Err(format!(
                "unknown namespace {other:?} (expected provider or service)"
            )),
        }
    }
}

/// Row and seat names: `[A-Za-z0-9][A-Za-z0-9_.-]{0,63}`. The alphabet keeps
/// names safe as file names, ledger key components and URL path segments.
pub fn valid_name(s: &str) -> bool {
    let bytes = s.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
        && s != "."
        && s != ".."
}

/// Clocks earlier than this (2025-06-15) are treated as broken. A clock
/// that has fallen back to the epoch would otherwise make every expiry
/// caveat pass and reset every daily budget.
pub const MIN_PLAUSIBLE_UNIX_S: u64 = 1_750_000_000;

/// The system clock cannot be used to evaluate expiries or budgets.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("system clock is unusable ({0}); refusing to evaluate expiries or budgets")]
pub struct ClockError(pub String);

/// Interpret a wall-clock reading. There is no fallback value: callers
/// fail closed on `Err`.
pub fn clock_from(now: SystemTime) -> Result<Duration, ClockError> {
    let since = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ClockError("it reads before 1970".to_owned()))?;
    if since.as_secs() < MIN_PLAUSIBLE_UNIX_S {
        return Err(ClockError(format!(
            "it reads {} s since the epoch, before this build existed",
            since.as_secs()
        )));
    }
    Ok(since)
}

pub fn unix_time() -> Result<u64, ClockError> {
    clock_from(SystemTime::now()).map(|d| d.as_secs())
}

pub fn unix_time_ms() -> Result<u64, ClockError> {
    clock_from(SystemTime::now()).map(|d| d.as_millis() as u64)
}

/// Fill `buf` from the OS CSPRNG.
pub fn random_bytes(buf: &mut [u8]) -> std::io::Result<()> {
    getrandom::getrandom(buf).map_err(|e| std::io::Error::other(format!("os rng: {e}")))
}

/// serde adapter: `Vec<u8>` as standard base64.
pub mod b64 {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

/// serde adapter: `[u8; N]` as lowercase hex.
pub mod hexser {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer, const N: usize>(v: &[u8; N], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<[u8; N], D::Error> {
        let s = String::deserialize(d)?;
        let mut out = [0u8; N];
        hex::decode_to_slice(s.as_bytes(), &mut out).map_err(serde::de::Error::custom)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        for ok in ["anthropic", "gh-rest", "a", "Seat_7.b"] {
            assert!(valid_name(ok), "{ok}");
        }
        for bad in ["", ".", "..", "-x", "a/b", "a b", "a:b", &"x".repeat(65)] {
            assert!(!valid_name(bad), "{bad}");
        }
    }

    /// #tooth: a clock before the epoch or before this build is an error,
    /// never a zero that would make every expiry pass.
    #[test]
    fn tooth_broken_clocks_fail_closed() {
        assert!(clock_from(UNIX_EPOCH - Duration::from_secs(1)).is_err());
        assert!(clock_from(UNIX_EPOCH).is_err());
        assert!(clock_from(UNIX_EPOCH + Duration::from_secs(MIN_PLAUSIBLE_UNIX_S - 1)).is_err());
        let ok = clock_from(UNIX_EPOCH + Duration::from_secs(MIN_PLAUSIBLE_UNIX_S)).unwrap();
        assert_eq!(ok.as_secs(), MIN_PLAUSIBLE_UNIX_S);
        assert!(unix_time().unwrap() >= MIN_PLAUSIBLE_UNIX_S);
    }

    #[test]
    fn namespace_round_trip() {
        assert_eq!(
            "provider".parse::<Namespace>().unwrap(),
            Namespace::Provider
        );
        assert_eq!("services".parse::<Namespace>().unwrap(), Namespace::Service);
        assert!("pool".parse::<Namespace>().is_err());
        assert_ne!(Namespace::Provider.dir(), Namespace::Service.dir());
    }
}
