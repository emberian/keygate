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
use std::time::{SystemTime, UNIX_EPOCH};

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

pub fn now_unix_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
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
