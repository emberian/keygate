//! `keygate.toml`: the non-secret half of the broker's state.
//!
//! Secrets never appear here; they enter through `keygate set` and live
//! sealed under `providers/` and `services/`.

use crate::path::PlainPath;
use crate::valid_name;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("config does not parse: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("neither [providers] nor [services] has a row; refusing to start an empty broker")]
    NoTables,
    #[error("{table}.{row}: {problem}")]
    Row {
        table: &'static str,
        row: String,
        problem: String,
    },
    #[error("broker: {0}")]
    Broker(String),
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub broker: BrokerCfg,
    /// Metered LLM upstreams. Optional independently of `services`.
    pub providers: Option<BTreeMap<String, ProviderCfg>>,
    /// Arbitrary HTTPS APIs and event streams. Optional independently of `providers`.
    pub services: Option<BTreeMap<String, ServiceCfg>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct BrokerCfg {
    /// Unix socket path; relative paths are resolved against the state dir.
    pub socket: PathBuf,
    /// Socket file mode. Widen (e.g. `0o660`) when agents run under other uids.
    pub socket_mode: u32,
    /// Opt-in loopback HTTP gateway. Must be a loopback address.
    pub http_listen: Option<SocketAddr>,
    /// Uids allowed to mint, set, revoke and list. Empty means the owner of
    /// the state directory.
    pub operator_uids: Vec<u32>,
    /// How long tickets (and retained buffered replies) stay replayable.
    pub retention_s: u64,
    /// Rewrite the journal after this many appended records.
    pub compact_every: u64,
    /// Largest buffered upstream reply keygate will hold and journal.
    pub max_response_bytes: usize,
    pub connect_timeout_ms: u64,
    /// Whole-exchange deadline for buffered calls. Streams have none.
    pub buffered_timeout_ms: u64,
}

impl Default for BrokerCfg {
    fn default() -> Self {
        BrokerCfg {
            socket: PathBuf::from("keygate.sock"),
            socket_mode: 0o600,
            http_listen: None,
            operator_uids: Vec::new(),
            retention_s: 900,
            compact_every: 1024,
            max_response_bytes: 16 << 20,
            connect_timeout_ms: 10_000,
            buffered_timeout_ms: 600_000,
        }
    }
}

/// The upstream fields every row has, borrowed from either table's row.
#[derive(Clone, Copy, Debug)]
pub struct UpstreamRef<'a> {
    pub origin: &'a str,
    pub auth_header: &'a str,
    pub auth_prefix: Option<&'a str>,
    pub caller_headers: &'a [String],
    pub fixed_headers: &'a BTreeMap<String, String>,
    pub max_request_bytes: usize,
}

fn default_auth_header() -> String {
    "authorization".to_owned()
}

fn default_max_request_bytes() -> usize {
    4 << 20
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCfg {
    /// `https://host[:port]`, or `http://127.0.0.1[:port]` / `http://[::1][:port]`.
    pub origin: String,
    /// Header the sealed secret is injected into.
    #[serde(default = "default_auth_header")]
    pub auth_header: String,
    /// Literal prefix before the secret; defaults to `"Bearer "` for
    /// `authorization` and to nothing for any other header.
    pub auth_prefix: Option<String>,
    /// Caller-supplied headers that are forwarded, beyond `accept` and
    /// `content-type`. Lowercase.
    #[serde(default)]
    pub caller_headers: Vec<String>,
    /// Headers keygate sets on every upstream request.
    #[serde(default)]
    pub fixed_headers: BTreeMap<String, String>,
    #[serde(default = "default_max_request_bytes")]
    pub max_request_bytes: usize,
    #[serde(default = "default_provider_methods")]
    pub methods: Vec<String>,
    /// Plain-path prefixes callers may reach.
    pub paths: Vec<String>,
    /// The JSON body's `model` must be one of these.
    pub models: Vec<String>,
    /// The JSON body must carry an explicit output-token cap no larger than this.
    pub max_output_tokens: u64,
    #[serde(default)]
    pub input_micro_usd_per_mtok: u64,
    #[serde(default)]
    pub output_micro_usd_per_mtok: u64,
    /// Ceiling on one call's reserved cost.
    pub per_call_micro_usd: Option<u64>,
    /// Ceiling on the row's total reserved cost per UTC day.
    pub per_day_micro_usd: Option<u64>,
    /// Fairness share: ceiling per seat per UTC day.
    pub per_seat_day_micro_usd: Option<u64>,
}

fn default_provider_methods() -> Vec<String> {
    vec!["POST".to_owned()]
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceCfg {
    /// `https://host[:port]`, or `http://127.0.0.1[:port]` / `http://[::1][:port]`.
    pub origin: String,
    /// Header the sealed secret is injected into.
    #[serde(default = "default_auth_header")]
    pub auth_header: String,
    /// Literal prefix before the secret; defaults to `"Bearer "` for
    /// `authorization` and to nothing for any other header.
    pub auth_prefix: Option<String>,
    /// Caller-supplied headers that are forwarded, beyond `accept` and
    /// `content-type`. Lowercase.
    #[serde(default)]
    pub caller_headers: Vec<String>,
    /// Headers keygate sets on every upstream request.
    #[serde(default)]
    pub fixed_headers: BTreeMap<String, String>,
    #[serde(default = "default_max_request_bytes")]
    pub max_request_bytes: usize,
    #[serde(default = "default_service_methods")]
    pub methods: Vec<String>,
    /// Prefixes served whole, journaled and replayable.
    #[serde(default)]
    pub buffered_paths: Vec<String>,
    /// Prefixes served as SSE / chunked streams.
    #[serde(default)]
    pub stream_paths: Vec<String>,
}

fn default_service_methods() -> Vec<String> {
    vec!["GET".to_owned()]
}

/// Headers that must never come from config or callers: they are either
/// hop-by-hop, owned by the HTTP stack, or would defeat `EchoGuard`.
pub const RESERVED_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "upgrade",
    "te",
    "trailer",
    "keep-alive",
    "proxy-authorization",
    "proxy-connection",
    "accept-encoding",
    "expect",
];

fn header_name_ok(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'))
        && !RESERVED_HEADERS.contains(&name)
}

/// Validate an origin string: scheme, host and optional port, nothing else.
pub fn check_origin(origin: &str) -> Result<(), String> {
    let url = url::Url::parse(origin).map_err(|e| format!("origin {origin:?}: {e}"))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(format!("origin {origin:?} must not carry userinfo"));
    }
    if url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || origin.ends_with('/')
    {
        return Err(format!(
            "origin {origin:?} must be scheme://host[:port] with no path, query or fragment"
        ));
    }
    match (url.scheme(), url.host()) {
        ("https", Some(_)) => Ok(()),
        ("http", Some(url::Host::Ipv4(ip))) if ip == std::net::Ipv4Addr::LOCALHOST => Ok(()),
        ("http", Some(url::Host::Ipv6(ip))) if ip == std::net::Ipv6Addr::LOCALHOST => Ok(()),
        ("http", _) => Err(format!(
            "origin {origin:?}: plain http is allowed only for 127.0.0.1 and [::1]"
        )),
        _ => Err(format!("origin {origin:?}: scheme must be https")),
    }
}

fn check_prefixes(what: &str, prefixes: &[String]) -> Result<(), String> {
    for prefix in prefixes {
        PlainPath::parse(prefix).map_err(|e| format!("{what} entry {prefix:?}: {e}"))?;
    }
    Ok(())
}

fn check_methods(methods: &[String]) -> Result<(), String> {
    if methods.is_empty() {
        return Err("methods is empty".to_owned());
    }
    for m in methods {
        if !matches!(
            m.as_str(),
            "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE"
        ) {
            return Err(format!(
                "method {m:?} is not one of GET HEAD POST PUT PATCH DELETE"
            ));
        }
    }
    Ok(())
}

macro_rules! upstream_ref {
    ($ty:ty) => {
        impl $ty {
            pub fn upstream(&self) -> UpstreamRef<'_> {
                UpstreamRef {
                    origin: &self.origin,
                    auth_header: &self.auth_header,
                    auth_prefix: self.auth_prefix.as_deref(),
                    caller_headers: &self.caller_headers,
                    fixed_headers: &self.fixed_headers,
                    max_request_bytes: self.max_request_bytes,
                }
            }
        }
    };
}
upstream_ref!(ProviderCfg);
upstream_ref!(ServiceCfg);

impl<'a> UpstreamRef<'a> {
    /// The literal placed before the secret in the auth header.
    pub fn effective_auth_prefix(&self) -> &'a str {
        match self.auth_prefix {
            Some(prefix) => prefix,
            None if self.auth_header == "authorization" => "Bearer ",
            None => "",
        }
    }

    fn check(&self) -> Result<(), String> {
        check_origin(self.origin)?;
        if !header_name_ok(self.auth_header) {
            return Err(format!(
                "auth_header {:?} is not a usable lowercase header name",
                self.auth_header
            ));
        }
        if !self
            .effective_auth_prefix()
            .bytes()
            .all(|b| (0x20..0x7f).contains(&b))
        {
            return Err("auth_prefix must be printable ASCII".to_owned());
        }
        for name in self.caller_headers {
            if !header_name_ok(name) {
                return Err(format!(
                    "caller_headers entry {name:?} is not a usable lowercase header name"
                ));
            }
            if name == self.auth_header {
                return Err(format!(
                    "caller_headers must not include the auth header {name:?}"
                ));
            }
        }
        for (name, value) in self.fixed_headers {
            if !header_name_ok(name) || name == self.auth_header {
                return Err(format!("fixed_headers key {name:?} is not usable"));
            }
            if !value.bytes().all(|b| (0x20..0x7f).contains(&b)) {
                return Err(format!(
                    "fixed_headers value for {name:?} must be printable ASCII"
                ));
            }
        }
        Ok(())
    }
}

impl Config {
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let config: Config = toml::from_str(text)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let providers = self.providers.as_ref().map_or(0, BTreeMap::len);
        let services = self.services.as_ref().map_or(0, BTreeMap::len);
        if providers + services == 0 {
            return Err(ConfigError::NoTables);
        }
        if let Some(addr) = self.broker.http_listen {
            if !addr.ip().is_loopback() {
                return Err(ConfigError::Broker(format!(
                    "http_listen {addr} is not a loopback address"
                )));
            }
        }
        if self.broker.retention_s == 0 || self.broker.compact_every == 0 {
            return Err(ConfigError::Broker(
                "retention_s and compact_every must be positive".to_owned(),
            ));
        }
        if self.broker.socket_mode & !0o777 != 0 {
            return Err(ConfigError::Broker(format!(
                "socket_mode {:o} is not a permission mode",
                self.broker.socket_mode
            )));
        }

        for (name, row) in self.providers.iter().flatten() {
            let fail = |problem: String| ConfigError::Row {
                table: "providers",
                row: name.clone(),
                problem,
            };
            if !valid_name(name) {
                return Err(fail(
                    "row name must match [A-Za-z0-9][A-Za-z0-9_.-]{0,63}".to_owned(),
                ));
            }
            row.upstream().check().map_err(fail)?;
            check_methods(&row.methods).map_err(fail)?;
            if row.paths.is_empty() {
                return Err(fail("paths is empty".to_owned()));
            }
            check_prefixes("paths", &row.paths).map_err(fail)?;
            if row.models.is_empty() {
                return Err(fail(
                    "models is empty; list every model callers may name".to_owned(),
                ));
            }
            if row.max_output_tokens == 0 {
                return Err(fail("max_output_tokens must be positive".to_owned()));
            }
        }
        for (name, row) in self.services.iter().flatten() {
            let fail = |problem: String| ConfigError::Row {
                table: "services",
                row: name.clone(),
                problem,
            };
            if !valid_name(name) {
                return Err(fail(
                    "row name must match [A-Za-z0-9][A-Za-z0-9_.-]{0,63}".to_owned(),
                ));
            }
            row.upstream().check().map_err(fail)?;
            check_methods(&row.methods).map_err(fail)?;
            if row.buffered_paths.is_empty() && row.stream_paths.is_empty() {
                return Err(fail(
                    "both buffered_paths and stream_paths are empty".to_owned(),
                ));
            }
            check_prefixes("buffered_paths", &row.buffered_paths).map_err(fail)?;
            check_prefixes("stream_paths", &row.stream_paths).map_err(fail)?;
        }
        Ok(())
    }
}

/// The starter config `keygate init` writes.
pub const EXAMPLE: &str = r#"# keygate.toml: rows, policy and listeners. No secrets live here;
# load them with `keygate set <provider|service> <row>` (reads stdin).

[broker]
socket = "keygate.sock"
# http_listen = "127.0.0.1:8787"   # opt-in loopback gateway

[providers.anthropic]
origin = "https://api.anthropic.com"
auth_header = "x-api-key"
paths = ["/v1/messages"]
models = ["claude-fable-5-2", "claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5"]
max_output_tokens = 32000
caller_headers = ["anthropic-version", "anthropic-beta"]
# input_micro_usd_per_mtok = 3000000
# output_micro_usd_per_mtok = 15000000
# per_call_micro_usd = 2000000
# per_day_micro_usd = 200000000
# per_seat_day_micro_usd = 50000000

[services.github]
origin = "https://api.github.com"
methods = ["GET", "POST"]
buffered_paths = ["/repos", "/user"]
fixed_headers = { "x-github-api-version" = "2022-11-28", "user-agent" = "keygate" }
"#;

#[cfg(test)]
mod tests {
    use super::*;

    const PROVIDER: &str = r#"
        [providers.llm]
        origin = "https://api.example.com"
        paths = ["/v1/messages"]
        models = ["m-1"]
        max_output_tokens = 1024
    "#;
    const SERVICE: &str = r#"
        [services.mcp]
        origin = "http://127.0.0.1:9000"
        stream_paths = ["/events"]
        caller_headers = ["last-event-id"]
    "#;

    #[test]
    fn example_config_is_valid() {
        let c = Config::parse(EXAMPLE).unwrap();
        assert_eq!(
            c.providers.unwrap()["anthropic"]
                .upstream()
                .effective_auth_prefix(),
            ""
        );
        assert_eq!(
            c.services.unwrap()["github"]
                .upstream()
                .effective_auth_prefix(),
            "Bearer "
        );
    }

    /// #tooth: each table is optional alone; neither is a startup refusal.
    #[test]
    fn tooth_tables_are_independently_optional() {
        let only_p = Config::parse(PROVIDER).unwrap();
        assert!(only_p.providers.is_some() && only_p.services.is_none());
        let only_s = Config::parse(SERVICE).unwrap();
        assert!(only_s.services.is_some() && only_s.providers.is_none());
        assert!(Config::parse(&format!("{PROVIDER}{SERVICE}")).is_ok());
        assert!(matches!(Config::parse(""), Err(ConfigError::NoTables)));
        assert!(matches!(
            Config::parse("[providers]\n[services]\n"),
            Err(ConfigError::NoTables)
        ));
    }

    #[test]
    fn origins() {
        for ok in [
            "https://api.example.com",
            "https://h:8443",
            "http://127.0.0.1:9",
            "http://[::1]:9",
            "http://127.0.0.1",
        ] {
            check_origin(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
        }
        for bad in [
            "http://example.com",
            "http://localhost:9",
            "http://127.0.0.2:9",
            "https://u:p@example.com",
            "https://example.com/",
            "https://example.com/v1",
            "https://example.com?x=1",
            "ftp://example.com",
            "example.com",
        ] {
            assert!(check_origin(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn bad_rows_are_refused() {
        let cases = [
            PROVIDER.replace("/v1/messages", "/v1/../x"),
            PROVIDER.replace("models = [\"m-1\"]", "models = []"),
            PROVIDER.replace("[providers.llm]", "[providers.\"a/b\"]"),
            format!("{PROVIDER}auth_header = \"Authorization\"\n"),
            format!("{PROVIDER}caller_headers = [\"accept-encoding\"]\n"),
            format!("{PROVIDER}caller_headers = [\"authorization\"]\n"),
            format!("{PROVIDER}surprise = 1\n"),
            SERVICE.replace("stream_paths = [\"/events\"]", ""),
            SERVICE.replace("[services.mcp]", "[services.mcp]\nmethods = [\"CONNECT\"]"),
            format!("[broker]\nhttp_listen = \"0.0.0.0:80\"\n{SERVICE}"),
        ];
        for text in cases {
            assert!(Config::parse(&text).is_err(), "should refuse:\n{text}");
        }
    }
}
