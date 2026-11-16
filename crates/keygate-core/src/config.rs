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

/// Which trust boundary the broker is deployed behind.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Deployment {
    /// Callers run under other uids than the broker and cannot read its
    /// state directory or memory. Operators are listed explicitly, a peer
    /// with the broker's own uid is not served as a caller, and upstreams
    /// must be HTTPS.
    #[default]
    Separated,
    /// Everything may share one uid, and plain-HTTP loopback upstreams are
    /// allowed. For tests and local experiments: any process of that uid
    /// can read the master key, and any local process that binds an
    /// upstream's port first receives that row's secret.
    Development,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct BrokerCfg {
    pub deployment: Deployment,
    /// Unix socket path; relative paths are resolved against the state dir.
    pub socket: PathBuf,
    /// Socket file mode. Widen (e.g. `0o660`) when agents run under other uids.
    pub socket_mode: u32,
    /// Opt-in loopback HTTP gateway. Must be a loopback address.
    pub http_listen: Option<SocketAddr>,
    /// Uids allowed to mint, set, revoke, forget and list. Must be listed
    /// in a `separated` deployment; in `development` an empty list means
    /// the owner of the state directory.
    pub operator_uids: Vec<u32>,
    /// Maximum accepted connections per transport.
    pub max_connections: usize,
    /// How long unused reservations remain Live.
    pub live_ttl_s: u64,
    /// How long terminal tickets (and retained buffered replies) stay replayable.
    pub retention_s: u64,
    /// Rewrite the journal after this many appended records.
    pub compact_every: u64,
    /// Ceiling on requests of unknown outcome remembered so they are never
    /// re-sent. Each is kept until the token that made it expires or its
    /// seat is revoked. At the ceiling, new requests are refused.
    pub max_uncertain_tickets: usize,
    /// Largest buffered upstream reply keygate will hold and journal.
    pub max_response_bytes: usize,
    pub connect_timeout_ms: u64,
    /// Whole-exchange deadline for buffered calls. Streams have none, but
    /// end when their token expires.
    pub buffered_timeout_ms: u64,
    /// Total time a peer gets to deliver one request: the HTTP head, then
    /// the HTTP body; or one Unix frame once its length has arrived.
    pub request_read_timeout_ms: u64,
    /// A Unix connection with no request in progress is closed after this.
    pub idle_timeout_ms: u64,
    /// On SIGTERM/SIGINT, how long in-flight calls get to record their
    /// outcome before the process exits.
    pub shutdown_grace_ms: u64,
}

impl Default for BrokerCfg {
    fn default() -> Self {
        BrokerCfg {
            deployment: Deployment::Separated,
            socket: PathBuf::from("keygate.sock"),
            socket_mode: 0o600,
            http_listen: None,
            operator_uids: Vec::new(),
            max_connections: 256,
            live_ttl_s: 120,
            retention_s: 900,
            compact_every: 1024,
            max_uncertain_tickets: crate::journal::DEFAULT_MAX_UNCERTAIN,
            max_response_bytes: 16 << 20,
            connect_timeout_ms: 10_000,
            buffered_timeout_ms: 600_000,
            request_read_timeout_ms: 30_000,
            idle_timeout_ms: 120_000,
            shutdown_grace_ms: 5_000,
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

/// The request shape a provider row speaks. It fixes the one path on which
/// generation requests are accepted and how the body is checked: the model
/// and the output cap are read from the JSON body, so only APIs that select
/// the model there are supported. APIs that select it in the URL path
/// (Gemini `generateContent`, Bedrock `invoke`, Azure deployment paths)
/// have no dialect; a row cannot be configured for them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Dialect {
    /// Anthropic Messages: `POST /v1/messages`, cap in `max_tokens`.
    AnthropicMessages,
    /// OpenAI Chat Completions: `POST /v1/chat/completions`, cap in
    /// `max_completion_tokens` or `max_tokens`, multiplied by `n`.
    OpenaiChat,
    /// OpenAI Responses: `POST /v1/responses`, cap in `max_output_tokens`.
    OpenaiResponses,
}

impl Dialect {
    pub const fn default_endpoint(self) -> &'static str {
        match self {
            Dialect::AnthropicMessages => "/v1/messages",
            Dialect::OpenaiChat => "/v1/chat/completions",
            Dialect::OpenaiResponses => "/v1/responses",
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Dialect::AnthropicMessages => "anthropic-messages",
            Dialect::OpenaiChat => "openai-chat",
            Dialect::OpenaiResponses => "openai-responses",
        }
    }
}

/// Request features a provider row refuses unless listed in `allow`. Each
/// one makes the real cost of a call depend on something that is not in
/// the request body, so with any of them allowed the reservation is no
/// longer an upper bound and settled spend can pass a cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Allowance {
    /// Input stored at the provider: `previous_response_id`,
    /// `conversation`, stored prompts, item references, file ids,
    /// containers, background runs. Stored objects belong to the upstream
    /// key, not to a seat: any seat on the row can reference another's.
    ServerState,
    /// Images or documents the provider fetches by URL.
    RemoteInput,
    /// Provider-run tools (web search, code execution, MCP connectors),
    /// which add fees and unmetered input.
    ServerTools,
    /// Priority or fast processing tiers billed above the row's prices.
    PremiumTier,
    /// Inline images, documents and audio, whose token cost is not bounded
    /// by their size in bytes.
    InlineMedia,
    /// Output other than text (audio, generated images). It is billed on
    /// its own channel at prices a row does not have, so the output-token
    /// cap and price do not describe it.
    NonTextOutput,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCfg {
    /// `https://host[:port]` (or, in a development deployment only,
    /// `http://127.0.0.1[:port]` / `http://[::1][:port]`).
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
    pub dialect: Dialect,
    /// The exact generation path, when it is not the dialect's default
    /// (compatible gateways that mount the API under a prefix).
    pub endpoint: Option<String>,
    /// Plain-path prefixes callers may `GET`/`HEAD` (model lists and the
    /// like). No other path or method reaches a provider.
    #[serde(default)]
    pub read_paths: Vec<String>,
    /// The JSON body's `model` must be one of these.
    pub models: Vec<String>,
    /// The JSON body must carry an explicit output-token cap; times `n`,
    /// it may not exceed this.
    pub max_output_tokens: u64,
    #[serde(default)]
    pub allow: Vec<Allowance>,
    #[serde(default)]
    pub input_micro_usd_per_mtok: u64,
    #[serde(default)]
    pub output_micro_usd_per_mtok: u64,
    /// Price of a cache-write input token. Defaults to twice the input
    /// price, the highest multiplier in current use.
    pub cache_write_micro_usd_per_mtok: Option<u64>,
    /// Price of a cache-read input token. Defaults to the input price.
    pub cache_read_micro_usd_per_mtok: Option<u64>,
    /// Ceiling on one call's reserved cost.
    pub per_call_micro_usd: Option<u64>,
    /// Ceiling on the row's total reserved cost per UTC day.
    pub per_day_micro_usd: Option<u64>,
    /// Fairness share: ceiling per seat per UTC day.
    pub per_seat_day_micro_usd: Option<u64>,
}

impl ProviderCfg {
    pub fn endpoint(&self) -> &str {
        self.endpoint
            .as_deref()
            .unwrap_or(self.dialect.default_endpoint())
    }

    /// Whether any token costs anything on this row. Without prices every
    /// reservation is zero and no spend cap can bind.
    pub fn is_priced(&self) -> bool {
        self.input_micro_usd_per_mtok > 0 || self.output_micro_usd_per_mtok > 0
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceCfg {
    /// `https://host[:port]` (or, in a development deployment only,
    /// `http://127.0.0.1[:port]` / `http://[::1][:port]`).
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

/// Headers that never come from config or callers and are never shown to
/// callers from an upstream reply: hop-by-hop headers, headers the HTTP
/// stack owns, and `accept-encoding` (a compressed echo would pass the
/// response guard unread).
pub const RESERVED_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "upgrade",
    "te",
    "trailer",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "accept-encoding",
    "expect",
];

/// Request headers that make an origin or a framework in front of it treat
/// the request as a different method, URL or client than the one keygate
/// admitted. Never forwarded, from callers or from `fixed_headers`.
pub const REWRITING_HEADERS: &[&str] = &[
    "x-http-method-override",
    "x-http-method",
    "x-method-override",
    "x-original-url",
    "x-rewrite-url",
    "x-original-uri",
    "forwarded",
    "via",
    "x-real-ip",
];

/// Headers that carry a credential. Only a row's own `auth_header` may be
/// one of these; a caller may not add a second credential beside it.
pub const CREDENTIAL_HEADERS: &[&str] = &[
    "authorization",
    "x-api-key",
    "api-key",
    "x-goog-api-key",
    "x-auth-token",
];

/// Headers that choose who is billed. The operator may fix them; a caller
/// may not send them.
pub const OPERATOR_ONLY_HEADERS: &[&str] = &[
    "openai-organization",
    "openai-project",
    "x-goog-user-project",
];

fn header_syntax_ok(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'))
}

/// A header name neither callers nor config may set.
pub fn header_is_reserved(name: &str) -> bool {
    RESERVED_HEADERS.contains(&name)
        || REWRITING_HEADERS.contains(&name)
        || name.starts_with("x-forwarded-")
        || name.starts_with("x-keygate-")
}

/// May the operator list `name` in `caller_headers`?
pub fn caller_header_ok(name: &str) -> bool {
    header_syntax_ok(name)
        && !header_is_reserved(name)
        && !CREDENTIAL_HEADERS.contains(&name)
        && !OPERATOR_ONLY_HEADERS.contains(&name)
}

/// May the operator set `name` in `fixed_headers`?
pub fn fixed_header_ok(name: &str) -> bool {
    header_syntax_ok(name) && !header_is_reserved(name) && !CREDENTIAL_HEADERS.contains(&name)
}

/// Validate an origin string: scheme, host and optional port, nothing else.
/// Plain HTTP is accepted only for loopback and only in a development
/// deployment: loopback has no server identity, so whichever local process
/// binds the port first is sent the row's secret.
pub fn check_origin(origin: &str, deployment: Deployment) -> Result<(), String> {
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
    let loopback = match url.host() {
        Some(url::Host::Ipv4(ip)) => ip == std::net::Ipv4Addr::LOCALHOST,
        Some(url::Host::Ipv6(ip)) => ip == std::net::Ipv6Addr::LOCALHOST,
        _ => false,
    };
    match (url.scheme(), url.host()) {
        ("https", Some(_)) => Ok(()),
        ("http", _) if loopback && deployment == Deployment::Development => Ok(()),
        ("http", _) if loopback => Err(format!(
            "origin {origin:?}: plain-http loopback is a development transport (any local process \
             that binds the port receives the secret); use https, or set [broker] deployment = \
             \"development\""
        )),
        ("http", _) => Err(format!(
            "origin {origin:?}: plain http is never allowed off loopback"
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

    fn check(&self, deployment: Deployment) -> Result<(), String> {
        check_origin(self.origin, deployment)?;
        if !header_syntax_ok(self.auth_header) || header_is_reserved(self.auth_header) {
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
        if self.max_request_bytes == 0 || self.max_request_bytes > 32 << 20 {
            return Err("max_request_bytes must be 1..=33554432".to_owned());
        }
        for name in self.caller_headers {
            if !caller_header_ok(name) {
                return Err(format!(
                    "caller_headers entry {name:?} is not allowed: it is malformed, hop-by-hop, \
                     rewrites the request, carries a credential, or selects who is billed"
                ));
            }
            if name == self.auth_header {
                return Err(format!(
                    "caller_headers must not include the auth header {name:?}"
                ));
            }
        }
        for (name, value) in self.fixed_headers {
            if !fixed_header_ok(name) || name == self.auth_header {
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
        let broker = &self.broker;
        if let Some(addr) = broker.http_listen {
            if !addr.ip().is_loopback() {
                return Err(ConfigError::Broker(format!(
                    "http_listen {addr} is not a loopback address"
                )));
            }
        }
        if broker.deployment == Deployment::Separated && broker.operator_uids.is_empty() {
            return Err(ConfigError::Broker(
                "operator_uids is empty. A separated deployment names its operators explicitly; \
                 list their uids, or set deployment = \"development\" to let the state \
                 directory's owner operate a single-uid test broker"
                    .to_owned(),
            ));
        }
        if broker.retention_s == 0
            || broker.live_ttl_s == 0
            || broker.compact_every == 0
            || broker.max_connections == 0
            || broker.max_connections > 1_000_000
            || broker.max_uncertain_tickets == 0
        {
            return Err(ConfigError::Broker(
                "retention_s, live_ttl_s, compact_every and max_uncertain_tickets must be positive; max_connections must be 1..=1000000".to_owned(),
            ));
        }
        if broker.request_read_timeout_ms == 0
            || broker.idle_timeout_ms == 0
            || broker.connect_timeout_ms == 0
            || broker.buffered_timeout_ms == 0
        {
            return Err(ConfigError::Broker(
                "request_read_timeout_ms, idle_timeout_ms, connect_timeout_ms and buffered_timeout_ms must be positive: every read has a deadline".to_owned(),
            ));
        }
        if broker.socket_mode & !0o777 != 0 {
            return Err(ConfigError::Broker(format!(
                "socket_mode {:o} is not a permission mode",
                broker.socket_mode
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
            row.upstream().check(broker.deployment).map_err(fail)?;
            PlainPath::parse(row.endpoint())
                .map_err(|e| fail(format!("endpoint {:?}: {e}", row.endpoint())))?;
            check_prefixes("read_paths", &row.read_paths).map_err(fail)?;
            if row.models.is_empty() {
                return Err(fail(
                    "models is empty; list every model callers may name".to_owned(),
                ));
            }
            if row.max_output_tokens == 0 {
                return Err(fail("max_output_tokens must be positive".to_owned()));
            }
            let capped = row.per_call_micro_usd.is_some()
                || row.per_day_micro_usd.is_some()
                || row.per_seat_day_micro_usd.is_some();
            if capped && !row.is_priced() {
                return Err(fail(
                    "a spend cap is set but both token prices are 0, so every reservation would \
                     be 0 and the cap could never bind; set input_micro_usd_per_mtok and \
                     output_micro_usd_per_mtok"
                        .to_owned(),
                ));
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
            row.upstream().check(broker.deployment).map_err(fail)?;
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

/// The starter config `keygate init` writes, with the initializing user as
/// the operator.
pub fn example(operator_uid: u32) -> String {
    EXAMPLE.replace("{operator_uid}", &operator_uid.to_string())
}

const EXAMPLE: &str = r#"# keygate.toml: rows, policy and listeners. No secrets live here;
# load them with `keygate set <provider|service> <row>` (reads stdin).

[broker]
# "separated": callers run under other uids than the broker and cannot read
# this directory. "development": single-uid experiments, never shared hosts.
deployment = "separated"
# Who may mint, set, revoke and forget. The broker's own uid may be listed;
# a peer with the broker's uid is never served as a caller.
operator_uids = [{operator_uid}]
# Callers under other uids need a socket they can reach, for example:
# socket = "/run/keygate/keygate.sock"
# socket_mode = 0o660
socket = "keygate.sock"
# http_listen = "127.0.0.1:8787"   # opt-in loopback gateway (bearer token only)

[providers.anthropic]
origin = "https://api.anthropic.com"
auth_header = "x-api-key"
dialect = "anthropic-messages"
models = ["claude-fable-5-2", "claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5"]
max_output_tokens = 32000
caller_headers = ["anthropic-version", "anthropic-beta"]
# Refused unless listed: "server-state", "remote-input", "server-tools",
# "premium-tier", "inline-media", "non-text-output". Each makes cost depend
# on more than the request body and the row's two token prices.
# allow = ["inline-media"]
# Spend caps need prices (micro-USD per million tokens):
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

    const DEV: &str = "[broker]\ndeployment = \"development\"\n";
    const PROVIDER: &str = r#"
        [providers.llm]
        origin = "https://api.example.com"
        dialect = "anthropic-messages"
        models = ["m-1"]
        max_output_tokens = 1024
    "#;
    const SERVICE: &str = r#"
        [services.mcp]
        origin = "https://mcp.example.com"
        stream_paths = ["/events"]
        caller_headers = ["last-event-id"]
    "#;

    fn dev(rows: &str) -> Result<Config, ConfigError> {
        Config::parse(&format!("{DEV}{rows}"))
    }

    #[test]
    fn example_config_is_valid_and_separated() {
        let c = Config::parse(&example(1234)).unwrap();
        assert_eq!(c.broker.deployment, Deployment::Separated);
        assert_eq!(c.broker.operator_uids, vec![1234]);
        let anthropic = &c.providers.as_ref().unwrap()["anthropic"];
        assert_eq!(anthropic.upstream().effective_auth_prefix(), "");
        assert_eq!(anthropic.endpoint(), "/v1/messages");
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
        let only_p = dev(PROVIDER).unwrap();
        assert!(only_p.providers.is_some() && only_p.services.is_none());
        let only_s = dev(SERVICE).unwrap();
        assert!(only_s.services.is_some() && only_s.providers.is_none());
        assert!(dev(&format!("{PROVIDER}{SERVICE}")).is_ok());
        assert!(matches!(Config::parse(""), Err(ConfigError::NoTables)));
        assert!(matches!(
            Config::parse("[providers]\n[services]\n"),
            Err(ConfigError::NoTables)
        ));
    }

    /// #tooth: the default deployment refuses the ambiguous setups. No
    /// implicit operator, and no plain-HTTP loopback upstream.
    #[test]
    fn tooth_separated_deployment_refuses_implicit_operator_and_loopback_http() {
        let err = Config::parse(SERVICE).unwrap_err();
        assert!(err.to_string().contains("operator_uids is empty"), "{err}");
        let separated = format!("[broker]\noperator_uids = [990]\n{SERVICE}");
        assert_eq!(
            Config::parse(&separated).unwrap().broker.deployment,
            Deployment::Separated
        );

        let loopback = separated.replace("https://mcp.example.com", "http://127.0.0.1:9000");
        let err = Config::parse(&loopback).unwrap_err();
        assert!(err.to_string().contains("development transport"), "{err}");
        // The same row is fine once the operator says this is development.
        let dev_loopback =
            format!("{DEV}{SERVICE}").replace("https://mcp.example.com", "http://127.0.0.1:9000");
        assert!(Config::parse(&dev_loopback).is_ok());
        assert!(
            Config::parse(&format!("[broker]\ndeployment = \"production\"\n{SERVICE}")).is_err()
        );
    }

    #[test]
    fn origins() {
        for ok in [
            "https://api.example.com",
            "https://h:8443",
            "https://127.0.0.1:8443",
        ] {
            check_origin(ok, Deployment::Separated).unwrap_or_else(|e| panic!("{ok}: {e}"));
        }
        for dev_only in ["http://127.0.0.1:9", "http://[::1]:9", "http://127.0.0.1"] {
            check_origin(dev_only, Deployment::Development)
                .unwrap_or_else(|e| panic!("{dev_only}: {e}"));
            assert!(
                check_origin(dev_only, Deployment::Separated).is_err(),
                "{dev_only}"
            );
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
            assert!(check_origin(bad, Deployment::Development).is_err(), "{bad}");
        }
    }

    #[test]
    fn bad_rows_are_refused() {
        let cases = [
            format!("{PROVIDER}endpoint = \"/v1/../x\"\n"),
            format!("{PROVIDER}read_paths = [\"/v1//models\"]\n"),
            PROVIDER.replace("models = [\"m-1\"]", "models = []"),
            PROVIDER.replace("[providers.llm]", "[providers.\"a/b\"]"),
            PROVIDER.replace("anthropic-messages", "gemini-generate-content"),
            PROVIDER.replace("dialect = \"anthropic-messages\"", ""),
            format!("{PROVIDER}paths = [\"/v1beta/models\"]\n"),
            format!("{PROVIDER}auth_header = \"Authorization\"\n"),
            format!("{PROVIDER}caller_headers = [\"accept-encoding\"]\n"),
            format!("{PROVIDER}allow = [\"everything\"]\n"),
            format!("{PROVIDER}surprise = 1\n"),
            format!("{PROVIDER}max_request_bytes = 0\n"),
            SERVICE.replace("stream_paths = [\"/events\"]", ""),
            SERVICE.replace("[services.mcp]", "[services.mcp]\nmethods = [\"CONNECT\"]"),
        ];
        for text in cases {
            assert!(dev(&text).is_err(), "should refuse:\n{text}");
        }
        assert!(Config::parse(&format!(
            "[broker]\ndeployment = \"development\"\nhttp_listen = \"0.0.0.0:80\"\n{SERVICE}"
        ))
        .is_err());
        let ok = dev(&format!("{PROVIDER}endpoint = \"/api/v1/messages\"\nread_paths = [\"/v1/models\"]\nallow = [\"server-state\", \"inline-media\"]\n")).unwrap();
        assert_eq!(ok.providers.unwrap()["llm"].endpoint(), "/api/v1/messages");
    }

    /// #tooth: headers that smuggle a method, a URL, a second credential or
    /// a billing identity cannot be opened to callers, and the rewriting
    /// ones cannot be fixed by config either.
    #[test]
    fn tooth_dangerous_headers_cannot_be_configured() {
        for name in [
            "x-http-method-override",
            "x-http-method",
            "x-method-override",
            "x-original-url",
            "x-rewrite-url",
            "forwarded",
            "x-forwarded-for",
            "x-forwarded-host",
            "x-keygate-ticket",
            "authorization",
            "x-api-key",
            "x-goog-api-key",
            "openai-organization",
            "openai-project",
            "connection",
            "Upper-Case",
        ] {
            assert!(
                dev(&format!("{SERVICE}caller_headers = [\"{name}\"]\n")
                    .replace("caller_headers = [\"last-event-id\"]\n", ""))
                .is_err(),
                "caller {name}"
            );
        }
        for name in [
            "x-http-method-override",
            "x-original-url",
            "x-forwarded-for",
            "authorization",
            "x-keygate-replayed",
        ] {
            assert!(
                dev(&format!(
                    "{SERVICE}fixed_headers = {{ \"{name}\" = \"v\" }}\n"
                ))
                .is_err(),
                "fixed {name}"
            );
        }
        // Billing identity is the operator's to fix, and ordinary headers pass.
        assert!(dev(&format!("{SERVICE}fixed_headers = {{ \"openai-organization\" = \"org-1\", \"user-agent\" = \"k\" }}\n")).is_ok());
        assert!(dev(&SERVICE.replace("last-event-id", "idempotency-key")).is_ok());
    }

    /// #tooth: a spend cap on a row with no prices can never bind, so it is
    /// refused instead of being silently void.
    #[test]
    fn tooth_caps_without_prices_are_refused() {
        for cap in [
            "per_call_micro_usd",
            "per_day_micro_usd",
            "per_seat_day_micro_usd",
        ] {
            let err = dev(&format!("{PROVIDER}{cap} = 1000\n")).unwrap_err();
            assert!(err.to_string().contains("could never bind"), "{err}");
            assert!(dev(&format!(
                "{PROVIDER}{cap} = 1000\noutput_micro_usd_per_mtok = 5\n"
            ))
            .is_ok());
        }
        assert!(!dev(PROVIDER).unwrap().providers.unwrap()["llm"].is_priced());
    }

    /// #tooth: connection admission, Live expiry and every read have finite bounds.
    #[test]
    fn tooth_broker_resource_defaults_and_bounds() {
        let cfg = dev(SERVICE).unwrap();
        assert_eq!(cfg.broker.max_connections, 256);
        assert_eq!(cfg.broker.live_ttl_s, 120);
        assert_eq!(cfg.broker.request_read_timeout_ms, 30_000);
        for field in [
            "max_connections = 0",
            "max_connections = 1000001",
            "live_ttl_s = 0",
            "request_read_timeout_ms = 0",
            "idle_timeout_ms = 0",
        ] {
            assert!(
                Config::parse(&format!("{DEV}{field}\n{SERVICE}")).is_err(),
                "{field}"
            );
        }
    }
}
