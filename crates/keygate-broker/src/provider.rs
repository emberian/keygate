//! Provider policy: what a metered LLM request may ask for and what it is
//! reserved and settled at.
//!
//! A provider row speaks one [`Dialect`]. Generation requests are accepted
//! only as `POST` to that dialect's single endpoint, where the model and the
//! output cap are in the JSON body and can be checked. The body is parsed
//! strictly (a duplicated key at any depth is refused, because keygate and
//! the upstream could disagree about which occurrence wins) and inspected
//! for features whose cost is not determined by the body.
//!
//! # Reservation
//!
//! `reserve = (body_bytes + 4096) tokens at the dearest input price
//!          + output_cap * max(n, best_of) tokens at the output price`
//!
//! A token is at least one byte of the request, so for a text-only request
//! this is an upper bound on what the call can cost at the row's prices,
//! given at most [`PROMPT_OVERHEAD_TOKENS`] of provider-added prompt. It is
//! deliberately loose; complete replies settle to reported usage. It is
//! *not* a bound for requests using a feature listed in the row's `allow`.

use crate::vault::{Prices, ProviderRow};
use keygate_core::config::{Allowance, Dialect};
use keygate_core::journal::{self, CallKind, Charge};
use keygate_core::path::PlainPath;
use keygate_core::proto::{Code, Refusal};
use serde::de::{Deserializer, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::{Map, Value};

/// Input tokens a provider may add that are not in the request body
/// (tool-use system prompts, message framing).
pub const PROMPT_OVERHEAD_TOKENS: u64 = 4096;
/// Largest accepted `n` / `best_of`.
pub const MAX_CHOICES: u64 = 16;

#[derive(Default)]
pub(crate) struct ProviderAdmission {
    pub model: Option<String>,
    pub reserve_micro_usd: u64,
    pub charges: Vec<Charge>,
    /// Present when the reply's usage should settle the reservation.
    pub prices: Option<Prices>,
}

/// A JSON value parsed with duplicate object keys refused at every depth.
struct Strict(Value);

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = Strict;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON value")
            }
            fn visit_bool<E>(self, v: bool) -> Result<Strict, E> {
                Ok(Strict(Value::Bool(v)))
            }
            fn visit_i64<E>(self, v: i64) -> Result<Strict, E> {
                Ok(Strict(Value::from(v)))
            }
            fn visit_u64<E>(self, v: u64) -> Result<Strict, E> {
                Ok(Strict(Value::from(v)))
            }
            fn visit_f64<E>(self, v: f64) -> Result<Strict, E> {
                Ok(Strict(Value::from(v)))
            }
            fn visit_str<E>(self, v: &str) -> Result<Strict, E> {
                Ok(Strict(Value::String(v.to_owned())))
            }
            fn visit_string<E>(self, v: String) -> Result<Strict, E> {
                Ok(Strict(Value::String(v)))
            }
            fn visit_unit<E>(self) -> Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Strict, A::Error> {
                let mut items = Vec::new();
                while let Some(Strict(item)) = seq.next_element()? {
                    items.push(item);
                }
                Ok(Strict(Value::Array(items)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Strict, A::Error> {
                let mut object = Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    let Strict(value) = map.next_value()?;
                    if object.contains_key(&key) {
                        return Err(serde::de::Error::custom(format!("duplicate key {key:?}")));
                    }
                    object.insert(key, value);
                }
                Ok(Strict(Value::Object(object)))
            }
        }
        deserializer.deserialize_any(StrictVisitor)
    }
}

fn parse_body(body: &[u8]) -> Result<Map<String, Value>, Refusal> {
    match serde_json::from_slice::<Strict>(body) {
        Ok(Strict(Value::Object(top))) => Ok(top),
        Ok(_) => Err(Refusal::new(
            Code::BadRequest,
            "provider request body must be a JSON object",
        )),
        Err(e) => Err(Refusal::new(
            Code::BadRequest,
            format!("provider request body must be a JSON object: {e}"),
        )),
    }
}

/// Does this body ask for a streamed reply? Unparseable bodies are not
/// streams; they are refused at admission either way.
pub(crate) fn stream_requested(body: &[u8]) -> bool {
    parse_body(body).is_ok_and(|top| top.get("stream") == Some(&Value::Bool(true)))
}

/// A key that is absent or `null` is `None`.
fn present<'a>(top: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    top.get(key).filter(|v| !v.is_null())
}

fn uint(top: &Map<String, Value>, key: &str) -> Result<Option<u64>, Refusal> {
    match present(top, key) {
        None => Ok(None),
        Some(value) => value.as_u64().map(Some).ok_or_else(|| {
            Refusal::new(
                Code::BadRequest,
                format!("{key:?} must be a non-negative integer"),
            )
        }),
    }
}

/// One request feature that needs a row allowance.
type Feature = (Allowance, &'static str);

fn is_remote(url: &str) -> bool {
    let lower = url.trim_start().to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

/// Classify a content part by its `type`, wherever it sits in the body.
/// Matching by shape at any depth can refuse a request whose tool input
/// merely resembles a content part; it cannot miss a part in a position
/// this code does not know about.
fn content_part(dialect: Dialect, part: &Map<String, Value>, found: &mut Vec<Feature>) {
    // A Chat Completions assistant message can point at audio the provider
    // stored from an earlier turn: `{"role":"assistant","audio":{"id":..}}`.
    // It has no `type`, so it is recognised by shape.
    if dialect == Dialect::OpenaiChat
        && part.get("role").and_then(Value::as_str) == Some("assistant")
        && part
            .get("audio")
            .and_then(Value::as_object)
            .is_some_and(|audio| present(audio, "id").is_some())
    {
        found.push((Allowance::ServerState, "a stored audio id"));
    }
    let Some(kind) = part.get("type").and_then(Value::as_str) else {
        return;
    };
    let text = |key: &str| part.get(key).and_then(Value::as_str);
    let has = |key: &str| present(part, key).is_some();
    match (dialect, kind) {
        (Dialect::AnthropicMessages, "image" | "document") => {
            match part
                .get("source")
                .and_then(|s| s.get("type"))
                .and_then(Value::as_str)
            {
                Some("url") => found.push((Allowance::RemoteInput, "a URL image/document source")),
                Some("file") => found.push((Allowance::ServerState, "a Files API source")),
                Some("base64") => found.push((Allowance::InlineMedia, "an inline image/document")),
                _ => {}
            }
        }
        (Dialect::AnthropicMessages, "container_upload") => {
            found.push((Allowance::ServerState, "a container upload"))
        }
        (Dialect::OpenaiChat, "image_url") => {
            let url = part
                .get("image_url")
                .and_then(|u| u.as_str().or_else(|| u.get("url").and_then(Value::as_str)));
            match url {
                Some(url) if is_remote(url) => {
                    found.push((Allowance::RemoteInput, "a remote image_url"))
                }
                _ => found.push((Allowance::InlineMedia, "an inline image")),
            }
        }
        (Dialect::OpenaiChat, "file") => {
            let file = part.get("file").and_then(Value::as_object);
            if file.is_some_and(|f| present(f, "file_id").is_some()) {
                found.push((Allowance::ServerState, "a file_id"));
            } else {
                found.push((Allowance::InlineMedia, "an inline file"));
            }
        }
        (Dialect::OpenaiChat | Dialect::OpenaiResponses, "input_audio") => {
            found.push((Allowance::InlineMedia, "inline audio"))
        }
        (Dialect::OpenaiResponses, "input_image" | "input_file") => {
            if has("file_id") {
                found.push((Allowance::ServerState, "a file_id"));
            }
            match text("image_url").or(text("file_url")) {
                Some(url) if is_remote(url) => {
                    found.push((Allowance::RemoteInput, "a remote image/file URL"))
                }
                Some(_) => found.push((Allowance::InlineMedia, "an inline image")),
                None => {}
            }
            if has("file_data") {
                found.push((Allowance::InlineMedia, "an inline file"));
            }
        }
        (Dialect::OpenaiResponses, "item_reference") => {
            found.push((Allowance::ServerState, "an item_reference"))
        }
        _ => {}
    }
}

fn walk(dialect: Dialect, value: &Value, found: &mut Vec<Feature>) {
    match value {
        Value::Object(object) => {
            content_part(dialect, object, found);
            for child in object.values() {
                walk(dialect, child, found);
            }
        }
        Value::Array(items) => {
            for item in items {
                walk(dialect, item, found);
            }
        }
        _ => {}
    }
}

/// Tools the provider itself runs. Anything that is not a caller-executed
/// tool counts, so a tool type this code has never heard of is refused
/// rather than waved through.
fn server_tools(dialect: Dialect, top: &Map<String, Value>, found: &mut Vec<Feature>) {
    let client_side = |kind: &str| match dialect {
        Dialect::AnthropicMessages => {
            kind == "custom"
                || ["bash_", "text_editor_", "computer_", "memory_"]
                    .iter()
                    .any(|prefix| kind.starts_with(prefix))
        }
        Dialect::OpenaiChat | Dialect::OpenaiResponses => matches!(kind, "function" | "custom"),
    };
    let tools = top.get("tools").and_then(Value::as_array);
    for tool in tools.into_iter().flatten() {
        if let Some(kind) = tool.get("type").and_then(Value::as_str) {
            if !client_side(kind) {
                found.push((Allowance::ServerTools, "a provider-run tool"));
                return;
            }
        }
    }
    let nonempty =
        |key: &str| present(top, key).is_some_and(|v| !v.as_array().is_some_and(|a| a.is_empty()));
    if dialect == Dialect::AnthropicMessages && nonempty("mcp_servers") {
        found.push((Allowance::ServerTools, "mcp_servers"));
    }
    if dialect == Dialect::OpenaiChat && nonempty("web_search_options") {
        found.push((Allowance::ServerTools, "web_search_options"));
    }
}

fn top_level_features(dialect: Dialect, top: &Map<String, Value>, found: &mut Vec<Feature>) {
    let state_keys: &[&'static str] = match dialect {
        Dialect::AnthropicMessages => &["container"],
        Dialect::OpenaiChat => &[],
        Dialect::OpenaiResponses => &["previous_response_id", "conversation", "prompt"],
    };
    for &key in state_keys {
        if present(top, key).is_some() {
            found.push((Allowance::ServerState, key));
        }
    }
    if dialect == Dialect::OpenaiResponses && top.get("background") == Some(&Value::Bool(true)) {
        found.push((Allowance::ServerState, "background"));
    }
    // Non-text output. Chat Completions asks for it with `modalities`
    // and configures it with `audio`; the Responses and Anthropic dialects
    // have no such body field (image generation there is a provider-run
    // tool, caught above). Anything but text in `modalities`, in any
    // dialect, is refused rather than guessed at.
    let non_text = match present(top, "modalities") {
        None => false,
        Some(Value::Array(wanted)) => wanted.iter().any(|m| m.as_str() != Some("text")),
        Some(_) => true,
    };
    if non_text {
        found.push((Allowance::NonTextOutput, "non-text output modalities"));
    }
    if dialect == Dialect::OpenaiChat && present(top, "audio").is_some() {
        found.push((Allowance::NonTextOutput, "audio output"));
    }
    if top.get("service_tier").and_then(Value::as_str) == Some("priority") {
        found.push((Allowance::PremiumTier, "service_tier \"priority\""));
    }
    if top.get("speed").and_then(Value::as_str) == Some("fast") {
        found.push((Allowance::PremiumTier, "speed \"fast\""));
    }
}

struct Inspected {
    model: String,
    stream: bool,
    /// Output tokens the request can produce in total.
    output_cap: u64,
}

fn inspect(row: &ProviderRow, top: &Map<String, Value>) -> Result<Inspected, Refusal> {
    let name = &row.upstream.name;
    let dialect = row.dialect;
    let model = match present(top, "model") {
        Some(Value::String(model)) => model.clone(),
        Some(_) => {
            return Err(Refusal::new(
                Code::ModelRefused,
                "\"model\" must be a string",
            ))
        }
        None => {
            return Err(Refusal::new(
                Code::ModelRefused,
                "request body names no model",
            ))
        }
    };
    if !row.models.contains(&model) {
        return Err(Refusal::new(
            Code::ModelRefused,
            format!("model {model:?} is not allowed on provider/{name}"),
        ));
    }
    let stream = match present(top, "stream") {
        None => false,
        Some(Value::Bool(stream)) => *stream,
        Some(_) => {
            return Err(Refusal::new(
                Code::BadRequest,
                "\"stream\" must be a boolean",
            ))
        }
    };

    let cap_keys: &[&str] = match dialect {
        Dialect::AnthropicMessages => &["max_tokens"],
        Dialect::OpenaiChat => &["max_completion_tokens", "max_tokens"],
        Dialect::OpenaiResponses => &["max_output_tokens"],
    };
    let mut cap = None;
    for key in cap_keys {
        cap = cap.max(uint(top, key)?);
    }
    let Some(cap) = cap else {
        return Err(Refusal::new(
            Code::TokenCapRefused,
            format!(
                "request must set {} (at most {}); an uncapped call cannot be budgeted",
                cap_keys.join(" or "),
                row.max_output_tokens
            ),
        ));
    };
    // `n` and `best_of` both multiply what is generated and billed.
    let choices = uint(top, "n")?
        .unwrap_or(1)
        .max(uint(top, "best_of")?.unwrap_or(1));
    if !(1..=MAX_CHOICES).contains(&choices)
        || uint(top, "n")? == Some(0)
        || uint(top, "best_of")? == Some(0)
    {
        return Err(Refusal::new(
            Code::TokenCapRefused,
            format!("n and best_of must be between 1 and {MAX_CHOICES}"),
        ));
    }
    let output_cap = cap
        .checked_mul(choices)
        .ok_or_else(|| Refusal::new(Code::TokenCapRefused, "output token cap times n overflows"))?;
    if output_cap > row.max_output_tokens {
        return Err(Refusal::new(
            Code::TokenCapRefused,
            format!(
                "aggregate output token cap {output_cap} exceeds provider/{name}'s limit {}",
                row.max_output_tokens
            ),
        ));
    }

    let mut found = Vec::new();
    top_level_features(dialect, top, &mut found);
    server_tools(dialect, top, &mut found);
    for value in top.values() {
        walk(dialect, value, &mut found);
    }
    if let Some((needs, what)) = found.into_iter().find(|(needs, _)| !row.allows(*needs)) {
        let flag = serde_json::to_value(needs)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default();
        return Err(Refusal::new(
            Code::Denied,
            format!(
                "request uses {what}, whose cost is not determined by the request body; \
                 provider/{name} refuses it unless its `allow` lists \"{flag}\""
            ),
        ));
    }
    Ok(Inspected {
        model,
        stream,
        output_cap,
    })
}

/// Micro-USD for token counts at per-million-token prices, rounded up and
/// saturating.
pub(crate) fn micro_usd(parts: &[(u64, u64)]) -> u64 {
    let total = parts.iter().fold(0u128, |sum, &(tokens, price)| {
        sum.saturating_add(u128::from(tokens) * u128::from(price))
    });
    u64::try_from(total.div_ceil(1_000_000)).unwrap_or(u64::MAX)
}

pub(crate) fn admit_provider(
    row: &ProviderRow,
    seat: &str,
    method: &reqwest::Method,
    path: &PlainPath,
    body: &[u8],
    kind: CallKind,
    now: u64,
) -> Result<ProviderAdmission, Refusal> {
    let name = &row.upstream.name;
    if *method == reqwest::Method::GET || *method == reqwest::Method::HEAD {
        if kind == CallKind::Stream {
            return Err(Refusal::new(
                Code::BadRequest,
                "provider streams are POST requests with \"stream\": true",
            ));
        }
        if !path.under_any(&row.read_paths) {
            return Err(Refusal::new(
                Code::PathRefused,
                format!("{path} is not under provider/{name}'s read_paths"),
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
    if *method != reqwest::Method::POST {
        return Err(Refusal::new(
            Code::MethodRefused,
            format!("provider/{name} does not allow {method}"),
        ));
    }
    // One exact path. The model is checked in the body, so a path that
    // selects the model (or anything else) is never reachable.
    if *path != row.endpoint {
        return Err(Refusal::new(
            Code::PathRefused,
            format!(
                "provider/{name} speaks {} and accepts POST only at {}; {path} is refused",
                row.dialect.name(),
                row.endpoint
            ),
        ));
    }

    let top = parse_body(body)?;
    let inspected = inspect(row, &top)?;
    match (kind, inspected.stream) {
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

    let input_bound = (body.len() as u64).saturating_add(PROMPT_OVERHEAD_TOKENS);
    let reserve = micro_usd(&[
        (input_bound, row.prices.worst_input()),
        (inspected.output_cap, row.prices.output),
    ]);
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
        model: Some(inspected.model),
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
        prices: (reserve > 0).then_some(row.prices),
    })
}

/// Usage as both API families report it. OpenAI's `prompt_tokens` /
/// `input_tokens` already include cached tokens (billed here at the full
/// input price, which is never below the real one). Anthropic's two cache
/// counters are additional to `input_tokens` and have their own prices.
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
    fn cost(&self, prices: Prices) -> Option<u64> {
        Some(micro_usd(&[
            (self.input_tokens?, prices.input),
            (self.cache_creation_input_tokens, prices.cache_write),
            (self.cache_read_input_tokens, prices.cache_read),
            (self.output_tokens?, prices.output),
        ]))
    }
}

pub(crate) fn metered_cost(body: &[u8], prices: Prices) -> Option<u64> {
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
pub(crate) struct UsageSniffer {
    line: zeroize::Zeroizing<Vec<u8>>,
    data: zeroize::Zeroizing<Vec<u8>>,
    after_cr: bool,
    invalid: bool,
    input: Option<u64>,
    cache_write: u64,
    cache_read: u64,
    output: Option<u64>,
}

impl UsageSniffer {
    const MAX_EVENT: usize = 64 * 1024;

    pub(crate) fn push(&mut self, bytes: &[u8]) {
        use zeroize::Zeroize;
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
        use zeroize::Zeroize;
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
        let Ok(event) = serde_json::from_slice::<Value>(&self.data) else {
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
        if let Some(input) = usage.input_tokens {
            self.input = Some(self.input.unwrap_or(0).max(input));
        }
        self.cache_write = self.cache_write.max(usage.cache_creation_input_tokens);
        self.cache_read = self.cache_read.max(usage.cache_read_input_tokens);
        // message_start's output count is provisional, not final usage.
        if kind != Some("message_start") {
            if let Some(output) = usage.output_tokens {
                self.output = Some(self.output.unwrap_or(0).max(output));
            }
        }
    }

    pub(crate) fn cost(self, prices: Prices) -> Option<u64> {
        if self.invalid || !self.line.is_empty() || !self.data.is_empty() {
            return None;
        }
        Some(micro_usd(&[
            (self.input?, prices.input),
            (self.cache_write, prices.cache_write),
            (self.cache_read, prices.cache_read),
            (self.output?, prices.output),
        ]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flat(input: u64, output: u64) -> Prices {
        Prices {
            input,
            output,
            cache_write: input,
            cache_read: input,
        }
    }

    #[test]
    fn strict_parse_refuses_duplicate_keys_at_any_depth() {
        assert!(parse_body(br#"{"model":"m","messages":[{"role":"user","content":"x"}]}"#).is_ok());
        for bad in [
            r#"{"model":"cheap","model":"dear"}"#,
            r#"{"max_tokens":1,"max_tokens":999999}"#,
            r#"{"messages":[{"content":[{"type":"text","type":"image"}]}]}"#,
            r#"{"a":{"b":{"c":1,"c":2}}}"#,
            r#"["model"]"#,
            r#""model""#,
            "not json",
            r#"{"model":"m"} trailing"#,
        ] {
            assert!(parse_body(bad.as_bytes()).is_err(), "{bad}");
        }
        assert!(stream_requested(br#"{"stream":true}"#));
        for not_stream in [
            r#"{"stream":false}"#,
            r#"{"stream":null}"#,
            r#"{}"#,
            r#"{"stream":true,"stream":true}"#,
            "x",
        ] {
            assert!(!stream_requested(not_stream.as_bytes()), "{not_stream}");
        }
    }

    #[test]
    fn pricing_rounds_up_and_does_not_overflow() {
        assert_eq!(micro_usd(&[(1, 1)]), 1);
        assert_eq!(
            micro_usd(&[(1_000_000, 3_000_000), (1_000_000, 15_000_000)]),
            18_000_000
        );
        assert_eq!(micro_usd(&[(0, 5), (0, 5)]), 0);
        assert_eq!(micro_usd(&[(u64::MAX, u64::MAX); 4]), u64::MAX);
    }

    #[test]
    fn usage_is_read_in_both_dialects_with_cache_prices() {
        let prices = flat(1_000_000, 2_000_000);
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
        // Cache writes and reads are billed at their own prices.
        let cached = Prices {
            input: 1_000_000,
            output: 0,
            cache_write: 2_000_000,
            cache_read: 100_000,
        };
        assert_eq!(
            metered_cost(
                br#"{"usage":{"input_tokens":10,"cache_creation_input_tokens":100,"cache_read_input_tokens":1000,"output_tokens":0}}"#,
                cached
            ),
            Some(10 + 200 + 100)
        );
        assert_eq!(metered_cost(br#"{"usage":{"input_tokens":1,"cache_read_input_tokens":18446744073709551615,"cache_creation_input_tokens":1,"output_tokens":0}}"#, flat(1_000_000, 0)), Some(u64::MAX));
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
            assert_eq!(sniff.cost(flat(1_000_000, 2_000_000)), Some(7));
        }
        for bad in [
            b"data: {\"usage\":{\"input_tokens\":1,\"output_tokens\":2}}".as_slice(),
            b"data: {\"usage\":{\"input_tokens\":1}}\n\n",
            b"data: {\"usage\":{\"input_tokens\":-1,\"output_tokens\":2}}\n\n",
        ] {
            let mut sniff = UsageSniffer::default();
            sniff.push(bad);
            assert_eq!(sniff.cost(flat(1, 1)), None);
        }
        let mut sniff = UsageSniffer::default();
        sniff.push(&vec![b'x'; UsageSniffer::MAX_EVENT + 1]);
        assert!(sniff.invalid);
        assert!(sniff.line.is_empty() && sniff.data.is_empty());
        sniff.push(event);
        assert_eq!(sniff.cost(flat(1, 1)), None);
    }
}
