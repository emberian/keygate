//! The Unix-socket protocol: one JSON object per frame, each frame a
//! big-endian `u32` length followed by that many bytes.
//!
//! None of these types implement `Debug`: requests carry bearer tokens and,
//! for `set`, a raw secret.

use crate::journal::{JournalStats, StreamSummary, TicketId};
use crate::macaroon::Caveat;
use crate::Namespace;
use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u32 = 2;
/// Largest frame either side will ever read.
pub const MAX_FRAME_BYTES: usize = 48 << 20;
/// Largest frame the broker reads from a connection that has not yet
/// presented a valid token for a larger one (see [`Request::Present`]).
/// Every operator request and every token fits well inside it.
pub const PREAUTH_FRAME_BYTES: usize = 64 << 10;

#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub enum Request {
    Hello,
    /// Operator: mint a root macaroon for a seat.
    MintMacaroon {
        seat: String,
        #[serde(default)]
        allowed_uid: Option<u32>,
        #[serde(default)]
        caveats: Vec<Caveat>,
    },
    /// Anyone: append caveats to a token. Needs no key and is also
    /// available fully offline in the CLI.
    Attenuate {
        token: String,
        caveats: Vec<Caveat>,
    },
    ProviderAuthorize(Call),
    ProviderForward(Call),
    ProviderStream(Call),
    ServiceAuthorize(ServiceAuthorize),
    ServiceForward(Call),
    ReconcileGitPush {
        ticket: TicketId,
        call: Call,
    },
    ServiceStream(Call),
    /// Operator: load or rotate a row's secret.
    Set {
        namespace: Namespace,
        row: String,
        /// The raw secret, base64. Zeroed by the broker after sealing.
        secret_b64: String,
        #[serde(default)]
        cut_existing: bool,
        /// Drop the row's retired secrets in the same step (for rotation
        /// scripts that have already invalidated the old key upstream).
        #[serde(default)]
        forget_retired: bool,
    },
    /// Operator: stop using a row's secret and cut every stream on it. The
    /// secret is kept sealed as a retired, guard-only pattern unless
    /// `forget` is set.
    Revoke {
        namespace: Namespace,
        row: String,
        #[serde(default)]
        forget: bool,
    },
    /// Operator: invalidate every macaroon minted for a seat so far.
    RevokeSeat {
        seat: String,
    },
    /// Operator: drop a row's retired, guard-only secrets.
    Forget {
        namespace: Namespace,
        row: String,
    },
    /// Caller: prove a token before sending a request larger than
    /// [`PREAUTH_FRAME_BYTES`]. The broker verifies it against the row and
    /// answers with the frame size this connection may now send.
    Present {
        token: String,
        namespace: Namespace,
        row: String,
    },
    Ls,
    Status,
}

/// One upstream call, as the caller describes it.
#[derive(Clone, Serialize, Deserialize)]
pub struct Call {
    /// `kgm_...`
    pub token: String,
    pub row: String,
    pub method: String,
    /// A plain path: no `%`, no `.`/`..`, no empty segments.
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<(String, String)>,
    #[serde(default, with = "crate::b64", skip_serializing_if = "Vec::is_empty")]
    pub body: Vec<u8>,
    /// Distinguishes intentionally repeated identical requests. Two calls
    /// that agree on everything including this are the same request: the
    /// second is a retry and is answered from the journal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// SSE resume point; sent upstream as `Last-Event-ID` when the row
    /// allows that header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_event_id: Option<String>,
}

/// Service rows route by path into buffered or stream handling, so an
/// authorize must say which it is for.
#[derive(Clone, Serialize, Deserialize)]
pub struct ServiceAuthorize {
    #[serde(flatten)]
    pub call: Call,
    #[serde(default)]
    pub stream: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RowInfo {
    pub namespace: Namespace,
    pub row: String,
    pub origin: String,
    /// `active`, `unset` or `revoked`.
    pub state: String,
    pub generation: u64,
    pub revoked_floor: u64,
    /// Earlier secrets still withheld from responses (see `forget`).
    #[serde(default)]
    pub retired: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusInfo {
    pub version: String,
    pub uptime_s: u64,
    pub provider_rows: Option<usize>,
    pub service_rows: Option<usize>,
    pub guarded_secrets: usize,
    /// Bytes of guard patterns in use, out of `echo::MAX_GUARD_BYTES`.
    #[serde(default)]
    pub guard_pattern_bytes: usize,
    /// `separated` or `development`.
    #[serde(default)]
    pub deployment: String,
    /// Calls currently between `Begin` and their recorded outcome.
    #[serde(default)]
    pub in_flight: usize,
    pub journal: JournalStats,
    pub http_listen: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Response {
    Hello {
        protocol: u32,
        version: String,
        /// The peer uid the broker sees for this connection.
        uid: u32,
        operator: bool,
        namespaces: Vec<Namespace>,
        /// `separated` or `development`.
        #[serde(default)]
        deployment: String,
        /// Whether this peer may make calls. False for a peer that shares
        /// the broker's uid in a separated deployment.
        #[serde(default)]
        caller: bool,
    },
    Token {
        token: String,
    },
    /// Answer to `present`: frames up to this size are now accepted.
    Presented {
        max_frame_bytes: usize,
    },
    Authorized {
        ticket: TicketId,
        /// Ticket state name (`live`, `replayable`, ...).
        state: String,
        /// True when this request already had a ticket.
        existing: bool,
        reserved_micro_usd: u64,
    },
    /// A whole buffered reply.
    Reply {
        ticket: TicketId,
        status: u16,
        headers: Vec<(String, String)>,
        #[serde(with = "crate::b64")]
        body: Vec<u8>,
        /// Served from the journal; the upstream was not contacted again.
        replayed: bool,
    },
    /// Stream head; `Chunk` frames and one `End` follow.
    Head {
        ticket: TicketId,
        status: u16,
        headers: Vec<(String, String)>,
    },
    Chunk {
        #[serde(with = "crate::b64")]
        data: Vec<u8>,
    },
    /// Stream closing summary. With `spent: true` it answers a retry of a
    /// stream ticket that had already ended (no `Head` precedes it).
    End {
        ticket: TicketId,
        summary: StreamSummary,
        spent: bool,
    },
    Rows {
        rows: Vec<RowInfo>,
    },
    Status(StatusInfo),
    Ok,
    Error(Refusal),
}

/// Why the broker refused. `code` is stable; `message` is for humans.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refusal {
    pub code: Code,
    pub message: String,
    /// Present when a stream was refused or cut with a recorded outcome.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<StreamSummary>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Code {
    BadRequest,
    BadToken,
    /// A macaroon caveat, seat epoch or uid binding refused the request.
    Denied,
    NotOperator,
    NamespaceDisabled,
    UnknownRow,
    /// The row has no usable secret (never set, or revoked).
    NoSecret,
    Revoked,
    MethodRefused,
    PathRefused,
    HeaderRefused,
    TooLarge,
    ModelRefused,
    TokenCapRefused,
    BudgetExceeded,
    /// An identical request is in progress right now.
    InFlight,
    /// An earlier attempt may have reached the upstream; not re-sent.
    Uncertain,
    /// Too many requests of unknown outcome are being remembered; no new
    /// request is accepted until their tokens expire or seats are revoked.
    NoResendLedgerFull,
    /// The upstream reply contained a guarded secret.
    Withheld,
    AuditFailed,
    JournalFailed,
    UpstreamFailed,
    /// The request was not delivered within the read deadline.
    Timeout,
    /// The broker is shutting down and takes no new calls.
    ShuttingDown,
    /// The system clock is unusable, so expiries cannot be evaluated.
    ClockFailed,
    Internal,
}

impl Code {
    /// Status the HTTP gateway answers with.
    pub const fn http_status(self) -> u16 {
        match self {
            Code::BadRequest | Code::PathRefused | Code::HeaderRefused => 400,
            Code::Timeout => 408,
            Code::ShuttingDown | Code::ClockFailed | Code::NoResendLedgerFull => 503,
            Code::BadToken => 401,
            Code::Denied
            | Code::NotOperator
            | Code::MethodRefused
            | Code::ModelRefused
            | Code::TokenCapRefused => 403,
            Code::NamespaceDisabled | Code::UnknownRow => 404,
            Code::InFlight | Code::Uncertain => 409,
            Code::TooLarge => 413,
            Code::BudgetExceeded => 429,
            Code::Withheld | Code::UpstreamFailed => 502,
            Code::NoSecret | Code::Revoked | Code::AuditFailed | Code::JournalFailed => 503,
            Code::Internal => 500,
        }
    }
}

impl Refusal {
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        Refusal {
            code,
            message: message.into(),
            summary: None,
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let code = serde_json::to_value(self.code)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned));
        write!(
            f,
            "{}: {}",
            code.as_deref().unwrap_or("refused"),
            self.message
        )
    }
}

impl std::error::Error for Refusal {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_shapes_are_stable() {
        let call = Call {
            token: "kgm_x".into(),
            row: "llm".into(),
            method: "POST".into(),
            path: "/v1/messages".into(),
            query: None,
            headers: vec![],
            body: b"{}".to_vec(),
            request_id: None,
            last_event_id: None,
        };
        let json = serde_json::to_value(Request::ProviderStream(call.clone())).unwrap();
        assert_eq!(json["op"], "provider-stream");
        assert_eq!(json["body"], "e30=");
        assert!(json.get("query").is_none());

        let json = serde_json::to_value(Request::ServiceAuthorize(ServiceAuthorize {
            call,
            stream: true,
        }))
        .unwrap();
        assert_eq!(json["op"], "service-authorize");
        assert_eq!(json["stream"], true);
        let back: Request = serde_json::from_value(json).unwrap();
        assert!(matches!(back, Request::ServiceAuthorize(a) if a.stream && a.call.row == "llm"));

        let minimal: Request = serde_json::from_str(
            r#"{"op":"service-forward","token":"kgm_x","row":"gh","method":"GET","path":"/user"}"#,
        )
        .unwrap();
        assert!(
            matches!(minimal, Request::ServiceForward(c) if c.body.is_empty() && c.headers.is_empty())
        );

        let mint: Request = serde_json::from_str(
            r#"{"op":"mint-macaroon","seat":"s","caveats":[{"max_spend_micro_usd":5},{"namespace":"service"},{"rows":["gh"]}]}"#,
        )
        .unwrap();
        assert!(matches!(mint, Request::MintMacaroon { caveats, .. } if caveats.len() == 3));

        let err = serde_json::to_value(Response::Error(Refusal::new(Code::BudgetExceeded, "no")))
            .unwrap();
        assert_eq!(err["type"], "error");
        assert_eq!(err["code"], "budget_exceeded");

        // Fields added in protocol 2 default when an older peer omits them.
        let revoke: Request =
            serde_json::from_str(r#"{"op":"revoke","namespace":"service","row":"gh"}"#).unwrap();
        assert!(matches!(revoke, Request::Revoke { forget: false, .. }));
        let present = serde_json::to_value(Request::Present {
            token: "kgm_x".into(),
            namespace: Namespace::Provider,
            row: "llm".into(),
        })
        .unwrap();
        assert_eq!(present["op"], "present");
        assert_eq!(Code::Timeout.http_status(), 408);
        const _: () = assert!(PREAUTH_FRAME_BYTES < MAX_FRAME_BYTES);
        assert_eq!(
            Refusal::new(Code::Withheld, "cut").to_string(),
            "withheld: cut"
        );
    }
}
