//! `#tooth` regressions for the third hardening round (`K-A1..K-A6` and
//! third-round audit follow-ups `C-1..C-7`). Every test drives the real broker
//! or custody boundary and asserts the fixed fail-closed behavior.

mod common;

use common::*;
use keygate_broker::{Broker, BrokerOptions, HeaderMode, Listeners};
use keygate_core::audit::{AuditEvent, AuditFaults, AuditLog};
use keygate_core::config::Config;
use keygate_core::journal::{self, CallKind, TicketState};
use keygate_core::macaroon::{Caveat, MacaroonV1};
use keygate_core::proto::Code;
use keygate_core::Namespace;
use std::io::Write;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

const P: Namespace = Namespace::Provider;
const S: Namespace = Namespace::Service;

fn priced(origin: &str, dialect: &str, extra: &str) -> String {
    format!(
        r#"[broker]
deployment = "development"

[providers.llm]
origin = "{origin}"
dialect = "{dialect}"
models = ["m-small"]
max_output_tokens = 1000
input_micro_usd_per_mtok = 1000000
output_micro_usd_per_mtok = 1000000
{extra}
"#
    )
}

/// #tooth (K-A1, C-5): OpenAI `/v1/responses` `input` item references with
/// omitted `type`, `type: null`, explicit `type: "item_reference"`, or a
/// contentless `"message"` carrying `id` are refused unless `allow` lists
/// `"server-state"`. Malformed input union discriminators are refused with
/// `BadRequest`, while ordinary untyped messages, stateless typed history
/// items, and arbitrary `id` fields inside tool schemas or tool-call
/// arguments pass without false positives.
#[tokio::test]
async fn tooth_responses_item_references_require_server_state_without_blocking_tool_ids() {
    let up =
        Upstream::start(|_| Reply::ok(r#"{"usage":{"input_tokens":5,"output_tokens":2}}"#)).await;
    let open_row = format!(
        "\n[providers.open]\norigin = \"{}\"\ndialect = \"openai-responses\"\nmodels = [\"m-small\"]\nmax_output_tokens = 1000\nallow = [\"server-state\"]\n",
        up.origin
    );
    let rig = Rig::new(&priced(&up.origin, "openai-responses", &open_row));
    let token = rig.token("seat-a");

    for (i, item) in [
        r#"{"id":"msg_stored"}"#,
        r#"{"id":"msg_stored","type":null}"#,
        r#"{"id":"msg_stored","type":"item_reference"}"#,
        r#"{"id":"msg_stored","role":"user","content":"smuggled"}"#,
        r#"{"id":"msg_stored","type":"message"}"#,
        r#"{"type":"computer_call_output","call_id":"call_1","output":{"type":"computer_screenshot","file_id":"file_stored"}}"#,
    ]
    .into_iter()
    .enumerate()
    {
        let body = format!(r#"{{"model":"m-small","max_output_tokens":10,"input":[{item}]}}"#);
        let mut req = call(&token, "llm", "POST", "/v1/responses", body.as_bytes());
        req.request_id = Some(format!("refused-{i}"));
        let refusal = rig.forward(P, req).await.unwrap_err();
        assert_eq!(refusal.code, Code::Denied, "{item}: {refusal}");
        assert!(
            refusal.message.contains("\"server-state\""),
            "{item}: {}",
            refusal.message
        );
    }

    for (i, (item, needed)) in [
        (
            r#"{"type":"computer_call_output","call_id":"call_2","output":{"type":"computer_screenshot","image_url":"https://example.com/screen.png"}}"#,
            "\"remote-input\"",
        ),
        (
            r#"{"type":"computer_call_output","call_id":"call_3","output":{"type":"computer_screenshot","image_url":"data:image/png;base64,AAAA"}}"#,
            "\"inline-media\"",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let body = format!(r#"{{"model":"m-small","max_output_tokens":10,"input":[{item}]}}"#);
        let mut req = call(&token, "llm", "POST", "/v1/responses", body.as_bytes());
        req.request_id = Some(format!("screenshot-{i}"));
        let refusal = rig.forward(P, req).await.unwrap_err();
        assert_eq!(refusal.code, Code::Denied, "{item}: {refusal}");
        assert!(
            refusal.message.contains(needed),
            "{item}: {}",
            refusal.message
        );
    }

    for (i, bad_body) in [
        r#"{"model":"m-small","max_output_tokens":10,"input":{"id":"msg_stored"}}"#,
        r#"{"model":"m-small","max_output_tokens":10,"input":["msg_stored"]}"#,
        r#"{"model":"m-small","max_output_tokens":10,"input":[{"id":"msg_stored","type":false}]}"#,
        r#"{"model":"m-small","max_output_tokens":10,"input":[{"id":"msg_stored","type":0}]}"#,
    ]
    .into_iter()
    .enumerate()
    {
        let mut req = call(&token, "llm", "POST", "/v1/responses", bad_body.as_bytes());
        req.request_id = Some(format!("malformed-{i}"));
        let refusal = rig.forward(P, req).await.unwrap_err();
        assert_eq!(refusal.code, Code::BadRequest, "{bad_body}: {refusal}");
    }
    assert_eq!(
        up.connections(),
        0,
        "all refusals happen before the network"
    );

    // Legitimate stateless Responses traffic with `id` in tool schemas,
    // function_call arguments, function_call_output, and inline assistant
    // messages passes without needing `server-state`.
    for (i, ok_body) in [
        r#"{"model":"m-small","max_output_tokens":10,"input":[{"role":"user","content":"hello"}]}"#,
        r#"{"model":"m-small","max_output_tokens":10,"input":[{"role":"user","type":null,"content":[{"type":"input_text","text":"hello"}]}]}"#,
        r#"{"model":"m-small","max_output_tokens":10,"tools":[{"type":"function","name":"lookup","parameters":{"type":"object","properties":{"id":{"type":"string"}},"required":["id"]}}],"input":[{"type":"message","id":"msg_prev","role":"assistant","content":[{"type":"output_text","text":"checking"}]},{"type":"function_call","id":"fc_1","call_id":"call_1","name":"lookup","arguments":"{\"id\":\"msg_stored\"}"},{"type":"function_call_output","id":"fco_1","call_id":"call_1","output":"{\"id\":\"row_42\"}"},{"type":"reasoning","id":"rs_1","summary":[]}]}"#,
    ]
    .into_iter()
    .enumerate()
    {
        let mut req = call(&token, "llm", "POST", "/v1/responses", ok_body.as_bytes());
        req.request_id = Some(format!("ok-{i}"));
        rig.forward(P, req)
            .await
            .unwrap_or_else(|e| panic!("legitimate body {i} refused: {e}"));
    }
    assert_eq!(up.hits(), 3);

    // Explicitly opting into `allow = ["server-state"]` permits shorthand and
    // explicit item references on that row.
    for (i, item) in [
        r#"{"id":"msg_stored"}"#,
        r#"{"id":"msg_stored","type":null}"#,
        r#"{"id":"msg_stored","type":"item_reference"}"#,
    ]
    .into_iter()
    .enumerate()
    {
        let body = format!(r#"{{"model":"m-small","max_output_tokens":10,"input":[{item}]}}"#);
        let mut req = call(&token, "open", "POST", "/v1/responses", body.as_bytes());
        req.request_id = Some(format!("open-{i}"));
        rig.forward(P, req).await.unwrap();
    }
    assert_eq!(up.hits(), 6);
}

/// #tooth (K-A2, C-5): a cleanly finished OpenAI Responses stream whose
/// terminal event is `response.incomplete` with complete usage settles to
/// actual usage instead of stranding the conservative reservation, while
/// missing/null/failed usage or premature EOF keeps the reservation.
#[tokio::test]
async fn tooth_incomplete_response_stream_settles_complete_usage_and_keeps_bad_usage() {
    let (mut senders, script) = script(4);
    let up = Upstream::start(move |_| script.next()).await;
    let rig = Rig::new(&priced(&up.origin, "openai-responses", ""));
    let token = rig.token("seat-a");
    let body = br#"{"model":"m-small","max_output_tokens":100,"stream":true,"input":"hello"}"#;

    let mut req1 = call(&token, "llm", "POST", "/v1/responses", body);
    req1.request_id = Some("complete-incomplete".into());
    let reserved = rig
        .broker
        .authorize(P, AGENT, req1.clone(), CallKind::Stream)
        .unwrap()
        .reserved_micro_usd;
    assert!(reserved > 8_000, "unexpected reservation: {reserved}");
    let mut live = rig.live(P, req1).await;
    let tx = senders.remove(0);
    tx.send(bytes::Bytes::from_static(
        b"event: response.in_progress\ndata: {\"type\":\"response.in_progress\",\"response\":{\"status\":\"in_progress\",\"usage\":null}}\n\nevent: response.incomplete\ndata: {\"type\":\"response.incomplete\",\"response\":{\"status\":\"incomplete\",\"incomplete_details\":{\"reason\":\"max_output_tokens\"},\"usage\":{\"input_tokens\":3,\"output_tokens\":100,\"total_tokens\":103}}}\n\n",
    ))
    .unwrap();
    drop(tx);
    let (_, summary) = drain(&mut live).await;
    assert!(summary.complete);
    assert_eq!(
        rig.broker.ticket(live.ticket).unwrap().reserved_micro_usd,
        103,
        "terminal response.incomplete with complete usage must settle"
    );

    // Terminal `response.incomplete` with `usage: null` keeps the reservation.
    let mut req2 = call(&token, "llm", "POST", "/v1/responses", body);
    req2.request_id = Some("null-usage".into());
    let mut live2 = rig.live(P, req2).await;
    let tx2 = senders.remove(0);
    tx2.send(bytes::Bytes::from_static(
        b"event: response.incomplete\ndata: {\"type\":\"response.incomplete\",\"response\":{\"status\":\"incomplete\",\"usage\":null}}\n\n",
    ))
    .unwrap();
    drop(tx2);
    let (_, summary2) = drain(&mut live2).await;
    assert!(summary2.complete);
    assert_eq!(
        rig.broker.ticket(live2.ticket).unwrap().reserved_micro_usd,
        reserved
    );

    // Non-terminal `response.in_progress` followed by premature EOF without a
    // terminal event keeps the reservation even if `in_progress` carried numbers.
    let mut req3 = call(&token, "llm", "POST", "/v1/responses", body);
    req3.request_id = Some("no-terminal".into());
    let mut live3 = rig.live(P, req3).await;
    let tx3 = senders.remove(0);
    tx3.send(bytes::Bytes::from_static(
        b"event: response.in_progress\ndata: {\"type\":\"response.in_progress\",\"response\":{\"status\":\"in_progress\",\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n",
    ))
    .unwrap();
    drop(tx3);
    let (_, summary3) = drain(&mut live3).await;
    assert!(summary3.complete);
    assert_eq!(
        rig.broker.ticket(live3.ticket).unwrap().reserved_micro_usd,
        reserved
    );

    // A stream that emits another `response.*` event after a terminal
    // `response.completed` / `response.incomplete` keeps the reservation
    // instead of settling stale usage from the earlier turn.
    let mut req4 = call(&token, "llm", "POST", "/v1/responses", body);
    req4.request_id = Some("post-terminal-event".into());
    let mut live4 = rig.live(P, req4).await;
    let tx4 = senders.remove(0);
    tx4.send(bytes::Bytes::from_static(
        b"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"usage\":{\"input_tokens\":3,\"output_tokens\":2}}}\n\nevent: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"status\":\"in_progress\"}}\n\n",
    ))
    .unwrap();
    drop(tx4);
    let (_, summary4) = drain(&mut live4).await;
    assert!(summary4.complete);
    assert_eq!(
        rig.broker.ticket(live4.ticket).unwrap().reserved_micro_usd,
        reserved,
        "post-terminal response.* events must invalidate stale usage settlement"
    );
}

/// #tooth (K-A3): a second `Broker::open` on the same state directory is
/// refused before opening mutable state, even when configured with a
/// different socket pathname.
#[tokio::test]
async fn tooth_state_lock_blocks_second_broker_on_any_socket() {
    let up = Upstream::start(|_| Reply::ok("{}")).await;
    let cfg = priced(&up.origin, "openai-chat", "per_day_micro_usd = 10000\n");
    let rig = Rig::new(&cfg);
    let first_listener = Listeners::bind(&rig.broker).await.unwrap();

    let mut second_cfg = Config::parse(&cfg).unwrap();
    second_cfg.broker.socket = "second.sock".into();
    let err = match Broker::open(rig.state(), second_cfg, BrokerOptions::default()) {
        Ok(_) => panic!("second broker opened an already-owned state directory"),
        Err(err) => err,
    };
    assert!(
        err.to_string()
            .contains("already owned by a running broker"),
        "{err}"
    );
    assert!(
        Broker::init_state(rig.state()).is_err(),
        "init_state must honor the live state lock"
    );

    // First broker remains sole owner: two ~8366 micro-USD reservations cannot
    // exceed the 10000 daily cap, and revocation on an unexhausted ticket/row
    // cannot be bypassed.
    let token = rig.token("seat-a");
    let body =
        br#"{"model":"m-small","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}"#;
    let mut req = call(&token, "llm", "POST", "/v1/chat/completions", body);
    req.request_id = Some("first".into());
    let authorized = rig
        .broker
        .authorize(P, AGENT, req.clone(), CallKind::Buffered)
        .unwrap();
    assert!(authorized.reserved_micro_usd > 8_000);
    let mut over_cap = req.clone();
    over_cap.request_id = Some("second".into());
    assert_eq!(
        rig.forward(P, over_cap).await.unwrap_err().code,
        Code::BudgetExceeded
    );
    rig.broker.revoke(P, "llm", false, OPERATOR).unwrap();
    assert_eq!(
        rig.forward(P, req).await.unwrap_err().code,
        Code::Revoked,
        "already-reserved ticket faces current revocation"
    );
    assert_eq!(up.hits(), 0);
    drop(first_listener);
}

/// #tooth (K-A3): a rejected duplicate startup on the same state directory
/// never touches, recovers, or compacts the running broker's WAL, so an
/// acknowledged buffered reply remains `Replayable` across restart.
#[tokio::test]
async fn tooth_failed_duplicate_start_preserves_retained_reply_durability() {
    let (mut senders, script) = script(1);
    let up = Upstream::start(move |_| script.next()).await;
    let cfg = format!(
        r#"[broker]
deployment = "development"
compact_every = 2

[services.api]
origin = "{}"
buffered_paths = ["/"]
"#,
        up.origin
    );
    let rig = Rig::new(&cfg);
    let listeners = Listeners::bind(&rig.broker).await.unwrap();
    let token = rig.token("seat-a");
    let request = call(&token, "api", "GET", "/", b"");
    let broker = rig.broker.clone();
    let copy = request.clone();
    let flight =
        tokio::spawn(async move { broker.forward(S, AGENT, copy, HeaderMode::Strict).await });
    up.arrived().await;

    // Duplicate open fails at StateLock before Journal::open can demote or compact.
    assert!(Broker::open(
        rig.state(),
        Config::parse(&cfg).unwrap(),
        BrokerOptions::default(),
    )
    .is_err());

    let tx = senders.pop().unwrap();
    tx.send(bytes::Bytes::from_static(b"done")).unwrap();
    drop(tx);
    let reply = flight.await.unwrap().unwrap();
    assert_eq!(reply.body, b"done");
    assert!(matches!(
        rig.broker.ticket(reply.ticket).unwrap().state,
        TicketState::Replayable(_)
    ));
    drop(listeners);

    let rig = rig.reopen(BrokerOptions::default());
    assert!(
        matches!(
            rig.broker.ticket(reply.ticket).unwrap().state,
            TicketState::Replayable(_)
        ),
        "retained reply must survive a rejected duplicate startup"
    );
    let replayed = rig.forward(S, request).await.unwrap();
    assert!(replayed.replayed);
    assert_eq!(replayed.body, b"done");
    assert_eq!(up.hits(), 1);
}

/// #tooth (K-A4): `AuditLog` recovers an unfinished crash tail before
/// appending `Begin`, refuses mid-file corruption on boot, and fails closed
/// before the network (poisoning subsequent calls) when audit sync or torn
/// rollback fails.
#[tokio::test]
async fn tooth_audit_recovers_torn_tail_and_poisons_broker_on_failed_sync() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    {
        let log = AuditLog::open(&path).unwrap();
        log.append(&AuditEvent::Admin {
            action: "set",
            uid: Some(0),
            namespace: Some(P),
            target: "llm",
            detail: "rotate",
        })
        .unwrap();
    }
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(br#"{"event":"begin","ticket":"torn"#)
        .unwrap();
    let audit = AuditLog::open(&path).unwrap();
    audit
        .append(&AuditEvent::Begin {
            ticket: journal::TicketId::from_bytes([1; 16]),
            seat: "a",
            uid: None,
            namespace: P,
            row: "llm",
            method: "POST",
            path: "/v1/responses",
            stream: false,
            generation: 1,
            request_digest: "fixture".into(),
            request_bytes: 2,
        })
        .unwrap();
    drop(audit);
    let lines: Vec<serde_json::Value> = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).expect("every recovered audit line must parse"))
        .collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["event"], "admin");
    assert_eq!(lines[1]["event"], "begin");

    // Broker boundary: audit sync failure refuses before network and poisons
    // later Begin appends until restart.
    let up = Upstream::start(|_| Reply::ok("{}")).await;
    let faults = Arc::new(AuditFaults::default());
    let cfg = format!(
        "[broker]\ndeployment = \"development\"\n[services.api]\norigin = \"{}\"\nbuffered_paths = [\"/\"]\n",
        up.origin
    );
    let rig = Rig::unset_with(
        &cfg,
        BrokerOptions {
            audit_faults: Some(faults.clone()),
            ..Default::default()
        },
    );
    rig.set(S, "api", SECRET, false);
    let token = rig.token("seat-a");

    faults.fail_sync.store(true, Ordering::SeqCst);
    let mut req1 = call(&token, "api", "GET", "/", b"");
    req1.request_id = Some("sync-fail".into());
    assert_eq!(
        rig.forward(S, req1.clone()).await.unwrap_err().code,
        Code::AuditFailed
    );
    assert_eq!(up.connections(), 0, "failed audit sync must block network");

    // Clearing the transient fault does not unpoison the audit writer.
    faults.fail_sync.store(false, Ordering::SeqCst);
    let mut req2 = call(&token, "api", "GET", "/", b"");
    req2.request_id = Some("after-poison".into());
    assert_eq!(
        rig.forward(S, req2.clone()).await.unwrap_err().code,
        Code::AuditFailed
    );
    assert_eq!(up.connections(), 0);

    // Reopening recovers from disk and allows requests again.
    let rig = rig.reopen(BrokerOptions::default());
    assert!(rig.forward(S, req2).await.is_ok());
    assert_eq!(up.hits(), 1);
}

/// #tooth (K-A5): end-to-end stream call whose token expires before network
/// transmission is refused without contacting the upstream.
#[tokio::test]
async fn tooth_expired_stream_never_contacts_upstream() {
    let up = Upstream::start(|_| Reply::ok("data: hi\n\n")).await;
    let cfg = format!(
        "[broker]\ndeployment = \"development\"\n[services.api]\norigin = \"{}\"\nstream_paths = [\"/events\"]\n",
        up.origin
    );
    let rig = Rig::new(&cfg);
    let root = rig.token("seat-a");
    let expiring = MacaroonV1::decode(&root)
        .unwrap()
        .attenuate(Caveat::ExpiresAtUnixS(now_unix_s() + 1))
        .unwrap()
        .encode();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let err = rig
        .stream(S, call(&expiring, "api", "GET", "/events", b""))
        .await
        .unwrap_err();
    assert_eq!(err.code, Code::Denied);
    assert_eq!(up.connections(), 0);
}
