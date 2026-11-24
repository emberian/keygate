//! `#tooth`: adversarial end-to-end tests. Each one drives the real broker
//! against a local HTTP/SSE upstream and asserts on what the upstream saw
//! and what reached the caller.

mod common;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use bytes::Bytes;
use common::*;
use keygate_broker::client::Client;
use keygate_broker::{
    BootError, Broker, BrokerOptions, Caller, HeaderMode, Listeners, StreamOutcome,
};
use keygate_core::audit::AuditLog;
use keygate_core::config::Config;
use keygate_core::journal::{self, CallKind, ClosedBy, TicketState};
use keygate_core::macaroon::{Caveat, MacaroonV1};
use keygate_core::proto::{Code, Request, Response, ServiceAuthorize};
use keygate_core::seal::SealError;
use keygate_core::Namespace;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const P: Namespace = Namespace::Provider;
const S: Namespace = Namespace::Service;

fn bytes(s: &'static str) -> Bytes {
    Bytes::from_static(s.as_bytes())
}

/// An upstream that answers every request with a distinct JSON body.
async fn counting_upstream() -> Upstream {
    let n = AtomicUsize::new(0);
    Upstream::start(move |_| {
        Reply::ok(format!(
            r#"{{"reply":{}}}"#,
            n.fetch_add(1, Ordering::SeqCst)
        ))
    })
    .await
}

// ----- EchoGuard on live streams ----------------------------------------------

/// Stream the secret from the upstream in `pieces` and check that nothing
/// of it reaches the caller.
async fn secret_split_case(pieces: Vec<&'static [u8]>) {
    let (senders, script) = script(1);
    let up = Upstream::start(move |_| script.next()).await;
    let rig = Rig::new(&config(&up.origin));
    let token = rig.token("seat-a");
    let request = call(
        &token,
        "llm",
        "POST",
        "/v1/messages",
        &llm("m-small", 100, true),
    );

    let mut live = rig.live(P, request.clone()).await;
    assert_eq!(
        up.last().header("x-api-key"),
        Some(SECRET),
        "the upstream gets the real key"
    );
    assert_eq!(up.last().header("accept-encoding"), Some("identity"));

    senders[0].send(bytes("data: hello\n\n")).unwrap();
    assert_eq!(next_chunk(&mut live).await, "data: hello\n\n");
    senders[0].send(bytes("data: ")).unwrap();
    assert_eq!(next_chunk(&mut live).await, "data: ");

    for piece in pieces {
        // The guard trips on the 16th secret byte, so with small pieces the
        // upstream request can be gone before the last ones are sent.
        let _ = senders[0].send(Bytes::from_static(piece));
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // By now keygate may already have torn the upstream request down.
    let _ = senders[0].send(bytes(" and the rest of the debug page"));

    let (after, summary) = drain(&mut live).await;
    assert!(
        after.is_empty(),
        "bytes leaked after the secret began: {:?}",
        String::from_utf8_lossy(&after)
    );
    assert!(summary.withheld && !summary.complete && !summary.revoked);
    assert_eq!(summary.closed_by, ClosedBy::Withheld);
    assert_eq!(summary.bytes, "data: hello\n\ndata: ".len() as u64);

    // The upstream request is killed, not left to drain.
    tokio::time::timeout(WAIT, senders[0].closed())
        .await
        .expect("upstream request was not aborted");

    // The ticket keeps the closing summary; a retry reports it and does not
    // open a second stream.
    match rig.stream(P, request).await.unwrap() {
        StreamOutcome::Spent { summary: again, .. } => assert_eq!(again, summary),
        StreamOutcome::Live(_) => panic!("a spent stream ticket reopened"),
    }
    assert_eq!(up.hits(), 1);

    let audit = std::fs::read_to_string(rig.state().join("audit.log")).unwrap();
    assert!(audit.contains(r#""event":"stream_end""#) && audit.contains(r#""withheld":true"#));
    assert_no_plaintext(rig.state(), SECRET);
}

#[tokio::test]
async fn tooth_stream_secret_split_in_two_chunks_is_cut() {
    secret_split_case(vec![b"sk-ant-", b"secret12345"]).await;
}

#[tokio::test]
async fn tooth_stream_secret_split_in_three_chunks_is_cut() {
    secret_split_case(vec![b"sk-ant-", b"secret1", b"2345"]).await;
}

#[tokio::test]
async fn tooth_stream_secret_split_into_single_bytes_is_cut() {
    secret_split_case(SECRET.as_bytes().chunks(1).collect()).await;
}

#[tokio::test]
async fn tooth_near_miss_stream_is_delivered_complete() {
    let (senders, script) = script(1);
    let up = Upstream::start(move |_| script.next()).await;
    let rig = Rig::new(&config(&up.origin));
    let token = rig.token("seat-a");
    let mut live = rig
        .live(S, call(&token, "api", "GET", "/events", b""))
        .await;
    // Fragments of the secret below the 16-byte window, split across
    // chunks, then the stream ends cleanly.
    for piece in [
        "event: x\ndata: sk-ant-",
        "secret12",
        "\n\ndata: sk-ant-sec",
    ] {
        senders[0].send(bytes(piece)).unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    drop(senders);
    let (delivered, summary) = drain(&mut live).await;
    assert_eq!(
        delivered,
        b"event: x\ndata: sk-ant-secret12\n\ndata: sk-ant-sec"
    );
    assert!(summary.complete && !summary.withheld);
    assert_eq!(summary.closed_by, ClosedBy::UpstreamEof);
    assert_eq!(summary.bytes, delivered.len() as u64);
}

#[tokio::test]
async fn tooth_secret_echoed_in_reply_is_withheld_whole() {
    // An upstream "debug" mode that reflects the credential it was sent.
    let up = Upstream::start(|seen| match seen.path.as_str() {
        "/repos/header" => Reply::Full {
            status: 500,
            headers: vec![(
                "x-debug-auth",
                seen.header("authorization").unwrap().to_owned(),
            )],
            body: b"oops".to_vec(),
        },
        "/events/header" => Reply::Full {
            status: 200,
            headers: vec![(
                "x-debug-auth",
                seen.header("authorization").unwrap().to_owned(),
            )],
            body: b"data: x\n\n".to_vec(),
        },
        "/repos/gzip" => Reply::Full {
            status: 200,
            headers: vec![("content-encoding", "gzip".into())],
            body: vec![0x1f, 0x8b, 8, 0],
        },
        _ => Reply::ok(format!(
            "your key was {}",
            seen.header("authorization").unwrap()
        )),
    })
    .await;
    let rig = Rig::new(&config(&up.origin));
    let token = rig.token("seat-a");

    // In the body.
    let body_echo = call(&token, "api", "GET", "/repos/body", b"");
    assert_eq!(
        rig.forward(S, body_echo.clone()).await.unwrap_err().code,
        Code::Withheld
    );
    // A retry is answered from the ticket: still withheld, not re-sent.
    assert_eq!(
        rig.forward(S, body_echo).await.unwrap_err().code,
        Code::Withheld
    );
    assert_eq!(up.hits(), 1);

    // In a header: caught before any head is emitted, buffered and stream.
    assert_eq!(
        rig.forward(S, call(&token, "api", "GET", "/repos/header", b""))
            .await
            .unwrap_err()
            .code,
        Code::Withheld
    );
    let refusal = rig
        .stream(S, call(&token, "api", "GET", "/events/header", b""))
        .await
        .unwrap_err();
    assert_eq!(refusal.code, Code::Withheld);
    let summary = refusal
        .summary
        .expect("a withheld stream carries its summary");
    assert!(summary.withheld && summary.bytes == 0);

    // A compressed body cannot be scanned, so it is not passed along.
    assert_eq!(
        rig.forward(S, call(&token, "api", "GET", "/repos/gzip", b""))
            .await
            .unwrap_err()
            .code,
        Code::Withheld
    );

    assert_no_plaintext(rig.state(), SECRET);
}

// ----- macaroons ----------------------------------------------------------------

fn raw(token: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD
        .decode(token.strip_prefix("kgm_").unwrap())
        .unwrap()
}

fn cooked(raw: &[u8]) -> String {
    format!("kgm_{}", URL_SAFE_NO_PAD.encode(raw))
}

#[tokio::test]
async fn tooth_macaroon_tampering_is_rejected_and_narrowing_is_enforced() {
    let up = counting_upstream().await;
    let rig = Rig::new(&config(&up.origin));
    let root = rig.token("seat-a");
    let get = |token: &str, path: &str| {
        let mut c = call(token, "api", "GET", path, b"");
        c.request_id = Some(format!("{}{path}", token.len()));
        c
    };

    // Offline attenuation: no broker, no key, only the token string.
    let narrowed = MacaroonV1::decode(&root)
        .unwrap()
        .attenuate(Caveat::PathPrefixes(vec!["/repos/mine".into()]))
        .unwrap()
        .attenuate(Caveat::ExpiresAtUnixS(now_unix_s() + 3600))
        .unwrap()
        .encode();
    assert!(
        rig.forward(S, get(&narrowed, "/repos/mine/issues"))
            .await
            .is_ok(),
        "a narrowed token works inside its bounds"
    );
    assert_eq!(
        rig.forward(S, get(&narrowed, "/repos/theirs"))
            .await
            .unwrap_err()
            .code,
        Code::Denied
    );
    assert!(
        rig.forward(S, get(&root, "/repos/theirs")).await.is_ok(),
        "the root token was not narrowed"
    );

    let expired = MacaroonV1::decode(&root)
        .unwrap()
        .attenuate(Caveat::ExpiresAtUnixS(now_unix_s() - 1))
        .unwrap()
        .encode();
    assert_eq!(
        rig.forward(S, get(&expired, "/repos/mine"))
            .await
            .unwrap_err()
            .code,
        Code::Denied
    );

    // Attack 1: strip the caveats, keeping the attenuated token's tag.
    let (root_raw, narrowed_raw) = (raw(&root), raw(&narrowed));
    let mut stripped = root_raw[..root_raw.len() - 32].to_vec();
    stripped.extend_from_slice(&narrowed_raw[narrowed_raw.len() - 32..]);
    assert_eq!(
        rig.forward(S, get(&cooked(&stripped), "/repos/theirs"))
            .await
            .unwrap_err()
            .code,
        Code::BadToken
    );

    // Attack 2: strip only the last caveat (the expiry).
    let one = raw(&MacaroonV1::decode(&root)
        .unwrap()
        .attenuate(Caveat::PathPrefixes(vec!["/repos/mine".into()]))
        .unwrap()
        .encode());
    let mut no_expiry = one[..one.len() - 32].to_vec();
    no_expiry.extend_from_slice(&narrowed_raw[narrowed_raw.len() - 32..]);
    assert_eq!(
        rig.forward(S, get(&cooked(&no_expiry), "/repos/mine"))
            .await
            .unwrap_err()
            .code,
        Code::BadToken
    );

    // Attack 3: widen MaxSpendMicroUsd in place. It is the final caveat, so
    // its u64 sits immediately before the 32-byte tag.
    let capped = raw(&MacaroonV1::decode(&root)
        .unwrap()
        .attenuate(Caveat::MaxSpendMicroUsd(1_000))
        .unwrap()
        .encode());
    let at = capped.len() - 32 - 8;
    assert_eq!(capped[at..at + 8], 1_000u64.to_le_bytes());
    let mut widened = capped.clone();
    widened[at..at + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(
        rig.forward(S, get(&cooked(&capped), "/repos/a"))
            .await
            .is_ok(),
        "the untampered capped token is fine"
    );
    assert_eq!(
        rig.forward(S, get(&cooked(&widened), "/repos/b"))
            .await
            .unwrap_err()
            .code,
        Code::BadToken
    );

    // Attack 4: a token minted under some other root key.
    let foreign = MacaroonV1::mint(
        &[7u8; 32],
        MacaroonV1::decode(&root).unwrap().root().clone(),
    )
    .encode();
    assert_eq!(
        rig.forward(S, get(&foreign, "/repos/a"))
            .await
            .unwrap_err()
            .code,
        Code::BadToken
    );

    assert_eq!(
        up.hits(),
        3,
        "only the three legitimate calls reached the upstream"
    );
}

#[tokio::test]
async fn tooth_uid_binding_and_seat_revocation() {
    let up = counting_upstream().await;
    let rig = Rig::new(&config(&up.origin));
    let bound = rig
        .broker
        .mint("seat-a", Some(4242), vec![], OPERATOR)
        .unwrap();
    let get = |id: &str| {
        let mut c = call(&bound, "api", "GET", "/repos/x", b"");
        c.request_id = Some(id.to_owned());
        c
    };

    // Right uid over the socket: fine. A co-tenant with another uid, or a
    // transport with no peer credentials at all: refused.
    assert!(rig
        .broker
        .forward(S, Caller { uid: Some(4242) }, get("1"), HeaderMode::Strict)
        .await
        .is_ok());
    for uid in [Some(4243), Some(0), None] {
        let err = rig
            .broker
            .forward(S, Caller { uid }, get("2"), HeaderMode::Strict)
            .await
            .unwrap_err();
        assert_eq!(err.code, Code::Denied, "uid {uid:?}");
    }

    // Revoking the seat kills every token minted before, and only those.
    let other_seat = rig.token("seat-b");
    rig.broker.revoke_seat("seat-a", OPERATOR).unwrap();
    assert_eq!(
        rig.broker
            .forward(S, Caller { uid: Some(4242) }, get("3"), HeaderMode::Strict)
            .await
            .unwrap_err()
            .code,
        Code::Denied
    );
    assert!(rig
        .forward(S, call(&other_seat, "api", "GET", "/repos/x", b""))
        .await
        .is_ok());
    let reminted = rig.token("seat-a");
    assert!(rig
        .forward(S, call(&reminted, "api", "GET", "/repos/x", b""))
        .await
        .is_ok());

    // The seat epoch survives a restart.
    let rig = rig.reopen(BrokerOptions::default());
    assert_eq!(
        rig.broker
            .forward(S, Caller { uid: Some(4242) }, get("4"), HeaderMode::Strict)
            .await
            .unwrap_err()
            .code,
        Code::Denied
    );
    assert_eq!(up.hits(), 3);
}

// ----- revocation vs rotation ---------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tooth_revoke_cuts_live_stream_within_50ms_and_rotation_does_not() {
    let (senders, script) = script(4);
    let up = Upstream::start(move |seen| {
        if seen.path == "/events" {
            script.next()
        } else {
            Reply::ok("{}")
        }
    })
    .await;
    let rig = Rig::new(&config(&up.origin));
    let token = rig.token("seat-a");
    let events = |id: &str| {
        let mut c = call(&token, "api", "GET", "/events", b"");
        c.request_id = Some(id.to_owned());
        c
    };

    let mut a = rig.live(S, events("a")).await;
    let mut b = rig.live(S, events("b")).await;
    senders[0].send(bytes("data: a1\n\n")).unwrap();
    senders[1].send(bytes("data: b1\n\n")).unwrap();
    assert_eq!(next_chunk(&mut a).await, "data: a1\n\n");
    assert_eq!(next_chunk(&mut b).await, "data: b1\n\n");

    // Routine rotation: both streams keep flowing on the old key.
    rig.set(S, "api", "sk-rotated-key-0002", false);
    senders[0].send(bytes("data: a2\n\n")).unwrap();
    senders[1].send(bytes("data: b2\n\n")).unwrap();
    assert_eq!(next_chunk(&mut a).await, "data: a2\n\n");
    assert_eq!(next_chunk(&mut b).await, "data: b2\n\n");

    // New requests use the new key at once.
    let mut c = rig.live(S, events("c")).await;
    assert_eq!(
        up.last().header("authorization"),
        Some("Bearer sk-rotated-key-0002")
    );

    // Rotation with --cut-existing severs everything on older generations.
    rig.set(S, "api", "sk-rotated-key-0003", true);
    for (stream, sender) in [
        (&mut a, &senders[0]),
        (&mut b, &senders[1]),
        (&mut c, &senders[2]),
    ] {
        let (rest, summary) = drain(stream).await;
        assert!(rest.is_empty());
        assert!(summary.revoked && !summary.complete);
        assert_eq!(summary.closed_by, ClosedBy::Revoked);
        tokio::time::timeout(WAIT, sender.closed())
            .await
            .expect("upstream stream was not aborted");
    }

    // A stream on the current key, then a hard revoke.
    let mut d = rig.live(S, events("d")).await;
    assert_eq!(
        up.last().header("authorization"),
        Some("Bearer sk-rotated-key-0003")
    );
    senders[3].send(bytes("data: d1\n\n")).unwrap();
    assert_eq!(next_chunk(&mut d).await, "data: d1\n\n");

    let cut = tokio::spawn(async move {
        let ended = drain(&mut d).await;
        (ended, Instant::now())
    });
    let revoked_at = Instant::now();
    rig.broker.revoke(S, "api", false, OPERATOR).unwrap();
    let ((rest, summary), cut_at) = tokio::time::timeout(WAIT, cut)
        .await
        .expect("stream survived revoke")
        .unwrap();
    let latency = cut_at.saturating_duration_since(revoked_at);
    eprintln!("revoke -> stream cut observed by caller: {latency:?}");
    assert!(
        latency < Duration::from_millis(50),
        "revoke took {latency:?} to cut the stream"
    );
    assert!(rest.is_empty());
    assert!(summary.revoked);
    assert_eq!(summary.closed_by, ClosedBy::Revoked);
    tokio::time::timeout(WAIT, senders[3].closed())
        .await
        .expect("upstream stream was not aborted");

    // The row is dead until a new secret is set, and says why.
    assert_eq!(
        rig.stream(S, events("e")).await.unwrap_err().code,
        Code::Revoked
    );
    assert_eq!(
        rig.forward(S, call(&token, "api", "GET", "/repos/x", b""))
            .await
            .unwrap_err()
            .code,
        Code::Revoked
    );
    assert_eq!(up.hits(), 4);
    for old in [SECRET, "sk-rotated-key-0002", "sk-rotated-key-0003"] {
        assert_no_plaintext(rig.state(), old);
    }

    // Revocation is durable: a restart does not resurrect the key.
    let rig = rig.reopen(BrokerOptions::default());
    let row = rig
        .broker
        .rows()
        .into_iter()
        .find(|r| r.namespace == S)
        .unwrap();
    assert_eq!(
        (row.state.as_str(), row.generation, row.revoked_floor),
        ("revoked", 3, 4)
    );
    rig.set(S, "api", "sk-rotated-key-0005", false);
    assert!(rig
        .forward(S, call(&token, "api", "GET", "/repos/x", b""))
        .await
        .is_ok());
}

// ----- ticket journal -----------------------------------------------------------

#[tokio::test]
async fn tooth_buffered_exact_retry_replays_without_resending() {
    let up = counting_upstream().await;
    let rig = Rig::new(&config(&up.origin));
    let token = rig.token("seat-a");
    let post = call(
        &token,
        "api",
        "POST",
        "/repos/o/r/issues",
        br#"{"title":"once"}"#,
    );

    let first = rig.forward(S, post.clone()).await.unwrap();
    assert!(!first.replayed);
    let retry = rig.forward(S, post.clone()).await.unwrap();
    assert!(retry.replayed);
    assert_eq!(
        (retry.ticket, retry.status, &retry.body),
        (first.ticket, first.status, &first.body)
    );
    assert_eq!(up.hits(), 1, "the POST was sent exactly once");

    // The replay survives a broker restart.
    let rig = rig.reopen(BrokerOptions::default());
    let after_restart = rig.forward(S, post.clone()).await.unwrap();
    assert!(after_restart.replayed);
    assert_eq!(after_restart.body, first.body);
    assert_eq!(up.hits(), 1);

    // A deliberate repeat is a different request; so is another seat's.
    let mut again = post.clone();
    again.request_id = Some("second".into());
    let second = rig.forward(S, again).await.unwrap();
    assert!(!second.replayed);
    assert_ne!(second.body, first.body);
    let mut other_seat = post.clone();
    other_seat.token = rig.token("seat-b");
    assert!(!rig.forward(S, other_seat).await.unwrap().replayed);
    assert_eq!(up.hits(), 3);
}

#[tokio::test]
async fn tooth_authorize_retry_shares_one_ticket_and_one_reservation() {
    let up =
        Upstream::start(|_| Reply::ok(r#"{"usage":{"input_tokens":7,"output_tokens":20}}"#)).await;
    let rig = Rig::new(&config(&up.origin));
    let token = rig.token("seat-a");
    let request = call(
        &token,
        "llm",
        "POST",
        "/v1/messages",
        &llm("m-small", 1000, false),
    );
    let day = journal::utc_day(now_unix_s());
    let row_day = journal::row_day_key("llm", day);

    let first = rig
        .broker
        .authorize(P, AGENT, request.clone(), CallKind::Buffered)
        .unwrap();
    assert!(!first.existing);
    assert_eq!((first.state, first.reserved_micro_usd), ("live", 1000));
    let again = rig
        .broker
        .authorize(P, AGENT, request.clone(), CallKind::Buffered)
        .unwrap();
    assert!(again.existing);
    assert_eq!(again.ticket, first.ticket);
    assert_eq!(
        rig.broker.spent(&row_day),
        1000,
        "the retry was not charged again"
    );
    assert_eq!(up.connections(), 0, "authorize never touches the network");

    // forward spends the same ticket, then settles to metered usage.
    let reply = rig.forward(P, request.clone()).await.unwrap();
    assert_eq!(reply.ticket, first.ticket);
    assert_eq!(rig.broker.spent(&row_day), 20);
    assert_eq!(
        rig.broker
            .spent(&journal::seat_day_key("llm", "seat-a", day)),
        20
    );
    let after = rig
        .broker
        .authorize(P, AGENT, request, CallKind::Buffered)
        .unwrap();
    assert_eq!((after.ticket, after.state), (first.ticket, "replayable"));
    assert_eq!(up.hits(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tooth_caller_disconnect_mid_flight_marks_ticket_uncertain() {
    let up = Upstream::start(|_| Reply::Hang).await;
    let rig = Rig::new(&config(&up.origin));
    let token = rig.token("seat-a");
    let listeners = Listeners::bind(&rig.broker).await.unwrap();
    let socket = listeners.socket_path.clone();
    let server = tokio::spawn(listeners.run(rig.broker.clone()));

    let request = Request::ServiceForward(call(
        &token,
        "api",
        "POST",
        "/repos/o/r/issues",
        br#"{"title":"once"}"#,
    ));
    let mut caller = Client::connect(&socket).await.unwrap();
    caller.send(&request).await.unwrap();
    up.arrived().await;

    // While it is in flight, the same request is refused as a duplicate.
    let mut second = Client::connect(&socket).await.unwrap();
    assert!(
        matches!(second.call(&request).await.unwrap(), Response::Error(r) if r.code == Code::InFlight)
    );

    // The caller dies. The POST may have landed, so it must never be re-sent.
    drop(caller);
    let deadline = Instant::now() + WAIT;
    let refusal = loop {
        match second.call(&request).await.unwrap() {
            Response::Error(r) if r.code == Code::InFlight && Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(5)).await
            }
            Response::Error(r) => break r,
            _ => panic!("an abandoned request was answered"),
        }
    };
    assert_eq!(refusal.code, Code::Uncertain);
    assert_eq!(up.hits(), 1, "no replay, no re-send");

    // Still uncertain after a restart.
    server.abort();
    let _ = server.await;
    drop(second);
    let rig = rig.reopen(BrokerOptions::default());
    let again = call(
        &token,
        "api",
        "POST",
        "/repos/o/r/issues",
        br#"{"title":"once"}"#,
    );
    assert_eq!(
        rig.forward(S, again).await.unwrap_err().code,
        Code::Uncertain
    );
    assert_eq!(up.hits(), 1);
}

#[tokio::test]
async fn tooth_dropped_exchange_future_marks_uncertain() {
    // The same guarantee at the engine boundary, which is what the HTTP
    // gateway relies on when hyper drops a handler on client disconnect.
    let up = Upstream::start(|_| Reply::Hang).await;
    let rig = Rig::new(&config(&up.origin));
    let token = rig.token("seat-a");
    let request = call(&token, "api", "POST", "/repos/o/r/issues", b"{}");
    let ticket = rig
        .broker
        .authorize(S, AGENT, request.clone(), CallKind::Buffered)
        .unwrap()
        .ticket;

    tokio::select! {
        _ = rig.forward(S, request.clone()) => panic!("a hung upstream answered"),
        _ = up.arrived() => {}
    }
    // Cancellation queues durable cleanup off the async worker. Until it
    // completes, InFlight still prevents duplicate upstream effects.
    tokio::time::timeout(WAIT, async {
        while rig.broker.ticket(ticket).unwrap().state == TicketState::InFlight {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        rig.broker.ticket(ticket).unwrap().state,
        TicketState::Uncertain
    );
    assert_eq!(
        rig.forward(S, request).await.unwrap_err().code,
        Code::Uncertain
    );
    assert_eq!(up.hits(), 1);
}

#[tokio::test]
async fn tooth_connect_failure_leaves_ticket_retryable() {
    // Nothing listens here: bind, read the port, close.
    let dead = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let rig = Rig::new(&config(&format!("http://{dead}")));
    let token = rig.token("seat-a");
    let request = call(&token, "api", "POST", "/repos/o/r/issues", b"{}");
    let refusal = rig.forward(S, request.clone()).await.unwrap_err();
    assert_eq!(refusal.code, Code::UpstreamFailed);
    // Nothing was sent, so the ticket is live again rather than uncertain.
    let authorized = rig
        .broker
        .authorize(S, AGENT, request, CallKind::Buffered)
        .unwrap();
    assert_eq!(authorized.state, "live");
}

// ----- audit-before-effect ------------------------------------------------------

#[tokio::test]
async fn tooth_audit_failure_refuses_before_any_upstream_connection() {
    let (_senders, script) = script(1);
    let up = Upstream::start(move |seen| {
        if seen.path == "/events" {
            script.next()
        } else {
            Reply::ok("{}")
        }
    })
    .await;
    let rig = Rig::new(&config(&up.origin));
    let token = rig.token("seat-a");
    let audit_path = rig.state().join("audit.log");
    let before = std::fs::read(&audit_path).unwrap();

    // Fault injection: the audit descriptor is read-only, so appends fail.
    let read_only = AuditLog::from_file(std::fs::File::open(&audit_path).unwrap());
    let rig = rig.reopen(BrokerOptions {
        audit: Some(read_only),
        ..Default::default()
    });

    let post = call(
        &token,
        "api",
        "POST",
        "/repos/o/r/issues",
        br#"{"title":"once"}"#,
    );
    let ticket = rig
        .broker
        .authorize(S, AGENT, post.clone(), CallKind::Buffered)
        .unwrap()
        .ticket;
    assert_eq!(
        rig.forward(S, post.clone()).await.unwrap_err().code,
        Code::AuditFailed
    );
    assert_eq!(
        rig.stream(S, call(&token, "api", "GET", "/events", b""))
            .await
            .unwrap_err()
            .code,
        Code::AuditFailed
    );
    assert_eq!(
        rig.forward(
            P,
            call(
                &token,
                "llm",
                "POST",
                "/v1/messages",
                &llm("m-small", 10, false)
            )
        )
        .await
        .unwrap_err()
        .code,
        Code::AuditFailed
    );

    assert_eq!(up.connections(), 0, "no TCP connection was even opened");
    assert_eq!(up.hits(), 0);
    assert_eq!(std::fs::read(&audit_path).unwrap(), before);
    // Operator changes fail closed too.
    assert_eq!(
        rig.broker
            .set(
                S,
                "api",
                keygate_core::secret::SecretBytes::new(b"sk-new-key-000001".to_vec()),
                false,
                false,
                OPERATOR
            )
            .unwrap_err()
            .code,
        Code::AuditFailed
    );
    // Nothing was sent, so the ticket is still live, and works once
    // auditing does.
    assert_eq!(rig.broker.ticket(ticket).unwrap().state, TicketState::Live);
    let rig = rig.reopen(BrokerOptions::default());
    let reply = rig.forward(S, post).await.unwrap();
    assert_eq!(reply.ticket, ticket);
    assert_eq!(up.hits(), 1);
    let audit = std::fs::read_to_string(&audit_path).unwrap();
    let begin = audit.find(r#""event":"begin""#).expect("Begin was audited");
    assert!(begin < audit.find(r#""event":"end""#).expect("End was audited"));
}

// ----- disjoint namespaces ------------------------------------------------------

#[tokio::test]
async fn tooth_provider_and_service_tables_are_disjoint() {
    let provider_up = Upstream::start(|_| Reply::ok(r#"{"from":"provider"}"#)).await;
    let service_up = Upstream::start(|_| Reply::ok(r#"{"from":"service"}"#)).await;
    // The same row name in both tables: unrelated rows.
    let config = format!(
        r#"
[providers.shared]
origin = "{}"
dialect = "anthropic-messages"
models = ["m-small"]
max_output_tokens = 1000

[services.shared]
origin = "{}"
methods = ["POST"]
buffered_paths = ["/v1/messages"]
"#,
        provider_up.origin, service_up.origin
    );
    let rig = Rig::unset(&config);
    rig.set(P, "shared", "provider-secret-0001", false);
    let token = rig.token("seat-a");
    let body = llm("m-small", 10, false);

    // Only the provider row has a secret; the service row of the same name
    // does not borrow it.
    assert_eq!(
        rig.forward(S, call(&token, "shared", "POST", "/v1/messages", &body))
            .await
            .unwrap_err()
            .code,
        Code::NoSecret
    );
    rig.set(S, "shared", "service-secret-0002", false);

    let p = rig
        .forward(P, call(&token, "shared", "POST", "/v1/messages", &body))
        .await
        .unwrap();
    let s = rig
        .forward(S, call(&token, "shared", "POST", "/v1/messages", &body))
        .await
        .unwrap();
    assert_eq!(
        (p.body.as_slice(), s.body.as_slice()),
        (
            br#"{"from":"provider"}"#.as_slice(),
            br#"{"from":"service"}"#.as_slice()
        )
    );
    assert_ne!(
        p.ticket, s.ticket,
        "identical requests in different namespaces are different tickets"
    );
    assert_eq!(
        provider_up.last().header("authorization"),
        Some("Bearer provider-secret-0001")
    );
    assert_eq!(
        service_up.last().header("authorization"),
        Some("Bearer service-secret-0002")
    );
    assert_eq!((provider_up.hits(), service_up.hits()), (1, 1));

    // A namespace caveat pins a token to one table.
    let provider_only = MacaroonV1::decode(&token)
        .unwrap()
        .attenuate(Caveat::Namespace(P))
        .unwrap()
        .encode();
    let mut pinned = call(&provider_only, "shared", "POST", "/v1/messages", &body);
    pinned.request_id = Some("pinned".into());
    assert_eq!(
        rig.forward(S, pinned.clone()).await.unwrap_err().code,
        Code::Denied
    );
    assert!(rig.forward(P, pinned).await.is_ok());

    // Revoking one table's row leaves the other's alone.
    rig.broker.revoke(P, "shared", false, OPERATOR).unwrap();
    let mut after = call(&token, "shared", "POST", "/v1/messages", &body);
    after.request_id = Some("after".into());
    assert_eq!(
        rig.forward(P, after.clone()).await.unwrap_err().code,
        Code::Revoked
    );
    assert!(rig.forward(S, after).await.is_ok());

    // On disk: a sealed blob moved into the other table does not open.
    let state = rig.state().to_owned();
    let Rig { dir, broker, .. } = rig;
    drop(broker);
    std::fs::copy(
        state.join("services/shared.sealed"),
        state.join("providers/shared.sealed"),
    )
    .unwrap();
    let boot = Broker::open(
        dir.path(),
        Config::parse(&development(&config)).unwrap(),
        BrokerOptions::default(),
    );
    assert!(matches!(
        boot,
        Err(BootError::Seal(SealError::Unauthentic {
            ns: Namespace::Provider,
            ..
        }))
    ));
}

#[tokio::test]
async fn tooth_each_table_is_optional_alone() {
    let up = counting_upstream().await;
    let full = config(&up.origin);
    let services_at = full.find("[services.api]").unwrap();
    let (broker_and_providers, services_only) = (&full[..services_at], &full[services_at..]);
    let token_for = |rig: &Rig| rig.token("seat-a");

    let rig = Rig::new(services_only);
    assert_eq!(rig.broker.namespaces(), vec![S]);
    assert!(rig
        .forward(S, call(&token_for(&rig), "api", "GET", "/repos/x", b""))
        .await
        .is_ok());
    let refusal = rig
        .forward(
            P,
            call(
                &token_for(&rig),
                "llm",
                "POST",
                "/v1/messages",
                &llm("m-small", 10, false),
            ),
        )
        .await
        .unwrap_err();
    assert_eq!(refusal.code, Code::NamespaceDisabled);

    let rig = Rig::new(broker_and_providers);
    assert_eq!(rig.broker.namespaces(), vec![P]);
    assert!(rig
        .forward(
            P,
            call(
                &token_for(&rig),
                "llm",
                "POST",
                "/v1/messages",
                &llm("m-small", 10, false)
            )
        )
        .await
        .is_ok());
    assert_eq!(
        rig.forward(S, call(&token_for(&rig), "api", "GET", "/repos/x", b""))
            .await
            .unwrap_err()
            .code,
        Code::NamespaceDisabled
    );

    // Neither table: refused at startup.
    let dir = tempfile::tempdir().unwrap();
    Broker::init_state(dir.path()).unwrap();
    assert!(matches!(
        Broker::open(dir.path(), Config::default(), BrokerOptions::default()),
        Err(BootError::ConfigFile(_))
    ));
}

// ----- provider policy ----------------------------------------------------------

#[tokio::test]
async fn tooth_provider_model_token_and_budget_checks() {
    let up = Upstream::start(|_| Reply::ok(r#"{"content":"hi"}"#)).await;
    let rig = Rig::new(&config(&up.origin));
    let token = rig.token("seat-a");
    let post = |id: &str, body: &[u8]| {
        let mut c = call(&token, "llm", "POST", "/v1/messages", body);
        c.request_id = Some(id.to_owned());
        c
    };
    let code = |result: Result<keygate_broker::BufferedReply, keygate_core::proto::Refusal>| {
        result.unwrap_err().code
    };

    assert_eq!(
        code(
            rig.forward(P, post("1", &llm("m-forbidden", 10, false)))
                .await
        ),
        Code::ModelRefused
    );
    assert_eq!(
        code(rig.forward(P, post("2", br#"{"max_tokens":10}"#)).await),
        Code::ModelRefused
    );
    // Parser-differential smuggling: which "model" wins is upstream-defined.
    assert_eq!(
        code(
            rig.forward(
                P,
                post(
                    "3",
                    br#"{"model":"m-small","model":"m-forbidden","max_tokens":10}"#
                )
            )
            .await
        ),
        Code::BadRequest
    );
    assert_eq!(
        code(
            rig.forward(P, post("4", &llm("m-small", 1001, false)))
                .await
        ),
        Code::TokenCapRefused
    );
    assert_eq!(
        code(rig.forward(P, post("5", br#"{"model":"m-small"}"#)).await),
        Code::TokenCapRefused
    );
    assert_eq!(
        code(
            rig.forward(
                P,
                post(
                    "6",
                    br#"{"model":"m-small","max_tokens":1,"max_tokens":1000000}"#
                )
            )
            .await
        ),
        Code::BadRequest
    );
    assert_eq!(
        code(rig.forward(P, post("7", b"not json")).await),
        Code::BadRequest
    );
    // The operation must match the body: no SSE through the buffered path.
    assert_eq!(
        code(rig.forward(P, post("8", &llm("m-small", 10, true))).await),
        Code::BadRequest
    );
    assert_eq!(
        rig.stream(P, post("9", &llm("m-small", 10, false)))
            .await
            .unwrap_err()
            .code,
        Code::BadRequest
    );
    let mut wrong_path = post("10", &llm("m-small", 10, false));
    wrong_path.path = "/v1/files".into();
    assert_eq!(code(rig.forward(P, wrong_path).await), Code::PathRefused);
    assert_eq!(up.hits(), 0, "every refusal happened before the network");

    // Daily ceiling: 2500 micro-USD at 1 per output token.
    assert!(rig
        .forward(P, post("a", &llm("m-small", 1000, false)))
        .await
        .is_ok());
    assert!(rig
        .forward(P, post("b", &llm("m-large", 1000, false)))
        .await
        .is_ok());
    assert_eq!(
        code(
            rig.forward(P, post("c", &llm("m-small", 1000, false)))
                .await
        ),
        Code::BudgetExceeded
    );
    // It is the row's ceiling, so another seat cannot slip past it...
    let mut other_seat = post("d", &llm("m-small", 1000, false));
    other_seat.token = rig.token("seat-b");
    assert_eq!(code(rig.forward(P, other_seat).await), Code::BudgetExceeded);
    // ...but a call that fits still goes through.
    assert!(rig
        .forward(P, post("e", &llm("m-small", 500, false)))
        .await
        .is_ok());
    assert_eq!(up.hits(), 3);
    assert_eq!(
        rig.broker
            .spent(&journal::row_day_key("llm", journal::utc_day(now_unix_s()))),
        2500
    );
}

#[tokio::test]
async fn tooth_macaroon_spend_cap_is_cumulative_across_attenuations() {
    let up = Upstream::start(|_| Reply::ok(r#"{"content":"hi"}"#)).await;
    let rig = Rig::new(&config(&up.origin).replace("per_day_micro_usd = 2500", ""));
    let capped = rig
        .broker
        .mint(
            "seat-a",
            None,
            vec![Caveat::MaxSpendMicroUsd(1500)],
            OPERATOR,
        )
        .unwrap();
    let child = MacaroonV1::decode(&capped)
        .unwrap()
        .attenuate(Caveat::Models(vec!["m-small".into()]))
        .unwrap()
        .encode();
    let post = |token: &str, id: &str, max_tokens: u64| {
        let mut c = call(
            token,
            "llm",
            "POST",
            "/v1/messages",
            &llm("m-small", max_tokens, false),
        );
        c.request_id = Some(id.to_owned());
        c
    };

    assert!(rig.forward(P, post(&capped, "1", 1000)).await.is_ok());
    // The child shares the parent's cap; attenuating does not reset it.
    assert_eq!(
        rig.forward(P, post(&child, "2", 1000))
            .await
            .unwrap_err()
            .code,
        Code::BudgetExceeded
    );
    assert_eq!(
        rig.forward(P, post(&capped, "3", 1000))
            .await
            .unwrap_err()
            .code,
        Code::BudgetExceeded
    );
    assert!(rig.forward(P, post(&child, "4", 500)).await.is_ok());
    assert_eq!(
        rig.forward(P, post(&child, "5", 1)).await.unwrap_err().code,
        Code::BudgetExceeded
    );
    // A caveat the child adds applies to the child alone.
    let large = call(
        &child,
        "llm",
        "POST",
        "/v1/messages",
        &llm("m-large", 1, false),
    );
    assert_eq!(rig.forward(P, large).await.unwrap_err().code, Code::Denied);
    // An unrelated token for the same seat has its own budget.
    assert!(rig
        .forward(P, post(&rig.token("seat-a"), "6", 1000))
        .await
        .is_ok());
    assert_eq!(up.hits(), 3);

    // The spend survives a restart.
    let rig = rig.reopen(BrokerOptions::default());
    assert_eq!(
        rig.forward(P, post(&capped, "7", 1))
            .await
            .unwrap_err()
            .code,
        Code::BudgetExceeded
    );
}

// ----- service path and header canonicalization --------------------------------

#[tokio::test]
async fn tooth_service_paths_headers_and_methods_are_canonical_or_refused() {
    let (senders, script) = script(1);
    let up = Upstream::start(move |seen| {
        if seen.path == "/events" {
            script.next()
        } else {
            Reply::ok("{}")
        }
    })
    .await;
    let rig = Rig::new(&config(&up.origin));
    let token = rig.token("seat-a");
    let get = |path: &str| call(&token, "api", "GET", path, b"");

    for path in [
        "/repos/%2e%2e/admin",
        "/repos/a%2Fb",
        "/repos/../admin",
        "/repos/./x",
        "/repos//x",
        "/repos/x/",
        "repos/x",
        "/repos/x#frag",
        "/repos/x?y=1",
        "/repos/x y",
        "/repos/x\\y",
        "/admin",
        "/reposx",
    ] {
        assert_eq!(
            rig.forward(S, get(path)).await.unwrap_err().code,
            Code::PathRefused,
            "{path}"
        );
    }
    // Buffered and stream prefixes do not substitute for each other.
    assert_eq!(
        rig.forward(S, get("/events")).await.unwrap_err().code,
        Code::PathRefused
    );
    assert_eq!(
        rig.stream(S, get("/repos/x")).await.unwrap_err().code,
        Code::PathRefused
    );

    let mut bad_query = get("/repos/x");
    bad_query.query = Some("a=1#frag".into());
    assert_eq!(
        rig.forward(S, bad_query).await.unwrap_err().code,
        Code::PathRefused
    );

    for method in ["DELETE", "get", "CONNECT"] {
        assert_eq!(
            rig.forward(S, call(&token, "api", method, "/repos/x", b""))
                .await
                .unwrap_err()
                .code,
            Code::MethodRefused,
            "{method}"
        );
    }
    for header in [
        "x-forwarded-for",
        "authorization",
        "host",
        "cookie",
        "accept-encoding",
    ] {
        let mut smuggle = get("/repos/x");
        smuggle.headers = vec![(header.to_owned(), "v".to_owned())];
        assert_eq!(
            rig.forward(S, smuggle).await.unwrap_err().code,
            Code::HeaderRefused,
            "{header}"
        );
    }
    assert_eq!(
        up.connections(),
        0,
        "every refusal happened before the network"
    );

    // What is allowed arrives exactly as asked.
    let mut ok = get("/repos/o/r");
    ok.query = Some("state=open&q=a%20b".into());
    ok.headers = vec![
        ("X-Trace".to_owned(), "t-1".to_owned()),
        ("accept".to_owned(), "application/json".to_owned()),
    ];
    rig.forward(S, ok).await.unwrap();
    let seen = up.last();
    assert_eq!(
        (seen.path.as_str(), seen.query.as_deref()),
        ("/repos/o/r", Some("state=open&q=a%20b"))
    );
    assert_eq!(
        (seen.header("x-trace"), seen.header("accept")),
        (Some("t-1"), Some("application/json"))
    );
    assert_eq!(
        seen.header("authorization"),
        Some(&*format!("Bearer {SECRET}"))
    );

    // A reconnect is a fresh ticket carrying Last-Event-ID.
    let mut resume = get("/events");
    resume.last_event_id = Some("41".into());
    let mut live = rig.live(S, resume).await;
    assert_eq!(up.last().header("last-event-id"), Some("41"));
    senders[0].send(bytes("id: 42\ndata: x\n\n")).unwrap();
    drop(senders);
    let (delivered, summary) = drain(&mut live).await;
    assert_eq!(delivered, b"id: 42\ndata: x\n\n");
    assert!(summary.complete);

    // ...and only where the row allows that header.
    let mut not_allowed = call(
        &token,
        "llm",
        "POST",
        "/v1/messages",
        &llm("m-small", 10, true),
    );
    not_allowed.last_event_id = Some("41".into());
    assert_eq!(
        rig.stream(P, not_allowed).await.unwrap_err().code,
        Code::HeaderRefused
    );
}

#[tokio::test]
async fn tooth_redirects_are_not_followed() {
    let elsewhere = counting_upstream().await;
    let location = format!("{}/steal", elsewhere.origin);
    let up = Upstream::start(move |_| Reply::Full {
        status: 302,
        headers: vec![("location", location.clone())],
        body: Vec::new(),
    })
    .await;
    let rig = Rig::new(&config(&up.origin));
    let reply = rig
        .forward(S, call(&rig.token("seat-a"), "api", "GET", "/repos/x", b""))
        .await
        .unwrap();
    assert_eq!(
        reply.status, 302,
        "the redirect is handed to the caller, not chased with the credential"
    );
    assert_eq!(elsewhere.connections(), 0);
}

// ----- transports ---------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tooth_unix_socket_protocol_end_to_end() {
    let (senders, script) = script(1);
    let up = Upstream::start(move |seen| {
        if seen.path == "/events" {
            script.next()
        } else {
            Reply::ok(r#"{"ok":true}"#)
        }
    })
    .await;
    let rig = Rig::unset(&config(&up.origin));
    let listeners = Listeners::bind(&rig.broker).await.unwrap();
    let socket = listeners.socket_path.clone();
    tokio::spawn(listeners.run(rig.broker.clone()));
    let mut client = Client::connect(&socket).await.unwrap();

    // The broker reads our uid from the kernel; we own the state dir, so
    // we are the operator.
    let Response::Hello {
        uid,
        operator,
        namespaces,
        ..
    } = client.call(&Request::Hello).await.unwrap()
    else {
        panic!("no hello")
    };
    assert!(operator);
    assert_eq!(namespaces, vec![P, S]);

    use base64::engine::general_purpose::STANDARD;
    let set = Request::Set {
        namespace: S,
        row: "api".into(),
        secret_b64: STANDARD.encode(SECRET),
        cut_existing: false,
        forget_retired: false,
    };
    assert!(matches!(client.call(&set).await.unwrap(), Response::Ok));
    let short = Request::Set {
        namespace: S,
        row: "api".into(),
        secret_b64: STANDARD.encode("short"),
        cut_existing: false,
        forget_retired: false,
    };
    assert!(
        matches!(client.call(&short).await.unwrap(), Response::Error(r) if r.code == Code::BadRequest)
    );

    let mint = Request::MintMacaroon {
        seat: "seat-a".into(),
        allowed_uid: Some(uid),
        caveats: vec![Caveat::Namespace(S)],
    };
    let Response::Token { token } = client.call(&mint).await.unwrap() else {
        panic!("no token")
    };
    let narrow = Request::Attenuate {
        token,
        caveats: vec![Caveat::Methods(vec!["GET".into()])],
    };
    let Response::Token { token } = client.call(&narrow).await.unwrap() else {
        panic!("no token")
    };

    let get = call(&token, "api", "GET", "/repos/o/r", b"");
    let authorize = Request::ServiceAuthorize(ServiceAuthorize {
        call: get.clone(),
        stream: false,
    });
    let Response::Authorized {
        ticket, existing, ..
    } = client.call(&authorize).await.unwrap()
    else {
        panic!("not authorized")
    };
    assert!(!existing);
    let Response::Reply {
        ticket: used,
        status,
        body,
        replayed,
        ..
    } = client
        .call(&Request::ServiceForward(get.clone()))
        .await
        .unwrap()
    else {
        panic!("no reply")
    };
    assert_eq!(
        (used, status, body.as_slice(), replayed),
        (ticket, 200, br#"{"ok":true}"#.as_slice(), false)
    );
    assert!(matches!(
        client.call(&Request::ServiceForward(get)).await.unwrap(),
        Response::Reply { replayed: true, .. }
    ));
    let post = Request::ServiceForward(call(&token, "api", "POST", "/repos/o/r", b"{}"));
    assert!(
        matches!(client.call(&post).await.unwrap(), Response::Error(r) if r.code == Code::Denied),
        "the Methods caveat binds"
    );
    assert_eq!(
        up.last().header("authorization"),
        Some(&*format!("Bearer {SECRET}"))
    );

    // Streaming: head, chunks as they arrive, then the closing summary.
    let events = Request::ServiceStream(call(&token, "api", "GET", "/events", b""));
    let Response::Head {
        ticket: stream_ticket,
        status,
        ..
    } = client.call(&events).await.unwrap()
    else {
        panic!("no head")
    };
    assert_eq!(status, 200);
    senders[0].send(bytes("data: one\n\n")).unwrap();
    assert!(
        matches!(client.recv().await.unwrap(), Response::Chunk { data } if data == b"data: one\n\n")
    );
    senders[0].send(bytes("data: two\n\n")).unwrap();
    assert!(
        matches!(client.recv().await.unwrap(), Response::Chunk { data } if data == b"data: two\n\n")
    );
    drop(senders);
    let Response::End {
        summary,
        spent,
        ticket: ended,
    } = client.recv().await.unwrap()
    else {
        panic!("no end")
    };
    assert!(summary.complete && !spent);
    assert_eq!((ended, summary.bytes), (stream_ticket, 22));
    // Retrying the spent stream ticket reports how it ended.
    let Response::End {
        summary: again,
        spent,
        ..
    } = client.call(&events).await.unwrap()
    else {
        panic!("no end")
    };
    assert!(spent);
    assert_eq!(again, summary);

    let Response::Rows { rows } = client.call(&Request::Ls).await.unwrap() else {
        panic!("no rows")
    };
    let states: Vec<_> = rows
        .iter()
        .map(|r| (r.namespace, r.row.as_str(), r.state.as_str()))
        .collect();
    assert_eq!(states, vec![(P, "llm", "unset"), (S, "api", "active")]);
    let Response::Status(status) = client.call(&Request::Status).await.unwrap() else {
        panic!("no status")
    };
    assert_eq!(
        (
            status.provider_rows,
            status.service_rows,
            status.guarded_secrets
        ),
        (Some(1), Some(1), 1)
    );

    assert!(matches!(
        client
            .call(&Request::Revoke {
                namespace: S,
                row: "api".into(),
                forget: false,
            })
            .await
            .unwrap(),
        Response::Ok
    ));
    let after = Request::ServiceForward(call(&token, "api", "GET", "/repos/after", b""));
    assert!(
        matches!(client.call(&after).await.unwrap(), Response::Error(r) if r.code == Code::Revoked)
    );

    // The socket is private to its owner by default.
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_no_plaintext(rig.state(), SECRET);

    // A peer that is not an operator gets data-plane access only.
    let not_us = config(&up.origin).replace(
        "[broker]",
        &format!("[broker]\noperator_uids = [{}]", uid + 1),
    );
    let rig = Rig::new(&not_us);
    let listeners = Listeners::bind(&rig.broker).await.unwrap();
    let socket = listeners.socket_path.clone();
    tokio::spawn(listeners.run(rig.broker.clone()));
    let mut client = Client::connect(&socket).await.unwrap();
    assert!(matches!(
        client.call(&Request::Hello).await.unwrap(),
        Response::Hello {
            operator: false,
            ..
        }
    ));
    let mint = Request::MintMacaroon {
        seat: "seat-a".into(),
        allowed_uid: None,
        caveats: vec![],
    };
    for operator_only in [
        mint,
        Request::Ls,
        Request::Status,
        Request::Revoke {
            namespace: S,
            row: "api".into(),
            forget: false,
        },
        Request::RevokeSeat {
            seat: "seat-a".into(),
        },
    ] {
        assert!(
            matches!(client.call(&operator_only).await.unwrap(), Response::Error(r) if r.code == Code::NotOperator)
        );
    }
    let set = Request::Set {
        namespace: S,
        row: "api".into(),
        secret_b64: STANDARD.encode("attacker-key-00001"),
        cut_existing: true,
        forget_retired: false,
    };
    assert!(
        matches!(client.call(&set).await.unwrap(), Response::Error(r) if r.code == Code::NotOperator)
    );
    let token = rig.token("seat-a");
    assert!(matches!(
        client
            .call(&Request::ServiceForward(call(
                &token, "api", "GET", "/repos/x", b""
            )))
            .await
            .unwrap(),
        Response::Reply { status: 200, .. }
    ));
    assert_eq!(
        up.last().header("authorization"),
        Some(&*format!("Bearer {SECRET}")),
        "the non-operator's set changed nothing"
    );
}

/// One raw HTTP/1.1 exchange, bypassing any client-side URL normalization.
async fn raw_http(addr: std::net::SocketAddr, request: String) -> String {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(WAIT, stream.read_to_end(&mut response))
        .await
        .expect("gateway did not answer")
        .unwrap();
    String::from_utf8_lossy(&response).into_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tooth_http_gateway_bearer_forward_and_sse() {
    let (senders, script) = script(2);
    let up = Upstream::start(move |seen| {
        if contains(&seen.body, br#""stream":true"#) {
            script.next()
        } else {
            Reply::ok(r#"{"content":"hello from upstream"}"#)
        }
    })
    .await;
    let cfg = config(&up.origin).replace("[broker]", "[broker]\nhttp_listen = \"127.0.0.1:0\"");
    let rig = Rig::new(&cfg);
    let listeners = Listeners::bind(&rig.broker).await.unwrap();
    let addr = listeners.http_addr.expect("gateway bound");
    assert!(addr.ip().is_loopback());
    tokio::spawn(listeners.run(rig.broker.clone()));
    let token = rig.token("seat-a");
    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    // What an SDK is configured with: a base URL and a "key".
    let base = format!("http://{addr}/v1/provider/llm");

    let response = http
        .post(format!("{base}/v1/messages"))
        .bearer_auth(&token)
        .header("anthropic-version", "2023-06-01")
        .header("x-stainless-lang", "js")
        .header("user-agent", "sdk/1.0")
        .body(llm("m-small", 100, false))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(response.headers().contains_key("x-keygate-ticket"));
    assert_eq!(
        response.text().await.unwrap(),
        r#"{"content":"hello from upstream"}"#
    );
    let seen = up.last();
    assert_eq!(seen.path, "/v1/messages");
    assert_eq!(
        seen.header("x-api-key"),
        Some(SECRET),
        "the upstream gets the sealed key"
    );
    assert_eq!(
        seen.header("anthropic-version"),
        Some("2023-06-01"),
        "allowlisted caller header forwarded"
    );
    assert!(
        seen.header("authorization").is_none(),
        "the macaroon never travels upstream"
    );
    assert!(
        seen.header("x-stainless-lang").is_none() && seen.header("user-agent").is_none(),
        "unlisted headers dropped"
    );
    assert!(!seen
        .headers
        .values()
        .any(|v| contains(v.as_bytes(), b"kgm_")));

    // The Anthropic SDK sends its key as x-api-key; an exact retry replays.
    let retry = http
        .post(format!("{base}/v1/messages"))
        .header("x-api-key", &token)
        .header("anthropic-version", "2023-06-01")
        .body(llm("m-small", 100, false))
        .send()
        .await
        .unwrap();
    assert_eq!(retry.status(), 200);
    assert_eq!(
        retry
            .headers()
            .get("x-keygate-replayed")
            .map(|v| v.as_bytes()),
        Some(b"true".as_slice())
    );
    assert_eq!(up.hits(), 1);

    // SSE: tokens arrive as the upstream produces them.
    let mut sse = http
        .post(format!("{base}/v1/messages"))
        .bearer_auth(&token)
        .body(llm("m-small", 100, true))
        .send()
        .await
        .unwrap();
    assert_eq!(sse.status(), 200);
    assert_eq!(
        sse.headers().get("content-type").unwrap(),
        "text/event-stream"
    );
    for event in [
        "data: {\"delta\":\"one\"}\n\n",
        "data: {\"delta\":\"two\"}\n\n",
    ] {
        senders[0].send(bytes(event)).unwrap();
        let chunk = tokio::time::timeout(WAIT, sse.chunk())
            .await
            .expect("SSE stalled")
            .unwrap()
            .expect("SSE ended early");
        assert_eq!(chunk, event);
    }
    drop(sse);
    tokio::time::timeout(WAIT, senders[0].closed())
        .await
        .expect("client hangup did not abort the upstream stream");

    // A stream that echoes the secret is broken off, not truncated quietly.
    let mut leaky = http
        .post(format!("{base}/v1/messages"))
        .bearer_auth(&token)
        .body(llm("m-large", 100, true))
        .send()
        .await
        .unwrap();
    senders[1].send(bytes("data: safe\n\n")).unwrap();
    assert_eq!(
        tokio::time::timeout(WAIT, leaky.chunk())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        "data: safe\n\n"
    );
    senders[1].send(bytes("data: sk-ant-secr")).unwrap();
    senders[1].send(bytes("et12345\n\n")).unwrap();
    let mut rest = Vec::new();
    let broken = loop {
        match tokio::time::timeout(WAIT, leaky.chunk())
            .await
            .expect("leaky stream stalled")
        {
            Ok(Some(chunk)) => rest.extend_from_slice(&chunk),
            Ok(None) => break false,
            Err(_) => break true,
        }
    };
    assert!(
        broken,
        "a cut stream must not look like a clean end of body"
    );
    // "data: " precedes the secret and may be delivered; nothing after it.
    assert!(
        b"data: ".starts_with(&rest),
        "leaked {:?}",
        String::from_utf8_lossy(&rest)
    );

    // Refusals.
    let unauthenticated = http
        .post(format!("{base}/v1/messages"))
        .bearer_auth("sk-ant-a-raw-key")
        .body(llm("m-small", 1, false))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), 401);
    let bound = rig
        .broker
        .mint("seat-a", Some(0), vec![], OPERATOR)
        .unwrap();
    let uid_bound = http
        .post(format!("{base}/v1/messages"))
        .bearer_auth(&bound)
        .body(llm("m-small", 2, false))
        .send()
        .await
        .unwrap();
    assert_eq!(
        uid_bound.status(),
        403,
        "uid-bound tokens need a transport with peer credentials"
    );
    let forbidden_model = http
        .post(format!("{base}/v1/messages"))
        .bearer_auth(&token)
        .body(llm("gpt-9", 1, false))
        .send()
        .await
        .unwrap();
    assert_eq!(forbidden_model.status(), 403);
    let body: serde_json::Value =
        serde_json::from_slice(&forbidden_model.bytes().await.unwrap()).unwrap();
    assert_eq!(body["error"]["code"], "model_refused");

    // Path tricks, sent raw so no client library tidies them first.
    let hits = up.hits();
    for path in [
        "/v1/service/api/repos/%2e%2e/admin",
        "/v1/service/api/repos/../admin",
        "/v1/service/api/repos//x",
        "/v1/service/api/repos/a%2fb",
    ] {
        let response = raw_http(addr, format!("GET {path} HTTP/1.1\r\nhost: x\r\nauthorization: Bearer {token}\r\nconnection: close\r\n\r\n")).await;
        assert!(response.starts_with("HTTP/1.1 400"), "{path}: {response}");
        assert!(response.contains("path_refused"), "{path}: {response}");
    }
    assert_eq!(up.hits(), hits);

    // Service rows work the same way; reads are never served stale.
    let service = format!("http://{addr}/v1/service/api/repos/o/r?state=open");
    for _ in 0..2 {
        let response = http.get(&service).bearer_auth(&token).send().await.unwrap();
        assert_eq!(response.status(), 200);
        assert!(!response.headers().contains_key("x-keygate-replayed"));
    }
    assert_eq!(up.hits(), hits + 2);
    assert_eq!(
        (up.last().path.as_str(), up.last().query.as_deref()),
        ("/repos/o/r", Some("state=open"))
    );
    assert_eq!(
        up.last().header("authorization"),
        Some(&*format!("Bearer {SECRET}"))
    );
}

#[tokio::test]
async fn tooth_gateway_refuses_non_loopback_bind() {
    assert!(keygate_broker::gateway::bind("0.0.0.0:0".parse().unwrap())
        .await
        .is_err());
    assert!(Config::parse("[broker]\nhttp_listen = \"0.0.0.0:8787\"\n[services.a]\norigin = \"https://a.example\"\nbuffered_paths = [\"/x\"]\n").is_err());
}

#[tokio::test]
async fn tooth_secrets_are_sealed_at_rest_and_short_ones_refused() {
    let up = counting_upstream().await;
    let rig = Rig::new(&config(&up.origin));
    assert_no_plaintext(rig.state(), SECRET);
    let sealed = std::fs::metadata(rig.state().join("services/api.sealed")).unwrap();
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(sealed.permissions().mode() & 0o777, 0o600);
    for (path, _) in files_under(rig.state()) {
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode & 0o077,
            0,
            "{} is readable beyond its owner ({mode:o})",
            path.display()
        );
    }

    let set = |secret: &[u8]| {
        rig.broker.set(
            S,
            "api",
            keygate_core::secret::SecretBytes::new(secret.to_vec()),
            false,
            false,
            OPERATOR,
        )
    };
    assert_eq!(set(b"short").unwrap_err().code, Code::BadRequest);
    assert_eq!(
        set(b"has\nnewline-in-it").unwrap_err().code,
        Code::BadRequest
    );
    assert_eq!(
        set(b" leading-space-key").unwrap_err().code,
        Code::BadRequest
    );
    assert_eq!(
        rig.broker
            .set(
                S,
                "nope",
                keygate_core::secret::SecretBytes::new(b"long-enough-key".to_vec()),
                false,
                false,
                OPERATOR
            )
            .unwrap_err()
            .code,
        Code::UnknownRow
    );
    // A failed set leaves the working secret in place.
    let token = rig.token("seat-a");
    assert!(rig
        .forward(S, call(&token, "api", "GET", "/repos/x", b""))
        .await
        .is_ok());
    assert_eq!(
        up.last().header("authorization"),
        Some(&*format!("Bearer {SECRET}"))
    );
}

/// #tooth: n cannot multiply completion output outside either cap or budget.
#[tokio::test]
async fn tooth_completion_count_is_capped_and_reserved() {
    let up = counting_upstream().await;
    let cfg = config(&up.origin).replace("per_day_micro_usd = 2500", "per_day_micro_usd = 1000");
    let rig = Rig::new(&cfg);
    let token = rig.token("seat-a");
    for (n, cap) in [(0, 1), (17, 1), (100, 4096), (2, 501), (16, u64::MAX)] {
        let body = serde_json::json!({"model":"m-small", "max_tokens":cap, "n":n}).to_string();
        assert_eq!(
            rig.forward(
                P,
                call(&token, "llm", "POST", "/v1/messages", body.as_bytes())
            )
            .await
            .unwrap_err()
            .code,
            Code::TokenCapRefused
        );
    }
    for n in ["-1", "1.5", "\"2\""] {
        let body = format!(r#"{{"model":"m-small","max_tokens":1,"n":{n}}}"#);
        assert_eq!(
            rig.forward(
                P,
                call(&token, "llm", "POST", "/v1/messages", body.as_bytes())
            )
            .await
            .unwrap_err()
            .code,
            Code::BadRequest
        );
    }
    assert_eq!(up.hits(), 0);
    let body = br#"{"model":"m-small","max_tokens":250,"n":4}"#;
    let request = call(&token, "llm", "POST", "/v1/messages", body);
    let auth = rig
        .broker
        .authorize(P, AGENT, request.clone(), CallKind::Buffered)
        .unwrap();
    assert_eq!(auth.reserved_micro_usd, 1000);
    rig.forward(P, request).await.unwrap();
    let next = call(
        &token,
        "llm",
        "POST",
        "/v1/messages",
        &llm("m-small", 1, false),
    );
    assert_eq!(
        rig.forward(P, next).await.unwrap_err().code,
        Code::BudgetExceeded
    );
    assert_eq!(up.hits(), 1);
}

/// #tooth: cached Anthropic input is charged, in buffered and SSE replies;
/// OpenAI's final usage is recognized across arbitrary chunk boundaries.
#[tokio::test]
async fn tooth_cache_and_stream_usage_settle_exactly() {
    let (senders, script) = script(2);
    let up = Upstream::start(move |seen| {
        if contains(&seen.body, br#""stream":true"#) { script.next() }
        else { Reply::ok(r#"{"usage":{"input_tokens":1,"cache_creation_input_tokens":20,"cache_read_input_tokens":300,"output_tokens":4}}"#) }
    }).await;
    let cfg = config(&up.origin)
        .replace(
            "output_micro_usd_per_mtok = 1000000",
            "input_micro_usd_per_mtok = 1000000\noutput_micro_usd_per_mtok = 2000000\ncache_write_micro_usd_per_mtok = 1250000\ncache_read_micro_usd_per_mtok = 100000",
        )
        .replace("per_day_micro_usd = 2500", "per_day_micro_usd = 100000");
    let rig = Rig::new(&cfg);
    let token = rig.token("seat-a");
    let reply = rig
        .forward(
            P,
            call(
                &token,
                "llm",
                "POST",
                "/v1/messages",
                &llm("m-small", 1000, false),
            ),
        )
        .await
        .unwrap();
    // 1 input at 1, 20 cache writes at 1.25, 300 cache reads at 0.1, 4
    // output at 2 micro-USD per token: 1 + 25 + 30 + 8.
    assert_eq!(
        rig.broker.ticket(reply.ticket).unwrap().reserved_micro_usd,
        64
    );
    let fixtures = [
        ("event: message_start\r\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":1,\"cache_creation_input_tokens\":20,\"cache_read_input_tokens\":300,\"output_tokens\":0}}}\r\n\r\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":4}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n", 64),
        ("data: {\"choices\":[],\"usage\":null}\n\ndata: {\"usage\":{\"prompt_tokens\":12,\"completion_tokens\":7,\"prompt_tokens_details\":{\"cached_tokens\":10}}}\n\ndata: [DONE]\n\n", 26),
    ];
    for ((fixture, expected), sender) in fixtures.into_iter().zip(senders) {
        let mut request = call(
            &token,
            "llm",
            "POST",
            "/v1/messages",
            &llm("m-small", 1000, true),
        );
        request.request_id = Some(expected.to_string());
        let mut live = rig.live(P, request.clone()).await;
        for byte in fixture.bytes() {
            sender.send(Bytes::from(vec![byte])).unwrap();
        }
        drop(sender);
        let (delivered, summary) = drain(&mut live).await;
        assert!(summary.complete);
        assert_eq!(delivered, fixture.as_bytes());
        assert_eq!(
            rig.broker.ticket(live.ticket).unwrap().reserved_micro_usd,
            expected
        );
        assert!(matches!(
            rig.stream(P, request).await.unwrap(),
            StreamOutcome::Spent { .. }
        ));
    }
    assert_eq!(
        rig.broker
            .spent(&journal::row_day_key("llm", journal::utc_day(now_unix_s()))),
        64 + 64 + 26
    );
}

/// #tooth: partial/missing usage and abnormal endings cannot release budget.
#[tokio::test]
async fn tooth_stream_incomplete_or_aborted_usage_keeps_reservation() {
    let (senders, script) = script(5);
    let up = Upstream::start(move |_| script.next()).await;
    let cfg = config(&up.origin).replace("per_day_micro_usd = 2500", "per_day_micro_usd = 10000");
    let rig = Rig::new(&cfg);
    for (i, sender) in senders.into_iter().enumerate() {
        let token = rig.token("seat-a");
        let mut request = call(
            &token,
            "llm",
            "POST",
            "/v1/messages",
            &llm("m-small", 100, true),
        );
        request.request_id = Some(i.to_string());
        let mut live = rig.live(P, request).await;
        let data = match i {
            0 => "data: {\"text\":\"no usage\"}\n\n",
            1 => "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}}\n\n",
            _ => "data: {\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1}}\n\n",
        };
        sender.send(Bytes::from(data)).unwrap();
        assert_eq!(next_chunk(&mut live).await, data);
        match i {
            2 => {
                rig.broker.revoke_seat("seat-a", OPERATOR).unwrap();
                let (_, summary) = drain(&mut live).await;
                assert!(summary.revoked);
            }
            3 => {
                sender.send(Bytes::from_static(SECRET.as_bytes())).unwrap();
                assert!(drain(&mut live).await.1.withheld);
            }
            4 => {
                let id = live.ticket;
                drop(live);
                tokio::time::timeout(WAIT, sender.closed()).await.unwrap();
                tokio::time::timeout(WAIT, async {
                    while !matches!(rig.broker.ticket(id).unwrap().state, TicketState::Closed(_)) {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
                assert_eq!(rig.broker.ticket(id).unwrap().reserved_micro_usd, 100);
                continue;
            }
            _ => {
                drop(sender);
                assert!(drain(&mut live).await.1.complete);
            }
        }
        assert_eq!(
            rig.broker.ticket(live.ticket).unwrap().reserved_micro_usd,
            100
        );
    }
}

/// #tooth: seat revocation cuts buffered calls, pre-head streams and idle
/// live streams, but cannot cut another seat using the same row.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tooth_seat_revocation_cuts_all_flight_phases() {
    let (senders, script) = script(2);
    let up = Upstream::start(move |seen| {
        if seen.path == "/events/live" {
            script.next()
        } else {
            Reply::Hang
        }
    })
    .await;
    let rig = Rig::new(&config(&up.origin));
    let token = rig.token("seat-a");
    let other = rig.token("seat-b");
    let mut live = rig
        .live(S, call(&token, "api", "GET", "/events/live", b""))
        .await;
    let mut survivor = rig
        .live(S, call(&other, "api", "GET", "/events/live", b""))
        .await;
    // Consume arrival notifications before starting each hung exchange.
    up.arrived().await;
    let buffered = tokio::spawn({
        let broker = rig.broker.clone();
        let token = token.clone();
        async move {
            broker
                .forward(
                    S,
                    AGENT,
                    call(&token, "api", "POST", "/repos/hang", b"{}"),
                    HeaderMode::Strict,
                )
                .await
        }
    });
    up.arrived().await;
    let prehead = tokio::spawn({
        let broker = rig.broker.clone();
        let token = token.clone();
        async move {
            broker
                .stream(
                    S,
                    AGENT,
                    call(&token, "api", "GET", "/events/hang", b""),
                    HeaderMode::Strict,
                )
                .await
        }
    });
    up.arrived().await;
    rig.broker.revoke_seat("seat-a", OPERATOR).unwrap();
    assert!(drain(&mut live).await.1.revoked);
    assert_eq!(
        tokio::time::timeout(WAIT, buffered)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err()
            .code,
        Code::Revoked
    );
    assert_eq!(
        tokio::time::timeout(WAIT, prehead)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err()
            .code,
        Code::Revoked
    );
    senders[1].send(bytes("data: still alive\n\n")).unwrap();
    assert_eq!(next_chunk(&mut survivor).await, "data: still alive\n\n");
    assert_eq!(
        rig.forward(S, call(&token, "api", "GET", "/repos/new", b""))
            .await
            .unwrap_err()
            .code,
        Code::Denied
    );
}

/// #tooth: an audit failure is explicit after seat revocation and the
/// revocation remains effective across restart.
#[tokio::test]
async fn tooth_revoke_seat_audit_failure_is_reported() {
    let up = counting_upstream().await;
    let rig = Rig::new(&config(&up.origin));
    let token = rig.token("seat-a");
    let audit = AuditLog::from_file(std::fs::File::open(rig.state().join("audit.log")).unwrap());
    let rig = rig.reopen(BrokerOptions {
        audit: Some(audit),
        ..Default::default()
    });
    let refusal = rig.broker.revoke_seat("seat-a", OPERATOR).unwrap_err();
    assert_eq!(refusal.code, Code::AuditFailed);
    assert!(refusal.message.contains("IS revoked"));
    let rig = rig.reopen(BrokerOptions::default());
    assert_eq!(
        rig.forward(S, call(&token, "api", "GET", "/repos", b""))
            .await
            .unwrap_err()
            .code,
        Code::Denied
    );
    assert_eq!(up.hits(), 0);
}

/// #tooth: rotation while waiting for a stream head cannot replace the
/// scrubber protecting the credential already sent upstream.
#[tokio::test]
async fn tooth_rotation_before_stream_head_keeps_old_secret_guarded() {
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let rig = Rig::new(&config(&origin));
    // Ensure there is no second row retaining the same old secret.
    rig.set(P, "llm", "another-secret-98765", false);
    let token = rig.token("seat-a");
    let (arrived_tx, arrived_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let gates = std::sync::Mutex::new(Some((arrived_tx, release_rx)));
        let service = service_fn(move |_req: hyper::Request<hyper::body::Incoming>| {
            let (arrived, release) = gates.lock().unwrap().take().unwrap();
            async move {
                arrived.send(()).unwrap();
                release.await.unwrap();
                Ok::<_, std::convert::Infallible>(
                    hyper::Response::builder()
                        .header("x-echo", SECRET)
                        .body(http_body_util::Full::new(Bytes::from_static(
                            b"data: ok\n\n",
                        )))
                        .unwrap(),
                )
            }
        });
        hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(socket), service)
            .await
            .unwrap();
    });
    let exchange = tokio::spawn({
        let broker = rig.broker.clone();
        async move {
            broker
                .stream(
                    S,
                    AGENT,
                    call(&token, "api", "GET", "/events", b""),
                    HeaderMode::Strict,
                )
                .await
        }
    });
    arrived_rx.await.unwrap();
    rig.set(S, "api", "rotated-secret-98765", false);
    release_tx.send(()).unwrap();
    assert_eq!(
        tokio::time::timeout(WAIT, exchange)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err()
            .code,
        Code::Withheld
    );
    server.abort();
}

/// #tooth: gateway reconnect state is forwarded or explicitly refused;
/// bare row routes and a trailing slash both reach the upstream root.
#[tokio::test]
async fn tooth_gateway_root_and_last_event_id() {
    let up = counting_upstream().await;
    let cfg = config(&up.origin)
        .replace("[broker]", "[broker]\nhttp_listen = \"127.0.0.1:0\"")
        .replace("buffered_paths = [\"/repos\"]", "buffered_paths = [\"/\"]");
    let rig = Rig::new(&cfg);
    let token = rig.token("seat-a");
    let listeners = Listeners::bind(&rig.broker).await.unwrap();
    let addr = listeners.http_addr.unwrap();
    let server = tokio::spawn(listeners.run(rig.broker.clone()));
    for suffix in ["", "/"] {
        let response = raw_http(addr, format!("GET /v1/service/api{suffix} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nLast-Event-ID: event-42\r\nConnection: close\r\n\r\n")).await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert_eq!(up.last().path, "/");
        assert_eq!(up.last().header("last-event-id"), Some("event-42"));
    }
    let response = raw_http(addr, format!("POST /v1/provider/llm/v1/messages HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nLast-Event-ID: forbidden\r\nContent-Length: 34\r\nConnection: close\r\n\r\n{{\"model\":\"m-small\",\"max_tokens\":1}}")).await;
    assert!(response.contains("header_refused"), "{response}");
    assert_eq!(up.hits(), 2);
    server.abort();
}

fn framed(request: &Request) -> Vec<u8> {
    let body = serde_json::to_vec(request).unwrap();
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&body);
    frame
}

/// #tooth: queued frames cannot disable hangup detection for either a
/// buffered call or an idle SSE stream; read-ahead also preserves frames.
#[tokio::test]
async fn tooth_unix_pipelined_hangup_and_frame_preservation() {
    let (senders, script) = script(2);
    let up = Upstream::start(move |seen| {
        if seen.path == "/events" {
            script.next()
        } else {
            Reply::Hang
        }
    })
    .await;
    let rig = Rig::new(&config(&up.origin));
    let token = rig.token("seat-a");
    let listeners = Listeners::bind(&rig.broker).await.unwrap();
    let socket = listeners.socket_path.clone();
    let server = tokio::spawn(listeners.run(rig.broker.clone()));
    for kind in [CallKind::Buffered, CallKind::Stream] {
        let (method, path) = if kind == CallKind::Buffered {
            ("POST", "/repos/hang")
        } else {
            ("GET", "/events")
        };
        let request = call(&token, "api", method, path, b"");
        let ticket = rig
            .broker
            .authorize(S, AGENT, request.clone(), kind)
            .unwrap()
            .ticket;
        let wire = if kind == CallKind::Buffered {
            Request::ServiceForward(request)
        } else {
            Request::ServiceStream(request)
        };
        let mut input = framed(&wire);
        input.extend(framed(&Request::Hello));
        let mut peer = tokio::net::UnixStream::connect(&socket).await.unwrap();
        peer.write_all(&input).await.unwrap();
        up.arrived().await;
        if kind == CallKind::Stream {
            let head = keygate_broker::wire::read_frame(&mut peer)
                .await
                .unwrap()
                .unwrap();
            assert!(matches!(
                serde_json::from_slice::<Response>(&head).unwrap(),
                Response::Head { .. }
            ));
        }
        drop(peer);
        tokio::time::timeout(WAIT, async {
            loop {
                let state = rig.broker.ticket(ticket).unwrap().state;
                if kind == CallKind::Buffered && state == TicketState::Uncertain {
                    break;
                }
                if let TicketState::Closed(summary) = state {
                    assert_eq!(summary.closed_by, ClosedBy::CallerDisconnect);
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
    tokio::time::timeout(WAIT, senders[0].closed())
        .await
        .unwrap();
    // Successful streaming keeps the queued frame intact for the next dispatch.
    let mut peer = tokio::net::UnixStream::connect(&socket).await.unwrap();
    let mut request = call(&token, "api", "GET", "/events", b"");
    request.request_id = Some("second-stream".into());
    let mut input = framed(&Request::ServiceStream(request));
    input.extend(framed(&Request::Hello));
    peer.write_all(&input).await.unwrap();
    let head = keygate_broker::wire::read_frame(&mut peer)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        serde_json::from_slice::<Response>(&head).unwrap(),
        Response::Head { .. }
    ));
    drop(senders);
    for expected_end in [true, false] {
        let frame = tokio::time::timeout(WAIT, keygate_broker::wire::read_frame(&mut peer))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let response: Response = serde_json::from_slice(&frame).unwrap();
        if expected_end {
            assert!(matches!(response, Response::End { .. }));
        } else {
            assert!(matches!(response, Response::Hello { .. }));
        }
    }
    server.abort();
}

/// #tooth: each transport's connection permit lasts for the entire socket
/// lifetime and is released on disconnect, including idle connections.
#[tokio::test]
async fn tooth_both_transports_bound_connections() {
    let up = counting_upstream().await;
    let cfg = config(&up.origin).replace(
        "[broker]",
        "[broker]\nmax_connections = 1\nhttp_listen = \"127.0.0.1:0\"",
    );
    let rig = Rig::new(&cfg);
    let token = rig.token("seat-a");
    let listeners = Listeners::bind(&rig.broker).await.unwrap();
    let socket = listeners.socket_path.clone();
    let addr = listeners.http_addr.unwrap();
    let server = tokio::spawn(listeners.run(rig.broker.clone()));
    let mut first = Client::connect(&socket).await.unwrap();
    assert!(matches!(
        first.call(&Request::Hello).await.unwrap(),
        Response::Hello { .. }
    ));
    let mut second = Client::connect(&socket).await.unwrap();
    second.send(&Request::Hello).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(30), second.recv())
            .await
            .is_err()
    );
    drop(first);
    assert!(matches!(
        tokio::time::timeout(WAIT, second.recv())
            .await
            .unwrap()
            .unwrap(),
        Response::Hello { .. }
    ));
    let mut first = tokio::net::TcpStream::connect(addr).await.unwrap();
    first.write_all(format!("GET /v1/service/api/repos HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\n\r\n").as_bytes()).await.unwrap();
    let mut header_byte = [0u8; 1];
    tokio::time::timeout(WAIT, first.read_exact(&mut header_byte))
        .await
        .unwrap()
        .unwrap();
    let mut second = tokio::net::TcpStream::connect(addr).await.unwrap();
    second.write_all(format!("GET /v1/service/api/repos HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    assert!(tokio::time::timeout(
        Duration::from_millis(30),
        second.read_exact(&mut header_byte)
    )
    .await
    .is_err());
    assert_eq!(up.hits(), 1);
    drop(first);
    let mut response = Vec::new();
    tokio::time::timeout(WAIT, second.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"));
    assert_eq!(up.hits(), 2);
    server.abort();
}

/// #tooth: admission uses the short Live TTL, while terminal reply retention
/// remains long; connect rollback also restores the short deadline.
#[tokio::test]
async fn tooth_live_deadline_is_distinct_from_reply_retention() {
    let up = counting_upstream().await;
    let cfg = config(&up.origin).replace("retention_s = 600", "retention_s = 600\nlive_ttl_s = 7");
    let rig = Rig::new(&cfg);
    let token = rig.token("seat-a");
    let request = call(&token, "api", "GET", "/repos", b"");
    let start = now_unix_s();
    let auth = rig
        .broker
        .authorize(S, AGENT, request.clone(), CallKind::Buffered)
        .unwrap();
    let ticket = rig.broker.ticket(auth.ticket).unwrap();
    assert!((start + 7..=now_unix_s() + 7).contains(&ticket.expires_unix_s));
    rig.forward(S, request).await.unwrap();
    assert!(rig.broker.ticket(auth.ticket).unwrap().expires_unix_s >= start + 600);
    let dead = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let rig = Rig::new(&cfg.replace(&up.origin, &format!("http://{dead}")));
    let token = rig.token("seat-a");
    let request = call(&token, "api", "GET", "/repos", b"");
    assert_eq!(
        rig.forward(S, request.clone()).await.unwrap_err().code,
        Code::UpstreamFailed
    );
    let auth = rig
        .broker
        .authorize(S, AGENT, request, CallKind::Buffered)
        .unwrap();
    assert!(rig.broker.ticket(auth.ticket).unwrap().expires_unix_s <= now_unix_s() + 7);
}

/// #tooth: a transport error after a valid usage event still retains the
/// reservation; receiving usage does not prove the stream completed.
#[tokio::test]
async fn tooth_upstream_error_after_usage_keeps_reservation() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rig = Rig::new(&config(&format!(
        "http://{}",
        listener.local_addr().unwrap()
    )));
    let token = rig.token("seat-a");
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut byte = [0u8];
        while !request.ends_with(b"\r\n\r\n") {
            socket.read_exact(&mut byte).await.unwrap();
            request.push(byte[0]);
        }
        let text = String::from_utf8(request).unwrap();
        let length: usize = text
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .map(str::to_owned)
            })
            .unwrap()
            .parse()
            .unwrap();
        socket.read_exact(&mut vec![0; length]).await.unwrap();
        let data = "data: {\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1}}\n\n";
        socket
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{data}\r\n",
                    data.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        // No terminating zero chunk: an incomplete transfer.
        socket.shutdown().await.unwrap();
    });
    let mut live = rig
        .live(
            P,
            call(
                &token,
                "llm",
                "POST",
                "/v1/messages",
                &llm("m-small", 100, true),
            ),
        )
        .await;
    let (_, summary) = drain(&mut live).await;
    assert_eq!(summary.closed_by, ClosedBy::UpstreamError);
    assert_eq!(
        rig.broker.ticket(live.ticket).unwrap().reserved_micro_usd,
        100
    );
    server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn git_land_reconciles_lost_replies_and_retries_only_with_the_original_cas() {
    use keygate_core::git_land::GitLand;
    use std::sync::Arc;
    fn git(repo: &std::path::Path, args: &[&str]) -> String {
        let out = std::process::Command::new("git")
            .current_dir(repo)
            .args(["-c", "user.name=B", "-c", "user.email=b@example.org"])
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    }
    let dir = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| git(dir.path(), args);
    run(&["init", "--bare"]);
    let tree = run(&["mktree"]);
    let old = run(&["commit-tree", &tree, "-m", "base"]);
    let child = |parent: &str, msg: &str| run(&["commit-tree", &tree, "-p", parent, "-m", msg]);
    let new = child(&old, "land");
    let later = child(&new, "later");
    let other = child(&old, "diverged");
    let reference = "refs/heads/main";
    run(&["update-ref", reference, &old]);
    let repo = dir.path().to_owned();
    let calls = AtomicUsize::new(0);
    let changed = Arc::new(tokio::sync::Notify::new());
    let signal = changed.clone();
    let up = Upstream::start(move |req| {
        if calls.fetch_add(1, Ordering::SeqCst) == 1 {
            let cas: GitLand = serde_json::from_slice(&req.body).unwrap();
            git(
                &repo,
                &[
                    "update-ref",
                    &cas.reference,
                    &cas.new_oid,
                    &cas.expected_old,
                ],
            );
            signal.notify_one();
        }
        Reply::Hang
    })
    .await;
    let binding = format!(
        "git_land_targets = {{ api = {:?} }}\ngit_land_micro_usd = 3",
        dir.path()
    );
    let cfg = config(&up.origin)
        .replace("[broker]", &format!("[broker]\n{binding}"))
        .replace("/repos", "/git/land");
    let rig = Rig::new(&cfg);
    let root = rig.token("agent");
    let scope = Caveat::GitRef {
        repo: "api".into(),
        reference: reference.into(),
    };
    let token = Broker::attenuate(
        &root,
        vec![
            scope,
            Caveat::Seat("agent".into()),
            Caveat::MaxSpendMicroUsd(3),
        ],
    )
    .unwrap();
    let git_token = |land: bool| {
        let routes = keygate_core::macaroon::WorkerRoutes {
            claim: None,
            done: None,
            land: land.then(|| "api".into()),
            reconcile: (!land).then(|| "api".into()),
        };
        Broker::attenuate(&token, vec![Caveat::WorkerRoutes(routes)]).unwrap()
    };
    let land_token = git_token(true);
    let reconcile_token = git_token(false);
    let request = |reference: &str| {
        let body = serde_json::json!({"repo":"api","reference":reference,"expected_old":old,"new_oid":new});
        call(
            &land_token,
            "api",
            "POST",
            "/git/land",
            body.to_string().as_bytes(),
        )
    };
    let reserve = |call| rig.broker.authorize(S, AGENT, call, CallKind::Buffered);
    assert_eq!(
        reserve(request("refs/heads/other")).unwrap_err().code,
        Code::Denied
    );
    let req = request(reference);
    let id = reserve(req.clone()).unwrap().ticket;
    let mut distinct = req.clone();
    distinct.request_id = Some("second charge".into());
    assert_eq!(reserve(distinct).unwrap_err().code, Code::BudgetExceeded);
    let send = || {
        let (broker, call) = (rig.broker.clone(), req.clone());
        tokio::spawn(async move { broker.forward(S, AGENT, call, HeaderMode::Strict).await })
    };
    let lost = || async {
        tokio::time::timeout(WAIT, async {
            while rig.broker.ticket(id).unwrap().state == TicketState::InFlight {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    };
    let first = send();
    up.arrived().await;
    first.abort();
    let _ = first.await;
    lost().await;
    let reconcile = |call| rig.broker.reconcile_git_push(AGENT, call, id);
    assert_eq!(reconcile(req.clone()).unwrap_err().code, Code::Denied);
    let mut settle = req.clone();
    settle.token = reconcile_token;
    assert_eq!(reserve(settle.clone()).unwrap_err().code, Code::Denied);
    let mut impostor = req.clone();
    impostor.token = root;
    assert!(reconcile(impostor).is_err());
    run(&["update-ref", reference, &other, &old]);
    assert_eq!(reconcile(settle.clone()).unwrap(), TicketState::Uncertain);
    run(&["update-ref", reference, &old, &other]);
    assert_eq!(reconcile(settle.clone()).unwrap(), TicketState::SafeToRetry);
    assert_eq!(up.hits(), 1);
    let second = send();
    tokio::time::timeout(WAIT, changed.notified())
        .await
        .unwrap();
    second.abort();
    let _ = second.await;
    lost().await;
    run(&["update-ref", reference, &later, &new]);
    let rig = rig.reopen(BrokerOptions::default());
    let state = rig.broker.reconcile_git_push(AGENT, settle, id).unwrap();
    assert_eq!(state, TicketState::Committed);
    assert_eq!(rig.broker.ticket(id).unwrap().reserved_micro_usd, 3);
    assert!(rig.forward(S, req).await.is_err());
    assert_eq!(up.hits(), 2);
}
