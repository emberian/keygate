//! `#tooth` regressions for the second-order audit: each test drives the
//! real broker over its real boundary (engine API, Unix socket, loopback
//! HTTP) and pins one finding's fix.

mod common;

use base64::{engine::general_purpose::STANDARD, Engine};
use bytes::Bytes;
use common::*;
use keygate_broker::client::Client;
use keygate_broker::harden::effective_uid;
use keygate_broker::wire::{read_frame, write_frame};
use keygate_broker::{Broker, BrokerOptions, Caller, HeaderMode, Listeners, StreamOutcome};
use keygate_core::config::Config;
use keygate_core::echo::guard_cost;
use keygate_core::journal::{self, CallKind, ClosedBy, JournalFaults, TicketState};
use keygate_core::macaroon::{Caveat, MacaroonV1};
use keygate_core::proto::{Call, Code, Refusal, Request, Response, PREAUTH_FRAME_BYTES};
use keygate_core::secret::SecretBytes;
use keygate_core::Namespace;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const P: Namespace = Namespace::Provider;
const S: Namespace = Namespace::Service;

fn bytes(s: &'static str) -> Bytes {
    Bytes::from_static(s.as_bytes())
}

fn secret(s: &str) -> SecretBytes {
    SecretBytes::new(s.as_bytes().to_vec())
}

fn attenuate(token: &str, caveat: Caveat) -> String {
    MacaroonV1::decode(token)
        .unwrap()
        .attenuate(caveat)
        .unwrap()
        .encode()
}

/// A call with its own request id, so tickets are never shared by accident.
fn fresh(mut call: Call) -> Call {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    call.request_id = Some(format!("fresh-{}", NEXT.fetch_add(1, Ordering::SeqCst)));
    call
}

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

fn code<T: std::fmt::Debug>(result: Result<T, Refusal>) -> Code {
    result.unwrap_err().code
}

// ----- #4 #5 #6: the response guard ---------------------------------------------

/// #tooth (audit 4): an echo that is not the exact secret still trips while
/// 16 consecutive bytes of it, or of a supported re-encoding, survive.
/// Before: the guard matched only the complete secret, so `secret[..len-1]`
/// passed with all but one byte.
#[tokio::test]
async fn tooth_truncated_altered_and_encoded_echoes_are_withheld() {
    const KEY: &str = "sk-live/AbCd+EfGh=IjKl/MnOp+QrSt=UvWx";
    let (senders, script) = script(1);
    let up = Upstream::start(move |seen| match seen.path.as_str() {
        "/repos/truncated" => Reply::ok(format!("key {}", &KEY[..KEY.len() - 1])),
        "/repos/altered" => Reply::ok(format!("key {}X", &KEY[..KEY.len() - 1])),
        "/repos/middle" => Reply::ok(format!("key ...{}...", &KEY[8..24])),
        "/repos/urlencoded" => Reply::ok(format!(
            "location: /cb?k={}",
            KEY.replace('/', "%2F")
                .replace('+', "%2B")
                .replace('=', "%3D")
        )),
        "/repos/urlencoded-lower" => Reply::ok(format!(
            "location: /cb?k={}",
            KEY.replace('/', "%2f")
                .replace('+', "%2b")
                .replace('=', "%3d")
        )),
        "/repos/json-slash" => Reply::ok(format!(r#"{{"k":"{}"}}"#, KEY.replace('/', "\\/"))),
        "/repos/fragment" => Reply::ok(format!("hint: {}", &KEY[..15])),
        "/repos/base64" => Reply::ok(STANDARD.encode(KEY)),
        "/events" => script.next(),
        _ => Reply::ok("{}"),
    })
    .await;
    let rig = Rig::unset(&config(&up.origin));
    rig.set(S, "api", KEY, false);
    let token = rig.token("seat-a");
    let get = |path: &str| call(&token, "api", "GET", path, b"");

    for path in [
        "/repos/truncated",
        "/repos/altered",
        "/repos/middle",
        "/repos/urlencoded",
        "/repos/urlencoded-lower",
        "/repos/json-slash",
    ] {
        assert_eq!(
            code(rig.forward(S, get(path)).await),
            Code::Withheld,
            "{path}"
        );
    }

    // The same across stream chunks: all but the last byte, then a wrong one.
    let mut live = rig.live(S, get("/events")).await;
    senders[0].send(bytes("data: ")).unwrap();
    assert_eq!(next_chunk(&mut live).await, "data: ");
    for piece in [&KEY[..10], &KEY[10..KEY.len() - 1], "X\n\n"] {
        let _ = senders[0].send(Bytes::copy_from_slice(piece.as_bytes()));
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let (after, summary) = drain(&mut live).await;
    assert!(
        summary.withheld && after.is_empty(),
        "leaked {:?}",
        String::from_utf8_lossy(&after)
    );

    // The stated limits, pinned so they stay stated: fewer than 16
    // consecutive bytes pass, and so does an encoding outside the list.
    let fragment = rig.forward(S, get("/repos/fragment")).await.unwrap();
    assert_eq!(fragment.body, format!("hint: {}", &KEY[..15]).as_bytes());
    assert!(rig.forward(S, get("/repos/base64")).await.is_ok());
    assert_no_plaintext(rig.state(), KEY);
}

/// #tooth (audit 5): a rotated or revoked secret may still be valid at the
/// provider, so it stays guarded (sealed, across restarts) until the
/// operator forgets it. Before: the guard was rebuilt from current secrets
/// only, and an echo of the old key passed.
#[tokio::test]
async fn tooth_retired_secrets_stay_guarded_until_forgotten() {
    const FIRST: &str = "sk-first-key-00000001";
    const SECOND: &str = "sk-second-key-0000002";
    let up = Upstream::start(|seen| match seen.path.as_str() {
        "/repos/echo-first" => Reply::ok(format!("previous key was {FIRST}")),
        "/repos/echo-second" => Reply::ok(format!("previous key was {SECOND}")),
        _ => Reply::ok("{}"),
    })
    .await;
    let rig = Rig::unset(&config(&up.origin));
    let token = rig.token("seat-a");
    let get = |path: &str| fresh(call(&token, "api", "GET", path, b""));
    let api = |rig: &Rig| {
        rig.broker
            .rows()
            .into_iter()
            .find(|r| r.namespace == S)
            .unwrap()
    };

    rig.set(S, "api", FIRST, false);
    rig.set(S, "api", SECOND, false);
    assert_eq!(api(&rig).retired, 1);
    assert_eq!(up.seen().len(), 0);
    assert_eq!(
        code(rig.forward(S, get("/repos/echo-first")).await),
        Code::Withheld
    );
    assert_eq!(
        up.last().header("authorization"),
        Some("Bearer sk-second-key-0000002"),
        "the retired key is never sent"
    );

    // Retired secrets are sealed with the row and survive a restart.
    assert_no_plaintext(rig.state(), FIRST);
    let rig = rig.reopen(BrokerOptions::default());
    assert_eq!(api(&rig).retired, 1);
    assert_eq!(
        code(rig.forward(S, get("/repos/echo-first")).await),
        Code::Withheld
    );

    // Revocation retires the key too; the row is dead but still guarded.
    rig.broker.revoke(S, "api", false, OPERATOR).unwrap();
    assert_eq!(
        (api(&rig).state.as_str(), api(&rig).retired),
        ("revoked", 2)
    );
    rig.set(S, "api", "sk-third-key-00000003", false);
    assert_eq!(
        code(rig.forward(S, get("/repos/echo-second")).await),
        Code::Withheld
    );

    // `forget` is the operator saying the old keys are dead upstream.
    assert_eq!(rig.broker.forget(S, "api", OPERATOR).unwrap(), 2);
    assert_eq!(api(&rig).retired, 0);
    let passed = rig.forward(S, get("/repos/echo-first")).await.unwrap();
    assert!(contains(&passed.body, FIRST.as_bytes()));
    let rig = rig.reopen(BrokerOptions::default());
    assert_eq!(api(&rig).retired, 0, "forgetting is durable");

    // The retired list is bounded, and the bound is explicit: the ninth
    // rotation is refused and changes nothing, unless it forgets.
    for i in 0..8 {
        rig.set(S, "api", &format!("sk-rotation-key-{i:04}"), false);
    }
    let before = api(&rig);
    assert_eq!(before.retired, 8);
    let refused = rig
        .broker
        .set(
            S,
            "api",
            secret("sk-rotation-key-9999"),
            false,
            false,
            OPERATOR,
        )
        .unwrap_err();
    assert_eq!(refused.code, Code::BadRequest);
    assert!(
        refused.message.contains("keygate forget"),
        "{}",
        refused.message
    );
    assert_eq!(api(&rig), before);
    rig.forward(S, get("/repos/x")).await.unwrap();
    assert_eq!(
        up.last().header("authorization"),
        Some("Bearer sk-rotation-key-0007")
    );
    rig.broker
        .set(
            S,
            "api",
            secret("sk-rotation-key-9999"),
            false,
            true,
            OPERATOR,
        )
        .unwrap();
    assert_eq!(api(&rig).retired, 0);
    // Revocation, unlike rotation, is never refused for lack of room.
    for i in 0..9 {
        rig.set(S, "api", &format!("sk-again-key-{i:07}"), false);
        if i == 7 {
            assert_eq!(api(&rig).retired, 8);
            rig.broker.revoke(S, "api", false, OPERATOR).unwrap();
            // Nothing is evicted: the revoked key joins the eight.
            assert_eq!(
                (api(&rig).state.as_str(), api(&rig).retired),
                ("revoked", 9)
            );
            rig.broker.revoke(S, "api", true, OPERATOR).unwrap();
            assert_eq!(api(&rig).retired, 0, "revoke --forget destroys");
        }
    }
}

/// #tooth (audit 6): what the guard may hold is capped. A secret whose
/// patterns do not fit is refused at `set` and nothing changes.
#[tokio::test]
async fn tooth_guard_budget_is_enforced_at_set() {
    let up = counting_upstream().await;
    let rig = Rig::new(&config(&up.origin));
    let status = rig.broker.status();
    // Both rows hold the same test secret: one pattern, counted once.
    assert_eq!(
        (status.guarded_secrets, status.guard_pattern_bytes),
        (1, guard_cost(SECRET.as_bytes()))
    );

    // 8 KiB of '/' has percent-encoded variants three times its size.
    let unguardable = "/".repeat(8192);
    let refused = rig
        .broker
        .set(S, "api", secret(&unguardable), false, false, OPERATOR)
        .unwrap_err();
    assert_eq!(refused.code, Code::BadRequest);
    assert!(
        refused.message.contains("guard patterns would total"),
        "{}",
        refused.message
    );
    assert_eq!(
        rig.broker.status().guard_pattern_bytes,
        status.guard_pattern_bytes
    );
    assert_eq!(
        rig.broker.rows().iter().map(|r| r.generation).max(),
        Some(1)
    );
    let token = rig.token("seat-a");
    rig.forward(S, call(&token, "api", "GET", "/repos/x", b""))
        .await
        .unwrap();
    assert_eq!(
        up.last().header("authorization"),
        Some(&*format!("Bearer {SECRET}"))
    );
}

// ----- #7: nothing is buffered before authentication ----------------------------

/// Write `head` (and nothing else) to the gateway and read what comes back.
async fn raw_http(addr: std::net::SocketAddr, head: String, more: &[u8]) -> (String, Duration) {
    let started = Instant::now();
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(head.as_bytes()).await.unwrap();
    let _ = stream.write_all(more).await;
    let mut response = Vec::new();
    tokio::time::timeout(WAIT, stream.read_to_end(&mut response))
        .await
        .expect("the gateway neither answered nor closed")
        .ok();
    (
        String::from_utf8_lossy(&response).into_owned(),
        started.elapsed(),
    )
}

/// #tooth (audit 7): the gateway verifies the token and bounds the body
/// from the request head. Before: up to 32 MiB per connection was collected
/// before the token was looked at, with no read deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tooth_gateway_authenticates_and_bounds_before_reading_the_body() {
    let up = counting_upstream().await;
    let cfg = config(&up.origin)
        .replace(
            "[broker]",
            "[broker]\nhttp_listen = \"127.0.0.1:0\"\nrequest_read_timeout_ms = 400",
        )
        .replace(
            "[providers.llm]",
            "[providers.llm]\nmax_request_bytes = 2048",
        );
    let rig = Rig::new(&cfg);
    let listeners = Listeners::bind(&rig.broker).await.unwrap();
    let addr = listeners.http_addr.unwrap();
    tokio::spawn(listeners.run(rig.broker.clone()));
    let token = rig.token("seat-a");
    let post = |token: &str, framing: &str| {
        format!("POST /v1/provider/llm/v1/messages HTTP/1.1\r\nhost: x\r\nauthorization: Bearer {token}\r\n{framing}\r\n\r\n")
    };
    let quick = Duration::from_millis(350);

    // An unauthenticated peer announcing 30 MB gets its answer from the
    // head alone: no body byte is sent here, and none is waited for.
    for (bad, status) in [
        ("sk-ant-not-a-keygate-token".to_owned(), "401"),
        (format!("{token}AAAA"), "401"),
        (
            attenuate(&token, Caveat::ExpiresAtUnixS(now_unix_s() - 1)),
            "403",
        ),
        (attenuate(&token, Caveat::Rows(vec!["api".into()])), "403"),
        (attenuate(&token, Caveat::Namespace(S)), "403"),
    ] {
        let (response, took) = raw_http(addr, post(&bad, "content-length: 30000000"), b"").await;
        assert!(
            response.starts_with(&format!("HTTP/1.1 {status}")),
            "{response}"
        );
        assert!(
            took < quick,
            "waited {took:?} for a body it should never read"
        );
    }

    // A good token is held to its row's size, again from the head.
    let (response, took) = raw_http(addr, post(&token, "content-length: 4096"), b"").await;
    assert!(
        response.starts_with("HTTP/1.1 413") && took < quick,
        "{took:?} {response}"
    );
    // ...and to its own MaxRequestBytes caveat.
    let small = attenuate(&token, Caveat::MaxRequestBytes(100));
    let (response, _) = raw_http(addr, post(&small, "content-length: 500"), b"").await;
    assert!(response.starts_with("HTTP/1.1 413"), "{response}");
    // With no Content-Length to announce it, the limit still stops the read.
    let mut chunked = Vec::new();
    for _ in 0..6 {
        chunked.extend_from_slice(b"200\r\n");
        chunked.extend_from_slice(&[b'x'; 512]);
        chunked.extend_from_slice(b"\r\n");
    }
    chunked.extend_from_slice(b"0\r\n\r\n");
    let (response, _) = raw_http(addr, post(&token, "transfer-encoding: chunked"), &chunked).await;
    assert!(response.starts_with("HTTP/1.1 413"), "{response}");

    // Slow body: a deadline, not a wait.
    let (response, took) = raw_http(addr, post(&token, "content-length: 100"), b"0123456789").await;
    assert!(response.starts_with("HTTP/1.1 408"), "{response}");
    assert!(
        took >= Duration::from_millis(350) && took < Duration::from_secs(5),
        "{took:?}"
    );
    // Slow head (slowloris): the connection is dropped at the deadline.
    let (response, took) = raw_http(
        addr,
        "POST /v1/provider/llm/v1/messages HTTP/1.1\r\nhost: x\r\n".to_owned(),
        b"",
    )
    .await;
    assert!(!response.contains(" 200 "), "{response}");
    assert!(
        took >= Duration::from_millis(350) && took < Duration::from_secs(5),
        "{took:?}"
    );

    assert_eq!(up.connections(), 0, "none of that reached the upstream");
    // And an honest request of the same shape goes straight through.
    let body = llm("m-small", 10, false);
    let (response, _) = raw_http(
        addr,
        post(
            &token,
            &format!("connection: close\r\ncontent-length: {}", body.len()),
        ),
        &body,
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert_eq!(up.hits(), 1);
}

/// #tooth (audit 7): the socket reads at most 64 KiB from a connection
/// that has not presented a valid token, allocates only what has arrived,
/// and bounds both the frame and the idle time. Before: any peer could
/// make the broker allocate 48 MiB per connection with four bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tooth_unix_frames_are_bounded_before_authentication() {
    let up = Upstream::start(|seen| Reply::ok(format!(r#"{{"got":{}}}"#, seen.body.len()))).await;
    let cfg = config(&up.origin).replace(
        "[broker]",
        "[broker]\nrequest_read_timeout_ms = 400\nidle_timeout_ms = 400",
    );
    let rig = Rig::new(&cfg);
    let listeners = Listeners::bind(&rig.broker).await.unwrap();
    let socket = listeners.socket_path.clone();
    tokio::spawn(listeners.run(rig.broker.clone()));
    let token = rig.token("seat-a");
    let raw = || tokio::net::UnixStream::connect(&socket);
    async fn next(stream: &mut tokio::net::UnixStream) -> Option<Response> {
        let frame = tokio::time::timeout(WAIT, read_frame(stream))
            .await
            .expect("no answer")
            .unwrap();
        frame.map(|f| serde_json::from_slice::<Response>(&f).unwrap())
    }

    // Four bytes announcing 10 MiB: refused from the prefix, then closed.
    let mut peer = raw().await.unwrap();
    peer.write_all(&(10u32 << 20).to_be_bytes()).await.unwrap();
    assert!(
        matches!(next(&mut peer).await, Some(Response::Error(r)) if r.code == Code::TooLarge && r.message.contains("present"))
    );
    assert!(next(&mut peer).await.is_none(), "connection closed");

    // `present` with a bad or wrong-row token raises nothing.
    let mut peer = raw().await.unwrap();
    let wrong_row = attenuate(&token, Caveat::Rows(vec!["llm".into()]));
    for (bad, expected) in [
        ("kgm_AAAA".to_owned(), Code::BadToken),
        (wrong_row, Code::Denied),
    ] {
        write_frame(
            &mut peer,
            &Request::Present {
                token: bad,
                namespace: S,
                row: "api".into(),
            },
        )
        .await
        .unwrap();
        assert!(matches!(next(&mut peer).await, Some(Response::Error(r)) if r.code == expected));
    }
    peer.write_all(&(100_000u32).to_be_bytes()).await.unwrap();
    assert!(matches!(next(&mut peer).await, Some(Response::Error(r)) if r.code == Code::TooLarge));

    // A valid `present` raises the limit to what that row accepts, and the
    // real client does this by itself for a large call.
    let big = vec![b'x'; 200_000];
    let mut client = Client::connect(&socket).await.unwrap();
    let request = Request::ServiceForward(call(&token, "api", "POST", "/repos/big", &big));
    assert!(serde_json::to_vec(&request).unwrap().len() > PREAUTH_FRAME_BYTES);
    assert!(
        matches!(client.call(&request).await.unwrap(), Response::Reply { status: 200, body, .. } if body == br#"{"got":200000}"#)
    );
    assert_eq!(up.last().body.len(), 200_000);
    // Small calls never needed it.
    let mut plain = Client::connect(&socket).await.unwrap();
    let small = Request::ServiceForward(call(&token, "api", "GET", "/repos/small", b""));
    assert!(matches!(
        plain.call(&small).await.unwrap(),
        Response::Reply { status: 200, .. }
    ));

    // A frame that stalls is cut at the read deadline...
    let mut peer = raw().await.unwrap();
    let started = Instant::now();
    peer.write_all(&1000u32.to_be_bytes()).await.unwrap();
    peer.write_all(b"0123456789").await.unwrap();
    assert!(matches!(next(&mut peer).await, Some(Response::Error(r)) if r.code == Code::Timeout));
    assert!(
        started.elapsed() >= Duration::from_millis(350)
            && started.elapsed() < Duration::from_secs(5)
    );
    // ...and a connection that says nothing is closed when idle.
    let mut peer = raw().await.unwrap();
    let started = Instant::now();
    assert!(next(&mut peer).await.is_none());
    assert!(
        started.elapsed() >= Duration::from_millis(350)
            && started.elapsed() < Duration::from_secs(5)
    );
    assert_eq!(up.hits(), 2);
}

// ----- #10: tickets belong to the token that opened them ------------------------

/// #tooth (audit 10): two tokens of one seat do not share tickets. Before:
/// the request digest ignored the token, so a narrower token B got token
/// A's reservation and A's retained reply for an identical request.
#[tokio::test]
async fn tooth_tickets_belong_to_the_token_that_opened_them() {
    let up = counting_upstream().await;
    let rig = Rig::new(&config(&up.origin));
    let a = rig.token("seat-a");
    let b = attenuate(&a, Caveat::Methods(vec!["POST".into()]));
    let other_root = rig.token("seat-a");
    let post = |token: &str| {
        call(
            token,
            "api",
            "POST",
            "/repos/o/r/issues",
            br#"{"title":"once"}"#,
        )
    };

    let first = rig.forward(S, post(&a)).await.unwrap();
    assert!(!first.replayed);
    // The identical request under B, or under another root token of the
    // same seat, is a different request: sent again, different ticket.
    for token in [&b, &other_root] {
        let theirs = rig.forward(S, post(token)).await.unwrap();
        assert!(
            !theirs.replayed,
            "another token replayed A's retained reply"
        );
        assert_ne!(theirs.ticket, first.ticket);
        assert_ne!(theirs.body, first.body);
    }
    assert_eq!(up.hits(), 3);
    // Each token still replays its own.
    for token in [&a, &b, &other_root] {
        assert!(rig.forward(S, post(token)).await.unwrap().replayed);
    }
    assert_eq!(up.hits(), 3);

    // Reservations are not shared either: A's authorize does not pre-pay B's.
    let body = llm("m-small", 1000, false);
    let reserve = |token: &str| {
        rig.broker.authorize(
            P,
            AGENT,
            call(token, "llm", "POST", "/v1/messages", &body),
            CallKind::Buffered,
        )
    };
    let ta = reserve(&a).unwrap();
    let tb = reserve(&b).unwrap();
    assert!(!ta.existing && !tb.existing);
    assert_ne!(ta.ticket, tb.ticket);
    let day = journal::row_day_key("llm", journal::utc_day(now_unix_s()));
    assert_eq!(rig.broker.spent(&day), 2000, "two tokens, two reservations");
    assert!(
        reserve(&a).unwrap().existing,
        "the same token's retry is still free"
    );
    assert_eq!(
        code(reserve(&other_root)),
        Code::BudgetExceeded,
        "a third token cannot ride on either"
    );
}

// ----- #11: streams end when their token does -----------------------------------

/// #tooth (audit 11): a stream is cut when its token's expiry passes.
/// Before: `ExpiresAtUnixS` was checked at admission only and a stream
/// opened one second before expiry ran indefinitely.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tooth_stream_is_cut_when_its_token_expires() {
    let (senders, script) = script(2);
    let up = Upstream::start(move |_| script.next()).await;
    let rig = Rig::new(&config(&up.origin));
    let root = rig.token("seat-a");
    let started = Instant::now();
    let short = attenuate(&root, Caveat::ExpiresAtUnixS(now_unix_s() + 2));

    let mut expiring = rig
        .live(S, fresh(call(&short, "api", "GET", "/events", b"")))
        .await;
    let mut lasting = rig
        .live(S, fresh(call(&root, "api", "GET", "/events", b"")))
        .await;
    senders[0].send(bytes("data: one\n\n")).unwrap();
    assert_eq!(next_chunk(&mut expiring).await, "data: one\n\n");

    let (rest, summary) = drain(&mut expiring).await;
    let took = started.elapsed();
    assert!(rest.is_empty());
    assert_eq!(summary.closed_by, ClosedBy::Expired);
    assert!(!summary.complete && !summary.revoked);
    assert!(
        took >= Duration::from_millis(900) && took < Duration::from_secs(4),
        "cut after {took:?}"
    );
    tokio::time::timeout(WAIT, senders[0].closed())
        .await
        .expect("upstream stream was not aborted");
    assert!(
        matches!(rig.broker.ticket(expiring.ticket).unwrap().state, TicketState::Closed(s) if s.closed_by == ClosedBy::Expired)
    );
    assert_eq!(
        code(
            rig.stream(S, fresh(call(&short, "api", "GET", "/events", b"")))
                .await
        ),
        Code::Denied
    );

    // A stream on a token with no expiry is untouched.
    senders[1].send(bytes("data: still here\n\n")).unwrap();
    assert_eq!(next_chunk(&mut lasting).await, "data: still here\n\n");
    drop(senders);
    assert!(drain(&mut lasting).await.1.complete);
}

// ----- #8 #9 #17: provider dialects and spend ------------------------------------

fn provider_rows(origin: &str, extra: &str) -> String {
    let row = |name: &str, dialect: &str, more: &str| {
        format!(
            "[providers.{name}]\norigin = \"{origin}\"\ndialect = \"{dialect}\"\nmodels = [\"m-small\"]\nmax_output_tokens = 1000\noutput_micro_usd_per_mtok = 1000000\n{more}\n"
        )
    };
    [
        row(
            "claude",
            "anthropic-messages",
            "read_paths = [\"/v1/models\"]",
        ),
        row("chat", "openai-chat", ""),
        row("resp", "openai-responses", ""),
        row(
            "router",
            "openai-chat",
            "endpoint = \"/api/v1/chat/completions\"",
        ),
        extra.to_owned(),
    ]
    .concat()
}

/// #tooth (audit 9): a provider row reaches exactly one generation endpoint,
/// the one whose body carries the model. Before: any path under a prefix
/// was allowed and only the top-level body was checked, so APIs that pick
/// the model in the path (Gemini, Bedrock, Azure deployments) bypassed the
/// model allowlist and the output cap.
#[tokio::test]
async fn tooth_provider_rows_reach_one_endpoint_of_their_dialect() {
    let up = counting_upstream().await;
    let rig = Rig::new(&provider_rows(&up.origin, ""));
    let token = rig.token("seat-a");
    let send = |row: &str, method: &str, path: &str, body: &str| {
        let request = fresh(call(&token, row, method, path, body.as_bytes()));
        let rig = &rig;
        async move { rig.forward(P, request).await.map(|_| ()) }
    };
    let anthropic = r#"{"model":"m-small","max_tokens":10}"#;
    let chat = r#"{"model":"m-small","max_completion_tokens":10}"#;
    let responses = r#"{"model":"m-small","max_output_tokens":10}"#;
    let gemini = r#"{"contents":[{"parts":[{"text":"hi"}]}],"generationConfig":{"maxOutputTokens":1000000,"candidateCount":8}}"#;

    // Path-selected models: none of these paths exists for any row.
    for (row, path, body) in [
        (
            "claude",
            "/v1beta/models/m-forbidden:generateContent",
            gemini,
        ),
        (
            "claude",
            "/v1/models/m-forbidden:streamGenerateContent",
            gemini,
        ),
        ("claude", "/model/m-forbidden/invoke", anthropic),
        (
            "chat",
            "/openai/deployments/m-forbidden/chat/completions",
            chat,
        ),
        ("claude", "/v1/messages/batches", anthropic),
        ("claude", "/v1/messages/count_tokens", anthropic),
        ("claude", "/v1/chat/completions", chat),
        ("chat", "/v1/messages", anthropic),
        ("chat", "/v1/responses", responses),
        ("router", "/v1/chat/completions", chat),
        ("claude", "/v1", anthropic),
    ] {
        assert_eq!(
            code(send(row, "POST", path, body).await),
            Code::PathRefused,
            "{row} {path}"
        );
    }
    // On the right path the body is what is checked, per dialect.
    assert_eq!(
        code(send("claude", "POST", "/v1/messages", gemini).await),
        Code::ModelRefused
    );
    assert_eq!(
        code(
            send(
                "claude",
                "POST",
                "/v1/messages",
                r#"{"model":"m-forbidden","max_tokens":1}"#
            )
            .await
        ),
        Code::ModelRefused
    );
    for (row, path, wrong_cap) in [
        ("claude", "/v1/messages", responses),
        ("claude", "/v1/messages", chat),
        ("chat", "/v1/chat/completions", responses),
        ("resp", "/v1/responses", anthropic),
        ("resp", "/v1/responses", chat),
    ] {
        assert_eq!(
            code(send(row, "POST", path, wrong_cap).await),
            Code::TokenCapRefused,
            "{row}: another dialect's cap field is not a cap"
        );
    }
    // Reads: only the listed prefixes, only GET/HEAD, never with a body.
    assert_eq!(
        code(send("claude", "GET", "/v1/files", "").await),
        Code::PathRefused
    );
    assert_eq!(
        code(send("chat", "GET", "/v1/models", "").await),
        Code::PathRefused
    );
    assert_eq!(
        code(send("claude", "DELETE", "/v1/models/m-small", "").await),
        Code::MethodRefused
    );
    assert_eq!(
        code(send("claude", "PUT", "/v1/messages", anthropic).await),
        Code::MethodRefused
    );
    assert_eq!(
        code(send("claude", "GET", "/v1/models", "{}").await),
        Code::BadRequest
    );
    assert_eq!(
        up.connections(),
        0,
        "every refusal happened before the network"
    );

    for (row, method, path, body) in [
        ("claude", "POST", "/v1/messages", anthropic),
        ("chat", "POST", "/v1/chat/completions", chat),
        (
            "chat",
            "POST",
            "/v1/chat/completions",
            r#"{"model":"m-small","max_tokens":10}"#,
        ),
        ("resp", "POST", "/v1/responses", responses),
        ("router", "POST", "/api/v1/chat/completions", chat),
        ("claude", "GET", "/v1/models", ""),
    ] {
        send(row, method, path, body)
            .await
            .unwrap_or_else(|r| panic!("{row} {path}: {r}"));
        assert_eq!(up.last().path, path);
    }
    assert_eq!(up.hits(), 6);

    // A dialect keygate does not speak cannot be configured at all.
    let unsupported =
        provider_rows(&up.origin, "").replace("openai-responses", "gemini-generate-content");
    assert!(Config::parse(&development(&unsupported)).is_err());
}

/// #tooth (audit 8b, 8d): input the provider holds or fetches, provider-run
/// tools and premium tiers make a call cost more than its body says, and a
/// stored conversation can be continued by any seat sharing the key. They
/// are refused unless the row's `allow` names them.
#[tokio::test]
async fn tooth_unmetered_and_server_side_input_is_refused_unless_allowed() {
    let up = counting_upstream().await;
    let open = format!(
        "[providers.open]\norigin = \"{}\"\ndialect = \"openai-responses\"\nmodels = [\"m-small\"]\nmax_output_tokens = 1000\nallow = [\"server-state\", \"remote-input\", \"server-tools\", \"premium-tier\", \"inline-media\", \"non-text-output\"]\n",
        up.origin
    );
    let rig = Rig::new(&provider_rows(&up.origin, &open));
    let token = rig.token("seat-a");
    let try_on = |row: &str, path: &str, extra: &str| {
        let cap = match row {
            "claude" => "max_tokens",
            "chat" => "max_completion_tokens",
            _ => "max_output_tokens",
        };
        let body = format!(r#"{{"model":"m-small","{cap}":10,{extra}}}"#);
        assert!(
            serde_json::from_str::<serde_json::Value>(&body).is_ok(),
            "test body is JSON: {body}"
        );
        let request = fresh(call(&token, row, "POST", path, body.as_bytes()));
        let rig = &rig;
        async move { rig.forward(P, request).await.map(|_| ()) }
    };

    let refused: &[(&str, &str, &str, &str)] = &[
        // Stored at the provider, reachable by any seat on the same key.
        (
            "resp",
            "/v1/responses",
            r#""previous_response_id":"resp_of_another_seat""#,
            "server-state",
        ),
        (
            "resp",
            "/v1/responses",
            r#""conversation":"conv_123""#,
            "server-state",
        ),
        (
            "resp",
            "/v1/responses",
            r#""conversation":{"id":"conv_123"}"#,
            "server-state",
        ),
        (
            "resp",
            "/v1/responses",
            r#""prompt":{"id":"pmpt_1"}"#,
            "server-state",
        ),
        (
            "resp",
            "/v1/responses",
            r#""background":true"#,
            "server-state",
        ),
        (
            "resp",
            "/v1/responses",
            r#""input":[{"type":"item_reference","id":"msg_1"}]"#,
            "server-state",
        ),
        (
            "resp",
            "/v1/responses",
            r#""input":[{"role":"user","content":[{"type":"input_file","file_id":"file_1"}]}]"#,
            "server-state",
        ),
        (
            "chat",
            "/v1/chat/completions",
            r#""messages":[{"role":"user","content":[{"type":"file","file":{"file_id":"file_1"}}]}]"#,
            "server-state",
        ),
        (
            "claude",
            "/v1/messages",
            r#""container":"cont_1""#,
            "server-state",
        ),
        (
            "claude",
            "/v1/messages",
            r#""messages":[{"role":"user","content":[{"type":"document","source":{"type":"file","file_id":"file_1"}}]}]"#,
            "server-state",
        ),
        // Fetched by the provider.
        (
            "resp",
            "/v1/responses",
            r#""input":[{"role":"user","content":[{"type":"input_image","image_url":"https://example.com/huge.png"}]}]"#,
            "remote-input",
        ),
        (
            "resp",
            "/v1/responses",
            r#""input":[{"role":"user","content":[{"type":"input_file","file_url":"https://example.com/book.pdf"}]}]"#,
            "remote-input",
        ),
        (
            "chat",
            "/v1/chat/completions",
            r#""messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"HTTPS://example.com/a.png"}}]}]"#,
            "remote-input",
        ),
        (
            "claude",
            "/v1/messages",
            r#""messages":[{"role":"user","content":[{"type":"document","source":{"type":"url","url":"https://example.com/book.pdf"}}]}]"#,
            "remote-input",
        ),
        (
            "claude",
            "/v1/messages",
            r#""messages":[{"role":"user","content":[{"type":"tool_result","content":[{"type":"image","source":{"type":"url","url":"https://example.com/a.png"}}]}]}]"#,
            "remote-input",
        ),
        // Run by the provider, with their own fees.
        (
            "resp",
            "/v1/responses",
            r#""tools":[{"type":"web_search"}]"#,
            "server-tools",
        ),
        (
            "resp",
            "/v1/responses",
            r#""tools":[{"type":"function","name":"f"},{"type":"code_interpreter","container":{"type":"auto"}}]"#,
            "server-tools",
        ),
        (
            "chat",
            "/v1/chat/completions",
            r#""web_search_options":{}"#,
            "server-tools",
        ),
        (
            "claude",
            "/v1/messages",
            r#""tools":[{"type":"web_search_20250305","name":"web_search"}]"#,
            "server-tools",
        ),
        (
            "claude",
            "/v1/messages",
            r#""mcp_servers":[{"type":"url","url":"https://mcp.example.com","name":"x"}]"#,
            "server-tools",
        ),
        // Output on another channel than text tokens (parent K-P4): audio
        // from Chat Completions, and the stored audio a later turn points at.
        (
            "chat",
            "/v1/chat/completions",
            r#""modalities":["text","audio"],"audio":{"voice":"alloy","format":"wav"}"#,
            "non-text-output",
        ),
        (
            "chat",
            "/v1/chat/completions",
            r#""audio":{"voice":"alloy","format":"mp3"}"#,
            "non-text-output",
        ),
        (
            "resp",
            "/v1/responses",
            r#""modalities":["audio"]"#,
            "non-text-output",
        ),
        (
            "claude",
            "/v1/messages",
            r#""modalities":"audio""#,
            "non-text-output",
        ),
        (
            "chat",
            "/v1/chat/completions",
            r#""messages":[{"role":"user","content":"again?"},{"role":"assistant","audio":{"id":"audio_abc123"}}]"#,
            "server-state",
        ),
        // Billed above the row's prices.
        (
            "resp",
            "/v1/responses",
            r#""service_tier":"priority""#,
            "premium-tier",
        ),
        (
            "claude",
            "/v1/messages",
            r#""speed":"fast""#,
            "premium-tier",
        ),
        // Token cost not bounded by size in bytes.
        (
            "claude",
            "/v1/messages",
            r#""messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"AAAA"}}]}]"#,
            "inline-media",
        ),
        (
            "chat",
            "/v1/chat/completions",
            r#""messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,AAAA"}}]}]"#,
            "inline-media",
        ),
        (
            "resp",
            "/v1/responses",
            r#""input":[{"role":"user","content":[{"type":"input_file","file_data":"AAAA","filename":"a.pdf"}]}]"#,
            "inline-media",
        ),
    ];
    for (row, path, extra, flag) in refused {
        let refusal = try_on(row, path, extra).await.unwrap_err();
        assert_eq!(refusal.code, Code::Denied, "{row}: {extra}");
        assert!(
            refusal.message.contains(&format!("\"{flag}\"")),
            "{extra}: {}",
            refusal.message
        );
    }
    assert_eq!(up.connections(), 0);

    // Ordinary agent traffic is not caught by any of that: caller-run
    // tools, a tool call whose input happens to hold a URL or a `type`,
    // text that mentions URLs, and explicit nulls.
    let accepted: &[(&str, &str, &str)] = &[
        (
            "claude",
            "/v1/messages",
            r#""tools":[{"name":"fetch","input_schema":{"type":"object","properties":{"url":{"type":"string"}}}},{"type":"bash_20250124","name":"bash"},{"type":"custom","name":"c","input_schema":{"type":"object"}}],"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"fetch","input":{"url":"https://example.com","type":"image"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"see https://example.com/a.png"}]}]"#,
        ),
        (
            "claude",
            "/v1/messages",
            r#""messages":[{"role":"user","content":[{"type":"document","source":{"type":"text","media_type":"text/plain","data":"plain inline text"}}]}],"service_tier":"standard_only","mcp_servers":[]"#,
        ),
        (
            "chat",
            "/v1/chat/completions",
            r#""tools":[{"type":"function","function":{"name":"f","parameters":{"type":"object"}}}],"messages":[{"role":"user","content":"look at https://example.com"}],"service_tier":"default","modalities":["text"],"audio":null"#,
        ),
        (
            "resp",
            "/v1/responses",
            r#""previous_response_id":null,"conversation":null,"background":false,"tools":[{"type":"function","name":"f"}],"input":"hi""#,
        ),
    ];
    for (row, path, extra) in accepted {
        try_on(row, path, extra)
            .await
            .unwrap_or_else(|r| panic!("{row}: {extra}: {r}"));
    }
    // And a row that opts in gets them, every one.
    for (_, _, extra, _) in refused.iter().filter(|(row, ..)| *row == "resp") {
        try_on("open", "/v1/responses", extra)
            .await
            .unwrap_or_else(|r| panic!("open: {extra}: {r}"));
    }
    assert_eq!(
        up.hits(),
        accepted.len() + refused.iter().filter(|(row, ..)| *row == "resp").count()
    );
}

/// #tooth (audit 8a, 8c, 17): the reservation covers everything that
/// multiplies or prices a call, and absent means absent.
#[tokio::test]
async fn tooth_reservation_covers_choices_cache_prices_and_null_fields() {
    let up = counting_upstream().await;
    let priced = format!(
        "[providers.priced]\norigin = \"{0}\"\ndialect = \"openai-chat\"\nmodels = [\"m-small\"]\nmax_output_tokens = 1000\ninput_micro_usd_per_mtok = 2000000\noutput_micro_usd_per_mtok = 1000000\n\n[providers.free]\norigin = \"{0}\"\ndialect = \"openai-chat\"\nmodels = [\"m-small\"]\nmax_output_tokens = 1000\n\n[services.api]\norigin = \"{0}\"\nbuffered_paths = [\"/repos\"]\n",
        up.origin
    );
    let rig = Rig::new(&provider_rows(&up.origin, &priced));
    let token = rig.token("seat-a");
    let reserve = |token: &str, row: &str, body: &str| {
        rig.broker
            .authorize(
                P,
                AGENT,
                fresh(call(
                    token,
                    row,
                    "POST",
                    "/v1/chat/completions",
                    body.as_bytes(),
                )),
                CallKind::Buffered,
            )
            .map(|a| a.reserved_micro_usd)
    };

    // 8c: best_of multiplies exactly like n; the larger of the two counts.
    assert_eq!(
        reserve(
            &token,
            "chat",
            r#"{"model":"m-small","max_tokens":100,"n":2,"best_of":3}"#
        )
        .unwrap(),
        300
    );
    assert_eq!(
        reserve(
            &token,
            "chat",
            r#"{"model":"m-small","max_tokens":100,"best_of":4}"#
        )
        .unwrap(),
        400
    );
    for over in [
        r#"{"model":"m-small","max_tokens":300,"best_of":4}"#,
        r#"{"model":"m-small","max_tokens":1,"best_of":17}"#,
        r#"{"model":"m-small","max_tokens":1,"best_of":0}"#,
        r#"{"model":"m-small","max_tokens":1,"n":0,"best_of":2}"#,
    ] {
        assert_eq!(
            code(reserve(&token, "chat", over)),
            Code::TokenCapRefused,
            "{over}"
        );
    }

    // 17: null is absent, the same way for admission and for classifying.
    let nulls = r#"{"model":"m-small","max_tokens":10,"n":null,"best_of":null,"stream":null}"#;
    assert_eq!(reserve(&token, "chat", nulls).unwrap(), 10);
    assert_eq!(Broker::provider_kind(nulls.as_bytes()), CallKind::Buffered);
    rig.forward(
        P,
        fresh(call(
            &token,
            "chat",
            "POST",
            "/v1/chat/completions",
            nulls.as_bytes(),
        )),
    )
    .await
    .unwrap();
    assert_eq!(
        code(reserve(
            &token,
            "chat",
            r#"{"model":"m-small","max_tokens":null}"#
        )),
        Code::TokenCapRefused
    );
    assert_eq!(
        code(reserve(
            &token,
            "chat",
            r#"{"model":"m-small","max_tokens":10,"stream":"yes"}"#
        )),
        Code::BadRequest
    );

    // The input side: every body byte and 4096 tokens of overhead, at the
    // dearest input price (cache writes default to twice the input price).
    let body =
        r#"{"model":"m-small","max_tokens":100,"messages":[{"role":"user","content":"hello"}]}"#;
    assert_eq!(
        reserve(&token, "priced", body).unwrap(),
        (body.len() as u64 + 4096) * 4 + 100
    );

    // 8a: a spend-capped token cannot be used where spending is not priced.
    let capped = attenuate(&token, Caveat::MaxSpendMicroUsd(1_000_000));
    let refusal = reserve(&capped, "free", body).unwrap_err();
    assert_eq!(refusal.code, Code::Denied);
    assert!(
        refusal.message.contains("no token prices"),
        "{}",
        refusal.message
    );
    assert_eq!(
        reserve(&token, "free", body).unwrap(),
        0,
        "an uncapped token may use an unpriced row"
    );
    assert!(reserve(&capped, "priced", body).is_ok());
    // Services are not metered; the cap neither binds nor blocks there.
    rig.forward(S, fresh(call(&capped, "api", "GET", "/repos/x", b"")))
        .await
        .unwrap();
    // And a cap on an unpriced row is a config error, not a silent no-op.
    let void_cap = priced.replace(
        "[providers.free]",
        "[providers.free]\nper_day_micro_usd = 5",
    );
    assert!(Config::parse(&development(&void_cap))
        .unwrap_err()
        .to_string()
        .contains("could never bind"));
}

// ----- #13 #14 #15 #16: headers, queries and tokens ------------------------------

/// #tooth (audit 14): a keygate token is never sent upstream, wherever a
/// caller puts it. Before: `?key=kgm_...` was forwarded verbatim.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tooth_tokens_never_travel_upstream() {
    let up = counting_upstream().await;
    let cfg = config(&up.origin).replace("[broker]", "[broker]\nhttp_listen = \"127.0.0.1:0\"");
    let rig = Rig::new(&cfg);
    let listeners = Listeners::bind(&rig.broker).await.unwrap();
    let addr = listeners.http_addr.unwrap();
    tokio::spawn(listeners.run(rig.broker.clone()));
    let token = rig.token("seat-a");
    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    let url = format!("http://{addr}/v1/service/api/repos/o/r");

    // In the query (how the Gemini SDK passes keys): refused, never sent.
    for query in [
        format!("key={token}"),
        "key=kgm_anything".to_owned(),
        format!("a=1&api_key={token}"),
    ] {
        let response = http
            .get(format!("{url}?{query}"))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 400, "{query}");
        assert!(response.text().await.unwrap().contains("path_refused"));
    }
    // A token only in the query authenticates nothing.
    let only_query = http.get(format!("{url}?key={token}")).send().await.unwrap();
    assert_eq!(only_query.status(), 401);
    assert_eq!(up.connections(), 0);

    // x-goog-api-key is a token source like the others, and is stripped.
    let response = http
        .get(&url)
        .header("x-goog-api-key", &token)
        .header("x-trace", "t-1")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let seen = up.last();
    assert_eq!(seen.header("x-trace"), Some("t-1"));
    assert!(seen.header("x-goog-api-key").is_none() && seen.header("x-api-key").is_none());
    assert!(!seen
        .headers
        .values()
        .any(|v| contains(v.as_bytes(), b"kgm_")));
    assert!(!seen.query.as_deref().unwrap_or("").contains("kgm_"));

    // Over the socket protocol the same holds for headers, query and body.
    let mut in_header = call(&token, "api", "GET", "/repos/o/r", b"");
    in_header.headers = vec![("x-trace".into(), token.clone())];
    assert_eq!(code(rig.forward(S, in_header).await), Code::HeaderRefused);
    let mut in_query = call(&token, "api", "GET", "/repos/o/r", b"");
    in_query.query = Some("cursor=kgm_x".into());
    assert_eq!(code(rig.forward(S, in_query).await), Code::PathRefused);
    let body = format!(r#"{{"note":"my key is {token}"}}"#);
    let in_body = fresh(call(&token, "api", "POST", "/repos/o/r", body.as_bytes()));
    assert_eq!(code(rig.forward(S, in_body).await), Code::BadRequest);
    assert_eq!(up.hits(), 1);
}

/// #tooth (audit 15): `Idempotency-Key` identifies the request to keygate
/// and, where the row allows the header, reaches the upstream too. Before:
/// it was consumed and never forwarded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tooth_idempotency_key_is_forwarded_where_allowed() {
    let up = counting_upstream().await;
    let cfg = config(&up.origin)
        .replace("[broker]", "[broker]\nhttp_listen = \"127.0.0.1:0\"")
        .replace(
            "\"last-event-id\", \"x-trace\"",
            "\"last-event-id\", \"x-trace\", \"idempotency-key\"",
        );
    let rig = Rig::new(&cfg);
    let listeners = Listeners::bind(&rig.broker).await.unwrap();
    let addr = listeners.http_addr.unwrap();
    tokio::spawn(listeners.run(rig.broker.clone()));
    let token = rig.token("seat-a");
    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    let post = |url: String, key: &'static str, body: Vec<u8>| {
        let request = http
            .post(url)
            .bearer_auth(&token)
            .header("idempotency-key", key)
            .body(body);
        async move { request.send().await.unwrap() }
    };
    let service = format!("http://{addr}/v1/service/api/repos/o/r/issues");

    let first = post(service.clone(), "key-1", b"{}".to_vec()).await;
    assert_eq!(first.status(), 200);
    assert_eq!(
        up.last().header("idempotency-key"),
        Some("key-1"),
        "the allowing row forwards it"
    );
    let retry = post(service.clone(), "key-1", b"{}".to_vec()).await;
    assert!(retry.headers().contains_key("x-keygate-replayed"));
    assert_eq!(up.hits(), 1);
    let other = post(service, "key-2", b"{}".to_vec()).await;
    assert!(!other.headers().contains_key("x-keygate-replayed"));
    assert_eq!(
        (up.hits(), up.last().header("idempotency-key")),
        (2, Some("key-2"))
    );

    // A row that does not list the header still deduplicates by it, but
    // does not forward it.
    let provider = format!("http://{addr}/v1/provider/llm/v1/messages");
    assert_eq!(
        post(provider.clone(), "key-1", llm("m-small", 10, false))
            .await
            .status(),
        200
    );
    assert!(up.last().header("idempotency-key").is_none());
    assert!(post(provider, "key-1", llm("m-small", 10, false))
        .await
        .headers()
        .contains_key("x-keygate-replayed"));
    assert_eq!(up.hits(), 3);
}

/// #tooth (audit 16): an upstream cannot speak in keygate's name or pass
/// hop-by-hop headers through. Before: `x-keygate-*` reply headers and
/// headers named in `Connection` reached the caller.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tooth_upstream_cannot_spoof_keygate_or_hop_by_hop_headers() {
    let up = Upstream::start(|_| Reply::Full {
        status: 200,
        headers: vec![
            ("x-keygate-replayed", "true".into()),
            (
                "x-keygate-ticket",
                "00000000000000000000000000000000".into(),
            ),
            ("connection", "x-internal-hop, close".into()),
            ("x-internal-hop", "between-proxies-only".into()),
            ("x-forwarded-for", "10.0.0.1".into()),
            ("x-request-id", "req-1".into()),
        ],
        body: b"{}".to_vec(),
    })
    .await;
    let cfg = config(&up.origin).replace("[broker]", "[broker]\nhttp_listen = \"127.0.0.1:0\"");
    let rig = Rig::new(&cfg);
    let token = rig.token("seat-a");

    let reply = rig
        .forward(S, call(&token, "api", "GET", "/repos/x", b""))
        .await
        .unwrap();
    let names: Vec<&str> = reply.headers.iter().map(|(n, _)| n.as_str()).collect();
    assert!(names.contains(&"x-request-id"), "{names:?}");
    for hidden in [
        "x-keygate-replayed",
        "x-keygate-ticket",
        "x-internal-hop",
        "connection",
        "x-forwarded-for",
    ] {
        assert!(
            !names.contains(&hidden),
            "{hidden} reached the caller: {names:?}"
        );
    }

    let listeners = Listeners::bind(&rig.broker).await.unwrap();
    let addr = listeners.http_addr.unwrap();
    tokio::spawn(listeners.run(rig.broker.clone()));
    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    let response = http
        .get(format!("http://{addr}/v1/service/api/repos/y"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    let tickets: Vec<_> = response
        .headers()
        .get_all("x-keygate-ticket")
        .iter()
        .collect();
    assert_eq!(tickets.len(), 1, "only keygate's own ticket header");
    assert_ne!(tickets[0], "00000000000000000000000000000000");
    assert!(
        !response.headers().contains_key("x-keygate-replayed"),
        "this reply was not replayed"
    );
    assert!(!response.headers().contains_key("x-internal-hop"));
}

// ----- #3 #19: the deployment boundary ------------------------------------------

/// #tooth (audit 3): in the default, separated deployment a peer running
/// as the broker's own uid is not served as a caller, operators are the
/// listed uids only, and a state directory open to others does not boot.
/// Before: the state directory's owner was silently the operator and any
/// co-uid process was served.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tooth_separated_deployment_does_not_serve_the_brokers_own_uid() {
    let me = effective_uid();
    // Nothing listens here; https means no plaintext fixture is involved.
    let dead = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let separated = format!(
        "[broker]\ndeployment = \"separated\"\noperator_uids = [{me}]\nconnect_timeout_ms = 2000\n\n[services.api]\norigin = \"https://{dead}\"\nbuffered_paths = [\"/repos\"]\n"
    );
    let rig = Rig::unset(&separated);
    assert!(
        !rig.broker.may_call(Some(me))
            && rig.broker.may_call(Some(me + 1))
            && rig.broker.may_call(None)
    );
    let listeners = Listeners::bind(&rig.broker).await.unwrap();
    let socket = listeners.socket_path.clone();
    tokio::spawn(listeners.run(rig.broker.clone()));
    let mut client = Client::connect(&socket).await.unwrap();
    assert_eq!(client.broker_uid(), me);

    let Response::Hello {
        operator,
        caller,
        deployment,
        uid,
        ..
    } = client.call(&Request::Hello).await.unwrap()
    else {
        panic!("no hello")
    };
    assert_eq!(
        (operator, caller, deployment.as_str(), uid),
        (true, false, "separated", me)
    );
    // The operator surface works for the listed uid...
    let set = Request::Set {
        namespace: S,
        row: "api".into(),
        secret_b64: STANDARD.encode(SECRET),
        cut_existing: false,
        forget_retired: false,
    };
    assert!(matches!(client.call(&set).await.unwrap(), Response::Ok));
    let mint = Request::MintMacaroon {
        seat: "seat-a".into(),
        allowed_uid: None,
        caveats: vec![],
    };
    let Response::Token { token } = client.call(&mint).await.unwrap() else {
        panic!("no token")
    };

    // ...but that same uid is refused on every data-plane request.
    let get = call(&token, "api", "GET", "/repos/x", b"");
    for request in [
        Request::ServiceForward(get.clone()),
        Request::ServiceAuthorize(keygate_core::proto::ServiceAuthorize {
            call: get.clone(),
            stream: false,
        }),
        Request::Present {
            token: token.clone(),
            namespace: S,
            row: "api".into(),
        },
    ] {
        assert!(
            matches!(client.call(&request).await.unwrap(), Response::Error(r) if r.code == Code::Denied && r.message.contains("own uid"))
        );
    }
    // A caller under another uid, or the gateway's uid-less caller, is
    // admitted (and then fails only because nothing listens upstream).
    for uid in [Some(me + 1), None] {
        let refusal = rig
            .broker
            .forward(S, Caller { uid }, fresh(get.clone()), HeaderMode::Strict)
            .await
            .unwrap_err();
        assert_eq!(refusal.code, Code::UpstreamFailed, "uid {uid:?}: {refusal}");
    }

    // An operator list that does not include us means no operator surface.
    let not_us = separated.replace(&format!("[{me}]"), &format!("[{}]", me + 1));
    let other = Rig::unset(&not_us);
    let listeners = Listeners::bind(&other.broker).await.unwrap();
    let socket = listeners.socket_path.clone();
    tokio::spawn(listeners.run(other.broker.clone()));
    let mut client = Client::connect(&socket).await.unwrap();
    assert!(matches!(
        client.call(&Request::Hello).await.unwrap(),
        Response::Hello {
            operator: false,
            caller: false,
            ..
        }
    ));
    for request in [
        mint,
        Request::Ls,
        Request::Forget {
            namespace: S,
            row: "api".into(),
        },
    ] {
        assert!(
            matches!(client.call(&request).await.unwrap(), Response::Error(r) if r.code == Code::NotOperator)
        );
    }

    // Custody of the state directory is checked at boot.
    use std::os::unix::fs::PermissionsExt;
    let Rig { dir, broker, .. } = other;
    drop(broker);
    for loose in [0o750, 0o755, 0o701] {
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(loose)).unwrap();
        let boot = Broker::open(
            dir.path(),
            Config::parse(&not_us).unwrap(),
            BrokerOptions::default(),
        );
        assert!(
            boot.is_err_and(|e| e.to_string().contains("must be 0700")),
            "{loose:o}"
        );
    }
}

/// #tooth (audit 19): the client checks who is listening before it sends a
/// token or a secret, and the socket appears at its path only with its
/// configured mode.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tooth_client_verifies_the_broker_and_socket_mode_is_never_wider() {
    use keygate_broker::client::ExpectedBroker;
    use std::os::unix::fs::PermissionsExt;
    let up = counting_upstream().await;
    let me = effective_uid();
    for mode in [0o600u32, 0o660, 0o666] {
        let cfg =
            config(&up.origin).replace("[broker]", &format!("[broker]\nsocket_mode = {mode}"));
        let rig = Rig::new(&cfg);
        let listeners = Listeners::bind(&rig.broker).await.unwrap();
        let socket = listeners.socket_path.clone();
        assert_eq!(
            std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
            mode
        );
        let leftovers: Vec<_> = std::fs::read_dir(rig.state())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n.to_string_lossy().starts_with("keygate.sock."))
            .collect();
        assert!(
            leftovers.is_empty(),
            "staging name left behind: {leftovers:?}"
        );
        tokio::spawn(listeners.run(rig.broker.clone()));

        assert!(Client::connect_expecting(&socket, ExpectedBroker::Uid(me))
            .await
            .is_ok());
        let wrong = Client::connect_expecting(&socket, ExpectedBroker::Uid(me + 1))
            .await
            .err()
            .unwrap();
        assert!(
            wrong.to_string().contains("not the expected uid"),
            "{wrong}"
        );
        assert!(
            Client::connect(&socket).await.is_ok(),
            "private directory, owner listening"
        );
        // If others could have replaced the socket, the default rule
        // refuses and the caller has to say whom it expects.
        std::fs::set_permissions(rig.state(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(Client::connect(&socket).await.is_err());
        assert!(Client::connect_expecting(&socket, ExpectedBroker::Uid(me))
            .await
            .is_ok());
        std::fs::set_permissions(rig.state(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    // Binding over a live broker is refused; over a dead one's socket, fine.
    let rig = Rig::new(&config(&up.origin));
    let first = Listeners::bind(&rig.broker).await.unwrap();
    assert!(Listeners::bind(&rig.broker).await.is_err());
    drop(first);
    assert!(Listeners::bind(&rig.broker).await.is_ok());
}

// ----- #2: journal failures at the broker boundary -------------------------------

/// #tooth (audit 2): when the journal cannot commit, calls fail closed
/// before the network, a transient short write does not brick the broker,
/// and after a failed fsync nothing more is sent until restart.
#[tokio::test]
async fn tooth_journal_failures_fail_closed_before_the_network() {
    let up = counting_upstream().await;
    let faults = Arc::new(JournalFaults::default());
    let rig = Rig::unset_with(
        &config(&up.origin),
        BrokerOptions {
            journal_faults: Some(faults.clone()),
            ..Default::default()
        },
    );
    rig.set(S, "api", SECRET, false);
    let token = rig.token("seat-a");
    let post = |id: &str| {
        let mut c = call(&token, "api", "POST", "/repos/o/r/issues", b"{}");
        c.request_id = Some(id.to_owned());
        c
    };

    // Disk full while opening the ticket: refused, nothing sent, and the
    // very next call works (the torn record was cut back).
    faults.short_write_after.store(20, Ordering::SeqCst);
    assert_eq!(code(rig.forward(S, post("a")).await), Code::JournalFailed);
    assert_eq!(up.connections(), 0);
    assert!(!rig.broker.status().journal.poisoned);
    assert!(!rig.forward(S, post("a")).await.unwrap().replayed);
    assert_eq!(up.hits(), 1);

    // fsync fails while recording a reply that the upstream did send. The
    // caller is told the journal failed; the broker stops taking calls.
    let before = up.hits();
    let arm = faults.clone();
    let authorized = rig
        .broker
        .authorize(S, AGENT, post("b"), CallKind::Buffered)
        .unwrap();
    // Fail the *second* commit from here (the claim succeeds, the outcome
    // does not): the claim is one commit, so arm after it via a watcher.
    let watcher = tokio::spawn({
        let rig_broker = rig.broker.clone();
        let ticket = authorized.ticket;
        async move {
            while rig_broker.ticket(ticket).unwrap().state != TicketState::InFlight {
                tokio::task::yield_now().await;
            }
            arm.fail_sync.store(true, Ordering::SeqCst);
        }
    });
    let outcome = rig.forward(S, post("b")).await;
    watcher.await.unwrap();
    assert_eq!(up.hits(), before + 1, "the request itself went out");
    assert_eq!(code(outcome), Code::JournalFailed);
    assert!(rig.broker.status().journal.poisoned);
    faults.fail_sync.store(false, Ordering::SeqCst);
    // Its ticket is still claimed in memory; nothing new can be opened.
    assert_eq!(code(rig.forward(S, post("b")).await), Code::InFlight);
    assert_eq!(code(rig.forward(S, post("c")).await), Code::JournalFailed);
    assert_eq!(
        code(
            rig.stream(S, fresh(call(&token, "api", "GET", "/events", b"")))
                .await
        ),
        Code::JournalFailed
    );
    assert_eq!(
        up.hits(),
        before + 1,
        "nothing is sent on an unjournaled broker"
    );

    // After a restart the half-recorded call is never re-sent. Whether its
    // outcome record survived the failed fsync decides between a replay
    // and Uncertain; with this injection the record did reach the file.
    let rig = rig.reopen(BrokerOptions::default());
    assert!(!rig.broker.status().journal.poisoned);
    assert!(rig.forward(S, post("b")).await.unwrap().replayed);
    assert!(rig.forward(S, post("a")).await.unwrap().replayed);
    assert!(!rig.forward(S, post("c")).await.unwrap().replayed);
    assert_eq!(up.hits(), before + 2);
}

// ----- shutdown ------------------------------------------------------------------

/// #tooth (audit 1, shutdown half): on shutdown the broker cuts streams and
/// in-flight calls, waits for their outcomes to be journaled, and takes no
/// new calls.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tooth_shutdown_cuts_flights_and_records_their_outcomes() {
    let (senders, script) = script(1);
    let up = Upstream::start(move |seen| match seen.path.as_str() {
        "/events" => script.next(),
        "/repos/hang" => Reply::Hang,
        _ => Reply::ok("{}"),
    })
    .await;
    let rig = Rig::new(&config(&up.origin));
    let token = rig.token("seat-a");

    let mut live = rig
        .live(S, call(&token, "api", "GET", "/events", b""))
        .await;
    senders[0].send(bytes("data: one\n\n")).unwrap();
    assert_eq!(next_chunk(&mut live).await, "data: one\n\n");
    let hung = call(&token, "api", "POST", "/repos/hang", b"{}");
    let hung_ticket = rig
        .broker
        .authorize(S, AGENT, hung.clone(), CallKind::Buffered)
        .unwrap()
        .ticket;
    let pending = tokio::spawn({
        let broker = rig.broker.clone();
        async move { broker.forward(S, AGENT, hung, HeaderMode::Strict).await }
    });
    up.arrived().await;
    up.arrived().await;
    assert_eq!(rig.broker.in_flight(), 2);

    let started = Instant::now();
    assert_eq!(
        rig.broker.shutdown(Duration::from_secs(5)).await,
        0,
        "every flight recorded its outcome"
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "drain waited {:?}",
        started.elapsed()
    );

    let (_, summary) = drain(&mut live).await;
    assert_eq!(summary.closed_by, ClosedBy::Shutdown);
    assert!(
        matches!(rig.broker.ticket(live.ticket).unwrap().state, TicketState::Closed(s) if s.closed_by == ClosedBy::Shutdown)
    );
    assert_eq!(code(pending.await.unwrap()), Code::ShuttingDown);
    assert_eq!(
        rig.broker.ticket(hung_ticket).unwrap().state,
        TicketState::Uncertain
    );
    tokio::time::timeout(WAIT, senders[0].closed())
        .await
        .expect("upstream stream was not aborted");

    assert_eq!(
        code(
            rig.forward(S, fresh(call(&token, "api", "GET", "/repos/x", b"")))
                .await
        ),
        Code::ShuttingDown
    );
    assert!(
        matches!(rig.stream(S, fresh(call(&token, "api", "GET", "/events", b""))).await, Err(r) if r.code == Code::ShuttingDown)
    );
    assert_eq!(up.hits(), 2);

    // A flight abandoned by its caller is counted until its Uncertain
    // record is on disk, so the drain cannot return ahead of it.
    let rig = rig.reopen(BrokerOptions::default());
    let abandoned = call(&token, "api", "POST", "/repos/hang", b"{\"n\":2}");
    let ticket = rig
        .broker
        .authorize(S, AGENT, abandoned.clone(), CallKind::Buffered)
        .unwrap()
        .ticket;
    tokio::select! {
        _ = rig.forward(S, abandoned) => panic!("a hung upstream answered"),
        _ = up.arrived() => {}
    }
    assert_eq!(rig.broker.shutdown(Duration::from_secs(5)).await, 0);
    assert_eq!(
        rig.broker.ticket(ticket).unwrap().state,
        TicketState::Uncertain
    );
    // And the stream cut by the first shutdown still reports how it ended.
    assert!(matches!(
        rig.stream(S, call(&token, "api", "GET", "/events", b"")).await,
        Err(r) if r.code == Code::ShuttingDown
    ));
    let rig = rig.reopen(BrokerOptions::default());
    assert!(matches!(
        rig.stream(S, call(&token, "api", "GET", "/events", b"")).await.unwrap(),
        StreamOutcome::Spent { summary: again, .. } if again == summary
    ));
}

// ----- follow-up K-P5, K-P6: how long things are remembered ---------------------

/// #tooth (follow-up K-P5): a request of unknown outcome is never re-sent
/// to an exact retry (same token, same Idempotency-Key, same bytes),
/// however long after `retention_s` the retry comes and across a restart.
/// Before: the Uncertain ticket was dropped at `retention_s` like a
/// completed reply, and the late retry sent the POST a second time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tooth_uncertain_requests_are_never_resent_however_late_the_retry() {
    let up = Upstream::start(|seen| {
        if seen.path.ends_with("/hang") {
            Reply::Hang
        } else {
            Reply::ok(r#"{"done":true}"#)
        }
    })
    .await;
    let cfg = config(&up.origin)
        .replace(
            "retention_s = 600",
            "retention_s = 1\nmax_uncertain_tickets = 2",
        )
        .replace("[broker]", "[broker]\nhttp_listen = \"127.0.0.1:0\"");
    let rig = Rig::new(&cfg);
    let token = rig.token("seat-a");
    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    let serve = |rig: &Rig| {
        let broker = rig.broker.clone();
        async move {
            let listeners = Listeners::bind(&broker).await.unwrap();
            let addr = listeners.http_addr.unwrap();
            (addr, tokio::spawn(listeners.run(broker)))
        }
    };
    // One POST: `Ok(status, code)` or `Err` when the client gave up waiting.
    let post = |addr: std::net::SocketAddr, token: &str, path: &str, key: &str| {
        let request = http
            .post(format!("http://{addr}/v1/service/api/repos/{path}"))
            .bearer_auth(token)
            .header("idempotency-key", key)
            .timeout(Duration::from_millis(400))
            .body(r#"{"transfer":"100 EUR"}"#);
        async move {
            let response = request.send().await.map_err(|_| ())?;
            let status = response.status().as_u16();
            let body: serde_json::Value =
                serde_json::from_slice(&response.bytes().await.map_err(|_| ())?)
                    .unwrap_or_default();
            Ok::<_, ()>((
                status,
                body["error"]["code"].as_str().unwrap_or("").to_owned(),
            ))
        }
    };
    let (addr, serving) = serve(&rig).await;

    // The caller gives up on a POST the upstream has received.
    assert!(post(addr, &token, "hang", "key-1").await.is_err());
    assert_eq!(up.hits(), 1);
    // The broker notices the hangup asynchronously; then it is Uncertain.
    let deadline = Instant::now() + WAIT;
    while rig.broker.status().journal.uncertain == 0 {
        assert!(
            Instant::now() < deadline,
            "the abandoned call never became Uncertain"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Well past retention_s (1 s), the exact retry is still refused.
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert_eq!(
        post(addr, &token, "hang", "key-1").await,
        Ok((409, "uncertain".into()))
    );
    assert_eq!(
        up.hits(),
        1,
        "an Uncertain POST was sent again after retention"
    );

    // The contrast the retention window is for: a *completed* reply is
    // replayed inside the window and forgotten after it.
    assert_eq!(
        post(addr, &token, "ok", "key-2").await,
        Ok((200, String::new()))
    );
    assert_eq!(
        post(addr, &token, "ok", "key-2").await,
        Ok((200, String::new()))
    );
    assert_eq!(up.hits(), 2, "replayed inside the window");
    tokio::time::sleep(Duration::from_millis(2200)).await;
    assert_eq!(
        post(addr, &token, "ok", "key-2").await,
        Ok((200, String::new()))
    );
    assert_eq!(
        up.hits(),
        3,
        "after the window a completed request is a new request"
    );

    // A restart and a compaction do not lose the record either.
    serving.abort();
    let _ = serving.await;
    let rig = rig.reopen(BrokerOptions::default());
    let (addr, _serving) = serve(&rig).await;
    assert_eq!(rig.broker.status().journal.uncertain, 1);
    assert_eq!(
        post(addr, &token, "hang", "key-1").await,
        Ok((409, "uncertain".into()))
    );
    assert_eq!(up.hits(), 3);

    // A new identity is the caller deliberately sending again: allowed.
    assert!(post(addr, &token, "hang", "key-1-again").await.is_err());
    assert_eq!(up.hits(), 4);
    let deadline = Instant::now() + WAIT;
    while rig.broker.status().journal.uncertain < 2 {
        assert!(Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // The ledger of such records is bounded (2 here). Full, it refuses
    // new requests; it does not drop an old record to make room.
    assert_eq!(
        post(addr, &token, "ok", "key-3").await,
        Ok((503, "no_resend_ledger_full".into()))
    );
    assert_eq!(
        post(addr, &token, "hang", "key-1").await,
        Ok((409, "uncertain".into()))
    );
    assert_eq!(up.hits(), 4);

    // Revoking the seat is what makes the records safe to drop: its old
    // tokens can never retry. That fact is journaled, and room appears.
    rig.broker.revoke_seat("seat-a", OPERATOR).unwrap();
    assert_eq!(
        post(addr, &token, "hang", "key-1").await.map(|r| r.0),
        Ok(403)
    );
    let reminted = rig.token("seat-a");
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(
        post(addr, &reminted, "ok", "key-3").await,
        Ok((200, String::new()))
    );
    assert_eq!(rig.broker.status().journal.uncertain, 0);
    assert_eq!(up.hits(), 5);
}

/// #tooth (follow-up K-P6): revoking a row whose retired list is full
/// forgets nothing. Every earlier key stays withheld, on other rows too
/// and across a restart, until `forget`. Before: revocation dropped the
/// oldest retired secret to make room, so an echo of that still-valid key
/// passed.
#[tokio::test]
async fn tooth_revocation_at_capacity_forgets_nothing() {
    fn key(i: usize) -> String {
        format!("sk-ring-key-{i:04}-0123456789")
    }
    let up = Upstream::start(|seen| match seen.path.strip_prefix("/repos/echo-") {
        Some(i) => Reply::ok(format!("an old key: {}", key(i.parse().unwrap()))),
        None => Reply::ok("{}"),
    })
    .await;
    let cfg = format!(
        "{}\n[services.other]\norigin = \"{}\"\nbuffered_paths = [\"/repos\"]\n",
        config(&up.origin),
        up.origin
    );
    let rig = Rig::unset(&cfg);
    rig.set(S, "other", SECRET, false);
    let token = rig.token("seat-a");
    let api = |rig: &Rig| {
        rig.broker
            .rows()
            .into_iter()
            .find(|r| r.namespace == S && r.row == "api")
            .unwrap()
    };
    // The echo arrives on a different row than the one the keys belong to.
    let echoed = |rig: &Rig, i: usize| {
        let request = fresh(call(
            &token,
            "other",
            "GET",
            &format!("/repos/echo-{i}"),
            b"",
        ));
        let broker = rig.broker.clone();
        async move { broker.forward(S, AGENT, request, HeaderMode::Strict).await }
    };

    // Nine keys: the ninth is active, the eight before it fill the list.
    for i in 0..9 {
        rig.set(S, "api", &key(i), false);
    }
    assert_eq!((api(&rig).state.as_str(), api(&rig).retired), ("active", 8));

    // Revoke without forgetting. It succeeds at once and keeps all nine.
    rig.broker.revoke(S, "api", false, OPERATOR).unwrap();
    assert_eq!(
        (api(&rig).state.as_str(), api(&rig).retired),
        ("revoked", 9)
    );
    for i in 0..9 {
        assert_eq!(
            code(echoed(&rig, i).await),
            Code::Withheld,
            "key {i} was forgotten by revoke"
        );
    }
    // Revoking again changes nothing.
    rig.broker.revoke(S, "api", false, OPERATOR).unwrap();
    assert_eq!(api(&rig).retired, 9);

    // Sealed, and still all there after a restart.
    for i in 0..9 {
        assert_no_plaintext(rig.state(), &key(i));
    }
    let rig = rig.reopen(BrokerOptions::default());
    assert_eq!(
        (api(&rig).state.as_str(), api(&rig).retired),
        ("revoked", 9)
    );
    for i in 0..9 {
        assert_eq!(
            code(echoed(&rig, i).await),
            Code::Withheld,
            "key {i} was lost in the restart"
        );
    }

    // A new secret needs the operator to say the old ones may go; until
    // then the row stays revoked and guarded.
    let refused = rig
        .broker
        .set(S, "api", secret(&key(9)), false, false, OPERATOR)
        .unwrap_err();
    assert_eq!(refused.code, Code::BadRequest);
    assert!(
        refused.message.contains("keygate forget"),
        "{}",
        refused.message
    );
    assert_eq!(
        (api(&rig).state.as_str(), api(&rig).retired),
        ("revoked", 9)
    );
    assert_eq!(code(echoed(&rig, 0).await), Code::Withheld);

    // Only the explicit forget removes patterns.
    assert_eq!(rig.broker.forget(S, "api", OPERATOR).unwrap(), 9);
    rig.set(S, "api", &key(9), false);
    assert_eq!((api(&rig).state.as_str(), api(&rig).retired), ("active", 0));
    let passed = echoed(&rig, 0).await.unwrap();
    assert!(contains(&passed.body, key(0).as_bytes()));
    assert_eq!(
        code(echoed(&rig, 9).await),
        Code::Withheld,
        "the new active key is guarded"
    );
    assert_eq!(
        rig.broker.status().guard_pattern_bytes,
        guard_cost(key(9).as_bytes()) + guard_cost(SECRET.as_bytes())
    );
}
