//! The opt-in loopback HTTP gateway.
//!
//! `/v1/provider/<row>/<path>` and `/v1/service/<row>/<path>` with the
//! macaroon where an SDK puts its API key: `Authorization: Bearer kgm_...`,
//! `x-api-key: kgm_...` (Anthropic) or `x-goog-api-key: kgm_...`. An
//! unmodified SDK works by pointing its base URL at
//! `http://127.0.0.1:<port>/v1/provider/<row>` and using the macaroon as
//! its API key. A token in the URL query is refused: URLs are logged.
//!
//! TCP offers no peer credentials, so callers here have no uid and
//! uid-bound macaroons are refused. Headers the row does not allow are
//! dropped rather than refused, because SDKs send many.
//!
//! Nothing is buffered for an unauthenticated peer: the token and route
//! are verified from the request head, the body is then limited to what
//! that token may send to that row (and refused from `Content-Length`
//! alone when it announces more), and both the head and the body must
//! arrive within `request_read_timeout_ms`.

use crate::engine::{Broker, Caller, HeaderMode, StreamItem, StreamOutcome};
use bytes::Bytes;
use http_body_util::{BodyExt, Either, Full, Limited};
use hyper::body::{Body, Frame, Incoming};
use hyper::header::{HeaderName, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use keygate_core::journal::{CallKind, TicketId};
use keygate_core::macaroon::TOKEN_PREFIX;
use keygate_core::proto::{Call, Code, Refusal};
use keygate_core::Namespace;
use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Semaphore};

/// Headers a token may arrive in. All are stripped before forwarding.
const TOKEN_HEADERS: &[&str] = &["authorization", "x-api-key", "x-goog-api-key"];
const IDEMPOTENCY_KEY: &str = "idempotency-key";
const KEYGATE_REQUEST_ID: &str = "x-keygate-request-id";
/// Largest request head (request line and headers) the gateway reads.
const MAX_HEAD_BYTES: usize = 128 << 10;

type GatewayBody = Either<Full<Bytes>, RelayBody>;

/// Bind the gateway. Anything but a loopback address is refused: the
/// gateway authenticates by bearer token alone and must not be reachable
/// from another host.
pub async fn bind(addr: SocketAddr) -> io::Result<TcpListener> {
    if !addr.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("gateway address {addr} is not loopback"),
        ));
    }
    TcpListener::bind(addr).await
}

pub async fn serve(broker: Broker, listener: TcpListener) -> io::Result<()> {
    if !listener.local_addr()?.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "gateway listener is not bound to loopback",
        ));
    }
    let connections = Arc::new(Semaphore::new(broker.config().max_connections));
    loop {
        let permit = connections
            .clone()
            .acquire_owned()
            .await
            .expect("connection semaphore stays open");
        match listener.accept().await {
            Ok((stream, _)) => {
                let broker = broker.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let head_deadline =
                        Duration::from_millis(broker.config().request_read_timeout_ms);
                    let service = service_fn(move |request| handle(broker.clone(), request));
                    let _ = hyper::server::conn::http1::Builder::new()
                        .timer(TokioTimer::new())
                        .header_read_timeout(head_deadline)
                        .max_buf_size(MAX_HEAD_BYTES)
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
            Err(e) => {
                eprintln!("keygate: gateway accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

async fn handle(
    broker: Broker,
    request: Request<Incoming>,
) -> Result<Response<GatewayBody>, Infallible> {
    Ok(route(broker, request)
        .await
        .unwrap_or_else(|refusal| refusal_response(&refusal)))
}

async fn route(
    broker: Broker,
    request: Request<Incoming>,
) -> Result<Response<GatewayBody>, Refusal> {
    let (parts, body) = request.into_parts();

    // The raw request path, exactly as the client spelled it. Splitting
    // off `/v1/<ns>/<row>` leaves the upstream path, which then has to
    // pass `plain_path` like any other.
    let (ns, row, path) = split_route(parts.uri.path())?;
    let token = bearer(&parts.headers)?;
    let caller = Caller { uid: None };

    // Before a single body byte is read: is this token good for this row,
    // and how much may it send?
    let limit = broker.preauthorize(ns, row, &token, caller)?;
    let announced = parts
        .headers
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if let Some(announced) = announced.filter(|len| *len > limit as u64) {
        return Err(Refusal::new(
            Code::TooLarge,
            format!(
                "request announces {announced} bytes; this token may send {limit} to {ns}/{row}"
            ),
        ));
    }

    let mut headers = Vec::new();
    let mut request_id = None;
    let last_event_id = parts
        .headers
        .get("last-event-id")
        .map(|v| {
            v.to_str()
                .map(str::to_owned)
                .map_err(|_| Refusal::new(Code::HeaderRefused, "invalid last-event-id"))
        })
        .transpose()?;
    for (name, value) in &parts.headers {
        if TOKEN_HEADERS.contains(&name.as_str()) || name.as_str() == "last-event-id" {
            // The macaroon never travels upstream.
            continue;
        }
        let Ok(value) = value.to_str() else { continue };
        match name.as_str() {
            KEYGATE_REQUEST_ID => {
                request_id = Some(value.to_owned());
                continue;
            }
            // Identifies the request to keygate and, where the row allows
            // the header, to the upstream as well.
            IDEMPOTENCY_KEY => request_id = request_id.or_else(|| Some(value.to_owned())),
            _ => {}
        }
        headers.push((name.as_str().to_owned(), value.to_owned()));
    }

    let read_deadline = Duration::from_millis(broker.config().request_read_timeout_ms);
    let body = match tokio::time::timeout(read_deadline, Limited::new(body, limit).collect()).await {
        Ok(Ok(body)) => body.to_bytes(),
        Ok(Err(e)) => {
            return Err(Refusal::new(
                Code::TooLarge,
                format!("request body unreadable or over the {limit} bytes this token may send to {ns}/{row}: {e}"),
            ))
        }
        Err(_) => {
            return Err(Refusal::new(
                Code::Timeout,
                "the request body was not delivered within the read deadline",
            ))
        }
    };

    let kind = broker.classify(ns, row, path, &body)?;
    let method = parts.method.as_str().to_owned();
    // A request with no idempotency key is deduplicated only where a
    // replay is the right answer: a buffered, non-idempotent call whose
    // reply may have been lost. Reads must hit the upstream every time,
    // and a stream reconnect always gets a fresh ticket.
    if request_id.is_none()
        && (kind == CallKind::Stream || matches!(method.as_str(), "GET" | "HEAD"))
    {
        request_id = Some(format!("gateway-{}", fresh_id()?));
    }

    let call = Call {
        token,
        row: row.to_owned(),
        method,
        path: path.to_owned(),
        query: parts.uri.query().map(str::to_owned),
        headers,
        body: body.to_vec(),
        request_id,
        last_event_id,
    };

    match kind {
        CallKind::Buffered => {
            let reply = broker.forward(ns, caller, call, HeaderMode::Filter).await?;
            let mut response = upstream_response(reply.status, &reply.headers, reply.ticket);
            if reply.replayed {
                response = response.header("x-keygate-replayed", "true");
            }
            finish(response, Either::Left(Full::new(Bytes::from(reply.body))))
        }
        CallKind::Stream => match broker.stream(ns, caller, call, HeaderMode::Filter).await? {
            StreamOutcome::Live(live) => {
                let response = upstream_response(live.status, &live.headers, live.ticket);
                finish(response, Either::Right(RelayBody { items: live.items }))
            }
            StreamOutcome::Spent { summary, .. } => Err(Refusal {
                code: Code::InFlight,
                message:
                    "this exact stream request already ran; reconnect with a new idempotency key"
                        .to_owned(),
                summary: Some(summary),
            }),
        },
    }
}

fn split_route(path: &str) -> Result<(Namespace, &str, &str), Refusal> {
    let not_found = || {
        Refusal::new(
            Code::UnknownRow,
            "gateway routes are /v1/provider/<row>/<path> and /v1/service/<row>/<path>",
        )
    };
    let rest = path.strip_prefix("/v1/").ok_or_else(not_found)?;
    let (ns, rest) = if let Some(rest) = rest.strip_prefix("provider/") {
        (Namespace::Provider, rest)
    } else if let Some(rest) = rest.strip_prefix("service/") {
        (Namespace::Service, rest)
    } else {
        return Err(not_found());
    };
    let (row, upstream_path) = match rest.find('/') {
        Some(slash) => rest.split_at(slash),
        None => (rest, "/"),
    };
    if !keygate_core::valid_name(row) {
        return Err(not_found());
    }
    Ok((ns, row, upstream_path))
}

/// The macaroon, from wherever an SDK put its API key.
fn bearer(headers: &hyper::HeaderMap) -> Result<String, Refusal> {
    let text = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let from_authorization = text(AUTHORIZATION.as_str()).and_then(|v| {
        v.strip_prefix("Bearer ")
            .or_else(|| v.strip_prefix("bearer "))
    });
    [from_authorization, text("x-api-key"), text("x-goog-api-key")]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|candidate| candidate.starts_with(TOKEN_PREFIX))
        .map(str::to_owned)
        .ok_or_else(|| {
            Refusal::new(
                Code::BadToken,
                "expected `Authorization: Bearer kgm_<macaroon>` (or the macaroon in x-api-key / x-goog-api-key)",
            )
        })
}

fn fresh_id() -> Result<String, Refusal> {
    TicketId::random()
        .map(|id| id.to_string())
        .map_err(|e| Refusal::new(Code::Internal, e.to_string()))
}

fn upstream_response(
    status: u16,
    headers: &[(String, String)],
    ticket: TicketId,
) -> hyper::http::response::Builder {
    let mut response =
        Response::builder().status(StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY));
    for (name, value) in headers {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            response = response.header(name, value);
        }
    }
    response.header("x-keygate-ticket", ticket.to_string())
}

fn finish(
    response: hyper::http::response::Builder,
    body: GatewayBody,
) -> Result<Response<GatewayBody>, Refusal> {
    response
        .body(body)
        .map_err(|e| Refusal::new(Code::Internal, format!("building the response failed: {e}")))
}

fn refusal_response(refusal: &Refusal) -> Response<GatewayBody> {
    let body = serde_json::json!({
        "type": "error",
        "error": {
            "type": "keygate_refusal",
            "code": refusal.code,
            "message": refusal.message,
            "summary": refusal.summary,
        }
    });
    let status = StatusCode::from_u16(refusal.code.http_status())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut response = Response::new(Either::Left(Full::new(Bytes::from(body.to_string()))));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

/// A stream reply body fed by the relay task. A stream that did not end
/// cleanly (revoked, withheld, upstream error) surfaces as a body error, so
/// the HTTP client sees a broken transfer rather than a short, valid-looking
/// one. Dropping the body (client went away) aborts the upstream.
struct RelayBody {
    items: mpsc::Receiver<StreamItem>,
}

impl Body for RelayBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        match self.items.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(StreamItem::Chunk(data))) => Poll::Ready(Some(Ok(Frame::data(data)))),
            Poll::Ready(Some(StreamItem::End(summary))) if summary.complete => Poll::Ready(None),
            Poll::Ready(Some(StreamItem::End(summary))) => Poll::Ready(Some(Err(
                io::Error::other(format!("keygate cut the stream: {:?}", summary.closed_by)),
            ))),
            Poll::Ready(None) => Poll::Ready(Some(Err(io::Error::other(
                "keygate stream relay ended without a summary",
            )))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes() {
        let (ns, row, path) = split_route("/v1/provider/anthropic/v1/messages").unwrap();
        assert_eq!(
            (ns, row, path),
            (Namespace::Provider, "anthropic", "/v1/messages")
        );
        let (ns, row, path) = split_route("/v1/service/gh/repos/o/r").unwrap();
        assert_eq!((ns, row, path), (Namespace::Service, "gh", "/repos/o/r"));
        // The upstream path is passed through raw; plain_path refuses it later.
        assert_eq!(
            split_route("/v1/service/gh/a/%2e%2e/b").unwrap().2,
            "/a/%2e%2e/b"
        );
        for bad in [
            "/",
            "/v1/pool/x/y",
            "/v2/provider/x/y",
            "/v1/provider//y",
            "/v1/provider/../y",
        ] {
            assert!(split_route(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn bearer_sources() {
        let mut headers = hyper::HeaderMap::new();
        assert!(bearer(&headers).is_err());
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer sk-ant-raw"));
        assert!(
            bearer(&headers).is_err(),
            "a raw key is not a keygate token"
        );
        headers.insert("x-goog-api-key", HeaderValue::from_static("kgm_goog"));
        assert_eq!(bearer(&headers).unwrap(), "kgm_goog");
        headers.insert("x-api-key", HeaderValue::from_static("kgm_abc"));
        assert_eq!(bearer(&headers).unwrap(), "kgm_abc");
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer kgm_xyz"));
        assert_eq!(bearer(&headers).unwrap(), "kgm_xyz");
    }
}
