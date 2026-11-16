//! The Unix-socket transport: framed JSON, with the peer's uid taken from
//! the kernel (`SO_PEERCRED` on Linux, `getpeereid` on macOS) for every
//! connection. The uid gates operator requests and uid-bound macaroons, and
//! in a separated deployment a peer with the broker's own uid is not served
//! as a caller.
//!
//! What a connection may make the broker buffer is bounded before any
//! token has been seen: frames are limited to
//! [`PREAUTH_FRAME_BYTES`](keygate_core::proto::PREAUTH_FRAME_BYTES) until
//! the peer `present`s a token that verifies for a row, which raises the
//! limit to that row's request size. Frame memory grows only as bytes
//! arrive, a frame must complete within `request_read_timeout_ms`, and an
//! idle connection is closed after `idle_timeout_ms`.

use crate::engine::{
    Broker, Caller, HeaderMode, StopOnDrop, StreamItem, StreamOutcome, WeakBroker,
};
use crate::wire::{read_frame_body, read_frame_len, write_frame};
use base64::{engine::general_purpose::STANDARD, Engine};
use keygate_core::journal::CallKind;
use keygate_core::proto::{
    Code, Refusal, Request, Response, MAX_FRAME_BYTES, PREAUTH_FRAME_BYTES, PROTOCOL_VERSION,
};
use keygate_core::secret::SecretBytes;
use keygate_core::Namespace;
use std::future::Future;
use std::io;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{watch, Semaphore};
use zeroize::Zeroize;

fn probe_existing_socket(path: &Path) -> io::Result<()> {
    use rustix::net::{
        connect, socket_with, AddressFamily, SocketAddrUnix, SocketFlags, SocketType,
    };

    let addr = SocketAddrUnix::new(path).map_err(io::Error::from)?;
    let sock = socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
        None,
    )
    .map_err(io::Error::from)?;

    match connect(&sock, &addr) {
        Ok(()) => Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            format!("a broker is already listening on {}", path.display()),
        )),
        Err(err) => {
            let io_err = io::Error::from(err);
            if io_err.kind() == io::ErrorKind::WouldBlock
                || matches!(
                    io_err.raw_os_error(),
                    Some(libc::EINPROGRESS | libc::EALREADY | libc::EISCONN)
                )
            {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!("a broker is already listening on {}", path.display()),
                ));
            }
            if matches!(
                io_err.kind(),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
            ) {
                return Ok(());
            }
            Err(io_err)
        }
    }
}

/// Bind the broker socket with `mode`. A leftover socket file from a dead
/// broker is replaced; a live one is an error.
///
/// The socket is bound under a private temporary name, given its mode, and
/// only then renamed into place, so it is never reachable at its public
/// path with any mode but the configured one.
pub fn bind(path: &Path, mode: u32) -> io::Result<UnixListener> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => probe_existing_socket(path)?,
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a socket", path.display()),
            ));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut nonce = [0u8; 4];
    keygate_core::random_bytes(&mut nonce)?;
    let mut staging = path.as_os_str().to_owned();
    staging.push(format!(".{:08x}", u32::from_le_bytes(nonce)));
    let staging = PathBuf::from(staging);
    let listener = UnixListener::bind(&staging)?;
    let installed = std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(mode))
        .and_then(|()| std::fs::rename(&staging, path));
    if let Err(e) = installed {
        let _ = std::fs::remove_file(&staging);
        return Err(e);
    }
    Ok(listener)
}

pub async fn serve(broker: Broker, listener: UnixListener) -> io::Result<()> {
    let connections = Arc::new(Semaphore::new(broker.config().max_connections));
    let idle = Duration::from_millis(broker.config().idle_timeout_ms);
    let deadline = Duration::from_millis(broker.config().request_read_timeout_ms);
    let weak = broker.downgrade();
    let shutdown = broker.subscribe_shutdown();
    let (stop_tx, _) = watch::channel(false);
    let _stop = StopOnDrop(stop_tx);
    loop {
        let permit = connections
            .clone()
            .acquire_owned()
            .await
            .expect("connection semaphore stays open");
        match listener.accept().await {
            Ok((stream, _)) => {
                let weak = weak.clone();
                let stop_rx = _stop.0.subscribe();
                let shutdown_rx = shutdown.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    // A connection error only ever concerns that one peer.
                    let _ = connection(weak, stream, idle, deadline, stop_rx, shutdown_rx).await;
                });
            }
            Err(e) => {
                // Typically fd exhaustion: back off instead of spinning.
                eprintln!("keygate: accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// The frame size a connection may send once a token has verified for a
/// row accepting `max_body` bytes: the body in base64, plus room for the
/// token, headers and the rest of the JSON.
pub fn frame_limit_for(max_body: usize) -> usize {
    (max_body.div_ceil(3) * 4 + PREAUTH_FRAME_BYTES).min(MAX_FRAME_BYTES)
}

/// Per-connection admission and lifecycle state.
struct Conn {
    uid: u32,
    /// Largest frame this peer may currently send.
    frame_limit: usize,
    /// Per-frame read and write deadline.
    deadline: Duration,
    /// Bytes read ahead of the frame being handled (pipelining).
    pending: zeroize::Zeroizing<Vec<u8>>,
    stop_rx: watch::Receiver<bool>,
    shutdown_rx: watch::Receiver<bool>,
}

/// Write a response frame bounded by `deadline` and cancelled if the listener
/// stops or a broker shutdown begins while the write is blocked. Returns
/// `Ok(false)` when stopped by shutdown/listener teardown.
async fn send_frame<W, T>(
    writer: &mut W,
    message: &T,
    deadline: Duration,
    stop_rx: &mut watch::Receiver<bool>,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> io::Result<bool>
where
    W: AsyncWrite + Unpin,
    T: serde::Serialize,
{
    let already_shutting_down = *shutdown_rx.borrow_and_update();
    tokio::select! {
        biased;
        _ = stop_rx.wait_for(|&s| s) => Ok(false),
        _ = shutdown_rx.wait_for(|&s| s), if !already_shutting_down => Ok(false),
        res = tokio::time::timeout(deadline, write_frame(writer, message)) => match res {
            Ok(Ok(())) => Ok(true),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the response frame was not read within the write deadline",
            )),
        },
    }
}

async fn connection(
    weak: WeakBroker,
    stream: UnixStream,
    idle: Duration,
    deadline: Duration,
    stop_rx: watch::Receiver<bool>,
    shutdown_rx: watch::Receiver<bool>,
) -> io::Result<()> {
    let uid = stream.peer_cred()?.uid();
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut conn = Conn {
        uid,
        frame_limit: PREAUTH_FRAME_BYTES,
        deadline,
        pending: zeroize::Zeroizing::new(Vec::new()),
        stop_rx,
        shutdown_rx,
    };
    loop {
        let mut queued =
            std::io::Cursor::new(zeroize::Zeroizing::new(std::mem::take(&mut *conn.pending)));
        let frame = {
            let mut input = (&mut queued).chain(&mut reader);
            // Waiting for a request to start is bounded by the idle timeout
            // and stops immediately when the listener or broker shuts down;
            // once its length has arrived, the whole frame is bounded by the
            // read deadline.
            let next_len = tokio::select! {
                biased;
                _ = conn.stop_rx.wait_for(|&s| s) => break,
                _ = conn.shutdown_rx.wait_for(|&s| s) => break,
                res = tokio::time::timeout(idle, read_frame_len(&mut input)) => res,
            };
            let Ok(len) = next_len else {
                break;
            };
            match len? {
                None => None,
                Some(len) if len > conn.frame_limit => {
                    let refusal = Refusal::new(
                        Code::TooLarge,
                        format!(
                            "frame of {len} bytes exceeds this connection's limit of {}; send \
                             `present` with a token for the row first",
                            conn.frame_limit
                        ),
                    );
                    let _ = send_frame(
                        &mut writer,
                        &Response::Error(refusal),
                        conn.deadline,
                        &mut conn.stop_rx,
                        &mut conn.shutdown_rx,
                    )
                    .await;
                    break;
                }
                Some(len) => {
                    match tokio::time::timeout(deadline, read_frame_body(&mut input, len)).await {
                        Ok(body) => Some(body?),
                        Err(_) => {
                            let refusal = Refusal::new(
                                Code::Timeout,
                                "the frame was not delivered within the read deadline",
                            );
                            let _ = send_frame(
                                &mut writer,
                                &Response::Error(refusal),
                                conn.deadline,
                                &mut conn.stop_rx,
                                &mut conn.shutdown_rx,
                            )
                            .await;
                            break;
                        }
                    }
                }
            }
        };
        let consumed = queued.position() as usize;
        conn.pending = queued.into_inner();
        conn.pending[..consumed].zeroize();
        conn.pending.drain(..consumed);
        let Some(mut frame) = frame else {
            break;
        };
        let request = serde_json::from_slice::<Request>(&frame);
        frame.zeroize();
        let request = match request {
            Ok(request) => request,
            Err(e) => {
                let refusal = Response::Error(Refusal::new(
                    Code::BadRequest,
                    format!("unreadable request: {e}"),
                ));
                if !send_frame(
                    &mut writer,
                    &refusal,
                    conn.deadline,
                    &mut conn.stop_rx,
                    &mut conn.shutdown_rx,
                )
                .await?
                {
                    break;
                }
                continue;
            }
        };
        let Some(broker) = weak.upgrade() else {
            let _ = send_frame(
                &mut writer,
                &Response::Error(Refusal::new(
                    Code::ShuttingDown,
                    "the broker is shutting down and takes no new calls",
                )),
                conn.deadline,
                &mut conn.stop_rx,
                &mut conn.shutdown_rx,
            )
            .await;
            break;
        };
        let keep_open = dispatch(broker, &mut conn, request, &mut reader, &mut writer).await?;
        if !keep_open {
            break;
        }
    }
    Ok(())
}

/// Run `work` unless the peer hangs up first. Returning `None` drops the
/// future, which is what turns an in-flight buffered call `Uncertain` and
/// aborts its upstream request.
async fn until_hangup<R, F>(
    reader: &mut R,
    pending: &mut Vec<u8>,
    limit: usize,
    work: F,
) -> Option<F::Output>
where
    R: AsyncBufRead + Unpin,
    F: Future,
{
    tokio::select! {
        biased;
        _ = watch_hangup(reader, pending, limit) => None,
        output = work => Some(output),
    }
}

/// Drain pipelined input into bounded read-ahead so buffered bytes cannot
/// mask EOF. Excess pipelining closes the connection instead of growing
/// memory indefinitely. All reads are readiness driven.
async fn watch_hangup<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    pending: &mut Vec<u8>,
    limit: usize,
) {
    loop {
        let Ok(bytes) = reader.fill_buf().await else {
            return;
        };
        // Read-ahead is held to what one frame from this peer may be.
        if bytes.is_empty() || pending.len() + bytes.len() > limit + 4 {
            return;
        }
        if pending.capacity() - pending.len() < bytes.len() {
            let want = (pending.len() + bytes.len())
                .max(pending.len() * 2)
                .min(limit + 4);
            let mut grown = Vec::with_capacity(want);
            grown.extend_from_slice(pending);
            pending.zeroize();
            *pending = grown;
        }
        pending.extend_from_slice(bytes);
        let n = bytes.len();
        reader.consume(n);
    }
}

/// Handle one request. Strong `broker` ownership is released before writing
/// any response frame so a peer that stalls reading its socket cannot pin
/// secrets or `broker.lock`. `Ok(false)` means the connection should close.
async fn dispatch<R, W>(
    broker: Broker,
    conn: &mut Conn,
    request: Request,
    reader: &mut R,
    writer: &mut W,
) -> io::Result<bool>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let uid = conn.uid;
    let limit = conn.frame_limit;
    let deadline = conn.deadline;
    let caller = Caller { uid: Some(uid) };
    let is_op = broker.is_operator(uid);
    let operator = || {
        if is_op {
            Ok(())
        } else {
            Err(Refusal::new(
                Code::NotOperator,
                format!("uid {uid} is not a keygate operator"),
            ))
        }
    };
    let answer = |result: Result<Response, Refusal>| result.unwrap_or_else(Response::Error);

    let (ns, call, kind, send) = match request {
        Request::Hello => {
            let hello = Response::Hello {
                protocol: PROTOCOL_VERSION,
                version: env!("CARGO_PKG_VERSION").to_owned(),
                uid,
                operator: is_op,
                namespaces: broker.namespaces(),
                deployment: broker.status_deployment().to_owned(),
                caller: broker.may_call(Some(uid)),
            };
            drop(broker);
            return send_frame(
                writer,
                &hello,
                deadline,
                &mut conn.stop_rx,
                &mut conn.shutdown_rx,
            )
            .await;
        }
        Request::MintMacaroon {
            seat,
            allowed_uid,
            caveats,
        } => {
            let minted = match operator() {
                Ok(()) => {
                    broker
                        .disk(move |b| b.mint(&seat, allowed_uid, caveats, caller))
                        .await
                }
                Err(e) => Err(e),
            };
            drop(broker);
            let resp = answer(minted.map(|token| Response::Token { token }));
            return send_frame(
                writer,
                &resp,
                deadline,
                &mut conn.stop_rx,
                &mut conn.shutdown_rx,
            )
            .await;
        }
        Request::Attenuate { token, caveats } => {
            drop(broker);
            let resp =
                answer(Broker::attenuate(&token, caveats).map(|token| Response::Token { token }));
            return send_frame(
                writer,
                &resp,
                deadline,
                &mut conn.stop_rx,
                &mut conn.shutdown_rx,
            )
            .await;
        }
        Request::Present {
            token,
            namespace,
            row,
        } => {
            let presented = broker
                .preauthorize(namespace, &row, &token, caller)
                .map(|max| {
                    conn.frame_limit = conn.frame_limit.max(frame_limit_for(max));
                    Response::Presented {
                        max_frame_bytes: conn.frame_limit,
                    }
                });
            drop(broker);
            let resp = answer(presented);
            return send_frame(
                writer,
                &resp,
                deadline,
                &mut conn.stop_rx,
                &mut conn.shutdown_rx,
            )
            .await;
        }
        Request::Set {
            namespace,
            row,
            mut secret_b64,
            cut_existing,
            forget_retired,
        } => {
            if let Err(refusal) = operator() {
                drop(broker);
                secret_b64.zeroize();
                return send_frame(
                    writer,
                    &Response::Error(refusal),
                    deadline,
                    &mut conn.stop_rx,
                    &mut conn.shutdown_rx,
                )
                .await;
            }
            let decoded = STANDARD.decode(secret_b64.as_bytes()).map(SecretBytes::new);
            secret_b64.zeroize();
            let done = broker
                .disk(move |broker| {
                    let secret = decoded
                        .map_err(|_| Refusal::new(Code::BadRequest, "secret_b64 is not base64"))?;
                    broker.set(
                        namespace,
                        &row,
                        secret,
                        cut_existing,
                        forget_retired,
                        caller,
                    )
                })
                .await;
            drop(broker);
            let resp = answer(done.map(|_| Response::Ok));
            return send_frame(
                writer,
                &resp,
                deadline,
                &mut conn.stop_rx,
                &mut conn.shutdown_rx,
            )
            .await;
        }
        Request::Revoke {
            namespace,
            row,
            forget,
        } => {
            let done = match operator() {
                Ok(()) => {
                    broker
                        .disk(move |b| b.revoke(namespace, &row, forget, caller))
                        .await
                }
                Err(e) => Err(e),
            };
            drop(broker);
            let resp = answer(done.map(|_| Response::Ok));
            return send_frame(
                writer,
                &resp,
                deadline,
                &mut conn.stop_rx,
                &mut conn.shutdown_rx,
            )
            .await;
        }
        Request::Forget { namespace, row } => {
            let done = match operator() {
                Ok(()) => {
                    broker
                        .disk(move |b| b.forget(namespace, &row, caller))
                        .await
                }
                Err(e) => Err(e),
            };
            drop(broker);
            let resp = answer(done.map(|_| Response::Ok));
            return send_frame(
                writer,
                &resp,
                deadline,
                &mut conn.stop_rx,
                &mut conn.shutdown_rx,
            )
            .await;
        }
        Request::RevokeSeat { seat } => {
            let done = match operator() {
                Ok(()) => broker.disk(move |b| b.revoke_seat(&seat, caller)).await,
                Err(e) => Err(e),
            };
            drop(broker);
            let resp = answer(done.map(|_| Response::Ok));
            return send_frame(
                writer,
                &resp,
                deadline,
                &mut conn.stop_rx,
                &mut conn.shutdown_rx,
            )
            .await;
        }
        Request::Ls => {
            let resp = answer(operator().map(|()| Response::Rows {
                rows: broker.rows(),
            }));
            drop(broker);
            return send_frame(
                writer,
                &resp,
                deadline,
                &mut conn.stop_rx,
                &mut conn.shutdown_rx,
            )
            .await;
        }
        Request::Status => {
            let status = match operator() {
                Ok(()) => Ok(Response::Status(broker.disk(|b| b.status()).await)),
                Err(e) => Err(e),
            };
            drop(broker);
            let resp = answer(status);
            return send_frame(
                writer,
                &resp,
                deadline,
                &mut conn.stop_rx,
                &mut conn.shutdown_rx,
            )
            .await;
        }
        Request::ProviderAuthorize(call) => {
            // Reserve for whichever operation the body asks for.
            let kind = Broker::provider_kind(&call.body);
            (Namespace::Provider, call, kind, false)
        }
        Request::ServiceAuthorize(auth) => {
            let kind = if auth.stream {
                CallKind::Stream
            } else {
                CallKind::Buffered
            };
            (Namespace::Service, auth.call, kind, false)
        }
        Request::ProviderForward(call) => (Namespace::Provider, call, CallKind::Buffered, true),
        Request::ServiceForward(call) => (Namespace::Service, call, CallKind::Buffered, true),
        Request::ProviderStream(call) => (Namespace::Provider, call, CallKind::Stream, true),
        Request::ServiceStream(call) => (Namespace::Service, call, CallKind::Stream, true),
    };

    if !send {
        let authorized = broker
            .disk(move |b| b.authorize(ns, caller, call, kind))
            .await
            .map(|a| Response::Authorized {
                ticket: a.ticket,
                state: a.state.to_owned(),
                existing: a.existing,
                reserved_micro_usd: a.reserved_micro_usd,
            });
        drop(broker);
        let resp = answer(authorized);
        return send_frame(
            writer,
            &resp,
            deadline,
            &mut conn.stop_rx,
            &mut conn.shutdown_rx,
        )
        .await;
    }

    let pending: &mut Vec<u8> = &mut conn.pending;
    let stop_rx = &mut conn.stop_rx;
    let shutdown_rx = &mut conn.shutdown_rx;

    match kind {
        CallKind::Buffered => {
            let result = {
                let outcome = until_hangup(
                    reader,
                    pending,
                    limit,
                    broker.forward(ns, caller, call, HeaderMode::Strict),
                )
                .await;
                drop(broker);
                let Some(result) = outcome else {
                    return Ok(false);
                };
                result
            };
            let reply = result.map(|r| Response::Reply {
                ticket: r.ticket,
                status: r.status,
                headers: r.headers,
                body: r.body,
                replayed: r.replayed,
            });
            send_frame(writer, &answer(reply), deadline, stop_rx, shutdown_rx).await
        }
        CallKind::Stream => {
            let result = {
                let outcome = until_hangup(
                    reader,
                    pending,
                    limit,
                    broker.stream(ns, caller, call, HeaderMode::Strict),
                )
                .await;
                drop(broker);
                let Some(result) = outcome else {
                    return Ok(false);
                };
                result
            };
            let mut live = match result {
                Ok(StreamOutcome::Live(live)) => live,
                Ok(StreamOutcome::Spent { ticket, summary }) => {
                    return send_frame(
                        writer,
                        &Response::End {
                            ticket,
                            summary,
                            spent: true,
                        },
                        deadline,
                        stop_rx,
                        shutdown_rx,
                    )
                    .await;
                }
                Err(refusal) => {
                    return send_frame(
                        writer,
                        &Response::Error(refusal),
                        deadline,
                        stop_rx,
                        shutdown_rx,
                    )
                    .await;
                }
            };
            let completed = until_hangup(reader, pending, limit, async {
                let ticket = live.ticket;
                if !send_frame(
                    writer,
                    &Response::Head {
                        ticket,
                        status: live.status,
                        headers: std::mem::take(&mut live.headers),
                    },
                    deadline,
                    stop_rx,
                    shutdown_rx,
                )
                .await?
                {
                    return Ok::<_, io::Error>(false);
                }
                while let Some(item) = live.items.recv().await {
                    match item {
                        StreamItem::Chunk(data) => {
                            if !send_frame(
                                writer,
                                &Response::Chunk {
                                    data: data.to_vec(),
                                },
                                deadline,
                                stop_rx,
                                shutdown_rx,
                            )
                            .await?
                            {
                                return Ok(false);
                            }
                        }
                        StreamItem::End(summary) => {
                            return send_frame(
                                writer,
                                &Response::End {
                                    ticket,
                                    summary,
                                    spent: false,
                                },
                                deadline,
                                stop_rx,
                                shutdown_rx,
                            )
                            .await;
                        }
                    }
                }
                Ok(false)
            })
            .await;
            completed.unwrap_or(Ok(false))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Client;
    use crate::harden::effective_uid;
    use crate::{BrokerOptions, Listeners};
    use keygate_core::config::Config;

    /// #tooth (C-3): unauthorized operator requests are turned away before
    /// acquiring any bounded `disk_slots` blocking-pool permit.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tooth_non_operator_requests_do_not_consume_disk_pool() {
        let dir = tempfile::tempdir().unwrap();
        Broker::init_state(dir.path()).unwrap();
        let not_me = effective_uid().wrapping_add(1);
        let cfg = Config::parse(&format!(
            "[broker]\ndeployment = \"separated\"\noperator_uids = [{not_me}]\n[services.api]\norigin = \"https://example.com\"\nbuffered_paths = [\"/\"]\n"
        ))
        .unwrap();
        let broker = Broker::open(dir.path(), cfg, BrokerOptions::default()).unwrap();
        let listeners = Listeners::bind(&broker).await.unwrap();
        let socket = listeners.socket_path.clone();
        let serve_task = tokio::spawn(listeners.run(broker.clone()));

        // Occupy every one of the 16 blocking-pool slots.
        let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut releases = Vec::new();
        let mut jobs = Vec::new();
        for _ in 0..16 {
            let (rel_tx, rel_rx) = std::sync::mpsc::channel();
            releases.push(rel_tx);
            let b = broker.clone();
            let started_tx = started_tx.clone();
            jobs.push(tokio::spawn(async move {
                b.disk(move |_| {
                    started_tx.send(()).unwrap();
                    rel_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                })
                .await;
            }));
        }
        for _ in 0..16 {
            started_rx.recv().await.unwrap();
        }

        let mut client = Client::connect(&socket).await.unwrap();
        for req in [
            Request::Set {
                namespace: Namespace::Service,
                row: "api".into(),
                secret_b64: STANDARD.encode("sk-unauthorized-secret-123"),
                cut_existing: false,
                forget_retired: false,
            },
            Request::Revoke {
                namespace: Namespace::Service,
                row: "api".into(),
                forget: false,
            },
            Request::Forget {
                namespace: Namespace::Service,
                row: "api".into(),
            },
            Request::RevokeSeat { seat: "a".into() },
            Request::Status,
            Request::Ls,
        ] {
            let resp = tokio::time::timeout(Duration::from_millis(500), client.call(&req))
                .await
                .expect("non-operator request blocked on saturated disk pool")
                .unwrap();
            assert!(
                matches!(resp, Response::Error(r) if r.code == Code::NotOperator),
                "expected NotOperator"
            );
        }

        for rel in releases {
            let _ = rel.send(());
        }
        for job in jobs {
            job.await.unwrap();
        }
        serve_task.abort();
    }

    /// #tooth (C-4): `unix::bind` probes an existing socket with `SOCK_NONBLOCK`
    /// so a live listener with a completely full accept backlog returns
    /// `AddrInUse` immediately instead of blocking in `connect(2)`.
    #[tokio::test]
    async fn tooth_bind_probes_full_backlog_socket_without_blocking() {
        use rustix::net::{
            bind as bind_sock, connect, listen, socket_with, AddressFamily, SocketAddrUnix,
            SocketFlags, SocketType,
        };
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("full.sock");
        let addr = SocketAddrUnix::new(&sock).unwrap();

        let listen_fd = socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        bind_sock(&listen_fd, &addr).unwrap();
        listen(&listen_fd, 1).unwrap();
        let original_ino = std::fs::symlink_metadata(&sock).unwrap().ino();

        // Saturate the listener's accept queue with nonblocking clients.
        let mut clients = Vec::new();
        let mut hit_would_block = false;
        for _ in 0..64 {
            let c_fd = socket_with(
                AddressFamily::UNIX,
                SocketType::STREAM,
                SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
                None,
            )
            .unwrap();
            match connect(&c_fd, &addr) {
                Ok(()) => clients.push(c_fd),
                Err(err) => {
                    let io_err = io::Error::from(err);
                    assert_eq!(
                        io_err.kind(),
                        io::ErrorKind::WouldBlock,
                        "unexpected: {io_err}"
                    );
                    hit_would_block = true;
                    break;
                }
            }
        }
        assert!(hit_would_block, "accept queue never saturated");

        let probe = tokio::time::timeout(Duration::from_millis(250), async { bind(&sock, 0o600) })
            .await
            .expect("unix::bind blocked on full backlog listener");
        assert_eq!(probe.unwrap_err().kind(), io::ErrorKind::AddrInUse);
        assert_eq!(
            std::fs::symlink_metadata(&sock).unwrap().ino(),
            original_ino,
            "live socket file must not be unlinked"
        );

        // Once the listener closes (allowing a moment in case a sibling test
        // thread forked right before `drop(listen_fd)` and has not yet hit
        // `execve` to close `CLOEXEC` descriptors), the stale socket file is
        // replaced cleanly.
        drop(clients);
        drop(listen_fd);
        let deadline = std::time::Instant::now() + Duration::from_millis(250);
        let rebound = loop {
            match bind(&sock, 0o600) {
                Ok(listener) => break listener,
                Err(e)
                    if e.kind() == io::ErrorKind::AddrInUse
                        && std::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
                Err(e) => panic!("stale socket must be replaced: {e:?}"),
            }
        };
        assert_ne!(
            std::fs::symlink_metadata(&sock).unwrap().ino(),
            original_ino
        );
        drop(rebound);
    }

    /// #tooth (C-7): an unauthenticated peer pipelining `Hello` frames without
    /// reading responses cannot pin `Broker` / `broker.lock` across listener
    /// stop or shutdown, and is closed at the write deadline.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tooth_stalled_hello_pipelining_does_not_pin_broker_or_state_lock() {
        use tokio::io::AsyncWriteExt;

        let dir = tempfile::tempdir().unwrap();
        Broker::init_state(dir.path()).unwrap();
        let cfg_text = "[broker]\ndeployment = \"development\"\nrequest_read_timeout_ms = 250\n[services.api]\norigin = \"http://127.0.0.1:9\"\nbuffered_paths = [\"/\"]\n";
        let cfg = Config::parse(cfg_text).unwrap();
        let broker = Broker::open(dir.path(), cfg, BrokerOptions::default()).unwrap();
        let listeners = Listeners::bind(&broker).await.unwrap();
        let socket = listeners.socket_path.clone();
        let mut serve_task = tokio::spawn(listeners.run(broker.clone()));

        let mut peer = UnixStream::connect(&socket).await.unwrap();
        let body = br#"{"op":"hello"}"#;
        let mut frame = Vec::with_capacity(4 + body.len());
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(body);
        let batch = frame.repeat(256);

        // Pipeline `Hello` requests without reading until the socket buffers fill
        // so the server's `write_frame` blocks waiting on this unread peer.
        while tokio::time::timeout(Duration::from_millis(30), peer.write_all(&batch))
            .await
            .is_ok()
        {}
        tokio::time::sleep(Duration::from_millis(30)).await;

        // Even while `peer` remains open and unread, stopping the listener and
        // dropping the owner's `Broker` releases `broker.lock` immediately
        // (well before the 250ms write deadline).
        serve_task.abort();
        let _ = (&mut serve_task).await;
        drop(broker);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            !crate::harden::state_is_locked(dir.path()),
            "stalled Unix writer pinned broker.lock after listener teardown"
        );
        let reopened = Broker::open(
            dir.path(),
            Config::parse(cfg_text).unwrap(),
            BrokerOptions::default(),
        )
        .expect("reopen must succeed immediately while unread peer socket still exists");
        drop(reopened);
        drop(peer);
    }
}
