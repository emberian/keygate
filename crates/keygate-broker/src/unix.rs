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

use crate::engine::{Broker, Caller, HeaderMode, StreamItem, StreamOutcome};
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
use tokio::sync::Semaphore;
use zeroize::Zeroize;

/// Bind the broker socket with `mode`. A leftover socket file from a dead
/// broker is replaced; a live one is an error.
///
/// The socket is bound under a private temporary name, given its mode, and
/// only then renamed into place, so it is never reachable at its public
/// path with any mode but the configured one.
pub fn bind(path: &Path, mode: u32) -> io::Result<UnixListener> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            if std::os::unix::net::UnixStream::connect(path).is_ok() {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!("a broker is already listening on {}", path.display()),
                ));
            }
        }
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
                    // A connection error only ever concerns that one peer.
                    let _ = connection(broker, stream).await;
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

/// Per-connection admission state.
struct Conn {
    uid: u32,
    /// Largest frame this peer may currently send.
    frame_limit: usize,
    /// Bytes read ahead of the frame being handled (pipelining).
    pending: zeroize::Zeroizing<Vec<u8>>,
}

async fn connection(broker: Broker, stream: UnixStream) -> io::Result<()> {
    let uid = stream.peer_cred()?.uid();
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut conn = Conn {
        uid,
        frame_limit: PREAUTH_FRAME_BYTES,
        pending: zeroize::Zeroizing::new(Vec::new()),
    };
    let idle = Duration::from_millis(broker.config().idle_timeout_ms);
    let deadline = Duration::from_millis(broker.config().request_read_timeout_ms);
    loop {
        let mut queued =
            std::io::Cursor::new(zeroize::Zeroizing::new(std::mem::take(&mut *conn.pending)));
        let frame = {
            let mut input = (&mut queued).chain(&mut reader);
            // Waiting for a request to start is bounded by the idle
            // timeout; once its length has arrived, the whole frame is
            // bounded by the read deadline.
            let Ok(len) = tokio::time::timeout(idle, read_frame_len(&mut input)).await else {
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
                    write_frame(&mut writer, &Response::Error(refusal)).await?;
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
                            write_frame(&mut writer, &Response::Error(refusal)).await?;
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
        let keep_open = match request {
            Ok(request) => dispatch(&broker, &mut conn, request, &mut reader, &mut writer).await?,
            Err(e) => {
                write_frame(
                    &mut writer,
                    &Response::Error(Refusal::new(
                        Code::BadRequest,
                        format!("unreadable request: {e}"),
                    )),
                )
                .await?;
                true
            }
        };
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
        pending.extend_from_slice(bytes);
        let n = bytes.len();
        reader.consume(n);
    }
}

/// Handle one request. `Ok(false)` means the peer is gone.
async fn dispatch<R, W>(
    broker: &Broker,
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
    let pending: &mut Vec<u8> = &mut conn.pending;
    let caller = Caller { uid: Some(uid) };
    let operator = || {
        if broker.is_operator(uid) {
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
                operator: broker.is_operator(uid),
                namespaces: broker.namespaces(),
                deployment: broker.status_deployment().to_owned(),
                caller: broker.may_call(Some(uid)),
            };
            write_frame(writer, &hello).await?;
            return Ok(true);
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
            write_frame(
                writer,
                &answer(minted.map(|token| Response::Token { token })),
            )
            .await?;
            return Ok(true);
        }
        Request::Attenuate { token, caveats } => {
            write_frame(
                writer,
                &answer(Broker::attenuate(&token, caveats).map(|token| Response::Token { token })),
            )
            .await?;
            return Ok(true);
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
            write_frame(writer, &answer(presented)).await?;
            return Ok(true);
        }
        Request::Set {
            namespace,
            row,
            mut secret_b64,
            cut_existing,
            forget_retired,
        } => {
            let decoded = STANDARD.decode(secret_b64.as_bytes()).map(SecretBytes::new);
            secret_b64.zeroize();
            let allowed = operator();
            let done = broker
                .disk(move |broker| {
                    allowed.and_then(|()| {
                        let secret = decoded.map_err(|_| {
                            Refusal::new(Code::BadRequest, "secret_b64 is not base64")
                        })?;
                        broker.set(
                            namespace,
                            &row,
                            secret,
                            cut_existing,
                            forget_retired,
                            caller,
                        )
                    })
                })
                .await;
            write_frame(writer, &answer(done.map(|_| Response::Ok))).await?;
            return Ok(true);
        }
        Request::Revoke {
            namespace,
            row,
            forget,
        } => {
            let allowed = operator();
            let done = broker
                .disk(move |b| allowed.and_then(|()| b.revoke(namespace, &row, forget, caller)))
                .await;
            write_frame(writer, &answer(done.map(|_| Response::Ok))).await?;
            return Ok(true);
        }
        Request::Forget { namespace, row } => {
            let allowed = operator();
            let done = broker
                .disk(move |b| allowed.and_then(|()| b.forget(namespace, &row, caller)))
                .await;
            write_frame(writer, &answer(done.map(|_| Response::Ok))).await?;
            return Ok(true);
        }
        Request::RevokeSeat { seat } => {
            let allowed = operator();
            let done = broker
                .disk(move |b| allowed.and_then(|()| b.revoke_seat(&seat, caller)))
                .await;
            write_frame(writer, &answer(done.map(|_| Response::Ok))).await?;
            return Ok(true);
        }
        Request::Ls => {
            write_frame(
                writer,
                &answer(operator().map(|()| Response::Rows {
                    rows: broker.rows(),
                })),
            )
            .await?;
            return Ok(true);
        }
        Request::Status => {
            let status = broker.disk(|b| b.status()).await;
            write_frame(
                writer,
                &answer(operator().map(|()| Response::Status(status))),
            )
            .await?;
            return Ok(true);
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
        write_frame(writer, &answer(authorized)).await?;
        return Ok(true);
    }

    match kind {
        CallKind::Buffered => {
            let Some(result) = until_hangup(
                reader,
                pending,
                limit,
                broker.forward(ns, caller, call, HeaderMode::Strict),
            )
            .await
            else {
                return Ok(false);
            };
            let reply = result.map(|r| Response::Reply {
                ticket: r.ticket,
                status: r.status,
                headers: r.headers,
                body: r.body,
                replayed: r.replayed,
            });
            write_frame(writer, &answer(reply)).await?;
        }
        CallKind::Stream => {
            let Some(result) = until_hangup(
                reader,
                pending,
                limit,
                broker.stream(ns, caller, call, HeaderMode::Strict),
            )
            .await
            else {
                return Ok(false);
            };
            let mut live = match result {
                Ok(StreamOutcome::Live(live)) => live,
                Ok(StreamOutcome::Spent { ticket, summary }) => {
                    write_frame(
                        writer,
                        &Response::End {
                            ticket,
                            summary,
                            spent: true,
                        },
                    )
                    .await?;
                    return Ok(true);
                }
                Err(refusal) => {
                    write_frame(writer, &Response::Error(refusal)).await?;
                    return Ok(true);
                }
            };
            let completed = until_hangup(reader, pending, limit, async {
                let ticket = live.ticket;
                write_frame(
                    writer,
                    &Response::Head {
                        ticket,
                        status: live.status,
                        headers: std::mem::take(&mut live.headers),
                    },
                )
                .await?;
                while let Some(item) = live.items.recv().await {
                    match item {
                        StreamItem::Chunk(data) => {
                            write_frame(
                                writer,
                                &Response::Chunk {
                                    data: data.to_vec(),
                                },
                            )
                            .await?
                        }
                        StreamItem::End(summary) => {
                            write_frame(
                                writer,
                                &Response::End {
                                    ticket,
                                    summary,
                                    spent: false,
                                },
                            )
                            .await?;
                            return Ok::<_, io::Error>(true);
                        }
                    }
                }
                Ok(false)
            })
            .await;
            return completed.unwrap_or(Ok(false));
        }
    }
    Ok(true)
}
