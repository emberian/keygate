//! The Unix-socket transport: framed JSON, with the peer's uid taken from
//! the kernel (`SO_PEERCRED` on Linux, `getpeereid` on macOS) for every
//! connection. The uid gates operator requests and uid-bound macaroons.

use crate::engine::{Broker, Caller, HeaderMode, StreamItem, StreamOutcome};
use crate::wire::{read_frame, write_frame};
use base64::{engine::general_purpose::STANDARD, Engine};
use keygate_core::journal::CallKind;
use keygate_core::proto::{Code, Refusal, Request, Response, PROTOCOL_VERSION};
use keygate_core::secret::SecretBytes;
use keygate_core::Namespace;
use std::future::Future;
use std::io;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, BufReader};
use tokio::net::{UnixListener, UnixStream};
use zeroize::Zeroize;

/// Bind the broker socket with `mode`. A leftover socket file from a dead
/// broker is replaced; a live one is an error.
pub fn bind(path: &Path, mode: u32) -> io::Result<UnixListener> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            if std::os::unix::net::UnixStream::connect(path).is_ok() {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!("a broker is already listening on {}", path.display()),
                ));
            }
            std::fs::remove_file(path)?;
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
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(listener)
}

pub async fn serve(broker: Broker, listener: UnixListener) -> io::Result<()> {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let broker = broker.clone();
                tokio::spawn(async move {
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

async fn connection(broker: Broker, stream: UnixStream) -> io::Result<()> {
    let uid = stream.peer_cred()?.uid();
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    while let Some(mut frame) = read_frame(&mut reader).await? {
        let request = serde_json::from_slice::<Request>(&frame);
        frame.zeroize();
        let keep_open = match request {
            Ok(request) => dispatch(&broker, uid, request, &mut reader, &mut writer).await?,
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
async fn until_hangup<R, F>(reader: &mut R, work: F) -> Option<F::Output>
where
    R: AsyncBufRead + Unpin,
    F: Future,
{
    tokio::pin!(work);
    tokio::select! {
        output = &mut work => return Some(output),
        buffered = reader.fill_buf() => match buffered {
            // The peer pipelined its next frame; it is still there.
            Ok(bytes) if !bytes.is_empty() => {}
            _ => return None,
        },
    }
    Some(work.await)
}

/// Handle one request. `Ok(false)` means the peer is gone.
async fn dispatch<R, W>(
    broker: &Broker,
    uid: u32,
    request: Request,
    reader: &mut R,
    writer: &mut W,
) -> io::Result<bool>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
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
            };
            write_frame(writer, &hello).await?;
            return Ok(true);
        }
        Request::MintMacaroon {
            seat,
            allowed_uid,
            caveats,
        } => {
            let minted = operator().and_then(|()| broker.mint(&seat, allowed_uid, caveats, caller));
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
        Request::Set {
            namespace,
            row,
            mut secret_b64,
            cut_existing,
        } => {
            let decoded = STANDARD.decode(secret_b64.as_bytes()).map(SecretBytes::new);
            secret_b64.zeroize();
            let done = operator().and_then(|()| {
                let secret = decoded
                    .map_err(|_| Refusal::new(Code::BadRequest, "secret_b64 is not base64"))?;
                broker.set(namespace, &row, secret, cut_existing, caller)
            });
            write_frame(writer, &answer(done.map(|_| Response::Ok))).await?;
            return Ok(true);
        }
        Request::Revoke { namespace, row } => {
            let done = operator().and_then(|()| broker.revoke(namespace, &row, caller));
            write_frame(writer, &answer(done.map(|_| Response::Ok))).await?;
            return Ok(true);
        }
        Request::RevokeSeat { seat } => {
            let done = operator().and_then(|()| broker.revoke_seat(&seat, caller));
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
            write_frame(
                writer,
                &answer(operator().map(|()| Response::Status(broker.status()))),
            )
            .await?;
            return Ok(true);
        }
        Request::ProviderAuthorize(call) => {
            let kind = provider_authorize_kind(&call);
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
            .authorize(ns, caller, call, kind)
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
            let Some(result) =
                until_hangup(reader, broker.forward(ns, caller, call, HeaderMode::Strict)).await
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
            let Some(result) =
                until_hangup(reader, broker.stream(ns, caller, call, HeaderMode::Strict)).await
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
            let mut watch_peer = true;
            loop {
                // Returning early drops `live`, which aborts the upstream.
                tokio::select! {
                    item = live.items.recv() => match item {
                        Some(StreamItem::Chunk(data)) => write_frame(writer, &Response::Chunk { data: data.to_vec() }).await?,
                        Some(StreamItem::End(summary)) => {
                            write_frame(writer, &Response::End { ticket, summary, spent: false }).await?;
                            break;
                        }
                        None => return Ok(false),
                    },
                    buffered = reader.fill_buf(), if watch_peer => match buffered {
                        Ok(bytes) if !bytes.is_empty() => watch_peer = false,
                        _ => return Ok(false),
                    },
                }
            }
        }
    }
    Ok(true)
}

/// `provider-authorize` reserves for whichever operation the body asks
/// for: a stream ticket when it says `"stream": true`, else a buffered one.
fn provider_authorize_kind(call: &keygate_core::proto::Call) -> CallKind {
    #[derive(serde::Deserialize)]
    struct Probe {
        #[serde(default)]
        stream: bool,
    }
    match serde_json::from_slice::<Probe>(&call.body) {
        Ok(Probe { stream: true }) => CallKind::Stream,
        _ => CallKind::Buffered,
    }
}
