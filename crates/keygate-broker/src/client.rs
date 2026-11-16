//! Socket client for the framed protocol.
//!
//! A client sends tokens, and an operator's client sends raw secrets, to
//! whatever is listening on the socket path. So before anything is sent the
//! client checks, from kernel peer credentials, that the listener is the
//! broker it expects.

use crate::wire::{read_frame, write_frame, write_raw_frame};
use keygate_core::proto::{Request, Response, PREAUTH_FRAME_BYTES};
use keygate_core::Namespace;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use tokio::io::BufReader;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;
use zeroize::Zeroize;

/// Who the listener on the socket must be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpectedBroker {
    /// Exactly this uid.
    Uid(u32),
    /// Root or this process's own uid, and only as the owner of the socket
    /// file, provided nobody else could have put a
    /// socket at that path: every directory from `/` down to the one
    /// holding it must belong to that same uid or to root and must not be
    /// group- or world-writable (sticky directories excepted).
    SocketOwner,
}

pub struct Client {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
    /// Largest frame the broker has agreed to read from this connection.
    frame_limit: usize,
    broker_uid: u32,
}

fn untrusted(socket: &Path, why: String) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "refusing to talk to {}: {why}. If this is the right broker, name its uid \
             (--broker-uid / KEYGATE_BROKER_UID)",
            socket.display()
        ),
    )
}

/// Check that the peer on `stream` is the expected broker.
fn verify_broker(socket: &Path, peer_uid: u32, expected: ExpectedBroker) -> io::Result<()> {
    match expected {
        ExpectedBroker::Uid(uid) if uid == peer_uid => Ok(()),
        ExpectedBroker::Uid(uid) => Err(untrusted(
            socket,
            format!("the listener runs as uid {peer_uid}, not the expected uid {uid}"),
        )),
        ExpectedBroker::SocketOwner => {
            // Without being told whom to expect, the only listeners worth
            // trusting with a token or a secret are root and ourselves.
            // "Whoever owns the socket" would include anyone able to bind
            // one in a directory of their own.
            let me = crate::harden::effective_uid();
            if peer_uid != 0 && peer_uid != me {
                return Err(untrusted(
                    socket,
                    format!("the listener runs as uid {peer_uid}, which is neither root nor this user (uid {me})"),
                ));
            }
            let owner = std::fs::symlink_metadata(socket)?.uid();
            if owner != peer_uid {
                return Err(untrusted(
                    socket,
                    format!("the socket file belongs to uid {owner} but the listener runs as uid {peer_uid}"),
                ));
            }
            // The whole path to the socket, not just its directory: a
            // writable ancestor lets someone swap in a directory and a
            // socket of their own, whose owner and listener would agree.
            let parent = socket.parent().filter(|d| !d.as_os_str().is_empty());
            let dir = std::fs::canonicalize(parent.unwrap_or(Path::new(".")))?;
            crate::harden::check_trusted_dirs(&dir, peer_uid).map_err(|e| {
                untrusted(
                    socket,
                    format!("{e}; whoever controls that directory could have replaced the socket"),
                )
            })?;
            Ok(())
        }
    }
}

impl Client {
    /// Connect, trusting the listener only under the
    /// [`ExpectedBroker::SocketOwner`] rule.
    pub async fn connect(socket: &Path) -> io::Result<Self> {
        Client::connect_expecting(socket, ExpectedBroker::SocketOwner).await
    }

    pub async fn connect_expecting(socket: &Path, expected: ExpectedBroker) -> io::Result<Self> {
        let stream = UnixStream::connect(socket).await?;
        let broker_uid = stream.peer_cred()?.uid();
        verify_broker(socket, broker_uid, expected)?;
        let (reader, writer) = stream.into_split();
        Ok(Client {
            reader: BufReader::new(reader),
            writer,
            frame_limit: PREAUTH_FRAME_BYTES,
            broker_uid,
        })
    }

    /// The uid the broker runs as, from kernel peer credentials.
    pub fn broker_uid(&self) -> u32 {
        self.broker_uid
    }

    /// Send a request. A call too large for the broker's pre-authentication
    /// frame limit is preceded by `present`, which proves the token and
    /// raises the limit for this connection.
    pub async fn send(&mut self, request: &Request) -> io::Result<()> {
        let mut frame = serde_json::to_vec(request)?;
        let sent = async {
            if frame.len() > self.frame_limit {
                if let Some((namespace, token, row)) = call_route(request) {
                    self.present(namespace, token, row).await?;
                }
            }
            write_raw_frame(&mut self.writer, &frame).await
        }
        .await;
        frame.zeroize();
        sent
    }

    async fn present(&mut self, namespace: Namespace, token: &str, row: &str) -> io::Result<()> {
        let present = Request::Present {
            token: token.to_owned(),
            namespace,
            row: row.to_owned(),
        };
        write_frame(&mut self.writer, &present).await?;
        match self.recv().await? {
            Response::Presented { max_frame_bytes } => {
                self.frame_limit = max_frame_bytes;
                Ok(())
            }
            Response::Error(refusal) => {
                Err(io::Error::new(io::ErrorKind::PermissionDenied, refusal))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected answer to present",
            )),
        }
    }

    /// The next frame from the broker.
    pub async fn recv(&mut self) -> io::Result<Response> {
        let Some(mut frame) = read_frame(&mut self.reader).await? else {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "broker closed the connection",
            ));
        };
        let response = serde_json::from_slice(&frame)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
        frame.zeroize();
        response
    }

    /// Send a request and read its first response frame. Stream requests
    /// answer with `Head`; keep calling [`Client::recv`] until `End`.
    pub async fn call(&mut self, request: &Request) -> io::Result<Response> {
        self.send(request).await?;
        self.recv().await
    }
}

/// The namespace, token and row of a request that carries a call.
fn call_route(request: &Request) -> Option<(Namespace, &str, &str)> {
    let (namespace, call) = match request {
        Request::ProviderAuthorize(call)
        | Request::ProviderForward(call)
        | Request::ProviderStream(call) => (Namespace::Provider, call),
        Request::ServiceForward(call) | Request::ServiceStream(call) => (Namespace::Service, call),
        Request::ServiceAuthorize(authorize) => (Namespace::Service, &authorize.call),
        _ => return None,
    };
    Some((namespace, &call.token, &call.row))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// #tooth: the client's identity rule for the listener.
    #[test]
    fn tooth_client_refuses_an_unexpected_listener() {
        let me = crate::harden::effective_uid();
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = dir.path().join("keygate.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();

        verify_broker(&socket, me, ExpectedBroker::Uid(me)).unwrap();
        let wrong = verify_broker(&socket, me, ExpectedBroker::Uid(me + 1)).unwrap_err();
        assert!(wrong.to_string().contains("not the expected uid"));

        // Socket owner: fine in a private directory we own...
        verify_broker(&socket, me, ExpectedBroker::SocketOwner).unwrap();
        // ...not when the listener is some third uid, however consistent
        // the socket's ownership looks (parent K-P3)...
        let third = verify_broker(&socket, me + 1, ExpectedBroker::SocketOwner).unwrap_err();
        assert!(third.to_string().contains("neither root nor"), "{third}");
        // ...and not when others could have swapped the socket.
        for writable in [0o770, 0o707, 0o777] {
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(writable))
                .unwrap();
            let err = verify_broker(&socket, me, ExpectedBroker::SocketOwner).unwrap_err();
            assert!(
                err.to_string().contains("could have replaced"),
                "{writable:o}: {err}"
            );
            // Naming the uid is the explicit override.
            verify_broker(&socket, me, ExpectedBroker::Uid(me)).unwrap();
        }
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    /// #tooth (parent K-P3): the directory holding the socket can be
    /// private and still be replaceable, if an ancestor is writable by
    /// others. The whole path is checked.
    #[test]
    fn tooth_client_checks_the_whole_path_to_the_socket() {
        let me = crate::harden::effective_uid();
        let top = tempfile::tempdir().unwrap();
        let chmod = |p: &Path, mode| {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap()
        };
        chmod(top.path(), 0o755);
        let shared = top.path().join("shared");
        let private = shared.join("run");
        std::fs::create_dir_all(&private).unwrap();
        chmod(&private, 0o755);
        let socket = private.join("keygate.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();

        chmod(&shared, 0o755);
        verify_broker(&socket, me, ExpectedBroker::SocketOwner).unwrap();
        for replaceable in [0o777, 0o775] {
            chmod(&shared, replaceable);
            let err = verify_broker(&socket, me, ExpectedBroker::SocketOwner).unwrap_err();
            assert!(
                err.to_string().contains("could have replaced"),
                "{replaceable:o}: {err}"
            );
            assert!(
                err.to_string().contains("shared"),
                "names the weak directory: {err}"
            );
        }
        // A sticky ancestor is fine: entries there cannot be renamed by others.
        chmod(&shared, 0o1777);
        verify_broker(&socket, me, ExpectedBroker::SocketOwner).unwrap();
        chmod(&shared, 0o755);
    }
}
