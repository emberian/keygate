//! Socket client for the framed protocol.

use crate::wire::{read_frame, write_frame};
use keygate_core::proto::{Request, Response};
use std::io;
use std::path::Path;
use tokio::io::BufReader;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;
use zeroize::Zeroize;

pub struct Client {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

impl Client {
    pub async fn connect(socket: &Path) -> io::Result<Self> {
        let (reader, writer) = UnixStream::connect(socket).await?.into_split();
        Ok(Client {
            reader: BufReader::new(reader),
            writer,
        })
    }

    pub async fn send(&mut self, request: &Request) -> io::Result<()> {
        write_frame(&mut self.writer, request).await
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
