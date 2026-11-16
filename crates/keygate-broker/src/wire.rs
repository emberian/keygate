//! Frame I/O for the socket protocol: `u32` big-endian length, then JSON.

use keygate_core::proto::MAX_FRAME_BYTES;
use serde::Serialize;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroize;

/// The largest step by which a frame buffer grows ahead of received data.
const READ_STEP: usize = 64 << 10;

/// A frame's announced length exceeds what the reader accepts.
#[derive(Debug, thiserror::Error)]
#[error("frame of {announced} bytes exceeds the {limit}-byte limit")]
pub struct FrameTooLarge {
    pub announced: usize,
    pub limit: usize,
}

/// Read a frame's length prefix. `Ok(None)` means the peer closed the
/// connection.
pub async fn read_frame_len<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Option<usize>> {
    let mut len = [0u8; 4];
    match reader.read_exact(&mut len).await {
        Ok(_) => Ok(Some(u32::from_be_bytes(len) as usize)),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
        Err(e) => Err(e),
    }
}

/// Read a frame body of `len` bytes. Memory is allocated as bytes arrive,
/// never from the announced length alone, so a peer that announces a large
/// frame and sends nothing costs four bytes.
pub async fn read_frame_body<R: AsyncRead + Unpin>(
    reader: &mut R,
    len: usize,
) -> io::Result<Vec<u8>> {
    let mut frame = Vec::with_capacity(len.min(READ_STEP));
    while frame.len() < len {
        let want = (len - frame.len()).min(READ_STEP);
        let start = frame.len();
        if frame.capacity() - start < want {
            // Grow into a fresh allocation and zero the old one: frames
            // can carry tokens and secrets.
            let mut grown = Vec::with_capacity((start + want).max(start * 2).min(len));
            grown.extend_from_slice(&frame);
            frame.zeroize();
            frame = grown;
        }
        frame.resize(start + want, 0);
        if let Err(e) = reader.read_exact(&mut frame[start..]).await {
            frame.zeroize();
            return Err(e);
        }
    }
    Ok(frame)
}

/// Read one frame of at most `limit` bytes. `Ok(None)` means the peer
/// closed the connection.
pub async fn read_frame_limited<R: AsyncRead + Unpin>(
    reader: &mut R,
    limit: usize,
) -> io::Result<Option<Vec<u8>>> {
    let Some(len) = read_frame_len(reader).await? else {
        return Ok(None);
    };
    if len > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            FrameTooLarge {
                announced: len,
                limit,
            },
        ));
    }
    read_frame_body(reader, len).await.map(Some)
}

/// Read one frame from a trusted peer (the broker, as seen by a client).
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Option<Vec<u8>>> {
    read_frame_limited(reader, MAX_FRAME_BYTES).await
}

/// Write already-serialized frame bytes.
pub async fn write_raw_frame<W: AsyncWrite + Unpin>(writer: &mut W, body: &[u8]) -> io::Result<()> {
    if body.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    writer.write_all(&(body.len() as u32).to_be_bytes()).await?;
    writer.write_all(body).await?;
    writer.flush().await
}

/// Write one frame. The serialized bytes are zeroed afterwards (including if
/// the write future is cancelled) because frames can carry tokens and secrets.
pub async fn write_frame<W: AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    message: &T,
) -> io::Result<()> {
    let body = zeroize::Zeroizing::new(serde_json::to_vec(message)?);
    write_raw_frame(writer, &body).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    /// #tooth: the announced length alone allocates nothing, a frame over
    /// the limit is refused from its four-byte prefix, and a frame arriving
    /// in pieces is reassembled exactly.
    #[tokio::test]
    async fn tooth_frames_are_bounded_before_they_are_buffered() {
        let (mut tx, mut rx) = tokio::io::duplex(1 << 20);
        // Announce 40 MiB, send nothing more.
        tx.write_all(&(40u32 << 20).to_be_bytes()).await.unwrap();
        let len = read_frame_len(&mut rx).await.unwrap().unwrap();
        assert_eq!(len, 40 << 20);
        let body = read_frame_body(&mut rx, len);
        tokio::pin!(body);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut body)
                .await
                .is_err(),
            "still waiting for bytes"
        );

        let (mut tx, mut rx) = tokio::io::duplex(1 << 20);
        tx.write_all(&(70_000u32).to_be_bytes()).await.unwrap();
        let err = read_frame_limited(&mut rx, 65_536).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err
            .get_ref()
            .unwrap()
            .downcast_ref::<FrameTooLarge>()
            .is_some());

        let (mut tx, mut rx) = tokio::io::duplex(4096);
        let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        let expected = payload.clone();
        let writer = tokio::spawn(async move {
            tx.write_all(&(payload.len() as u32).to_be_bytes())
                .await
                .unwrap();
            for piece in payload.chunks(7001) {
                tx.write_all(piece).await.unwrap();
            }
        });
        assert_eq!(
            read_frame_limited(&mut rx, 1 << 20).await.unwrap().unwrap(),
            expected
        );
        writer.await.unwrap();
        assert!(read_frame(&mut rx).await.unwrap().is_none(), "clean close");
    }
}
