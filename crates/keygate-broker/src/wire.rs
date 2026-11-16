//! Frame I/O for the socket protocol: `u32` big-endian length, then JSON.

use keygate_core::proto::MAX_FRAME_BYTES;
use serde::Serialize;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroize;

/// Read one frame. `Ok(None)` means the peer closed the connection.
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match reader.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame of {len} bytes exceeds the {MAX_FRAME_BYTES} limit"),
        ));
    }
    let mut frame = vec![0u8; len];
    reader.read_exact(&mut frame).await?;
    Ok(Some(frame))
}

/// Write one frame. The serialized bytes are zeroed afterwards because
/// frames can carry tokens and secrets.
pub async fn write_frame<W: AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    message: &T,
) -> io::Result<()> {
    let mut body = serde_json::to_vec(message)?;
    let result = async {
        if body.len() > MAX_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame too large",
            ));
        }
        writer.write_all(&(body.len() as u32).to_be_bytes()).await?;
        writer.write_all(&body).await?;
        writer.flush().await
    }
    .await;
    body.zeroize();
    result
}
