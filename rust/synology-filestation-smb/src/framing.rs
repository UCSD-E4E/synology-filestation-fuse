//! An `smb2` transport over any byte stream.
//!
//! `smb2` asks for two things and supplies neither: `send` is handed a
//! complete SMB2 message and must put it on the wire, `receive` must return
//! exactly one message however the stream underneath delivered it. Between
//! them sits the framing from MS-SMB2 §2.1 — four bytes, one zero and then a
//! three-byte big-endian length, the only big-endian thing in the protocol.
//!
//! The crate ships that over TCP. This is the same thing over *anything* that
//! reads and writes, which is what lets the same SMB client run over a socket
//! and over the userspace TCP stack inside an OpenVPN tunnel, with nothing in
//! between knowing the difference.
//!
//! Deliberately generic rather than tied to the tunnel: what this needs is
//! [`AsyncRead`] + [`AsyncWrite`], the tunnel's stream is one, and a transport
//! that named it would drag a VPN client into a crate about SMB.

use async_trait::async_trait;
use smb2::error::{Error, Result};
use smb2::transport::{TransportReceive, TransportSend};
use tokio::io::{split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::Mutex;

/// The largest message the framing can describe.
///
/// Three bytes of length stop here — one short of 16 MiB, not at it. A message
/// beyond this is framed as its own remainder: 16 MiB exactly becomes the
/// header `[00, 00, 00, 00]`, an empty frame followed by 16 MiB of body the
/// peer reads as headers, and every message after that is nonsense.
///
/// The same arithmetic as the missing check in `receive`, which is what makes
/// getting it wrong here easy: three bytes cannot say 16 MiB, so a limit
/// written as 16 MiB is one value too generous in one direction and could
/// never fire in the other.
const MAX_FRAME_SIZE: usize = 0xFF_FFFF;

/// An `smb2` transport over one byte stream.
///
/// `Send` is asked of the stream and `Sync` deliberately is not: the tunnel's
/// stream holds boxed futures, so it is one and not the other, and the mutexes
/// below make this type `Sync` regardless. A `Sync` bound here would exclude
/// the only stream this was written for.
///
/// The halves are locked separately on purpose. `smb2` drives both from a
/// single `select!` loop — a request going out while a response is being
/// waited for is the ordinary case, not a rare one — so a lock shared between
/// them would deadlock the first time it happened.
pub struct StreamTransport<S> {
    reader: Mutex<ReadHalf<S>>,
    writer: Mutex<WriteHalf<S>>,
}

impl<S: AsyncRead + AsyncWrite> StreamTransport<S> {
    pub fn new(stream: S) -> Self {
        let (reader, writer) = split(stream);
        Self {
            reader: Mutex::new(reader),
            writer: Mutex::new(writer),
        }
    }
}

#[async_trait]
impl<S: AsyncRead + AsyncWrite + Send> TransportSend for StreamTransport<S> {
    async fn send(&self, data: &[u8]) -> Result<()> {
        let len = data.len();
        if len > MAX_FRAME_SIZE {
            return Err(Error::invalid_data(format!(
                "message size {len} exceeds maximum frame size {MAX_FRAME_SIZE}"
            )));
        }

        let header = [0x00, (len >> 16) as u8, (len >> 8) as u8, len as u8];

        let mut writer = self.writer.lock().await;
        writer.write_all(&header).await.map_err(Error::Io)?;
        writer.write_all(data).await.map_err(Error::Io)?;
        writer.flush().await.map_err(Error::Io)?;
        Ok(())
    }
}

#[async_trait]
impl<S: AsyncRead + AsyncWrite + Send> TransportReceive for StreamTransport<S> {
    async fn receive(&self) -> Result<Vec<u8>> {
        let mut reader = self.reader.lock().await;

        // `read_exact` rather than `read`: a stream may hand over one byte at
        // a time, and the header arriving in four pieces is ordinary rather
        // than exotic — especially over a tunnel, where what a segment holds
        // has nothing to do with what a message needs.
        let mut header = [0u8; 4];
        reader.read_exact(&mut header).await.map_err(ended)?;

        // The NetBIOS message type, which is zero for a session message.
        // Anything else means the stream is not where we believe it is, and
        // reading on from there produces plausible nonsense rather than an
        // error.
        if header[0] != 0x00 {
            return Err(Error::invalid_data(format!(
                "invalid transport frame: first byte must be 0x00, got 0x{:02X}",
                header[0]
            )));
        }

        // Three bytes, so at most 16 MB minus one — which is below
        // `MAX_FRAME_SIZE` by construction. There is deliberately no bound
        // check here: one could never fire, and a guard that cannot fire reads
        // as protection that is not there. The allocation is bounded by the
        // header's own width.
        let len = ((header[1] as usize) << 16) | ((header[2] as usize) << 8) | (header[3] as usize);

        let mut message = vec![0u8; len];
        reader.read_exact(&mut message).await.map_err(ended)?;
        Ok(message)
    }
}

/// A stream that stopped in the middle of a message is a connection that
/// ended, not a short message — which is the distinction that keeps a
/// truncated response from being handed upwards as a real one.
fn ended(error: std::io::Error) -> Error {
    if error.kind() == std::io::ErrorKind::UnexpectedEof {
        Error::Disconnected
    } else {
        Error::Io(error)
    }
}
