//! SMB on a byte stream nobody in this workspace dialled.
//!
//! The point of the exercise: the driver reaches an SMB-only NAS from off
//! campus through an in-process OpenVPN client, and the thing the SMB client
//! is handed at the end of that is a stream, not an address. Everything below
//! is ordinary SMB; what is new is only where the bytes go.
//!
//! So the peer here is a real one in the sense that matters — it reads what
//! was actually sent, checks it is the command it should be, and answers with
//! bytes packed by `smb2`'s own wire types. It stops at authentication, which
//! needs an NTLM exchange this test has no business reimplementing: reaching
//! SESSION_SETUP proves NEGOTIATE went out framed, came back, and was
//! understood, which is the whole of what this crate contributes.

use std::time::Duration;

use smb2::msg::header::Header;
use smb2::msg::negotiate::{NegotiateContext, NegotiateResponse, HASH_ALGORITHM_SHA512};
use smb2::pack::{Guid, Pack, ReadCursor, Unpack, WriteCursor};
use smb2::types::flags::{Capabilities, SecurityMode};
use smb2::types::{Command, Dialect};
use synology_filestation_smb::{SmbConfig, SmbTransport};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

/// Header plus body, with no transport framing.
fn pack(header: &Header, body: &dyn Pack) -> Vec<u8> {
    let mut cursor = WriteCursor::new();
    header.pack(&mut cursor);
    body.pack(&mut cursor);
    cursor.into_inner()
}

/// Read one framed message from the stream.
async fn take_frame(stream: &mut DuplexStream) -> Vec<u8> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await.expect("framing");
    assert_eq!(header[0], 0x00, "a NetBIOS session message");
    let len = ((header[1] as usize) << 16) | ((header[2] as usize) << 8) | (header[3] as usize);
    let mut message = vec![0u8; len];
    stream.read_exact(&mut message).await.expect("a body");
    message
}

/// Put one framed message on the stream.
async fn give_frame(stream: &mut DuplexStream, message: &[u8]) {
    let len = message.len();
    let header = [0x00, (len >> 16) as u8, (len >> 8) as u8, len as u8];
    stream.write_all(&header).await.expect("framing");
    stream.write_all(message).await.expect("body");
    stream.flush().await.expect("flushed");
}

fn negotiate_response() -> Vec<u8> {
    let mut header = Header::new_request(Command::Negotiate);
    header.flags.set_response();
    header.credits = 1;

    let body = NegotiateResponse {
        security_mode: SecurityMode::new(SecurityMode::SIGNING_ENABLED),
        dialect_revision: Dialect::Smb3_1_1,
        server_guid: Guid {
            data1: 0x1111_2222,
            data2: 0x3333,
            data3: 0x4444,
            data4: [0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC],
        },
        capabilities: Capabilities::default(),
        max_transact_size: 65536,
        max_read_size: 65536,
        max_write_size: 65536,
        system_time: 132_000_000_000_000_000,
        server_start_time: 131_000_000_000_000_000,
        security_buffer: vec![0x60, 0x00],
        negotiate_contexts: vec![NegotiateContext::PreauthIntegrity {
            hash_algorithms: vec![HASH_ALGORITHM_SHA512],
            salt: vec![0xBB; 32],
        }],
    };
    pack(&header, &body)
}

#[tokio::test]
async fn an_smb_session_starts_on_a_stream_we_were_handed() {
    let (ours, mut theirs) = tokio::io::duplex(64 * 1024);

    // The peer: answer NEGOTIATE, then report what came next.
    let (reached, arrived) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let first = take_frame(&mut theirs).await;
        let mut cursor = ReadCursor::new(&first);
        let header = Header::unpack(&mut cursor).expect("a real SMB2 header");
        assert_eq!(
            header.command,
            Command::Negotiate,
            "the exchange opens here"
        );

        give_frame(&mut theirs, &negotiate_response()).await;

        // Whatever the client says once it believes the dialect.
        let second = take_frame(&mut theirs).await;
        let mut cursor = ReadCursor::new(&second);
        let header = Header::unpack(&mut cursor).expect("a real SMB2 header");
        let _ = reached.send(header.command);

        // And then nothing, which ends the attempt.
    });

    // Spawned rather than held: a future that is never polled does nothing at
    // all, and this one has to be running for the peer to hear anything.
    let attempt = tokio::spawn(async move {
        let cfg = SmbConfig::new("nas.example", "user", "hunter2");
        SmbTransport::over(ours, &cfg).await.map(|_| ())
    });

    assert_eq!(
        tokio::time::timeout(Duration::from_secs(20), arrived)
            .await
            .expect("the client got past negotiate")
            .expect("the peer reported it"),
        Command::SessionSetup,
        "negotiate was framed, answered, understood, and authentication followed"
    );

    // The peer never authenticates it, so the attempt does not succeed — the
    // point was how far it got, and on what.
    assert!(tokio::time::timeout(Duration::from_secs(20), attempt)
        .await
        .expect("it does not hang")
        .expect("the task finished")
        .is_err());
}

/// A stream shaped like the one this exists for.
///
/// `TunnelStream` keeps its in-flight `flush`/`shutdown` waits as boxed
/// futures, and `dyn Future + Send` is `Send` and not `Sync` — so the tunnel's
/// stream is `Send` and not `Sync` either. A `Sync` bound on [`SmbTransport::over`]
/// therefore excluded the only caller it was written for, and nothing noticed,
/// because nothing calls it yet. This mirrors that shape so the compiler
/// notices instead.
///
/// The real proof lands when `synology-filestation-connect` hands a genuine
/// `TunnelStream` to `over`; until then this stands in for it, here rather
/// than in the tunnel's own crate because an SMB crate has no business
/// depending on a VPN client.
struct SendNotSync {
    inner: DuplexStream,
    #[allow(dead_code)]
    waiting: Option<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>>,
}

impl tokio::io::AsyncRead for SendNotSync {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for SendNotSync {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn a_stream_that_is_send_but_not_sync_is_accepted() {
    // This test is about whether it compiles. Running it only shows the bound
    // is not merely satisfiable in principle.
    let (ours, mut theirs) = tokio::io::duplex(64 * 1024);
    let ours = SendNotSync {
        inner: ours,
        waiting: None,
    };

    tokio::spawn(async move {
        let first = take_frame(&mut theirs).await;
        let mut cursor = ReadCursor::new(&first);
        let header = Header::unpack(&mut cursor).expect("a real SMB2 header");
        assert_eq!(header.command, Command::Negotiate);
    });

    let cfg = SmbConfig::new("nas.example", "user", "hunter2");
    let attempt = tokio::time::timeout(Duration::from_secs(20), SmbTransport::over(ours, &cfg));

    assert!(
        attempt.await.expect("it does not hang").is_err(),
        "nobody answered"
    );
}

#[tokio::test]
async fn a_stream_still_needs_a_host_to_name_the_server() {
    // `host` is not only where `connect` dials — it names the server on the
    // wire. `cfg.addr()` always appends a port, so an empty one sails past the
    // SMB client's own guard and surfaces as a malformed UNC path much later.
    let (ours, _theirs) = tokio::io::duplex(64 * 1024);
    let mut cfg = SmbConfig::new("", "user", "hunter2");
    cfg.host = String::new();

    let refused = tokio::time::timeout(Duration::from_secs(5), SmbTransport::over(ours, &cfg))
        .await
        .expect("refused before any of it is attempted");

    assert!(refused.is_err());
}
