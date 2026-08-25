//! The framing `smb2` leaves to whoever supplies the transport.
//!
//! MS-SMB2 §2.1: every message over TCP is preceded by four bytes — one zero,
//! then a three-byte big-endian length. It is the only big-endian thing in the
//! whole protocol, and `smb2`'s transport traits deliberately do not do it:
//! `send` is handed a complete message and `receive` must return exactly one,
//! whatever the stream underneath did with the boundaries.
//!
//! Which is the part worth testing. A stream is entitled to deliver a header
//! one byte at a time and then two messages in a single read, and code that
//! assumes otherwise works against a loopback socket and fails against a NAS
//! at the end of a tunnel.

use std::time::Duration;

use smb2::transport::{TransportReceive, TransportSend};
use synology_filestation_smb::StreamTransport;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A message with its four bytes in front, as it should appear on the wire.
fn framed(payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut frame = vec![0x00, (len >> 16) as u8, (len >> 8) as u8, len as u8];
    frame.extend_from_slice(payload);
    frame
}

#[tokio::test]
async fn a_message_goes_out_with_its_length_in_front() {
    let (ours, mut theirs) = tokio::io::duplex(4096);
    let transport = StreamTransport::new(ours);

    transport.send(b"SMB2...").await.expect("sent");

    let mut wire = [0u8; 11];
    theirs.read_exact(&mut wire).await.expect("it arrived");
    assert_eq!(
        &wire[..4],
        &[0x00, 0x00, 0x00, 0x07],
        "one zero, then seven"
    );
    assert_eq!(&wire[4..], b"SMB2...");
}

#[tokio::test]
async fn a_frame_split_across_reads_is_still_one_message() {
    // A one-byte pipe: every read returns a single byte, so the header itself
    // arrives in four pieces. This is the case a `read` rather than a
    // `read_exact` gets wrong, and it is entirely ordinary on a real link.
    let (ours, mut theirs) = tokio::io::duplex(1);
    let transport = StreamTransport::new(ours);

    tokio::spawn(async move {
        theirs
            .write_all(&framed(b"a message that will be delivered in pieces"))
            .await
            .expect("written");
    });

    let message = tokio::time::timeout(Duration::from_secs(5), transport.receive())
        .await
        .expect("in reasonable time")
        .expect("received");
    assert_eq!(message, b"a message that will be delivered in pieces");
}

#[tokio::test]
async fn two_frames_in_one_read_are_two_messages() {
    // The other half of the same problem: what arrives together must still be
    // taken apart. A `receive` that returned everything it read would hand
    // `smb2` two responses glued together and be told the second is nonsense.
    let (ours, mut theirs) = tokio::io::duplex(4096);
    let transport = StreamTransport::new(ours);

    let mut both = framed(b"first");
    both.extend_from_slice(&framed(b"second"));
    theirs.write_all(&both).await.expect("written at once");

    assert_eq!(transport.receive().await.expect("one"), b"first");
    assert_eq!(transport.receive().await.expect("two"), b"second");
}

#[tokio::test]
async fn a_frame_of_no_length_is_a_message_of_no_bytes() {
    // A header with a zero length is how NetBIOS spells a keep-alive. It is a
    // complete frame carrying nothing, not a stream that has ended, and the
    // next message follows it as normal.
    let (ours, mut theirs) = tokio::io::duplex(4096);
    let transport = StreamTransport::new(ours);

    let mut both = framed(b"");
    both.extend_from_slice(&framed(b"and then a real one"));
    theirs.write_all(&both).await.expect("written");

    assert!(transport.receive().await.expect("a frame").is_empty());
    assert_eq!(
        transport.receive().await.expect("the next one"),
        b"and then a real one"
    );
}

#[tokio::test]
async fn a_frame_that_does_not_begin_with_zero_is_refused() {
    // The first byte is the NetBIOS message type and it is zero for a session
    // message. Anything else means the stream is not where we think it is,
    // and reading on from there produces plausible nonsense.
    let (ours, mut theirs) = tokio::io::duplex(4096);
    let transport = StreamTransport::new(ours);

    theirs
        .write_all(&[0x85, 0x00, 0x00, 0x04, 1, 2, 3, 4])
        .await
        .expect("written");

    assert!(transport.receive().await.is_err());
}

#[tokio::test]
async fn a_stream_that_ends_mid_message_is_not_a_short_message() {
    // Half a message is not a message. Returned as one, `smb2` would try to
    // read a header out of a truncated buffer.
    let (ours, mut theirs) = tokio::io::duplex(4096);
    let transport = StreamTransport::new(ours);

    let mut half = framed(b"the whole thing");
    half.truncate(4 + 5);
    theirs.write_all(&half).await.expect("written");
    drop(theirs);

    assert!(transport.receive().await.is_err(), "it never all arrived");
}

#[tokio::test]
async fn a_message_too_large_to_frame_is_refused_before_it_is_sent() {
    // Three bytes of length cannot say more than 16 MB, so a larger message
    // would be framed as its own remainder — a length field that quietly
    // wraps is how a stream desynchronises.
    let (ours, _theirs) = tokio::io::duplex(4096);
    let transport = StreamTransport::new(ours);

    let enormous = vec![0u8; 16 * 1024 * 1024 + 1];
    assert!(transport.send(&enormous).await.is_err());
}

#[tokio::test]
async fn sending_and_receiving_do_not_wait_for_each_other() {
    // `smb2` drives both halves from one `select!` loop, so a transport that
    // shared a lock between them would deadlock the moment a request went out
    // while a response was being waited for.
    let (ours, mut theirs) = tokio::io::duplex(4096);
    let transport = std::sync::Arc::new(StreamTransport::new(ours));

    let receiving = {
        let transport = transport.clone();
        tokio::spawn(async move { transport.receive().await })
    };

    // With the receive already parked, a send must still go through.
    tokio::time::timeout(Duration::from_secs(5), transport.send(b"a request"))
        .await
        .expect("the send is not held up by the waiting receive")
        .expect("sent");

    let mut wire = vec![0u8; 13];
    theirs.read_exact(&mut wire).await.expect("it arrived");
    theirs.write_all(&framed(b"an answer")).await.expect("sent");

    let answer = tokio::time::timeout(Duration::from_secs(5), receiving)
        .await
        .expect("in reasonable time")
        .expect("the task finished")
        .expect("received");
    assert_eq!(answer, b"an answer");
}

#[tokio::test]
async fn smb2_itself_will_talk_through_it() {
    // Everything above is this transport measured against my reading of what
    // `smb2` wants. This is `smb2` measured against the transport: a real
    // `Connection` built on it, asked to negotiate, and what comes out of the
    // stream is a properly framed SMB2 message rather than anything I decided
    // it should be.
    let (ours, mut theirs) = tokio::io::duplex(64 * 1024);
    let transport = std::sync::Arc::new(StreamTransport::new(ours));

    let mut connection = smb2::client::connection::Connection::from_transport(
        Box::new(std::sync::Arc::clone(&transport)),
        Box::new(transport),
        "a peer that is not there",
    );

    // Nobody answers, so this cannot finish — the point is what it sent.
    let _ = tokio::time::timeout(Duration::from_millis(500), connection.negotiate()).await;

    let mut header = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), theirs.read_exact(&mut header))
        .await
        .expect("something was sent")
        .expect("four bytes of framing");

    assert_eq!(header[0], 0x00, "a NetBIOS session message");
    let len = ((header[1] as usize) << 16) | ((header[2] as usize) << 8) | (header[3] as usize);
    assert!(len > 0, "and it has a body");

    let mut message = vec![0u8; len];
    theirs.read_exact(&mut message).await.expect("the body");
    assert_eq!(
        &message[..4],
        &[0xFE, b'S', b'M', b'B'],
        "which is an SMB2 message, framed exactly as long as it says"
    );
}
