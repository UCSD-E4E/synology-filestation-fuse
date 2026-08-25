//! A TCP conversation over the tunnel's own device.
//!
//! The tunnel carries IP packets and nothing on the machine knows what to do
//! with them, which is exactly the arrangement that needs no tun device and no
//! privileges — and exactly the arrangement where a mistake shows up as
//! silence. So the device is given a peer: a second `smoltcp` interface on the
//! other end of an in-memory link, listening where the NAS would.
//!
//! What this proves is the wiring — layer three with no ethernet header, the
//! address the server assigned us, packets going out and coming back, and the
//! stream semantics anything above is entitled to expect. What it cannot prove
//! is that a real DSM answers, which is the live pass.

use std::net::Ipv4Addr;
use std::time::Duration;

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use synology_filestation_openvpn::{Ifconfig, TunnelDevice, TunnelStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

/// Where the NAS sits inside the tunnel, and the port that matters.
const NAS: (Ipv4Addr, u16) = (Ipv4Addr::new(10, 90, 24, 1), 445);

const OURS: Ifconfig = Ifconfig {
    address: Ipv4Addr::new(10, 90, 24, 6),
    prefix: 24,
};

/// Long enough for a handshake over a link with no latency at all.
const PATIENCE: Duration = Duration::from_secs(5);

/// What the peer has been asked to do next.
enum Ask {
    Send(Vec<u8>),
    Close,
}

/// The other end of the link: an interface that listens where the NAS would,
/// running on its own task because the stream under test now drives itself.
struct Peer {
    device: TunnelDevice,
    interface: Interface,
    sockets: SocketSet<'static>,
    handle: smoltcp::iface::SocketHandle,
    inbound: mpsc::Receiver<Vec<u8>>,
    clock: i64,
}

impl Peer {
    fn listening(outbound: mpsc::Sender<Vec<u8>>, inbound: mpsc::Receiver<Vec<u8>>) -> Self {
        let mut device = TunnelDevice::new(outbound);
        let mut interface = Interface::new(
            Config::new(HardwareAddress::Ip),
            &mut device,
            Instant::from_micros(0),
        );
        interface.update_ip_addrs(|addresses| {
            let _ = addresses.push(IpCidr::new(IpAddress::Ipv4(NAS.0), 24));
        });

        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; 16 * 1024]),
            tcp::SocketBuffer::new(vec![0u8; 16 * 1024]),
        );
        socket.listen(NAS.1).expect("a free port");

        let mut sockets = SocketSet::new(Vec::new());
        let handle = sockets.add(socket);

        Self {
            device,
            interface,
            sockets,
            handle,
            inbound,
            clock: 0,
        }
    }

    fn poll(&mut self) {
        self.clock += 1_000;
        self.interface.poll(
            Instant::from_micros(self.clock),
            &mut self.device,
            &mut self.sockets,
        );
    }

    fn socket(&mut self) -> &mut tcp::Socket<'static> {
        self.sockets.get_mut::<tcp::Socket>(self.handle)
    }

    /// Run until told to stop, doing as asked and reporting what arrives.
    fn spawn(mut self) -> (mpsc::Sender<Ask>, mpsc::Receiver<Vec<u8>>) {
        let (ask, mut asked) = mpsc::channel::<Ask>(64);
        let (heard, hearing) = mpsc::channel::<Vec<u8>>(64);

        tokio::spawn(async move {
            let mut queued: Vec<u8> = Vec::new();
            let mut closing = false;
            loop {
                while let Ok(packet) = self.inbound.try_recv() {
                    self.device.push(packet);
                }
                self.poll();

                if !queued.is_empty() && self.socket().can_send() {
                    let sent = self.socket().send_slice(&queued).unwrap_or(0);
                    queued.drain(..sent);
                }
                if queued.is_empty() && closing && self.socket().may_send() {
                    self.socket().close();
                }

                let mut buffer = [0u8; 4096];
                while self.socket().can_recv() {
                    match self.socket().recv_slice(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(len) => {
                            if heard.send(buffer[..len].to_vec()).await.is_err() {
                                return;
                            }
                        }
                    }
                }

                match asked.try_recv() {
                    Ok(Ask::Send(bytes)) => queued.extend_from_slice(&bytes),
                    Ok(Ask::Close) => closing = true,
                    // Nothing more will be asked, which is not the same as
                    // being finished: what has been handed to `smoltcp` is
                    // not yet on the wire, and a peer that returns here drops
                    // the link out from under its own last segments.
                    Err(_) => {}
                }

                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        });

        (ask, hearing)
    }
}

/// A stream connected to a peer that is already listening.
async fn connected() -> (TunnelStream, mpsc::Sender<Ask>, mpsc::Receiver<Vec<u8>>) {
    let (to_peer, peer_inbound) = mpsc::channel(64);
    let (to_us, our_inbound) = mpsc::channel(64);

    let (ask, heard) = Peer::listening(to_us, peer_inbound).spawn();
    let stream = TunnelStream::connect(to_peer, our_inbound, OURS, NAS, PATIENCE)
        .await
        .expect("the connection comes up");

    (stream, ask, heard)
}

#[tokio::test]
async fn a_connection_is_made_and_carries_bytes_both_ways() {
    let (mut stream, ask, mut heard) = connected().await;

    stream.write_all(b"SMB2 would go here").await.expect("sent");
    assert_eq!(
        heard.recv().await.expect("the far end reads it"),
        b"SMB2 would go here"
    );

    ask.send(Ask::Send(b"and the answer".to_vec()))
        .await
        .expect("the far end speaks");
    let mut answer = [0u8; 14];
    stream.read_exact(&mut answer).await.expect("readable");
    assert_eq!(&answer, b"and the answer");
}

#[tokio::test]
async fn a_read_waits_for_bytes_instead_of_reporting_none() {
    // The whole reason this is an `AsyncRead`. A read that returned zero for
    // "nothing has arrived yet" is indistinguishable from end of stream, and
    // every framing layer above — including the one SMB needs — treats zero as
    // the connection being over. So a read with nothing to give must wait.
    let (mut stream, ask, _heard) = connected().await;

    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_millis(200), stream.read_exact(&mut byte)).await;
    assert!(read.is_err(), "nothing has been sent, so nothing is read");

    ask.send(Ask::Send(b"x".to_vec())).await.expect("queued");
    stream
        .read_exact(&mut byte)
        .await
        .expect("and now there is something");
    assert_eq!(&byte, b"x");
}

#[tokio::test]
async fn the_far_end_hanging_up_is_the_end_of_the_stream() {
    // The other half of the same distinction: when the connection really is
    // over, a read has to say so, or a reader waits for a peer that has gone.
    let (mut stream, ask, _heard) = connected().await;

    ask.send(Ask::Send(b"last words".to_vec()))
        .await
        .expect("queued");
    ask.send(Ask::Close).await.expect("and then goodbye");

    let mut rest = Vec::new();
    let read = tokio::time::timeout(PATIENCE, stream.read_to_end(&mut rest))
        .await
        .expect("the end arrives rather than hanging");

    assert_eq!(read.expect("a clean end"), rest.len());
    assert_eq!(rest, b"last words", "everything sent before the close");
}

#[tokio::test]
async fn bytes_sent_in_pieces_arrive_as_one_stream() {
    // TCP is a byte stream, and the framing layer above this reads a
    // four-byte header and then exactly as many bytes as it named. Both of
    // those cross segment boundaries whenever the far end feels like it.
    let (mut stream, ask, _heard) = connected().await;

    for piece in [&b"one"[..], b"two", b"three"] {
        ask.send(Ask::Send(piece.to_vec())).await.expect("queued");
        // Deliberately spaced, so they cannot arrive as one segment.
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let mut all = [0u8; 11];
    tokio::time::timeout(PATIENCE, stream.read_exact(&mut all))
        .await
        .expect("in reasonable time")
        .expect("readable");
    assert_eq!(&all, b"onetwothree");
}

#[tokio::test]
async fn a_reader_that_takes_its_time_loses_nothing() {
    // More than fits in any one buffer between the stack and the reader. A
    // link drops what it cannot carry; a stream must not, and the difference
    // is the whole reason there is a window.
    let (mut stream, ask, _heard) = connected().await;

    let sent: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let sending = {
        let sent = sent.clone();
        tokio::spawn(async move {
            for chunk in sent.chunks(8 * 1024) {
                if ask.send(Ask::Send(chunk.to_vec())).await.is_err() {
                    return;
                }
            }
            let _ = ask.send(Ask::Close).await;
        })
    };

    let mut received = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), stream.read_to_end(&mut received))
        .await
        .expect("in reasonable time")
        .expect("readable");
    sending.await.expect("the sender finished");

    assert_eq!(received.len(), sent.len(), "nothing was dropped");
    assert_eq!(received, sent, "and nothing was reordered");
}

#[tokio::test]
async fn the_first_thing_out_is_a_syn_to_where_we_were_told() {
    // Before any peer answers: the packets a connection attempt puts on the
    // tunnel should be addressed from where the server said we are, to where
    // we were asked to go. Getting the source wrong is the sort of thing that
    // works locally and fails on the NAS, where the address was assigned for a
    // reason.
    let (to_peer, mut peer_inbound) = mpsc::channel(64);
    let (_to_us, our_inbound) = mpsc::channel(64);

    let attempt = tokio::spawn(TunnelStream::connect(
        to_peer,
        our_inbound,
        Ifconfig {
            address: Ipv4Addr::new(10, 90, 24, 6),
            prefix: 30,
        },
        NAS,
        Duration::from_millis(200),
    ));

    let packet = tokio::time::timeout(PATIENCE, peer_inbound.recv())
        .await
        .expect("something went out")
        .expect("a packet");

    // An IPv4 header with no options, then TCP.
    assert_eq!(packet[0] >> 4, 4, "IPv4");
    assert_eq!(packet[9], 6, "carrying TCP");
    assert_eq!(
        &packet[12..16],
        &[10, 90, 24, 6],
        "from the address we were given"
    );
    assert_eq!(&packet[16..20], &[10, 90, 24, 1], "to the NAS");

    let header_len = ((packet[0] & 0x0f) as usize) * 4;
    let tcp = &packet[header_len..];
    assert_eq!(u16::from_be_bytes([tcp[2], tcp[3]]), 445, "to the SMB port");
    // Flags live in the low six bits of byte 13; SYN is bit 1, and nothing
    // else should be set on a first attempt.
    assert_eq!(tcp[13] & 0x3f, 0x02, "a bare SYN");

    // And nobody answered it, which is a failure rather than a wait forever.
    assert!(attempt.await.expect("the task finished").is_err());
}

#[tokio::test]
async fn a_flushed_write_survives_letting_go_of_the_stream() {
    // Dropping the stream stops the task that owns the stack, so anything it
    // had not sent yet goes with it. That is what makes `flush` load-bearing
    // rather than decorative: a caller that writes, flushes and lets go is
    // entitled to have the write happen.
    let (mut stream, _ask, mut heard) = connected().await;

    stream
        .write_all(b"the last thing written")
        .await
        .expect("queued");
    stream.flush().await.expect("flushed");
    drop(stream);

    let mut collected = Vec::new();
    while collected.len() < 22 {
        let more = tokio::time::timeout(PATIENCE, heard.recv())
            .await
            .expect("the far end already has it")
            .expect("a chunk");
        collected.extend_from_slice(&more);
    }
    assert_eq!(collected, b"the last thing written");
}

#[tokio::test]
async fn a_shutdown_waits_for_what_it_is_shutting_down() {
    // The same promise, made harder: everything written must be out before
    // the connection is finished with, and `shutdown` must not return until
    // it is.
    let (mut stream, _ask, mut heard) = connected().await;

    stream.write_all(b"goodbye").await.expect("queued");
    tokio::time::timeout(PATIENCE, stream.shutdown())
        .await
        .expect("it does not wait forever")
        .expect("shut down");
    drop(stream);

    assert_eq!(
        tokio::time::timeout(PATIENCE, heard.recv())
            .await
            .expect("already delivered")
            .expect("a chunk"),
        b"goodbye"
    );
}
