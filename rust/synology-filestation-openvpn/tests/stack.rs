//! A TCP conversation over the tunnel's own device.
//!
//! The tunnel carries IP packets and nothing on the machine knows what to do
//! with them, which is exactly the arrangement that needs no tun device and no
//! privileges — and exactly the arrangement where a mistake shows up as
//! silence. So the device is given a peer: a second `smoltcp` interface on the
//! other end of an in-memory link, listening where the NAS would.
//!
//! What this proves is the wiring — layer three with no ethernet header, the
//! address the server assigned us, packets going out and coming back. What it
//! cannot prove is that a real DSM answers, which is the live pass.

use std::net::Ipv4Addr;

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use synology_filestation_openvpn::{Ifconfig, TunnelDevice, TunnelStream};
use tokio::sync::mpsc;

/// Where the NAS sits inside the tunnel, and the port that matters.
const NAS: (Ipv4Addr, u16) = (Ipv4Addr::new(10, 90, 24, 1), 445);

/// The other end of the link: an interface that listens where the NAS would.
struct Peer {
    device: TunnelDevice,
    interface: Interface,
    sockets: SocketSet<'static>,
    handle: smoltcp::iface::SocketHandle,
    clock: i64,
}

impl Peer {
    fn listening(outbound: mpsc::Sender<Vec<u8>>, inbound: mpsc::Receiver<Vec<u8>>) -> Self {
        let mut device = TunnelDevice::new(outbound, inbound);
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
}

#[tokio::test]
async fn a_connection_is_made_and_carries_bytes_both_ways() {
    let (to_peer, peer_inbound) = mpsc::channel(64);
    let (to_us, our_inbound) = mpsc::channel(64);

    let stream = TunnelStream::connect(
        to_peer,
        our_inbound,
        Ifconfig {
            address: Ipv4Addr::new(10, 90, 24, 6),
            prefix: 24,
        },
        NAS,
    )
    .await
    .expect("a socket, and a SYN on its way");

    let mut peer = Peer::listening(to_us, peer_inbound);

    // The handshake takes a few exchanges, and each side only moves when it
    // is polled.
    for _ in 0..50 {
        peer.poll();
        stream.poll().await;
        if stream.is_open().await && peer.socket().may_send() {
            break;
        }
    }
    assert!(stream.is_open().await, "the connection never came up");

    // Us to the NAS.
    stream.write(b"SMB2 would go here").await.expect("queued");
    for _ in 0..20 {
        stream.poll().await;
        peer.poll();
    }
    let mut received = [0u8; 64];
    let len = peer
        .socket()
        .recv_slice(&mut received)
        .expect("the far end reads it");
    assert_eq!(&received[..len], b"SMB2 would go here");

    // And back.
    peer.socket()
        .send_slice(b"and the answer")
        .expect("the far end speaks");
    for _ in 0..20 {
        peer.poll();
        stream.poll().await;
    }
    let mut answer = [0u8; 64];
    let len = stream.read(&mut answer).await.expect("readable");
    assert_eq!(&answer[..len], b"and the answer");
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

    let stream = TunnelStream::connect(
        to_peer,
        our_inbound,
        Ifconfig {
            address: Ipv4Addr::new(10, 90, 24, 6),
            prefix: 30,
        },
        NAS,
    )
    .await
    .expect("a socket");
    stream.poll().await;

    let packet = peer_inbound.try_recv().expect("something went out");

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
}
