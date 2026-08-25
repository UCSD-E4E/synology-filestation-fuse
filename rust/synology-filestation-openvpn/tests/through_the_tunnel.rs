//! A TCP conversation, end to end, through a tunnel that really encrypts.
//!
//! Every piece of this crate has been tested against something: the wire
//! format against captured bytes, the key derivation against OpenSSL, the
//! protocol against a real `openvpn`, the TCP stack against a peer on an
//! in-memory link. What none of them cover is all of it at once — and the
//! joins are where this kind of thing goes wrong, quietly, in a way that looks
//! like the network.
//!
//! So: a tunnel to a peer over a real socket, a TCP connection opened through
//! it, and bytes going both ways. The peer decrypts what arrives, hands it to
//! a `smoltcp` interface listening where the NAS would be, and encrypts
//! whatever that interface says back. Nothing on this machine routes
//! 10.90.24.1 and nothing is asked to.
//!
//! What it still cannot prove is that a real DSM answers. That is the live
//! pass, and it needs a person.

mod common;

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use common::{Answer, FakeServer, TA_KEY_HEX};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use synology_filestation_openvpn::{Session, SessionConfig, StaticKey, Tunnel, TunnelDevice, PING};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

/// Where the NAS sits inside the tunnel, and the port that matters.
const NAS: (Ipv4Addr, u16) = (Ipv4Addr::new(10, 90, 24, 1), 445);

const PUSH: &str = "PUSH_REPLY,ifconfig 10.90.24.6 255.255.255.0,peer-id 4,cipher AES-256-CBC";

fn a_free_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .expect("a local socket")
        .local_addr()
        .expect("bound")
        .port()
}

/// The far end: an OpenVPN peer with a TCP stack behind it.
///
/// Two layers in one task, because that is what a NAS is from here — the thing
/// that terminates the tunnel is also the thing listening on 445.
fn spawn_nas(mut server: FakeServer, port: u16) {
    tokio::spawn(async move {
        let socket = tokio::net::UdpSocket::bind(("127.0.0.1", port))
            .await
            .expect("the port is free");

        // The tunnel's inside, from the NAS's point of view.
        let (outbound, mut from_stack) = mpsc::channel::<Vec<u8>>(64);
        let mut device = TunnelDevice::new(outbound);
        let mut interface = Interface::new(
            Config::new(HardwareAddress::Ip),
            &mut device,
            Instant::from_micros(0),
        );
        interface.update_ip_addrs(|addresses| {
            let _ = addresses.push(IpCidr::new(IpAddress::Ipv4(NAS.0), 24));
        });

        let mut listener = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; 16 * 1024]),
            tcp::SocketBuffer::new(vec![0u8; 16 * 1024]),
        );
        listener.listen(NAS.1).expect("a free port");
        let mut sockets = SocketSet::new(Vec::new());
        let handle = sockets.add(listener);

        let mut clock = 0i64;
        let mut client: Option<SocketAddr> = None;
        let mut datagram = vec![0u8; 4096];

        loop {
            tokio::select! {
                received = socket.recv_from(&mut datagram) => {
                    let Ok((len, from)) = received else { return };
                    client = Some(from);
                    let arrived = &datagram[..len];
                    if Session::is_data(arrived) {
                        match server.decrypt_payload(arrived) {
                            // A keepalive is addressed to the tunnel, not
                            // through it.
                            Ok(payload) if payload == PING => {}
                            Ok(payload) => device.push(payload),
                            Err(_) => {}
                        }
                    } else {
                        for answer in server.handle(arrived) {
                            let _ = socket.send_to(&answer, from).await;
                        }
                    }
                }
                // TCP has its own clock: acknowledgements and retransmissions
                // happen on it, not only when something arrives.
                _ = tokio::time::sleep(Duration::from_millis(1)) => {}
            }

            clock += 1_000;
            interface.poll(Instant::from_micros(clock), &mut device, &mut sockets);

            // Whatever the client said, said back to it — proof the bytes
            // survived the whole round trip rather than merely left.
            let listening = sockets.get_mut::<tcp::Socket>(handle);
            let mut buffer = [0u8; 4096];
            while listening.can_recv() && listening.can_send() {
                match listening.recv_slice(&mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(len) => {
                        let answer: Vec<u8> = buffer[..len]
                            .iter()
                            .map(|byte| byte.to_ascii_uppercase())
                            .collect();
                        let _ = listening.send_slice(&answer);
                    }
                }
            }

            clock += 1_000;
            interface.poll(Instant::from_micros(clock), &mut device, &mut sockets);

            // And out through the tunnel, encrypted like anything else.
            while let Ok(packet) = from_stack.try_recv() {
                if let Some(to) = client {
                    let sealed = server.encrypt_payload(&packet);
                    let _ = socket.send_to(&sealed, to).await;
                }
            }
        }
    });
}

#[tokio::test]
async fn a_conversation_completes_through_the_tunnel() {
    let server = FakeServer::new(Answer::KeyMaterialThen(PUSH.to_string()));
    let mut config = SessionConfig::new(
        server.ca_pem.clone(),
        "localhost",
        StaticKey::from_hex(TA_KEY_HEX).expect("test vector"),
    );
    config.tls_timeout = Duration::from_millis(100);

    let port = a_free_port();
    spawn_nas(server, port);

    let remote: SocketAddr = ([127, 0, 0, 1], port).into();
    let tunnel = Tunnel::connect(config, remote).await.expect("a tunnel");

    let mut stream = tunnel
        .open_stream(NAS, Duration::from_secs(20))
        .await
        .expect("a connection to the NAS inside the tunnel");

    stream
        .write_all(b"smb2 would go here")
        .await
        .expect("written");

    let mut answer = [0u8; 18];
    tokio::time::timeout(Duration::from_secs(20), stream.read_exact(&mut answer))
        .await
        .expect("in reasonable time")
        .expect("read");

    assert_eq!(
        &answer, b"SMB2 WOULD GO HERE",
        "the bytes came back, which means they arrived"
    );
}
