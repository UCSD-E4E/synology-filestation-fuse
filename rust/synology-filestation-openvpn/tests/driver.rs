//! The driver against a peer in this process.
//!
//! `tests/interop.rs` drives a real `openvpn` and is the stronger check, but
//! it needs the binary and is skipped without it. This one needs nothing but a
//! loopback socket, so it runs everywhere the crate is built — and it is the
//! only place the driver's own error handling is exercised, as opposed to the
//! state machine's.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::{Answer, FakeServer, TA_KEY_HEX};
use synology_filestation_openvpn::{SessionConfig, StaticKey, Tunnel};

const PUSH: &str = "PUSH_REPLY,ifconfig 10.90.24.6 255.255.255.0,peer-id 4,cipher AES-256-CBC";

/// A port nothing is listening on, having just been let go of.
fn a_free_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .expect("a local socket")
        .local_addr()
        .expect("bound")
        .port()
}

/// Answer whatever arrives, from `port`, starting `after`.
fn serve_from(mut server: FakeServer, port: u16, after: Duration) {
    tokio::spawn(async move {
        tokio::time::sleep(after).await;
        let socket = tokio::net::UdpSocket::bind(("127.0.0.1", port))
            .await
            .expect("the port is still free");
        let mut buffer = vec![0u8; 4096];
        loop {
            let Ok((len, from)) = socket.recv_from(&mut buffer).await else {
                return;
            };
            for answer in server.handle(&buffer[..len]) {
                let _ = socket.send_to(&answer, from).await;
            }
        }
    });
}

fn config_for(server: &FakeServer) -> SessionConfig {
    let mut config = SessionConfig::new(
        server.ca_pem.clone(),
        "localhost",
        StaticKey::from_hex(TA_KEY_HEX).expect("test vector"),
    );
    // Retransmit briskly: this test is about what happens between attempts,
    // and the default two seconds is a long time to hold a test open.
    config.tls_timeout = Duration::from_millis(100);
    config
}

#[tokio::test]
async fn a_tunnel_comes_up_over_a_real_socket() {
    let server = FakeServer::new(Answer::KeyMaterialThen(PUSH.to_string()));
    let config = config_for(&server);
    let port = a_free_port();
    serve_from(server, port, Duration::ZERO);

    let remote: SocketAddr = ([127, 0, 0, 1], port).into();
    let tunnel = Tunnel::connect(config, remote)
        .await
        .expect("a handshake over loopback");

    assert!(tunnel.failure().is_none(), "and nothing went wrong after");
}

#[tokio::test]
async fn a_refusal_before_the_peer_is_listening_does_not_end_the_tunnel() {
    // The socket is `connect`ed, so the kernel reports ICMP port-unreachable
    // as `ECONNREFUSED` on the next operation — which is exactly what a client
    // dialling a server that has not finished starting gets back, and what a
    // NAT that has forgotten the binding produces mid-session.
    //
    // Treated as fatal it ends the tunnel permanently on a condition the
    // retransmission layer exists to ride out: the peer here answers a few
    // hundred milliseconds later and everything works.
    let server = FakeServer::new(Answer::KeyMaterialThen(PUSH.to_string()));
    let config = config_for(&server);
    let port = a_free_port();
    serve_from(server, port, Duration::from_millis(400));

    let remote: SocketAddr = ([127, 0, 0, 1], port).into();
    let tunnel = Tunnel::connect(config, remote)
        .await
        .expect("the refusals are not the end of it");

    assert!(tunnel.failure().is_none());
}
