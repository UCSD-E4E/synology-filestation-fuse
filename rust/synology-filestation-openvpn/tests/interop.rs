//! Interoperability against a real OpenVPN.
//!
//! Everything else in this crate is checked against captured bytes or against
//! itself. This drives an actual `openvpn` process — as the *server* end, on
//! loopback — and completes the opening exchange with it. That is the only
//! test here that can fail because we misunderstood the protocol rather than
//! because we mis-implemented what we understood.
//!
//! It needs no privileges and no tun device: `--dev null` gives a peer that
//! speaks the control channel and has nowhere to put the tunnel afterwards,
//! which is exactly as far as this goes.
//!
//! ```text
//! nix develop -c cargo test -p synology-filestation-openvpn --test interop -- --ignored --nocapture
//! ```
//!
//! `#[ignore]`d because it needs the `openvpn` binary; set `OPENVPN_BIN` if it
//! is not on `PATH`.

use std::io::ErrorKind;
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use synology_filestation_openvpn::{
    ClientAuth, ControlChannel, DataChannel, DataKeys, KeyDirection, KeyId, Opcode, Session,
    SessionConfig, SessionId, StaticKey, TlsAuth, PING,
};

/// The same throwaway key the other tests use. It is a test vector, not a
/// credential, and here it also has to reach the `openvpn` process — which is
/// why it is written out in the file format rather than kept as bytes.
const TA_KEY_HEX: &str = concat!(
    "95300e5e0e76a0ed8f58bcdea1b9475b53e468c00d3ba0fb3400e40b2d22ea32",
    "bc5f2f826ebf6378648286697501db24bf2696fa4597231db5b680f6c2e04495",
    "24116f6ea79ae602988d7cf021d8fd35829ddb0249ca4e265723bd93c8141c31",
    "1c2c4bdd4142d7ac06eac732903ed85e547ea8af3c4c04149a4a48e3f31b4bb4",
    "9d73ec8c5da92958a44a23b1e978b4ea0c91b915d650975ede0e784c54544c2f",
    "3947bd3deb19a49925ae2e8b0675d79c77d31116502426e0d740ec23d1d9a634",
    "ba08b32b4ad94b5e5f5eda002e07120ef092c3b08f4bc0842de9ebb0dc953dad",
    "59a382aeb73f10a3b3a75277d045906b48e82f6d5aba62017fc218180fdb4ae6",
);

const OUR_SESSION: SessionId =
    SessionId::from_bytes([0x0e, 0x4e, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);

#[test]
#[ignore = "spawns a real openvpn process"]
fn a_real_openvpn_answers_our_opening_reset() {
    let server = OpenVpnServer::start();

    let socket = connected_socket(server.port);

    let key = StaticKey::from_hex(TA_KEY_HEX).expect("test vector");
    let mut channel = ControlChannel::new(
        TlsAuth::new(&key, KeyDirection::Inverse),
        OUR_SESSION,
        Duration::from_secs(2),
    );
    // Read what arrives a second time, to look at it rather than just accept
    // it. Same key, same direction: this is the client's view.
    let observer = TlsAuth::new(&key, KeyDirection::Inverse);

    channel.open();

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut buf = [0u8; 4096];
    let mut answer = None;

    while Instant::now() < deadline && answer.is_none() {
        let now = Instant::now();
        while let Some(datagram) = channel.poll_transmit(now, net_time()) {
            socket.send(&datagram).expect("send");
        }

        match socket.recv(&mut buf) {
            // A keepalive is not for the control channel.
            Ok(len) if is_data(&buf[..len]) => continue,
            Ok(len) => {
                let datagram = &buf[..len];
                let (packet, _) = observer
                    .unwrap(datagram)
                    .expect("openvpn signed it with the key we gave it");
                channel
                    .handle(datagram, Instant::now())
                    .expect("and the channel accepts it");

                if packet.opcode == Opcode::ControlHardResetServerV2 {
                    answer = Some(packet);
                }
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {}
            Err(error) if error.kind() == ErrorKind::TimedOut => {}
            Err(error) => panic!("recv failed: {error}"),
        }
    }

    let answer = answer.unwrap_or_else(|| {
        panic!(
            "openvpn never answered our reset.\n--- its log ---\n{}",
            server.log()
        )
    });

    assert_eq!(
        channel.remote_session(),
        Some(answer.session_id),
        "the channel latched onto the session openvpn chose"
    );

    let acks = answer
        .acks
        .as_ref()
        .expect("a server reset acknowledges the client reset that caused it");
    assert_eq!(
        acks.ids(),
        &[0],
        "and what it acknowledges is our first message"
    );
    assert_eq!(
        acks.session_id(),
        OUR_SESSION,
        "addressed to the session we opened, which is how we know it is for us"
    );
}

/// Whether a datagram belongs to the data channel rather than the control one.
///
/// Every loop here needs this. The server sends a keepalive once a second,
/// and a data packet handed to the control channel fails its `tls-auth`
/// check — so a loop that does not sort them out fails whenever a keepalive
/// lands inside it. That is rare enough to pass by luck when the tests are
/// quick and reliable once they are not, which is the worst shape a test
/// failure can have.
fn is_data(datagram: &[u8]) -> bool {
    match datagram.first() {
        Some(&first) => {
            let opcode = first >> 3;
            opcode == Opcode::DataV1 as u8 || opcode == Opcode::DataV2 as u8
        }
        None => false,
    }
}

/// A socket pointed at the server, with a read timeout short enough that the
/// drive loop keeps retransmitting.
fn connected_socket(port: u16) -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("a local socket");
    socket
        .connect(("127.0.0.1", port))
        .expect("point it at the server");
    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("so the loop can drive retransmission");
    socket
}

fn net_time() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is after 1970")
        .as_secs() as u32
}

/// A real `openvpn`, running as the TLS server end of a point-to-point link.
struct OpenVpnServer {
    child: Child,
    port: u16,
    dir: PathBuf,
    pki: Pki,
}

impl OpenVpnServer {
    fn start() -> Self {
        // Per instance, not per process: the tests in this file run in
        // parallel by default, and two servers sharing a directory means one
        // of them deletes the other's certificates on the way out.
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "openvpn-interop-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("a working directory");

        let pki = Pki::generate();
        write(&dir.join("ca.crt"), &pki.ca_pem);
        write(&dir.join("server.crt"), &pki.server_cert_pem);
        write(&dir.join("server.key"), &pki.server_key_pem);
        write(&dir.join("ta.key"), &static_key_file());

        // Held until the child has bound, because `free_port` lets go of the
        // port to hand it over: two servers starting at once could otherwise
        // be given the same one, and the loser fails to bind while the winner
        // talks to the wrong test.
        static SPAWNING: Mutex<()> = Mutex::new(());
        let spawning = SPAWNING
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let port = free_port();
        let log = dir.join("openvpn.log");
        let binary = std::env::var("OPENVPN_BIN").unwrap_or_else(|_| "openvpn".to_string());

        let child = Command::new(&binary)
            .args(["--tls-server", "--dev", "null", "--proto", "udp"])
            .args(["--lport", &port.to_string()])
            .args([
                "--ca",
                "ca.crt",
                "--cert",
                "server.crt",
                "--key",
                "server.key",
            ])
            .args(["--dh", "none"])
            .args(["--tls-auth", "ta.key", "0"])
            .args(["--auth", "SHA512", "--data-ciphers", "AES-256-CBC"])
            // A keepalive every second, so the server puts encrypted data
            // packets on the wire without a tunnel to carry traffic from.
            // Decrypting one of those is what proves the data channel.
            .args(["--ping", "1"])
            // Renegotiate quickly, so a test can watch one happen instead of
            // waiting out the hour `reneg-sec` defaults to.
            .args(["--reneg-sec", "10"])
            .args(["--log", "openvpn.log", "--verb", "4"])
            .current_dir(&dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|error| {
                panic!("could not run `{binary}`: {error}. Set OPENVPN_BIN if it is elsewhere.")
            });

        let server = Self {
            child,
            port,
            dir,
            pki,
        };
        server.wait_until_listening(&log);
        drop(spawning);
        server
    }

    /// Wait for the socket to be bound, so the first packet is not simply lost.
    ///
    /// A lost first packet would still be recovered by retransmission, which
    /// is the point of the layer under test — but it would turn a fast failure
    /// into a two-second one, and a flake into something that looks like a
    /// protocol bug.
    fn wait_until_listening(&self, log: &Path) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if std::fs::read_to_string(log)
                .unwrap_or_default()
                .contains("link local")
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!(
            "openvpn never bound its socket.\n--- its log ---\n{}",
            self.log()
        );
    }

    /// Stop the peer, so a test can watch what happens to a tunnel whose far
    /// end has gone.
    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join("openvpn.log")).unwrap_or_default()
    }
}

impl Drop for OpenVpnServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn write(path: &Path, contents: &str) {
    std::fs::write(path, contents).unwrap_or_else(|error| panic!("writing {path:?}: {error}"));
}

/// Ask the operating system for a port, then let go of it.
///
/// There is a race here in principle. In practice the window is microseconds
/// and the alternative — a hardcoded port — collides with whatever else is on
/// the machine, which is worse and harder to read when it happens.
fn free_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .expect("a port")
        .local_addr()
        .expect("its address")
        .port()
}

/// Render the test key in the format `openvpn --genkey` writes, which is also
/// the format a `.ovpn` inlines.
fn static_key_file() -> String {
    let body: Vec<String> = TA_KEY_HEX
        .as_bytes()
        .chunks(32)
        .map(|line| String::from_utf8(line.to_vec()).expect("hex is ascii"))
        .collect();

    format!(
        "#\n# 2048 bit OpenVPN static key\n#\n-----BEGIN OpenVPN Static key V1-----\n{}\n-----END OpenVPN Static key V1-----\n",
        body.join("\n")
    )
}

#[test]
#[ignore = "spawns a real openvpn process"]
fn a_tls_handshake_completes_over_the_control_channel() {
    // The whole stack at once: `tls-auth`, framing, retransmission, and now an
    // ordinary TLS session running inside OpenVPN's control messages. If the
    // fragmentation is wrong by one byte in either direction this does not
    // degrade, it fails to decrypt.
    let server = OpenVpnServer::start();

    let socket = connected_socket(server.port);

    let mut config = SessionConfig::new(
        server.pki.ca_pem.clone(),
        "localhost",
        StaticKey::from_hex(TA_KEY_HEX).expect("test vector"),
    );
    // A point-to-point OpenVPN always asks for a client certificate. e4e-nas
    // does not — it runs `verify-client-cert none` and takes an AD username
    // and password instead — so this is the test's shape, not the
    // deployment's.
    config.client_auth = Some(ClientAuth {
        cert_chain_pem: server.pki.client_cert_pem.clone(),
        private_key_pem: zeroize::Zeroizing::new(server.pki.client_key_pem.clone()),
    });

    let mut session = Session::new(config).expect("a client");

    let deadline = Instant::now() + Duration::from_secs(30);
    let mut buf = [0u8; 4096];

    while Instant::now() < deadline && session.is_handshaking() {
        let now = Instant::now();
        while let Some(datagram) = session.poll_transmit(now, net_time()) {
            // A refusal here means the peer is gone, and why it went is in its
            // log rather than in the errno.
            socket
                .send(&datagram)
                .unwrap_or_else(|error| panic!("{error}\n--- openvpn log ---\n{}", server.log()));
        }

        match socket.recv(&mut buf) {
            // A keepalive is not for the control channel.
            Ok(len) if is_data(&buf[..len]) => continue,
            Ok(len) => session
                .handle(&buf[..len], Instant::now())
                .unwrap_or_else(|error| panic!("{error}\n--- openvpn log ---\n{}", server.log())),
            Err(error) if error.kind() == ErrorKind::WouldBlock => {}
            Err(error) if error.kind() == ErrorKind::TimedOut => {}
            Err(error) => panic!("recv failed: {error}"),
        }
    }

    assert!(
        !session.is_handshaking(),
        "the handshake did not finish.\n--- openvpn log ---\n{}",
        server.log()
    );
    assert!(
        session.remote_session().is_some(),
        "and it finished with the peer we opened against"
    );
}

#[test]
#[ignore = "spawns a real openvpn process"]
fn the_key_exchange_completes_against_a_real_openvpn() {
    // The end of the handshake: TLS comes up, both ends send their key
    // material inside it, and the data-channel keys fall out of the PRF.
    //
    // This is the test that says the message layout is right. A field a byte
    // out of place, a string length that counts its NUL wrongly, a random in
    // the wrong order — openvpn reads all of those as a malformed key method
    // and stops, and no amount of testing our encoder against our decoder
    // would notice.
    let server = OpenVpnServer::start();
    let socket = connected_socket(server.port);

    let mut config = SessionConfig::new(
        server.pki.ca_pem.clone(),
        "localhost",
        StaticKey::from_hex(TA_KEY_HEX).expect("test vector"),
    );
    config.client_auth = Some(ClientAuth {
        cert_chain_pem: server.pki.client_cert_pem.clone(),
        private_key_pem: zeroize::Zeroizing::new(server.pki.client_key_pem.clone()),
    });

    let mut session = Session::new(config).expect("a client");
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut buf = [0u8; 4096];

    while Instant::now() < deadline && !session.is_established() {
        let now = Instant::now();
        while let Some(datagram) = session.poll_transmit(now, net_time()) {
            socket
                .send(&datagram)
                .unwrap_or_else(|error| panic!("{error}\n--- openvpn log ---\n{}", server.log()));
        }

        match socket.recv(&mut buf) {
            // A keepalive is not for the control channel.
            Ok(len) if is_data(&buf[..len]) => continue,
            Ok(len) => session
                .handle(&buf[..len], Instant::now())
                .unwrap_or_else(|error| panic!("{error}\n--- openvpn log ---\n{}", server.log())),
            Err(error) if error.kind() == ErrorKind::WouldBlock => {}
            Err(error) if error.kind() == ErrorKind::TimedOut => {}
            Err(error) => panic!("recv failed: {error}"),
        }
    }

    assert!(
        session.is_established(),
        "the key exchange did not finish.\n--- openvpn log ---\n{}",
        server.log()
    );

    let keys = session.keys().expect("established means keys");
    assert_eq!(
        keys.len(),
        256,
        "two directions, a cipher and an HMAC key each"
    );
    assert!(
        keys.iter().any(|&byte| byte != 0),
        "and they are derived rather than left empty"
    );
}

#[test]
#[ignore = "spawns a real openvpn process"]
fn a_ping_from_a_real_openvpn_decrypts() {
    // The end of the road for the handshake: keys that are actually right.
    // Everything before this produces 256 bytes that look like key material
    // whether or not they are, and the only way to tell is to take a packet
    // encrypted by someone else and get their plaintext back out.
    //
    // The server is run with `--ping 1`, so it emits keepalives on the data
    // channel with no tunnel traffic to carry. Those sixteen bytes are a
    // constant, so recognising them proves the key derivation, the direction
    // of the two slots, the framing and the CBC construction all at once.
    let server = OpenVpnServer::start();
    let socket = connected_socket(server.port);

    let mut config = SessionConfig::new(
        server.pki.ca_pem.clone(),
        "localhost",
        StaticKey::from_hex(TA_KEY_HEX).expect("test vector"),
    );
    config.client_auth = Some(ClientAuth {
        cert_chain_pem: server.pki.client_cert_pem.clone(),
        private_key_pem: zeroize::Zeroizing::new(server.pki.client_key_pem.clone()),
    });

    let mut session = Session::new(config).expect("a client");
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut buf = [0u8; 4096];
    let mut data: Option<DataChannel> = None;
    let mut ping = None;

    while Instant::now() < deadline && ping.is_none() {
        let now = Instant::now();
        while let Some(datagram) = session.poll_transmit(now, net_time()) {
            socket
                .send(&datagram)
                .unwrap_or_else(|error| panic!("{error}\n--- openvpn log ---\n{}", server.log()));
        }

        let len = match socket.recv(&mut buf) {
            Ok(len) => len,
            Err(error)
                if error.kind() == ErrorKind::WouldBlock || error.kind() == ErrorKind::TimedOut =>
            {
                continue
            }
            Err(error) => panic!("recv failed: {error}"),
        };

        // Data packets are the ones the control channel does not want. A
        // point-to-point peer assigns no peer id, so these arrive as
        // `P_DATA_V1`.
        if is_data(&buf[..len]) {
            let channel = data.get_or_insert_with(|| {
                DataChannel::new(
                    DataKeys::for_client(session.keys().expect("keys by now")).expect("256 bytes"),
                    None,
                    KeyId::FIRST,
                )
            });
            let payload = channel.decrypt(&buf[..len]).unwrap_or_else(|error| {
                panic!(
                    "a data packet from openvpn did not decrypt: {error}\n--- openvpn log ---\n{}",
                    server.log()
                )
            });
            ping = Some(payload);
            continue;
        }

        session
            .handle(&buf[..len], Instant::now())
            .unwrap_or_else(|error| panic!("{error}\n--- openvpn log ---\n{}", server.log()));
    }

    let ping = ping.unwrap_or_else(|| {
        panic!(
            "no data packet arrived.\n--- openvpn log ---\n{}",
            server.log()
        )
    });

    assert_eq!(
        ping, PING,
        "openvpn's keepalive, decrypted with keys we derived from a PRF it never told us the answer to"
    );
}

#[test]
#[ignore = "spawns a real openvpn process"]
fn a_renegotiation_completes_against_a_real_openvpn() {
    // This test used to assert that a renegotiation was *refused*, and said
    // it would fail the day one could be completed. This is that day.
    //
    // The server runs `--reneg-sec 10`, so ten seconds in it begins a new key
    // generation: a soft reset under a new key id, then a second TLS
    // handshake and key exchange on the same control channel. The keys that
    // come out are different ones, and the session is still up.
    //
    // An hour is the default, and a multi-gigabyte copy passes it by
    // definition, so this is the difference between a tunnel that survives a
    // long transfer and one that does not.
    let server = OpenVpnServer::start();
    let socket = connected_socket(server.port);

    let mut config = SessionConfig::new(
        server.pki.ca_pem.clone(),
        "localhost",
        StaticKey::from_hex(TA_KEY_HEX).expect("test vector"),
    );
    config.client_auth = Some(ClientAuth {
        cert_chain_pem: server.pki.client_cert_pem.clone(),
        private_key_pem: zeroize::Zeroizing::new(server.pki.client_key_pem.clone()),
    });

    let mut session = Session::new(config).expect("a client");
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut buf = [0u8; 4096];
    let mut first_keys: Option<Vec<u8>> = None;

    while Instant::now() < deadline {
        let now = Instant::now();
        while let Some(datagram) = session.poll_transmit(now, net_time()) {
            let _ = socket.send(&datagram);
        }

        let len = match socket.recv(&mut buf) {
            Ok(len) => len,
            Err(_) => continue,
        };
        if is_data(&buf[..len]) {
            continue;
        }

        // A refused datagram is not a refused session; only a fatal one ends
        // it. Reordering and retransmission both produce the other sort.
        if let Err(error) = session.handle(&buf[..len], Instant::now()) {
            assert!(
                !error.is_fatal(),
                "{error}\n--- openvpn log ---\n{}",
                server.log()
            );
            continue;
        }

        match (&first_keys, session.keys()) {
            (None, Some(keys)) => first_keys = Some(keys.to_vec()),
            (Some(first), Some(now_keys)) if first != now_keys => {
                // The keys changed under us, which only a completed
                // renegotiation does.
                return;
            }
            _ => {}
        }
    }

    panic!(
        "no renegotiation completed in 30s.\n--- openvpn log ---\n{}",
        server.log()
    );
}

#[test]
#[ignore = "spawns a real openvpn process"]
fn a_packet_sent_immediately_after_a_rotation_is_accepted() {
    // `promote` documents a window it cannot close: our packets under the new
    // key can arrive before the peer has activated its own new state, and it
    // drops what it cannot yet decrypt. Whether that window is real, and how
    // wide, is a question about openvpn rather than about this code — so it
    // is measured rather than reasoned about.
    //
    // If this ever fails, the answer is to keep sending under the old key
    // until something arrives under the new one. Today it passes, which says
    // the peer has both halves by the time it sends us its own key material.
    let server = OpenVpnServer::start();
    let socket = connected_socket(server.port);

    let mut config = SessionConfig::new(
        server.pki.ca_pem.clone(),
        "localhost",
        StaticKey::from_hex(TA_KEY_HEX).expect("test vector"),
    );
    config.client_auth = Some(ClientAuth {
        cert_chain_pem: server.pki.client_cert_pem.clone(),
        private_key_pem: zeroize::Zeroizing::new(server.pki.client_key_pem.clone()),
    });

    let mut session = Session::new(config).expect("a client");
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut buf = [0u8; 4096];
    let mut first_keys: Option<Vec<u8>> = None;
    let mut rotated = false;

    while Instant::now() < deadline && !rotated {
        let now = Instant::now();
        while let Some(datagram) = session.poll_transmit(now, net_time()) {
            let _ = socket.send(&datagram);
        }

        let len = match socket.recv(&mut buf) {
            Ok(len) => len,
            Err(_) => continue,
        };
        if is_data(&buf[..len]) {
            continue;
        }
        if let Err(error) = session.handle(&buf[..len], Instant::now()) {
            assert!(!error.is_fatal(), "{error}");
            continue;
        }

        match (&first_keys, session.keys()) {
            (None, Some(keys)) => first_keys = Some(keys.to_vec()),
            (Some(first), Some(current)) if first != current => rotated = true,
            _ => {}
        }
    }
    assert!(
        rotated,
        "no rotation.\n--- openvpn log ---\n{}",
        server.log()
    );

    // Immediately: no waiting, no settling.
    let complaints_before = server
        .log()
        .matches("Authenticate/Decrypt packet error")
        .count();
    let datagram = session
        .send_payload(Instant::now(), &PING)
        .expect("the tunnel is up");
    socket.send(&datagram).expect("send");
    std::thread::sleep(Duration::from_millis(500));

    assert_eq!(
        server
            .log()
            .matches("Authenticate/Decrypt packet error")
            .count(),
        complaints_before,
        "openvpn refused a packet sent under the keys it had just given us.\n--- its log ---\n{}",
        server.log()
    );
}

#[test]
#[ignore = "spawns a real openvpn process"]
fn a_real_openvpn_accepts_a_packet_we_encrypted() {
    // Everything else here proves we can *read* what openvpn sends. Nothing
    // proved it can read what we send — our encryption was checked only by our
    // own decryption, which agrees with itself by construction. That is the
    // half that matters for the keepalive: a packet openvpn cannot
    // authenticate is dropped in silence, and the tunnel is then torn down at
    // `ping-restart` for a reason indistinguishable from the network.
    //
    // openvpn says nothing when a packet is fine, so the test needs a control:
    // a deliberately corrupted packet must produce the complaint, and a good
    // one must not. Without the control, "no error in the log" would also be
    // what a test that sent nothing at all looks like.
    let server = OpenVpnServer::start();
    let socket = connected_socket(server.port);

    let mut config = SessionConfig::new(
        server.pki.ca_pem.clone(),
        "localhost",
        StaticKey::from_hex(TA_KEY_HEX).expect("test vector"),
    );
    config.client_auth = Some(ClientAuth {
        cert_chain_pem: server.pki.client_cert_pem.clone(),
        private_key_pem: zeroize::Zeroizing::new(server.pki.client_key_pem.clone()),
    });

    let mut session = Session::new(config).expect("a client");
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut buf = [0u8; 4096];
    let mut tunnel: Option<DataChannel> = None;
    let mut heard_from_it = false;

    // Waiting for one of its keepalives, not merely for our own keys. The
    // server generates its data-channel key a moment after we generate ours,
    // and a packet sent into that gap is dropped as "Key not initialized
    // (yet)" — which is neither an acceptance nor a refusal, and would make
    // both halves of this test meaningless.
    while Instant::now() < deadline && !heard_from_it {
        let now = Instant::now();
        while let Some(datagram) = session.poll_transmit(now, net_time()) {
            let _ = socket.send(&datagram);
        }

        let len = match socket.recv(&mut buf) {
            Ok(len) => len,
            Err(_) => continue,
        };

        if is_data(&buf[..len]) {
            let channel = tunnel.get_or_insert_with(|| {
                // A point-to-point peer assigns no peer id, so `P_DATA_V1`.
                DataChannel::new(
                    DataKeys::for_client(session.keys().expect("keys by now")).expect("256 bytes"),
                    None,
                    KeyId::FIRST,
                )
            });
            if channel.decrypt(&buf[..len]).is_ok() {
                heard_from_it = true;
            }
            continue;
        }

        let _ = session.handle(&buf[..len], Instant::now());
    }

    let mut tunnel = tunnel.unwrap_or_else(|| {
        panic!(
            "the server never spoke on the data channel.\n--- its log ---\n{}",
            server.log()
        )
    });
    assert!(heard_from_it, "its key is ready, so ours can be judged");

    let good = tunnel.encrypt(&PING).expect("encrypt");
    socket.send(&good).expect("send");
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        !server.log().contains("Authenticate/Decrypt packet error"),
        "openvpn refused a packet we encrypted.\n--- its log ---\n{}",
        server.log()
    );

    // The control. One flipped bit in the ciphertext, and the complaint we
    // just asserted the absence of must appear — otherwise its absence above
    // meant nothing.
    let mut bad = tunnel.encrypt(&PING).expect("encrypt");
    let last = bad.len() - 1;
    bad[last] ^= 0x01;
    socket.send(&bad).expect("send");
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        server.log().contains("Authenticate/Decrypt packet error"),
        "openvpn accepted a corrupted packet, so its silence proves nothing.\n--- its log ---\n{}",
        server.log()
    );
}

/// A throwaway certificate authority and the two certificates it issues.
///
/// A real hierarchy rather than one self-signed certificate used everywhere,
/// because both ends check more than the signature: OpenVPN rejects a client
/// certificate without the client-authentication purpose, and the extended key
/// usage is the sort of thing a shortcut here would quietly skip and the NAS
/// would not.
struct Pki {
    ca_pem: String,
    server_cert_pem: String,
    server_key_pem: String,
    client_cert_pem: String,
    client_key_pem: String,
}

impl Pki {
    fn generate() -> Self {
        use rcgen::{
            BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
            KeyPair,
        };

        let ca_key = KeyPair::generate().expect("a key");
        let mut ca_params = CertificateParams::new(Vec::new()).expect("ca params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "openvpn-interop-ca");
        let ca = ca_params.self_signed(&ca_key).expect("a self-signed ca");
        let issuer = Issuer::from_params(&ca_params, &ca_key);

        let server_key = KeyPair::generate().expect("a key");
        let mut server_params =
            CertificateParams::new(vec!["localhost".to_string()]).expect("server params");
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server = server_params
            .signed_by(&server_key, &issuer)
            .expect("a server certificate");

        let client_key = KeyPair::generate().expect("a key");
        let mut client_params =
            CertificateParams::new(vec!["client".to_string()]).expect("client params");
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client = client_params
            .signed_by(&client_key, &issuer)
            .expect("a client certificate");

        Self {
            ca_pem: ca.pem(),
            server_cert_pem: server.pem(),
            server_key_pem: server_key.serialize_pem(),
            client_cert_pem: client.pem(),
            client_key_pem: client_key.serialize_pem(),
        }
    }
}

#[tokio::test]
#[ignore = "spawns a real openvpn process"]
async fn the_driver_brings_a_tunnel_up_against_a_real_openvpn() {
    // The first test in this crate with a socket in it, and the last thing
    // that had never been exercised: everything else drives the state machine
    // by hand — which is what made it testable at all — so nothing had run the
    // whole thing end to end. Bind, hand it what arrives, send what it asks
    // for, sleep as long as it says, and come back with a tunnel.
    let server = OpenVpnServer::start();

    let mut config = SessionConfig::new(
        server.pki.ca_pem.clone(),
        "localhost",
        StaticKey::from_hex(TA_KEY_HEX).expect("test vector"),
    );
    config.client_auth = Some(ClientAuth {
        cert_chain_pem: server.pki.client_cert_pem.clone(),
        private_key_pem: zeroize::Zeroizing::new(server.pki.client_key_pem.clone()),
    });

    let remote: std::net::SocketAddr = format!("127.0.0.1:{}", server.port)
        .parse()
        .expect("a local address");

    let tunnel = synology_filestation_openvpn::Tunnel::connect(config, remote)
        .await
        .unwrap_or_else(|error| {
            panic!(
                "the tunnel did not come up: {error}\n--- openvpn log ---\n{}",
                server.log()
            )
        });

    // And it carries. The keepalive is the one payload whose acceptance
    // openvpn will comment on if it is wrong.
    let complaints_before = server
        .log()
        .matches("Authenticate/Decrypt packet error")
        .count();
    tunnel
        .send(PING.to_vec())
        .await
        .expect("the tunnel carries");
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert_eq!(
        server
            .log()
            .matches("Authenticate/Decrypt packet error")
            .count(),
        complaints_before,
        "openvpn refused what the driver sent.\n--- its log ---\n{}",
        server.log()
    );
    assert!(
        tunnel.failure().is_none(),
        "the tunnel stopped: {:?}",
        tunnel.failure()
    );
}

#[tokio::test]
#[ignore = "spawns a real openvpn process"]
async fn a_peer_that_vanishes_is_noticed() {
    // Without this the tunnel is worse than broken, it is silent: `failure()`
    // stays `None`, `recv()` waits forever, and `send()` returns `Ok` while
    // every payload goes nowhere. A caller has no way to tell that from a
    // quiet link.
    //
    // `ping-restart` is the peer's own answer to how long silence may last,
    // so it is the number used here rather than one of ours.
    let mut server = OpenVpnServer::start();

    let mut config = SessionConfig::new(
        server.pki.ca_pem.clone(),
        "localhost",
        StaticKey::from_hex(TA_KEY_HEX).expect("test vector"),
    );
    config.client_auth = Some(ClientAuth {
        cert_chain_pem: server.pki.client_cert_pem.clone(),
        private_key_pem: zeroize::Zeroizing::new(server.pki.client_key_pem.clone()),
    });
    // This peer pushes no `ping-restart`, so the fallback is what applies —
    // shortened here because the test is about noticing, not about waiting.
    config.peer_timeout = Duration::from_secs(3);

    let remote: std::net::SocketAddr = format!("127.0.0.1:{}", server.port)
        .parse()
        .expect("a local address");

    let mut tunnel = synology_filestation_openvpn::Tunnel::connect(config, remote)
        .await
        .unwrap_or_else(|error| panic!("the tunnel did not come up: {error}"));

    // And now the far end simply stops.
    server.kill();

    // `recv` ends when the loop does, which is the signal a caller actually
    // waits on.
    let ended = tokio::time::timeout(Duration::from_secs(20), tunnel.recv()).await;

    assert!(
        matches!(ended, Ok(None)),
        "the tunnel neither delivered nor ended after the peer vanished"
    );
    assert!(
        matches!(
            tunnel.failure(),
            Some(synology_filestation_openvpn::Error::PeerGone(_))
        ),
        "and it should say why: {:?}",
        tunnel.failure()
    );
}
