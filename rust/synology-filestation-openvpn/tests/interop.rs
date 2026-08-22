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
        let opcode = buf[0] >> 3;
        if opcode == Opcode::DataV1 as u8 || opcode == Opcode::DataV2 as u8 {
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
