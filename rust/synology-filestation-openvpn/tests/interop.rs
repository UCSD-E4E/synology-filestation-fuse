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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use synology_filestation_openvpn::{
    ControlChannel, KeyDirection, Opcode, SessionId, StaticKey, TlsAuth,
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

    let socket = UdpSocket::bind("127.0.0.1:0").expect("a local socket");
    socket
        .connect(("127.0.0.1", server.port))
        .expect("point it at the server");
    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("so the loop can drive retransmission");

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
}

impl OpenVpnServer {
    fn start() -> Self {
        let dir = std::env::temp_dir().join(format!("openvpn-interop-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a working directory");

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("a certificate");
        // One self-signed certificate serving as its own CA. The client half of
        // that trust decision is ours to make and we are not making it here:
        // this test is about the control channel, not about who the peer is.
        write(&dir.join("ca.crt"), &cert.cert.pem());
        write(&dir.join("server.key"), &cert.signing_key.serialize_pem());
        write(&dir.join("ta.key"), &static_key_file());

        let port = free_port();
        let log = dir.join("openvpn.log");
        let binary = std::env::var("OPENVPN_BIN").unwrap_or_else(|_| "openvpn".to_string());

        let child = Command::new(&binary)
            .args(["--tls-server", "--dev", "null", "--proto", "udp"])
            .args(["--lport", &port.to_string()])
            .args(["--ca", "ca.crt", "--cert", "ca.crt", "--key", "server.key"])
            .args(["--dh", "none"])
            .args(["--tls-auth", "ta.key", "0"])
            .args(["--auth", "SHA512", "--data-ciphers", "AES-256-CBC"])
            .args(["--log", "openvpn.log", "--verb", "4"])
            .current_dir(&dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|error| {
                panic!("could not run `{binary}`: {error}. Set OPENVPN_BIN if it is elsewhere.")
            });

        let server = Self { child, port, dir };
        server.wait_until_listening(&log);
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
