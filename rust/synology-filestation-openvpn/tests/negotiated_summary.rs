//! What the tunnel says about itself once it is up.
//!
//! Its own test binary, deliberately. A scoped `tracing` subscriber is
//! thread-local, and the global callsite-interest cache it depends on is
//! shared with every other test in the same binary — so an assertion on log
//! output passes alone and fails beside thirty tests that install no
//! subscriber. One test per process removes the race rather than papering
//! over it with a retry.

mod common;

use std::time::Instant;

use common::{exchange, Answer, FakeServer, TA_KEY_HEX};
use synology_filestation_openvpn::{Session, SessionConfig, StaticKey};

fn session_against(server: &FakeServer) -> Session {
    let config = SessionConfig::new(
        server.ca_pem.clone(),
        "localhost",
        StaticKey::from_hex(TA_KEY_HEX).expect("test vector"),
    );
    Session::new(config).expect("a client")
}
// ── What the tunnel says about itself ────────────────────────────────────────

/// Somewhere to put log events so a test can read them back.
#[derive(Clone, Default)]
struct Sink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Sink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Sink {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Captures what this thread logs, at the level somebody actually runs at.
struct LogCapture {
    sink: Sink,
    _guard: tracing::subscriber::DefaultGuard,
}

impl LogCapture {
    fn at_the_default_level() -> Self {
        let sink = Sink::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(sink.clone())
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .finish();
        Self {
            _guard: tracing::subscriber::set_default(subscriber),
            sink,
        }
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.sink.0.lock().unwrap()).into_owned()
    }
}

/// Regression: this crate logged nothing at all — it did not even depend on
/// `tracing`. So when a tunnel came up and TCP to the NAS inside it then
/// failed, there was no way to see what the server had actually assigned us,
/// and "the tunnel is up but nothing answered at 10.90.24.1:445" could not be
/// told apart from "we are on a different subnet from the address we dialled".
/// The one fact that separates those is the address in the push reply, and it
/// was parsed, stored, and never mentioned.
#[test]
fn the_negotiated_tunnel_is_described_once_it_is_ready() {
    let logs = LogCapture::at_the_default_level();
    let mut server = FakeServer::new(Answer::KeyMaterialThen(
        "PUSH_REPLY,ifconfig 10.90.24.6 255.255.255.0,peer-id 4,cipher AES-256-CBC,ping 10"
            .to_string(),
    ));
    let mut session = session_against(&server);

    exchange(&mut session, &mut server, Instant::now()).expect("nothing to refuse");

    let said = logs.text();
    assert!(
        said.contains("10.90.24.6"),
        "the address the server gave us is the fact that says whether the NAS \
         is even on our subnet. Got:\n{said}"
    );
    assert!(
        said.contains("AES-256-CBC"),
        "and the cipher it settled on, since a mismatch there carries corrupt \
         bytes rather than failing. Got:\n{said}"
    );
}
