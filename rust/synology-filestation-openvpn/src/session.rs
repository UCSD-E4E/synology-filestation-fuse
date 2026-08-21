//! A TLS session carried on the control channel.
//!
//! OpenVPN runs an ordinary TLS handshake inside its own control messages, and
//! then uses the session that comes out to exchange the material for the data
//! channel. Nothing about the TLS is unusual — which is the point, and the
//! reason `rustls` can be dropped in here without teaching it anything about
//! OpenVPN.
//!
//! What the control channel needs from us in return is fragmentation. TLS
//! produces a byte stream; the channel carries messages that have to fit in a
//! datagram, and its window holds only six at a time. Bytes that do not fit
//! have to *wait*, not disappear: a TLS stream with a hole in it does not
//! resynchronise, it fails to decrypt and takes the session with it.

use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use zeroize::Zeroizing;

use std::io::{Read, Write};

use crate::channel::ControlChannel;
use crate::key_method::{ClientKeyMethod2, ServerKeyMethod2};
use crate::packet::SessionId;
use crate::prf::{key_expansion, KeySource2};
use crate::static_key::{KeyDirection, StaticKey};
use crate::tls_auth::TlsAuth;
use crate::Error;

/// OpenVPN's control channel MTU, which is what `--max-packet-size` sets and
/// what `min_int(TLS_CHANNEL_BUF_SIZE, frame.tun_mtu)` bounds. 1250 is the
/// default and what the server we are talking to reports.
const CONTROL_MTU: usize = 1250;

/// What a control packet spends before any payload: the opcode and session id
/// (9), the `tls-auth` HMAC (64) and replay header (8), a worst-case ack block
/// (41) and the message id (4).
///
/// This is `calc_control_channel_frame_overhead`, and it comes to the same 126
/// that OpenVPN prints as `headroom` in its own MTU line — which is how it was
/// checked.
const CONTROL_OVERHEAD: usize = 9 + 64 + 8 + 41 + 4;

/// The most TLS we can put in one control message.
pub const MAX_TLS_FRAGMENT: usize = CONTROL_MTU - CONTROL_OVERHEAD;

/// The options string both ends compare. A mismatch is a warning in the
/// peer's log rather than a refusal, which is why this can be a constant: it
/// describes the tunnel we are asking for, and the server tells us if it
/// disagrees.
const OPTIONS: &str = "V4,dev-type tun,link-mtu 1602,tun-mtu 1500,proto UDPv4,\
cipher AES-256-CBC,auth SHA512,keysize 256,key-method 2,tls-client";

/// What we tell the server about ourselves. `IV_PROTO=2` is the bit that says
/// we understand `P_DATA_V2` and its peer id, which is what a modern server
/// assigns; `IV_CIPHERS` is what it negotiates the data cipher from.
const PEER_INFO: &str = "IV_VER=2.5.11\nIV_PLAT=rust\nIV_PROTO=2\nIV_CIPHERS=AES-256-CBC\n";

/// How to reach the peer, and how to be sure it is the peer.
pub struct SessionConfig {
    /// The `<ca>` block from the `.ovpn`, in PEM. It *replaces* the system
    /// trust store rather than adding to it: the server presents a publicly
    /// issued certificate, so trusting every public CA would mean trusting
    /// anyone who can obtain one for this name.
    pub ca_pem: String,
    /// The name the certificate must be for — `verify-x509-name` in the
    /// profile.
    pub server_name: String,
    /// The `tls-auth` key from the same profile.
    pub static_key: StaticKey,
    /// `key-direction`; the published profile says 1, which is
    /// [`KeyDirection::Inverse`].
    pub key_direction: KeyDirection,
    /// Our session id. Defaults to a random one, which is what it should be.
    pub session_id: SessionId,
    /// `--tls-timeout`, the first retransmission interval.
    pub tls_timeout: Duration,
    /// The credentials the server authenticates. e4e-nas takes an AD username
    /// and password; a peer that asks for neither is sent empty fields.
    pub credentials: Option<Credentials>,
    /// A client certificate, if the server asks for one.
    ///
    /// e4e-nas does not: it runs `verify-client-cert none` and authenticates
    /// with an AD username and password instead. This exists because a
    /// point-to-point OpenVPN — which is what the interop test can run without
    /// privileges — always asks.
    pub client_auth: Option<ClientAuth>,
}

/// What the server checks against the directory.
pub struct Credentials {
    pub username: String,
    pub password: Zeroizing<String>,
}

/// A certificate chain and its key, for a server that asks.
pub struct ClientAuth {
    pub cert_chain_pem: String,
    /// Zeroized on drop, like every other key in this crate. rustls keeps its
    /// own copy of the parsed key and that one is out of our hands, so this
    /// removes one copy rather than all of them.
    pub private_key_pem: Zeroizing<String>,
}

impl SessionConfig {
    /// Everything but the identity of the far end, which has no sensible
    /// default.
    pub fn new(
        ca_pem: impl Into<String>,
        server_name: impl Into<String>,
        static_key: StaticKey,
    ) -> Self {
        Self {
            ca_pem: ca_pem.into(),
            server_name: server_name.into(),
            static_key,
            key_direction: KeyDirection::Inverse,
            session_id: SessionId::random(),
            tls_timeout: Duration::from_secs(2),
            credentials: None,
            client_auth: None,
        }
    }
}

/// How far along a session is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// TLS is still negotiating.
    Tls,
    /// Our key material has gone out; the peer's has not come back.
    AwaitingKeys,
    /// Both ends have contributed, and the data-channel keys exist.
    Established,
}

/// A TLS session and the control channel underneath it.
pub struct Session {
    channel: ControlChannel,
    tls: ClientConnection,
    outbox: Outbox,
    phase: Phase,
    source: KeySource2,
    credentials: Option<Credentials>,
    /// Plaintext read out of TLS, which arrives in pieces.
    inbound: Vec<u8>,
    keys: Option<Zeroizing<Vec<u8>>>,
}

impl Session {
    pub fn new(config: SessionConfig) -> Result<Self, Error> {
        let channel = ControlChannel::new(
            TlsAuth::new(&config.static_key, config.key_direction),
            config.session_id,
            config.tls_timeout,
        );

        let tls = ClientConnection::new(
            Arc::new(client_config(&config)?),
            ServerName::try_from(config.server_name.clone())
                .map_err(|_| {
                    Error::Tls(format!("{} is not a valid server name", config.server_name))
                })?
                .to_owned(),
        )
        .map_err(|error| Error::Tls(error.to_string()))?;

        let mut session = Self {
            channel,
            tls,
            outbox: Outbox::default(),
            phase: Phase::Tls,
            source: KeySource2::new_client(),
            credentials: config.credentials,
            inbound: Vec::new(),
            keys: None,
        };
        // Opened here rather than by a separate call. rustls has a
        // `ClientHello` ready the moment it is built, so a session that could
        // be polled before it was opened would put that hello on the wire as
        // an ordinary control message with no reset in front of it — a start
        // no server accepts. Removing the window is better than documenting
        // it.
        session.channel.open();
        Ok(session)
    }

    /// Whether the TLS handshake is still in progress.
    pub fn is_handshaking(&self) -> bool {
        self.tls.is_handshaking()
    }

    /// Whether both ends have contributed key material and the data-channel
    /// keys exist.
    pub fn is_established(&self) -> bool {
        self.phase == Phase::Established
    }

    /// The derived key material: two directions, each a cipher key then an
    /// HMAC key, 64 bytes apiece.
    pub fn keys(&self) -> Option<&[u8]> {
        self.keys.as_ref().map(|keys| keys.as_slice())
    }

    /// The next datagram to send.
    pub fn poll_transmit(&mut self, now: Instant, net_time: u32) -> Option<Vec<u8>> {
        self.send_our_key_material();

        // Take whatever TLS has produced, then hand the channel as much of it
        // as its window will hold.
        while self.tls.wants_write() {
            let mut bytes = Vec::new();
            match self.tls.write_tls(&mut bytes) {
                Ok(0) | Err(_) => break,
                Ok(_) => self.outbox.push(&bytes),
            }
        }
        self.outbox.drain_into(&mut self.channel);

        self.channel.poll_transmit(now, net_time)
    }

    /// When [`Session::poll_transmit`] will next have something.
    ///
    /// `None` means idle. TLS counts here as well as the channel: a handshake
    /// step leaves rustls with bytes to send and the send window empty, and a
    /// caller sleeping on the window alone would stall the handshake it is
    /// trying to drive.
    pub fn next_wakeup(&self, now: Instant) -> Option<Instant> {
        // Only when the channel could actually take the bytes. Bytes held back
        // by a full window are a reason to wait for an acknowledgement, not a
        // reason to be woken immediately — a caller told otherwise would call
        // `poll_transmit`, get nothing, and come straight back.
        if self.channel.can_send() && (self.tls.wants_write() || !self.outbox.is_empty()) {
            return Some(now);
        }
        self.channel.next_wakeup(now)
    }

    /// Take a datagram from the network and feed whatever it carried to TLS.
    pub fn handle(&mut self, datagram: &[u8], now: Instant) -> Result<(), Error> {
        self.channel.handle(datagram, now)?;

        while let Some(record) = self.channel.poll_control() {
            let mut remaining = record.as_slice();
            while !remaining.is_empty() {
                self.tls
                    .read_tls(&mut remaining)
                    .map_err(|error| Error::Tls(error.to_string()))?;
                self.tls
                    .process_new_packets()
                    .map_err(|error| Error::Tls(error.to_string()))?;
            }
        }

        self.receive_their_key_material()
    }

    /// The peer's session id, once it has told us.
    pub fn remote_session(&self) -> Option<SessionId> {
        self.channel.remote_session()
    }

    /// Send our half of the key material, once TLS will carry it.
    ///
    /// Exactly once: the phase moves whether or not the write succeeds,
    /// because rustls buffers it and a second copy would be read as a second
    /// message.
    fn send_our_key_material(&mut self) {
        if self.phase != Phase::Tls || self.tls.is_handshaking() {
            return;
        }

        let empty = Zeroizing::new(String::new());
        let (username, password) = match &self.credentials {
            Some(credentials) => (credentials.username.as_str(), &credentials.password),
            None => ("", &empty),
        };

        let message = ClientKeyMethod2 {
            source: &self.source,
            options: OPTIONS,
            username,
            password,
            peer_info: PEER_INFO,
        }
        .encode();

        // A failure here is a closed session, which the next poll reports
        // through the ordinary path rather than by panicking in a setter.
        let _ = self.tls.writer().write_all(&message);
        self.phase = Phase::AwaitingKeys;
    }

    /// Take the peer's key material if all of it has arrived.
    fn receive_their_key_material(&mut self) -> Result<(), Error> {
        if self.phase != Phase::AwaitingKeys {
            return Ok(());
        }

        let mut buffer = [0u8; 2048];
        while let Ok(read) = self.tls.reader().read(&mut buffer) {
            if read == 0 {
                break;
            }
            self.inbound.extend_from_slice(&buffer[..read]);
        }

        match ServerKeyMethod2::decode(&self.inbound) {
            // Not all of it is here yet. TLS is a stream, so this is ordinary.
            Err(Error::Truncated { .. }) => Ok(()),
            Err(error) => Err(error),
            Ok(reply) => {
                self.source.server_random1 = reply.random1;
                self.source.server_random2 = reply.random2;

                let server_session = self
                    .channel
                    .remote_session()
                    .ok_or_else(|| Error::Tls("key material before a session id".into()))?;
                self.keys = Some(Zeroizing::new(key_expansion(
                    &self.source,
                    self.channel.local_session(),
                    server_session,
                )));
                self.inbound.clear();
                self.phase = Phase::Established;
                Ok(())
            }
        }
    }
}

fn client_config(config: &SessionConfig) -> Result<ClientConfig, Error> {
    let mut roots = RootCertStore::empty();
    let mut pem = config.ca_pem.as_bytes();
    for certificate in rustls_pemfile::certs(&mut pem) {
        let certificate = certificate.map_err(|error| Error::Tls(error.to_string()))?;
        roots
            .add(certificate)
            .map_err(|error| Error::Tls(error.to_string()))?;
    }
    if roots.is_empty() {
        return Err(Error::Tls("the ca block contains no certificates".into()));
    }

    // `ring` rather than the default provider, matching the rest of the
    // workspace: aws-lc-rs needs a C toolchain the Windows and manylinux
    // builds do not have.
    let builder =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|error| Error::Tls(error.to_string()))?
            .with_root_certificates(roots);

    match &config.client_auth {
        None => Ok(builder.with_no_client_auth()),
        Some(auth) => {
            let mut chain_pem = auth.cert_chain_pem.as_bytes();
            let chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut chain_pem)
                .collect::<Result<_, _>>()
                .map_err(|error| Error::Tls(error.to_string()))?;

            let mut key_pem = auth.private_key_pem.as_bytes();
            let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_pem)
                .map_err(|error| Error::Tls(error.to_string()))?
                .ok_or_else(|| Error::Tls("no private key in the client auth block".into()))?;

            builder
                .with_client_auth_cert(chain, key)
                .map_err(|error| Error::Tls(error.to_string()))
        }
    }
}

/// TLS bytes waiting for room on the control channel.
///
/// The whole job is not losing any. `send_control` refuses when the window is
/// full, and a caller that treats that as "sent" puts a hole in a TLS stream —
/// which does not resynchronise. It fails to decrypt, and takes the session
/// with it.
#[derive(Default)]
struct Outbox {
    pending: Vec<u8>,
}

impl Outbox {
    fn push(&mut self, bytes: &[u8]) {
        self.pending.extend_from_slice(bytes);
    }

    fn drain_into(&mut self, channel: &mut ControlChannel) {
        while !self.pending.is_empty() {
            let take = self.pending.len().min(MAX_TLS_FRAGMENT);
            if !channel.send_control(self.pending[..take].to_vec()) {
                // The window is full. Everything still here goes out once the
                // peer acknowledges enough for it to move.
                return;
            }
            self.pending.drain(..take);
        }
    }

    fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    #[cfg(test)]
    fn pending(&self) -> usize {
        self.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reliable::SendWindow;

    fn new_channel() -> ControlChannel {
        ControlChannel::new(
            TlsAuth::new(&StaticKey::from_bytes([7; 256]), KeyDirection::Inverse),
            SessionId::from_bytes([1; 8]),
            Duration::from_secs(2),
        )
    }

    /// How many datagrams the channel is willing to emit right now.
    fn datagrams(channel: &mut ControlChannel) -> usize {
        let now = Instant::now();
        let mut count = 0;
        while channel.poll_transmit(now, 0).is_some() {
            count += 1;
        }
        count
    }

    /// A session pointed at a certificate authority that exists only here.
    fn test_session() -> Session {
        let key = rcgen::KeyPair::generate().expect("a key");
        let mut params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = params.self_signed(&key).expect("a certificate");

        Session::new(SessionConfig::new(
            ca.pem(),
            "localhost",
            StaticKey::from_bytes([7; 256]),
        ))
        .expect("a session")
    }

    #[test]
    fn a_handshake_waiting_to_go_out_asks_to_be_polled_now() {
        // rustls has a ClientHello ready the moment it is created, before the
        // channel has anything of its own. A wakeup that consulted only the
        // send window would report "nothing to do" and a caller sleeping on it
        // would stall the handshake before it started.
        let session = test_session();
        let now = Instant::now();

        assert_eq!(session.next_wakeup(now), Some(now));
    }

    #[test]
    fn the_first_thing_a_session_sends_is_a_reset() {
        // rustls has a `ClientHello` ready as soon as it exists. If a session
        // could be polled before it was opened, that hello would go out as an
        // ordinary control message with no reset in front of it, and no server
        // would accept the session.
        use crate::packet::{ControlPacket, Opcode};

        let mut session = test_session();
        let datagram = session
            .poll_transmit(Instant::now(), 0)
            .expect("a new session has something to say");

        let peer = TlsAuth::new(&StaticKey::from_bytes([7; 256]), KeyDirection::Normal);
        let (packet, _): (ControlPacket, _) = peer.unwrap(&datagram).expect("authentic");

        assert_eq!(packet.opcode, Opcode::ControlHardResetClientV2);
        assert_eq!(packet.packet_id, Some(0));
        assert!(
            packet.payload.is_empty(),
            "the handshake does not start until the session is open"
        );
    }

    #[test]
    fn a_full_send_window_is_a_reason_to_wait_rather_than_spin() {
        // Bytes held back by a full window are not work that can be done now.
        // Reporting them as due would have an event loop call `poll_transmit`,
        // get nothing, and come straight back — a busy wait dressed as a
        // wakeup.
        let mut session = test_session();
        let now = Instant::now();
        session
            .outbox
            .push(&vec![0u8; MAX_TLS_FRAGMENT * (SendWindow::CAPACITY + 1)]);
        session.outbox.drain_into(&mut session.channel);
        while session.channel.poll_transmit(now, 0).is_some() {}

        assert!(!session.outbox.is_empty(), "a fragment is still waiting");
        let wakeup = session.next_wakeup(now).expect("the window will move");
        assert!(
            wakeup > now,
            "wait for an acknowledgement rather than spinning on a full window"
        );
    }

    #[test]
    fn a_stream_is_cut_into_pieces_that_fit_one_datagram() {
        let mut outbox = Outbox::default();
        let mut channel = new_channel();
        outbox.push(&vec![0u8; MAX_TLS_FRAGMENT]);
        outbox.drain_into(&mut channel);
        assert_eq!(
            datagrams(&mut channel),
            1,
            "exactly a fragment is one message"
        );

        let mut outbox = Outbox::default();
        let mut channel = new_channel();
        outbox.push(&vec![0u8; MAX_TLS_FRAGMENT + 1]);
        outbox.drain_into(&mut channel);

        assert_eq!(outbox.pending(), 0, "all of it was handed over");
        assert_eq!(
            datagrams(&mut channel),
            2,
            "one byte more needs a second message"
        );
    }

    #[test]
    fn bytes_the_window_will_not_take_are_kept_rather_than_dropped() {
        let mut outbox = Outbox::default();
        let mut channel = new_channel();
        // One fragment more than the window can hold.
        outbox.push(&vec![0u8; MAX_TLS_FRAGMENT * (SendWindow::CAPACITY + 1)]);

        outbox.drain_into(&mut channel);

        assert_eq!(
            outbox.pending(),
            MAX_TLS_FRAGMENT,
            "the fragment that did not fit is still here, not lost"
        );
        assert_eq!(datagrams(&mut channel), SendWindow::CAPACITY);
    }
}
