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
use crate::data::{DataChannel, DataKeys};
use crate::key_method::{ClientKeyMethod2, ServerMessage};
use crate::packet::SessionId;
use crate::packet::{KeyId, Opcode};
use crate::prf::{key_expansion, KeySource2};
use crate::push::{PushReply, PUSH_REQUEST};
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

/// How often to ask again while the server has not answered a `PUSH_REQUEST`
/// — OpenVPN's `PUSH_REQUEST_INTERVAL`.
const PUSH_REQUEST_INTERVAL: Duration = Duration::from_secs(5);

/// How long to keep asking before giving up, matching `--hand-window`.
///
/// A client that pulls its configuration cannot work without the answer, so
/// asking forever would be a session that is never usable and never says why.
const PUSH_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

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
    /// We have asked what the server wants us to know, and are waiting. A
    /// point-to-point peer never answers, so nothing blocks on this.
    AwaitingPush,
    /// The server has told us. Nothing further is expected, though it may
    /// still say things.
    Ready,
}

/// A TLS session and the control channel underneath it.
pub struct Session {
    channel: ControlChannel,
    tls: ClientConnection,
    outbox: Outbox,
    phase: Phase,
    source: KeySource2,
    credentials: Option<Credentials>,
    /// Plaintext read out of TLS, which arrives in pieces. It holds the
    /// peer's key material until it has all arrived, so it is cleared rather
    /// than merely dropped.
    inbound: Zeroizing<Vec<u8>>,
    keys: Option<Zeroizing<Vec<u8>>>,
    push: Option<PushReply>,
    /// When the last `PUSH_REQUEST` went out, so it can go again.
    push_requested_at: Option<Instant>,
    /// When we first asked, so the asking can stop.
    push_first_requested_at: Option<Instant>,
    /// The tunnel itself, once there are keys to build it from.
    data: Option<DataChannel>,
    /// When we last put anything on the wire, which is what a keepalive is
    /// measured from.
    last_sent: Option<Instant>,
    /// A failure from a path that cannot return one — see
    /// [`Session::poll_transmit`].
    failure: Option<Error>,
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
            inbound: Zeroizing::new(Vec::new()),
            keys: None,
            push: None,
            push_requested_at: None,
            push_first_requested_at: None,
            data: None,
            last_sent: None,
            failure: None,
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
        matches!(
            self.phase,
            Phase::Established | Phase::AwaitingPush | Phase::Ready
        )
    }

    /// What the server pushed, once it has.
    ///
    /// A `--mode server` peer answers a `PUSH_REQUEST` with the peer id, the
    /// cipher it chose and the keepalive intervals. A point-to-point peer has
    /// no push exchange at all, and this stays `None` — which is not a
    /// failure, it is what that kind of peer looks like.
    pub fn push_reply(&self) -> Option<&PushReply> {
        self.push.as_ref()
    }

    /// Whether the tunnel is ready to carry payload.
    pub fn is_ready(&self) -> bool {
        self.data.is_some()
    }

    /// Wrap a payload for the tunnel.
    pub fn send_payload(&mut self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        let data = self.data.as_mut().ok_or(Error::NotReady)?;
        let datagram = data.encrypt(payload)?;
        Ok(datagram)
    }

    /// Unwrap a datagram the tunnel carried.
    pub fn receive_payload(&mut self, datagram: &[u8]) -> Result<Vec<u8>, Error> {
        let data = self.data.as_mut().ok_or(Error::NotReady)?;
        data.decrypt(datagram)
    }

    /// Whether a datagram belongs to the tunnel rather than to the handshake.
    ///
    /// A caller reading a socket has to sort them out before handing either to
    /// the wrong place: a data packet given to the control channel fails its
    /// `tls-auth` check, and a control packet given to the tunnel fails to
    /// decrypt.
    pub fn is_data(datagram: &[u8]) -> bool {
        match datagram.first() {
            Some(&first) => {
                let opcode = first >> 3;
                opcode == Opcode::DataV1 as u8 || opcode == Opcode::DataV2 as u8
            }
            None => false,
        }
    }

    /// The derived key material: two directions, each a cipher key then an
    /// HMAC key, 64 bytes apiece.
    pub fn keys(&self) -> Option<&[u8]> {
        self.keys.as_ref().map(|keys| keys.as_slice())
    }

    /// The next datagram to send.
    /// A failure from a step that had nowhere to report one.
    ///
    /// [`Session::poll_transmit`] returns a datagram, not a result, but the
    /// push request it may resend can fail. Rather than drop that — the
    /// mistake this crate has already made once — it is kept here, returned
    /// by the next [`Session::handle`], and stops the session sending
    /// anything more.
    pub fn failure(&self) -> Option<&Error> {
        self.failure.as_ref()
    }

    pub fn poll_transmit(&mut self, now: Instant, net_time: u32) -> Option<Vec<u8>> {
        if self.failure.is_some() {
            return None;
        }
        if let Err(error) = self.resend_push_request(now) {
            self.failure = Some(error);
            return None;
        }

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

        if let Some(datagram) = self.channel.poll_transmit(now, net_time) {
            self.last_sent = Some(now);
            return Some(datagram);
        }

        self.poll_keepalive(now)
    }

    /// A keepalive, if the server asked for one and we have been quiet.
    ///
    /// The server counts silence, not idleness: `ping-restart` is how long it
    /// waits before deciding we have gone. Ordinary traffic resets that too,
    /// which is why this is measured from the last thing we sent rather than
    /// on a fixed schedule.
    fn poll_keepalive(&mut self, now: Instant) -> Option<Vec<u8>> {
        let interval = self.push.as_ref()?.ping?;
        let due = match self.last_sent {
            Some(last) => now.duration_since(last) >= interval,
            None => true,
        };
        if !due {
            return None;
        }

        let datagram = self.data.as_mut()?.encrypt(&crate::PING).ok()?;
        self.last_sent = Some(now);
        Some(datagram)
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
        if let Some(error) = self.failure.take() {
            return Err(error);
        }
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

        // Both of these belong here rather than in `poll_transmit`, and not
        // only because they can fail: the TLS handshake finishes while
        // *reading*, so this is the moment our key material becomes sendable.
        // Putting them where the result can be returned means a failure is
        // reported rather than dropped.
        self.send_our_key_material()?;
        // Once, for whatever phase we are in, before anything tries to read
        // the buffer.
        self.drain_plaintext()?;
        self.receive_their_key_material()?;
        self.receive_push_reply()
    }

    /// The peer's session id, once it has told us.
    pub fn remote_session(&self) -> Option<SessionId> {
        self.channel.remote_session()
    }

    /// Send our half of the key material, once TLS will carry it.
    ///
    /// Exactly once: the phase moves as soon as the message is written,
    /// because rustls buffers it and a second copy would be read as a second
    /// message.
    fn send_our_key_material(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Tls || self.tls.is_handshaking() {
            return Ok(());
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
        .encode()?;

        self.tls
            .writer()
            .write_all(&message)
            .map_err(|error| Error::Tls(error.to_string()))?;
        self.phase = Phase::AwaitingKeys;
        Ok(())
    }

    /// Build the data channel, now that everything it needs exists.
    fn open_tunnel(&mut self) -> Result<(), Error> {
        let keys = self.keys.as_ref().ok_or(Error::NotReady)?;
        let peer_id = self.push.as_ref().and_then(|reply| reply.peer_id);
        self.data = Some(DataChannel::new(
            DataKeys::for_client(keys)?,
            peer_id,
            KeyId::FIRST,
        ));
        Ok(())
    }

    /// Ask again, if the answer has not come.
    ///
    /// A server that is not yet ready to answer says nothing at all, and a
    /// request sent once is then a request never answered — the session would
    /// sit there established, with no peer id, sending `P_DATA_V1` packets a
    /// `--mode server` peer drops without a word. Real clients retransmit on
    /// about this interval for the same reason.
    fn resend_push_request(&mut self, now: Instant) -> Result<(), Error> {
        if self.phase != Phase::AwaitingPush {
            return Ok(());
        }
        // Giving up is part of asking. A client that pulls cannot work
        // without the answer, so asking forever would be a session that is
        // never usable and never says why.
        if let Some(first) = self.push_first_requested_at {
            if now.duration_since(first) >= PUSH_REQUEST_TIMEOUT {
                return Err(Error::NoPushReply);
            }
        }

        match self.push_requested_at {
            Some(sent) if now.duration_since(sent) < PUSH_REQUEST_INTERVAL => Ok(()),
            _ => self.send_push_request(now),
        }
    }

    fn send_push_request(&mut self, now: Instant) -> Result<(), Error> {
        self.tls
            .writer()
            .write_all(format!("{PUSH_REQUEST}\0").as_bytes())
            .map_err(|error| Error::Tls(error.to_string()))?;
        self.push_requested_at = Some(now);
        self.push_first_requested_at.get_or_insert(now);
        Ok(())
    }

    /// Take the push reply, if the server has sent one.
    fn receive_push_reply(&mut self) -> Result<(), Error> {
        if self.phase != Phase::AwaitingPush || self.inbound.is_empty() {
            return Ok(());
        }

        let (message, used) = match ServerMessage::decode(&self.inbound) {
            Ok(decoded) => decoded,
            // Still arriving.
            Err(Error::Truncated { .. }) => return Ok(()),
            Err(error) => return Err(error),
        };
        self.inbound = Zeroizing::new(self.inbound[used..].to_vec());

        let ServerMessage::Control(text) = message else {
            // Key material where a push reply belongs is a renegotiation,
            // which is not built yet. Saying so beats treating it as the
            // answer to a question we did not ask.
            return Err(Error::UnexpectedControlMessage(
                "key material after the exchange".into(),
            ));
        };

        if let Some(detail) = text.strip_prefix("AUTH_FAILED") {
            return Err(Error::AuthFailed(detail.to_string()));
        }

        let reply = PushReply::parse(&text)?;
        if !reply.compression_is_supported() {
            // Compression prepends a byte to every payload and changes the
            // framing, exactly as a different cipher would. A tunnel that
            // came up and carried corrupt bytes would be worse than one that
            // refused to come up.
            return Err(Error::UnsupportedCompression(
                reply.compression.clone().unwrap_or_default(),
            ));
        }
        if !reply.cipher_is_supported() {
            // Refused rather than ignored: encrypting with a cipher the
            // server did not choose produces packets it drops without a word,
            // which is indistinguishable from a broken network.
            return Err(Error::UnsupportedCipher(
                reply.cipher.clone().unwrap_or_default(),
            ));
        }
        self.push = Some(reply);
        self.phase = Phase::Ready;
        self.open_tunnel()
    }

    /// Move whatever TLS has decrypted into `inbound`.
    ///
    /// Unconditional, and that is the point. This used to live inside the
    /// key-material step, guarded by its phase — so once the session moved on
    /// to waiting for a push reply, nothing refilled the buffer and the reply
    /// was decrypted by rustls and then left there. Everything after it
    /// silently did not happen: no peer id, so data packets stayed `P_DATA_V1`;
    /// no cipher check; and an `AUTH_FAILED` arriving late was swallowed whole.
    ///
    /// A step that every phase needs does not belong inside one of them.
    fn drain_plaintext(&mut self) -> Result<(), Error> {
        let mut buffer = Zeroizing::new([0u8; 2048]);
        loop {
            match self.tls.reader().read(buffer.as_mut()) {
                Ok(read) if read > 0 => self.inbound.extend_from_slice(&buffer[..read]),
                // A clean close, which is not the same as "nothing right now".
                // Treating it as the latter would leave us waiting for the
                // rest of a message from a peer that has finished talking.
                Ok(_) => return Err(Error::PeerClosed),
                // Nothing more to read at the moment: the ordinary case.
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                // Anything else is the session failing, and swallowing it
                // would leave us decoding a buffer that will never grow again.
                Err(error) => return Err(Error::Tls(error.to_string())),
            }
        }
        Ok(())
    }

    /// Take the peer's key material if all of it has arrived.
    fn receive_their_key_material(&mut self) -> Result<(), Error> {
        if self.phase != Phase::AwaitingKeys {
            return Ok(());
        }

        match ServerMessage::decode(&self.inbound) {
            // Not all of it is here yet. TLS is a stream, so this is ordinary.
            Err(Error::Truncated { .. }) => Ok(()),
            Err(error) => Err(error),

            // Authentication is the likeliest thing to go wrong, and the
            // server says so in words rather than by failing the exchange.
            // Reading it as key material would report the first letters of
            // "AUTH_FAILED" as a key method number.
            Ok((ServerMessage::Control(message), _)) => {
                Err(match message.strip_prefix("AUTH_FAILED") {
                    Some(detail) => Error::AuthFailed(detail.to_string()),
                    None => Error::UnexpectedControlMessage(message),
                })
            }

            Ok((ServerMessage::KeyMethod2(reply), used)) => {
                self.source.server_random1 = reply.random1;
                self.source.server_random2 = reply.random2;

                let server_session = self
                    .channel
                    .remote_session()
                    .ok_or_else(|| Error::Tls("key material before a session id".into()))?;
                self.keys = Some(key_expansion(
                    &self.source,
                    self.channel.local_session(),
                    server_session,
                ));

                // Only what the message used. A flight can carry more behind
                // it — a push reply arrives this way — and dropping the
                // remainder would lose bytes that rustls has already handed
                // over and will not hand over again.
                //
                // Rebuilt rather than drained in place, because `Vec::drain`
                // leaves the moved-down bytes in the tail of the same
                // allocation, where the key material we just consumed would
                // sit uncleared.
                let rest = Zeroizing::new(self.inbound[used..].to_vec());
                self.inbound = rest;
                self.phase = Phase::Established;

                // Ask what else the server wants us to know. Its answer
                // carries the peer id that makes our data packets
                // addressable, so against a real server this is not optional.
                self.phase = Phase::AwaitingPush;

                // What followed the key material in the same flight may
                // already be the answer.
                self.receive_push_reply()
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
    fn a_push_reply_waiting_in_the_buffer_is_consumed() {
        // Narrower than it looks, and worth saying so: this pins that a reply
        // already in `inbound` is parsed and kept. It does *not* cover how the
        // reply gets there, which is where the bug was — the drain was gated
        // on the key-material phase, so after the request went out nothing
        // ever refilled the buffer. Covering that needs an in-process TLS peer
        // to produce real plaintext, which does not exist here yet.
        let mut session = test_session();
        session.phase = Phase::AwaitingPush;
        // Consuming the reply also opens the tunnel, which needs the keys the
        // exchange would have produced.
        session.keys = Some(Zeroizing::new(vec![0u8; 256]));
        session.inbound = Zeroizing::new(b"PUSH_REPLY,peer-id 9,cipher AES-256-CBC\0".to_vec());

        session.receive_push_reply().expect("a well-formed reply");

        let reply = session.push_reply().expect("kept");
        assert_eq!(reply.peer_id.map(|id| id.get()), Some(9));
        assert!(reply.cipher_is_supported());
        assert!(
            session.inbound.is_empty(),
            "and consumed, so the next message starts where it should"
        );
        assert!(session.is_ready(), "and the tunnel exists");
    }

    #[test]
    fn a_cipher_we_cannot_speak_stops_the_session() {
        let mut session = test_session();
        session.phase = Phase::AwaitingPush;
        session.inbound = Zeroizing::new(b"PUSH_REPLY,cipher AES-256-GCM\0".to_vec());

        assert_eq!(
            session.receive_push_reply().unwrap_err(),
            Error::UnsupportedCipher("AES-256-GCM".to_string()),
            "better than encrypting with an algorithm the server did not pick"
        );
    }

    #[test]
    fn a_refusal_arriving_after_the_request_is_still_a_refusal() {
        // `AUTH_FAILED` can arrive at this point too, and reading it as a push
        // reply would report it as an unparseable directive rather than as the
        // wrong password it is.
        let mut session = test_session();
        session.phase = Phase::AwaitingPush;
        session.inbound = Zeroizing::new(b"AUTH_FAILED,expired\0".to_vec());

        assert_eq!(
            session.receive_push_reply().unwrap_err(),
            Error::AuthFailed(",expired".to_string())
        );
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
