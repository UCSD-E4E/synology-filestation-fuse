//! A server, in this process, that a `Session` can complete a whole handshake
//! against.
//!
//! The interop tests drive a real `openvpn`, which is the stronger check and
//! the one that catches misunderstandings. But it is a *point-to-point* peer:
//! it never assigns a peer id, and it cannot be told to refuse a password, to
//! answer late, or to push something we cannot speak. Whole branches of the
//! session state machine have no way to be reached from there, and one of
//! them held a bug that would have surfaced as the live pass failing in a way
//! that looked like the network.
//!
//! So this peer exists to reach them. It is deliberately simple — no
//! retransmission, no windowing, no loss — because the tests drive it in
//! lockstep and the layers that handle loss are tested elsewhere. What it does
//! faithfully is the *shape* of the exchange: the reset, the TLS handshake,
//! key material, and whatever it has been told to say afterwards.
//!
//! It also matches the real deployment more closely than the loopback openvpn
//! does, in the one way that matters here: it asks for no client certificate,
//! because e4e-nas runs `verify-client-cert none` and authenticates an AD
//! username and password instead.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection};
use synology_filestation_openvpn::{
    key_expansion, Acks, ControlPacket, DataChannel, DataKeys, Error, KeyDirection, KeyId,
    KeySource2, Opcode, SessionId, StaticKey, TlsAuth,
};

/// The same throwaway key the rest of the tests use.
pub const TA_KEY_HEX: &str = concat!(
    "95300e5e0e76a0ed8f58bcdea1b9475b53e468c00d3ba0fb3400e40b2d22ea32",
    "bc5f2f826ebf6378648286697501db24bf2696fa4597231db5b680f6c2e04495",
    "24116f6ea79ae602988d7cf021d8fd35829ddb0249ca4e265723bd93c8141c31",
    "1c2c4bdd4142d7ac06eac732903ed85e547ea8af3c4c04149a4a48e3f31b4bb4",
    "9d73ec8c5da92958a44a23b1e978b4ea0c91b915d650975ede0e784c54544c2f",
    "3947bd3deb19a49925ae2e8b0675d79c77d31116502426e0d740ec23d1d9a634",
    "ba08b32b4ad94b5e5f5eda002e07120ef092c3b08f4bc0842de9ebb0dc953dad",
    "59a382aeb73f10a3b3a75277d045906b48e82f6d5aba62017fc218180fdb4ae6",
);

pub const SERVER_SESSION: SessionId = SessionId::from_bytes([0x5e; 8]);

/// What the peer says once the client's key material has arrived.
pub enum Answer {
    /// The ordinary thing: key material, then this push reply when asked.
    KeyMaterialThen(String),
    /// Key material, and then nothing at all — a server that hears the
    /// `PUSH_REQUEST` and never replies.
    KeyMaterialOnly,
    /// No key material: a refusal, in words, exactly as a wrong password
    /// produces.
    Refuse(String),
}

pub struct FakeServer {
    auth: TlsAuth,
    tls: ServerConnection,
    /// Kept so a renegotiation can build a second TLS session on the same
    /// terms, exactly as the client does.
    tls_config: Arc<ServerConfig>,
    pub ca_pem: String,
    next_message_id: u32,
    next_replay_id: u32,
    /// Client message ids we have not acknowledged yet.
    owed_acks: Vec<u32>,
    client_session: Option<SessionId>,
    plaintext: Vec<u8>,
    answer: Answer,
    sent_key_material: bool,
    answered_push: bool,
    /// Both ends' material, once the client has sent its half.
    client_source: Option<KeySource2>,
    data: Option<DataChannel>,
    /// The peer's receive window: the next client message it expects, and the
    /// ones that arrived early.
    ///
    /// This much of a reliability layer and no more, because TLS needs exactly
    /// two things of whatever is under it. It must not see a record twice — a
    /// client that retransmits would otherwise present one, and TLS reads a
    /// repeat as an attack rather than as a duplicate. And it must see records
    /// in order — a flight that arrives out of order and is fed through in
    /// arrival order is a decryption failure, not a reordering.
    next_expected: u32,
    early: BTreeMap<u32, Vec<u8>>,
    /// The generation being negotiated, once this peer has started one.
    ///
    /// A second everything: its own TLS session, its own message numbering
    /// from zero, its own key material. Only the session id and the
    /// `tls-auth` key carry over — which is what makes a renegotiation
    /// different from a reconnection, and what the client has to get right.
    reneg: Option<Renegotiation>,
}

struct Renegotiation {
    key_id: KeyId,
    tls: ServerConnection,
    next_expected: u32,
    early: BTreeMap<u32, Vec<u8>>,
    next_message_id: u32,
    owed_acks: Vec<u32>,
    plaintext: Vec<u8>,
    answered: bool,
}

impl FakeServer {
    pub fn new(answer: Answer) -> Self {
        let key = KeyPairAndCert::generate();

        let config = Arc::new(
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("default versions")
                // No client certificate, matching e4e-nas: it runs
                // `verify-client-cert none` and takes an AD username and password.
                .with_no_client_auth()
                .with_single_cert(key.chain, key.private)
                .expect("a usable certificate"),
        );

        Self {
            auth: TlsAuth::new(
                &StaticKey::from_hex(TA_KEY_HEX).expect("test vector"),
                KeyDirection::Normal,
            ),
            tls: ServerConnection::new(config.clone()).expect("a server"),
            tls_config: config,
            ca_pem: key.ca_pem,
            next_message_id: 0,
            next_replay_id: 1,
            owed_acks: Vec::new(),
            client_session: None,
            plaintext: Vec::new(),
            answer,
            sent_key_material: false,
            answered_push: false,
            client_source: None,
            data: None,
            next_expected: 0,
            early: BTreeMap::new(),
            reneg: None,
        }
    }

    /// Begin a new key generation, as a server does every `reneg-sec`.
    ///
    /// Returns the soft reset that announces it.
    pub fn renegotiate(&mut self) -> Vec<u8> {
        let key_id = KeyId::new(1).expect("one fits in three bits");
        let config = self.tls_config.clone();
        self.reneg = Some(Renegotiation {
            key_id,
            tls: ServerConnection::new(config).expect("a server"),
            next_expected: 0,
            early: BTreeMap::new(),
            next_message_id: 0,
            owed_acks: Vec::new(),
            plaintext: Vec::new(),
            answered: false,
        });

        let packet = ControlPacket {
            opcode: Opcode::ControlSoftResetV1,
            key_id,
            session_id: SERVER_SESSION,
            acks: None,
            packet_id: Some(0),
            payload: Vec::new(),
        };
        let reneg = self.reneg.as_mut().expect("just built");
        reneg.next_message_id = 1;
        let replay_id = self.next_replay_id;
        self.next_replay_id += 1;
        self.auth.wrap(&packet, replay_id, 0)
    }

    /// Whether the new generation has finished negotiating.
    pub fn renegotiated(&self) -> bool {
        self.reneg.as_ref().is_some_and(|reneg| reneg.answered)
    }

    /// Take a datagram from the client; give back whatever the peer says.
    pub fn handle(&mut self, datagram: &[u8]) -> Vec<Vec<u8>> {
        let (packet, _) = self.auth.unwrap(datagram).expect("the client signs it");
        self.client_session.get_or_insert(packet.session_id);

        if self
            .reneg
            .as_ref()
            .is_some_and(|reneg| reneg.key_id == packet.key_id)
        {
            return self.handle_renegotiation(packet);
        }

        if let Some(id) = packet.packet_id {
            self.owed_acks.push(id);
        }

        let mut out = Vec::new();
        match packet.opcode {
            Opcode::ControlHardResetClientV2 => {
                // The reset is message zero of the same sequence the control
                // messages continue, so the window has to step over it — or
                // everything after it waits forever for a message that has
                // already been dealt with.
                if packet.packet_id == Some(self.next_expected) {
                    self.next_expected += 1;
                }
                out.push(self.reset());
            }
            Opcode::ControlV1 => {
                let id = packet.packet_id.expect("a control message is numbered");
                if id >= self.next_expected {
                    self.early.insert(id, packet.payload);
                }
                // Only ever in order, and only ever once.
                while let Some(payload) = self.early.remove(&self.next_expected) {
                    self.next_expected += 1;
                    let mut remaining = payload.as_slice();
                    while !remaining.is_empty() {
                        self.tls.read_tls(&mut remaining).expect("readable");
                        self.tls.process_new_packets().expect("valid TLS");
                    }
                    self.read_plaintext();
                    self.speak();
                    out.extend(self.flush_tls());
                }
            }
            _ => {}
        }

        // An acknowledgement still owed goes out on its own, as a real peer's
        // would.
        if !self.owed_acks.is_empty() {
            out.push(self.ack_only());
        }

        out
    }

    /// Decrypt a tunnel packet the client sent.
    ///
    /// The peer runs the same derivation over the same material rather than
    /// being handed the answer — which is what makes a payload test mean
    /// something: if either end derived differently, this would not decrypt.
    pub fn decrypt_payload(&mut self, datagram: &[u8]) -> Result<Vec<u8>, Error> {
        self.tunnel().decrypt(datagram)
    }

    /// The peer's end of the data channel, derived the same way the client's
    /// is — which is what makes a payload test mean anything.
    fn tunnel(&mut self) -> &mut DataChannel {
        if self.data.is_none() {
            let source = self.client_source.clone().expect("the client's material");
            let expansion = key_expansion(
                &source,
                self.client_session.expect("the client's session id"),
                SERVER_SESSION,
            );
            self.data = Some(DataChannel::new(
                DataKeys::for_server(&expansion).expect("256 bytes"),
                None,
                KeyId::FIRST,
            ));
        }
        self.data.as_mut().expect("built above")
    }

    /// Wrap a payload the way the peer would, so the client has something to
    /// receive.
    pub fn encrypt_payload(&mut self, payload: &[u8]) -> Vec<u8> {
        self.tunnel().encrypt(payload).expect("encrypt")
    }

    /// The same exchange again, under the new key.
    fn handle_renegotiation(&mut self, packet: ControlPacket) -> Vec<Vec<u8>> {
        let session = self.client_session.expect("known by now");
        let reneg = self.reneg.as_mut().expect("checked by the caller");

        if let Some(id) = packet.packet_id {
            reneg.owed_acks.push(id);
        }

        let mut records: Vec<Vec<u8>> = Vec::new();
        if packet.opcode == Opcode::ControlV1 {
            if let Some(id) = packet.packet_id {
                if id >= reneg.next_expected {
                    reneg.early.insert(id, packet.payload);
                }
            }
            while let Some(payload) = reneg.early.remove(&reneg.next_expected) {
                reneg.next_expected += 1;
                let mut remaining = payload.as_slice();
                while !remaining.is_empty() {
                    reneg.tls.read_tls(&mut remaining).expect("readable");
                    reneg.tls.process_new_packets().expect("valid TLS");
                }

                let mut buffer = [0u8; 4096];
                while let Ok(read) = reneg.tls.reader().read(&mut buffer) {
                    if read == 0 {
                        break;
                    }
                    reneg.plaintext.extend_from_slice(&buffer[..read]);
                }

                if reneg.plaintext.len() > 4
                    && reneg.plaintext[..4] == [0, 0, 0, 0]
                    && !reneg.answered
                {
                    reneg.answered = true;
                    let reply = server_key_method_2();
                    reneg.tls.writer().write_all(&reply).expect("write");
                }

                while reneg.tls.wants_write() {
                    let mut bytes = Vec::new();
                    match reneg.tls.write_tls(&mut bytes) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => records.push(bytes),
                    }
                }
            }
        }

        // Framed with the new key id, and numbered from zero again.
        let mut out = Vec::new();
        for record in records {
            for chunk in record.chunks(1024) {
                let reneg = self.reneg.as_mut().expect("still there");
                let acks = take_acks(&mut reneg.owed_acks, session);
                let id = reneg.next_message_id;
                reneg.next_message_id += 1;
                let key_id = reneg.key_id;
                let packet = ControlPacket {
                    opcode: Opcode::ControlV1,
                    key_id,
                    session_id: SERVER_SESSION,
                    acks,
                    packet_id: Some(id),
                    payload: chunk.to_vec(),
                };
                let replay_id = self.next_replay_id;
                self.next_replay_id += 1;
                out.push(self.auth.wrap(&packet, replay_id, 0));
            }
        }

        let reneg = self.reneg.as_mut().expect("still there");
        if !reneg.owed_acks.is_empty() {
            let acks = take_acks(&mut reneg.owed_acks, session);
            let key_id = reneg.key_id;
            let packet = ControlPacket {
                opcode: Opcode::AckV1,
                key_id,
                session_id: SERVER_SESSION,
                acks,
                packet_id: None,
                payload: Vec::new(),
            };
            let replay_id = self.next_replay_id;
            self.next_replay_id += 1;
            out.push(self.auth.wrap(&packet, replay_id, 0));
        }
        out
    }

    fn read_plaintext(&mut self) {
        let mut buffer = [0u8; 4096];
        while let Ok(read) = self.tls.reader().read(&mut buffer) {
            if read == 0 {
                break;
            }
            self.plaintext.extend_from_slice(&buffer[..read]);
        }
    }

    /// Say whatever this peer has been told to say, once there is something to
    /// say it about.
    fn speak(&mut self) {
        // The client's key material starts with four zero bytes; its
        // `PUSH_REQUEST` does not.
        let has_key_material = self.plaintext.len() > 4 && self.plaintext[..4] == [0, 0, 0, 0];
        let has_push_request = self
            .plaintext
            .windows(PUSH_REQUEST_BYTES.len())
            .any(|window| window == PUSH_REQUEST_BYTES);

        if has_key_material && !self.sent_key_material {
            self.sent_key_material = true;
            self.client_source = Some(client_source_from(&self.plaintext));
            match &self.answer {
                Answer::Refuse(message) => {
                    let text = format!("{message}\0");
                    self.tls.writer().write_all(text.as_bytes()).expect("write");
                    return;
                }
                _ => {
                    let reply = server_key_method_2();
                    self.tls.writer().write_all(&reply).expect("write");
                }
            }
        }

        if has_push_request && !self.answered_push {
            if let Answer::KeyMaterialThen(reply) = &self.answer {
                self.answered_push = true;
                let text = format!("{reply}\0");
                self.tls.writer().write_all(text.as_bytes()).expect("write");
            }
        }
    }

    fn flush_tls(&mut self) -> Vec<Vec<u8>> {
        let mut records = Vec::new();
        while self.tls.wants_write() {
            let mut bytes = Vec::new();
            match self.tls.write_tls(&mut bytes) {
                Ok(0) | Err(_) => break,
                Ok(_) => records.push(bytes),
            }
        }

        records
            .into_iter()
            .flat_map(|record| {
                record
                    .chunks(1024)
                    .map(|chunk| self.control(chunk.to_vec()))
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    fn reset(&mut self) -> Vec<u8> {
        let packet = ControlPacket {
            opcode: Opcode::ControlHardResetServerV2,
            key_id: KeyId::FIRST,
            session_id: SERVER_SESSION,
            acks: self.take_acks(),
            packet_id: Some(self.take_message_id()),
            payload: Vec::new(),
        };
        self.wrap(&packet)
    }

    fn control(&mut self, payload: Vec<u8>) -> Vec<u8> {
        let packet = ControlPacket {
            opcode: Opcode::ControlV1,
            key_id: KeyId::FIRST,
            session_id: SERVER_SESSION,
            acks: self.take_acks(),
            packet_id: Some(self.take_message_id()),
            payload,
        };
        self.wrap(&packet)
    }

    fn ack_only(&mut self) -> Vec<u8> {
        let packet = ControlPacket {
            opcode: Opcode::AckV1,
            key_id: KeyId::FIRST,
            session_id: SERVER_SESSION,
            acks: self.take_acks(),
            packet_id: None,
            payload: Vec::new(),
        };
        self.wrap(&packet)
    }

    fn wrap(&mut self, packet: &ControlPacket) -> Vec<u8> {
        let replay_id = self.next_replay_id;
        self.next_replay_id += 1;
        self.auth.wrap(packet, replay_id, 0)
    }

    fn take_acks(&mut self) -> Option<Acks> {
        let session = self.client_session?;
        if self.owed_acks.is_empty() {
            return None;
        }
        let taking = self.owed_acks.len().min(Acks::MAX);
        let ids: Vec<u32> = self.owed_acks.drain(..taking).collect();
        Some(Acks::new(ids, session).expect("bounded by Acks::MAX"))
    }

    fn take_message_id(&mut self) -> u32 {
        let id = self.next_message_id;
        self.next_message_id += 1;
        id
    }
}

const PUSH_REQUEST_BYTES: &[u8] = b"PUSH_REQUEST\0";

/// A server's key-method message: two randoms, no pre-master, then the three
/// strings it always writes.
fn server_key_method_2() -> Vec<u8> {
    let mut out = vec![0, 0, 0, 0, 2];
    out.extend_from_slice(&[0x51; 32]);
    out.extend_from_slice(&[0x62; 32]);
    let options = b"V4,cipher AES-256-CBC,auth SHA512\0";
    out.extend_from_slice(&(options.len() as u16).to_be_bytes());
    out.extend_from_slice(options);
    out.extend_from_slice(&[0, 0]); // username
    out.extend_from_slice(&[0, 0]); // password
    out.extend_from_slice(&[0, 0]); // peer info
    out
}

struct KeyPairAndCert {
    chain: Vec<CertificateDer<'static>>,
    private: PrivateKeyDer<'static>,
    ca_pem: String,
}

impl KeyPairAndCert {
    fn generate() -> Self {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("a certificate");
        Self {
            chain: vec![cert.cert.der().clone()],
            private: PrivateKeyDer::try_from(cert.signing_key.serialize_der())
                .expect("a usable key"),
            ca_pem: cert.cert.pem(),
        }
    }
}

/// Drive a session against a peer over a link that loses and reorders.
///
/// Only datagrams *to* the peer are dropped: this peer does not retransmit —
/// deliberately, it is meant to be simple — so losing one of its replies would
/// stall a handshake for reasons that say nothing about the client. What is
/// under test is the client's own recovery: its retransmission timer, and its
/// receive window putting a reordered flight back in order before TLS ever
/// sees it.
///
/// Time advances in steps longer than the retransmission timeout, so a lost
/// message is actually resent rather than merely queued.
pub fn exchange_lossy(
    session: &mut synology_filestation_openvpn::Session,
    server: &mut FakeServer,
    now: Instant,
    drop_every: usize,
    // What "finished" means, said by the caller rather than guessed at here.
    // A renegotiation begins with the session already ready, so a driver that
    // assumed readiness was the end would return before it had done anything.
    done: impl Fn(&synology_filestation_openvpn::Session, &FakeServer) -> bool,
) -> Result<(), synology_filestation_openvpn::Error> {
    let mut sent = 0usize;
    let mut at = now;

    for _ in 0..200 {
        let mut progressed = false;

        // A whole flight, then delivered backwards — so the *peer's* receive
        // window has to reorder as well. Feeding TLS a flight in arrival order
        // is a decryption failure rather than a reordering, which is a panic
        // waiting for the first link that delivers out of order.
        let mut outbound = Vec::new();
        while let Some(datagram) = session.poll_transmit(at, 0) {
            sent += 1;
            if sent.is_multiple_of(drop_every) {
                continue; // lost on the way out
            }
            outbound.push(datagram);
        }

        for datagram in outbound.into_iter().rev() {
            // Backwards again on the way back, so the client's receive window
            // has to put a flight in order before TLS sees any of it.
            for reply in server.handle(&datagram).into_iter().rev() {
                progressed = true;
                // A refused datagram is not a refused session. Reordering
                // makes this happen for real: a flight arriving backwards
                // puts the peer's acknowledgement in front of the reset that
                // opens the session, and the client is right to turn that
                // away — the reset is along in a moment. A driver that gave up
                // here could not survive a reordered link.
                if let Err(error) = session.handle(&reply, at) {
                    if error.is_fatal() {
                        return Err(error);
                    }
                }
            }
        }

        if done(session, server) {
            return Ok(());
        }
        if let Some(error) = session.failure() {
            return Err(error.clone());
        }

        // Only now does the clock move: waiting is what a retransmission
        // timer is for, and advancing it on a round that made progress would
        // spend the handshake's own deadlines on nothing.
        if !progressed {
            at += Duration::from_millis(2_500);
        }
    }

    // Falling out of the budget is a stalled handshake, and returning `Ok`
    // for it would make `expect("recovery, not failure")` unable to fire —
    // a test that cannot fail.
    Err(synology_filestation_openvpn::Error::Tls(
        "the handshake did not finish within the round budget".into(),
    ))
}

/// Drive a session against a peer until it stops having anything to say.
///
/// Returns the last error, if the session refused something — which several
/// tests are about.
pub fn exchange(
    session: &mut synology_filestation_openvpn::Session,
    server: &mut FakeServer,
    now: Instant,
) -> Result<(), synology_filestation_openvpn::Error> {
    let mut pending: Vec<Vec<u8>> = Vec::new();

    for round in 0..64 {
        let at = now + Duration::from_millis(round * 10);

        while let Some(datagram) = session.poll_transmit(at, 0) {
            pending.extend(server.handle(&datagram));
        }

        if pending.is_empty() {
            return Ok(());
        }
        for datagram in std::mem::take(&mut pending) {
            session.handle(&datagram, at)?;
        }
    }
    Ok(())
}

/// The material both ends will derive from: the client's, out of its message,
/// beside the randoms this peer always sends.
fn client_source_from(key_method: &[u8]) -> KeySource2 {
    let mut source = KeySource2::default();
    source.pre_master.copy_from_slice(&key_method[5..53]);
    source.client_random1.copy_from_slice(&key_method[53..85]);
    source.client_random2.copy_from_slice(&key_method[85..117]);
    source.server_random1 = [0x51; 32];
    source.server_random2 = [0x62; 32];
    source
}

/// Acknowledgements to attach, bounded the way the wire bounds them.
fn take_acks(owed: &mut Vec<u32>, session: SessionId) -> Option<Acks> {
    if owed.is_empty() {
        return None;
    }
    let taking = owed.len().min(Acks::MAX);
    let ids: Vec<u32> = owed.drain(..taking).collect();
    Some(Acks::new(ids, session).expect("bounded by Acks::MAX"))
}
