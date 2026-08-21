//! The control channel as one thing: authentication, framing and
//! retransmission wired together.
//!
//! The pieces are tested on their own elsewhere. What is left is how they
//! behave in combination — which packet goes out when, what rides along on it,
//! and which packets are refused because they belong to somebody else's
//! session.
//!
//! The peer here is a second `ControlChannel` configured the way the server
//! would be, plus a bare `TlsAuth` for looking at what was actually sent. That
//! is not the same as testing against a real OpenVPN; for that see
//! `tests/interop.rs`, which drives an actual `openvpn` process.

use std::time::{Duration, Instant};

use synology_filestation_openvpn::{
    Acks, ControlChannel, ControlPacket, KeyDirection, KeyId, Opcode, SessionId, StaticKey,
    TlsAuth, TlsAuthHeader,
};

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

const TLS_TIMEOUT: Duration = Duration::from_secs(2);
const CLIENT_SESSION: SessionId = SessionId::from_bytes([0xc1; 8]);
const SERVER_SESSION: SessionId = SessionId::from_bytes([0x5e; 8]);

fn key() -> StaticKey {
    StaticKey::from_hex(TA_KEY_HEX).expect("test vector")
}

fn client() -> ControlChannel {
    ControlChannel::new(
        TlsAuth::new(&key(), KeyDirection::Inverse),
        CLIENT_SESSION,
        TLS_TIMEOUT,
    )
}

/// A peer that verifies what we sign, and signs what we verify.
fn server_at(session_id: SessionId) -> ControlChannel {
    ControlChannel::new(
        TlsAuth::new(&key(), KeyDirection::Normal),
        session_id,
        TLS_TIMEOUT,
    )
}

fn server() -> ControlChannel {
    server_at(SERVER_SESSION)
}

/// Read a datagram the client sent, the way the server's `tls-auth` would.
fn read(datagram: &[u8]) -> (ControlPacket, TlsAuthHeader) {
    TlsAuth::new(&key(), KeyDirection::Normal)
        .unwrap(datagram)
        .expect("the peer must accept what we send")
}

/// Bring both ends up to the point where each knows the other's session id.
fn handshaken(now: Instant) -> (ControlChannel, ControlChannel) {
    let mut client = client();
    let mut server = server();

    client.open();
    let hello = client.poll_transmit(now, 0).expect("client reset");
    server.handle(&hello, now).expect("the peer accepts it");

    server.open();
    let reply = server.poll_transmit(now, 0).expect("server reset");
    client.handle(&reply, now).expect("a valid reply");

    (client, server)
}

#[test]
fn opening_the_channel_sends_a_hard_reset() {
    let now = Instant::now();
    let mut client = client();
    client.open();

    let datagram = client
        .poll_transmit(now, 0)
        .expect("a reset goes out at once");
    let (packet, _) = read(&datagram);

    assert_eq!(packet.opcode, Opcode::ControlHardResetClientV2);
    assert_eq!(packet.session_id, CLIENT_SESSION);
    assert_eq!(packet.key_id, KeyId::FIRST);
    assert_eq!(
        packet.packet_id,
        Some(0),
        "the first message of the session"
    );
    assert_eq!(packet.acks, None, "nothing has been received yet");
}

#[test]
fn nothing_is_sent_when_there_is_nothing_to_say() {
    let now = Instant::now();
    let mut client = client();

    assert!(
        client.poll_transmit(now, 0).is_none(),
        "an unopened channel has no reason to send"
    );
}

#[test]
fn the_reset_is_repeated_until_it_is_acknowledged() {
    let start = Instant::now();
    let mut client = client();
    client.open();

    client.poll_transmit(start, 0).expect("first attempt");
    assert!(
        client.poll_transmit(start, 0).is_none(),
        "not again in the same instant"
    );

    assert!(
        client.poll_transmit(start + TLS_TIMEOUT, 0).is_some(),
        "the peer has not answered, so it goes again"
    );
}

#[test]
fn the_servers_reset_settles_who_we_are_talking_to() {
    let now = Instant::now();
    assert_eq!(client().remote_session(), None, "nobody yet");

    let (client, _) = handshaken(now);

    assert_eq!(client.remote_session(), Some(SERVER_SESSION));
}

#[test]
fn an_answered_reset_is_replaced_by_a_bare_acknowledgement() {
    let start = Instant::now();
    let (mut client, _) = handshaken(start);

    let much_later = start + Duration::from_secs(60);
    let datagram = client
        .poll_transmit(much_later, 0)
        .expect("we still owe the server an acknowledgement");
    let (packet, _) = read(&datagram);

    assert_eq!(
        packet.opcode,
        Opcode::AckV1,
        "an acknowledgement on its own, not the reset again"
    );
    assert_eq!(
        packet.acks.expect("it acknowledges something").ids(),
        &[0],
        "the server's reset"
    );
    assert_eq!(packet.packet_id, None, "an ack is not itself acknowledged");
}

#[test]
fn acknowledgements_ride_along_on_the_next_real_packet() {
    // A bare ack costs a datagram. If there is something to say anyway, the
    // acks belong on it — which is why the ack block sits inside every control
    // packet rather than having a packet type to itself.
    let now = Instant::now();
    let (mut client, _) = handshaken(now);

    client.send_control(b"a TLS record".to_vec());
    let datagram = client.poll_transmit(now, 0).expect("something to send");
    let (packet, _) = read(&datagram);

    assert_eq!(packet.opcode, Opcode::ControlV1);
    assert_eq!(packet.payload, b"a TLS record");
    assert_eq!(
        packet.acks.expect("carried along").ids(),
        &[0],
        "the server's reset, acknowledged without spending a packet on it"
    );
}

#[test]
fn control_payloads_come_out_in_the_order_they_were_sent() {
    let now = Instant::now();
    let (mut client, mut server) = handshaken(now);

    client.send_control(b"first".to_vec());
    let first = client.poll_transmit(now, 0).expect("first");
    client.send_control(b"second".to_vec());
    let second = client.poll_transmit(now, 0).expect("second");

    // Delivered out of order on purpose.
    server.handle(&second, now).expect("valid");
    assert_eq!(
        server.poll_control(),
        None,
        "it waits for the one before it"
    );

    server.handle(&first, now).expect("valid");
    assert_eq!(server.poll_control(), Some(b"first".to_vec()));
    assert_eq!(server.poll_control(), Some(b"second".to_vec()));
    assert_eq!(server.poll_control(), None);
}

#[test]
fn a_packet_from_a_different_session_is_refused() {
    // Once the peer's session id is known, a packet claiming another one is
    // either a stale session or somebody else's, and neither belongs here.
    let now = Instant::now();
    let (mut client, _) = handshaken(now);

    let mut impostor = server_at(SessionId::from_bytes([0xff; 8]));
    impostor.open();
    let datagram = impostor
        .poll_transmit(now, 0)
        .expect("a correctly signed packet");

    assert!(
        client.handle(&datagram, now).is_err(),
        "correctly signed, wrong session"
    );
}

#[test]
fn an_acknowledgement_addressed_to_another_session_is_refused() {
    // The ack block names the session whose messages are being acknowledged.
    // Accepting one addressed elsewhere would let a stray packet clear
    // messages that are still in flight.
    let now = Instant::now();
    let mut client = client();
    client.open();
    client.poll_transmit(now, 0).expect("our reset");

    let elsewhere = ControlPacket {
        opcode: Opcode::AckV1,
        key_id: KeyId::FIRST,
        session_id: SERVER_SESSION,
        acks: Some(Acks::new(vec![0], SessionId::from_bytes([0xaa; 8])).expect("one ack fits")),
        packet_id: None,
        payload: Vec::new(),
    };
    let datagram = TlsAuth::new(&key(), KeyDirection::Normal).wrap(&elsewhere, 1, 0);

    assert!(client.handle(&datagram, now).is_err());
    assert!(
        client.poll_transmit(now + TLS_TIMEOUT, 0).is_some(),
        "our reset is still outstanding, because that ack was not ours"
    );
}

#[test]
fn each_datagram_gets_its_own_tls_auth_packet_id() {
    // The replay counter is per datagram, not per message, so a retransmission
    // advances it. A peer that sees the same id twice may drop the second.
    let start = Instant::now();
    let mut client = client();
    client.open();

    let first = client.poll_transmit(start, 0).expect("first attempt");
    let again = client
        .poll_transmit(start + TLS_TIMEOUT, 0)
        .expect("retransmission");

    assert_eq!(
        read(&first).1.packet_id,
        1,
        "OpenVPN starts this count at one"
    );
    assert_eq!(read(&again).1.packet_id, 2);
}

#[test]
fn a_forged_packet_never_reaches_the_reliability_layer() {
    let now = Instant::now();
    let mut client = client();
    client.open();
    client.poll_transmit(now, 0).expect("our reset");

    // A packet that would acknowledge our reset, signed with the wrong key.
    let other_key = StaticKey::from_bytes([0x11; 256]);
    let ack = ControlPacket {
        opcode: Opcode::AckV1,
        key_id: KeyId::FIRST,
        session_id: SERVER_SESSION,
        acks: Some(Acks::new(vec![0], CLIENT_SESSION).expect("one ack fits")),
        packet_id: None,
        payload: Vec::new(),
    };
    let datagram = TlsAuth::new(&other_key, KeyDirection::Normal).wrap(&ack, 1, 0);

    assert!(client.handle(&datagram, now).is_err());
    assert!(
        client.poll_transmit(now + TLS_TIMEOUT, 0).is_some(),
        "the reset is still in flight, because that ack was never authentic"
    );
}
