//! Golden tests against packets a real OpenVPN client actually put on the wire.
//!
//! The three hex blobs below are the first three control packets emitted by
//! `openvpn 2.6.21` — the initial `P_CONTROL_HARD_RESET_CLIENT_V2` and its two
//! retransmissions — captured off a UDP socket standing in for the server:
//!
//! ```text
//! openvpn --client --dev null --proto udp --remote 127.0.0.1 11940 \
//!         --ca ca.crt --auth-user-pass creds.txt \
//!         --tls-auth ta.key 1 --auth SHA512 --data-ciphers AES-256-CBC
//! ```
//!
//! Testing against our own encoder would only prove it agrees with itself, and
//! the one property that matters here is agreeing with someone else's — a
//! server that drops anything it cannot authenticate, silently and before it
//! will tell us why.
//!
//! `ta.key` was generated for this capture and is used nowhere: it is a test
//! vector, not a credential. It is spelled as raw hex and reassembled into the
//! file format at runtime, so the repository holds no blob that looks like a
//! key anyone should care about.

use synology_filestation_openvpn::{
    Acks, ControlPacket, KeyDirection, Opcode, SessionId, StaticKey, TlsAuth,
};

/// The 2048-bit static key the capture was made with, in the order the file
/// stores it: `keys[0].cipher | keys[0].hmac | keys[1].cipher | keys[1].hmac`.
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

/// First packet out: opcode 7, key id 0, no acks, message packet-id 0.
const RESET_1: &str = concat!(
    "38d96e11ba3a75cad1",
    "146a3502f9d1dd410b35a31fb39da0caaf81b431e4063ae4337b164476c2c033",
    "2b56ce2f01048d97dda96001a8fb6d0cec662a544b565facb3d0d6e9ef01a284",
    "00000001",
    "6a87eba5",
    "00",
    "00000000",
);

/// Its first retransmission — same message, next tls-auth packet id.
const RESET_2: &str = concat!(
    "38d96e11ba3a75cad1",
    "f94afd257345138ba86ce622b21ab8ceef8d424027b796ca29eae017ba820e39",
    "fe4b99193bf2c30c2037242908bcd47a0f1bce1d43d15a12743a7263264a70d3",
    "00000002",
    "6a87eba5",
    "00",
    "00000000",
);

fn key() -> StaticKey {
    StaticKey::from_hex(TA_KEY_HEX).expect("test vector is a well-formed key")
}

/// The client side of a `key-direction 1` config, which is what the published
/// `e4e-nas-vpn.ovpn` carries. It *signs* with slot 1.
fn client_auth() -> TlsAuth {
    TlsAuth::new(&key(), KeyDirection::Inverse)
}

/// The other end of the same key: `tls-auth ta.key 0`, which verifies slot 1.
///
/// The captured packets were sent by a client, so verifying them is the
/// server's job — a client cannot check its own HMAC, and that asymmetry is
/// the mechanism, not an inconvenience.
fn server_auth() -> TlsAuth {
    TlsAuth::new(&key(), KeyDirection::Normal)
}

fn bytes(hex: &str) -> Vec<u8> {
    hex::decode(hex).expect("test vector is valid hex")
}

#[test]
fn a_captured_hard_reset_decodes_to_its_fields() {
    let (packet, header) = server_auth()
        .unwrap(&bytes(RESET_1))
        .expect("a packet openvpn itself emitted must authenticate");

    assert_eq!(packet.opcode, Opcode::ControlHardResetClientV2);
    assert_eq!(packet.key_id, 0);
    assert_eq!(
        packet.session_id,
        SessionId::from_bytes([0xd9, 0x6e, 0x11, 0xba, 0x3a, 0x75, 0xca, 0xd1])
    );
    assert_eq!(packet.acks, None, "nothing has been received yet");
    assert_eq!(packet.packet_id, Some(0));
    assert!(packet.payload.is_empty(), "a reset carries no TLS payload");

    // The tls-auth packet id is a separate sequence from the message id above:
    // it counts packets sent, so a retransmission advances it.
    assert_eq!(header.packet_id, 1);
    assert_eq!(header.net_time, 0x6a87_eba5);
}

#[test]
fn a_retransmission_repeats_the_message_and_advances_the_tls_auth_id() {
    let auth = server_auth();
    let (first, first_header) = auth.unwrap(&bytes(RESET_1)).expect("valid");
    let (again, again_header) = auth.unwrap(&bytes(RESET_2)).expect("valid");

    assert_eq!(first.packet_id, again.packet_id, "same message");
    assert_eq!(first.session_id, again.session_id);
    assert_eq!(first_header.packet_id + 1, again_header.packet_id);
}

#[test]
fn rewrapping_a_captured_packet_reproduces_it_byte_for_byte() {
    let original = bytes(RESET_1);
    let (packet, header) = server_auth().unwrap(&original).expect("valid");

    assert_eq!(
        client_auth().wrap(&packet, header.packet_id, header.net_time),
        original,
        "our encoder must agree with the one that produced the capture"
    );
}

#[test]
fn a_packet_whose_body_was_altered_does_not_authenticate() {
    let mut tampered = bytes(RESET_1);
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01; // the message packet-id, which the HMAC covers

    assert!(
        server_auth().unwrap(&tampered).is_err(),
        "the HMAC exists precisely to catch this"
    );
}

#[test]
fn each_end_verifies_the_slot_the_other_end_signs_with() {
    // A client cannot authenticate its own packet, and that is the point: the
    // two slots are what stop a replayed client packet from being accepted as
    // if it came from the server. Getting `key-direction` backwards produces a
    // tunnel that hangs with no reply rather than an error, so pin both halves.
    assert!(
        server_auth().unwrap(&bytes(RESET_1)).is_ok(),
        "the server verifies with the slot the client signed with"
    );
    assert_eq!(
        client_auth().unwrap(&bytes(RESET_1)).unwrap_err(),
        synology_filestation_openvpn::Error::BadHmac,
        "and the client's own slot does not verify its own packet"
    );
}

#[test]
fn an_ack_carries_acknowledged_ids_and_no_message_id() {
    let auth = client_auth();
    let session = SessionId::from_bytes([1, 2, 3, 4, 5, 6, 7, 8]);
    let remote = SessionId::from_bytes([9, 10, 11, 12, 13, 14, 15, 16]);
    let ack = ControlPacket {
        opcode: Opcode::AckV1,
        key_id: 0,
        session_id: session,
        acks: Some(Acks {
            ids: vec![0, 1],
            session_id: remote,
        }),
        packet_id: None,
        payload: Vec::new(),
    };

    let wire = auth.wrap(&ack, 4, 0x6a87_eba5);
    let (decoded, _) = server_auth()
        .unwrap(&wire)
        .expect("the far end must accept what we send");

    assert_eq!(decoded, ack);
}

#[test]
fn a_control_packet_round_trips_with_its_tls_payload() {
    let auth = client_auth();
    let packet = ControlPacket {
        opcode: Opcode::ControlV1,
        key_id: 0,
        session_id: SessionId::from_bytes([1, 2, 3, 4, 5, 6, 7, 8]),
        acks: Some(Acks {
            ids: vec![0],
            session_id: SessionId::from_bytes([9, 10, 11, 12, 13, 14, 15, 16]),
        }),
        packet_id: Some(1),
        payload: b"\x16\x03\x01 a ClientHello would live here".to_vec(),
    };

    let wire = auth.wrap(&packet, 7, 0x6a87_eba5);
    let (decoded, _) = server_auth()
        .unwrap(&wire)
        .expect("the far end must accept what we send");

    assert_eq!(decoded, packet);
}

#[test]
fn a_truncated_packet_is_an_error_not_a_panic() {
    let full = bytes(RESET_1);
    for cut in 0..full.len() {
        assert!(
            server_auth().unwrap(&full[..cut]).is_err(),
            "a short packet must be refused, not indexed into ({cut} bytes)"
        );
    }
}
