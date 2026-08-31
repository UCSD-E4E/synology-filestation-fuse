//! The two fields with a range smaller than their type, and what happens at
//! the edge of it.
//!
//! Both are places where a silent truncation would produce a packet that is
//! well-formed enough to send and wrong enough to be dropped without comment —
//! the failure mode this whole crate is arranged to avoid.

use synology_filestation_openvpn::{
    Acks, ControlPacket, Error, KeyDirection, KeyId, Opcode, SessionId, StaticKey, TlsAuth,
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

fn key() -> StaticKey {
    StaticKey::from_hex(TA_KEY_HEX).expect("test vector")
}

fn session(byte: u8) -> SessionId {
    SessionId::from_bytes([byte; 8])
}

#[test]
fn a_key_id_wider_than_three_bits_cannot_be_built() {
    // The opcode occupies the top five bits of the first byte, so the key id
    // has three. Masking a wider value would put a *different* key id on the
    // wire than the caller asked for, and the packet would be answered by
    // silence rather than by a complaint.
    for value in 0..=7u8 {
        assert_eq!(KeyId::new(value).map(KeyId::get), Some(value));
    }
    assert_eq!(KeyId::new(8), None);
    assert_eq!(KeyId::new(255), None);
}

#[test]
fn key_ids_recycle_to_one_so_that_zero_still_means_first() {
    // OpenVPN increments the key id on each renegotiation and wraps at 7 —
    // back to 1, not to 0, because 0 is how both ends recognise the original
    // key. A tunnel that outlives `reneg-sec` walks this whole cycle.
    let mut id = KeyId::FIRST;
    let walked: Vec<u8> = (0..9)
        .map(|_| {
            let current = id.get();
            id = id.next();
            current
        })
        .collect();

    assert_eq!(walked, vec![0, 1, 2, 3, 4, 5, 6, 7, 1]);
}

#[test]
fn at_most_eight_acks_fit_in_a_packet() {
    let ids: Vec<u32> = (0..8).collect();
    assert!(
        Acks::new(ids, session(9)).is_ok(),
        "eight is what RELIABLE_ACK_SIZE allows"
    );

    let too_many: Vec<u32> = (0..9).collect();
    assert_eq!(
        Acks::new(too_many, session(9)).unwrap_err(),
        Error::TooManyAcks { count: 9 },
        "a ninth would either be dropped or corrupt the count byte"
    );
}

#[test]
fn a_packet_claiming_more_acks_than_can_exist_is_refused() {
    // Built by hand rather than through `Acks`, which is what makes this worth
    // testing: no honest peer sends it, so the only way to see one is from a
    // peer that is not honest, and the decoder is all that stands between it
    // and the rest of the client.
    let mut tail = vec![9u8]; // an ack count of nine
    for id in 0..9u32 {
        tail.extend_from_slice(&id.to_be_bytes());
    }
    tail.extend_from_slice(session(9).as_bytes());
    tail.extend_from_slice(&0u32.to_be_bytes());

    let datagram = sign_as_client(Opcode::ControlV1, session(1), &tail, 1, 0);

    assert_eq!(
        TlsAuth::new(&key(), KeyDirection::Normal)
            .unwrap(&datagram)
            .unwrap_err(),
        Error::TooManyAcks { count: 9 },
        "the far end refuses this too, and matching it keeps our idea of a valid packet the same as everybody else's"
    );
}

#[test]
fn eight_acks_still_round_trip() {
    // The boundary from the other side: the largest legal packet must survive,
    // or the limit is a bug rather than a limit.
    let packet = ControlPacket {
        opcode: Opcode::ControlV1,
        key_id: KeyId::FIRST,
        session_id: session(1),
        acks: Some(Acks::new((0..8).collect(), session(9)).expect("eight is legal")),
        packet_id: Some(3),
        payload: Vec::new(),
    };

    let wire = TlsAuth::new(&key(), KeyDirection::Inverse).wrap(&packet, 1, 0);
    let (decoded, _) = TlsAuth::new(&key(), KeyDirection::Normal)
        .unwrap(&wire)
        .expect("a full ack array is still a legal packet");

    assert_eq!(decoded, packet);
}

/// Sign an arbitrary tail the way a client would.
///
/// This deliberately duplicates `TlsAuth::wrap`, because its whole purpose is
/// to build packets `wrap` cannot: the crate's types refuse to represent them,
/// which is the property under test.
fn sign_as_client(
    opcode: Opcode,
    session_id: SessionId,
    tail: &[u8],
    packet_id: u32,
    net_time: u32,
) -> Vec<u8> {
    use hmac::digest::KeyInit;
    use hmac::{Hmac, Mac};
    use sha2::Sha512;

    // Slot 1's HMAC half — the client's, per `key-direction 1`.
    let key_bytes = hex::decode(TA_KEY_HEX).expect("test vector");
    let hmac_key = &key_bytes[192..256];

    let mut prefix = vec![(opcode as u8) << 3];
    prefix.extend_from_slice(session_id.as_bytes());

    let mut signed = Vec::new();
    signed.extend_from_slice(&packet_id.to_be_bytes());
    signed.extend_from_slice(&net_time.to_be_bytes());
    signed.extend_from_slice(&prefix);
    signed.extend_from_slice(tail);

    let mut mac = <Hmac<Sha512>>::new_from_slice(hmac_key).expect("any key length");
    mac.update(&signed);

    let mut wire = prefix;
    wire.extend_from_slice(&mac.finalize().into_bytes());
    wire.extend_from_slice(&packet_id.to_be_bytes());
    wire.extend_from_slice(&net_time.to_be_bytes());
    wire.extend_from_slice(tail);
    wire
}
