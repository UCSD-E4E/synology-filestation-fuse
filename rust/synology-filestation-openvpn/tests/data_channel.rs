//! The data channel, checked at the byte level and across the two directions.
//!
//! Both ends answer a malformed data packet with silence — no error, no log
//! line the other side can see — so every rule here is one that would
//! otherwise be discovered as "the tunnel is up and nothing goes through it".

use synology_filestation_openvpn::{DataChannel, DataKeys, Error, KeyId, Opcode, PeerId, PING};

/// Distinguishable material in each of the four 64-byte slots, so a test that
/// picks the wrong one produces obviously wrong bytes rather than nearly right
/// ones.
fn expansion() -> Vec<u8> {
    let mut keys = Vec::with_capacity(256);
    keys.extend(std::iter::repeat_n(0x11, 64)); // slot 0 cipher
    keys.extend(std::iter::repeat_n(0x22, 64)); // slot 0 hmac
    keys.extend(std::iter::repeat_n(0x33, 64)); // slot 1 cipher
    keys.extend(std::iter::repeat_n(0x44, 64)); // slot 1 hmac
    keys
}

const PEER_ID: u32 = 0x00_be_ef;

fn client() -> DataChannel {
    DataChannel::new(
        DataKeys::for_client(&expansion()).expect("256 bytes"),
        Some(PeerId::new(PEER_ID).expect("fits in three bytes")),
        KeyId::FIRST,
    )
}

fn server() -> DataChannel {
    DataChannel::new(
        DataKeys::for_server(&expansion()).expect("256 bytes"),
        Some(PeerId::new(PEER_ID).expect("fits in three bytes")),
        KeyId::FIRST,
    )
}

fn iv(byte: u8) -> [u8; 16] {
    [byte; 16]
}

#[test]
fn what_the_client_sends_the_server_reads() {
    let mut client = client();
    let mut server = server();

    let datagram = client
        .encrypt_with_iv(b"a tunnelled packet", iv(1))
        .expect("encrypt");

    assert_eq!(
        server.decrypt(&datagram).expect("the far end reads it"),
        b"a tunnelled packet"
    );
}

#[test]
fn a_client_cannot_read_its_own_packets() {
    // The asymmetry is the mechanism, exactly as it is for `tls-auth`: each
    // direction has its own keys, and a client that could read its own
    // packets would be one whose slots were the wrong way round — a tunnel
    // where both ends encrypt happily and neither can read anything.
    let mut sender = client();
    let mut same_direction = client();

    let datagram = sender.encrypt_with_iv(b"outbound", iv(1)).expect("encrypt");

    assert_eq!(
        same_direction.decrypt(&datagram).unwrap_err(),
        Error::BadHmac,
        "the receive slot is the other one"
    );
}

#[test]
fn the_header_is_an_opcode_a_key_id_and_a_peer_id() {
    let mut client = DataChannel::new(
        DataKeys::for_client(&expansion()).expect("256 bytes"),
        Some(PeerId::new(0x00_12_34).expect("fits in three bytes")),
        KeyId::new(5).expect("five fits in three bits"),
    );

    let datagram = client.encrypt_with_iv(b"x", iv(1)).expect("encrypt");

    assert_eq!(
        datagram[0] >> 3,
        Opcode::DataV2 as u8,
        "the opcode occupies the top five bits"
    );
    assert_eq!(datagram[0] & 0x07, 5, "and the key id the bottom three");
    assert_eq!(
        &datagram[1..4],
        &[0x00, 0x12, 0x34],
        "three bytes of peer id, most significant first"
    );
}

#[test]
fn the_hmac_covers_the_iv_and_ciphertext_and_not_the_header() {
    // OpenVPN's comment where it prepends the header says the opcode is
    // authenticated. That is true of the AEAD path and not of this one, and
    // believing it would produce packets no server accepts.
    let mut client = client();
    let mut server = server();
    let mut datagram = client.encrypt_with_iv(b"payload", iv(1)).expect("encrypt");

    // Changing the peer id leaves the packet readable...
    datagram[3] ^= 0xff;
    assert!(
        server.decrypt(&datagram).is_ok(),
        "the header is outside the authenticated region"
    );

    // ...while changing anything from the IV onwards does not.
    let mut datagram = client.encrypt_with_iv(b"payload", iv(2)).expect("encrypt");
    let last = datagram.len() - 1;
    datagram[last] ^= 0x01;
    assert_eq!(server.decrypt(&datagram).unwrap_err(), Error::BadHmac);
}

#[test]
fn the_packet_id_travels_inside_the_encryption() {
    // Beside it would be the obvious place, and it is the wrong one: the four
    // bytes are prepended to the plaintext before the cipher runs. The
    // evidence is in the length — the ciphertext is a block longer than the
    // payload alone would need.
    let mut client = client();

    let datagram = client.encrypt_with_iv(&[0u8; 16], iv(1)).expect("encrypt");

    let ciphertext = &datagram[4 + 64 + 16..];
    assert_eq!(
        ciphertext.len(),
        32,
        "sixteen bytes of payload plus four of packet id, padded to two blocks"
    );
}

#[test]
fn each_packet_gets_the_next_id_and_a_replay_is_refused() {
    let mut client = client();
    let mut server = server();

    let first = client.encrypt_with_iv(b"one", iv(1)).expect("encrypt");
    let second = client.encrypt_with_iv(b"two", iv(2)).expect("encrypt");

    assert_eq!(server.decrypt(&first).expect("valid"), b"one");
    assert_eq!(server.decrypt(&second).expect("valid"), b"two");
    assert_eq!(
        server.decrypt(&first).unwrap_err(),
        Error::Replayed,
        "a captured data packet is as authentic as it ever was"
    );
}

#[test]
fn a_packet_from_another_tunnel_is_refused() {
    let mut client = client();
    let other_expansion: Vec<u8> = std::iter::repeat_n(0x99, 256).collect();
    let mut stranger = DataChannel::new(
        DataKeys::for_server(&other_expansion).expect("256 bytes"),
        Some(PeerId::new(PEER_ID).expect("fits in three bytes")),
        KeyId::FIRST,
    );

    let datagram = client
        .encrypt_with_iv(b"not for you", iv(1))
        .expect("encrypt");

    assert_eq!(stranger.decrypt(&datagram).unwrap_err(), Error::BadHmac);
}

#[test]
fn a_control_packet_is_not_mistaken_for_data() {
    let mut client = client();
    let mut server = server();
    let mut datagram = client.encrypt_with_iv(b"payload", iv(1)).expect("encrypt");
    datagram[0] = (Opcode::ControlV1 as u8) << 3;

    assert_eq!(
        server.decrypt(&datagram).unwrap_err(),
        Error::UnexpectedDataOpcode(Opcode::ControlV1),
        "it is refused for what it is, before any key is used on it"
    );
}

#[test]
fn a_truncated_packet_is_an_error_not_a_panic() {
    let mut client = client();
    let datagram = client.encrypt_with_iv(b"payload", iv(1)).expect("encrypt");

    for cut in 0..datagram.len() {
        let mut server = server();
        assert!(
            server.decrypt(&datagram[..cut]).is_err(),
            "{cut} bytes must be refused rather than indexed into"
        );
    }
}

#[test]
fn a_ping_survives_the_round_trip() {
    // The sixteen bytes a real OpenVPN sends to say "still here". The interop
    // test recognises these coming off the wire; this one pins that the
    // constant is what goes in and comes out.
    let mut client = client();
    let mut server = server();

    let datagram = client.encrypt_with_iv(&PING, iv(1)).expect("encrypt");

    assert_eq!(server.decrypt(&datagram).expect("valid"), PING);
}

#[test]
fn a_short_key_expansion_is_refused() {
    assert!(DataKeys::for_client(&[0u8; 255]).is_err());
    assert!(DataKeys::for_client(&[0u8; 256]).is_ok());
}

#[test]
fn a_peer_that_assigned_no_id_gets_the_shorter_form() {
    // Point-to-point OpenVPN negotiates no peer id, and both ends then speak
    // `P_DATA_V1` — the same packet without the three bytes. A client that
    // could only produce V2 would be talking to itself.
    let mut client = DataChannel::new(
        DataKeys::for_client(&expansion()).expect("256 bytes"),
        None,
        KeyId::FIRST,
    );
    let mut server = DataChannel::new(
        DataKeys::for_server(&expansion()).expect("256 bytes"),
        None,
        KeyId::FIRST,
    );

    let datagram = client
        .encrypt_with_iv(b"no peer id here", iv(1))
        .expect("encrypt");

    assert_eq!(datagram[0] >> 3, Opcode::DataV1 as u8);
    assert_eq!(
        server.decrypt(&datagram).expect("the far end reads it"),
        b"no peer id here"
    );
}

#[test]
fn a_peer_id_wider_than_its_field_cannot_be_built() {
    // Three bytes on the wire. Masking a wider value would produce a valid
    // packet addressed to a different client, which the server drops without
    // a word — the same failure `KeyId` exists to prevent, one field over.
    assert_eq!(PeerId::new(0x00ff_ffff).map(PeerId::get), Some(0x00ff_ffff));
    assert_eq!(PeerId::new(0x0100_0000), None);
    assert_eq!(PeerId::new(u32::MAX), None);
}

#[test]
fn every_packet_gets_a_different_iv() {
    // CBC needs a fresh, unpredictable IV per packet, and nothing about a
    // supplied one can be checked — so the ordinary path generates it.
    let mut client = client();

    let first = client.encrypt(b"same payload").expect("encrypt");
    let second = client.encrypt(b"same payload").expect("encrypt");

    let iv = |packet: &[u8]| packet[4 + 64..4 + 64 + 16].to_vec();
    assert_ne!(iv(&first), iv(&second));
}

#[test]
fn a_data_packet_for_another_key_says_so_rather_than_crying_forgery() {
    // After a renegotiation the peer sends under a new key id. Checking the
    // HMAC with the key we still hold would fail, and "packet is not
    // authentic" reads as an attack rather than the ordinary key rotation it
    // is — which is the difference between investigating a break-in and
    // implementing a feature.
    let mut client = client();
    let mut datagram = client
        .encrypt_with_iv(b"after a rotation", iv(1))
        .expect("encrypt");
    datagram[0] = ((Opcode::DataV2 as u8) << 3) | 1;

    let mut server = server();
    assert_eq!(
        server.decrypt(&datagram).unwrap_err(),
        Error::OtherKeyId(KeyId::new(1).expect("one fits"), KeyId::FIRST)
    );
}
