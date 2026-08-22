//! The key-exchange message, field by field.
//!
//! The layout is checked at fixed offsets rather than by round-tripping
//! through our own decoder, because agreeing with ourselves is not the
//! property that matters: the reader is a real OpenVPN, and it says nothing at
//! all when a field is a byte out of place.

use synology_filestation_openvpn::{
    ClientKeyMethod2, Error, KeySource2, ServerKeyMethod2, ServerMessage,
};
use zeroize::Zeroizing;

fn source() -> KeySource2 {
    KeySource2 {
        pre_master: [0xa1; 48],
        client_random1: [0xb2; 32],
        client_random2: [0xc3; 32],
        server_random1: [0; 32],
        server_random2: [0; 32],
    }
}

fn password() -> Zeroizing<String> {
    Zeroizing::new("hunter2".to_string())
}

#[test]
fn the_client_message_has_the_layout_openvpn_reads() {
    let source = source();
    let password = password();
    let encoded = ClientKeyMethod2 {
        source: &source,
        options: "V4",
        username: "ad-user",
        password: &password,
        peer_info: "IV_VER=2.5.11\n",
    }
    .encode()
    .expect("every field fits");

    assert_eq!(&encoded[0..4], &[0, 0, 0, 0], "a literal zero first");
    assert_eq!(encoded[4], 2, "key method 2");
    assert_eq!(&encoded[5..53], &[0xa1; 48], "the pre-master");
    assert_eq!(&encoded[53..85], &[0xb2; 32], "random1");
    assert_eq!(&encoded[85..117], &[0xc3; 32], "random2");

    // Then the four strings, each a length that counts its own NUL.
    assert_eq!(
        &encoded[117..119],
        &[0, 3],
        "\"V4\" is three bytes with its NUL"
    );
    assert_eq!(&encoded[119..122], b"V4\0");
    assert_eq!(&encoded[122..124], &[0, 8]);
    assert_eq!(&encoded[124..132], b"ad-user\0");
    assert_eq!(&encoded[132..134], &[0, 8]);
    assert_eq!(&encoded[134..142], b"hunter2\0");
    assert_eq!(&encoded[142..144], &[0, 15], "fourteen bytes and its NUL");
    assert_eq!(&encoded[144..], b"IV_VER=2.5.11\n\0");
}

#[test]
fn an_absent_credential_is_a_zero_length_not_a_lone_nul() {
    // OpenVPN writes these through `write_empty_string`, which puts a length
    // of zero and stops. A length of one and a NUL is the obvious alternative
    // and would shift every field after it.
    let source = source();
    let empty = Zeroizing::new(String::new());
    let encoded = ClientKeyMethod2 {
        source: &source,
        options: "",
        username: "",
        password: &empty,
        peer_info: "",
    }
    .encode()
    .expect("every field fits");

    assert_eq!(encoded.len(), 4 + 1 + 48 + 32 + 32 + 2 * 4);
    assert_eq!(&encoded[117..], &[0, 0, 0, 0, 0, 0, 0, 0]);
}

/// A server reply, built the way a server builds one: no pre-master, and the
/// three trailing strings it always writes even when they are empty.
fn server_reply(options: &str) -> Vec<u8> {
    let mut out = server_reply_without_trailing_fields(options);
    out.extend_from_slice(&[0, 0]); // username
    out.extend_from_slice(&[0, 0]); // password
    out.extend_from_slice(&[0, 0]); // peer info
    out
}

/// The same, stopping after the options — a peer that says less than it might.
fn server_reply_without_trailing_fields(options: &str) -> Vec<u8> {
    let mut out = vec![0, 0, 0, 0, 2];
    out.extend_from_slice(&[0xd4; 32]);
    out.extend_from_slice(&[0xe5; 32]);
    let len = options.len() + 1;
    out.extend_from_slice(&(len as u16).to_be_bytes());
    out.extend_from_slice(options.as_bytes());
    out.push(0);
    out
}

#[test]
fn the_server_reply_carries_two_randoms_and_no_pre_master() {
    let (decoded, used) =
        ServerKeyMethod2::decode(&server_reply("V4,cipher AES-256-CBC")).expect("valid");

    assert_eq!(decoded.random1, [0xd4; 32]);
    assert_eq!(decoded.random2, [0xe5; 32]);
    assert_eq!(decoded.options, "V4,cipher AES-256-CBC");
    assert_eq!(
        used,
        server_reply("V4,cipher AES-256-CBC").len(),
        "all of it"
    );
}

#[test]
fn a_half_arrived_reply_says_not_yet_rather_than_no() {
    // TLS is a stream, so a reader can hold part of a message. Every prefix
    // has to be distinguishable from a message that will never parse,
    // otherwise the session is abandoned for arriving in two pieces.
    let whole = server_reply("V4");

    for cut in 0..whole.len() {
        let error = ServerKeyMethod2::decode(&whole[..cut]).unwrap_err();
        assert!(
            matches!(error, Error::Truncated { .. }),
            "{cut} bytes in: {error}"
        );
    }
    assert!(ServerKeyMethod2::decode(&whole).is_ok());
}

#[test]
fn another_key_method_is_refused_by_name() {
    let mut reply = server_reply("V4");
    reply[4] = 1;

    assert_eq!(
        ServerKeyMethod2::decode(&reply).unwrap_err(),
        Error::UnsupportedKeyMethod(1),
        "key method 1 was removed from OpenVPN, and we never spoke it"
    );
}

#[test]
fn an_empty_options_string_is_read_as_empty() {
    let mut reply = vec![0, 0, 0, 0, 2];
    reply.extend_from_slice(&[0xd4; 32]);
    reply.extend_from_slice(&[0xe5; 32]);
    reply.extend_from_slice(&[0, 0]); // no options
    reply.extend_from_slice(&[0, 0]); // and no username,
    reply.extend_from_slice(&[0, 0]); // password
    reply.extend_from_slice(&[0, 0]); // or peer info

    assert_eq!(
        ServerKeyMethod2::decode(&reply).expect("valid").0.options,
        ""
    );
}

#[test]
fn the_fields_we_do_not_use_are_still_consumed() {
    // The server writes a username, a password and a peer-info string after
    // its options. We want none of them, but they belong to this message: a
    // reader that stops at the options leaves three empty strings behind, and
    // the next read finds six zero bytes where a header should be — which
    // looks exactly like a key method numbered zero.
    let mut reply = server_reply_without_trailing_fields("V4");
    reply.extend_from_slice(&[0, 0]); // empty username
    reply.extend_from_slice(&[0, 0]); // empty password
    reply.extend_from_slice(&[0, 5]);
    reply.extend_from_slice(b"IV_X\0"); // peer info, five bytes with its NUL
    let whole = reply.len();

    let (_, used) = ServerKeyMethod2::decode(&reply).expect("valid");

    assert_eq!(used, whole, "all of it, including the fields we ignore");
}

#[test]
fn a_message_that_stops_after_its_options_has_not_finished_arriving() {
    // The tempting reading is "this peer sent fewer fields". On a TLS stream
    // there is no frame to tell that apart from "the rest is still coming",
    // and choosing wrongly puts the boundary of the *next* message in the
    // wrong place. Every real OpenVPN writes all three, so waiting is right.
    let reply = server_reply_without_trailing_fields("V4");

    assert!(matches!(
        ServerKeyMethod2::decode(&reply),
        Err(Error::Truncated { .. })
    ));
}

#[test]
fn a_field_too_long_to_describe_is_refused_rather_than_truncated() {
    // The length is a `u16`. Casting a longer one would wrap, and the message
    // would then parse into something else entirely — every field after the
    // wrapped one shifted, and no complaint from either end until the session
    // failed for an unrelated-looking reason.
    let source = source();
    let password = password();
    let enormous = "x".repeat(u16::MAX as usize);

    let error = ClientKeyMethod2 {
        source: &source,
        options: "V4",
        username: &enormous,
        password: &password,
        peer_info: "",
    }
    .encode()
    .unwrap_err();

    assert_eq!(
        error,
        Error::FieldTooLong {
            context: "the username"
        },
        "and it says which field, so a caller knows what to shorten"
    );
}

#[test]
fn a_refusal_is_read_as_words_rather_than_as_key_material() {
    // The likeliest thing to go wrong is a mistyped password, and the server
    // answers that in English rather than by failing the exchange. Decoding it
    // as a key method reads "AUTH" as the leading zero and the underscore as
    // the method number, so the person at the keyboard is told the peer
    // offered key method 95.
    let mut message = b"AUTH_FAILED,session expired".to_vec();
    message.push(0);

    let (decoded, used) = ServerMessage::decode(&message).expect("readable");

    assert_eq!(
        decoded,
        ServerMessage::Control("AUTH_FAILED,session expired".to_string())
    );
    assert_eq!(used, message.len(), "the NUL is part of the message");
}

#[test]
fn key_material_and_control_messages_are_told_apart_by_their_first_bytes() {
    // A key method begins with four zero bytes; a control message begins with
    // text. Nothing else is needed to tell them apart, which is what makes the
    // check cheap enough to do before every decode.
    let reply = server_reply("V4");
    let (decoded, used) = ServerMessage::decode(&reply).expect("readable");

    assert!(matches!(decoded, ServerMessage::KeyMethod2(_)));
    assert_eq!(used, reply.len());
}

#[test]
fn what_follows_a_reply_in_the_same_flight_is_left_alone() {
    // The server can put more behind its key material — a push reply arrives
    // this way. The consumed length is what lets a caller keep the rest
    // instead of throwing away bytes TLS will not hand over twice.
    let mut flight = server_reply("V4");
    let reply_len = flight.len();
    flight.extend_from_slice(b"PUSH_REPLY,route 10.90.24.0\0");

    let (_, used) = ServerMessage::decode(&flight).expect("readable");

    assert_eq!(used, reply_len, "only the key method was consumed");
    let (next, _) = ServerMessage::decode(&flight[used..]).expect("and the rest still reads");
    assert!(matches!(next, ServerMessage::Control(_)));
}
