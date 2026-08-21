//! The key-exchange message, field by field.
//!
//! The layout is checked at fixed offsets rather than by round-tripping
//! through our own decoder, because agreeing with ourselves is not the
//! property that matters: the reader is a real OpenVPN, and it says nothing at
//! all when a field is a byte out of place.

use synology_filestation_openvpn::{ClientKeyMethod2, Error, KeySource2, ServerKeyMethod2};
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

/// A server reply, built the way a server builds it: no pre-master.
fn server_reply(options: &str) -> Vec<u8> {
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
    let decoded = ServerKeyMethod2::decode(&server_reply("V4,cipher AES-256-CBC")).expect("valid");

    assert_eq!(decoded.random1, [0xd4; 32]);
    assert_eq!(decoded.random2, [0xe5; 32]);
    assert_eq!(decoded.options, "V4,cipher AES-256-CBC");
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
    reply.extend_from_slice(&[0, 0]);

    assert_eq!(ServerKeyMethod2::decode(&reply).expect("valid").options, "");
}

#[test]
fn trailing_bytes_are_left_for_the_fields_we_do_not_read() {
    // The server also sends username, password and peer-info fields, all
    // usually empty. We stop at the options string, so whatever follows must
    // not make the message look malformed.
    let mut reply = server_reply("V4");
    reply.extend_from_slice(&[0, 0, 0, 0, 0, 6]);
    reply.extend_from_slice(b"IV_X\0");

    assert!(ServerKeyMethod2::decode(&reply).is_ok());
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
