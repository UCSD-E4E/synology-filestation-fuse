//! Reading `ta.key` — as `openvpn --genkey` writes it, and as a `.ovpn`
//! inlines it.
//!
//! Both forms have to work from one parser: the role that publishes
//! `e4e-nas-vpn.ovpn` embeds the generated file verbatim between `<tls-auth>`
//! tags, so the block a client reads is the file with markup around it.

use synology_filestation_openvpn::{Error, StaticKey, STATIC_KEY_LEN};

/// 256 bytes of key material, written out the way the file does: 16 lines of
/// 32 hex digits. The value is arbitrary — byte `i` is `i` — because the
/// question here is the framing, not the bytes.
fn key_body() -> String {
    let hex: String = (0..STATIC_KEY_LEN)
        .map(|i| format!("{:02x}", i as u8))
        .collect();
    hex.as_bytes()
        .chunks(32)
        .map(|line| std::str::from_utf8(line).expect("hex is ascii"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// What `openvpn --genkey secret ta.key` leaves on disk.
fn generated_file() -> String {
    format!(
        "#\n# 2048 bit OpenVPN static key\n#\n-----BEGIN OpenVPN Static key V1-----\n{}\n-----END OpenVPN Static key V1-----\n",
        key_body()
    )
}

#[test]
fn a_generated_key_file_parses() {
    assert!(StaticKey::parse(&generated_file()).is_ok());
}

#[test]
fn the_same_key_inlined_in_a_dot_ovpn_parses_identically() {
    let inlined = format!(
        "remote e4e-nas.ucsd.edu 1194\nkey-direction 1\n<tls-auth>\n{}</tls-auth>\n",
        generated_file()
    );

    let from_block = StaticKey::parse(&inlined).expect("the inlined form is the file");
    let from_file = StaticKey::parse(&generated_file()).expect("the file is the file");

    // No `PartialEq` on a key — comparing them is exactly the operation the
    // type exists to make awkward — so compare through what they produce.
    assert_eq!(
        signature_with(&from_block),
        signature_with(&from_file),
        "the same key material either way"
    );
}

#[test]
fn a_key_of_the_wrong_length_is_refused_with_its_length() {
    let short = format!(
        "-----BEGIN OpenVPN Static key V1-----\n{}\n-----END OpenVPN Static key V1-----\n",
        "00".repeat(128)
    );

    assert_eq!(
        StaticKey::parse(&short).unwrap_err(),
        Error::KeyLength { actual: 128 },
        "half a key is not a key, and the error should say how short it was"
    );
}

#[test]
fn a_body_that_is_not_hex_is_refused() {
    let bad = format!(
        "-----BEGIN OpenVPN Static key V1-----\n{}\n-----END OpenVPN Static key V1-----\n",
        "zz".repeat(STATIC_KEY_LEN)
    );

    assert_eq!(StaticKey::parse(&bad).unwrap_err(), Error::KeyNotHex);
}

#[test]
fn a_config_with_no_key_block_says_so() {
    assert_eq!(
        StaticKey::parse("remote e4e-nas.ucsd.edu 1194\nkey-direction 1\n").unwrap_err(),
        Error::KeyMissing,
        "a .ovpn without <tls-auth> is a different failure from a corrupt one"
    );
}

#[test]
fn a_key_never_prints_itself() {
    let rendered = format!("{:?}", StaticKey::parse(&generated_file()).expect("valid"));

    assert!(
        !rendered.contains("0001020304"),
        "no key material in Debug output"
    );
    assert_eq!(rendered, "StaticKey(<redacted>)");
}

/// Sign a fixed packet so two keys can be compared by what they do.
fn signature_with(key: &StaticKey) -> Vec<u8> {
    use synology_filestation_openvpn::{ControlPacket, KeyDirection, Opcode, SessionId, TlsAuth};

    TlsAuth::new(key, KeyDirection::Inverse).wrap(
        &ControlPacket {
            opcode: Opcode::ControlHardResetClientV2,
            key_id: 0,
            session_id: SessionId::from_bytes([0; 8]),
            acks: None,
            packet_id: Some(0),
            payload: Vec::new(),
        },
        1,
        0,
    )
}
