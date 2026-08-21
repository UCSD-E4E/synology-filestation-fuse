//! The pseudo-random function, and the keys it produces.
//!
//! Two independent things are checked here. The PRF itself is pinned against
//! OpenSSL, because a key derivation that is subtly wrong produces keys that
//! look perfectly random and decrypt nothing — there is no partial credit and
//! no error message, so the only useful test is agreement with the
//! implementation the far end is built on.
//!
//! What sits on top is OpenVPN's own arrangement of it, and that is the reason
//! this client can exist at all: OpenVPN 2.5 derives data-channel keys from
//! material it exchanges *inside* the TLS session, not from the TLS master
//! secret. A TLS library therefore needs to expose nothing beyond the session
//! itself, which is why rustls is enough.

use synology_filestation_openvpn::{key_expansion, tls1_prf, KeySource2, SessionId};

/// Generated with the implementation the server is built on, so that this
/// agrees with something other than itself:
///
/// ```text
/// openssl kdf -kdfopt digest:MD5-SHA1 -kdfopt hexsecret:<secret> \
///             -kdfopt hexseed:<seed> -keylen <n> -binary TLS1-PRF
/// ```
///
/// The secret is bytes 0..48 and the seed is bytes 100..150, both ascending.
const PRF_48: &str = concat!(
    "0b8ba0bc027ba8546865ed57e65a7d3f43ae495232b7eb49",
    "c654f363fa4db2da00957efb5ab2daf1946c25488d0fcce7",
);

/// The same secret and seed, asked for enough output to need several rounds —
/// which is where an off-by-one in the iteration shows up.
const PRF_256: &str = concat!(
    "0b8ba0bc027ba8546865ed57e65a7d3f43ae495232b7eb49c654f363fa4db2da",
    "00957efb5ab2daf1946c25488d0fcce7eab893e3ea1036cbabe06eac24e7f255",
    "5376952052346065cbedda57c957ae4854150a45791f4e6ecb614832575f6f91",
    "8eca57773221a122bb4593896beed06837b554d61991dd0a2183d7de94b25ee4",
    "baccfb16e381d2619a5af7a43a27c469cae2529e8c77719062ab4daba28998a2",
    "d0327e0fc425a76aa412d8a098f44190a12301c512066065293c5f2eb2efe60d",
    "2da8ac446a2e76d7ea28e3bbbe1ee7d91ad4140c09b2ff104c5376d7d280709d",
    "4a78378e68243397b6a6d40b13e3f9410dfeff3eaa6d1dddcee427e317c443a8",
);

fn secret() -> Vec<u8> {
    (0..48u8).collect()
}

fn seed() -> Vec<u8> {
    (100..150u8).collect()
}

#[test]
fn the_prf_agrees_with_openssl() {
    let mut out = vec![0u8; 48];
    tls1_prf(&secret(), &seed(), &mut out);

    assert_eq!(hex::encode(&out), PRF_48);
}

#[test]
fn the_prf_agrees_with_openssl_over_many_rounds() {
    // 256 bytes is what a key expansion actually asks for, and it takes
    // several iterations of both halves to produce.
    let mut out = vec![0u8; 256];
    tls1_prf(&secret(), &seed(), &mut out);

    assert_eq!(hex::encode(&out), PRF_256);
}

#[test]
fn a_shorter_request_is_a_prefix_of_a_longer_one() {
    // The PRF is a stream: asking for less gives the beginning of the same
    // bytes. If it were not, truncation would silently change every key.
    let mut long = vec![0u8; 100];
    tls1_prf(&secret(), &seed(), &mut long);

    for len in [1usize, 15, 16, 17, 31, 64, 99] {
        let mut short = vec![0u8; len];
        tls1_prf(&secret(), &seed(), &mut short);
        assert_eq!(short, long[..len], "asking for {len} bytes");
    }
}

#[test]
fn the_seed_is_part_of_the_output() {
    let mut with = vec![0u8; 32];
    tls1_prf(&secret(), &seed(), &mut with);

    let mut without = vec![0u8; 32];
    let mut other = seed();
    other[0] ^= 1;
    tls1_prf(&secret(), &other, &mut without);

    assert_ne!(with, without, "one flipped bit changes everything");
}

#[test]
fn key_expansion_produces_four_keys_from_both_ends_material() {
    // The shape of what comes out: two directions, each with a cipher key and
    // an HMAC key, in the order the static key file also uses.
    let source = KeySource2 {
        pre_master: [1u8; 48],
        client_random1: [2u8; 32],
        client_random2: [3u8; 32],
        server_random1: [4u8; 32],
        server_random2: [5u8; 32],
    };
    let client_sid = SessionId::from_bytes([6; 8]);
    let server_sid = SessionId::from_bytes([7; 8]);

    let keys = key_expansion(&source, client_sid, server_sid);

    assert_eq!(keys.len(), 256, "four 64-byte keys");
    assert_ne!(
        &keys[..64],
        &keys[128..192],
        "the two directions do not share a cipher key"
    );
}

#[test]
fn every_input_changes_the_keys() {
    // Each of these is mixed in at a different point — two of them only in the
    // second call, and the session ids only in its seed. A derivation that
    // quietly ignored one would still produce believable keys, and would fail
    // only as "decryption failed" much later, so each is pinned.
    let base = KeySource2 {
        pre_master: [1u8; 48],
        client_random1: [2u8; 32],
        client_random2: [3u8; 32],
        server_random1: [4u8; 32],
        server_random2: [5u8; 32],
    };
    let client_sid = SessionId::from_bytes([6; 8]);
    let server_sid = SessionId::from_bytes([7; 8]);
    let expected = key_expansion(&base, client_sid, server_sid);

    let mut changed = base.clone();
    changed.pre_master[0] ^= 1;
    assert_ne!(key_expansion(&changed, client_sid, server_sid), expected);

    let mut changed = base.clone();
    changed.client_random1[0] ^= 1;
    assert_ne!(key_expansion(&changed, client_sid, server_sid), expected);

    let mut changed = base.clone();
    changed.server_random1[0] ^= 1;
    assert_ne!(key_expansion(&changed, client_sid, server_sid), expected);

    let mut changed = base.clone();
    changed.client_random2[0] ^= 1;
    assert_ne!(key_expansion(&changed, client_sid, server_sid), expected);

    let mut changed = base.clone();
    changed.server_random2[0] ^= 1;
    assert_ne!(key_expansion(&changed, client_sid, server_sid), expected);

    assert_ne!(
        key_expansion(&base, SessionId::from_bytes([9; 8]), server_sid),
        expected,
        "the client session id is in the seed"
    );
    assert_ne!(
        key_expansion(&base, client_sid, SessionId::from_bytes([9; 8])),
        expected,
        "and so is the server's"
    );
}

#[test]
fn the_session_ids_are_not_interchangeable() {
    // They go into the seed in a fixed order — client first. Swapping them is
    // exactly the mistake a client and a server would make in opposite
    // directions, and it produces two sets of keys that never meet.
    let source = KeySource2 {
        pre_master: [1u8; 48],
        client_random1: [2u8; 32],
        client_random2: [3u8; 32],
        server_random1: [4u8; 32],
        server_random2: [5u8; 32],
    };
    let client_sid = SessionId::from_bytes([6; 8]);
    let server_sid = SessionId::from_bytes([7; 8]);

    assert_ne!(
        key_expansion(&source, client_sid, server_sid),
        key_expansion(&source, server_sid, client_sid)
    );
}
