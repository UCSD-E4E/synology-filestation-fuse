//! The session state machine, end to end, against a peer in this process.
//!
//! These are the branches the interop tests cannot reach. A point-to-point
//! `openvpn` never assigns a peer id, never answers a `PUSH_REQUEST`, and
//! cannot be told to refuse a password or to answer late — so the parts of the
//! session that deal with those had no coverage at all, and one of them held a
//! bug that would only have shown up against the NAS.
//!
//! They also run everywhere. The interop tests need the `openvpn` binary and
//! so run on Linux only; this peer is `rustls` and a few hundred lines, so
//! Windows and macOS check the same behaviour.

mod common;

use std::time::{Duration, Instant};

use common::{exchange, Answer, FakeServer, TA_KEY_HEX};
use synology_filestation_openvpn::{Error, Session, SessionConfig, StaticKey};

fn session_against(server: &FakeServer) -> Session {
    let config = SessionConfig::new(
        server.ca_pem.clone(),
        "localhost",
        StaticKey::from_hex(TA_KEY_HEX).expect("test vector"),
    );
    Session::new(config).expect("a client")
}

#[test]
fn a_whole_handshake_ends_with_keys_and_a_push_reply() {
    let mut server = FakeServer::new(Answer::KeyMaterialThen(
        "PUSH_REPLY,ifconfig 10.90.24.6 255.255.255.0,peer-id 4,cipher AES-256-CBC,ping 10"
            .to_string(),
    ));
    let mut session = session_against(&server);

    exchange(&mut session, &mut server, Instant::now()).expect("nothing to refuse");

    assert!(session.is_established(), "the key exchange finished");
    assert_eq!(session.keys().map(<[u8]>::len), Some(256));

    let reply = session.push_reply().expect("the server answered");
    assert_eq!(reply.peer_id.map(|id| id.get()), Some(4));
    assert_eq!(reply.ping, Some(Duration::from_secs(10)));
}

#[test]
fn a_push_reply_that_arrives_later_is_still_read() {
    // This is the one. The reply cannot share a flight with the key material —
    // the server has not seen the request yet when it sends the keys — so it
    // always arrives in a later datagram. Draining rustls used to be gated on
    // the key-material phase, which meant nothing ever refilled the buffer
    // afterwards and the reply sat in it, decrypted and unread.
    //
    // Everything downstream then silently did not happen, and the interop
    // tests went green throughout, because their peer has no push exchange at
    // all.
    let mut server = FakeServer::new(Answer::KeyMaterialThen("PUSH_REPLY,peer-id 9".to_string()));
    let mut session = session_against(&server);

    exchange(&mut session, &mut server, Instant::now()).expect("nothing to refuse");

    assert_eq!(
        session.push_reply().and_then(|reply| reply.peer_id),
        synology_filestation_openvpn::PeerId::new(9),
        "the reply arrived in its own datagram and was read"
    );
}

#[test]
fn a_refused_password_says_so() {
    // The likeliest failure there is, and the one a user meets. The server
    // answers the key exchange with words instead of key material.
    let mut server = FakeServer::new(Answer::Refuse("AUTH_FAILED".to_string()));
    let mut session = session_against(&server);

    let error = exchange(&mut session, &mut server, Instant::now()).unwrap_err();

    assert_eq!(error, Error::AuthFailed(String::new()));
    assert!(!session.is_established());
}

#[test]
fn a_refusal_carrying_a_reason_keeps_it() {
    let mut server = FakeServer::new(Answer::Refuse(
        "AUTH_FAILED,SESSION: your session has expired".to_string(),
    ));
    let mut session = session_against(&server);

    let error = exchange(&mut session, &mut server, Instant::now()).unwrap_err();

    assert_eq!(
        error,
        Error::AuthFailed(",SESSION: your session has expired".to_string()),
        "whatever the server said is worth passing on"
    );
}

#[test]
fn a_cipher_we_cannot_speak_stops_the_session_rather_than_the_tunnel() {
    // e4e-nas runs `encryption AUTO`, so this is a real possibility rather
    // than a hypothetical: the alternative to refusing is a tunnel that comes
    // up, encrypts with the wrong algorithm, and carries nothing.
    let mut server = FakeServer::new(Answer::KeyMaterialThen(
        "PUSH_REPLY,peer-id 1,cipher AES-256-GCM".to_string(),
    ));
    let mut session = session_against(&server);

    let error = exchange(&mut session, &mut server, Instant::now()).unwrap_err();

    assert_eq!(error, Error::UnsupportedCipher("AES-256-GCM".to_string()));
}

#[test]
fn a_server_that_never_answers_the_request_leaves_the_session_usable() {
    // A point-to-point peer does exactly this. It is not a failure: the keys
    // exist and the tunnel works, there is simply no peer id, so packets take
    // the shorter form.
    let mut server = FakeServer::new(Answer::KeyMaterialOnly);
    let mut session = session_against(&server);

    exchange(&mut session, &mut server, Instant::now()).expect("silence is not an error");

    assert!(session.is_established());
    assert!(session.keys().is_some());
    assert_eq!(session.push_reply(), None);
}

#[test]
fn the_keys_both_ends_derive_are_not_the_ones_either_end_sent() {
    // A session's keys come out of the PRF over material from both ends, so
    // two sessions with the same server produce different keys. If they did
    // not, every session would share a keystream with every other.
    let mut first_server = FakeServer::new(Answer::KeyMaterialOnly);
    let mut first = session_against(&first_server);
    exchange(&mut first, &mut first_server, Instant::now()).expect("valid");

    let mut second_server = FakeServer::new(Answer::KeyMaterialOnly);
    let mut second = session_against(&second_server);
    exchange(&mut second, &mut second_server, Instant::now()).expect("valid");

    assert_ne!(
        first.keys().expect("keys"),
        second.keys().expect("keys"),
        "two sessions, two sets of keys"
    );
}
