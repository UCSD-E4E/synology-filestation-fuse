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

use common::{exchange, exchange_lossy, Answer, FakeServer, TA_KEY_HEX};
use synology_filestation_openvpn::{Error, Session, SessionConfig, StaticKey, PING};

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
fn a_server_that_has_not_answered_yet_is_not_a_failure_yet() {
    // Silence is ordinary at first — the server may not be ready. The keys
    // exist and the session is established; what it does not have is a
    // tunnel, because the peer id that makes data packets addressable comes
    // in the answer.
    //
    // A point-to-point openvpn stays here forever, which is why the interop
    // tests build their own `DataChannel` from `keys()`. Against a
    // `--mode server` peer it is a failure, and after the handshake window
    // this client says so — see `asking_for_a_configuration_forever_is_not_asking`.
    let mut server = FakeServer::new(Answer::KeyMaterialOnly);
    let mut session = session_against(&server);

    exchange(&mut session, &mut server, Instant::now()).expect("silence is not yet an error");

    assert!(session.is_established());
    assert!(session.keys().is_some());
    assert_eq!(session.push_reply(), None);
    assert!(
        !session.is_ready(),
        "and no tunnel, because there is no peer id"
    );
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

#[test]
fn a_push_request_is_asked_again_until_it_is_answered() {
    // A server that is not ready to answer says nothing at all. A request
    // sent once is then a request never answered: the session sits there
    // established with no peer id, sending the short form of every data
    // packet, which a `--mode server` peer drops without a word.
    let mut server = FakeServer::new(Answer::KeyMaterialOnly);
    let mut session = session_against(&server);
    let start = Instant::now();

    exchange(&mut session, &mut server, start).expect("silence is not an error");
    assert_eq!(session.push_reply(), None, "nothing came back");

    // Not yet — asking every time round the loop would be a flood, not a
    // retry.
    assert!(session
        .poll_transmit(start + Duration::from_secs(2), 0)
        .is_none());

    // But at OpenVPN's own interval, it asks again rather than waiting
    // forever for an answer that is not coming on its own.
    assert!(
        session
            .poll_transmit(start + Duration::from_secs(6), 0)
            .is_some(),
        "the request goes out again"
    );
}

#[test]
fn compression_the_server_pushes_stops_the_session() {
    let mut server = FakeServer::new(Answer::KeyMaterialThen(
        "PUSH_REPLY,peer-id 1,comp-lzo".to_string(),
    ));
    let mut session = session_against(&server);

    let error = exchange(&mut session, &mut server, Instant::now()).unwrap_err();

    assert_eq!(error, Error::UnsupportedCompression("comp-lzo".to_string()));
}

#[test]
fn a_ready_session_carries_payload_both_ways() {
    // The point of all of it: bytes in, bytes out, under keys neither end
    // sent.
    let mut server = FakeServer::new(Answer::KeyMaterialThen(
        "PUSH_REPLY,peer-id 4,cipher AES-256-CBC".to_string(),
    ));
    let mut session = session_against(&server);
    let start = Instant::now();
    exchange(&mut session, &mut server, start).expect("a whole handshake");

    assert!(session.is_ready(), "there is a tunnel");
    let datagram = session
        .send_payload(start, b"a packet for the NAS")
        .expect("wrapped");

    assert!(
        Session::is_data(&datagram),
        "and it is data, not another handshake message"
    );
    assert_eq!(
        server
            .decrypt_payload(&datagram)
            .expect("the peer reads it"),
        b"a packet for the NAS"
    );
}

#[test]
fn a_session_with_no_tunnel_yet_refuses_payload_rather_than_inventing_one() {
    let server = FakeServer::new(Answer::KeyMaterialOnly);
    let mut session = session_against(&server);

    assert_eq!(
        session
            .send_payload(Instant::now(), b"too early")
            .unwrap_err(),
        Error::NotReady
    );
}

#[test]
fn a_quiet_session_sends_the_keepalive_the_server_asked_for() {
    // The server counts silence, not idleness: `ping-restart` is how long it
    // waits before deciding we have gone. Without this the tunnel would work
    // perfectly and then be torn down a minute into the first pause.
    let mut server = FakeServer::new(Answer::KeyMaterialThen(
        "PUSH_REPLY,peer-id 4,ping 10,ping-restart 60".to_string(),
    ));
    let mut session = session_against(&server);
    let start = Instant::now();
    exchange(&mut session, &mut server, start).expect("a whole handshake");

    // Nothing to say, and not long enough to need to say it.
    assert!(session
        .poll_transmit(start + Duration::from_secs(5), 0)
        .is_none());

    let datagram = session
        .poll_transmit(start + Duration::from_secs(11), 0)
        .expect("a keepalive is due");

    assert!(Session::is_data(&datagram));
    assert_eq!(
        server
            .decrypt_payload(&datagram)
            .expect("the peer reads it"),
        PING,
        "and it is the keepalive openvpn recognises"
    );
}

#[test]
fn a_server_that_asked_for_no_keepalive_gets_none() {
    let mut server = FakeServer::new(Answer::KeyMaterialThen("PUSH_REPLY,peer-id 4".to_string()));
    let mut session = session_against(&server);
    let start = Instant::now();
    exchange(&mut session, &mut server, start).expect("a whole handshake");

    assert!(
        session
            .poll_transmit(start + Duration::from_secs(600), 0)
            .is_none(),
        "silence was not asked for, so silence it is"
    );
}

#[test]
fn asking_for_a_configuration_forever_is_not_asking() {
    // A client that pulls cannot work without the answer. Retrying is right;
    // retrying without end is a session that is never usable and never says
    // why.
    let mut server = FakeServer::new(Answer::KeyMaterialOnly);
    let mut session = session_against(&server);
    let start = Instant::now();
    exchange(&mut session, &mut server, start).expect("silence is not yet an error");

    let much_later = start + Duration::from_secs(90);
    assert!(session.poll_transmit(much_later, 0).is_none());
    assert_eq!(session.failure(), Some(&Error::NoPushReply));
}

#[test]
fn the_peers_own_keepalive_is_not_handed_to_the_caller() {
    // A real openvpn sends an encrypted PING every `ping` seconds. Those
    // sixteen bytes are addressed to the tunnel, not sent through it, and
    // handing them up would splice them into whatever stream the caller is
    // reassembling — a corruption that reads as the far end misbehaving.
    let mut server = FakeServer::new(Answer::KeyMaterialThen(
        "PUSH_REPLY,peer-id 4,ping 10".to_string(),
    ));
    let mut session = session_against(&server);
    let start = Instant::now();
    exchange(&mut session, &mut server, start).expect("a whole handshake");

    let keepalive = server.encrypt_payload(&PING);
    assert_eq!(
        session.receive_payload(&keepalive).expect("it decrypts"),
        None,
        "nothing for the caller"
    );

    let real = server.encrypt_payload(b"an actual packet");
    assert_eq!(
        session.receive_payload(&real).expect("it decrypts"),
        Some(b"an actual packet".to_vec())
    );
}

#[test]
fn traffic_of_its_own_postpones_the_keepalive() {
    // The server counts silence, so a busy tunnel has already said everything
    // a keepalive would. Sending one anyway is a packet per interval that
    // nobody needed.
    let mut server = FakeServer::new(Answer::KeyMaterialThen(
        "PUSH_REPLY,peer-id 4,ping 10".to_string(),
    ));
    let mut session = session_against(&server);
    let start = Instant::now();
    exchange(&mut session, &mut server, start).expect("a whole handshake");

    let busy = start + Duration::from_secs(9);
    session.send_payload(busy, b"traffic").expect("wrapped");

    assert!(
        session
            .poll_transmit(busy + Duration::from_secs(5), 0)
            .is_none(),
        "not due: we spoke five seconds ago"
    );
    assert!(
        session
            .poll_transmit(busy + Duration::from_secs(11), 0)
            .is_some(),
        "due: eleven seconds of silence"
    );
}

#[test]
fn the_wakeup_knows_when_the_keepalive_is_due() {
    // `next_wakeup` is what a caller sleeps on. Once the handshake settles the
    // control channel has nothing outstanding and answers `None`, so a wakeup
    // consulting only that would sleep through every ping — and the server
    // would drop a tunnel for a silence the client had a timer for.
    let mut server = FakeServer::new(Answer::KeyMaterialThen(
        "PUSH_REPLY,peer-id 4,ping 10".to_string(),
    ));
    let mut session = session_against(&server);
    let start = Instant::now();
    exchange(&mut session, &mut server, start).expect("a whole handshake");

    let settled = start + Duration::from_secs(1);
    session.send_payload(settled, b"traffic").expect("wrapped");

    assert_eq!(
        session.next_wakeup(settled),
        Some(settled + Duration::from_secs(10)),
        "the next thing due is the keepalive"
    );
}

#[test]
fn a_keepalive_interval_of_zero_means_no_keepalive() {
    // OpenVPN spells "off" as zero. Taken literally it is a keepalive that is
    // always due, and a caller draining `poll_transmit` never finishes.
    let mut server = FakeServer::new(Answer::KeyMaterialThen(
        "PUSH_REPLY,peer-id 4,ping 0".to_string(),
    ));
    let mut session = session_against(&server);
    let start = Instant::now();
    exchange(&mut session, &mut server, start).expect("a whole handshake");

    assert_eq!(session.push_reply().expect("answered").ping, None);
    assert!(session
        .poll_transmit(start + Duration::from_secs(3600), 0)
        .is_none());
}

#[test]
fn a_handshake_survives_a_link_that_loses_and_reorders() {
    // The reliability layer is tested on its own, and the session is tested
    // over a link that behaves. Neither says anything about the two together,
    // and that composition is where every recurring bug in this crate has
    // lived: each layer right, the seam between them wrong.
    //
    // Every third datagram out is lost, and every flight in arrives
    // backwards.
    let mut server = FakeServer::new(Answer::KeyMaterialThen(
        "PUSH_REPLY,peer-id 4,cipher AES-256-CBC,ping 10".to_string(),
    ));
    let mut session = session_against(&server);

    exchange_lossy(
        &mut session,
        &mut server,
        Instant::now(),
        3,
        |session, _| session.is_ready(),
    )
    .expect("recovery, not failure");

    assert!(session.is_ready(), "the handshake finished anyway");
    assert_eq!(
        session
            .push_reply()
            .and_then(|reply| reply.peer_id)
            .map(|id| id.get()),
        Some(4),
        "and everything arrived, in order, exactly once"
    );
}

#[test]
fn a_handshake_survives_heavier_loss() {
    // Every other datagram. Slower, not different: the same timer runs more
    // often.
    let mut server = FakeServer::new(Answer::KeyMaterialThen("PUSH_REPLY,peer-id 7".to_string()));
    let mut session = session_against(&server);

    exchange_lossy(
        &mut session,
        &mut server,
        Instant::now(),
        2,
        |session, _| session.is_ready(),
    )
    .expect("recovery, not failure");

    assert!(session.is_ready());
    assert_eq!(
        session
            .push_reply()
            .and_then(|reply| reply.peer_id)
            .map(|id| id.get()),
        Some(7)
    );
}

#[test]
fn a_renegotiation_replaces_the_keys_without_stopping_the_tunnel() {
    // What `reneg-sec` does to a copy that outlives it, which every
    // multi-gigabyte copy does. The peer starts a new generation; a second
    // TLS handshake and key exchange run on the same control channel under a
    // new key id; and when they finish the tunnel is carrying traffic under
    // keys that did not exist a moment ago.
    //
    // The old keys keep working throughout. A renegotiation that paused the
    // tunnel would be one nobody could afford to run mid-copy.
    let mut server = FakeServer::new(Answer::KeyMaterialThen(
        "PUSH_REPLY,peer-id 4,cipher AES-256-CBC".to_string(),
    ));
    let mut session = session_against(&server);
    let start = Instant::now();
    exchange(&mut session, &mut server, start).expect("a whole handshake");

    let first_keys = session.keys().expect("keys").to_vec();
    assert!(session.is_ready());

    // The tunnel works before.
    let before = session
        .send_payload(start, b"before the rotation")
        .expect("wrapped");
    assert_eq!(
        server.decrypt_payload(&before).expect("the peer reads it"),
        b"before the rotation"
    );

    // And now the peer rotates.
    let announcement = server.renegotiate();
    session
        .handle(&announcement, start)
        .expect("a new generation, not an intruder");
    exchange(&mut session, &mut server, start).expect("the second handshake");

    assert!(server.renegotiated(), "the peer saw it through");
    let second_keys = session.keys().expect("keys").to_vec();
    assert_ne!(
        first_keys, second_keys,
        "new keys, which is the entire point"
    );
    assert!(session.is_ready(), "and the tunnel is still there");
}

#[test]
fn a_renegotiation_survives_a_link_that_loses_and_reorders() {
    // The rotation is a whole handshake, so it meets loss like the first one
    // did — except now there are two message streams in flight at once, and
    // they must not be confused for one another.
    let mut server = FakeServer::new(Answer::KeyMaterialThen(
        "PUSH_REPLY,peer-id 4,cipher AES-256-CBC".to_string(),
    ));
    let mut session = session_against(&server);
    let start = Instant::now();
    exchange(&mut session, &mut server, start).expect("a whole handshake");
    let first_keys = session.keys().expect("keys").to_vec();

    let announcement = server.renegotiate();
    session.handle(&announcement, start).expect("valid");
    exchange_lossy(&mut session, &mut server, start, 3, |_, server| {
        server.renegotiated()
    })
    .expect("recovery, not failure");

    assert!(server.renegotiated());
    assert_ne!(first_keys, session.keys().expect("keys").to_vec());
}

#[test]
fn packets_still_in_flight_under_the_old_keys_are_read_after_a_rotation() {
    // A rotation does not stop what is already on the wire. A tunnel that
    // forgot the old keys the instant it re-keyed would drop the last few
    // packets of every rotation — an hour apart, and indistinguishable from a
    // lossy link.
    let mut server = FakeServer::new(Answer::KeyMaterialThen(
        "PUSH_REPLY,peer-id 4,cipher AES-256-CBC".to_string(),
    ));
    let mut session = session_against(&server);
    let start = Instant::now();
    exchange(&mut session, &mut server, start).expect("a whole handshake");

    // The peer sends under the keys in force now...
    let in_flight = server.encrypt_payload(b"sent before the rotation");

    // ...and the rotation happens before it is read.
    let announcement = server.renegotiate();
    session
        .handle(&announcement, start)
        .expect("a new generation");
    exchange(&mut session, &mut server, start).expect("the second handshake");
    assert!(server.renegotiated());

    assert_eq!(
        session.receive_payload(&in_flight).expect("still readable"),
        Some(b"sent before the rotation".to_vec()),
        "the old keys outlive the rotation by exactly as long as they need to"
    );
}

#[test]
fn a_renegotiation_the_peer_abandons_does_not_block_the_next_one() {
    // The peer announces a generation and then says nothing more about it —
    // and later tries again under a different key. Ours has to follow, or it
    // would be negotiating a generation nobody is listening for.
    let mut server = FakeServer::new(Answer::KeyMaterialThen(
        "PUSH_REPLY,peer-id 4,cipher AES-256-CBC".to_string(),
    ));
    let mut session = session_against(&server);
    let start = Instant::now();
    exchange(&mut session, &mut server, start).expect("a whole handshake");
    let first_keys = session.keys().expect("keys").to_vec();

    // Announced, then abandoned: the peer's own state is replaced when it
    // starts again.
    let abandoned = server.renegotiate();
    session.handle(&abandoned, start).expect("a new generation");

    let second = server.renegotiate();
    session.handle(&second, start).expect("and another");
    exchange(&mut session, &mut server, start).expect("the one that finishes");

    assert!(server.renegotiated());
    assert_ne!(
        first_keys,
        session.keys().expect("keys").to_vec(),
        "the second attempt saw it through"
    );
}

/// The invariant that seven separate bugs have violated.
///
/// `next_wakeup` is a promise about `poll_transmit`: if there is something to
/// send now, the caller must be told to ask now. Every time a new thing was
/// added that `poll_transmit` would do — fast retransmit, a freed send window,
/// the keepalive, a renegotiation's outbox — the wakeup was not told about it,
/// and a caller sleeping on the answer missed it.
///
/// Checking it once per state is worth more than remembering to update two
/// functions together, because it holds for paths nobody has written yet.
/// Asking the question costs a datagram, so the datagram is delivered rather
/// than dropped: a check that quietly loses the opening reset would be
/// measuring a session it had broken.
fn wakeup_agrees_with_transmit(
    session: &mut Session,
    server: &mut FakeServer,
    now: Instant,
    state: &str,
) {
    let wakeup = session.next_wakeup(now);
    let datagram = session.poll_transmit(now, 0);
    let sends = datagram.is_some();

    if let Some(datagram) = datagram {
        // `poll_transmit` speaks for both channels, so what comes back may be
        // a keepalive rather than a handshake message — and the peer's control
        // path cannot authenticate one of those.
        if Session::is_data(&datagram) {
            server
                .decrypt_payload(&datagram)
                .expect("the peer reads it");
        } else {
            for reply in server.handle(&datagram) {
                let _ = session.handle(&reply, now);
            }
        }
    }

    if sends {
        // At or before `now`: a deadline already past means "due", and a
        // caller sleeping until it wakes immediately. What must never happen
        // is a wakeup in the future, or none at all, while something waits.
        match wakeup {
            Some(at) => assert!(
                at <= now,
                "{state}: something to send, and the wakeup pointed at the future"
            ),
            None => panic!("{state}: something to send, and the wakeup said idle"),
        }
    }
    if wakeup.is_none() {
        assert!(
            !sends,
            "{state}: the wakeup said idle and there was something to send"
        );
    }
}

#[test]
fn the_wakeup_never_disagrees_with_what_can_be_sent() {
    let mut server = FakeServer::new(Answer::KeyMaterialThen(
        "PUSH_REPLY,peer-id 4,cipher AES-256-CBC,ping 10".to_string(),
    ));
    let mut session = session_against(&server);
    let start = Instant::now();

    // Fresh: rustls has a ClientHello ready before the channel has anything.
    wakeup_agrees_with_transmit(&mut session, &mut server, start, "before the handshake");

    exchange(&mut session, &mut server, start).expect("a whole handshake");
    wakeup_agrees_with_transmit(&mut session, &mut server, start, "settled");

    // A keepalive coming due.
    wakeup_agrees_with_transmit(
        &mut session,
        &mut server,
        start + Duration::from_secs(30),
        "keepalive due",
    );

    // And in the middle of a rotation, where a second handshake's fragments
    // are waiting on a second key.
    let announcement = server.renegotiate();
    session
        .handle(&announcement, start)
        .expect("a new generation");
    // Several times over: the first thing due is the channel's own
    // acknowledgement of the soft reset, and only once that is gone is the
    // second handshake's first fragment the *only* thing waiting — which is
    // the state where forgetting it in the wakeup actually shows.
    for step in 0..4 {
        wakeup_agrees_with_transmit(
            &mut session,
            &mut server,
            start,
            &format!("renegotiating, step {step}"),
        );
    }

    exchange(&mut session, &mut server, start).expect("the second handshake");
    wakeup_agrees_with_transmit(&mut session, &mut server, start, "after the rotation");
}

#[test]
fn the_wakeup_agrees_while_a_push_reply_is_outstanding() {
    // The retry path has its own timer, and its own chance to be forgotten.
    let mut server = FakeServer::new(Answer::KeyMaterialOnly);
    let mut session = session_against(&server);
    let start = Instant::now();
    exchange(&mut session, &mut server, start).expect("silence is not yet an error");

    for after in [0u64, 3, 6, 12] {
        wakeup_agrees_with_transmit(
            &mut session,
            &mut server,
            start + Duration::from_secs(after),
            &format!("{after}s into waiting for a push reply"),
        );
    }
}

#[test]
fn an_idle_tunnel_is_not_declared_dead_by_default() {
    // The tunnel sends nothing and the peer sends nothing, because that is
    // what was agreed. A deadline here would end a working idle tunnel for
    // behaving exactly as arranged — `recv` returning `None` and `send`
    // failing, on a link where nothing was wrong.
    let mut server = FakeServer::new(Answer::KeyMaterialThen(
        "PUSH_REPLY,peer-id 4,cipher AES-256-CBC".to_string(),
    ));
    let mut session = session_against(&server);
    exchange(&mut session, &mut server, Instant::now()).expect("a whole handshake");

    assert_eq!(
        session.peer_timeout(),
        None,
        "silence was agreed, so silence proves nothing"
    );
}

#[test]
fn the_servers_own_restart_interval_is_used_when_it_gives_one() {
    let mut server = FakeServer::new(Answer::KeyMaterialThen(
        "PUSH_REPLY,peer-id 4,ping 10,ping-restart 60".to_string(),
    ));
    let mut session = session_against(&server);
    exchange(&mut session, &mut server, Instant::now()).expect("a whole handshake");

    assert_eq!(session.peer_timeout(), Some(Duration::from_secs(60)));
}

#[test]
fn a_caller_that_would_rather_not_wait_forever_can_say_so() {
    // The local policy OpenVPN spells `--ping-restart`. A caller who prefers a
    // bounded wait on a silent link is entitled to one, whatever the peer
    // asked for.
    let mut server = FakeServer::new(Answer::KeyMaterialThen("PUSH_REPLY,peer-id 4".to_string()));
    let mut config = SessionConfig::new(
        server.ca_pem.clone(),
        "localhost",
        StaticKey::from_hex(TA_KEY_HEX).expect("test vector"),
    );
    config.peer_timeout = Some(Duration::from_secs(30));
    let mut session = Session::new(config).expect("a client");
    exchange(&mut session, &mut server, Instant::now()).expect("a whole handshake");

    assert_eq!(session.peer_timeout(), Some(Duration::from_secs(30)));
}

#[test]
fn a_restart_interval_of_zero_is_off_rather_than_immediate() {
    // Zero is how OpenVPN spells "off" — the same rule the `ping` arm already
    // followed. Read literally it is a deadline that expired before the reply
    // was parsed, and the tunnel ends on the next turn of the loop.
    let mut server = FakeServer::new(Answer::KeyMaterialThen(
        "PUSH_REPLY,peer-id 4,ping 10,ping-restart 0".to_string(),
    ));
    let mut session = session_against(&server);
    exchange(&mut session, &mut server, Instant::now()).expect("a whole handshake");

    assert_eq!(
        session.push_reply().expect("answered").ping_restart,
        None,
        "off, not zero"
    );
    assert_eq!(
        session.peer_timeout(),
        None,
        "and certainly not a deadline already past"
    );
}
