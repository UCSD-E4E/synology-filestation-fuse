//! Reading what the server pushed.
//!
//! Only lightly proven against a real openvpn. A point-to-point peer — the
//! only kind the interop tests can run without privileges — does answer a
//! `PUSH_REQUEST`, which I had written down as it not doing so until the
//! driver test brought a tunnel up against one. What it does not do is assign
//! a peer id, so the directive that matters most here is exactly the one that
//! never arrives.
//!
//! The rest are the ones e4e-nas's configuration will produce, taken from
//! `spec/e4e-nas/vpn.yml` and from OpenVPN's own option parser, and the first
//! time most of them meet a real server is the live pass.

use std::net::Ipv4Addr;
use std::time::Duration;

use synology_filestation_openvpn::{Error, PeerId, PushReply};

#[test]
fn a_reply_carries_the_peer_id_the_cipher_and_the_keepalive() {
    let reply = PushReply::parse(
        "PUSH_REPLY,ifconfig 10.90.24.6 255.255.255.0,peer-id 3,cipher AES-256-CBC,ping 10,ping-restart 60",
    )
    .expect("a well-formed reply");

    assert_eq!(reply.peer_id, PeerId::new(3));
    assert_eq!(reply.cipher.as_deref(), Some("AES-256-CBC"));
    assert_eq!(
        reply.ifconfig,
        Some((
            Ipv4Addr::new(10, 90, 24, 6),
            Ipv4Addr::new(255, 255, 255, 0)
        ))
    );
    assert_eq!(reply.ping, Some(Duration::from_secs(10)));
    assert_eq!(reply.ping_restart, Some(Duration::from_secs(60)));
}

#[test]
fn a_cipher_we_cannot_speak_is_visible_rather_than_assumed() {
    // e4e-nas is configured with `encryption AUTO`, so the server picks. If it
    // picks something this client does not implement, the only useful
    // behaviour is to say so: encrypting with the wrong algorithm produces
    // packets the server drops without a word, which looks exactly like a
    // network fault.
    let reply = PushReply::parse("PUSH_REPLY,cipher AES-256-GCM").expect("well formed");

    assert_eq!(reply.cipher.as_deref(), Some("AES-256-GCM"));
    assert!(!reply.cipher_is_supported());
}

#[test]
fn a_reply_that_pushes_no_cipher_leaves_ours_in_place() {
    let reply = PushReply::parse("PUSH_REPLY,peer-id 1").expect("well formed");

    assert_eq!(reply.cipher, None);
    assert!(
        reply.cipher_is_supported(),
        "silence means the negotiated cipher stands"
    );
}

#[test]
fn the_cipher_name_is_matched_without_regard_to_case() {
    let reply = PushReply::parse("PUSH_REPLY,cipher aes-256-cbc").expect("well formed");

    assert!(reply.cipher_is_supported());
}

#[test]
fn directives_we_do_not_act_on_are_kept_rather_than_dropped() {
    // Routes and DNS have nothing to act on here — the tunnel ends inside one
    // process and carries one connection — but a directive that vanishes is
    // one nobody can diagnose later.
    let reply = PushReply::parse(
        "PUSH_REPLY,route 10.90.24.0 255.255.255.0,dhcp-option DNS 10.90.24.1,peer-id 7",
    )
    .expect("well formed");

    assert_eq!(reply.directives.len(), 3);
    assert!(reply
        .directives
        .iter()
        .any(|directive| directive.starts_with("route ")));
    assert_eq!(reply.peer_id, PeerId::new(7));
}

#[test]
fn an_empty_reply_is_a_reply() {
    // A server with nothing to say sends the command on its own, with no
    // comma after it.
    let reply = PushReply::parse("PUSH_REPLY").expect("well formed");

    assert_eq!(reply, PushReply::default());
}

#[test]
fn something_that_is_not_a_push_reply_is_refused() {
    assert_eq!(
        PushReply::parse("AUTH_FAILED").unwrap_err(),
        Error::UnexpectedControlMessage("AUTH_FAILED".to_string())
    );
}

#[test]
fn a_peer_id_too_wide_for_the_wire_is_refused() {
    // Three bytes on the wire, so a server offering more is one we cannot
    // address. Better to say so than to send packets to a masked-down id
    // belonging to somebody else.
    let error = PushReply::parse("PUSH_REPLY,peer-id 16777216").unwrap_err();

    assert_eq!(
        error,
        Error::BadPushDirective("peer-id 16777216".to_string())
    );
}

#[test]
fn a_directive_with_nonsense_where_a_number_belongs_is_refused() {
    for bad in [
        "PUSH_REPLY,peer-id three",
        "PUSH_REPLY,ping soon",
        "PUSH_REPLY,ping-restart never",
        "PUSH_REPLY,ifconfig 10.90.24.6 not-a-mask",
    ] {
        assert!(
            matches!(PushReply::parse(bad), Err(Error::BadPushDirective(_))),
            "{bad} should be refused"
        );
    }
}

#[test]
fn spacing_between_directives_does_not_change_the_meaning() {
    let reply = PushReply::parse("PUSH_REPLY, peer-id 2 , ping 5 ").expect("well formed");

    assert_eq!(reply.peer_id, PeerId::new(2));
    assert_eq!(reply.ping, Some(Duration::from_secs(5)));
}

#[test]
fn pushed_compression_is_refused_because_it_changes_the_framing() {
    // Compression is not a property of the payload: it prepends a byte to
    // every packet. A client that implements none and ignores the directive
    // brings a tunnel up and carries corrupt bytes, which is worse than not
    // coming up.
    for directive in [
        "comp-lzo",
        "comp-lzo yes",
        "compress lz4",
        "compress stub-v2",
    ] {
        let reply = PushReply::parse(&format!("PUSH_REPLY,{directive}")).expect("well formed");
        assert!(
            !reply.compression_is_supported(),
            "{directive} should be refused"
        );
        assert_eq!(reply.compression.as_deref(), Some(directive));
    }
}

#[test]
fn a_server_saying_compression_is_off_asks_nothing_of_us() {
    let reply = PushReply::parse("PUSH_REPLY,comp-lzo no,peer-id 2").expect("well formed");

    assert!(reply.compression_is_supported());
    assert_eq!(reply.compression, None);
}

#[test]
fn a_pushed_ifconfig_under_either_topology_gives_the_right_prefix() {
    // The second address means different things under the two topologies, and
    // nothing in the reply says which. OpenVPN 2.6 defaults to `subnet`; 2.5 —
    // which is what e4e-nas runs — still defaults to `net30`, so this is not a
    // legacy case, it is the likely one.
    let subnet = PushReply::parse("PUSH_REPLY,ifconfig 10.90.24.6 255.255.255.0")
        .expect("well formed")
        .ifconfig
        .expect("present");
    assert_eq!(
        synology_filestation_openvpn::Ifconfig::from_push(subnet.0, subnet.1),
        synology_filestation_openvpn::Ifconfig {
            address: Ipv4Addr::new(10, 90, 24, 6),
            prefix: 24,
        }
    );

    // Under net30 the second address is the peer, and reading it as a mask
    // would put us on a subnet that does not exist.
    let net30 = PushReply::parse("PUSH_REPLY,ifconfig 10.90.24.6 10.90.24.5")
        .expect("well formed")
        .ifconfig
        .expect("present");
    assert_eq!(
        synology_filestation_openvpn::Ifconfig::from_push(net30.0, net30.1),
        synology_filestation_openvpn::Ifconfig {
            address: Ipv4Addr::new(10, 90, 24, 6),
            prefix: 30,
        }
    );
}
