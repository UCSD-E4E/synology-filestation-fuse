//! The replay window, including the parts of OpenVPN's behaviour that look
//! like bugs until you know why they are there.

use synology_filestation_openvpn::ReplayWindow;

/// The sender's clock. Constant in most of these: a session's packets normally
/// share a second or two, and the interesting behaviour is within one.
const T: u32 = 1_786_698_661;

#[test]
fn a_packet_is_accepted_once() {
    let mut window = ReplayWindow::new();

    assert!(window.accept(1, T));
    assert!(!window.accept(1, T), "the same packet again is a replay");
}

#[test]
fn packets_in_order_are_all_accepted() {
    let mut window = ReplayWindow::new();

    for id in 1..=1000 {
        assert!(window.accept(id, T), "id {id} arrived in order");
    }
}

#[test]
fn reordering_within_the_window_is_tolerated() {
    // UDP reorders. A strict counter would drop a packet that merely overtook
    // another, and the sender would retransmit something that arrived.
    let mut window = ReplayWindow::new();

    assert!(window.accept(10, T));
    assert!(window.accept(7, T), "late, but not too late");
    assert!(window.accept(9, T));
    assert!(!window.accept(7, T), "though only once each");
}

#[test]
fn a_packet_further_back_than_the_window_is_refused() {
    // Sixty-four is `DEFAULT_SEQ_BACKTRACK`. Beyond it there is no record of
    // whether the packet was seen, and a guess in the accepting direction is
    // the one that lets a replay through.
    let mut window = ReplayWindow::new();
    assert!(window.accept(100, T));

    assert!(
        window.accept(100 - 63, T),
        "the oldest id still in the window"
    );
    assert!(!window.accept(100 - 64, T), "one past it");
    assert!(!window.accept(1, T));
}

#[test]
fn a_jump_forward_leaves_the_old_window_behind() {
    let mut window = ReplayWindow::new();
    assert!(window.accept(1, T));

    assert!(
        window.accept(1000, T),
        "a large jump forward is not suspicious"
    );
    assert!(
        !window.accept(2, T),
        "but everything before the new window is now unprovable"
    );
    assert!(window.accept(999, T), "and what is inside it still works");
}

#[test]
fn a_later_clock_starts_a_fresh_sequence() {
    // The counter restarts when the sender's clock moves on, so an id that
    // would be a replay in the old second is a new packet in the new one.
    let mut window = ReplayWindow::new();
    assert!(window.accept(5, T));
    assert!(!window.accept(5, T));

    assert!(
        window.accept(5, T + 1),
        "a different second, a different packet"
    );
    assert!(!window.accept(5, T + 1));
}

#[test]
fn a_clock_that_goes_backwards_is_refused() {
    let mut window = ReplayWindow::new();
    assert!(window.accept(5, T));

    assert!(
        !window.accept(9999, T - 1),
        "an honest sender's clock does not go back, and a captured packet's does"
    );
}

#[test]
fn packet_id_zero_is_never_accepted() {
    // OpenVPN numbers from one. A zero is a bug or a probe, and either way
    // there is nothing to gain by taking it.
    let mut window = ReplayWindow::new();

    assert!(!window.accept(0, T));
    assert!(!window.accept(0, 0));
}

#[test]
fn a_captured_packet_cannot_be_played_into_the_same_session() {
    // The point of the whole file: a datagram taken off the wire stays
    // perfectly authentic, so authentication alone does not refuse it.
    let mut window = ReplayWindow::new();
    let captured = (42, T);

    assert!(window.accept(captured.0, captured.1));
    for _ in 0..10 {
        assert!(
            !window.accept(captured.0, captured.1),
            "no amount of repetition makes it new"
        );
    }
}
