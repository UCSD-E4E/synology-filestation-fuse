//! The reliability layer: what makes a control channel over UDP behave like a
//! stream, so that a TLS handshake can run on top of it.
//!
//! Every rule here is copied from OpenVPN's `reliable.c` rather than invented,
//! because both ends have to agree about when a packet counts as lost. Where a
//! choice looked arbitrary, the test says which line of theirs it comes from.
//!
//! Time is passed in rather than read, so a backoff schedule that takes half a
//! minute in production takes no time at all to check.

use std::time::{Duration, Instant};

use synology_filestation_openvpn::{Delivery, Opcode, RecvWindow, SendWindow};

/// `--tls-timeout` defaults to 2 seconds.
const TLS_TIMEOUT: Duration = Duration::from_secs(2);

fn send_window() -> SendWindow {
    SendWindow::new(TLS_TIMEOUT)
}

fn payload(tag: u8) -> Vec<u8> {
    vec![tag; 4]
}

#[test]
fn messages_are_numbered_from_zero_upward() {
    let mut window = send_window();

    assert_eq!(window.queue(Opcode::ControlV1, payload(1)), Some(0));
    assert_eq!(window.queue(Opcode::ControlV1, payload(2)), Some(1));
    assert_eq!(window.queue(Opcode::ControlV1, payload(3)), Some(2));
}

#[test]
fn the_send_window_refuses_work_it_could_not_track() {
    // Six outstanding messages, per TLS_RELIABLE_N_SEND_BUFFERS. Refusing is
    // the point: the layer above has to wait for an ack rather than hand over
    // a message nothing is holding on to.
    let mut window = send_window();
    for _ in 0..SendWindow::CAPACITY {
        assert!(window.queue(Opcode::ControlV1, payload(0)).is_some());
    }

    assert_eq!(window.queue(Opcode::ControlV1, payload(0)), None);
    assert!(window.is_full());
}

#[test]
fn the_window_will_not_run_ahead_of_its_oldest_unacknowledged_message() {
    // Counting outstanding messages is not the same as bounding how far ahead
    // we have run, and the difference deadlocks. Queue a full window, then let
    // everything but the first be acknowledged: only one message is
    // outstanding, but the next id would be CAPACITY beyond the one the peer
    // is still waiting for. Its receive window would eventually drop such a
    // message *without acknowledging it* — see `RecvWindow::accept` — and we
    // would retransmit something it has promised never to accept.
    let start = Instant::now();
    let mut window = send_window();
    for _ in 0..SendWindow::CAPACITY {
        window.queue(Opcode::ControlV1, payload(0)).expect("room");
        window.next_due(start).expect("sent");
    }

    window.acknowledge(&(1..SendWindow::CAPACITY as u32).collect::<Vec<_>>());
    assert_eq!(window.in_flight(), 1, "only message 0 is still outstanding");

    assert_eq!(
        window.queue(Opcode::ControlV1, payload(0)),
        None,
        "a free slot is not permission to get further ahead"
    );

    window.acknowledge(&[0]);
    assert!(
        window.queue(Opcode::ControlV1, payload(0)).is_some(),
        "and once the peer has caught up, the window moves with it"
    );
}

#[test]
fn a_queued_message_is_due_immediately_and_lowest_id_first() {
    let now = Instant::now();
    let mut window = send_window();
    window.queue(Opcode::ControlV1, payload(1));
    window.queue(Opcode::ControlV1, payload(2));

    let first = window
        .next_due(now)
        .expect("a fresh message is due at once");
    assert_eq!(first.packet_id, 0);
    assert_eq!(first.payload, payload(1));

    let second = window.next_due(now).expect("so is the one behind it");
    assert_eq!(second.packet_id, 1);

    assert!(
        window.next_due(now).is_none(),
        "neither is due again until its timeout expires"
    );
}

#[test]
fn retransmission_backs_off_by_doubling() {
    // `best->next_try = now + best->timeout; best->timeout *= 2` — so the gaps
    // are 2s, 4s, 8s. On a link that is dropping packets this is what stops the
    // client from adding to the problem.
    let start = Instant::now();
    let mut window = send_window();
    window.queue(Opcode::ControlV1, payload(1));

    window.next_due(start).expect("first transmission");

    for (attempt, gap) in [2u64, 4, 8].into_iter().enumerate() {
        let due_at = window
            .next_wakeup(start)
            .expect("something is still in flight");
        let just_before = due_at - Duration::from_millis(1);
        assert!(
            window.next_due(just_before).is_none(),
            "attempt {attempt} must not go early"
        );
        assert_eq!(
            window.next_due(due_at).map(|out| out.packet_id),
            Some(0),
            "attempt {attempt} is due after {gap}s"
        );
    }

    assert_eq!(
        window.next_wakeup(start).expect("still unacknowledged") - start,
        Duration::from_secs(2 + 4 + 8 + 16),
        "the fourth wait is 16s"
    );
}

#[test]
fn an_acknowledged_message_is_never_sent_again() {
    let start = Instant::now();
    let mut window = send_window();
    window.queue(Opcode::ControlV1, payload(1));
    window.queue(Opcode::ControlV1, payload(2));
    window.next_due(start);
    window.next_due(start);

    window.acknowledge(&[0]);

    let much_later = start + Duration::from_secs(60);
    assert_eq!(
        window.next_due(much_later).map(|out| out.packet_id),
        Some(1),
        "only the unacknowledged one comes back"
    );
    assert_eq!(window.in_flight(), 1);
}

#[test]
fn acknowledging_everything_empties_the_window() {
    let mut window = send_window();
    for _ in 0..SendWindow::CAPACITY {
        window.queue(Opcode::ControlV1, payload(0));
    }
    assert!(window.is_full());

    window.acknowledge(&(0..SendWindow::CAPACITY as u32).collect::<Vec<_>>());

    assert_eq!(window.in_flight(), 0);
    assert_eq!(window.next_wakeup(Instant::now()), None);
    assert!(window.queue(Opcode::ControlV1, payload(0)).is_some());
}

#[test]
fn three_acks_for_later_messages_resend_this_one_early() {
    // `N_ACK_RETRANSMIT` — if three packets sent *after* this one have been
    // acknowledged, waiting out the backoff is just latency: the peer has
    // plainly moved past it. This is the difference between a handshake that
    // recovers from one lost packet in milliseconds and one that stalls for
    // two seconds.
    let start = Instant::now();
    let mut window = send_window();
    for tag in 0..4 {
        window.queue(Opcode::ControlV1, payload(tag));
        window.next_due(start).expect("sent");
    }

    window.acknowledge(&[1, 2]);
    assert!(
        window.next_due(start).is_none(),
        "two is not yet enough to call it lost"
    );

    window.acknowledge(&[3]);
    assert_eq!(
        window.next_due(start).map(|out| out.packet_id),
        Some(0),
        "the third ack for a later message resends this one without waiting"
    );
}

#[test]
fn a_message_due_for_fast_retransmit_wakes_the_caller_now() {
    // `next_wakeup` is what a caller sleeps on. If it reports the old backoff
    // deadline for a message that fast retransmit has already made due, the
    // caller sleeps through it and the optimisation does nothing at all —
    // worse than not having it, because the code claims otherwise.
    let start = Instant::now();
    let mut window = send_window();
    for tag in 0..4 {
        window.queue(Opcode::ControlV1, payload(tag));
        window.next_due(start).expect("sent");
    }

    window.acknowledge(&[1, 2, 3]);

    assert_eq!(
        window.next_wakeup(start),
        Some(start),
        "message 0 is due now, not when its timeout would have expired"
    );
}

#[test]
fn an_ack_for_an_unknown_id_is_ignored() {
    let start = Instant::now();
    let mut window = send_window();
    window.queue(Opcode::ControlV1, payload(1));
    window.next_due(start);

    window.acknowledge(&[7, 99]);

    assert_eq!(window.in_flight(), 1, "nothing was acknowledged");
}

#[test]
fn messages_arrive_in_order_however_they_were_delivered() {
    let mut window = RecvWindow::new();

    assert_eq!(window.accept(2, payload(2)), Delivery::Buffered);
    assert_eq!(
        window.next_in_order(),
        None,
        "0 has not arrived, so 2 waits its turn"
    );

    assert_eq!(window.accept(0, payload(0)), Delivery::Buffered);
    assert_eq!(window.next_in_order(), Some(payload(0)));
    assert_eq!(window.next_in_order(), None, "1 is still missing");

    assert_eq!(window.accept(1, payload(1)), Delivery::Buffered);
    assert_eq!(window.next_in_order(), Some(payload(1)));
    assert_eq!(
        window.next_in_order(),
        Some(payload(2)),
        "and now 2 follows"
    );
}

#[test]
fn a_duplicate_is_acknowledged_again_but_delivered_once() {
    // "Process outgoing acknowledgment for packet just received, even if it's
    // a replay" (ssl.c). A duplicate usually means our ack was the thing that
    // got lost, so staying silent would keep the peer retransmitting.
    let mut window = RecvWindow::new();
    window.accept(0, payload(0));
    window.next_in_order();

    assert_eq!(
        window.accept(0, payload(0)),
        Delivery::Duplicate,
        "already delivered, but still worth acknowledging"
    );
    assert!(Delivery::Duplicate.should_acknowledge());
    assert_eq!(window.next_in_order(), None, "not delivered twice");
}

#[test]
fn a_message_too_far_ahead_is_dropped_without_acknowledgement() {
    // Acknowledging a packet we did not keep would tell the peer to stop
    // sending it, and it would never arrive. Dropping it in silence makes the
    // peer retransmit once the window has moved.
    let mut window = RecvWindow::new();

    let far_ahead = RecvWindow::CAPACITY as u32;
    assert_eq!(window.accept(far_ahead, payload(9)), Delivery::OutOfWindow);
    assert!(!Delivery::OutOfWindow.should_acknowledge());

    assert_eq!(
        window.accept(far_ahead - 1, payload(8)),
        Delivery::Buffered,
        "the last slot in the window is still usable"
    );
}

#[test]
fn acknowledgements_are_handed_out_in_packet_sized_batches() {
    let mut window = RecvWindow::new();
    for id in 0..5 {
        window.accept(id, payload(id as u8));
    }

    assert_eq!(window.take_acks(3), vec![0, 1, 2], "oldest first");
    assert_eq!(window.take_acks(3), vec![3, 4]);
    assert_eq!(window.take_acks(3), Vec::<u32>::new(), "and then nothing");
}

#[test]
fn an_out_of_window_message_leaves_nothing_to_acknowledge() {
    let mut window = RecvWindow::new();
    window.accept(RecvWindow::CAPACITY as u32, payload(9));

    assert_eq!(window.take_acks(8), Vec::<u32>::new());
}
