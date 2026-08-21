//! Turning a UDP control channel into something a TLS handshake can run on.
//!
//! TLS assumes a stream: no gaps, no reordering, no duplicates. UDP offers
//! none of that, so OpenVPN puts a small windowed retransmission layer
//! underneath — every control message gets an id, the peer acknowledges it,
//! and an unacknowledged message is sent again on a doubling schedule.
//!
//! The rules are taken from OpenVPN's `reliable.c` rather than chosen, because
//! both ends have to agree on when a packet counts as lost. The two that look
//! like details and are not:
//!
//! * a **duplicate** inside the window is acknowledged again but delivered
//!   once — a duplicate usually means our ack was what went missing, and
//!   silence would keep the peer retransmitting;
//! * a message **beyond** the window is dropped *without* an acknowledgement,
//!   because acknowledging what we did not keep tells the peer to stop sending
//!   the one thing we still need.
//!
//! Nothing here reads the clock. `now` is a parameter, so a backoff schedule
//! that takes half a minute in production takes none in a test.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use crate::packet::Opcode;

/// A message the send window wants put on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outgoing {
    pub opcode: Opcode,
    /// The message id the peer will acknowledge.
    pub packet_id: u32,
    pub payload: Vec<u8>,
}

/// One message we are holding until the peer admits to having it.
#[derive(Debug, Clone)]
struct InFlight {
    opcode: Opcode,
    payload: Vec<u8>,
    /// When this may next be sent. `None` means "right now, never sent".
    next_try: Option<Instant>,
    /// How long to wait after the next send — doubles each time.
    timeout: Duration,
    /// Acknowledgements seen for *later* messages while this one waited.
    later_acks: u8,
}

/// Outgoing control messages, and when to send them again.
pub struct SendWindow {
    in_flight: BTreeMap<u32, InFlight>,
    next_id: u32,
    initial_timeout: Duration,
}

impl SendWindow {
    /// `TLS_RELIABLE_N_SEND_BUFFERS`. Also the window size, and the window is
    /// a promise: the peer sizes its receive buffer on the assumption that we
    /// will not get further ahead than this, and drops anything beyond it
    /// *without acknowledging it*. Breaking the promise does not lose one
    /// message, it deadlocks the session.
    pub const CAPACITY: usize = 6;

    /// Three acknowledgements for *later* messages mean this one is lost
    /// (`N_ACK_RETRANSMIT`) — the peer has plainly moved past it, so waiting
    /// out the backoff would only add latency.
    const FAST_RETRANSMIT_AFTER: u8 = 3;

    /// `initial_timeout` is `--tls-timeout`, 2 seconds by default.
    pub fn new(initial_timeout: Duration) -> Self {
        Self {
            in_flight: BTreeMap::new(),
            next_id: 0,
            initial_timeout,
        }
    }

    /// Take a message, or refuse it because the window is full.
    ///
    /// Refusing is the useful behaviour: the caller has to wait for an
    /// acknowledgement rather than hand over a message nothing is holding.
    pub fn queue(&mut self, opcode: Opcode, payload: Vec<u8>) -> Option<u32> {
        if self.is_full() {
            return None;
        }

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.in_flight.insert(
            id,
            InFlight {
                opcode,
                payload,
                next_try: None,
                timeout: self.initial_timeout,
                later_acks: 0,
            },
        );
        Some(id)
    }

    /// Whether another message can be taken.
    ///
    /// Two separate limits, both of them OpenVPN's
    /// (`reliable_get_buf_output_sequenced`). There has to be a free slot —
    /// and the next id has to still be within `CAPACITY` of the oldest message
    /// the peer has not acknowledged.
    ///
    /// The second is the one that is easy to miss, because a free slot looks
    /// like permission. Acknowledgements arriving out of order free slots
    /// without moving the oldest outstanding id, so counting alone would let
    /// us run arbitrarily far ahead of a peer that is still waiting for one
    /// early message.
    pub fn is_full(&self) -> bool {
        if self.in_flight.len() >= Self::CAPACITY {
            return true;
        }
        // A `BTreeMap` is ordered, so the first key is the oldest id still
        // outstanding.
        match self.in_flight.keys().next() {
            Some(&oldest) => self.next_id.wrapping_sub(oldest) >= Self::CAPACITY as u32,
            None => false,
        }
    }

    pub fn in_flight(&self) -> usize {
        self.in_flight.len()
    }

    /// The next message to put on the wire at `now`, lowest id first.
    ///
    /// Calling this *is* the send: the entry's backoff advances, so a caller
    /// that drops the result has consumed a transmission.
    pub fn next_due(&mut self, now: Instant) -> Option<Outgoing> {
        let (&id, entry) = self
            .in_flight
            .iter_mut()
            .find(|(_, entry)| entry.is_due(now, Self::FAST_RETRANSMIT_AFTER))?;

        entry.next_try = Some(now + entry.timeout);
        entry.timeout *= 2;
        entry.later_acks = 0;

        Some(Outgoing {
            opcode: entry.opcode,
            packet_id: id,
            payload: entry.payload.clone(),
        })
    }

    /// When [`SendWindow::next_due`] will next have something, so a caller can
    /// sleep instead of spin. `None` means nothing is in flight.
    ///
    /// Takes `now` for the same reason everything else here does — a message
    /// that has never been sent is due immediately, and saying so requires
    /// naming a moment. Reading the clock to do it would put the one piece of
    /// hidden time back into a layer built to have none.
    ///
    /// It has to agree with [`SendWindow::next_due`] about what "due" means,
    /// fast retransmit included. Reporting a backoff deadline for a message
    /// that three later acknowledgements have already condemned would have the
    /// caller sleep straight through it, which is worse than not having the
    /// optimisation at all.
    pub fn next_wakeup(&self, now: Instant) -> Option<Instant> {
        self.in_flight
            .values()
            .map(|entry| {
                if entry.is_due(now, Self::FAST_RETRANSMIT_AFTER) {
                    now
                } else {
                    entry.next_try.unwrap_or(now)
                }
            })
            .min()
    }

    /// Apply acknowledgements from the peer.
    ///
    /// An id we do not recognise is ignored: it is either already
    /// acknowledged, or the peer talking about a session we do not have.
    pub fn acknowledge(&mut self, ids: &[u32]) {
        for &id in ids {
            if self.in_flight.remove(&id).is_none() {
                continue;
            }
            // Anything still waiting that was sent *before* this one now has
            // evidence against it.
            for (&pending, entry) in self.in_flight.iter_mut() {
                if pending < id {
                    entry.later_acks = entry.later_acks.saturating_add(1);
                }
            }
        }
    }
}

impl InFlight {
    fn is_due(&self, now: Instant, fast_retransmit_after: u8) -> bool {
        match self.next_try {
            None => true,
            Some(at) => now >= at || self.later_acks >= fast_retransmit_after,
        }
    }
}

/// What happened to a message we were offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// Kept, and will come back out of [`RecvWindow::next_in_order`].
    Buffered,
    /// Seen before. Worth acknowledging, not worth delivering twice.
    Duplicate,
    /// Too far ahead to keep. Deliberately *not* acknowledged.
    OutOfWindow,
}

impl Delivery {
    /// Whether the peer should be told we have this one.
    pub fn should_acknowledge(self) -> bool {
        match self {
            Delivery::Buffered | Delivery::Duplicate => true,
            Delivery::OutOfWindow => false,
        }
    }
}

/// Incoming control messages, reassembled into the order they were sent.
pub struct RecvWindow {
    buffered: BTreeMap<u32, Vec<u8>>,
    /// The id we are waiting for; everything below it has been delivered.
    next_expected: u32,
    pending_acks: Vec<u32>,
}

impl RecvWindow {
    /// `TLS_RELIABLE_N_REC_BUFFERS`. Anything at or beyond
    /// `next_expected + CAPACITY` would de-sequentialise the buffer, which
    /// OpenVPN refuses in order to avoid a deadlock — so do we.
    pub const CAPACITY: usize = 12;

    pub fn new() -> Self {
        Self {
            buffered: BTreeMap::new(),
            next_expected: 0,
            pending_acks: Vec::new(),
        }
    }

    /// Offer a received message.
    pub fn accept(&mut self, packet_id: u32, payload: Vec<u8>) -> Delivery {
        if !self.in_window(packet_id) {
            return Delivery::OutOfWindow;
        }

        let verdict = if packet_id < self.next_expected || self.buffered.contains_key(&packet_id) {
            Delivery::Duplicate
        } else {
            self.buffered.insert(packet_id, payload);
            Delivery::Buffered
        };

        if verdict.should_acknowledge() && !self.pending_acks.contains(&packet_id) {
            self.pending_acks.push(packet_id);
        }
        verdict
    }

    /// The next message in order, if it has arrived.
    pub fn next_in_order(&mut self) -> Option<Vec<u8>> {
        let payload = self.buffered.remove(&self.next_expected)?;
        self.next_expected = self.next_expected.wrapping_add(1);
        Some(payload)
    }

    /// Up to `max` ids to acknowledge, oldest first, removed as they are taken.
    ///
    /// `max` is the caller's, because how many fit depends on the packet they
    /// are riding on — see [`crate::Acks::MAX`].
    pub fn take_acks(&mut self, max: usize) -> Vec<u32> {
        let taken = self.pending_acks.len().min(max);
        self.pending_acks.drain(..taken).collect()
    }

    /// Only the *upper* bound is checked, matching `reliable_pid_in_range2`:
    /// an id below `next_expected` is a replay, and a replay is still worth
    /// acknowledging.
    ///
    /// OpenVPN also handles this comparison wrapping past 2^32. A control
    /// channel carries a handshake and a renegotiation an hour, so reaching
    /// four billion messages is not a case this needs to be right about.
    fn in_window(&self, packet_id: u32) -> bool {
        packet_id < self.next_expected.wrapping_add(Self::CAPACITY as u32)
    }
}

impl Default for RecvWindow {
    fn default() -> Self {
        Self::new()
    }
}
