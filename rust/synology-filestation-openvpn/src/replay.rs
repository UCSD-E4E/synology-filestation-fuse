//! Refusing packets we have already seen.
//!
//! Every control packet carries a replay header — a counter and the sender's
//! clock — inside the region the `tls-auth` HMAC covers. Authenticating it and
//! then not *checking* it leaves the obvious hole: a datagram captured off the
//! wire is still perfectly authentic, and can be played back into a later
//! session to inject stale bytes into a TLS stream that will never recover
//! from them.
//!
//! The window is OpenVPN's (`packet_id_test`), including the parts that look
//! lenient. It is a sliding window rather than a strict counter because UDP
//! reorders, and 64 is `DEFAULT_SEQ_BACKTRACK`.
//!
//! One consequence worth knowing, because it is shared with OpenVPN rather
//! than introduced here: an attacker holding the `tls-auth` key — which on a
//! password-authenticated VPN is every user — can burn a packet id before the
//! real peer uses it, and the real packet is then dropped as a replay. The
//! session recovers on the retransmission, which carries the next id.

/// How far behind the highest id we still accept, `DEFAULT_SEQ_BACKTRACK`.
const WINDOW: u32 = 64;

/// The replay state for one direction of one session.
#[derive(Debug, Default)]
pub struct ReplayWindow {
    /// The sender's clock as of the highest id accepted.
    time: u32,
    /// The highest id accepted at that time.
    highest: u32,
    /// One bit per id in `(highest - WINDOW, highest]`, with bit 0 being
    /// `highest` itself. Set means seen.
    seen: u64,
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether to accept this packet — and, if so, remember it.
    ///
    /// Testing and recording are one operation deliberately: they are only
    /// ever correct together, and separating them makes forgetting the second
    /// half a thing that can happen.
    pub fn accept(&mut self, packet_id: u32, net_time: u32) -> bool {
        // OpenVPN numbers packets from one, so a zero is either a bug or
        // someone probing.
        if packet_id == 0 {
            return false;
        }

        if net_time > self.time {
            // The sender's clock moved on, which starts a fresh sequence.
            self.time = net_time;
            self.highest = packet_id;
            self.seen = 1;
            return true;
        }

        if net_time < self.time {
            // Time going backwards is not something an honest sender does.
            return false;
        }

        if packet_id > self.highest {
            let advance = packet_id - self.highest;
            self.seen = if advance >= u64::BITS {
                // Everything in the old window is now out of range.
                1
            } else {
                (self.seen << advance) | 1
            };
            self.highest = packet_id;
            return true;
        }

        let behind = self.highest - packet_id;
        if behind >= WINDOW {
            // Too old to prove anything about, so it is refused rather than
            // guessed at.
            return false;
        }

        let bit = 1u64 << behind;
        if self.seen & bit != 0 {
            return false;
        }
        self.seen |= bit;
        true
    }
}
