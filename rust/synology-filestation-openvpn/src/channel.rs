//! The control channel: authentication, framing and retransmission as one
//! thing.
//!
//! This is the layer a TLS session sits on. It takes datagrams in and gives
//! datagrams out, and in between it guarantees what TLS needs — that the bytes
//! handed up arrive once, in order, and came from the peer we started talking
//! to.
//!
//! It holds no socket and reads no clock. `now` and the timestamp that goes in
//! each packet are parameters, which keeps the whole handshake testable
//! without a network and lets the caller decide what "now" means when it is
//! driving several sessions at once.

use std::time::{Duration, Instant};

use crate::packet::{Acks, ControlPacket, KeyId, Opcode, SessionId};
use crate::reliable::{RecvWindow, SendWindow};
use crate::replay::ReplayWindow;
use crate::tls_auth::TlsAuth;
use crate::Error;

pub struct ControlChannel {
    auth: TlsAuth,
    local_session: SessionId,
    remote_session: Option<SessionId>,
    key_id: KeyId,
    send: SendWindow,
    recv: RecvWindow,
    /// The `tls-auth` replay counter, which counts *datagrams* rather than
    /// messages. OpenVPN's first packet carries 1, not 0.
    next_replay_id: u32,
    /// The same counter in the other direction, as the peer sends it.
    replay: ReplayWindow,
}

impl ControlChannel {
    pub fn new(auth: TlsAuth, local_session: SessionId, tls_timeout: Duration) -> Self {
        Self {
            auth,
            local_session,
            remote_session: None,
            key_id: KeyId::FIRST,
            send: SendWindow::new(tls_timeout),
            recv: RecvWindow::new(),
            next_replay_id: 1,
            replay: ReplayWindow::new(),
        }
    }

    /// Begin a session by queueing the opening reset.
    pub fn open(&mut self) {
        self.send
            .queue(Opcode::ControlHardResetClientV2, Vec::new());
    }

    /// Queue a TLS record to be carried to the peer.
    ///
    /// Returns `false` if the window is full, which means the peer has not
    /// acknowledged enough for us to run further ahead. The caller has to try
    /// again rather than let the record be forgotten.
    pub fn send_control(&mut self, payload: Vec<u8>) -> bool {
        self.send.queue(Opcode::ControlV1, payload).is_some()
    }

    /// The peer's session id, once it has told us.
    pub fn remote_session(&self) -> Option<SessionId> {
        self.remote_session
    }

    /// The next datagram to put on the wire, if there is one.
    ///
    /// `net_time` is what goes in the packet's replay header: the sender's
    /// clock in seconds since the epoch, truncated to 32 bits.
    pub fn poll_transmit(&mut self, now: Instant, net_time: u32) -> Option<Vec<u8>> {
        let acks = self.take_acks();

        let packet = match self.send.next_due(now) {
            Some(outgoing) => ControlPacket {
                opcode: outgoing.opcode,
                key_id: self.key_id,
                session_id: self.local_session,
                acks,
                packet_id: Some(outgoing.packet_id),
                payload: outgoing.payload,
            },
            // Nothing of our own to say. Acknowledgements still have to get
            // there, or the peer keeps retransmitting what we already have.
            None if acks.is_some() => ControlPacket {
                opcode: Opcode::AckV1,
                key_id: self.key_id,
                session_id: self.local_session,
                acks,
                packet_id: None,
                payload: Vec::new(),
            },
            None => return None,
        };

        let replay_id = self.next_replay_id;
        self.next_replay_id = self.next_replay_id.wrapping_add(1);
        Some(self.auth.wrap(&packet, replay_id, net_time))
    }

    /// When [`ControlChannel::poll_transmit`] will next have something.
    ///
    /// `None` means there is nothing to send and nothing to wait for. It has
    /// to account for acknowledgements as well as the send window: handling a
    /// datagram leaves an ack owed without putting anything in flight, and a
    /// caller that slept on the window alone would sit there while the peer
    /// retransmitted what we already have.
    pub fn next_wakeup(&self, now: Instant) -> Option<Instant> {
        if self.recv.owes_acks() {
            return Some(now);
        }
        self.send.next_wakeup(now)
    }

    /// Take a datagram from the network.
    ///
    /// Every rejection here is an error rather than a silent drop, because the
    /// caller is the only thing that can count them, and a peer that is
    /// consistently rejected is worth noticing.
    pub fn handle(&mut self, datagram: &[u8], _now: Instant) -> Result<(), Error> {
        let (packet, header) = self.auth.unwrap(datagram)?;

        // Straight after authentication, and before anything is interpreted —
        // which is where OpenVPN checks it too. A captured datagram stays
        // authentic forever; this is the only thing that stops it being
        // replayed into a later session.
        //
        // The window is updated for a packet we may still reject below. That
        // is deliberate: the id was genuinely used, and a rejection on other
        // grounds does not hand it back.
        if !self.replay.accept(header.packet_id, header.net_time) {
            return Err(Error::Replayed);
        }

        // Everything else is checked before anything is changed. The first
        // authentic packet settles who the peer is, so a packet we are about
        // to reject must not settle it first — that would lock the channel
        // onto a peer it has just refused, and the real server would then be
        // turned away as an impostor for the rest of the session.
        if let Some(known) = self.remote_session {
            if known != packet.session_id {
                return Err(Error::WrongSession);
            }
        }
        if let Some(acks) = &packet.acks {
            if acks.session_id() != self.local_session {
                // Acknowledgements for a session that is not ours would clear
                // messages of ours that are still in flight.
                return Err(Error::AckForAnotherSession);
            }
        }

        self.remote_session.get_or_insert(packet.session_id);
        if let Some(acks) = &packet.acks {
            self.send.acknowledge(acks.ids());
        }
        // A `P_ACK_V1` carries no message id and nothing to deliver.
        if let Some(packet_id) = packet.packet_id {
            self.recv.accept(packet_id, packet.opcode, packet.payload);
        }

        Ok(())
    }

    /// The next TLS record from the peer, in the order it was sent.
    ///
    /// A reset occupies a place in the sequence like any other message, but it
    /// is not a TLS record and handing its empty payload upwards would feed
    /// the session a zero-length read. So resets are stepped over here, having
    /// already done their work when they arrived.
    pub fn poll_control(&mut self) -> Option<Vec<u8>> {
        loop {
            match self.recv.next_in_order()? {
                (Opcode::ControlV1, payload) => return Some(payload),
                _ => continue,
            }
        }
    }

    /// Acknowledgements to attach to the next outgoing packet.
    ///
    /// Nothing can be acknowledged before the peer's session id is known,
    /// because the ack block has to name it — but that is not a case that
    /// arises: the packet that gives us the session id is the first one there
    /// is anything to acknowledge for.
    fn take_acks(&mut self) -> Option<Acks> {
        let session_id = self.remote_session?;
        let ids = self.recv.take_acks(Acks::MAX);
        if ids.is_empty() {
            return None;
        }
        Some(Acks::new(ids, session_id).expect("take_acks is bounded by Acks::MAX"))
    }
}

impl std::fmt::Debug for ControlChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlChannel")
            .field("local_session", &self.local_session)
            .field("remote_session", &self.remote_session)
            .field("key_id", &self.key_id)
            .field("in_flight", &self.send.in_flight())
            .finish_non_exhaustive()
    }
}
