//! The control channel: authentication, framing and retransmission as one
//! thing.
//!
//! This is the layer a TLS session sits on. It takes datagrams in and gives
//! datagrams out, and in between it guarantees what TLS needs — that the bytes
//! handed up arrive once, in order, and came from the peer we started talking
//! to.
//!
//! A session outlives its keys. Every `reneg-sec` — an hour by default, and a
//! multi-gigabyte copy passes that by definition — the peer starts a *new key
//! state*: a new key id, a fresh TLS handshake, and its own message numbering
//! beginning again at zero. The session id and the `tls-auth` key stay put, so
//! the two states share this channel and are told apart by the key id in every
//! packet.
//!
//! Which is why the channel holds two of them. The one carrying traffic keeps
//! carrying it while the other negotiates; nothing pauses, and when the new
//! keys are ready the caller promotes them.
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

/// One generation of keys, and the message stream that negotiates it.
///
/// The windows are per key state rather than per session because the peer
/// numbers each state's messages from zero. Sharing one window between two
/// states would make the new state's first message look like a replay of the
/// old state's first message — which is exactly what happened before this
/// existed.
struct KeyState {
    key_id: KeyId,
    send: SendWindow,
    recv: RecvWindow,
    /// Whether *we* opened this one, which decides how strict we are about
    /// the first packet back.
    opened: bool,
}

impl KeyState {
    fn new(key_id: KeyId, tls_timeout: Duration) -> Self {
        Self {
            key_id,
            send: SendWindow::new(tls_timeout),
            recv: RecvWindow::new(),
            opened: false,
        }
    }
}

pub struct ControlChannel {
    auth: TlsAuth,
    local_session: SessionId,
    remote_session: Option<SessionId>,
    /// The `tls-auth` replay counter, which counts *datagrams* rather than
    /// messages, and belongs to the session rather than to either key state:
    /// OpenVPN keeps it in `tls_wrap`, which the states share.
    next_replay_id: u32,
    replay: ReplayWindow,
    tls_timeout: Duration,
    /// The keys carrying traffic.
    primary: KeyState,
    /// A generation being negotiated, if the peer has started one.
    pending: Option<KeyState>,
}

impl ControlChannel {
    /// The message id of the reset that opens a session. It is the first
    /// message we send, so it is always zero.
    const OPENING_MESSAGE_ID: u32 = 0;

    pub fn new(auth: TlsAuth, local_session: SessionId, tls_timeout: Duration) -> Self {
        Self {
            auth,
            local_session,
            remote_session: None,
            next_replay_id: 1,
            replay: ReplayWindow::new(),
            tls_timeout,
            primary: KeyState::new(KeyId::FIRST, tls_timeout),
            pending: None,
        }
    }

    /// Begin a session by queueing the opening reset.
    ///
    /// This also decides what we will accept back. Having opened a session, the
    /// only packet that can legitimately be its first answer is the server
    /// reset that acknowledges it — see [`ControlChannel::handle`].
    pub fn open(&mut self) {
        self.primary.opened = true;
        self.primary
            .send
            .queue(Opcode::ControlHardResetClientV2, Vec::new());
    }

    /// Queue a TLS record to be carried to the peer, under one key or the
    /// other.
    ///
    /// Returns `false` if that key's window is full, which means the peer has
    /// not acknowledged enough for us to run further ahead. The caller has to
    /// try again rather than let the record be forgotten.
    pub fn send_control(&mut self, key_id: KeyId, payload: Vec<u8>) -> bool {
        match self.state_mut(key_id) {
            Some(state) => state.send.queue(Opcode::ControlV1, payload).is_some(),
            None => false,
        }
    }

    /// The peer's session id, once it has told us.
    pub fn remote_session(&self) -> Option<SessionId> {
        self.remote_session
    }

    /// The session id we chose.
    pub fn local_session(&self) -> SessionId {
        self.local_session
    }

    /// The generation currently carrying traffic.
    pub fn key_id(&self) -> KeyId {
        self.primary.key_id
    }

    /// The generation being negotiated, if the peer has started one.
    pub fn pending_key_id(&self) -> Option<KeyId> {
        self.pending.as_ref().map(|state| state.key_id)
    }

    /// Make the negotiated generation the one that carries traffic.
    ///
    /// The old *control* state is dropped: its handshake is over, and the
    /// peer has no more to say under it.
    ///
    /// The old *data* keys are a different matter, and the caller keeps them
    /// for a while — see `Session::receive_payload`. Two windows open around
    /// this call, and only one of them can be closed from here. Packets the
    /// peer sent under the old key may still be in flight, which the caller
    /// handles by keeping the old key to decrypt with. And packets we send
    /// under the new key may arrive before the peer has activated its own new
    /// state, which it drops; those are recovered by whatever sits above the
    /// tunnel, as any lost packet is.
    pub fn promote(&mut self) {
        if let Some(pending) = self.pending.take() {
            self.primary = pending;
        }
    }

    /// Whether the generation carrying traffic has room for another message.
    pub fn can_send(&self) -> bool {
        self.can_send_for(self.primary.key_id)
    }

    /// The same question about either generation.
    ///
    /// A caller deciding when to wake needs this per key: bytes held back by
    /// one generation's full window are a reason to wait for *its*
    /// acknowledgement, not a reason to be woken immediately.
    pub fn can_send_for(&self, key_id: KeyId) -> bool {
        self.states()
            .find(|state| state.key_id == key_id)
            .is_some_and(|state| !state.send.is_full())
    }

    /// The next datagram to put on the wire, if there is one.
    ///
    /// `net_time` is what goes in the packet's replay header: the sender's
    /// clock in seconds since the epoch, truncated to 32 bits.
    pub fn poll_transmit(&mut self, now: Instant, net_time: u32) -> Option<Vec<u8>> {
        // The negotiation first. It is the thing with a deadline — the peer
        // started it and will give up on us — while the traffic-carrying state
        // is by then usually only acknowledging.
        for key_id in self.key_ids() {
            if let Some(packet) = self.next_packet(key_id, now) {
                let replay_id = self.next_replay_id;
                self.next_replay_id = self.next_replay_id.wrapping_add(1);
                return Some(self.auth.wrap(&packet, replay_id, net_time));
            }
        }
        None
    }

    /// When [`ControlChannel::poll_transmit`] will next have something.
    ///
    /// `None` means there is nothing to send and nothing to wait for. It has
    /// to account for acknowledgements as well as the send window: handling a
    /// datagram leaves an ack owed without putting anything in flight, and a
    /// caller that slept on the window alone would sit there while the peer
    /// retransmitted what we already have.
    pub fn next_wakeup(&self, now: Instant) -> Option<Instant> {
        let mut soonest = None;
        for state in self.states() {
            let due = if state.recv.owes_acks() {
                Some(now)
            } else {
                state.send.next_wakeup(now)
            };
            soonest = match (soonest, due) {
                (None, due) => due,
                (Some(a), Some(b)) => Some(a.min(b)),
                (some, None) => some,
            };
        }
        soonest
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

        // Everything else is checked before anything is changed.
        match self.remote_session {
            Some(known) if known != packet.session_id => return Err(Error::WrongSession),
            Some(_) => {}
            // Nothing is known about the peer yet, so this packet is about to
            // decide it — which makes it the one worth being strict about. We
            // are always the side that opens a session, so the only thing that
            // can legitimately answer is a server reset acknowledging ours.
            //
            // Without this, a datagram captured from an *earlier* session is
            // still authentic and still passes a replay window that was
            // created along with this channel, and it would latch us onto a
            // peer that is not there — after which the real server is refused
            // as an impostor. Requiring the acknowledgement is what makes the
            // rule bite: a captured reset acknowledges a session id we no
            // longer have, and ours is random.
            None if self.primary.opened => {
                // Together these say "this is the answer to what we just
                // sent" rather than merely "this is well formed". The
                // acknowledgement carries most of the weight — it has to name
                // our session id, which is random, and acknowledge the opening
                // message itself — and a packet captured from an earlier
                // session satisfies neither.
                //
                // Its own message id has to be the first one too. A reset
                // numbered anything else would be admitted and then sit in the
                // receive window behind a message zero that never comes, so
                // the session would be established and mute.
                let answers_our_open = packet.opcode == Opcode::ControlHardResetServerV2
                    && packet.packet_id == Some(Self::OPENING_MESSAGE_ID)
                    && packet
                        .acks
                        .as_ref()
                        .is_some_and(|acks| acks.ids().contains(&Self::OPENING_MESSAGE_ID));
                if !answers_our_open {
                    return Err(Error::UnexpectedFirstPacket);
                }
            }
            // A channel that has not opened anything has no expectation to
            // hold the first packet to.
            None => {}
        }

        if let Some(acks) = &packet.acks {
            if acks.session_id() != self.local_session {
                // Acknowledgements for a session that is not ours would clear
                // messages of ours that are still in flight.
                return Err(Error::AckForAnotherSession);
            }
        }

        // A soft reset under a key we do not have is the peer starting a new
        // generation. Refusing it — which this did until renegotiation
        // existed — leaves the peer negotiating with nobody and eventually
        // dropping the session, an hour into whatever it was carrying.
        if packet.opcode == Opcode::ControlSoftResetV1 && packet.key_id != self.primary.key_id {
            // A soft reset for a generation we are not already negotiating
            // replaces whatever we were negotiating. A peer whose attempt
            // stalled simply tries again under the next key id, and holding
            // on to the abandoned one would refuse every later attempt as
            // `OtherKeyId` — the session then dies when the key it is still
            // using expires, which is the failure renegotiation exists to
            // prevent.
            let already = self
                .pending
                .as_ref()
                .is_some_and(|state| state.key_id == packet.key_id);
            if !already {
                self.pending = Some(KeyState::new(packet.key_id, self.tls_timeout));
            }
        }

        // Settled before the state is borrowed, and only now that every
        // check has passed.
        self.remote_session.get_or_insert(packet.session_id);

        let primary_key_id = self.primary.key_id;
        let Some(state) = self.state_mut(packet.key_id) else {
            return Err(Error::OtherKeyId(packet.key_id, primary_key_id));
        };

        if let Some(acks) = &packet.acks {
            state.send.acknowledge(acks.ids());
        }
        // A `P_ACK_V1` carries no message id and nothing to deliver.
        if let Some(packet_id) = packet.packet_id {
            state.recv.accept(packet_id, packet.opcode, packet.payload);
        }

        Ok(())
    }

    /// The next TLS record from the peer, and which generation it belongs to.
    ///
    /// A reset occupies a place in the sequence like any other message, but it
    /// is not a TLS record and handing its empty payload upwards would feed
    /// the session a zero-length read. So resets are stepped over here, having
    /// already done their work when they arrived.
    pub fn poll_control(&mut self) -> Option<(KeyId, Vec<u8>)> {
        for key_id in self.key_ids() {
            let state = self.state_mut(key_id)?;
            loop {
                match state.recv.next_in_order() {
                    Some((Opcode::ControlV1, payload)) => return Some((key_id, payload)),
                    Some(_) => continue,
                    None => break,
                }
            }
        }
        None
    }

    /// Which generations exist, the one being negotiated first.
    fn key_ids(&self) -> Vec<KeyId> {
        match &self.pending {
            Some(pending) => vec![pending.key_id, self.primary.key_id],
            None => vec![self.primary.key_id],
        }
    }

    fn states(&self) -> impl Iterator<Item = &KeyState> {
        std::iter::once(&self.primary).chain(self.pending.iter())
    }

    fn state_mut(&mut self, key_id: KeyId) -> Option<&mut KeyState> {
        if self.primary.key_id == key_id {
            return Some(&mut self.primary);
        }
        match &mut self.pending {
            Some(pending) if pending.key_id == key_id => Some(pending),
            _ => None,
        }
    }

    /// What one generation wants to send now, if anything.
    fn next_packet(&mut self, key_id: KeyId, now: Instant) -> Option<ControlPacket> {
        let local_session = self.local_session;
        let remote_session = self.remote_session;
        let state = self.state_mut(key_id)?;

        // Decide whether there is anything to send *before* collecting
        // acknowledgements. `take_acks` also offers ids already sent, so
        // asking it first would make every call look like it had something to
        // say, and a caller polling until `None` would never stop.
        let due = state.send.next_due(now);
        if due.is_none() && !state.recv.owes_acks() {
            return None;
        }

        let acks = remote_session.and_then(|session_id| {
            let ids = state.recv.take_acks(Acks::MAX);
            (!ids.is_empty())
                .then(|| Acks::new(ids, session_id).expect("take_acks is bounded by Acks::MAX"))
        });

        Some(match due {
            Some(outgoing) => ControlPacket {
                opcode: outgoing.opcode,
                key_id,
                session_id: local_session,
                acks,
                packet_id: Some(outgoing.packet_id),
                payload: outgoing.payload,
            },
            // Nothing of our own to say. Acknowledgements still have to get
            // there, or the peer keeps retransmitting what we already have.
            None => ControlPacket {
                opcode: Opcode::AckV1,
                key_id,
                session_id: local_session,
                acks,
                packet_id: None,
                payload: Vec::new(),
            },
        })
    }
}

impl std::fmt::Debug for ControlChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlChannel")
            .field("local_session", &self.local_session)
            .field("remote_session", &self.remote_session)
            .field("key_id", &self.primary.key_id)
            .field("pending_key_id", &self.pending_key_id())
            .field("in_flight", &self.primary.send.in_flight())
            .finish_non_exhaustive()
    }
}
