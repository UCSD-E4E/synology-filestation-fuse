//! Control-channel packet framing.
//!
//! A control packet on the wire, once the `tls-auth` envelope is peeled off,
//! is:
//!
//! ```text
//! opcode<<3 | key_id  (1)
//! session id          (8)   — ours
//! ack count           (1)
//! acked packet ids    (4 × count)
//! session id          (8)   — the peer's, present only when count > 0
//! packet id           (4)   — absent on P_ACK_V1, which is not itself acked
//! payload             (…)   — TLS ciphertext, or empty on a reset
//! ```
//!
//! The ack block sits *inside* the authenticated region and in front of the
//! message id, which is why acks can ride along on any control packet instead
//! of always costing one of their own.

use crate::Error;

/// The eight-byte identifier each end picks for its half of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId([u8; Self::LEN]);

impl SessionId {
    /// Session ids are 8 bytes (`SID_SIZE`).
    pub const LEN: usize = 8;

    pub fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

/// The packet kinds this client needs.
///
/// The `_V1` hard resets and `P_CONTROL_WKC_V1` are deliberately absent: they
/// belong to key method 1 and to tls-crypt-v2, neither of which this server
/// offers. An opcode we do not know is an error rather than a silent skip,
/// because the alternative is misreading a packet's layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    /// `P_CONTROL_SOFT_RESET_V1` — begin a renegotiation without dropping the
    /// tunnel. A copy that outlives `reneg-sec` depends on this.
    ControlSoftResetV1 = 3,
    /// `P_CONTROL_V1` — carries TLS ciphertext.
    ControlV1 = 4,
    /// `P_ACK_V1` — acknowledgements only.
    AckV1 = 5,
    /// `P_DATA_V1` — tunnelled payload, no peer id.
    DataV1 = 6,
    /// `P_CONTROL_HARD_RESET_CLIENT_V2` — our opening packet.
    ControlHardResetClientV2 = 7,
    /// `P_CONTROL_HARD_RESET_SERVER_V2` — the server's answer to it.
    ControlHardResetServerV2 = 8,
    /// `P_DATA_V2` — tunnelled payload with a peer id, which is what a modern
    /// server assigns us.
    DataV2 = 9,
}

impl Opcode {
    fn from_u8(value: u8) -> Result<Self, Error> {
        Ok(match value {
            3 => Opcode::ControlSoftResetV1,
            4 => Opcode::ControlV1,
            5 => Opcode::AckV1,
            6 => Opcode::DataV1,
            7 => Opcode::ControlHardResetClientV2,
            8 => Opcode::ControlHardResetServerV2,
            9 => Opcode::DataV2,
            other => return Err(Error::UnknownOpcode(other)),
        })
    }

    /// Every control packet except a bare ack is itself acknowledged, so every
    /// one but `P_ACK_V1` carries a message id.
    fn carries_packet_id(self) -> bool {
        self != Opcode::AckV1
    }
}

/// Which key generation a packet belongs to.
///
/// Three bits, sharing the first byte with the opcode. A wider value has
/// nowhere to go, and masking one down would put a key id on the wire that the
/// caller did not ask for — answered, like every other malformed packet, with
/// silence. So the type simply cannot hold one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyId(u8);

impl KeyId {
    /// The original key of a session. Zero means *first*, which is why
    /// [`KeyId::next`] never returns here.
    pub const FIRST: KeyId = KeyId(0);

    /// `None` if the value does not fit in three bits.
    pub fn new(value: u8) -> Option<Self> {
        (value <= KEY_ID_MASK).then_some(Self(value))
    }

    pub fn get(self) -> u8 {
        self.0
    }

    /// The next generation, as a renegotiation would number it.
    ///
    /// Counts up to 7 and then recycles to **1**, not to 0: both ends use a
    /// key id of 0 to recognise the original key, so reusing it after a
    /// renegotiation would make a fresh key indistinguishable from the first
    /// one. A tunnel that outlives `reneg-sec` — any large copy — walks this
    /// cycle for real.
    pub fn next(self) -> Self {
        match (self.0 + 1) & KEY_ID_MASK {
            0 => Self(1),
            next => Self(next),
        }
    }
}

/// Acknowledgements, and the session they belong to.
///
/// The two travel together on the wire — the peer's session id is written only
/// when there is at least one id to acknowledge — so they are one field here.
/// Splitting them would let a caller build a packet with acks and no session,
/// which is not a thing that exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acks {
    ids: Vec<u32>,
    session_id: SessionId,
}

impl Acks {
    /// A packet carries at most this many acknowledgements
    /// (`RELIABLE_ACK_SIZE`). The count is one byte, so a longer list would
    /// not merely be rejected — past 255 it would wrap and describe a packet
    /// that is not the one being sent.
    pub const MAX: usize = 8;

    pub fn new(ids: Vec<u32>, session_id: SessionId) -> Result<Self, Error> {
        if ids.len() > Self::MAX {
            return Err(Error::TooManyAcks { count: ids.len() });
        }
        Ok(Self { ids, session_id })
    }

    /// Message ids being acknowledged. Never longer than [`Acks::MAX`].
    pub fn ids(&self) -> &[u32] {
        &self.ids
    }

    /// The session those ids were seen on: the peer's.
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }
}

/// A decoded control packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlPacket {
    pub opcode: Opcode,
    /// Which key generation this belongs to.
    pub key_id: KeyId,
    /// The sender's session id.
    pub session_id: SessionId,
    /// Acknowledgements riding along on this packet, if any.
    pub acks: Option<Acks>,
    /// This packet's own message id. `None` on `P_ACK_V1`.
    pub packet_id: Option<u32>,
    /// TLS ciphertext, or empty.
    pub payload: Vec<u8>,
}

impl ControlPacket {
    /// The opcode/key-id byte and session id, which the `tls-auth` envelope
    /// has to put in front of the HMAC even though the HMAC covers them.
    pub(crate) fn encode_prefix(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + SessionId::LEN);
        out.push(((self.opcode as u8) << OPCODE_SHIFT) | self.key_id.get());
        out.extend_from_slice(self.session_id.as_bytes());
        out
    }

    /// Everything after the envelope: acks, message id, payload.
    pub(crate) fn encode_tail(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + SessionId::LEN + 4 + self.payload.len());
        match &self.acks {
            Some(acks) => {
                // `Acks` cannot be longer than `Acks::MAX`, which is 8.
                out.push(acks.ids.len() as u8);
                for id in &acks.ids {
                    out.extend_from_slice(&id.to_be_bytes());
                }
                out.extend_from_slice(acks.session_id.as_bytes());
            }
            None => out.push(0),
        }
        if let Some(id) = self.packet_id {
            out.extend_from_slice(&id.to_be_bytes());
        }
        out.extend_from_slice(&self.payload);
        out
    }

    pub(crate) fn decode(prefix: &[u8], tail: &[u8]) -> Result<Self, Error> {
        let header = *prefix.first().ok_or(Error::Truncated {
            context: "an opcode",
        })?;
        let opcode = Opcode::from_u8(header >> OPCODE_SHIFT)?;
        let key_id = KeyId::new(header & KEY_ID_MASK).expect("three masked bits fit in a KeyId");

        let session_id = prefix.get(1..1 + SessionId::LEN).ok_or(Error::Truncated {
            context: "a session id",
        })?;
        let session_id = SessionId::from_bytes(
            session_id
                .try_into()
                .expect("the slice is exactly SessionId::LEN long"),
        );

        let mut cursor = Cursor::new(tail);
        let count = cursor.u8("an ack count")? as usize;
        let acks = if count > 0 {
            let mut ids = Vec::with_capacity(count);
            for _ in 0..count {
                ids.push(cursor.u32("an acknowledged packet id")?);
            }
            // `Acks::new` is what refuses an oversized array, and it refuses
            // it for the same reason OpenVPN's own reader does: a peer that
            // sends nine acks is not a peer we understand.
            Some(Acks::new(ids, cursor.session_id()?)?)
        } else {
            None
        };
        let packet_id = if opcode.carries_packet_id() {
            Some(cursor.u32("a packet id")?)
        } else {
            None
        };

        Ok(Self {
            opcode,
            key_id,
            session_id,
            acks,
            packet_id,
            payload: cursor.rest().to_vec(),
        })
    }
}

/// The opcode occupies the high five bits of the first byte, the key id the
/// low three.
const OPCODE_SHIFT: u8 = 3;
const KEY_ID_MASK: u8 = 0x07;

/// A bounds-checked reader, so a malformed packet is an error and never a
/// panic. This parses attacker-reachable bytes: anyone who can send us a UDP
/// datagram can reach it.
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn take(&mut self, n: usize, context: &'static str) -> Result<&'a [u8], Error> {
        let slice = self
            .bytes
            .get(self.at..self.at + n)
            .ok_or(Error::Truncated { context })?;
        self.at += n;
        Ok(slice)
    }

    fn u8(&mut self, context: &'static str) -> Result<u8, Error> {
        Ok(self.take(1, context)?[0])
    }

    fn u32(&mut self, context: &'static str) -> Result<u32, Error> {
        let bytes = self.take(4, context)?;
        Ok(u32::from_be_bytes(bytes.try_into().expect("four bytes")))
    }

    fn session_id(&mut self) -> Result<SessionId, Error> {
        let bytes = self.take(SessionId::LEN, "an acked session id")?;
        Ok(SessionId::from_bytes(
            bytes.try_into().expect("SessionId::LEN bytes"),
        ))
    }

    fn rest(&self) -> &'a [u8] {
        &self.bytes[self.at..]
    }
}
