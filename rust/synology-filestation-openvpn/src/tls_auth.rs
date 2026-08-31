//! The `tls-auth` envelope: an HMAC over every control packet, checked before
//! the server will do any TLS work at all.
//!
//! On the wire the HMAC sits *behind* the opcode and session id:
//!
//! ```text
//! opcode | session id | HMAC | packet id | net time | acks | packet id | payload
//! ```
//!
//! but it is computed over a different order — the packet id and timestamp
//! first, then everything else in wire order:
//!
//! ```text
//! packet id | net time | opcode | session id | acks | packet id | payload
//! ```
//!
//! OpenVPN calls the rearrangement `swap_hmac` and does it so the same
//! encrypt/decrypt path can serve both the control and data channels. There is
//! no cryptographic content to it; it just has to match exactly, and it is the
//! sort of detail that is invisible when it is wrong, because the far end
//! answers a bad HMAC with silence.

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::packet::{ControlPacket, SessionId};
use crate::static_key::{KeyDirection, StaticKey};
use crate::Error;

/// SHA-512, matching `auth SHA512` in the published `.ovpn`.
///
/// Hardcoded rather than negotiated: the digest is not something the protocol
/// agrees on, it is something both ends are configured with, and ours is
/// configured by the same repository that configures the server. A second
/// digest can be added the day a second server needs one.
type ControlHmac = Hmac<Sha512>;
const HMAC_LEN: usize = 64;

/// The replay fields OpenVPN prefixes to each authenticated packet.
///
/// This is a *separate* sequence from the message id inside
/// [`ControlPacket::packet_id`]: it counts datagrams sent, so a retransmission
/// of the same message advances it. That is what lets the far end drop
/// replays without also dropping honest retransmissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsAuthHeader {
    /// Monotonic counter over datagrams sent on this key.
    pub packet_id: u32,
    /// The sender's clock, seconds since the epoch, truncated to 32 bits.
    pub net_time: u32,
}

/// Signs outgoing control packets and verifies incoming ones.
///
/// Note what this does *not* do: it has no replay window. Rejecting a packet
/// id we have already seen needs state that belongs with the session, next to
/// the reliability layer that is also tracking ids — putting a second,
/// disagreeing notion of "seen" here would be worse than having none.
pub struct TlsAuth {
    /// Copied out of the [`StaticKey`], and zeroized on drop for the same
    /// reason it is: a key that outlives its owner in freed memory is still a
    /// key.
    out_key: Zeroizing<Vec<u8>>,
    in_key: Zeroizing<Vec<u8>>,
}

impl TlsAuth {
    /// `direction` is the local end's `key-direction`: [`KeyDirection::Inverse`]
    /// for a client whose config says `key-direction 1`.
    pub fn new(key: &StaticKey, direction: KeyDirection) -> Self {
        Self {
            out_key: Zeroizing::new(key.out_hmac(direction).to_vec()),
            in_key: Zeroizing::new(key.in_hmac(direction).to_vec()),
        }
    }

    /// Produce the bytes to put in a datagram.
    pub fn wrap(&self, packet: &ControlPacket, packet_id: u32, net_time: u32) -> Vec<u8> {
        let prefix = packet.encode_prefix();
        let tail = packet.encode_tail();

        let mut signed = Vec::with_capacity(8 + prefix.len() + tail.len());
        signed.extend_from_slice(&packet_id.to_be_bytes());
        signed.extend_from_slice(&net_time.to_be_bytes());
        signed.extend_from_slice(&prefix);
        signed.extend_from_slice(&tail);

        let mac = self.sign(&self.out_key, &signed);

        let mut wire = Vec::with_capacity(prefix.len() + HMAC_LEN + 8 + tail.len());
        wire.extend_from_slice(&prefix);
        wire.extend_from_slice(&mac);
        wire.extend_from_slice(&packet_id.to_be_bytes());
        wire.extend_from_slice(&net_time.to_be_bytes());
        wire.extend_from_slice(&tail);
        wire
    }

    /// Verify a datagram and decode what it carried.
    ///
    /// The HMAC is checked before anything is interpreted, so a packet from a
    /// scanner costs one hash and nothing else.
    pub fn unwrap(&self, datagram: &[u8]) -> Result<(ControlPacket, TlsAuthHeader), Error> {
        const PREFIX_LEN: usize = 1 + SessionId::LEN;
        const REPLAY_LEN: usize = 8;

        let prefix = datagram.get(..PREFIX_LEN).ok_or(Error::Truncated {
            context: "an opcode and session id",
        })?;
        let mac = datagram
            .get(PREFIX_LEN..PREFIX_LEN + HMAC_LEN)
            .ok_or(Error::Truncated {
                context: "a tls-auth HMAC",
            })?;
        let replay = datagram
            .get(PREFIX_LEN + HMAC_LEN..PREFIX_LEN + HMAC_LEN + REPLAY_LEN)
            .ok_or(Error::Truncated {
                context: "a tls-auth packet id",
            })?;
        let tail = &datagram[PREFIX_LEN + HMAC_LEN + REPLAY_LEN..];

        let mut signed = Vec::with_capacity(REPLAY_LEN + prefix.len() + tail.len());
        signed.extend_from_slice(replay);
        signed.extend_from_slice(prefix);
        signed.extend_from_slice(tail);

        self.verify(&self.in_key, &signed, mac)?;

        let header = TlsAuthHeader {
            packet_id: u32::from_be_bytes(replay[..4].try_into().expect("four bytes")),
            net_time: u32::from_be_bytes(replay[4..].try_into().expect("four bytes")),
        };
        Ok((ControlPacket::decode(prefix, tail)?, header))
    }

    fn sign(&self, key: &[u8], message: &[u8]) -> [u8; HMAC_LEN] {
        let mut mac = ControlHmac::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(message);
        mac.finalize().into_bytes().into()
    }

    fn verify(&self, key: &[u8], message: &[u8], expected: &[u8]) -> Result<(), Error> {
        let mut mac = ControlHmac::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(message);
        mac.verify_slice(expected).map_err(|_| Error::BadHmac)
    }
}

/// Never let a key reach a log line.
impl std::fmt::Debug for TlsAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TlsAuth(<redacted>)")
    }
}
