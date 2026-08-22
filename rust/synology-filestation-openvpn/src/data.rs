//! The data channel: the tunnel's actual payload.
//!
//! Everything until now has been arranging for two keys to exist. This is
//! what they are for. A `P_DATA_V2` packet, as e4e-nas is configured
//! (`AES-256-CBC` with `SHA512`), looks like this:
//!
//! ```text
//! opcode<<3 | key id   (1)
//! peer id              (3)   assigned by the server
//! HMAC-SHA-512         (64)  over the IV and ciphertext, nothing else
//! IV                   (16)  fresh per packet
//! ciphertext           (…)   AES-256-CBC over: packet id (4) ‖ payload
//! ```
//!
//! Two details that are easy to get wrong and impossible to debug once wrong,
//! because both ends answer a bad packet with silence:
//!
//! * the packet id is *inside* the encryption, not beside it — it is prepended
//!   to the plaintext before the cipher runs, in the short four-byte form
//!   (`CO_PACKET_ID_LONG_FORM` belongs to static-key mode, not to us);
//! * the HMAC covers the IV and ciphertext but **not** the opcode and peer id
//!   in front of them. OpenVPN's comment at that prepend says the opcode is
//!   authenticated, which is true of the AEAD path and not of this one.
//!
//! The key material is split the way OpenVPN splits it: a client uses slot 0
//! to send and slot 1 to receive (`KEY_DIRECTION_NORMAL`), and a server does
//! the reverse. Getting that backwards produces a tunnel where each end
//! encrypts perfectly and neither can read anything.

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::packet::{KeyId, Opcode};
use crate::replay::ReplayWindow;
use crate::Error;

type Encryptor = cbc::Encryptor<aes::Aes256>;
type Decryptor = cbc::Decryptor<aes::Aes256>;

/// AES-256 takes 32 bytes of each 64-byte cipher slot.
const CIPHER_KEY_LEN: usize = 32;
/// HMAC-SHA-512 takes all 64 of each HMAC slot.
const HMAC_KEY_LEN: usize = 64;
/// AES has a 16-byte block, and so a 16-byte IV.
const IV_LEN: usize = 16;
/// `P_DATA_V2`: the opcode-and-key-id byte plus a three-byte peer id.
const HEADER_V2_LEN: usize = 4;
/// `P_DATA_V1`: the opcode byte alone.
const HEADER_V1_LEN: usize = 1;

/// The four keys a session derives, sorted into the two we send with and the
/// two we receive with.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DataKeys {
    encrypt_cipher: [u8; CIPHER_KEY_LEN],
    encrypt_hmac: [u8; HMAC_KEY_LEN],
    decrypt_cipher: [u8; CIPHER_KEY_LEN],
    decrypt_hmac: [u8; HMAC_KEY_LEN],
}

impl DataKeys {
    /// A client's view of the 256 bytes from [`crate::key_expansion`]: send
    /// with slot 0, receive with slot 1.
    pub fn for_client(expansion: &[u8]) -> Result<Self, Error> {
        Self::split(expansion, 0, 1)
    }

    /// A server's view — the same material, the slots the other way round.
    /// Only tests need this, and they need it to prove the asymmetry is real.
    pub fn for_server(expansion: &[u8]) -> Result<Self, Error> {
        Self::split(expansion, 1, 0)
    }

    fn split(expansion: &[u8], out_slot: usize, in_slot: usize) -> Result<Self, Error> {
        if expansion.len() < 256 {
            return Err(Error::Truncated {
                context: "a key expansion",
            });
        }
        // Each slot is a 64-byte cipher key followed by a 64-byte HMAC key,
        // and only part of the cipher key is used. The unused tail is what
        // makes room for a larger cipher without changing the derivation.
        let cipher_at = |slot: usize| slot * 128;
        let hmac_at = |slot: usize| slot * 128 + 64;

        let mut keys = Self {
            encrypt_cipher: [0; CIPHER_KEY_LEN],
            encrypt_hmac: [0; HMAC_KEY_LEN],
            decrypt_cipher: [0; CIPHER_KEY_LEN],
            decrypt_hmac: [0; HMAC_KEY_LEN],
        };
        let at = cipher_at(out_slot);
        keys.encrypt_cipher
            .copy_from_slice(&expansion[at..at + CIPHER_KEY_LEN]);
        let at = hmac_at(out_slot);
        keys.encrypt_hmac
            .copy_from_slice(&expansion[at..at + HMAC_KEY_LEN]);
        let at = cipher_at(in_slot);
        keys.decrypt_cipher
            .copy_from_slice(&expansion[at..at + CIPHER_KEY_LEN]);
        let at = hmac_at(in_slot);
        keys.decrypt_hmac
            .copy_from_slice(&expansion[at..at + HMAC_KEY_LEN]);
        Ok(keys)
    }
}

impl std::fmt::Debug for DataKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DataKeys(<redacted>)")
    }
}

/// One direction pair of a tunnel: encrypt outgoing payloads, decrypt
/// incoming ones.
pub struct DataChannel {
    keys: DataKeys,
    /// The id the server gave us, if it gave us one. A server running
    /// `--mode server` assigns one and both ends then use `P_DATA_V2`; a
    /// point-to-point peer assigns none and the packets are `P_DATA_V1`,
    /// which is the same thing without the three bytes.
    peer_id: Option<u32>,
    key_id: KeyId,
    next_packet_id: u32,
    replay: ReplayWindow,
}

impl DataChannel {
    pub fn new(keys: DataKeys, peer_id: Option<u32>, key_id: KeyId) -> Self {
        Self {
            keys,
            peer_id,
            key_id,
            // OpenVPN numbers data packets from one, as it does everywhere
            // else: zero is reserved to mean "no packet".
            next_packet_id: 1,
            replay: ReplayWindow::new(),
        }
    }

    /// Wrap a payload into a datagram.
    pub fn encrypt(&mut self, payload: &[u8], iv: [u8; IV_LEN]) -> Result<Vec<u8>, Error> {
        let packet_id = self.next_packet_id;
        self.next_packet_id = self
            .next_packet_id
            .checked_add(1)
            .ok_or(Error::PacketIdExhausted)?;

        // The packet id goes inside the encryption, ahead of the payload.
        let mut plaintext = Zeroizing::new(Vec::with_capacity(4 + payload.len()));
        plaintext.extend_from_slice(&packet_id.to_be_bytes());
        plaintext.extend_from_slice(payload);

        let ciphertext = Encryptor::new(&self.keys.encrypt_cipher.into(), &iv.into())
            .encrypt_padded_vec_mut::<Pkcs7>(&plaintext);

        let mut mac = <Hmac<Sha512>>::new_from_slice(&self.keys.encrypt_hmac)
            .expect("HMAC accepts any key length");
        mac.update(&iv);
        mac.update(&ciphertext);
        let tag = mac.finalize().into_bytes();

        let mut out = Vec::with_capacity(HEADER_V2_LEN + tag.len() + IV_LEN + ciphertext.len());
        match self.peer_id {
            Some(peer_id) => {
                out.push(((Opcode::DataV2 as u8) << 3) | self.key_id.get());
                out.extend_from_slice(&peer_id.to_be_bytes()[1..]);
            }
            None => out.push(((Opcode::DataV1 as u8) << 3) | self.key_id.get()),
        }
        out.extend_from_slice(&tag);
        out.extend_from_slice(&iv);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Unwrap a datagram, or say why it is not one of ours.
    pub fn decrypt(&mut self, datagram: &[u8]) -> Result<Vec<u8>, Error> {
        // SHA-512, so the tag is 64 bytes.
        let tag_len = HMAC_KEY_LEN;

        let opcode = match datagram.first() {
            Some(&first) => Opcode::from_u8(first >> 3)?,
            None => {
                return Err(Error::Truncated {
                    context: "a data packet",
                })
            }
        };
        // Which of the two forms it is decides where the packet starts, so it
        // has to be read before anything is measured.
        let header_end = match opcode {
            Opcode::DataV2 => HEADER_V2_LEN,
            Opcode::DataV1 => HEADER_V1_LEN,
            other => return Err(Error::UnexpectedDataOpcode(other)),
        };
        let tag_end = header_end + tag_len;
        let iv_end = tag_end + IV_LEN;

        if datagram.len() <= iv_end {
            return Err(Error::Truncated {
                context: "a data packet",
            });
        }

        // Authenticate before interpreting anything: the HMAC is the only
        // reason to believe any of the rest.
        let mut mac = <Hmac<Sha512>>::new_from_slice(&self.keys.decrypt_hmac)
            .expect("HMAC accepts any key length");
        mac.update(&datagram[tag_end..]);
        mac.verify_slice(&datagram[header_end..tag_end])
            .map_err(|_| Error::BadHmac)?;

        let iv: [u8; IV_LEN] = datagram[tag_end..iv_end]
            .try_into()
            .expect("the slice is exactly IV_LEN long");
        let plaintext = Zeroizing::new(
            Decryptor::new(&self.keys.decrypt_cipher.into(), &iv.into())
                .decrypt_padded_vec_mut::<Pkcs7>(&datagram[iv_end..])
                .map_err(|_| Error::BadPadding)?,
        );

        if plaintext.len() < 4 {
            return Err(Error::Truncated {
                context: "a packet id",
            });
        }
        let packet_id = u32::from_be_bytes(plaintext[..4].try_into().expect("four bytes"));

        // The data channel's ids carry no timestamp — that is the long form,
        // and this is the short one — so the window is told a constant time
        // and does its work on the sequence alone.
        if !self.replay.accept(packet_id, 0) {
            return Err(Error::Replayed);
        }

        Ok(plaintext[4..].to_vec())
    }
}

impl std::fmt::Debug for DataChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataChannel")
            .field("peer_id", &self.peer_id)
            .field("key_id", &self.key_id)
            .field("next_packet_id", &self.next_packet_id)
            .finish_non_exhaustive()
    }
}

/// The payload OpenVPN sends to say "still here".
///
/// It is a fixed sixteen bytes rather than a protocol message, which is what
/// makes it useful as proof: a tunnel that can produce these bytes from a
/// packet it was handed has the keys, the direction and the framing all right
/// at once.
pub const PING: [u8; 16] = [
    0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48,
];
