//! The `tls-auth` static key, and which half of it we sign with.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Error;

/// An OpenVPN static key is 2048 bits.
pub const STATIC_KEY_LEN: usize = 256;

/// Each of the two directions gets a cipher key and an HMAC key, in that order.
const CIPHER_LEN: usize = 64;
const HMAC_LEN: usize = 64;
const SLOT_LEN: usize = CIPHER_LEN + HMAC_LEN;

const BEGIN: &str = "-----BEGIN OpenVPN Static key V1-----";
const END: &str = "-----END OpenVPN Static key V1-----";

/// The contents of a `tls-auth` key file, or of the `<tls-auth>` block inlined
/// in a `.ovpn`.
///
/// The file holds four 64-byte keys back to back — `keys[0].cipher`,
/// `keys[0].hmac`, `keys[1].cipher`, `keys[1].hmac` — and `tls-auth` uses only
/// the two HMAC halves. The cipher halves are read and kept purely so the
/// layout stays honest; nothing in this crate uses them.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct StaticKey([u8; STATIC_KEY_LEN]);

impl StaticKey {
    /// Take the key material directly. Mostly useful to tests and to callers
    /// that have already decoded a `<tls-auth>` block themselves.
    pub fn from_bytes(bytes: [u8; STATIC_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Decode the bare hexadecimal body — no header lines, no whitespace rules.
    pub fn from_hex(hex: &str) -> Result<Self, Error> {
        let digits: Vec<u8> = hex.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        if !digits.len().is_multiple_of(2) {
            return Err(Error::KeyNotHex);
        }
        if digits.len() / 2 != STATIC_KEY_LEN {
            return Err(Error::KeyLength {
                actual: digits.len() / 2,
            });
        }

        let mut out = [0u8; STATIC_KEY_LEN];
        for (byte, pair) in out.iter_mut().zip(digits.chunks_exact(2)) {
            let hi = hex_digit(pair[0])?;
            let lo = hex_digit(pair[1])?;
            *byte = (hi << 4) | lo;
        }
        Ok(Self(out))
    }

    /// Pull the key out of the surrounding file: the `-----BEGIN …-----` form
    /// that `openvpn --genkey` writes, and that a `.ovpn` inlines verbatim
    /// between `<tls-auth>` tags.
    ///
    /// Comment lines are ignored, which is what makes the generated file and
    /// the inlined block the same input.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let body = text
            .split_once(BEGIN)
            .and_then(|(_, rest)| rest.split_once(END))
            .map(|(body, _)| body)
            .ok_or(Error::KeyMissing)?;

        let hex: String = body
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect();

        Self::from_hex(&hex)
    }

    /// The HMAC key we sign outgoing packets with.
    pub(crate) fn out_hmac(&self, direction: KeyDirection) -> &[u8] {
        self.hmac_slot(direction.out_slot())
    }

    /// The HMAC key the peer signs with, which is what we verify against.
    pub(crate) fn in_hmac(&self, direction: KeyDirection) -> &[u8] {
        self.hmac_slot(direction.in_slot())
    }

    fn hmac_slot(&self, slot: usize) -> &[u8] {
        let start = slot * SLOT_LEN + CIPHER_LEN;
        &self.0[start..start + HMAC_LEN]
    }
}

/// Never print key material, not even redacted-looking fragments of it.
impl std::fmt::Debug for StaticKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StaticKey(<redacted>)")
    }
}

fn hex_digit(byte: u8) -> Result<u8, Error> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(Error::KeyNotHex),
    }
}

/// Which slot of the key each end signs with — `key-direction` in the config.
///
/// The two ends must disagree: the client's `key-direction 1` pairs with the
/// server's `tls-auth ta.key 0`. Get it backwards and the server drops every
/// packet without answering, because dropping unauthenticated packets in
/// silence is the entire point of the mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyDirection {
    /// `key-direction 0` — sign with slot 0, verify slot 1. The server's side
    /// of the published `e4e-nas-vpn.ovpn`.
    Normal,
    /// `key-direction 1` — sign with slot 1, verify slot 0. Our side.
    Inverse,
    /// No `key-direction` at all: both ends use slot 0 for everything.
    Bidirectional,
}

impl KeyDirection {
    fn out_slot(self) -> usize {
        match self {
            KeyDirection::Normal | KeyDirection::Bidirectional => 0,
            KeyDirection::Inverse => 1,
        }
    }

    fn in_slot(self) -> usize {
        match self {
            KeyDirection::Normal => 1,
            KeyDirection::Inverse | KeyDirection::Bidirectional => 0,
        }
    }
}
