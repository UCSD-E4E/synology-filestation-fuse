//! An in-process OpenVPN client.
//!
//! e4e-nas terminates an OpenVPN tunnel itself so that off-campus researchers
//! can reach SMB on the appliance and nothing else. Using it should not require
//! a tun device, `CAP_NET_ADMIN`, a privileged helper or an installer
//! component, and it should not touch the rest of the machine's traffic — so
//! this crate speaks the protocol in the same process as the mount, and the
//! bytes it recovers are handed to a userspace TCP stack rather than to the
//! kernel.
//!
//! What is here so far is the control channel's envelope: the static key, the
//! packet framing, and the `tls-auth` HMAC that the server checks *before* it
//! will do any TLS work at all. That ordering is the reason this is the first
//! piece — a client that gets the HMAC wrong does not get an error back, it
//! gets silence.
//!
//! Everything is pinned against packets a real OpenVPN client emitted; see
//! `tests/wire_format.rs`.

mod channel;
mod packet;
mod reliable;
mod static_key;
mod tls_auth;

pub use channel::ControlChannel;
pub use packet::{Acks, ControlPacket, KeyId, Opcode, SessionId};
pub use reliable::{Delivery, Outgoing, RecvWindow, SendWindow};
pub use static_key::{KeyDirection, StaticKey, STATIC_KEY_LEN};
pub use tls_auth::{TlsAuth, TlsAuthHeader};

/// Everything that can go wrong reading a key or a packet.
///
/// Deliberately one enum: the caller's question is always "can I use this?",
/// and splitting it by module would only make them write two `From` impls.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("packet is too short to hold {context}")]
    Truncated {
        /// What we were trying to read when the bytes ran out.
        context: &'static str,
    },

    #[error("unknown packet opcode {0}")]
    UnknownOpcode(u8),

    #[error("a packet carries at most {max} acknowledgements; this one claims {count}", max = crate::Acks::MAX)]
    TooManyAcks {
        /// How many the packet claimed to carry.
        count: usize,
    },

    #[error("packet is not authentic: the tls-auth HMAC does not match")]
    BadHmac,

    #[error("packet belongs to a different session")]
    WrongSession,

    #[error("a static key is {STATIC_KEY_LEN} bytes; this one is {actual}")]
    KeyLength {
        /// How many bytes were actually decoded.
        actual: usize,
    },

    #[error("static key is not hexadecimal")]
    KeyNotHex,

    #[error("no OpenVPN static key found")]
    KeyMissing,
}
