//! What the server tells us after it has accepted us.
//!
//! Once the key exchange is done the client sends `PUSH_REQUEST`, and the
//! server answers with a comma-separated list of directives:
//!
//! ```text
//! PUSH_REPLY,ifconfig 10.90.24.6 255.255.255.0,peer-id 3,cipher AES-256-CBC,ping 10,ping-restart 60
//! ```
//!
//! Three of those matter to us. The **peer id** is what makes a data packet
//! `P_DATA_V2` instead of `P_DATA_V1`. The **cipher** is the one the server
//! actually chose, which need not be the one we asked for — e4e-nas is
//! configured with `encryption AUTO`, so this is where we would learn it had
//! picked something else. And **ping** is how often we have to prove we are
//! still here, with `ping-restart` the deadline by which the server gives up
//! on us.
//!
//! Everything else is kept but unused. A route we cannot install and an
//! address we do not assign to an interface are not our business: the tunnel
//! terminates inside this process and carries one connection to one port.

use std::net::Ipv4Addr;
use std::time::Duration;

use crate::data::PeerId;
use crate::Error;

/// The request that asks for all this. NUL-terminated on the wire, like every
/// control-channel string.
pub const PUSH_REQUEST: &str = "PUSH_REQUEST";

/// The cipher this client implements.
///
/// A server that chooses another one is not a server we can talk to, and
/// saying so is much better than encrypting with the wrong algorithm and
/// watching every packet be dropped in silence.
pub const SUPPORTED_CIPHER: &str = "AES-256-CBC";

/// What the server pushed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PushReply {
    /// Present when the server assigns one, which a `--mode server` peer does
    /// and a point-to-point peer does not.
    pub peer_id: Option<PeerId>,
    /// The data-channel cipher the server settled on.
    pub cipher: Option<String>,
    /// Our address inside the tunnel, and the mask or peer beside it.
    pub ifconfig: Option<(Ipv4Addr, Ipv4Addr)>,
    /// How often to send a keepalive.
    pub ping: Option<Duration>,
    /// How long the server will wait before concluding we have gone.
    pub ping_restart: Option<Duration>,
    /// A compression directive, if the server pushed one.
    ///
    /// Compression is not a detail of the payload — it prepends a byte to
    /// every packet and changes the framing, exactly as a different cipher
    /// would. This client implements none, so a server that enables it is one
    /// we cannot talk to.
    pub compression: Option<String>,
    /// Every directive, in the order they arrived, including the ones above.
    pub directives: Vec<String>,
}

impl PushReply {
    /// Parse a `PUSH_REPLY` string, without its trailing NUL.
    pub fn parse(reply: &str) -> Result<Self, Error> {
        let body = reply
            .strip_prefix("PUSH_REPLY")
            .ok_or_else(|| Error::UnexpectedControlMessage(reply.to_string()))?
            // A reply with nothing to say is `PUSH_REPLY` alone; one with
            // anything to say separates it with a comma.
            .strip_prefix(',')
            .unwrap_or("");

        let mut parsed = Self::default();
        for directive in body.split(',').map(str::trim).filter(|d| !d.is_empty()) {
            parsed.directives.push(directive.to_string());

            let mut words = directive.split_whitespace();
            let (Some(name), rest) = (words.next(), words.collect::<Vec<_>>()) else {
                continue;
            };

            match (name, rest.as_slice()) {
                ("peer-id", [id]) => {
                    let value: u32 = id
                        .parse()
                        .map_err(|_| Error::BadPushDirective(directive.to_string()))?;
                    parsed.peer_id = Some(
                        PeerId::new(value)
                            .ok_or_else(|| Error::BadPushDirective(directive.to_string()))?,
                    );
                }
                ("cipher", [name]) => parsed.cipher = Some((*name).to_string()),
                ("ifconfig", [address, mask]) => {
                    let address = address
                        .parse()
                        .map_err(|_| Error::BadPushDirective(directive.to_string()))?;
                    let mask = mask
                        .parse()
                        .map_err(|_| Error::BadPushDirective(directive.to_string()))?;
                    parsed.ifconfig = Some((address, mask));
                }
                // `comp-lzo no` is the server saying it is *off*, which is
                // the one form that asks nothing of us.
                ("comp-lzo", ["no"]) => {}
                ("comp-lzo" | "compress", _) => parsed.compression = Some(directive.to_string()),
                // Zero is how OpenVPN spells "off". Taken literally it would
                // mean a keepalive that is always due, and a caller polling
                // until there is nothing to send would never get there.
                ("ping", [seconds]) => {
                    parsed.ping = match seconds_from(seconds, directive)? {
                        zero if zero.is_zero() => None,
                        interval => Some(interval),
                    }
                }
                ("ping-restart", [seconds]) => {
                    parsed.ping_restart = Some(seconds_from(seconds, directive)?)
                }
                // Routes, DNS, compression settings and whatever else a server
                // chooses to say. Kept in `directives` and otherwise ignored:
                // this tunnel ends inside one process and carries one
                // connection, so there is nothing to install them on.
                _ => {}
            }
        }

        Ok(parsed)
    }

    /// Whether the server asked for compression we cannot do.
    pub fn compression_is_supported(&self) -> bool {
        self.compression.is_none()
    }

    /// Whether the cipher the server chose is one we can speak.
    ///
    /// A server that pushes no cipher has left the one we negotiated in place.
    pub fn cipher_is_supported(&self) -> bool {
        match &self.cipher {
            None => true,
            Some(cipher) => cipher.eq_ignore_ascii_case(SUPPORTED_CIPHER),
        }
    }
}

fn seconds_from(value: &str, directive: &str) -> Result<Duration, Error> {
    value
        .parse()
        .map(Duration::from_secs)
        .map_err(|_| Error::BadPushDirective(directive.to_string()))
}
