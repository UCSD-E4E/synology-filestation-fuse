//! The key exchange that happens inside the TLS session.
//!
//! Once TLS is up, each end sends one message — OpenVPN calls it key method 2
//! — carrying the random material the data-channel keys are derived from, the
//! options string both ends compare, and, for the client, the credentials.
//!
//! ```text
//! u32     0                  (a literal, discarded on the way in)
//! u8      2                  key method
//! bytes   pre-master (48)    client only
//! bytes   random1 (32)
//! bytes   random2 (32)
//! string  options
//! string  username           empty when there is none
//! string  password
//! string  peer info
//! ```
//!
//! A "string" is a `u16` length followed by that many bytes, the last of which
//! is a NUL that the length counts. An empty one is a length of zero and no
//! bytes — not a length of one and a NUL, which is the sort of detail that
//! costs an afternoon.
//!
//! Nothing here is length-framed as a whole: the message ends where its last
//! field ends, and TLS gives us a stream rather than records, so a reader has
//! to be able to say "not yet" as well as "no". That is why decoding
//! distinguishes [`Error::Truncated`] from everything else.

use zeroize::Zeroizing;

use crate::prf::KeySource2;
use crate::Error;

/// OpenVPN's key method 2, the only one still in use.
const KEY_METHOD_2: u8 = 2;

/// What the client sends.
pub struct ClientKeyMethod2<'a> {
    pub source: &'a KeySource2,
    /// The options string, which the peer compares against its own and
    /// complains about rather than refuses.
    pub options: &'a str,
    pub username: &'a str,
    pub password: &'a Zeroizing<String>,
    /// `IV_` lines describing what this client supports.
    pub peer_info: &'a str,
}

impl ClientKeyMethod2<'_> {
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        // Sized up front, before a single secret byte goes in. A growing
        // `Vec` reallocates, and each reallocation copies the pre-master and
        // the password into a new block and frees the old one without
        // clearing it — so wrapping the finished buffer in `Zeroizing` would
        // protect the one copy that is easiest to find.
        let mut out = Vec::with_capacity(
            4 + 1
                + 48
                + 32
                + 32
                + 2 * 4
                + self.options.len()
                + self.username.len()
                + self.password.len()
                + self.peer_info.len()
                + 4,
        );
        out.extend_from_slice(&0u32.to_be_bytes());
        out.push(KEY_METHOD_2);
        out.extend_from_slice(&self.source.pre_master);
        out.extend_from_slice(&self.source.client_random1);
        out.extend_from_slice(&self.source.client_random2);
        write_string(&mut out, self.options, "the options string")?;
        write_string(&mut out, self.username, "the username")?;
        write_string(&mut out, self.password, "the password")?;
        write_string(&mut out, self.peer_info, "the peer info")?;
        Ok(Zeroizing::new(out))
    }
}

/// Whatever the server sent us over the TLS session.
///
/// It is not always key material. If authentication fails — the likeliest
/// outcome of a mistyped password, and the one a user will actually meet —
/// the server sends `AUTH_FAILED` as text instead. Reading that as a key
/// method turns "wrong password" into "peer offered key method 95", which
/// tells the person at the keyboard nothing.
///
/// The two are easy to tell apart: a key method begins with four zero bytes,
/// and a control message begins with printable text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerMessage {
    KeyMethod2(ServerKeyMethod2),
    /// A NUL-terminated control message, such as `AUTH_FAILED`.
    Control(String),
}

impl ServerMessage {
    /// Decode one message, and say how many bytes it used.
    ///
    /// The length matters: a flight can carry more than one message, and a
    /// caller that keeps the remainder needs to know where to resume.
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize), Error> {
        if bytes.len() < 4 {
            return Err(Error::Truncated {
                context: "a message header",
            });
        }

        if bytes[..4] != [0, 0, 0, 0] {
            let end = bytes
                .iter()
                .position(|&byte| byte == 0)
                .ok_or(Error::Truncated {
                    context: "a control message",
                })?;
            let text = String::from_utf8_lossy(&bytes[..end]).into_owned();
            return Ok((Self::Control(text), end + 1));
        }

        let (key_method, used) = ServerKeyMethod2::decode(bytes)?;
        Ok((Self::KeyMethod2(key_method), used))
    }
}

/// What the server sends back: its own random material and its options.
///
/// No pre-master — only the client contributes one, and that asymmetry is what
/// makes the two directions' key material different.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerKeyMethod2 {
    pub random1: [u8; 32],
    pub random2: [u8; 32],
    pub options: String,
}

impl ServerKeyMethod2 {
    /// Decode the server's reply, or say why not.
    ///
    /// [`Error::Truncated`] means "not yet": TLS delivers a stream, so a
    /// caller that has not read the whole message must be able to tell that
    /// apart from a message it will never be able to read.
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize), Error> {
        let mut reader = Reader::new(bytes);

        reader.take(4, "the leading zero")?;
        let method = reader.take(1, "a key method")?[0];
        if method != KEY_METHOD_2 {
            return Err(Error::UnsupportedKeyMethod(method));
        }

        let random1 = reader.array("the server's first random")?;
        let random2 = reader.array("the server's second random")?;
        let options = reader.string("the options string")?;

        Ok((
            Self {
                random1,
                random2,
                options,
            },
            reader.at,
        ))
    }
}

/// A `u16` length — counting the trailing NUL — and then the bytes.
///
/// An empty string is a zero length and nothing else — OpenVPN writes those
/// through a separate `write_empty_string`, which is why the two cases do not
/// look alike on the wire.
fn write_string(out: &mut Vec<u8>, value: &str, context: &'static str) -> Result<(), Error> {
    if value.is_empty() {
        out.extend_from_slice(&0u16.to_be_bytes());
        return Ok(());
    }
    // The length is a `u16`, so a longer value cannot be described. Truncating
    // it would produce a message that parses and means something else, which
    // is worse than refusing to send one.
    let len = u16::try_from(value.len() + 1).map_err(|_| Error::FieldTooLong { context })?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    out.push(0);
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
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

    fn array<const N: usize>(&mut self, context: &'static str) -> Result<[u8; N], Error> {
        Ok(self
            .take(N, context)?
            .try_into()
            .expect("the slice is exactly N long"))
    }

    fn string(&mut self, context: &'static str) -> Result<String, Error> {
        let len = u16::from_be_bytes(self.array::<2>(context)?) as usize;
        if len == 0 {
            return Ok(String::new());
        }
        let bytes = self.take(len, context)?;
        // The length counts a trailing NUL. Trimming rather than requiring it:
        // what the string says matters here, and a peer that miscounts by one
        // is not a reason to abandon a working session.
        let text = bytes.strip_suffix(&[0]).unwrap_or(bytes);
        Ok(String::from_utf8_lossy(text).into_owned())
    }
}
