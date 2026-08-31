//! Deriving the data-channel keys.
//!
//! This is the part that decides whether a pure-Rust client is possible at
//! all. OpenVPN 2.5 does **not** derive its data-channel keys from the TLS
//! master secret: it exchanges its own key material inside the TLS session and
//! runs its own PRF over that. A TLS library therefore has to expose nothing
//! beyond the session — no exporter, no internals — which is why `rustls` is
//! enough here where it would not have been for 2.6's `tls-ekm`.
//!
//! The PRF is TLS 1.0's, MD5 and SHA-1 in parallel over the two halves of the
//! secret, exclusive-ored together (RFC 2246 §5). OpenVPN reaches it through
//! OpenSSL's `EVP_md5_sha1`; the tests pin ours against the same OpenSSL.

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use md5::Md5;
use sha1::Sha1;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::packet::SessionId;

/// The random material both ends contribute, as `key_source2` on the wire.
///
/// The client sends the pre-master and its two randoms; the server answers
/// with two randoms of its own and no pre-master. Both sides then hold all of
/// it and derive the same keys without either having sent a key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeySource2 {
    pub pre_master: [u8; 48],
    pub client_random1: [u8; 32],
    pub client_random2: [u8; 32],
    pub server_random1: [u8; 32],
    pub server_random2: [u8; 32],
}

impl Default for KeySource2 {
    fn default() -> Self {
        Self {
            pre_master: [0; 48],
            client_random1: [0; 32],
            client_random2: [0; 32],
            server_random1: [0; 32],
            server_random2: [0; 32],
        }
    }
}

impl KeySource2 {
    /// Fresh client-side material. The server's halves stay zero until it
    /// answers.
    pub fn new_client() -> Self {
        Self {
            pre_master: rand::random(),
            client_random1: rand::random(),
            client_random2: rand::random(),
            server_random1: [0; 32],
            server_random2: [0; 32],
        }
    }
}

/// Never let key material reach a log line.
impl std::fmt::Debug for KeySource2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeySource2(<redacted>)")
    }
}

/// What OpenVPN prefixes to both PRF labels.
const LABEL_PREFIX: &str = "OpenVPN ";

/// The 256 bytes of key material: two directions, each a 64-byte cipher key
/// followed by a 64-byte HMAC key — the same layout a static key file uses.
pub fn key_expansion(
    source: &KeySource2,
    client_session: SessionId,
    server_session: SessionId,
) -> Zeroizing<Vec<u8>> {
    // First the master secret, from the pre-master and the *first* randoms.
    // The seed carries material that came out of the TLS session, so it is
    // cleared with everything else rather than left in a freed allocation.
    // Sized up front for the same reason the message is: growing the buffer
    // reallocates, and the copy left behind by a reallocation is freed
    // without being cleared, which would make the `Zeroizing` decorative.
    let mut seed = Zeroizing::new(Vec::with_capacity(LABEL_PREFIX.len() + 13 + 32 + 32));
    seed.extend_from_slice(LABEL_PREFIX.as_bytes());
    seed.extend_from_slice(b"master secret");
    seed.extend_from_slice(&source.client_random1);
    seed.extend_from_slice(&source.server_random1);

    let mut master = [0u8; 48];
    tls1_prf(&source.pre_master, &seed, &mut master);

    // Then the keys, from the master and the *second* randoms — plus both
    // session ids, which is what stops two sessions between the same pair
    // deriving the same keys.
    let mut seed = Zeroizing::new(Vec::with_capacity(
        LABEL_PREFIX.len() + 13 + 32 + 32 + 2 * SessionId::LEN,
    ));
    seed.extend_from_slice(LABEL_PREFIX.as_bytes());
    seed.extend_from_slice(b"key expansion");
    seed.extend_from_slice(&source.client_random2);
    seed.extend_from_slice(&source.server_random2);
    seed.extend_from_slice(client_session.as_bytes());
    seed.extend_from_slice(server_session.as_bytes());

    let mut keys = Zeroizing::new(vec![0u8; 256]);
    tls1_prf(&master, &seed, &mut keys);

    master.zeroize();
    keys
}

/// The TLS 1.0 PRF: `P_MD5(S1, seed) XOR P_SHA1(S2, seed)`.
///
/// The secret is split in half, and for an odd length the halves overlap by a
/// byte — which never happens here, since everything this crate feeds it is
/// even, but the rule is cheap to keep and expensive to rediscover.
pub fn tls1_prf(secret: &[u8], seed: &[u8], out: &mut [u8]) {
    let half = secret.len().div_ceil(2);
    let s1 = &secret[..half];
    let s2 = &secret[secret.len() - half..];

    p_hash::<Hmac<Md5>>(s1, seed, out);

    let mut sha1_out = Zeroizing::new(vec![0u8; out.len()]);
    p_hash::<Hmac<Sha1>>(s2, seed, &mut sha1_out);

    for (byte, sha1) in out.iter_mut().zip(sha1_out.iter()) {
        *byte ^= sha1;
    }
}

/// `P_hash` from RFC 2246: `HMAC(secret, A(i) + seed)` concatenated, where
/// `A(0) = seed` and `A(i) = HMAC(secret, A(i-1))`.
fn p_hash<M: Mac + KeyInit>(secret: &[u8], seed: &[u8], out: &mut [u8]) {
    // Every intermediate here is key material. `Zeroizing` rather than a
    // final `zeroize()` call, because the loop replaces `a` each round and
    // only the last one would otherwise be cleared.
    let mac = |data: &[&[u8]]| -> Zeroizing<Vec<u8>> {
        let mut hmac = <M as KeyInit>::new_from_slice(secret).expect("HMAC accepts any key length");
        for part in data {
            hmac.update(part);
        }
        Zeroizing::new(hmac.finalize().into_bytes().to_vec())
    };

    let mut a = mac(&[seed]);
    let mut written = 0;

    while written < out.len() {
        let block = mac(&[&a, seed]);
        let take = block.len().min(out.len() - written);
        out[written..written + take].copy_from_slice(&block[..take]);
        written += take;

        a = mac(&[&a]);
    }
}
