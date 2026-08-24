//! Working out what address we are, from what the server said.
//!
//! `ifconfig` arrives in the push reply as two addresses, and what the second
//! one *means* depends on a setting the server never sends us:
//!
//! * `topology subnet` — the second is a netmask, and we are one host on a
//!   shared subnet.
//! * `topology net30` — the second is the *peer's* address, and we are one end
//!   of a four-address point-to-point block.
//!
//! OpenVPN 2.6 changed the default to `subnet`; 2.5, which is what e4e-nas
//! runs, still defaults to `net30` (`o->topology = TOP_NET30` in
//! `options.c`). So both have to be read, and there is nothing in the reply
//! saying which — only the shape of the second address.
//!
//! A netmask is a run of ones followed by a run of zeroes, and nothing else
//! is. An address that is not one is a peer, because it cannot be a mask. That
//! is a rule about bit patterns rather than a guess: `255.255.255.0` is a mask
//! and `10.90.24.1` is not, and no plausible mask is mistakable for a
//! plausible peer.

use std::net::Ipv4Addr;

/// Where we are on the tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ifconfig {
    /// The address the server gave us.
    pub address: Ipv4Addr,
    /// How much of it is network, in bits.
    pub prefix: u8,
}

impl Ifconfig {
    /// Read the two addresses from a push reply.
    pub fn from_push(address: Ipv4Addr, second: Ipv4Addr) -> Self {
        match prefix_of_netmask(second) {
            Some(prefix) => Self { address, prefix },
            // Not a mask, so it is the peer: a `net30` block, which is always
            // four addresses.
            None => Self {
                address,
                prefix: 30,
            },
        }
    }
}

/// The prefix length of a netmask, if that is what this is.
///
/// `None` for anything that is not a contiguous run of ones — which is what
/// tells a mask from a peer address.
fn prefix_of_netmask(candidate: Ipv4Addr) -> Option<u8> {
    let bits = u32::from_be_bytes(candidate.octets());
    let ones = bits.leading_ones();
    // Everything after the leading ones must be zero, or it is not a mask.
    // `0.0.0.0` is not one either: a mask of nothing is not something a
    // server sends.
    // `checked_shl` rather than `wrapping_shl`: shifting a `u32` by 32 wraps
    // to shifting by nothing, so `255.255.255.255` would test as leaving bits
    // behind and be read as a peer address.
    if ones == 0 || bits.checked_shl(ones).unwrap_or(0) != 0 {
        return None;
    }
    Some(ones as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_contiguous_mask_is_read_as_one() {
        for (mask, prefix) in [
            ([255, 255, 255, 0], 24),
            ([255, 255, 255, 252], 30),
            ([255, 255, 0, 0], 16),
            ([255, 255, 255, 255], 32),
            ([128, 0, 0, 0], 1),
        ] {
            assert_eq!(prefix_of_netmask(mask.into()), Some(prefix), "{mask:?}");
        }
    }

    #[test]
    fn an_address_that_is_not_a_mask_is_not_read_as_one() {
        // The point of the rule: these are the second value under `net30`,
        // and reading one as a mask would put us on the wrong subnet.
        for peer in [
            [10, 90, 24, 1],
            [10, 90, 24, 5],
            [192, 168, 1, 1],
            [0, 0, 0, 0],
            // A run of ones with a gap in it. Not a mask, however much it
            // looks like one at a glance.
            [255, 255, 0, 255],
        ] {
            assert_eq!(prefix_of_netmask(peer.into()), None, "{peer:?}");
        }
    }
}
