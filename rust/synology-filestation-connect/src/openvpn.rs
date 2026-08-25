//! The escalation, carried out.
//!
//! [`Chain`](crate::Chain) decides that SMB needs a tunnel; this is the thing
//! that raises one. It is the only place in the workspace that knows both
//! halves — the decision layer above and the OpenVPN client below — which is
//! why it lives here rather than in either.
//!
//! Nothing about it touches the operating system's network. The tunnel
//! terminates in this process, a userspace TCP stack sits on it, and what
//! comes back out is a byte stream like any other. No tun device, no
//! `CAP_NET_ADMIN`, no privileged helper, no installer component, and no
//! effect on anything else the machine is doing.
//!
//! ## One tunnel per connection
//!
//! Every call raises a fresh one. That sounds wasteful and is the honest
//! shape: the connection is what the caller asked for, an OpenVPN session
//! carries exactly one here, and a session that has died is usually why the
//! caller is asking again. Keeping a tunnel alive between calls would mean
//! deciding when to tear it down, which is a question nothing here can answer
//! and [`Chain`](crate::Chain) already answers in its own terms.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use synology_filestation_openvpn::{credentials, Error as VpnError, Profile, Tunnel as OpenVpn};
use tracing::{debug, info};
use zeroize::Zeroizing;

use crate::{Connection, Tunnel, TunnelUnavailable};

/// The tunnel described by a `.ovpn` profile on disk.
pub struct OpenVpnTunnel {
    /// Where the profile is. Read on each attempt rather than held: it is a
    /// shared secret (it embeds `ta.key`), and the copy on disk is the one
    /// [`ProfileSource`](crate::profile::ProfileSource) keeps current.
    profile: PathBuf,
    username: String,
    password: Zeroizing<String>,
    /// How long the whole thing may take, handshake included.
    patience: Duration,
}

/// Hand-written so the password never reaches a log.
impl std::fmt::Debug for OpenVpnTunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenVpnTunnel")
            .field("profile", &self.profile)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("patience", &self.patience)
            .finish()
    }
}

impl OpenVpnTunnel {
    pub fn new(
        profile: impl Into<PathBuf>,
        username: impl Into<String>,
        password: impl Into<String>,
        patience: Duration,
    ) -> Self {
        Self {
            profile: profile.into(),
            username: username.into(),
            password: Zeroizing::new(password.into()),
            patience,
        }
    }

    /// Raise a tunnel and open a connection through it, by `deadline`.
    async fn raise(
        &self,
        host: Ipv4Addr,
        port: u16,
        deadline: tokio::time::Instant,
    ) -> Result<Connection, TunnelUnavailable> {
        let text = Zeroizing::new(read_profile(&self.profile).await?);
        let profile = Profile::parse(&text).map_err(|e| {
            TunnelUnavailable::Transient(format!(
                "the vpn profile is not one this client can use: {e}"
            ))
        })?;

        let server = profile.remote.clone();
        let dial = (profile.remote.clone(), profile.port);
        let config = profile
            .into_config(Some(credentials(
                self.username.clone(),
                self.password.to_string(),
            )))
            .map_err(|e| {
                TunnelUnavailable::Transient(format!("the vpn profile is incomplete: {e}"))
            })?;

        // Resolved here rather than inside the tunnel, so a name that does not
        // resolve is reported as what it is rather than as a handshake nobody
        // answered.
        let resolved = tokio::net::lookup_host(dial).await.map_err(|e| {
            TunnelUnavailable::Transient(format!("cannot resolve the vpn server {server}: {e}"))
        })?;
        let remote = pick_address(resolved).ok_or_else(|| {
            TunnelUnavailable::Transient(format!("the vpn server {server} resolves to nothing"))
        })?;

        debug!("tunnel: raising one to {server} for {host}:{port}");
        let tunnel = OpenVpn::connect(config, remote).await.map_err(|e| {
            let why = format!("the vpn tunnel to {server} did not come up: {e}");
            // A rejected password is not a blip. Every attempt is a real
            // authentication against the domain controller, so a chain that
            // re-probes on a timer works its way to a locked account.
            match e {
                VpnError::AuthFailed(_) => TunnelUnavailable::Refused(why),
                _ => TunnelUnavailable::Transient(why),
            }
        })?;

        // What is left of the budget, not the whole of it again. Handing the
        // full patience here means the outer bound always fires first, so
        // every failure is reported as the tunnel not coming up — erasing the
        // difference between a tunnel that never came up and a NAS not
        // listening behind one, which is the difference this layer exists to
        // draw.
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let stream = tunnel.open_stream((host, port), left).await.map_err(|e| {
            TunnelUnavailable::Transient(format!(
                "the tunnel is up, but nothing answered at {host}:{port} inside it: {e}"
            ))
        })?;

        info!("tunnel: up, and {host}:{port} answered through it");
        Ok(Box::new(stream))
    }
}

#[async_trait]
impl Tunnel for OpenVpnTunnel {
    async fn open(&self, host: &str, port: u16) -> Result<Connection, TunnelUnavailable> {
        // An address, not a name. The tunnel pushes no DNS by design, so a
        // name here would be resolved against the network the tunnel exists to
        // get around — which either fails, or succeeds and points somewhere
        // else entirely.
        let address: Ipv4Addr = host.parse().map_err(|_| {
            TunnelUnavailable::Transient(format!(
                "{host} is not an address, and a tunnel that pushes no DNS has no way to \
                 make it one"
            ))
        })?;

        // The trait asks for a bounded wait, and this is where it is bounded:
        // the pieces below have their own deadlines, but nothing until here
        // knows how long the whole thing may take.
        // A backstop, not the mechanism: the steps inside share this deadline
        // and each says what it was doing, so this only fires if one of them
        // fails to bound itself.
        let deadline = tokio::time::Instant::now() + self.patience;
        match tokio::time::timeout_at(deadline, self.raise(address, port, deadline)).await {
            Ok(outcome) => outcome,
            Err(_) => Err(TunnelUnavailable::Transient(format!(
                "the vpn tunnel did not come up within {:?}",
                self.patience
            ))),
        }
    }
}

/// Which of a name's addresses to dial.
///
/// IPv4 first, then whatever there is. Not a preference about protocols: the
/// resolver's order is its own business, and a AAAA record in front of a
/// working A record would otherwise fail the whole escalation on a machine
/// with no IPv6 route — which describes most of the networks somebody is on
/// when they need this at all.
fn pick_address(resolved: impl Iterator<Item = SocketAddr>) -> Option<SocketAddr> {
    let mut first = None;
    for address in resolved {
        if address.is_ipv4() {
            return Some(address);
        }
        first.get_or_insert(address);
    }
    first
}

/// The profile's text, with a failure that names the file.
async fn read_profile(path: &Path) -> Result<String, TunnelUnavailable> {
    tokio::fs::read_to_string(path).await.map_err(|e| {
        TunnelUnavailable::Transient(format!(
            "cannot read the vpn profile at {}: {e}",
            path.display()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(text: &str) -> SocketAddr {
        text.parse().expect("an address")
    }

    #[test]
    fn an_ipv4_address_is_preferred_wherever_it_comes_in_the_list() {
        // A resolver answering with the AAAA record first is ordinary. On a
        // machine with no IPv6 route, taking whatever came first fails the
        // whole escalation with a working A record sitting right behind it.
        let resolved = [addr("[2001:db8::1]:1194"), addr("10.0.0.1:1194")];

        assert_eq!(
            pick_address(resolved.into_iter()),
            Some(addr("10.0.0.1:1194"))
        );
    }

    #[test]
    fn an_ipv6_only_name_is_still_dialled() {
        // Preferring one is not refusing the other: a server that really is
        // v6-only should be tried, not skipped.
        let resolved = [addr("[2001:db8::1]:1194")];

        assert_eq!(
            pick_address(resolved.into_iter()),
            Some(addr("[2001:db8::1]:1194"))
        );
    }

    #[test]
    fn a_name_that_resolves_to_nothing_has_nothing_to_dial() {
        assert_eq!(pick_address(std::iter::empty()), None);
    }
}
