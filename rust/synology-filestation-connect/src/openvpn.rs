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

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use synology_filestation_openvpn::{credentials, Profile, Tunnel as OpenVpn};
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

    /// Raise a tunnel and open a connection through it, however long that
    /// takes.
    async fn raise(&self, host: Ipv4Addr, port: u16) -> Result<Connection, TunnelUnavailable> {
        let text = Zeroizing::new(read_profile(&self.profile).await?);
        let profile = Profile::parse(&text).map_err(|e| {
            TunnelUnavailable(format!(
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
            .map_err(|e| TunnelUnavailable(format!("the vpn profile is incomplete: {e}")))?;

        // Resolved here rather than inside the tunnel, so a name that does not
        // resolve is reported as what it is rather than as a handshake nobody
        // answered.
        let remote = tokio::net::lookup_host(dial)
            .await
            .map_err(|e| TunnelUnavailable(format!("cannot resolve the vpn server {server}: {e}")))?
            .next()
            .ok_or_else(|| {
                TunnelUnavailable(format!("the vpn server {server} resolves to nothing"))
            })?;

        debug!("tunnel: raising one to {server} for {host}:{port}");
        let tunnel = OpenVpn::connect(config, remote).await.map_err(|e| {
            TunnelUnavailable(format!("the vpn tunnel to {server} did not come up: {e}"))
        })?;

        // The same patience again, which is not the same as what is left of
        // it — the outer bound in `open` is what actually stops this, and this
        // one only keeps the stack from waiting forever if that ever changes.
        let stream = tunnel
            .open_stream((host, port), self.patience)
            .await
            .map_err(|e| {
                TunnelUnavailable(format!(
                    "nothing answered at {host}:{port} inside the tunnel: {e}"
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
            TunnelUnavailable(format!(
                "{host} is not an address, and a tunnel that pushes no DNS has no way to \
                 make it one"
            ))
        })?;

        // The trait asks for a bounded wait, and this is where it is bounded:
        // the pieces below have their own deadlines, but nothing until here
        // knows how long the whole thing may take.
        match tokio::time::timeout(self.patience, self.raise(address, port)).await {
            Ok(outcome) => outcome,
            Err(_) => Err(TunnelUnavailable(format!(
                "the vpn tunnel did not come up within {:?}",
                self.patience
            ))),
        }
    }
}

/// The profile's text, with a failure that names the file.
async fn read_profile(path: &Path) -> Result<String, TunnelUnavailable> {
    tokio::fs::read_to_string(path).await.map_err(|e| {
        TunnelUnavailable(format!(
            "cannot read the vpn profile at {}: {e}",
            path.display()
        ))
    })
}
