//! Which way to reach the NAS, and when to look again.
//!
//! Three legs, best first: SMB straight to the appliance, SMB through a
//! tunnel, and the HTTP FileStation API. They are not equivalent — SMB
//! addresses byte ranges, so a write that dies at 540 MiB resumes at 540 MiB,
//! while the HTTP upload has no resume and loses the file. The chain exists so
//! a user on a network that blocks port 445 still gets their file across,
//! without everyone else paying for that.
//!
//! ## The shape of the decision
//!
//! A tunnel is not a peer of the other two: it is a *precondition* that can
//! make SMB reachable. So `--disable-vpn` does not remove a transport, it
//! forbids the escalation, and a user on a locked-down network falls straight
//! from SMB to HTTP with no tunnel dialog.
//!
//! ## Why the choice is cached
//!
//! Every operation asks which transport to use, and probing per operation
//! would put a TCP connect in front of every `stat`. So the answer is decided
//! once and cached, and the cache expires **only while degraded**: sitting on
//! the best leg there is nothing better to find, so nothing is probed and
//! steady state costs nothing. Demotion does not wait for the cache — a
//! backend that starts failing trips its own circuit breaker in
//! `synology-filestation-core`, which is what makes a dead link cheap instead
//! of a ten-second timeout per call.

use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use tokio::time::Instant;
use tracing::{debug, info, warn};

/// How long a degraded choice is trusted before the chain looks for a better
/// one. Steady state on the best leg never re-probes, so this is not a poll
/// interval so much as "how stale may a workaround get".
pub const DEFAULT_RECHECK: Duration = Duration::from_secs(60);

/// What is carrying the data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Transport {
    /// The HTTP FileStation API. Works from anywhere the DSM port is open,
    /// and cannot resume an interrupted transfer.
    Https,
    /// SMB through a tunnel we brought up.
    SmbOverVpn,
    /// SMB straight to the appliance.
    SmbDirect,
}

impl Transport {
    /// Whether this is the best the chain can do, and therefore whether
    /// looking again could find anything.
    fn is_best(self) -> bool {
        self == Transport::SmbDirect
    }
}

impl std::fmt::Display for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Transport::SmbDirect => "SMB",
            Transport::SmbOverVpn => "SMB via VPN",
            Transport::Https => "HTTPS",
        };
        f.write_str(name)
    }
}

/// Which legs the user has allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportPolicy {
    smb: bool,
    vpn: bool,
    https: bool,
}

/// A policy that forbids everything, which is a configuration mistake rather
/// than a mount that quietly does nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NothingEnabled;

impl std::fmt::Display for NothingEnabled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("every transport is disabled, so there is no way to reach the NAS")
    }
}

impl std::error::Error for NothingEnabled {}

impl Default for TransportPolicy {
    fn default() -> Self {
        Self {
            smb: true,
            vpn: true,
            https: true,
        }
    }
}

impl TransportPolicy {
    /// Build a policy from the three `--disable-*` flags.
    ///
    /// Disabling means *do not probe*, not *probe and ignore*: on a network
    /// that black-holes port 445, `--disable-smb` also saves the connect
    /// timeout. It implies no escalation either, since there would be nothing
    /// to escalate to.
    pub fn from_flags(
        disable_smb: bool,
        disable_vpn: bool,
        disable_https: bool,
    ) -> Result<Self, NothingEnabled> {
        if disable_smb && disable_https {
            return Err(NothingEnabled);
        }
        Ok(Self {
            smb: !disable_smb,
            vpn: !disable_smb && !disable_vpn,
            https: !disable_https,
        })
    }

    /// Whether SMB may be probed at all.
    pub fn allows_smb(&self) -> bool {
        self.smb
    }

    /// Whether a tunnel may be raised to reach SMB.
    pub fn allows_vpn(&self) -> bool {
        self.vpn
    }

    /// Whether the HTTP API may carry the data.
    pub fn allows_https(&self) -> bool {
        self.https
    }
}

/// Can SMB be reached right now?
#[async_trait]
pub trait Prober: Send + Sync {
    /// True when the SMB port answers. Implementations must bound their own
    /// wait: this runs while a user watches a spinner.
    async fn smb_reachable(&self) -> bool;
}

/// Something that can make an unreachable NAS reachable.
#[async_trait]
pub trait Tunnel: Send + Sync {
    /// Bring the tunnel up, or say why not.
    ///
    /// Must not prompt: this can run at a cache expiry, and a dialog in the
    /// middle of someone's copy is worse than staying on the slower leg. A
    /// tunnel needing input reports failure and waits to be asked explicitly.
    async fn bring_up(&self) -> Result<(), TunnelUnavailable>;
}

/// A tunnel that could not be established, with a reason worth logging.
#[derive(Debug, Clone)]
pub struct TunnelUnavailable(pub String);

impl std::fmt::Display for TunnelUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TunnelUnavailable {}

/// The tunnel used when the caller has none: it never comes up, so the chain
/// falls from SMB straight to HTTP.
pub struct NoTunnel;

#[async_trait]
impl Tunnel for NoTunnel {
    async fn bring_up(&self) -> Result<(), TunnelUnavailable> {
        Err(TunnelUnavailable("no tunnel is configured".into()))
    }
}

/// A TCP connect to the SMB port, which is all "reachable" needs to mean here:
/// authentication is settled separately, against the HTTP API, before any of
/// this runs.
pub struct TcpProber {
    host: String,
    port: u16,
    timeout: Duration,
}

impl TcpProber {
    /// Probe `host` on the standard SMB port.
    pub fn new(host: impl Into<String>, timeout: Duration) -> Self {
        Self {
            host: host.into(),
            port: 445,
            timeout,
        }
    }
}

#[async_trait]
impl Prober for TcpProber {
    async fn smb_reachable(&self) -> bool {
        let addr = format!("{}:{}", self.host, self.port);
        match tokio::time::timeout(self.timeout, tokio::net::TcpStream::connect(&addr)).await {
            Ok(Ok(_)) => true,
            Ok(Err(e)) => {
                debug!("smb probe: {addr} refused the connection ({e})");
                false
            }
            Err(_) => {
                debug!("smb probe: {addr} did not answer within {:?}", self.timeout);
                false
            }
        }
    }
}

/// Nothing in the policy can carry data right now.
#[derive(Debug, Clone)]
pub struct NoTransport;

impl std::fmt::Display for NoTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SMB is unreachable and the HTTP fallback is disabled")
    }
}

impl std::error::Error for NoTransport {}

/// A cached choice and the moment it stops being trusted.
#[derive(Debug, Clone, Copy)]
struct Decision {
    transport: Transport,
    /// `None` for a choice at the top of the chain: there is nothing better to
    /// find, so it never expires on its own.
    expires_at: Option<Instant>,
}

/// Picks a transport, remembers it, and looks again when the answer could have
/// improved.
pub struct Chain {
    policy: TransportPolicy,
    prober: Box<dyn Prober>,
    tunnel: Box<dyn Tunnel>,
    recheck: Duration,
    decision: Mutex<Option<Decision>>,
}

impl Chain {
    /// Build a chain. `recheck` bounds how stale a *degraded* choice may get;
    /// see [`DEFAULT_RECHECK`].
    pub fn new(
        policy: TransportPolicy,
        prober: Box<dyn Prober>,
        tunnel: Box<dyn Tunnel>,
        recheck: Duration,
    ) -> Self {
        Self {
            policy,
            prober,
            tunnel,
            recheck,
            decision: Mutex::new(None),
        }
    }

    /// The transport to use now.
    ///
    /// Cheap on the common path: a decision that has not expired is returned
    /// without touching the network.
    pub async fn transport(&self) -> Result<Transport, NoTransport> {
        if let Some(cached) = self.cached(Instant::now()) {
            return Ok(cached);
        }
        let chosen = self.decide().await?;
        self.remember(chosen, Instant::now());
        Ok(chosen)
    }

    /// The current choice without deciding one, for a status line that must
    /// not cause network traffic to render.
    pub fn current(&self) -> Option<Transport> {
        self.decision.lock().unwrap().map(|d| d.transport)
    }

    fn cached(&self, now: Instant) -> Option<Transport> {
        let decision = (*self.decision.lock().unwrap())?;
        match decision.expires_at {
            // Best available: nothing to look for, so it never goes stale.
            None => Some(decision.transport),
            Some(at) if now < at => Some(decision.transport),
            Some(_) => None,
        }
    }

    fn remember(&self, transport: Transport, now: Instant) {
        let expires_at = if transport.is_best() {
            None
        } else {
            Some(now + self.recheck)
        };
        *self.decision.lock().unwrap() = Some(Decision {
            transport,
            expires_at,
        });
    }

    async fn decide(&self) -> Result<Transport, NoTransport> {
        if self.policy.allows_smb() {
            if self.prober.smb_reachable().await {
                debug!("transport: SMB answers directly");
                return Ok(Transport::SmbDirect);
            }
            if self.policy.allows_vpn() {
                match self.tunnel.bring_up().await {
                    Ok(()) if self.prober.smb_reachable().await => {
                        info!("transport: SMB reachable through the tunnel");
                        return Ok(Transport::SmbOverVpn);
                    }
                    // A tunnel that came up without making SMB reachable is
                    // not a tunnel to here; say so rather than blaming SMB.
                    Ok(()) => warn!("transport: tunnel is up but SMB still does not answer"),
                    Err(e) => debug!("transport: no tunnel ({e})"),
                }
            }
        }

        if self.policy.allows_https() {
            info!("transport: falling back to the HTTP API");
            return Ok(Transport::Https);
        }
        Err(NoTransport)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[derive(Default)]
    struct FakeProber {
        reachable: AtomicBool,
        probes: AtomicUsize,
    }

    impl FakeProber {
        fn new(reachable: bool) -> Self {
            Self {
                reachable: AtomicBool::new(reachable),
                probes: AtomicUsize::new(0),
            }
        }
        fn probes(&self) -> usize {
            self.probes.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl Prober for std::sync::Arc<FakeProber> {
        async fn smb_reachable(&self) -> bool {
            self.probes.fetch_add(1, Ordering::SeqCst);
            self.reachable.load(Ordering::SeqCst)
        }
    }

    #[derive(Default)]
    struct FakeTunnel {
        works: bool,
        /// Set when the tunnel is what makes SMB answer.
        opens: AtomicUsize,
        prober: Option<std::sync::Arc<FakeProber>>,
    }

    #[async_trait]
    impl Tunnel for std::sync::Arc<FakeTunnel> {
        async fn bring_up(&self) -> Result<(), TunnelUnavailable> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            if !self.works {
                return Err(TunnelUnavailable("no route".into()));
            }
            if let Some(p) = &self.prober {
                p.reachable.store(true, Ordering::SeqCst);
            }
            Ok(())
        }
    }

    fn chain(
        policy: TransportPolicy,
        prober: std::sync::Arc<FakeProber>,
        tunnel: std::sync::Arc<FakeTunnel>,
    ) -> Chain {
        Chain::new(policy, Box::new(prober), Box::new(tunnel), DEFAULT_RECHECK)
    }

    #[test]
    fn forbidding_everything_is_a_configuration_error() {
        // Better to refuse at startup than to mount something that cannot
        // answer a single read.
        assert!(TransportPolicy::from_flags(true, false, true).is_err());
    }

    #[test]
    fn disabling_smb_also_forbids_the_tunnel() {
        // A tunnel exists to make SMB reachable. Without SMB there is nothing
        // on the other side of it worth dialling.
        let policy = TransportPolicy::from_flags(true, false, false).unwrap();
        assert!(!policy.allows_smb());
        assert!(!policy.allows_vpn());
        assert!(policy.allows_https());
    }

    #[tokio::test]
    async fn a_reachable_smb_wins_and_no_tunnel_is_dialled() {
        let prober = std::sync::Arc::new(FakeProber::new(true));
        let tunnel = std::sync::Arc::new(FakeTunnel::default());
        let chain = chain(TransportPolicy::default(), prober.clone(), tunnel.clone());

        assert_eq!(chain.transport().await.unwrap(), Transport::SmbDirect);
        assert_eq!(
            tunnel.opens.load(Ordering::SeqCst),
            0,
            "nothing to escalate"
        );
    }

    #[tokio::test]
    async fn an_unreachable_smb_escalates_through_the_tunnel() {
        let prober = std::sync::Arc::new(FakeProber::new(false));
        let tunnel = std::sync::Arc::new(FakeTunnel {
            works: true,
            prober: Some(prober.clone()),
            ..Default::default()
        });
        let chain = chain(TransportPolicy::default(), prober.clone(), tunnel.clone());

        assert_eq!(chain.transport().await.unwrap(), Transport::SmbOverVpn);
        assert_eq!(tunnel.opens.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_tunnel_that_comes_up_without_reaching_smb_is_not_the_answer() {
        // Connected to *a* network is not connected to *this* NAS. Reporting
        // SmbOverVpn here would blame SMB for a routing problem.
        let prober = std::sync::Arc::new(FakeProber::new(false));
        let tunnel = std::sync::Arc::new(FakeTunnel {
            works: true,
            prober: None,
            ..Default::default()
        });
        let chain = chain(TransportPolicy::default(), prober.clone(), tunnel.clone());

        assert_eq!(chain.transport().await.unwrap(), Transport::Https);
    }

    #[tokio::test]
    async fn a_disabled_tunnel_falls_straight_to_http() {
        let prober = std::sync::Arc::new(FakeProber::new(false));
        let tunnel = std::sync::Arc::new(FakeTunnel {
            works: true,
            prober: Some(prober.clone()),
            ..Default::default()
        });
        let policy = TransportPolicy::from_flags(false, true, false).unwrap();
        let chain = chain(policy, prober.clone(), tunnel.clone());

        assert_eq!(chain.transport().await.unwrap(), Transport::Https);
        assert_eq!(
            tunnel.opens.load(Ordering::SeqCst),
            0,
            "no dialog, no dialling"
        );
    }

    #[tokio::test]
    async fn disabling_smb_costs_no_probe() {
        // The point of the flag on a network that black-holes 445: not one
        // connect timeout is paid.
        let prober = std::sync::Arc::new(FakeProber::new(true));
        let tunnel = std::sync::Arc::new(FakeTunnel::default());
        let policy = TransportPolicy::from_flags(true, false, false).unwrap();
        let chain = chain(policy, prober.clone(), tunnel.clone());

        assert_eq!(chain.transport().await.unwrap(), Transport::Https);
        assert_eq!(prober.probes(), 0);
    }

    #[tokio::test]
    async fn disabling_http_fails_loudly_rather_than_pretending() {
        let prober = std::sync::Arc::new(FakeProber::new(false));
        let tunnel = std::sync::Arc::new(FakeTunnel::default());
        let policy = TransportPolicy::from_flags(false, false, true).unwrap();
        let chain = chain(policy, prober.clone(), tunnel.clone());

        assert!(chain.transport().await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn the_choice_is_not_re_probed_on_every_call() {
        let prober = std::sync::Arc::new(FakeProber::new(true));
        let tunnel = std::sync::Arc::new(FakeTunnel::default());
        let chain = chain(TransportPolicy::default(), prober.clone(), tunnel.clone());

        for _ in 0..5 {
            assert_eq!(chain.transport().await.unwrap(), Transport::SmbDirect);
        }
        assert_eq!(prober.probes(), 1, "decided once, remembered after that");
    }

    #[tokio::test(start_paused = true)]
    async fn sitting_on_the_best_transport_never_probes_again() {
        // Nothing better exists, so a timer here would be pure noise on the
        // network for the entire life of the mount.
        let prober = std::sync::Arc::new(FakeProber::new(true));
        let tunnel = std::sync::Arc::new(FakeTunnel::default());
        let chain = chain(TransportPolicy::default(), prober.clone(), tunnel.clone());

        chain.transport().await.unwrap();
        tokio::time::advance(DEFAULT_RECHECK * 10).await;
        chain.transport().await.unwrap();

        assert_eq!(prober.probes(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_degraded_choice_is_looked_at_again_and_promoted() {
        let prober = std::sync::Arc::new(FakeProber::new(false));
        let tunnel = std::sync::Arc::new(FakeTunnel::default());
        let chain = chain(TransportPolicy::default(), prober.clone(), tunnel.clone());

        assert_eq!(chain.transport().await.unwrap(), Transport::Https);

        // The network comes back: on campus, off the hotel wifi, tunnel up by
        // other means.
        prober.reachable.store(true, Ordering::SeqCst);
        assert_eq!(
            chain.transport().await.unwrap(),
            Transport::Https,
            "still trusted until it expires"
        );

        tokio::time::advance(DEFAULT_RECHECK + Duration::from_secs(1)).await;
        assert_eq!(chain.transport().await.unwrap(), Transport::SmbDirect);
    }

    #[tokio::test]
    async fn the_status_line_never_causes_traffic() {
        let prober = std::sync::Arc::new(FakeProber::new(true));
        let tunnel = std::sync::Arc::new(FakeTunnel::default());
        let chain = chain(TransportPolicy::default(), prober.clone(), tunnel.clone());

        assert_eq!(chain.current(), None, "nothing decided yet");
        chain.transport().await.unwrap();
        assert_eq!(chain.current(), Some(Transport::SmbDirect));
        assert_eq!(prober.probes(), 1, "asking what is live decided nothing");
    }
}
