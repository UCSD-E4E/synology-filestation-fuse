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

pub mod profile;

use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Instant;
use tracing::{debug, info};

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

/// Where the NAS is, on each side of the tunnel.
///
/// Two addresses, not one, because the tunnel deliberately pushes no DNS: a
/// client inside it reaches the NAS at a private address that its public name
/// does not resolve to. Probing the wrong one is the difference between "SMB
/// is down" and "SMB is one escalation away".
#[derive(Debug, Clone)]
pub struct Endpoints {
    /// The publicly resolvable name. Carries the HTTP API, and is what the
    /// direct SMB probe asks.
    pub public_host: String,
    /// The NAS's address inside the tunnel, when one is configured. `None`
    /// means there is nowhere for an escalation to land, so none is attempted
    /// however healthy the tunnel is.
    pub tunnel_host: Option<String>,
}

impl Endpoints {
    /// A NAS reachable only by its public name.
    pub fn public_only(host: impl Into<String>) -> Self {
        Self {
            public_host: host.into(),
            tunnel_host: None,
        }
    }

    /// A NAS that is also reachable at `tunnel_host` once the tunnel is up.
    pub fn with_tunnel(host: impl Into<String>, tunnel_host: impl Into<String>) -> Self {
        Self {
            public_host: host.into(),
            tunnel_host: Some(tunnel_host.into()),
        }
    }
}

/// A chosen transport and the address to use it against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// Which leg of the chain this is.
    pub transport: Transport,
    /// The host SMB should connect to. `None` on the HTTP leg, which carries
    /// no SMB at all.
    pub smb_host: Option<String>,
}

/// Can SMB be reached at `host` right now?
#[async_trait]
pub trait Prober: Send + Sync {
    /// True when the SMB port answers. The host is a parameter because the
    /// answer differs per leg: the public name for a direct connection, the
    /// in-tunnel address once a tunnel is up. Implementations must bound their
    /// own wait: this runs while a user watches a spinner.
    async fn smb_reachable(&self, host: &str) -> bool;
}

/// A byte stream to the NAS, however it was arrived at.
///
/// Boxed and named only by what it does, so this crate stays a decision layer:
/// what actually satisfies it is a TCP connection inside a userspace stack
/// inside an OpenVPN tunnel, and nothing here needs to know that.
pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncStream for T {}

/// An open connection to the NAS through a tunnel.
pub type Connection = Box<dyn AsyncStream>;

/// Something that can make an unreachable NAS reachable.
#[async_trait]
pub trait Tunnel: Send + Sync {
    /// Bring the tunnel up and open a connection to `host:port` through it.
    ///
    /// Opening it **is** the probe. There is no separate "is it reachable"
    /// question to ask first: a tunnel that terminates inside this process has
    /// no address the operating system can be asked about, so the only way to
    /// find out whether the NAS answers is to talk to it — and having done
    /// that, throwing the connection away to open another one would be a
    /// second handshake to learn what the first already proved.
    ///
    /// Must not prompt: this can run at a cache expiry, and a dialog in the
    /// middle of someone's copy is worse than staying on the slower leg. A
    /// tunnel needing input reports failure and waits to be asked explicitly.
    async fn open(&self, host: &str, port: u16) -> Result<Connection, TunnelUnavailable>;
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
    async fn open(&self, _host: &str, _port: u16) -> Result<Connection, TunnelUnavailable> {
        Err(TunnelUnavailable("no tunnel is configured".into()))
    }
}

/// A TCP connect to the SMB port, which is all "reachable" needs to mean here:
/// authentication is settled separately, against the HTTP API, before any of
/// this runs.
pub struct TcpProber {
    port: u16,
    timeout: Duration,
}

impl TcpProber {
    /// Probe the standard SMB port, giving up after `timeout`.
    ///
    /// A TCP connect and nothing more: reachability, not authorization. ICMP
    /// is not used — the tunnel drops it by design, so a ping would report a
    /// working path as dead.
    pub fn new(timeout: Duration) -> Self {
        Self { port: 445, timeout }
    }
}

#[async_trait]
impl Prober for TcpProber {
    async fn smb_reachable(&self, host: &str) -> bool {
        let addr = format!("{}:{}", host, self.port);
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
#[derive(Debug, Clone)]
struct Decision {
    route: Route,
    /// `None` for a choice at the top of the chain: there is nothing better to
    /// find, so it never expires on its own.
    expires_at: Option<Instant>,
}

/// The SMB port, which is not configurable: it is what SMB is.
const SMB_PORT: u16 = 445;

/// How SMB can be reached right now.
///
/// Two of these are addresses and one is an open connection, because that is
/// the honest shape of the answer. A NAS reachable directly is dialled by
/// whoever wants it; one reachable only through a tunnel was *already* dialled
/// to find that out, and handing back the connection is what stops the same
/// work being done twice.
pub enum SmbRoute {
    /// It answers directly. Dial this host.
    Direct { host: String },
    /// It answers through a tunnel, and this is the connection to it.
    Tunnelled {
        /// The address inside the tunnel, which still names the server on the
        /// wire even though it has already been dialled.
        host: String,
        connection: Connection,
    },
    /// SMB cannot be reached; the chain has fallen to the HTTP API.
    Unavailable,
}

/// Picks a transport, remembers it, and looks again when the answer could have
/// improved.
pub struct Chain {
    policy: TransportPolicy,
    endpoints: Endpoints,
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
        endpoints: Endpoints,
        prober: Box<dyn Prober>,
        tunnel: Box<dyn Tunnel>,
        recheck: Duration,
    ) -> Self {
        Self {
            policy,
            endpoints,
            prober,
            tunnel,
            recheck,
            decision: Mutex::new(None),
        }
    }

    /// The transport to use now, and the address to use it against.
    ///
    /// Cheap on the common path: a decision that has not expired is returned
    /// without touching the network.
    pub async fn route(&self) -> Result<Route, NoTransport> {
        if let Some(cached) = self.cached(Instant::now()) {
            return Ok(cached);
        }
        // The tunnel leg proves itself by opening a connection, and a caller
        // asking only which transport to use has nowhere to put one. Dropped
        // rather than avoided: there is no cheaper question to ask.
        let (chosen, _proof) = self.decide().await?;
        self.remember(chosen.clone(), Instant::now());
        Ok(chosen)
    }

    /// Reach SMB by the best route there is.
    ///
    /// This is what a mount calls. [`route`](Self::route) answers *which*
    /// transport; this answers *with* one — and on the tunnel leg that is a
    /// connection already open, because opening it was the only way to know
    /// the leg works.
    pub async fn reach_smb(&self) -> Result<SmbRoute, NoTransport> {
        if let Some(cached) = self.cached(Instant::now()) {
            match cached.transport {
                Transport::SmbDirect => {
                    if let Some(host) = cached.smb_host {
                        return Ok(SmbRoute::Direct { host });
                    }
                }
                Transport::Https => return Ok(SmbRoute::Unavailable),
                Transport::SmbOverVpn => {
                    if let Some(host) = cached.smb_host.clone() {
                        match self.tunnel.open(&host, SMB_PORT).await {
                            Ok(connection) => return Ok(SmbRoute::Tunnelled { host, connection }),
                            // What was remembered no longer holds. Falling
                            // through re-decides rather than reporting a
                            // failure the chain has other answers to.
                            Err(e) => {
                                debug!("transport: the remembered tunnel no longer opens ({e})");
                                self.forget();
                            }
                        }
                    }
                }
            }
        }

        let (chosen, opened) = self.decide().await?;
        self.remember(chosen.clone(), Instant::now());
        Ok(match (chosen.transport, chosen.smb_host, opened) {
            (Transport::SmbOverVpn, Some(host), Some(connection)) => {
                SmbRoute::Tunnelled { host, connection }
            }
            (Transport::SmbDirect, Some(host), _) => SmbRoute::Direct { host },
            _ => SmbRoute::Unavailable,
        })
    }

    fn forget(&self) {
        *self.decision.lock().unwrap() = None;
    }

    /// The current choice without deciding one, for a status line that must
    /// not cause network traffic to render.
    pub fn current(&self) -> Option<Route> {
        self.decision
            .lock()
            .unwrap()
            .as_ref()
            .map(|d| d.route.clone())
    }

    fn cached(&self, now: Instant) -> Option<Route> {
        let guard = self.decision.lock().unwrap();
        let decision = guard.as_ref()?;
        match decision.expires_at {
            // Best available: nothing to look for, so it never goes stale.
            None => Some(decision.route.clone()),
            Some(at) if now < at => Some(decision.route.clone()),
            Some(_) => None,
        }
    }

    fn remember(&self, route: Route, now: Instant) {
        let expires_at = if route.transport.is_best() {
            None
        } else {
            Some(now + self.recheck)
        };
        *self.decision.lock().unwrap() = Some(Decision { route, expires_at });
    }

    /// The best leg available, and — on the tunnel leg — the connection that
    /// proved it.
    async fn decide(&self) -> Result<(Route, Option<Connection>), NoTransport> {
        if self.policy.allows_smb() {
            let public = &self.endpoints.public_host;
            if self.prober.smb_reachable(public).await {
                debug!("transport: SMB answers directly at {public}");
                return Ok((
                    Route {
                        transport: Transport::SmbDirect,
                        smb_host: Some(public.clone()),
                    },
                    None,
                ));
            }
            match (self.policy.allows_vpn(), &self.endpoints.tunnel_host) {
                // The address *inside* the tunnel, not the public name: the
                // tunnel pushes no DNS, and the public name is exactly the one
                // that just failed. A tunnel that comes up without reaching
                // SMB and one that never comes up are now the same answer
                // here — the error says which, and it is the tunnel's to
                // explain rather than this layer's to guess.
                (true, Some(inside)) => match self.tunnel.open(inside, SMB_PORT).await {
                    Ok(connection) => {
                        info!("transport: SMB reachable through the tunnel at {inside}");
                        return Ok((
                            Route {
                                transport: Transport::SmbOverVpn,
                                smb_host: Some(inside.clone()),
                            },
                            Some(connection),
                        ));
                    }
                    Err(e) => debug!("transport: no SMB through a tunnel ({e})"),
                },
                // Nowhere for an escalation to land. Raising the tunnel would
                // still leave us with no address to mount, so don't.
                (true, None) => {
                    debug!("transport: no in-tunnel address configured, so no escalation")
                }
                (false, _) => {}
            }
        }

        if self.policy.allows_https() {
            info!("transport: falling back to the HTTP API");
            return Ok((
                Route {
                    transport: Transport::Https,
                    smb_host: None,
                },
                None,
            ));
        }
        Err(NoTransport)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex as StdMutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const PUBLIC: &str = "e4e-nas.ucsd.edu";
    const INSIDE: &str = "10.90.24.1";

    #[derive(Default)]
    struct FakeProber {
        /// Hosts that answer on 445.
        answering: StdMutex<Vec<String>>,
        /// Every host asked, in order.
        asked: StdMutex<Vec<String>>,
    }

    impl FakeProber {
        fn answering(hosts: &[&str]) -> Arc<Self> {
            Arc::new(Self {
                answering: StdMutex::new(hosts.iter().map(|h| h.to_string()).collect()),
                asked: StdMutex::new(Vec::new()),
            })
        }
        fn nothing_answers() -> Arc<Self> {
            Self::answering(&[])
        }
        fn asked(&self) -> Vec<String> {
            self.asked.lock().unwrap().clone()
        }
        fn probes(&self) -> usize {
            self.asked.lock().unwrap().len()
        }
        fn starts_answering(&self, host: &str) {
            self.answering.lock().unwrap().push(host.to_string());
        }
    }

    #[async_trait]
    impl Prober for Arc<FakeProber> {
        async fn smb_reachable(&self, host: &str) -> bool {
            self.asked.lock().unwrap().push(host.to_string());
            self.answering.lock().unwrap().iter().any(|h| h == host)
        }
    }

    struct FakeTunnel {
        /// Whether a connection through it can be opened at all.
        works: AtomicBool,
        opens: AtomicUsize,
        /// Every host it was asked to open a connection to, in order.
        asked: StdMutex<Vec<String>>,
        /// The far end of whatever it last handed out, so a test can see what
        /// was written to it.
        far_end: StdMutex<Option<tokio::io::DuplexStream>>,
    }

    impl FakeTunnel {
        fn new(works: bool) -> Arc<Self> {
            Arc::new(Self {
                works: AtomicBool::new(works),
                opens: AtomicUsize::new(0),
                asked: StdMutex::new(Vec::new()),
                far_end: StdMutex::new(None),
            })
        }
        /// A tunnel that cannot be raised.
        fn absent() -> Arc<Self> {
            Self::new(false)
        }
        /// A tunnel that opens a connection to the NAS.
        fn reaching() -> Arc<Self> {
            Self::new(true)
        }
        /// A tunnel that comes up but reaches nothing useful — which, now that
        /// opening is the probe, is indistinguishable from one that does not
        /// come up, and is meant to be.
        fn to_nowhere() -> Arc<Self> {
            Self::new(false)
        }
        fn opens(&self) -> usize {
            self.opens.load(Ordering::SeqCst)
        }
        fn stops_working(&self) {
            self.works.store(false, Ordering::SeqCst);
        }
        fn asked(&self) -> Vec<String> {
            self.asked.lock().unwrap().clone()
        }
        fn take_far_end(&self) -> tokio::io::DuplexStream {
            self.far_end.lock().unwrap().take().expect("one was opened")
        }
    }

    #[async_trait]
    impl Tunnel for Arc<FakeTunnel> {
        async fn open(&self, host: &str, port: u16) -> Result<Connection, TunnelUnavailable> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            self.asked.lock().unwrap().push(format!("{host}:{port}"));
            if !self.works.load(Ordering::SeqCst) {
                return Err(TunnelUnavailable("no route".into()));
            }
            let (ours, theirs) = tokio::io::duplex(4096);
            *self.far_end.lock().unwrap() = Some(theirs);
            Ok(Box::new(ours))
        }
    }

    fn chain(policy: TransportPolicy, prober: Arc<FakeProber>, tunnel: Arc<FakeTunnel>) -> Chain {
        Chain::new(
            policy,
            Endpoints::with_tunnel(PUBLIC, INSIDE),
            Box::new(prober),
            Box::new(tunnel),
            DEFAULT_RECHECK,
        )
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
        let prober = FakeProber::answering(&[PUBLIC]);
        let tunnel = FakeTunnel::absent();
        let chain = chain(TransportPolicy::default(), prober.clone(), tunnel.clone());

        let route = chain.route().await.unwrap();
        assert_eq!(route.transport, Transport::SmbDirect);
        assert_eq!(route.smb_host.as_deref(), Some(PUBLIC));
        assert_eq!(prober.asked(), vec![PUBLIC], "the public name, once");
        assert_eq!(tunnel.opens(), 0, "nothing to escalate");
    }

    #[tokio::test]
    async fn the_tunnel_leg_is_probed_at_the_in_tunnel_address() {
        // The whole reason Endpoints carries two hosts: the tunnel pushes no
        // DNS, so the public name still fails inside it. Probing that name
        // again would report the escalation as useless and fall to HTTP.
        let prober = FakeProber::nothing_answers();
        let tunnel = FakeTunnel::reaching();
        let chain = chain(TransportPolicy::default(), prober.clone(), tunnel.clone());

        let route = chain.route().await.unwrap();
        assert_eq!(route.transport, Transport::SmbOverVpn);
        assert_eq!(
            route.smb_host.as_deref(),
            Some(INSIDE),
            "callers mount the in-tunnel address, not the public name"
        );
        assert_eq!(
            prober.asked(),
            vec![PUBLIC],
            "the public name is asked once, and not again inside the tunnel"
        );
        assert_eq!(
            tunnel.asked(),
            vec![format!("{INSIDE}:445")],
            "the connection is opened to the in-tunnel address, which is what \
             proves the leg — the public name is exactly the one that just failed"
        );
        assert_eq!(tunnel.opens(), 1);
    }

    #[tokio::test]
    async fn without_an_in_tunnel_address_no_tunnel_is_dialled() {
        // Raising a tunnel we have no address to mount through would cost the
        // user a connection and change nothing.
        let prober = FakeProber::nothing_answers();
        let tunnel = FakeTunnel::to_nowhere();
        let chain = Chain::new(
            TransportPolicy::default(),
            Endpoints::public_only(PUBLIC),
            Box::new(prober.clone()),
            Box::new(tunnel.clone()),
            DEFAULT_RECHECK,
        );

        assert_eq!(chain.route().await.unwrap().transport, Transport::Https);
        assert_eq!(tunnel.opens(), 0);
    }

    #[tokio::test]
    async fn a_tunnel_that_comes_up_without_reaching_smb_is_not_the_answer() {
        // Connected to *a* network is not connected to *this* NAS. Reporting
        // SmbOverVpn here would blame SMB for a routing problem.
        let prober = FakeProber::nothing_answers();
        let tunnel = FakeTunnel::to_nowhere();
        let chain = chain(TransportPolicy::default(), prober.clone(), tunnel.clone());

        let route = chain.route().await.unwrap();
        assert_eq!(route.transport, Transport::Https);
        assert_eq!(route.smb_host, None, "the HTTP leg carries no SMB");
        assert_eq!(tunnel.opens(), 1, "tried, and honestly reported");
    }

    #[tokio::test]
    async fn a_disabled_tunnel_falls_straight_to_http() {
        let prober = FakeProber::nothing_answers();
        let tunnel = FakeTunnel::reaching();
        let policy = TransportPolicy::from_flags(false, true, false).unwrap();
        let chain = chain(policy, prober.clone(), tunnel.clone());

        assert_eq!(chain.route().await.unwrap().transport, Transport::Https);
        assert_eq!(tunnel.opens(), 0, "no dialog, no dialling");
    }

    #[tokio::test]
    async fn disabling_smb_costs_no_probe() {
        // The point of the flag on a network that black-holes 445: not one
        // connect timeout is paid.
        let prober = FakeProber::answering(&[PUBLIC]);
        let tunnel = FakeTunnel::absent();
        let policy = TransportPolicy::from_flags(true, false, false).unwrap();
        let chain = chain(policy, prober.clone(), tunnel.clone());

        assert_eq!(chain.route().await.unwrap().transport, Transport::Https);
        assert_eq!(prober.probes(), 0);
    }

    #[tokio::test]
    async fn disabling_http_fails_loudly_rather_than_pretending() {
        let prober = FakeProber::nothing_answers();
        let tunnel = FakeTunnel::absent();
        let policy = TransportPolicy::from_flags(false, false, true).unwrap();
        let chain = chain(policy, prober.clone(), tunnel.clone());

        assert!(chain.route().await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn the_choice_is_not_re_probed_on_every_call() {
        let prober = FakeProber::answering(&[PUBLIC]);
        let tunnel = FakeTunnel::absent();
        let chain = chain(TransportPolicy::default(), prober.clone(), tunnel.clone());

        for _ in 0..5 {
            assert_eq!(chain.route().await.unwrap().transport, Transport::SmbDirect);
        }
        assert_eq!(prober.probes(), 1, "decided once, remembered after that");
    }

    #[tokio::test(start_paused = true)]
    async fn sitting_on_the_best_transport_never_probes_again() {
        // Nothing better exists, so a timer here would be pure noise on the
        // network for the entire life of the mount.
        let prober = FakeProber::answering(&[PUBLIC]);
        let tunnel = FakeTunnel::absent();
        let chain = chain(TransportPolicy::default(), prober.clone(), tunnel.clone());

        chain.route().await.unwrap();
        tokio::time::advance(DEFAULT_RECHECK * 10).await;
        chain.route().await.unwrap();

        assert_eq!(prober.probes(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_degraded_choice_is_looked_at_again_and_promoted() {
        let prober = FakeProber::nothing_answers();
        let tunnel = FakeTunnel::absent();
        let chain = chain(TransportPolicy::default(), prober.clone(), tunnel.clone());

        assert_eq!(chain.route().await.unwrap().transport, Transport::Https);

        // The network comes back: on campus, off the hotel wifi, tunnel up by
        // other means.
        prober.starts_answering(PUBLIC);
        assert_eq!(
            chain.route().await.unwrap().transport,
            Transport::Https,
            "still trusted until it expires"
        );

        tokio::time::advance(DEFAULT_RECHECK + Duration::from_secs(1)).await;
        assert_eq!(chain.route().await.unwrap().transport, Transport::SmbDirect);
    }

    #[tokio::test]
    async fn the_status_line_never_causes_traffic() {
        let prober = FakeProber::answering(&[PUBLIC]);
        let tunnel = FakeTunnel::absent();
        let chain = chain(TransportPolicy::default(), prober.clone(), tunnel.clone());

        assert_eq!(chain.current(), None, "nothing decided yet");
        chain.route().await.unwrap();
        assert_eq!(
            chain.current().map(|r| r.transport),
            Some(Transport::SmbDirect)
        );
        assert_eq!(prober.probes(), 1, "asking what is live decided nothing");
    }

    #[tokio::test]
    async fn the_tunnel_leg_hands_back_the_connection_it_opened() {
        // The point of the whole shape. Opening it was the only way to learn
        // the leg works, so the caller gets that connection rather than an
        // address it would have to dial through a tunnel it cannot see.
        let prober = FakeProber::nothing_answers();
        let tunnel = FakeTunnel::reaching();
        let chain = chain(TransportPolicy::default(), prober.clone(), tunnel.clone());

        let reached = chain.reach_smb().await.unwrap();
        let SmbRoute::Tunnelled {
            host,
            mut connection,
        } = reached
        else {
            panic!("the tunnel leg should have been taken");
        };
        assert_eq!(host, INSIDE, "and it still names the server");

        // A real connection, not a token: what goes in comes out the far end.
        connection.write_all(b"smb2 would go here").await.unwrap();
        let mut far = tunnel.take_far_end();
        let mut heard = [0u8; 18];
        far.read_exact(&mut heard).await.unwrap();
        assert_eq!(&heard, b"smb2 would go here");

        assert_eq!(tunnel.opens(), 1, "and it was opened once, not twice");
    }

    #[tokio::test]
    async fn a_remembered_tunnel_route_opens_a_fresh_connection() {
        // The decision is cacheable; a connection is not. A second caller gets
        // its own, without the ladder being climbed again.
        let prober = FakeProber::nothing_answers();
        let tunnel = FakeTunnel::reaching();
        let chain = chain(TransportPolicy::default(), prober.clone(), tunnel.clone());

        let _first = chain.reach_smb().await.unwrap();
        let probes = prober.probes();
        let second = chain.reach_smb().await.unwrap();

        assert!(matches!(second, SmbRoute::Tunnelled { .. }));
        assert_eq!(tunnel.opens(), 2, "a connection each");
        assert_eq!(
            prober.probes(),
            probes,
            "and the public host was not asked again"
        );
    }

    #[tokio::test]
    async fn a_tunnel_that_stops_opening_makes_the_chain_look_again() {
        // A remembered answer that no longer holds is not a failure to report:
        // the chain has other legs, and the whole point of remembering is that
        // it can stop.
        let prober = FakeProber::nothing_answers();
        let tunnel = FakeTunnel::reaching();
        let chain = chain(TransportPolicy::default(), prober.clone(), tunnel.clone());

        assert!(matches!(
            chain.reach_smb().await.unwrap(),
            SmbRoute::Tunnelled { .. }
        ));
        tunnel.stops_working();

        assert!(
            matches!(chain.reach_smb().await.unwrap(), SmbRoute::Unavailable),
            "it falls to HTTP rather than insisting on what it remembered"
        );
    }

    #[tokio::test]
    async fn a_reachable_nas_is_dialled_by_whoever_wants_it() {
        // Nothing is opened on this leg: the caller can reach the address
        // itself, and opening a connection here would be one it did not ask
        // for.
        let prober = FakeProber::answering(&[PUBLIC]);
        let tunnel = FakeTunnel::absent();
        let chain = chain(TransportPolicy::default(), prober.clone(), tunnel.clone());

        match chain.reach_smb().await.unwrap() {
            SmbRoute::Direct { host } => assert_eq!(host, PUBLIC),
            _ => panic!("SMB answers directly"),
        }
        assert_eq!(tunnel.opens(), 0);
    }
}
