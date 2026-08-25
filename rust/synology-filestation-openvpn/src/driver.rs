//! The part that actually runs.
//!
//! Everything else in this crate is deliberately sans-io: a state machine that
//! is handed datagrams and asked what to send, with `now` as a parameter. That
//! is what made it testable against captured bytes, a peer in this process,
//! and a real `openvpn`, on a link that loses and reorders, without any of it
//! needing a network.
//!
//! It also means nothing was driving it. This is the driver: one task that
//! owns a socket, hands the session what arrives, sends what it asks for, and
//! wakes when it says to. All the timing lives here and nowhere else, so the
//! state machine stays a state machine.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::ip::Ifconfig;
use crate::session::{Session, SessionConfig};
use crate::stack::TunnelStream;
use crate::Error;

/// How long to wait for the tunnel to come up before giving up on it.
///
/// The handshake is a few round trips; anything approaching this means the
/// far end is not answering, and a caller waiting forever cannot tell that
/// from a slow link.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// How long to sleep when the session has nothing to wait for.
///
/// It should not happen — the session asks for a wakeup whenever it has work —
/// but a driver that would sleep forever on a wrong answer is a driver that
/// hangs. This bounds the damage to a tenth of a second.
const IDLE_POLL: Duration = Duration::from_millis(100);

/// A running tunnel.
///
/// Payload in, payload out. What travels is whatever the caller puts in it —
/// for this driver's purpose, IP packets on their way to one port on one
/// host.
pub struct Tunnel {
    outgoing: mpsc::Sender<Vec<u8>>,
    incoming: mpsc::Receiver<Vec<u8>>,
    /// Why the tunnel stopped, once it has.
    failure: Arc<Mutex<Option<Error>>>,
    /// Where the server put us, from its push reply.
    ifconfig: Option<Ifconfig>,
    task: JoinHandle<()>,
}

impl Tunnel {
    /// Bring a tunnel up, and return once it is carrying.
    pub async fn connect(config: SessionConfig, remote: SocketAddr) -> Result<Self, Error> {
        // Bound to whatever the OS gives us: this is a client, and `nobind` is
        // what the published profile says. The family has to match the peer's,
        // or `connect` fails with an errno that says nothing about why.
        let unspecified: SocketAddr = match remote {
            SocketAddr::V4(_) => ([0, 0, 0, 0], 0).into(),
            SocketAddr::V6(_) => (std::net::Ipv6Addr::UNSPECIFIED, 0).into(),
        };
        let socket = UdpSocket::bind(unspecified)
            .await
            .map_err(|error| Error::Io(error.to_string()))?;
        socket
            .connect(remote)
            .await
            .map_err(|error| Error::Io(error.to_string()))?;

        let session = Session::new(config)?;
        let (to_tunnel, from_caller) = mpsc::channel(64);
        let (to_caller, from_tunnel) = mpsc::channel(64);
        let failure = Arc::new(Mutex::new(None));
        let (ready, is_ready) = tokio::sync::oneshot::channel();

        let task = tokio::spawn(run(
            socket,
            session,
            from_caller,
            to_caller,
            failure.clone(),
            ready,
        ));

        let outcome = match tokio::time::timeout(CONNECT_TIMEOUT, is_ready).await {
            Ok(Ok(Ok(ifconfig))) => {
                return Ok(Self {
                    outgoing: to_tunnel,
                    incoming: from_tunnel,
                    failure,
                    ifconfig,
                    task,
                })
            }
            // The task reported why it could not.
            Ok(Ok(Err(error))) => error,
            // The task ended without saying anything, which is a bug in it
            // rather than in the peer.
            Ok(Err(_)) => Error::Io("the tunnel task stopped".into()),
            Err(_) => Error::HandshakeTimeout,
        };

        // Every failing path takes the task with it. `Tunnel::drop` does this
        // for a tunnel that was returned; a `connect` that returns an error
        // returns no tunnel, so without this the task lives on with a bound
        // socket, retransmitting into the dark — one per attempt, and a
        // caller that retries makes a collection of them.
        task.abort();
        Err(outcome)
    }

    /// Put a payload through the tunnel.
    pub async fn send(&self, payload: Vec<u8>) -> Result<(), Error> {
        self.outgoing
            .send(payload)
            .await
            .map_err(|_| self.why_it_stopped())
    }

    /// Take the next payload out of it. `None` means the tunnel has stopped.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.incoming.recv().await
    }

    /// Where the server put us inside the tunnel.
    ///
    /// `None` when it pushed no `ifconfig`, which means it intends to carry
    /// something other than IP — nothing this driver has any use for, but not
    /// this layer's business to refuse.
    pub fn ifconfig(&self) -> Option<Ifconfig> {
        self.ifconfig
    }

    /// Open a TCP connection through the tunnel.
    ///
    /// This is the join the rest of the crate was for: the tunnel carries IP
    /// packets, [`TunnelStream`] is a TCP stack that speaks them, and neither
    /// knows about the other until here. What comes back reads and writes like
    /// any other stream, and nothing on this machine has — or needs — a route
    /// to the address at the far end.
    ///
    /// The tunnel is consumed. One connection is what this exists to carry,
    /// the packets have to go somewhere exclusively, and it means the tunnel
    /// failing arrives where a caller is already looking: as an error on the
    /// stream rather than as silence.
    pub async fn open_stream(
        self,
        remote: (Ipv4Addr, u16),
        patience: Duration,
    ) -> Result<TunnelStream, Error> {
        let ifconfig = self
            .ifconfig
            .ok_or_else(|| Error::Io("the server pushed no address for us".into()))?;

        // Two channels and a pump, because the stack wants somewhere to put
        // packets and somewhere to take them from, while the tunnel wants to
        // be sent and received on.
        let (to_tunnel, mut from_stack) = mpsc::channel::<Vec<u8>>(64);
        let (to_stack, from_tunnel) = mpsc::channel::<Vec<u8>>(64);

        let mut tunnel = self;
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    outbound = from_stack.recv() => match outbound {
                        Some(packet) => {
                            if tunnel.send(packet).await.is_err() {
                                return;
                            }
                        }
                        // The stack has gone, so nothing more will be sent and
                        // nothing more is worth receiving.
                        None => return,
                    },
                    inbound = tunnel.recv() => match inbound {
                        // Dropped rather than waited on: this is a link, and a
                        // link that blocks stops carrying in both directions.
                        // TCP above asks again.
                        Some(packet) => {
                            let _ = to_stack.try_send(packet);
                        }
                        None => return,
                    },
                }
            }
        });

        TunnelStream::connect(to_tunnel, from_tunnel, ifconfig, remote, patience).await
    }

    /// Why the tunnel stopped, if it has.
    pub fn failure(&self) -> Option<Error> {
        self.failure.lock().ok().and_then(|failure| failure.clone())
    }

    fn why_it_stopped(&self) -> Error {
        self.failure()
            .unwrap_or_else(|| Error::Io("the tunnel has stopped".into()))
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Whether a socket error is about this moment rather than about the tunnel.
///
/// The socket is `connect`ed, which is what lets the loop use `send`/`recv`
/// without carrying the peer address around — and which also means the kernel
/// reports ICMP back to us. A server that has not finished starting, a NAT
/// that has forgotten the binding, a router that briefly has no route: each
/// arrives as an error on the *next* operation, and each is exactly what the
/// retransmission layer exists to ride out. Ending the tunnel on one turns a
/// blip into a permanent failure.
///
/// All of these are delivered once, for one ICMP message, so treating them as
/// non-fatal cannot spin: the following `recv` waits like any other. Errors
/// that describe the socket itself — a bad descriptor, a lost binding — are
/// not on this list and still end the loop.
fn is_transient(error: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;

    matches!(
        error.kind(),
        ConnectionRefused | ConnectionReset | HostUnreachable | NetworkUnreachable | TimedOut
    )
}

/// The loop.
async fn run(
    socket: UdpSocket,
    mut session: Session,
    mut from_caller: mpsc::Receiver<Vec<u8>>,
    to_caller: mpsc::Sender<Vec<u8>>,
    failure: Arc<Mutex<Option<Error>>>,
    ready: tokio::sync::oneshot::Sender<Result<Option<Ifconfig>, Error>>,
) {
    let mut ready = Some(ready);
    let mut buffer = vec![0u8; 4096];
    let mut last_heard = Instant::now();

    let outcome = loop {
        // Everything the session wants to say, before deciding how long to
        // wait.
        loop {
            let now = Instant::now();
            let Some(datagram) = session.poll_transmit(now, net_time()) else {
                break;
            };
            if let Err(error) = socket.send(&datagram).await {
                // A link that cannot carry this datagram now. The layer above
                // will send it again.
                if is_transient(&error) {
                    continue;
                }
                let error = Error::Io(error.to_string());
                break_with(&mut ready, error.clone());
                return finish(failure, error);
            }
        }
        if let Some(error) = session.failure() {
            break error.clone();
        }

        // The moment it becomes carrying, the caller waiting on `connect` is
        // told.
        if session.is_ready() {
            if let Some(ready) = ready.take() {
                // Read here rather than kept on the session: the push reply is
                // the only place the server says where we are, and the session
                // is about to be shut away inside this loop.
                let ifconfig = session.push_reply().and_then(|reply| {
                    reply
                        .ifconfig
                        .map(|(address, second)| Ifconfig::from_push(address, second))
                });
                let _ = ready.send(Ok(ifconfig));
            }
        }

        // A peer that has stopped answering. `ping-restart` is how long it
        // waits before giving up on us, and it is the same question in the
        // other direction — without asking it, a vanished peer leaves the
        // tunnel reporting no failure, `recv` pending forever, and `send`
        // returning `Ok` while every payload goes nowhere.
        //
        // Only where silence means something. A server that asked for no
        // keepalives is one nothing is expected from, and counting its quiet
        // would end a tunnel that is working exactly as arranged.
        if let Some(limit) = session.peer_timeout() {
            if last_heard.elapsed() >= limit {
                break Error::PeerGone(limit);
            }
        }

        let wakeup = session
            .next_wakeup(Instant::now())
            .map(|at| at.saturating_duration_since(Instant::now()))
            // Bounded so the dead-peer check above runs even when the session
            // believes it has nothing to wait for.
            .unwrap_or(IDLE_POLL)
            .min(IDLE_POLL.max(Duration::from_secs(1)));

        tokio::select! {
            received = socket.recv(&mut buffer) => match received {
                Ok(len) => {
                    last_heard = Instant::now();
                    let datagram = &buffer[..len];
                    if Session::is_data(datagram) {
                        match session.receive_payload(datagram) {
                            // A keepalive: addressed to the tunnel, not
                            // through it.
                            Ok(None) => {}
                            Ok(Some(payload)) => match to_caller.try_send(payload) {
                                Ok(()) => {}
                                // The caller is behind. Dropping is what a
                                // link does when a queue fills, and what
                                // sits above this tunnel will ask again —
                                // whereas waiting here stops the loop, and a
                                // loop that stops sends no keepalives and is
                                // dropped by the peer for silence.
                                Err(mpsc::error::TrySendError::Full(_)) => {}
                                Err(mpsc::error::TrySendError::Closed(_)) => {
                                    break Error::Io("nobody is reading the tunnel".into())
                                }
                            },
                            Err(error) if error.is_fatal() => break error,
                            // One packet, not the session.
                            Err(_) => {}
                        }
                    } else if let Err(error) = session.handle(datagram, Instant::now()) {
                        if error.is_fatal() {
                            break error;
                        }
                    }
                }
                // Something the socket reports once and recovers from,
                // rather than a reason to end the tunnel.
                Err(error) if is_transient(&error) => {}
                Err(error) => break Error::Io(error.to_string()),
            },

            outbound = from_caller.recv() => match outbound {
                Some(payload) => match session.send_payload(Instant::now(), &payload) {
                    Ok(datagram) => {
                        if let Err(error) = socket.send(&datagram).await {
                            if !is_transient(&error) {
                                break Error::Io(error.to_string());
                            }
                            // Dropped, as a link drops what it cannot carry.
                            // What sits above this tunnel is TCP, and TCP's
                            // answer to a lost segment is to send it again.
                        }
                    }
                    Err(error) if error.is_fatal() => break error,
                    Err(_) => {}
                },
                // The caller has gone.
                None => break Error::Io("the tunnel was dropped".into()),
            },

            _ = tokio::time::sleep(wakeup) => {}
        }
    };

    break_with(&mut ready, outcome.clone());
    finish(failure, outcome);
}

/// Tell a caller still waiting on `connect` why it will not happen.
fn break_with(
    ready: &mut Option<tokio::sync::oneshot::Sender<Result<Option<Ifconfig>, Error>>>,
    error: Error,
) {
    if let Some(ready) = ready.take() {
        let _ = ready.send(Err(error));
    }
}

fn finish(failure: Arc<Mutex<Option<Error>>>, error: Error) {
    if let Ok(mut failure) = failure.lock() {
        *failure = Some(error);
    }
}

fn net_time() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs() as u32)
        .unwrap_or(0)
}
