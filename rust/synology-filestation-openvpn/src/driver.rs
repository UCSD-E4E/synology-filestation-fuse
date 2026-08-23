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

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::session::{Session, SessionConfig};
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
    task: JoinHandle<()>,
}

impl Tunnel {
    /// Bring a tunnel up, and return once it is carrying.
    pub async fn connect(config: SessionConfig, remote: SocketAddr) -> Result<Self, Error> {
        // Bound to whatever the OS gives us: this is a client, and `nobind` is
        // what the published profile says.
        let socket = UdpSocket::bind(("0.0.0.0", 0))
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

        match tokio::time::timeout(CONNECT_TIMEOUT, is_ready).await {
            Ok(Ok(Ok(()))) => Ok(Self {
                outgoing: to_tunnel,
                incoming: from_tunnel,
                failure,
                task,
            }),
            // The task reported why it could not.
            Ok(Ok(Err(error))) => Err(error),
            // The task ended without saying anything, which is a bug in it
            // rather than in the peer.
            Ok(Err(_)) => Err(Error::Io("the tunnel task stopped".into())),
            Err(_) => Err(Error::HandshakeTimeout),
        }
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

/// The loop.
async fn run(
    socket: UdpSocket,
    mut session: Session,
    mut from_caller: mpsc::Receiver<Vec<u8>>,
    to_caller: mpsc::Sender<Vec<u8>>,
    failure: Arc<Mutex<Option<Error>>>,
    ready: tokio::sync::oneshot::Sender<Result<(), Error>>,
) {
    let mut ready = Some(ready);
    let mut buffer = vec![0u8; 4096];

    let outcome = loop {
        // Everything the session wants to say, before deciding how long to
        // wait.
        loop {
            let now = Instant::now();
            let Some(datagram) = session.poll_transmit(now, net_time()) else {
                break;
            };
            if let Err(error) = socket.send(&datagram).await {
                break_with(&mut ready, Error::Io(error.to_string()));
                return finish(failure, Error::Io("send failed".into()));
            }
        }
        if let Some(error) = session.failure() {
            break error.clone();
        }

        // The moment it becomes carrying, the caller waiting on `connect` is
        // told.
        if session.is_ready() {
            if let Some(ready) = ready.take() {
                let _ = ready.send(Ok(()));
            }
        }

        let wakeup = session
            .next_wakeup(Instant::now())
            .map(|at| at.saturating_duration_since(Instant::now()))
            .unwrap_or(IDLE_POLL);

        tokio::select! {
            received = socket.recv(&mut buffer) => match received {
                Ok(len) => {
                    let datagram = &buffer[..len];
                    if Session::is_data(datagram) {
                        match session.receive_payload(datagram) {
                            // A keepalive: addressed to the tunnel, not
                            // through it.
                            Ok(None) => {}
                            Ok(Some(payload)) => {
                                if to_caller.send(payload).await.is_err() {
                                    break Error::Io("nobody is reading the tunnel".into());
                                }
                            }
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
                Err(error) => break Error::Io(error.to_string()),
            },

            outbound = from_caller.recv() => match outbound {
                Some(payload) => match session.send_payload(Instant::now(), &payload) {
                    Ok(datagram) => {
                        if let Err(error) = socket.send(&datagram).await {
                            break Error::Io(error.to_string());
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
fn break_with(ready: &mut Option<tokio::sync::oneshot::Sender<Result<(), Error>>>, error: Error) {
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
