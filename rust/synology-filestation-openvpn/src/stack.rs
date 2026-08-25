//! A TCP stack that lives in this process.
//!
//! The tunnel carries IP packets, because `dev tun` is a layer-3 device. The
//! operating system knows nothing about them — that is the whole point, and
//! the reason none of this needs a tun device, an installer component or a
//! privilege it does not have. So the packets need somewhere to go, and that
//! somewhere is here: `smoltcp`, an interface holding the address the server
//! assigned us, and one TCP connection to one port on one host.
//!
//! Deliberately one connection. This tunnel exists to carry SMB to a NAS that
//! terminates it; a general-purpose stack would be more code doing more than
//! anyone asked for.
//!
//! ## Why a task rather than a handle to poll
//!
//! `smoltcp` is sans-io like the rest of this crate: it does nothing until
//! polled, and it must be polled on a *timer* as well as on arrival, because
//! retransmission and delayed acknowledgement are things it does on its own
//! clock. Exposing that as a `poll()` for the caller to call put the whole
//! protocol's correctness in the hands of whoever used it — and the caller
//! this exists for is `smb2`, which reads and writes and quite reasonably
//! expects a stream to keep working while it is doing neither.
//!
//! So the stack gets a task of its own, exactly as the tunnel below it does,
//! and what comes out is an ordinary [`AsyncRead`] + [`AsyncWrite`].

use std::io;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant as StdInstant};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{IpAddress, IpCidr};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::PollSender;

use crate::ip::Ifconfig;
use crate::Error;

/// What the tunnel's MTU leaves for a TCP payload.
///
/// The server pushes `mssfix 1450`, and the packets we hand it are already
/// inside an encrypted datagram. Claiming more than fits would produce
/// fragmentation the tunnel cannot do anything useful with.
const MTU: usize = 1400;

/// How much each direction may buffer inside the stack.
///
/// A window, in effect: this is what the far end is allowed to have in flight
/// before it must wait for us to read.
const BUFFER: usize = 64 * 1024;

/// The largest piece of a write handed to the stack at once.
///
/// A caller writing a megabyte should not turn into a megabyte-long
/// allocation in the queue; it turns into pieces the send buffer can take.
const WRITE_CHUNK: usize = 16 * 1024;

/// How many pieces may sit between the stack and the reader, or the writer and
/// the stack.
///
/// Small on purpose. This is not where buffering belongs — the socket's own
/// window is — and a deep queue here would let the far end believe bytes had
/// been read that are still in a channel.
const QUEUE_DEPTH: usize = 8;

/// A ceiling on how long the loop will sleep when `smoltcp` asks for nothing.
///
/// It should not happen, but a stack that sleeps forever on a wrong answer is
/// a stack that hangs.
const IDLE_POLL: Duration = Duration::from_millis(50);

/// The device `smoltcp` drives, which is the tunnel wearing a different hat.
///
/// Everything above treats it as a network card; everything below is
/// `Tunnel::send` and `Tunnel::recv`. Arrived packets are [`push`]ed in by
/// whoever is driving, rather than pulled from a channel here, because the
/// driver has to *wait* on that channel among other things and a device is
/// only ever asked whether something has already arrived.
///
/// [`push`]: TunnelDevice::push
pub struct TunnelDevice {
    outbound: mpsc::Sender<Vec<u8>>,
    inbox: std::collections::VecDeque<Vec<u8>>,
}

impl TunnelDevice {
    pub fn new(outbound: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            outbound,
            inbox: std::collections::VecDeque::new(),
        }
    }

    /// Hand the device a packet that arrived from the tunnel.
    pub fn push(&mut self, packet: Vec<u8>) {
        self.inbox.push_back(packet);
    }
}

impl Device for TunnelDevice {
    type RxToken<'a>
        = TunnelRx
    where
        Self: 'a;
    type TxToken<'a>
        = TunnelTx<'a>
    where
        Self: 'a;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        // Layer three: no ethernet header, because `dev tun` has none.
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = MTU;
        capabilities
    }

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.inbox.pop_front()?;
        Some((
            TunnelRx { packet },
            TunnelTx {
                outbound: &self.outbound,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TunnelTx {
            outbound: &self.outbound,
        })
    }
}

pub struct TunnelRx {
    packet: Vec<u8>,
}

impl RxToken for TunnelRx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.packet)
    }
}

pub struct TunnelTx<'a> {
    outbound: &'a mpsc::Sender<Vec<u8>>,
}

impl TxToken for TunnelTx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        // Dropped if the tunnel is gone or its queue is full, which is what a
        // link does with a packet it cannot carry. TCP above will send it
        // again.
        let _ = self.outbound.try_send(buffer);
        result
    }
}

/// How much of what the caller wrote is still ours to deliver.
///
/// Without this, `flush` and `shutdown` could only lie: they would return the
/// moment the bytes reached a channel, and `Drop` — which stops the task —
/// would then throw away everything the stack had not got round to sending. A
/// caller that writes, flushes and lets go is entitled to have the write
/// happen.
/// A count rather than a flag, because a flag cannot be asked the question.
/// The caller knows how many bytes it has handed over; what it needs to know
/// is whether *those* have arrived. A "nothing outstanding" flag is still true
/// for the moment between a write reaching the queue and the stack noticing
/// it, and a flush that returns in that moment returns too early.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Progress {
    /// Bytes from the caller the far end has acknowledged.
    acknowledged: u64,
    /// Our half is closed and everything written went out before the FIN.
    closed: bool,
}

/// One TCP connection over the tunnel, as a stream.
pub struct TunnelStream {
    writes: PollSender<Vec<u8>>,
    reads: mpsc::Receiver<Vec<u8>>,
    /// What was handed over but has not been copied out yet, and how much of
    /// it is gone. A reader is entitled to ask for one byte at a time.
    partial: Vec<u8>,
    taken: usize,
    /// How many bytes have been accepted from the caller, ever. What `flush`
    /// waits to see acknowledged.
    written: u64,
    progress: watch::Receiver<Progress>,
    /// Waits in progress, because these are polled repeatedly and the wait has
    /// to survive between calls.
    ///
    /// One slot each, rather than one between them: a `flush` that is
    /// abandoned — a timeout, a `select!` losing the race — leaves its wait
    /// behind, and a shared slot would hand it to the next `shutdown` to
    /// finish, which would then be waiting for the wrong thing entirely.
    flushing: Wait,
    shutting_down: Wait,
    task: JoinHandle<()>,
}

/// A wait on the stack's progress, kept across polls.
type Wait = Option<Pin<Box<dyn std::future::Future<Output = ()> + Send>>>;

/// Wait until the stack says what the caller is waiting for is true.
///
/// A stack that has stopped answers every question the same way: there is
/// nothing more it will do, so there is nothing more to wait for.
fn until(
    mut progress: watch::Receiver<Progress>,
    done: impl Fn(Progress) -> bool + Send + 'static,
) -> Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
    Box::pin(async move {
        while !done(*progress.borrow_and_update()) {
            if progress.changed().await.is_err() {
                return;
            }
        }
    })
}

impl TunnelStream {
    /// Open a connection through the tunnel, and return once it is up.
    ///
    /// `ifconfig` is where the server put us; `remote` is what we are dialling
    /// — for this driver's purpose, the NAS at its address inside the tunnel.
    /// `patience` bounds the wait: a peer that never answers is a failure, not
    /// a caller blocked forever.
    pub async fn connect(
        outbound: mpsc::Sender<Vec<u8>>,
        inbound: mpsc::Receiver<Vec<u8>>,
        ifconfig: Ifconfig,
        remote: (Ipv4Addr, u16),
        patience: Duration,
    ) -> Result<Self, Error> {
        let mut device = TunnelDevice::new(outbound);
        let started = StdInstant::now();

        let mut interface = Interface::new(
            Config::new(smoltcp::wire::HardwareAddress::Ip),
            &mut device,
            Instant::from_micros(0),
        );
        interface.update_ip_addrs(|addresses| {
            let _ = addresses.push(IpCidr::new(
                IpAddress::Ipv4(ifconfig.address),
                ifconfig.prefix,
            ));
        });

        let socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; BUFFER]),
            tcp::SocketBuffer::new(vec![0u8; BUFFER]),
        );
        let mut sockets = SocketSet::new(Vec::new());
        let handle = sockets.add(socket);

        sockets
            .get_mut::<tcp::Socket>(handle)
            .connect(
                interface.context(),
                (IpAddress::Ipv4(remote.0), remote.1),
                // An ephemeral source port. Anything unused will do; the far
                // end only cares that it is consistent.
                49152 + (rand::random::<u16>() % 16000),
            )
            .map_err(|error| Error::Io(format!("connect: {error}")))?;

        let (to_stack, from_caller) = mpsc::channel(QUEUE_DEPTH);
        let (to_caller, from_stack) = mpsc::channel(QUEUE_DEPTH);
        let (up, is_up) = tokio::sync::oneshot::channel();
        let (progress, watching) = watch::channel(Progress {
            acknowledged: 0,
            closed: false,
        });

        let task = tokio::spawn(drive(
            Driver {
                device,
                interface,
                sockets,
                handle,
                inbound,
                from_caller,
                to_caller: Some(to_caller),
                progress,
                started,
            },
            up,
        ));

        match tokio::time::timeout(patience, is_up).await {
            Ok(Ok(Ok(()))) => Ok(Self {
                writes: PollSender::new(to_stack),
                reads: from_stack,
                partial: Vec::new(),
                taken: 0,
                written: 0,
                progress: watching,
                flushing: None,
                shutting_down: None,
                task,
            }),
            Ok(Ok(Err(error))) => {
                task.abort();
                Err(error)
            }
            // The task ended without saying anything, which is a bug in it
            // rather than in the peer.
            Ok(Err(_)) => {
                task.abort();
                Err(Error::Io("the stack stopped".into()))
            }
            Err(_) => {
                task.abort();
                Err(Error::Io(format!(
                    "no answer from {}:{} inside the tunnel",
                    remote.0, remote.1
                )))
            }
        }
    }
}

impl Drop for TunnelStream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl AsyncRead for TunnelStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();

        while me.taken == me.partial.len() {
            match me.reads.poll_recv(cx) {
                Poll::Ready(Some(chunk)) => {
                    me.partial = chunk;
                    me.taken = 0;
                }
                // The connection is over. Zero bytes means exactly this and
                // nothing else, which is what lets a framing layer above tell
                // "the peer hung up" from "not yet".
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }

        let available = &me.partial[me.taken..];
        let wanted = available.len().min(buf.remaining());
        buf.put_slice(&available[..wanted]);
        me.taken += wanted;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for TunnelStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();

        match me.writes.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(_)) => return Poll::Ready(Err(gone())),
            Poll::Pending => return Poll::Pending,
        }

        let taking = buf.len().min(WRITE_CHUNK);
        me.writes
            .send_item(buf[..taking].to_vec())
            .map_err(|_| gone())?;
        me.written += taking as u64;
        Poll::Ready(Ok(taking))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        let written = me.written;
        poll_wait(&mut me.flushing, &me.progress, cx, move |progress| {
            progress.acknowledged >= written
        })
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        // Closing our half of the channel is how the stack is told to close
        // its half of the connection — and then we wait for it to have done
        // so, because a shutdown that returns before the bytes went out is
        // the thing a shutdown exists to prevent.
        me.writes.close();
        poll_wait(&mut me.shutting_down, &me.progress, cx, |progress| {
            progress.closed
        })
    }
}

/// Poll a wait, starting it if it has not started.
fn poll_wait(
    slot: &mut Wait,
    progress: &watch::Receiver<Progress>,
    cx: &mut Context<'_>,
    done: impl Fn(Progress) -> bool + Send + 'static,
) -> Poll<io::Result<()>> {
    let waiting = slot.get_or_insert_with(|| until(progress.clone(), done));
    match waiting.as_mut().poll(cx) {
        Poll::Ready(()) => {
            *slot = None;
            Poll::Ready(Ok(()))
        }
        Poll::Pending => Poll::Pending,
    }
}

fn gone() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "the tunnel stack has stopped")
}

/// Everything the loop owns.
struct Driver {
    device: TunnelDevice,
    interface: Interface,
    sockets: SocketSet<'static>,
    handle: SocketHandle,
    /// Packets arriving from the tunnel.
    inbound: mpsc::Receiver<Vec<u8>>,
    /// Bytes the caller wants sent.
    from_caller: mpsc::Receiver<Vec<u8>>,
    /// How much of what the caller wrote is still ours to deliver.
    progress: watch::Sender<Progress>,
    /// Bytes that arrived for the caller, until the peer stops sending.
    ///
    /// Dropped at that point and not before: letting go of it is how a reader
    /// above is told the stream has ended, and it is a different event from
    /// the connection being over. A peer that has said everything it intends
    /// to say still owes us an acknowledgement for what we are sending.
    to_caller: Option<mpsc::Sender<Vec<u8>>>,
    started: StdInstant,
}

impl Driver {
    fn now(&self) -> Instant {
        Instant::from_micros(self.started.elapsed().as_micros() as i64)
    }

    fn socket(&mut self) -> &mut tcp::Socket<'static> {
        self.sockets.get_mut::<tcp::Socket>(self.handle)
    }
}

/// The loop: poll, move bytes in both directions, and wait for whichever of
/// the four things that can happen next happens first.
async fn drive(mut driver: Driver, up: tokio::sync::oneshot::Sender<Result<(), Error>>) {
    let mut up = Some(up);
    // Whether the connection has ever been up, which is what separates "the
    // peer has stopped sending" from "it has not started".
    let mut established = false;
    // Bytes accepted from the caller that the send buffer had no room for.
    let mut queued: Vec<u8> = Vec::new();
    // How many bytes have been taken from the caller's queue, ever.
    let mut accepted: u64 = 0;
    // Whether the caller has finished writing, so the connection should be
    // closed once what it wrote has gone.
    let mut closing = false;

    loop {
        let now = driver.now();
        driver
            .interface
            .poll(now, &mut driver.device, &mut driver.sockets);

        // The moment it is carrying, whoever called `connect` is told.
        if driver.socket().may_send() {
            established = true;
            if let Some(up) = up.take() {
                let _ = up.send(Ok(()));
            }
        }

        // Out: as much of what the caller wrote as the window will take.
        if !queued.is_empty() && driver.socket().can_send() {
            match driver.socket().send_slice(&queued) {
                Ok(sent) => drop(queued.drain(..sent)),
                Err(_) => break,
            }
        }
        if closing && queued.is_empty() && driver.socket().may_send() {
            driver.socket().close();
        }

        // What anyone waiting on `flush` or `shutdown` is waiting for. What
        // has been taken from the caller, less what is still waiting for the
        // window and what the far end has not acknowledged — so this counts
        // bytes that *arrived*, rather than bytes that merely left.
        let outstanding = (queued.len() + driver.socket().send_queue()) as u64;
        let acknowledged = accepted.saturating_sub(outstanding);
        let closed = closing && outstanding == 0 && !driver.socket().may_send();
        driver.progress.send_replace(Progress {
            acknowledged,
            closed,
        });

        // In: only as much as there is somewhere to put. Bytes left in the
        // socket are the window closing, which is how a reader that has
        // stopped reading slows the far end down instead of losing anything.
        let mut buffer = [0u8; 8 * 1024];
        {
            // Split apart so the socket and the caller's queue can be held at
            // once: they are different fields, which the borrow checker only
            // believes when it is shown them separately.
            let Driver {
                sockets,
                handle,
                to_caller,
                ..
            } = &mut driver;
            let socket = sockets.get_mut::<tcp::Socket>(*handle);
            while let (true, Some(sender)) = (socket.can_recv(), to_caller.as_ref()) {
                let Ok(permit) = sender.try_reserve() else {
                    break;
                };
                match socket.recv_slice(&mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(len) => permit.send(buffer[..len].to_vec()),
                }
            }
        }

        // The peer has closed its half and everything it sent has been
        // handed over. Letting go of the sender here is the end of stream a
        // reader above is waiting for — and doing it on this condition rather
        // than on the connection being finished is what stops a peer that
        // closes politely from leaving a reader waiting forever, which is
        // exactly how SMB servers end a session.
        if established && !driver.socket().may_recv() && !driver.socket().can_recv() {
            driver.to_caller = None;
        }
        if !driver.socket().is_active() {
            break;
        }

        // Whether there are bytes waiting on a reader that has not caught up.
        let waiting_on_reader = driver.socket().can_recv() && driver.to_caller.is_some();
        let accepting_writes = queued.is_empty() && !closing;
        let delay = driver
            .interface
            .poll_delay(driver.now(), &driver.sockets)
            .map(|delay| Duration::from_micros(delay.total_micros()))
            .unwrap_or(IDLE_POLL)
            .min(IDLE_POLL);

        tokio::select! {
            packet = driver.inbound.recv() => match packet {
                Some(packet) => driver.device.push(packet),
                // The tunnel has stopped, so the connection through it has
                // too.
                None => break,
            },

            written = driver.from_caller.recv(), if accepting_writes => match written {
                Some(bytes) => {
                    accepted += bytes.len() as u64;
                    queued = bytes;
                }
                // The caller has finished writing, or gone.
                None => closing = true,
            },

            // Room for the reader appearing is a reason to wake: there are
            // bytes sitting in the socket waiting for it.
            _ = async {
                match driver.to_caller.as_ref() {
                    Some(sender) => { let _ = sender.reserve().await; }
                    None => std::future::pending().await,
                }
            }, if waiting_on_reader => {}

            _ = tokio::time::sleep(delay) => {}
        }
    }

    // Nothing more will be sent, whatever anyone is waiting for. Saying so
    // beats leaving a `flush` waiting on a stack that has stopped.
    driver.progress.send_replace(Progress {
        acknowledged: u64::MAX,
        closed: true,
    });

    // Whoever is waiting on `connect` hears why, rather than waiting out the
    // whole timeout for an answer that is never coming.
    if let Some(up) = up.take() {
        let _ = up.send(Err(Error::Io("the connection was refused or reset".into())));
    }
}
