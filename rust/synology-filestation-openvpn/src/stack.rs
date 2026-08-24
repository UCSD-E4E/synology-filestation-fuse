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

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Instant as StdInstant;

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{IpAddress, IpCidr};
use tokio::sync::{mpsc, Mutex};

use crate::ip::Ifconfig;
use crate::Error;

/// What the tunnel's MTU leaves for a TCP payload.
///
/// The server pushes `mssfix 1450`, and the packets we hand it are already
/// inside an encrypted datagram. Claiming more than fits would produce
/// fragmentation the tunnel cannot do anything useful with.
const MTU: usize = 1400;

/// How much each direction may buffer.
///
/// A window, in effect: this is what the far end is allowed to have in flight
/// before it must wait for us to read.
const BUFFER: usize = 64 * 1024;

/// The device `smoltcp` drives, which is the tunnel wearing a different hat.
///
/// Everything above treats it as a network card; everything below is
/// `Tunnel::send` and `Tunnel::recv`.
pub struct TunnelDevice {
    outbound: mpsc::Sender<Vec<u8>>,
    inbound: mpsc::Receiver<Vec<u8>>,
}

impl TunnelDevice {
    pub fn new(outbound: mpsc::Sender<Vec<u8>>, inbound: mpsc::Receiver<Vec<u8>>) -> Self {
        Self { outbound, inbound }
    }

    fn take(&mut self) -> Option<Vec<u8>> {
        // Never blocking: `smoltcp` is asking whether anything has arrived,
        // and "not yet" is an answer.
        self.inbound.try_recv().ok()
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
        let packet = self.take()?;
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

/// One TCP connection over the tunnel.
pub struct TunnelStream {
    inner: Arc<Mutex<StackInner>>,
    handle: smoltcp::iface::SocketHandle,
}

struct StackInner {
    device: TunnelDevice,
    interface: Interface,
    sockets: SocketSet<'static>,
    started: StdInstant,
}

impl StackInner {
    /// Let `smoltcp` do whatever the clock and the arrived packets allow.
    fn poll(&mut self) {
        let now = Instant::from_micros(self.started.elapsed().as_micros() as i64);
        self.interface
            .poll(now, &mut self.device, &mut self.sockets);
    }
}

impl TunnelStream {
    /// Open a connection through the tunnel.
    ///
    /// `ifconfig` is where the server put us; `remote` is what we are dialling
    /// — for this driver's purpose, the NAS at its address inside the tunnel.
    pub async fn connect(
        outbound: mpsc::Sender<Vec<u8>>,
        inbound: mpsc::Receiver<Vec<u8>>,
        ifconfig: Ifconfig,
        remote: (Ipv4Addr, u16),
    ) -> Result<Self, Error> {
        let mut device = TunnelDevice::new(outbound, inbound);
        let started = StdInstant::now();
        let now = Instant::from_micros(0);

        let mut interface = Interface::new(
            Config::new(smoltcp::wire::HardwareAddress::Ip),
            &mut device,
            now,
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

        let inner = Arc::new(Mutex::new(StackInner {
            device,
            interface,
            sockets,
            started,
        }));

        {
            let mut guard = inner.lock().await;
            let StackInner {
                interface, sockets, ..
            } = &mut *guard;
            let socket = sockets.get_mut::<tcp::Socket>(handle);
            socket
                .connect(
                    interface.context(),
                    (IpAddress::Ipv4(remote.0), remote.1),
                    // An ephemeral source port. Anything unused will do; the
                    // far end only cares that it is consistent.
                    49152 + (rand::random::<u16>() % 16000),
                )
                .map_err(|error| Error::Io(format!("connect: {error}")))?;
            guard.poll();
        }

        Ok(Self { inner, handle })
    }

    /// Drive the stack once, and say whether the connection is up.
    ///
    /// The caller is expected to keep calling this — it is what turns arrived
    /// packets into acknowledgements and queued bytes into segments.
    pub async fn poll(&self) -> bool {
        let mut guard = self.inner.lock().await;
        guard.poll();
        guard.sockets.get::<tcp::Socket>(self.handle).may_send()
    }

    /// Queue bytes for the far end. Returns how many were taken.
    pub async fn write(&self, data: &[u8]) -> Result<usize, Error> {
        let mut guard = self.inner.lock().await;
        let taken = {
            let socket = guard.sockets.get_mut::<tcp::Socket>(self.handle);
            if !socket.may_send() {
                return Err(Error::Io("the connection is not open".into()));
            }
            socket
                .send_slice(data)
                .map_err(|error| Error::Io(format!("send: {error}")))?
        };
        guard.poll();
        Ok(taken)
    }

    /// Take whatever has arrived. Empty means nothing yet, not end of stream.
    pub async fn read(&self, buffer: &mut [u8]) -> Result<usize, Error> {
        let mut guard = self.inner.lock().await;
        guard.poll();
        let socket = guard.sockets.get_mut::<tcp::Socket>(self.handle);
        if !socket.can_recv() {
            return Ok(0);
        }
        socket
            .recv_slice(buffer)
            .map_err(|error| Error::Io(format!("recv: {error}")))
    }

    /// Whether the far end has accepted the connection.
    pub async fn is_open(&self) -> bool {
        let mut guard = self.inner.lock().await;
        guard.poll();
        guard.sockets.get::<tcp::Socket>(self.handle).is_active()
    }
}
