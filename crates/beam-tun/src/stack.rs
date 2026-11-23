//! Pluggable Layer 3 -> Layer 4 TCP stack abstraction (`NetStack`) and its
//! Phase 1 `smoltcp` implementation (`SmoltcpStack`).
//!
//! Designing `beam-tun` around `NetStack` lets Phase 2 swap in a custom
//! lightweight proxy TCP/IP stack without touching the TUN device, router,
//! XUDP bridge, or `beam-client` binary.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer, State as TcpState};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpListenEndpoint, Ipv4Address};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, mpsc};

use crate::packet::{IP_PROTO_TCP, parse_ipv4, parse_tcp_syn};

const DEFAULT_MAX_TCP_CONNECTIONS: usize = 256;
const DEFAULT_TCP_BUFFER_BYTES: usize = 64 * 1024;
const STREAM_CHANNEL_CAPACITY: usize = 32;
const MAX_POLL_ITERATIONS: usize = 16;

/// Tuning parameters for a [`NetStack`] implementation.
#[derive(Clone, Copy, Debug)]
pub struct TcpStackConfig {
    /// Interface MTU in bytes (typically 1500).
    pub mtu: usize,
    /// Maximum concurrent TCP sockets tracked by the stack.
    pub max_connections: usize,
    /// Per-socket TCP receive/send buffer size in bytes.
    pub socket_buffer_bytes: usize,
}

impl Default for TcpStackConfig {
    fn default() -> Self {
        Self {
            mtu: 1500,
            max_connections: DEFAULT_MAX_TCP_CONNECTIONS,
            socket_buffer_bytes: DEFAULT_TCP_BUFFER_BYTES,
        }
    }
}

/// An accepted TCP connection emitted by a [`NetStack`].
pub struct AcceptedTcpStream {
    /// Client source address inside the TUN.
    pub src: SocketAddrV4,
    /// Intended remote destination address.
    pub dst: SocketAddrV4,
    /// Bidirectional async stream bridged to the stack's TCP state machine.
    pub stream: TunTcpStream,
}

/// Pluggable Layer 3 -> Layer 4 TCP stack interface.
pub trait NetStack: Send + 'static {
    /// Feeds one incoming IPv4 TCP packet from the TUN device into the stack.
    fn push_ipv4_tcp(&mut self, packet: &[u8]);

    /// Advances timers, drains relay <-> TCP buffers, emits newly accepted
    /// connections into `accepted`, and appends outbound IPv4 packets to `tx_out`.
    fn poll(
        &mut self,
        now_ms: i64,
        tx_out: &mut Vec<Vec<u8>>,
        accepted: &mut Vec<AcceptedTcpStream>,
    );

    /// Returns the number of milliseconds until the next scheduled stack timer,
    /// or `None` if no timer is pending.
    fn poll_delay_ms(&mut self, now_ms: i64) -> Option<u64>;

    /// Returns a handle notified whenever a relay writes to or closes a
    /// [`TunTcpStream`], allowing the engine loop to wake immediately.
    fn waker(&self) -> Arc<Notify>;
}

/// Async TCP stream bridged to a [`NetStack`] socket.
pub struct TunTcpStream {
    from_stack: mpsc::Receiver<Vec<u8>>,
    read_buf: Vec<u8>,
    read_offset: usize,
    to_stack: Option<mpsc::Sender<Vec<u8>>>,
    waker: Arc<Notify>,
}

impl AsyncRead for TunTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        if this.read_offset < this.read_buf.len() {
            let avail = &this.read_buf[this.read_offset..];
            let n = avail.len().min(buf.remaining());
            buf.put_slice(&avail[..n]);
            this.read_offset += n;
            if this.read_offset == this.read_buf.len() {
                this.read_buf.clear();
                this.read_offset = 0;
            }
            this.waker.notify_one();
            return Poll::Ready(Ok(()));
        }

        match this.from_stack.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
            Poll::Ready(Some(chunk)) => {
                let n = chunk.len().min(buf.remaining());
                buf.put_slice(&chunk[..n]);
                if n < chunk.len() {
                    this.read_buf = chunk;
                    this.read_offset = n;
                }
                this.waker.notify_one();
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl AsyncWrite for TunTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let Some(tx) = this.to_stack.as_ref() else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TUN TCP stream already shut down",
            )));
        };

        let chunk_len = buf.len().min(16 * 1024);
        match tx.try_send(buf[..chunk_len].to_vec()) {
            Ok(()) => {
                this.waker.notify_one();
                Poll::Ready(Ok(chunk_len))
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TUN TCP socket closed",
            ))),
            Err(mpsc::error::TrySendError::Full(_)) => {
                // Ask the stack to drain and re-wake this task.
                this.waker.notify_one();
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.waker.notify_one();
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.to_stack.take();
        this.waker.notify_one();
        Poll::Ready(Ok(()))
    }
}

impl Drop for TunTcpStream {
    fn drop(&mut self) {
        self.to_stack.take();
        self.waker.notify_one();
    }
}

/// In-memory virtual IP device backing `smoltcp::iface::Interface`.
struct VirtIpDevice {
    mtu: usize,
    rx_queue: VecDeque<Vec<u8>>,
    tx_queue: VecDeque<Vec<u8>>,
}

impl VirtIpDevice {
    fn new(mtu: usize) -> Self {
        Self {
            mtu,
            rx_queue: VecDeque::with_capacity(64),
            tx_queue: VecDeque::with_capacity(64),
        }
    }
}

struct VirtRxToken(Vec<u8>);

impl RxToken for VirtRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

struct VirtTxToken<'a>(&'a mut VecDeque<Vec<u8>>);

impl TxToken for VirtTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let result = f(&mut buf);
        self.0.push_back(buf);
        result
    }
}

impl Device for VirtIpDevice {
    type RxToken<'a> = VirtRxToken;
    type TxToken<'a> = VirtTxToken<'a>;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.rx_queue.pop_front()?;
        Some((VirtRxToken(pkt), VirtTxToken(&mut self.tx_queue)))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(VirtTxToken(&mut self.tx_queue))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

type FlowKey = (Ipv4Addr, u16, Ipv4Addr, u16);

struct ManagedTcpSocket {
    handle: SocketHandle,
    flow: FlowKey,
    accepted: bool,
    to_relay: Option<mpsc::Sender<Vec<u8>>>,
    from_relay: Option<mpsc::Receiver<Vec<u8>>>,
    pending_write: Vec<u8>,
    pending_write_offset: usize,
    relay_eof: bool,
}

/// Phase 1 [`NetStack`] implementation backed by `smoltcp` (`any_ip = true`).
pub struct SmoltcpStack {
    config: TcpStackConfig,
    iface: Interface,
    device: VirtIpDevice,
    sockets: SocketSet<'static>,
    managed: Vec<ManagedTcpSocket>,
    active_flows: HashMap<FlowKey, SocketHandle>,
    waker: Arc<Notify>,
}

impl SmoltcpStack {
    /// Creates a new `smoltcp`-backed TCP stack.
    pub fn new(config: TcpStackConfig) -> Self {
        let mut device = VirtIpDevice::new(config.mtu.max(576));
        let iface_cfg = IfaceConfig::new(HardwareAddress::Ip);
        let mut iface = Interface::new(iface_cfg, &mut device, SmolInstant::from_millis(0));
        iface.set_any_ip(true);
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::v4(172, 19, 0, 2), 30));
        });
        // With `any_ip = true`, smoltcp requires the default route's router_addr
        // to be an address owned by this interface (`has_ip_addr(router_addr)`).
        let _ = iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(172, 19, 0, 2));

        Self {
            config,
            iface,
            device,
            sockets: SocketSet::new(Vec::new()),
            managed: Vec::new(),
            active_flows: HashMap::new(),
            waker: Arc::new(Notify::new()),
        }
    }
}

impl NetStack for SmoltcpStack {
    fn push_ipv4_tcp(&mut self, packet: &[u8]) {
        let Some(ip) = parse_ipv4(packet) else {
            return;
        };
        if ip.protocol != IP_PROTO_TCP {
            return;
        }

        // On a fresh SYN, pre-allocate a listening smoltcp socket bound to the
        // exact (dst_ip, dst_port) so `any_ip` accepts the handshake.
        if let Some((src_port, dst_port)) = parse_tcp_syn(ip.payload) {
            let flow: FlowKey = (ip.src_ip, src_port, ip.dst_ip, dst_port);
            if !self.active_flows.contains_key(&flow)
                && self.managed.len() < self.config.max_connections
            {
                let rx_buf = SocketBuffer::new(vec![0u8; self.config.socket_buffer_bytes]);
                let tx_buf = SocketBuffer::new(vec![0u8; self.config.socket_buffer_bytes]);
                let mut sock = TcpSocket::new(rx_buf, tx_buf);
                sock.set_nagle_enabled(false);
                let listen_ep = IpListenEndpoint {
                    addr: Some(IpAddress::Ipv4(ip.dst_ip)),
                    port: dst_port,
                };
                if sock.listen(listen_ep).is_ok() {
                    let handle = self.sockets.add(sock);
                    self.active_flows.insert(flow, handle);
                    self.managed.push(ManagedTcpSocket {
                        handle,
                        flow,
                        accepted: false,
                        to_relay: None,
                        from_relay: None,
                        pending_write: Vec::new(),
                        pending_write_offset: 0,
                        relay_eof: false,
                    });
                }
            }
        }

        // Bound the device RX queue to prevent unbounded memory growth.
        if self.device.rx_queue.len() < 1024 {
            self.device.rx_queue.push_back(ip.raw.to_vec());
        }
    }

    fn poll(
        &mut self,
        now_ms: i64,
        tx_out: &mut Vec<Vec<u8>>,
        accepted: &mut Vec<AcceptedTcpStream>,
    ) {
        let timestamp = SmolInstant::from_millis(now_ms);

        for _ in 0..MAX_POLL_ITERATIONS {
            let mut made_progress = false;

            if self
                .iface
                .poll(timestamp, &mut self.device, &mut self.sockets)
                == smoltcp::iface::PollResult::SocketStateChanged
            {
                made_progress = true;
            }

            let mut i = 0;
            while i < self.managed.len() {
                let handle = self.managed[i].handle;
                let sock = self.sockets.get_mut::<TcpSocket<'static>>(handle);

                // 1. Hand off newly established sockets to the async relay.
                if !self.managed[i].accepted
                    && sock.is_active()
                    && sock.state() != TcpState::SynReceived
                {
                    let (to_relay_tx, to_relay_rx) = mpsc::channel(STREAM_CHANNEL_CAPACITY);
                    let (from_relay_tx, from_relay_rx) = mpsc::channel(STREAM_CHANNEL_CAPACITY);
                    let flow = self.managed[i].flow;
                    self.managed[i].accepted = true;
                    self.managed[i].to_relay = Some(to_relay_tx);
                    self.managed[i].from_relay = Some(from_relay_rx);
                    accepted.push(AcceptedTcpStream {
                        src: SocketAddrV4::new(flow.0, flow.1),
                        dst: SocketAddrV4::new(flow.2, flow.3),
                        stream: TunTcpStream {
                            from_stack: to_relay_rx,
                            read_buf: Vec::new(),
                            read_offset: 0,
                            to_stack: Some(from_relay_tx),
                            waker: Arc::clone(&self.waker),
                        },
                    });
                    made_progress = true;
                }

                // 2. Drain TUN -> relay (with TCP window backpressure).
                if let Some(to_relay) = self.managed[i].to_relay.as_ref() {
                    while sock.can_recv() {
                        let Ok(permit) = to_relay.try_reserve() else {
                            break;
                        };
                        let mut data = Vec::new();
                        let res = sock.recv(|buf| {
                            let take = buf.len().min(16 * 1024);
                            data.extend_from_slice(&buf[..take]);
                            (take, ())
                        });
                        if res.is_ok() && !data.is_empty() {
                            permit.send(data);
                            made_progress = true;
                        } else {
                            break;
                        }
                    }
                    // Peer sent FIN and all buffered data has been read.
                    if !sock.may_recv() && !sock.can_recv() {
                        self.managed[i].to_relay.take();
                    }
                }

                // 3. Drain relay -> TUN.
                if self.managed[i].accepted {
                    while sock.can_send() {
                        if self.managed[i].pending_write_offset
                            < self.managed[i].pending_write.len()
                        {
                            let slice = &self.managed[i].pending_write
                                [self.managed[i].pending_write_offset..];
                            match sock.send_slice(slice) {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    self.managed[i].pending_write_offset += n;
                                    if self.managed[i].pending_write_offset
                                        == self.managed[i].pending_write.len()
                                    {
                                        self.managed[i].pending_write.clear();
                                        self.managed[i].pending_write_offset = 0;
                                    }
                                    made_progress = true;
                                }
                            }
                        } else if let Some(from_relay) = self.managed[i].from_relay.as_mut() {
                            match from_relay.try_recv() {
                                Ok(chunk) => {
                                    self.managed[i].pending_write = chunk;
                                    self.managed[i].pending_write_offset = 0;
                                    made_progress = true;
                                }
                                Err(mpsc::error::TryRecvError::Empty) => break,
                                Err(mpsc::error::TryRecvError::Disconnected) => {
                                    self.managed[i].from_relay.take();
                                    self.managed[i].relay_eof = true;
                                    break;
                                }
                            }
                        } else {
                            break;
                        }
                    }

                    if self.managed[i].relay_eof
                        && self.managed[i].pending_write.is_empty()
                        && sock.may_send()
                    {
                        sock.close();
                        made_progress = true;
                    }
                }

                // 4. Reclaim closed sockets.
                let remove = sock.state() == TcpState::Closed;
                if remove {
                    let removed = self.managed.swap_remove(i);
                    self.active_flows.remove(&removed.flow);
                    self.sockets.remove(removed.handle);
                    made_progress = true;
                } else {
                    i += 1;
                }
            }

            if !made_progress {
                break;
            }
        }

        while let Some(pkt) = self.device.tx_queue.pop_front() {
            tx_out.push(pkt);
        }
    }

    fn poll_delay_ms(&mut self, now_ms: i64) -> Option<u64> {
        self.iface
            .poll_delay(SmolInstant::from_millis(now_ms), &self.sockets)
            .map(|d| d.total_millis())
    }

    fn waker(&self) -> Arc<Notify> {
        Arc::clone(&self.waker)
    }
}
