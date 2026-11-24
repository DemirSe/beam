//! Pluggable Layer 3 -> Layer 4 TCP stack abstraction (`NetStack`) and its
//! async stream bridge (`TunTcpStream`, `TunTcpReader`, `TunTcpWriter`).

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, mpsc};

const DEFAULT_MAX_TCP_CONNECTIONS: usize = 256;
const DEFAULT_TCP_BUFFER_BYTES: usize = 4 * 1024 * 1024;

/// Tuning parameters for a [`NetStack`] implementation.
#[derive(Clone, Copy, Debug)]
pub struct TcpStackConfig {
    /// Interface MTU in bytes (typically 1500).
    pub mtu: usize,
    /// Maximum concurrent TCP sockets tracked by the stack.
    pub max_connections: usize,
    /// Per-socket TCP receive/send buffer ceiling in bytes.
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
    pub src: SocketAddr,
    /// Intended remote destination address.
    pub dst: SocketAddr,
    /// Bidirectional async stream bridged to the stack's TCP state machine.
    pub stream: TunTcpStream,
}

/// Pluggable Layer 3 -> Layer 4 TCP stack interface.
pub trait NetStack: Send + 'static {
    /// Feeds one incoming IPv4 or IPv6 TCP packet from the TUN device into the stack.
    fn push_ip_tcp(&mut self, packet: &[u8]);

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
    in_flight_relay: Option<Arc<AtomicUsize>>,
}

/// Owned read half of a [`TunTcpStream`].
pub struct TunTcpReader {
    from_stack: mpsc::Receiver<Vec<u8>>,
    waker: Arc<Notify>,
    in_flight_relay: Option<Arc<AtomicUsize>>,
}

impl TunTcpReader {
    /// Receives the next chunk from the TUN TCP socket, or `None` on EOF.
    pub async fn recv_chunk(&mut self) -> Option<Vec<u8>> {
        let chunk = self.from_stack.recv().await?;
        if let Some(counter) = self.in_flight_relay.as_ref() {
            counter.fetch_sub(chunk.len(), Ordering::AcqRel);
        }
        self.waker.notify_one();
        Some(chunk)
    }

    /// Non-blocking receive of an already-queued chunk from the TUN TCP socket.
    pub fn try_recv_chunk(&mut self) -> Option<Vec<u8>> {
        let chunk = self.from_stack.try_recv().ok()?;
        if let Some(counter) = self.in_flight_relay.as_ref() {
            counter.fetch_sub(chunk.len(), Ordering::AcqRel);
        }
        self.waker.notify_one();
        Some(chunk)
    }

    /// Returns `true` if another chunk is already buffered in the channel.
    pub fn has_queued(&self) -> bool {
        !self.from_stack.is_empty()
    }
}

/// Owned write half of a [`TunTcpStream`] with spin-free async backpressure.
pub struct TunTcpWriter {
    to_stack: Option<mpsc::Sender<Vec<u8>>>,
    waker: Arc<Notify>,
}

impl TunTcpWriter {
    /// Sends a chunk to the TUN TCP socket, awaiting backpressure without spinning.
    pub async fn send_chunk(&mut self, data: Vec<u8>) -> io::Result<()> {
        let Some(tx) = self.to_stack.as_ref() else {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TUN TCP stream already shut down",
            ));
        };
        tx.send(data)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "TUN TCP socket closed"))?;
        self.waker.notify_one();
        Ok(())
    }

    /// Closes the write half (triggers TCP FIN on the TUN socket).
    pub fn shutdown(&mut self) {
        self.to_stack.take();
        self.waker.notify_one();
    }
}

impl Drop for TunTcpWriter {
    fn drop(&mut self) {
        self.to_stack.take();
        self.waker.notify_one();
    }
}

impl TunTcpStream {
    /// Constructs a [`TunTcpStream`] with optional atomic in-flight byte accounting.
    pub(crate) fn new_with_accounting(
        from_stack: mpsc::Receiver<Vec<u8>>,
        to_stack: mpsc::Sender<Vec<u8>>,
        waker: Arc<Notify>,
        in_flight_relay: Option<Arc<AtomicUsize>>,
    ) -> Self {
        Self {
            from_stack,
            read_buf: Vec::new(),
            read_offset: 0,
            to_stack: Some(to_stack),
            waker,
            in_flight_relay,
        }
    }

    /// Splits this stream into spin-free chunked read and write halves.
    pub fn into_split(mut self) -> (TunTcpReader, TunTcpWriter) {
        let (_, dummy_rx) = mpsc::channel(1);
        let from_stack = std::mem::replace(&mut self.from_stack, dummy_rx);
        let to_stack = self.to_stack.take();
        let waker = Arc::clone(&self.waker);
        let in_flight_relay = self.in_flight_relay.take();
        (
            TunTcpReader {
                from_stack,
                waker: Arc::clone(&waker),
                in_flight_relay,
            },
            TunTcpWriter { to_stack, waker },
        )
    }
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
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Ready(Some(chunk)) => {
                if let Some(counter) = this.in_flight_relay.as_ref() {
                    counter.fetch_sub(chunk.len(), Ordering::AcqRel);
                }
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

        let chunk_len = buf.len().min(64 * 1024);
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
