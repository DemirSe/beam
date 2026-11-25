//! Pluggable Layer 3 -> Layer 4 TCP stack abstraction (`NetStack`) and its
//! async stream bridge (`TunTcpStream`, `TunTcpReader`, `TunTcpWriter`).

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, mpsc};

use crate::stats::DropCounters;

const DEFAULT_MAX_TCP_CONNECTIONS: usize = 256;
const DEFAULT_TCP_BUFFER_BYTES: usize = 4 * 1024 * 1024;
const DEFAULT_HANDSHAKE_TIMEOUT_MS: u64 = 10_000;
const DEFAULT_IDLE_TIMEOUT_MS: u64 = 300_000;
const RELAY_BUF_POOL_MAX: usize = 8;

/// Bounded, passive pool of relay read buffers shared by the TCP relay task and
/// the stack's server-to-client drain path.
///
/// The relay reads into an owned buffer and hands it to the stack; the stack
/// returns it here after copying the bytes into the TCP TX queue. Steady-state
/// downloads therefore stop allocating a fresh buffer per read chunk. The pool
/// holds at most [`RELAY_BUF_POOL_MAX`] buffers and has no background timer.
#[derive(Debug, Default)]
pub struct RelayBufPool {
    free: Mutex<Vec<Vec<u8>>>,
}

impl RelayBufPool {
    /// Creates a shared, empty pool.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn take(&self) -> Option<Vec<u8>> {
        self.free.lock().ok()?.pop()
    }

    /// Returns `buf` to the pool unless the pool is full.
    pub fn put(&self, mut buf: Vec<u8>) {
        let Ok(mut free) = self.free.lock() else {
            return;
        };
        if free.len() >= RELAY_BUF_POOL_MAX {
            return;
        }
        buf.clear();
        free.push(buf);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.free.lock().map(|f| f.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod pool_tests {
    use super::*;

    #[test]
    fn relay_buf_pool_reuses_buffers_and_stays_bounded() {
        let pool = RelayBufPool::new();
        assert_eq!(pool.len(), 0);
        assert!(pool.take().is_none());

        for size in 1..=(RELAY_BUF_POOL_MAX + 4) {
            pool.put(vec![0u8; size]);
        }
        assert_eq!(pool.len(), RELAY_BUF_POOL_MAX, "pool must stay bounded");

        let buf = pool.take().expect("pooled buffer");
        assert!(buf.is_empty(), "returned buffers are cleared");
        assert!(buf.capacity() > 0);
        assert_eq!(pool.len(), RELAY_BUF_POOL_MAX - 1);
    }
}

/// Tuning parameters for a [`NetStack`] implementation.
#[derive(Clone, Copy, Debug)]
pub struct TcpStackConfig {
    /// Interface MTU in bytes (typically 1500).
    pub mtu: usize,
    /// Maximum concurrent TCP sockets tracked by the stack.
    pub max_connections: usize,
    /// Per-socket TCP receive/send buffer ceiling in bytes.
    pub socket_buffer_bytes: usize,
    /// Timeout in milliseconds for completing the initial TCP 3-way handshake.
    pub handshake_timeout_ms: u64,
    /// Idle timeout in milliseconds before established/close-wait sockets are reclaimed.
    pub idle_timeout_ms: u64,
}

impl Default for TcpStackConfig {
    fn default() -> Self {
        Self {
            mtu: 1500,
            max_connections: DEFAULT_MAX_TCP_CONNECTIONS,
            socket_buffer_bytes: DEFAULT_TCP_BUFFER_BYTES,
            handshake_timeout_ms: DEFAULT_HANDSHAKE_TIMEOUT_MS,
            idle_timeout_ms: DEFAULT_IDLE_TIMEOUT_MS,
        }
    }
}

/// Per-flow dirty notification callback used by [`NetStack`] implementations
/// to avoid O(N) scans across idle connections on wakeup.
pub(crate) trait FlowWaker: Send + Sync {
    fn wake(&self);
}

#[inline]
fn wake_stack(waker: &Arc<Notify>, flow_waker: Option<&Arc<dyn FlowWaker>>) {
    if let Some(fw) = flow_waker {
        fw.wake();
    } else {
        waker.notify_one();
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

    /// Resets all active TCP flows (emitting `TCP RST` packets into `tx_out`
    /// and closing relay channels) on network/gateway transitions so local
    /// applications reconnect immediately instead of hanging on dead sockets.
    fn reset_all(&mut self, _tx_out: &mut Vec<Vec<u8>>) {}

    /// Attaches the engine drop counters so the stack can report silent drops
    /// (for example an overflowing receive queue). Implementations that cannot
    /// drop silently keep the default no-op.
    fn set_drop_counters(&mut self, _drops: Arc<DropCounters>) {}
}

/// Async TCP stream bridged to a [`NetStack`] socket.
pub struct TunTcpStream {
    from_stack: mpsc::Receiver<Vec<u8>>,
    read_buf: Vec<u8>,
    read_offset: usize,
    to_stack: Option<mpsc::Sender<Vec<u8>>>,
    waker: Arc<Notify>,
    flow_waker: Option<Arc<dyn FlowWaker>>,
    in_flight_relay: Option<Arc<AtomicUsize>>,
    aborted: Option<Arc<AtomicBool>>,
    pool: Arc<RelayBufPool>,
}

/// Owned read half of a [`TunTcpStream`].
pub struct TunTcpReader {
    from_stack: mpsc::Receiver<Vec<u8>>,
    waker: Arc<Notify>,
    flow_waker: Option<Arc<dyn FlowWaker>>,
    in_flight_relay: Option<Arc<AtomicUsize>>,
}

impl TunTcpReader {
    /// Receives the next chunk from the TUN TCP socket, or `None` on EOF.
    pub async fn recv_chunk(&mut self) -> Option<Vec<u8>> {
        let chunk = self.from_stack.recv().await?;
        if let Some(counter) = self.in_flight_relay.as_ref() {
            counter.fetch_sub(chunk.len(), Ordering::AcqRel);
        }
        wake_stack(&self.waker, self.flow_waker.as_ref());
        Some(chunk)
    }

    /// Non-blocking receive of an already-queued chunk from the TUN TCP socket.
    pub fn try_recv_chunk(&mut self) -> Option<Vec<u8>> {
        let chunk = self.from_stack.try_recv().ok()?;
        if let Some(counter) = self.in_flight_relay.as_ref() {
            counter.fetch_sub(chunk.len(), Ordering::AcqRel);
        }
        wake_stack(&self.waker, self.flow_waker.as_ref());
        Some(chunk)
    }

    /// Returns `true` if another chunk is already buffered in the channel.
    pub fn has_queued(&self) -> bool {
        !self.from_stack.is_empty()
    }
}

/// Releases the in-flight accounting of chunks that were queued for a relay but
/// will never be read, so dropping a relay cannot leave the advertised TCP
/// receive window shrunken for the rest of the flow.
///
/// Both call sites are terminal drops of the reader half. After `close()` and
/// draining, the counter is swapped to zero: even a Tokio `Permit` reserved
/// before `close()` cannot leave permanently charged bytes.
fn release_queued_in_flight(
    from_stack: &mut mpsc::Receiver<Vec<u8>>,
    in_flight_relay: Option<&Arc<AtomicUsize>>,
) -> bool {
    let Some(counter) = in_flight_relay else {
        return false;
    };
    // Close before draining so a concurrent send cannot succeed after the drain
    // and leave bytes charged for a chunk that nobody will ever read.
    from_stack.close();
    while from_stack.try_recv().is_ok() {}
    let freed = counter.swap(0, Ordering::AcqRel);
    freed > 0
}

impl Drop for TunTcpReader {
    fn drop(&mut self) {
        if release_queued_in_flight(&mut self.from_stack, self.in_flight_relay.as_ref()) {
            wake_stack(&self.waker, self.flow_waker.as_ref());
        }
    }
}

/// Owned write half of a [`TunTcpStream`] with spin-free async backpressure.
pub struct TunTcpWriter {
    to_stack: Option<mpsc::Sender<Vec<u8>>>,
    waker: Arc<Notify>,
    flow_waker: Option<Arc<dyn FlowWaker>>,
    aborted: Option<Arc<AtomicBool>>,
    pool: Arc<RelayBufPool>,
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
        wake_stack(&self.waker, self.flow_waker.as_ref());
        Ok(())
    }

    /// Sends `data` using a recycled relay buffer when one is available, so a
    /// download does not allocate a fresh chunk per read (falls back to a plain
    /// copy when the pool is empty).
    pub async fn send_chunk_pooled(&mut self, data: &[u8]) -> io::Result<()> {
        let mut buf = match self.pool.take() {
            Some(buf) if buf.capacity() >= data.len() => buf,
            Some(undersized) => {
                // Keep the small buffer for a later read instead of dropping it.
                self.pool.put(undersized);
                Vec::with_capacity(data.len())
            }
            None => Vec::with_capacity(data.len()),
        };
        buf.clear();
        buf.extend_from_slice(data);
        self.send_chunk(buf).await
    }

    /// Waits until the TUN TCP socket closes the write channel (e.g. peer RST
    /// or `NetStack::reset_all`).
    pub async fn closed(&self) {
        if let Some(tx) = self.to_stack.as_ref() {
            tx.closed().await;
        }
    }

    /// Closes the write half (triggers TCP FIN on the TUN socket).
    pub fn shutdown(&mut self) {
        self.to_stack.take();
        wake_stack(&self.waker, self.flow_waker.as_ref());
    }

    /// Aborts the write half, signaling the stack to emit TCP `RST` instead of `FIN`.
    pub fn abort(&mut self) {
        if let Some(flag) = self.aborted.as_ref() {
            flag.store(true, Ordering::Release);
        }
        self.to_stack.take();
        wake_stack(&self.waker, self.flow_waker.as_ref());
    }
}

impl Drop for TunTcpWriter {
    fn drop(&mut self) {
        if self.to_stack.take().is_some() {
            wake_stack(&self.waker, self.flow_waker.as_ref());
        }
    }
}

impl TunTcpStream {
    /// Constructs a [`TunTcpStream`] with optional atomic in-flight byte accounting,
    /// abort flag, and per-flow dirty waker.
    pub(crate) fn new_with_accounting(
        from_stack: mpsc::Receiver<Vec<u8>>,
        to_stack: mpsc::Sender<Vec<u8>>,
        waker: Arc<Notify>,
        flow_waker: Option<Arc<dyn FlowWaker>>,
        in_flight_relay: Option<Arc<AtomicUsize>>,
        aborted: Option<Arc<AtomicBool>>,
        pool: Arc<RelayBufPool>,
    ) -> Self {
        Self {
            from_stack,
            read_buf: Vec::new(),
            read_offset: 0,
            to_stack: Some(to_stack),
            waker,
            flow_waker,
            in_flight_relay,
            aborted,
            pool,
        }
    }

    /// Aborts the stream, signaling the stack to emit TCP `RST` instead of `FIN`.
    pub fn abort(&mut self) {
        if let Some(flag) = self.aborted.as_ref() {
            flag.store(true, Ordering::Release);
        }
        self.to_stack.take();
        wake_stack(&self.waker, self.flow_waker.as_ref());
    }

    /// Splits this stream into spin-free chunked read and write halves.
    pub fn into_split(mut self) -> (TunTcpReader, TunTcpWriter) {
        let (_, dummy_rx) = mpsc::channel(1);
        let from_stack = std::mem::replace(&mut self.from_stack, dummy_rx);
        let to_stack = self.to_stack.take();
        let waker = Arc::clone(&self.waker);
        let flow_waker = self.flow_waker.take();
        let in_flight_relay = self.in_flight_relay.take();
        let aborted = self.aborted.take();
        let pool = Arc::clone(&self.pool);
        (
            TunTcpReader {
                from_stack,
                waker: Arc::clone(&waker),
                flow_waker: flow_waker.clone(),
                in_flight_relay,
            },
            TunTcpWriter {
                to_stack,
                waker,
                flow_waker,
                aborted,
                pool,
            },
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
            wake_stack(&this.waker, this.flow_waker.as_ref());
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
                wake_stack(&this.waker, this.flow_waker.as_ref());
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
                wake_stack(&this.waker, this.flow_waker.as_ref());
                Poll::Ready(Ok(chunk_len))
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TUN TCP socket closed",
            ))),
            Err(mpsc::error::TrySendError::Full(_)) => {
                wake_stack(&this.waker, this.flow_waker.as_ref());
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        wake_stack(&self.waker, self.flow_waker.as_ref());
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.to_stack.take();
        wake_stack(&this.waker, this.flow_waker.as_ref());
        Poll::Ready(Ok(()))
    }
}

impl Drop for TunTcpStream {
    fn drop(&mut self) {
        let mut woken = self.to_stack.take().is_some();
        if release_queued_in_flight(&mut self.from_stack, self.in_flight_relay.as_ref()) {
            woken = true;
        }
        if woken {
            wake_stack(&self.waker, self.flow_waker.as_ref());
        }
    }
}

#[cfg(test)]
mod accounting_tests {
    use super::*;

    #[test]
    fn dropping_the_relay_reader_never_loses_in_flight_bytes() {
        // Terminal drops swap the counter to zero, so even a Tokio `Permit`
        // reserved before `close()` cannot leave permanently charged bytes.
        // The racing thread below charges and releases bytes with a net
        // change of zero, so any lost release leaves a non-zero residue.
        for round in 0..500 {
            let (tx, rx) = mpsc::channel::<Vec<u8>>(8);
            let counter = Arc::new(AtomicUsize::new(0));
            for _ in 0..4 {
                counter.fetch_add(512, Ordering::AcqRel);
                assert!(tx.try_send(vec![0u8; 512]).is_ok(), "round {round}");
            }
            let stream = TunTcpStream::new_with_accounting(
                rx,
                tx.clone(),
                Arc::new(Notify::new()),
                None,
                Some(Arc::clone(&counter)),
                None,
                RelayBufPool::new(),
            );
            let (reader, _writer) = stream.into_split();

            let racer_counter = Arc::clone(&counter);
            let racer = std::thread::spawn(move || {
                for _ in 0..64 {
                    racer_counter.fetch_add(1, Ordering::AcqRel);
                    racer_counter.fetch_sub(1, Ordering::AcqRel);
                    std::thread::yield_now();
                }
            });

            // Wait for any concurrent reader-side activity to finish before
            // the terminal drop (in production only the dropped reader ever
            // subtracts from `in_flight_relay`).
            racer.join().expect("racer thread");
            drop(reader);

            assert_eq!(
                counter.load(Ordering::Acquire),
                0,
                "round {round}: queued bytes must be fully released"
            );
        }
    }

    #[test]
    fn terminal_drop_zeroes_reserved_permit_residue() {
        // Simulates a `try_reserve` permit taken before `close()`: the counter
        // holds charged bytes with no chunk left in the channel. A terminal
        // drop must still swap to zero.
        let (_tx, rx) = mpsc::channel::<Vec<u8>>(8);
        let counter = Arc::new(AtomicUsize::new(0));
        counter.fetch_add(1024, Ordering::AcqRel);
        let stream = TunTcpStream::new_with_accounting(
            rx,
            _tx,
            Arc::new(Notify::new()),
            None,
            Some(Arc::clone(&counter)),
            None,
            RelayBufPool::new(),
        );
        let (reader, _writer) = stream.into_split();
        drop(reader);
        assert_eq!(counter.load(Ordering::Acquire), 0);
    }
}
