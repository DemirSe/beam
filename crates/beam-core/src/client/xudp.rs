//! Client-side XUDP multiplexer over VLESS `Command::Mux`.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::address::NetLocation;
use crate::vless::{Addons, Command};
use crate::xudp::frame::{
    FrameOption, FrameSpec, MAX_PAYLOAD_LEN, SessionStatus, TargetNetwork, encode_frame,
    encode_frame_header, parse_frame,
};

use super::{BeamClientConfig, ClientError, dial_vless};

const DEFAULT_MAX_SESSIONS: usize = 256;
const DEFAULT_OUTBOUND_QUEUE: usize = 256;
const DEFAULT_REPLY_QUEUE: usize = 64;
const READ_BUF_CAPACITY: usize = 16 * 1024;
const MAX_READ_BUF: usize = 64 * 1024;
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// Upper bound for one coalesced `write_all` of already-encoded XUDP frames.
const WRITE_COALESCE_CAP: usize = 64 * 1024;
/// Header room reserved in a queued datagram so [`XudpSession::send_owned`] can
/// prepend the frame header without reallocating or copying the payload twice.
pub const FRAME_HEADER_RESERVE: usize = 32;
const CLOSE_FLUSH_TIMEOUT: Duration = Duration::from_secs(2);

/// Minimum idle timeout applied to the shared XUDP mux reader so short
/// per-session idle timeouts do not thrash the multiplexed stream.
pub const MIN_MUX_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

fn effective_mux_idle_timeout(configured: Duration) -> Duration {
    configured.max(MIN_MUX_IDLE_TIMEOUT)
}

/// Tuning parameters for [`XudpClient`].
#[derive(Clone, Copy, Debug)]
pub struct XudpClientConfig {
    /// Maximum concurrent UDP sessions on this mux stream.
    pub max_sessions: usize,
    /// Bounded queue of encoded outbound XUDP frames.
    pub outbound_queue: usize,
    /// Bounded queue of inbound replies per session.
    pub reply_queue: usize,
}

impl Default for XudpClientConfig {
    fn default() -> Self {
        Self {
            max_sessions: DEFAULT_MAX_SESSIONS,
            outbound_queue: DEFAULT_OUTBOUND_QUEUE,
            reply_queue: DEFAULT_REPLY_QUEUE,
        }
    }
}

/// Errors returned by [`XudpClient`] and [`XudpSession`].
#[derive(Debug, thiserror::Error)]
pub enum XudpClientError {
    /// Dialing the underlying VLESS Mux stream failed.
    #[error("client connect failed: {0}")]
    Connect(#[from] ClientError),

    /// The mux stream has closed.
    #[error("XUDP mux stream is closed")]
    Closed,

    /// Maximum concurrent sessions on this mux reached.
    #[error("XUDP client session limit reached")]
    SessionLimit,

    /// Payload is empty or exceeds [`MAX_PAYLOAD_LEN`].
    #[error("XUDP payload length {length} is invalid (must be 1..={max})")]
    InvalidPayloadLength {
        /// Provided payload length.
        length: usize,
        /// Maximum supported payload length.
        max: usize,
    },

    /// Frame encoding failed.
    #[error("XUDP frame error: {0}")]
    Frame(#[from] crate::xudp::XudpError),
}

/// A datagram received from an [`XudpSession`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XudpReply {
    /// Source address reported by the server (may differ from destination on full-cone).
    pub source: Option<NetLocation>,
    /// Datagram payload bytes.
    pub payload: Vec<u8>,
}

struct SessionTable {
    next_id: u16,
    sessions: HashMap<u16, mpsc::Sender<XudpReply>>,
    max_sessions: usize,
    closed: bool,
}

impl SessionTable {
    fn new(max_sessions: usize) -> Self {
        Self {
            next_id: 1,
            sessions: HashMap::new(),
            max_sessions: max_sessions.max(1),
            closed: false,
        }
    }

    fn allocate(&mut self, tx: mpsc::Sender<XudpReply>) -> Result<u16, XudpClientError> {
        if self.closed {
            return Err(XudpClientError::Closed);
        }
        if self.sessions.len() >= self.max_sessions {
            return Err(XudpClientError::SessionLimit);
        }
        for _ in 0..u16::MAX {
            let id = self.next_id;
            self.next_id = self.next_id.wrapping_add(1);
            if self.next_id == 0 {
                self.next_id = 1;
            }
            if id != 0 && !self.sessions.contains_key(&id) {
                self.sessions.insert(id, tx);
                return Ok(id);
            }
        }
        Err(XudpClientError::SessionLimit)
    }

    fn remove(&mut self, id: u16) {
        self.sessions.remove(&id);
    }

    fn close_all(&mut self) {
        self.closed = true;
        self.sessions.clear();
    }
}

/// Drains encoded XUDP frames from `outbound_rx` and writes them as few
/// `write_all` calls as possible.
///
/// Exposed because the mux writer task, the coalescing tests, and the
/// `xudp_writer` benchmark all drive this exact loop.
///
/// The first frame after a wakeup is written together with every frame that is
/// already queued, up to [`WRITE_COALESCE_CAP`]. Frames are never split or
/// dropped: a frame that would overflow the batch is carried to the next
/// iteration and written on its own, and a frame larger than the cap is written
/// in one call by itself. `flush` runs only when nothing else is queued, which
/// keeps interactive latency at zero while removing one syscall per queued
/// frame during bursts.
pub async fn run_writer<W: AsyncWriteExt + Unpin>(
    write_half: &mut W,
    outbound_rx: &mut mpsc::Receiver<Vec<u8>>,
    writer_closed_rx: &mut watch::Receiver<bool>,
) {
    let mut batch: Vec<u8> = Vec::with_capacity(WRITE_COALESCE_CAP);
    let mut carry: Option<Vec<u8>> = None;

    loop {
        let first = match carry.take() {
            Some(frame) => frame,
            None => tokio::select! {
                biased;
                _ = writer_closed_rx.changed() => {
                    if *writer_closed_rx.borrow() {
                        break;
                    }
                    continue;
                }
                maybe = outbound_rx.recv() => {
                    let Some(frame) = maybe else {
                        break;
                    };
                    frame
                }
            },
        };

        batch.clear();
        batch.extend_from_slice(&first);
        drop(first);

        let mut disconnected = false;
        while batch.len() < WRITE_COALESCE_CAP {
            match outbound_rx.try_recv() {
                Ok(next) => {
                    if batch.len().saturating_add(next.len()) > WRITE_COALESCE_CAP {
                        carry = Some(next);
                        break;
                    }
                    batch.extend_from_slice(&next);
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    disconnected = true;
                    break;
                }
            }
        }

        if !matches!(
            timeout(WRITE_TIMEOUT, write_half.write_all(&batch)).await,
            Ok(Ok(()))
        ) {
            return;
        }
        // `carry` is a frame already popped from the queue, so the channel may
        // look empty while bytes are still pending.
        if carry.is_none()
            && outbound_rx.is_empty()
            && !matches!(timeout(WRITE_TIMEOUT, write_half.flush()).await, Ok(Ok(())))
        {
            return;
        }
        if disconnected && carry.is_none() {
            return;
        }
    }
}

/// Multiplexed XUDP client running over one VLESS `Command::Mux` stream.
pub struct XudpClient {
    table: Arc<Mutex<SessionTable>>,
    outbound_tx: Option<mpsc::Sender<Vec<u8>>>,
    reply_queue: usize,
    reader_task: JoinHandle<()>,
    writer_task: Option<JoinHandle<()>>,
}

impl XudpClient {
    /// Connects to the `beam` server and starts an XUDP mux stream.
    pub async fn connect(
        config: &BeamClientConfig,
        xudp_config: XudpClientConfig,
    ) -> Result<Self, XudpClientError> {
        let stream = dial_vless(config, Command::Mux, Addons::empty(), None).await?;
        let (mut read_half, mut write_half) = tokio::io::split(stream);

        let table = Arc::new(Mutex::new(SessionTable::new(xudp_config.max_sessions)));
        let (outbound_tx, mut outbound_rx) =
            mpsc::channel::<Vec<u8>>(xudp_config.outbound_queue.max(1));
        let (closed_tx, mut writer_closed_rx) = watch::channel(false);
        let mut reader_closed_rx = closed_tx.subscribe();

        let writer_table = Arc::clone(&table);
        let writer_closed_tx = closed_tx.clone();
        let writer_task = tokio::spawn(async move {
            run_writer(&mut write_half, &mut outbound_rx, &mut writer_closed_rx).await;
            let _ = timeout(Duration::from_secs(1), write_half.shutdown()).await;
            let _ = writer_closed_tx.send(true);
            if let Ok(mut guard) = writer_table.lock() {
                guard.close_all();
            }
        });

        let reader_table = Arc::clone(&table);
        let idle_timeout = effective_mux_idle_timeout(config.idle_timeout);
        let reader_task = tokio::spawn(async move {
            let mut buf = Vec::with_capacity(READ_BUF_CAPACITY);
            let mut offset = 0usize;
            let mut chunk = vec![0u8; 8192];

            loop {
                let read_res = tokio::select! {
                    biased;
                    _ = reader_closed_rx.changed() => {
                        if *reader_closed_rx.borrow() {
                            break;
                        }
                        continue;
                    }
                    res = timeout(idle_timeout, read_half.read(&mut chunk)) => res,
                };
                match read_res {
                    Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                    Ok(Ok(n)) => {
                        if buf.len().saturating_sub(offset).saturating_add(n) > MAX_READ_BUF {
                            break;
                        }
                        if offset > 0 && buf.len() + n > buf.capacity() {
                            buf.copy_within(offset.., 0);
                            buf.truncate(buf.len() - offset);
                            offset = 0;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                    }
                }

                loop {
                    let slice = &buf[offset..];
                    if slice.is_empty() {
                        break;
                    }
                    match parse_frame(slice) {
                        Ok(Some((frame, consumed))) => {
                            offset += consumed;
                            match frame.status {
                                SessionStatus::Keep => {
                                    if !frame.payload.is_empty() {
                                        let tx = reader_table.lock().ok().and_then(|t| {
                                            t.sessions.get(&frame.session_id).cloned()
                                        });
                                        if let Some(tx) = tx {
                                            let _ = tx.try_send(XudpReply {
                                                source: frame.destination,
                                                payload: frame.payload.to_vec(),
                                            });
                                        }
                                    }
                                }
                                SessionStatus::End => {
                                    if let Ok(mut t) = reader_table.lock() {
                                        t.remove(frame.session_id);
                                    }
                                }
                                SessionStatus::New | SessionStatus::KeepAlive => {}
                            }
                        }
                        Ok(None) => break,
                        Err(_) => {
                            let _ = closed_tx.send(true);
                            if let Ok(mut t) = reader_table.lock() {
                                t.close_all();
                            }
                            return;
                        }
                    }
                }

                if offset == buf.len() {
                    buf.clear();
                    offset = 0;
                }
            }

            let _ = closed_tx.send(true);
            if let Ok(mut t) = reader_table.lock() {
                t.close_all();
            }
        });

        Ok(Self {
            table,
            outbound_tx: Some(outbound_tx),
            reply_queue: xudp_config.reply_queue.max(1),
            reader_task,
            writer_task: Some(writer_task),
        })
    }

    /// Returns `true` if the underlying mux stream is still open.
    pub fn is_open(&self) -> bool {
        self.outbound_tx.as_ref().is_some_and(|tx| !tx.is_closed())
            && self.table.lock().map(|t| !t.closed).unwrap_or(false)
    }

    /// Opens a new UDP session targeting `destination`.
    pub fn open_session(&self, destination: NetLocation) -> Result<XudpSession, XudpClientError> {
        let outbound_tx = self
            .outbound_tx
            .as_ref()
            .ok_or(XudpClientError::Closed)?
            .clone();
        let (reply_tx, reply_rx) = mpsc::channel(self.reply_queue);
        let session_id = {
            let mut guard = self.table.lock().map_err(|_| XudpClientError::Closed)?;
            guard.allocate(reply_tx)?
        };
        Ok(XudpSession {
            session_id,
            default_dest: destination,
            sent_new: false,
            table: Arc::clone(&self.table),
            outbound_tx,
            reply_rx,
        })
    }

    /// Gracefully flushes queued frames and sends TLS `close_notify` before closing.
    pub async fn close(self) {
        self.close_with_timeout(CLOSE_FLUSH_TIMEOUT).await;
    }

    async fn close_with_timeout(mut self, flush_timeout: Duration) {
        self.outbound_tx.take();
        if let Some(writer) = self.writer_task.as_mut() {
            tokio::select! {
                _ = &mut *writer => {
                    self.writer_task = None;
                }
                () = tokio::time::sleep(flush_timeout) => {
                    writer.abort();
                    let _ = writer.await;
                    self.writer_task = None;
                }
            }
        }
        if let Ok(mut t) = self.table.lock() {
            t.close_all();
        }
        self.reader_task.abort();
    }
}

impl Drop for XudpClient {
    fn drop(&mut self) {
        if let Ok(mut t) = self.table.lock() {
            t.close_all();
        }
        self.reader_task.abort();
        if let Some(writer) = self.writer_task.take() {
            writer.abort();
        }
    }
}

/// A single multiplexed UDP session inside an [`XudpClient`].
pub struct XudpSession {
    session_id: u16,
    default_dest: NetLocation,
    sent_new: bool,
    table: Arc<Mutex<SessionTable>>,
    outbound_tx: mpsc::Sender<Vec<u8>>,
    reply_rx: mpsc::Receiver<XudpReply>,
}

impl XudpSession {
    /// Sends a UDP datagram to the session's default destination.
    pub async fn send(&mut self, payload: &[u8]) -> Result<(), XudpClientError> {
        let dest = if self.sent_new {
            None
        } else {
            Some(self.default_dest.clone())
        };
        self.send_inner(dest, payload).await
    }

    /// Sends a UDP datagram to an explicit destination (XUDP per-frame retargeting).
    pub async fn send_to(
        &mut self,
        destination: NetLocation,
        payload: &[u8],
    ) -> Result<(), XudpClientError> {
        self.send_inner(Some(destination), payload).await
    }

    /// Sends an owned payload to an explicit destination, prepending the frame
    /// header in place.
    ///
    /// The caller should reserve [`FRAME_HEADER_RESERVE`] bytes of extra
    /// capacity (see [`Self::alloc_payload`]); then no second allocation is
    /// needed compared with [`Self::send_to`] (one in-buffer move).
    pub async fn send_owned(
        &mut self,
        destination: NetLocation,
        payload: Vec<u8>,
    ) -> Result<(), XudpClientError> {
        if !self.is_live() {
            return Err(XudpClientError::Closed);
        }
        if payload.is_empty() || payload.len() > MAX_PAYLOAD_LEN {
            return Err(XudpClientError::InvalidPayloadLength {
                length: payload.len(),
                max: MAX_PAYLOAD_LEN,
            });
        }
        let status = if self.sent_new {
            SessionStatus::Keep
        } else {
            SessionStatus::New
        };
        let spec = FrameSpec {
            session_id: self.session_id,
            status,
            option: FrameOption::DATA,
            network: Some(TargetNetwork::Udp),
            destination: Some(&destination),
            global_id: None,
            payload: &[],
        };
        let mut header = Vec::with_capacity(FRAME_HEADER_RESERVE);
        encode_frame_header(&mut header, spec, payload.len())?;
        let mut frame = payload;
        let body_len = frame.len();
        frame.reserve(header.len());
        frame.resize(body_len + header.len(), 0);
        frame.copy_within(0..body_len, header.len());
        frame[..header.len()].copy_from_slice(&header);
        self.outbound_tx
            .send(frame)
            .await
            .map_err(|_| XudpClientError::Closed)?;
        self.sent_new = true;
        Ok(())
    }

    /// Allocates a datagram buffer with [`FRAME_HEADER_RESERVE`] bytes of
    /// headroom so [`Self::send_owned`] can prepend the header without growing.
    pub fn alloc_payload(size: usize) -> Vec<u8> {
        Vec::with_capacity(FRAME_HEADER_RESERVE.saturating_add(size))
    }

    /// Returns `true` while this session is still registered on a live mux.
    fn is_live(&self) -> bool {
        self.table
            .lock()
            .map(|t| !t.closed && t.sessions.contains_key(&self.session_id))
            .unwrap_or(false)
    }

    async fn send_inner(
        &mut self,
        destination: Option<NetLocation>,
        payload: &[u8],
    ) -> Result<(), XudpClientError> {
        if !self.is_live() {
            return Err(XudpClientError::Closed);
        }
        if payload.is_empty() || payload.len() > MAX_PAYLOAD_LEN {
            return Err(XudpClientError::InvalidPayloadLength {
                length: payload.len(),
                max: MAX_PAYLOAD_LEN,
            });
        }
        let status = if self.sent_new {
            SessionStatus::Keep
        } else {
            SessionStatus::New
        };
        let network = destination.as_ref().map(|_| TargetNetwork::Udp);
        let spec = FrameSpec {
            session_id: self.session_id,
            status,
            option: FrameOption::DATA,
            network,
            destination: destination.as_ref(),
            global_id: None,
            payload,
        };
        let mut encoded = Vec::with_capacity(64 + payload.len());
        encode_frame(&mut encoded, spec)?;
        self.outbound_tx
            .send(encoded)
            .await
            .map_err(|_| XudpClientError::Closed)?;
        self.sent_new = true;
        Ok(())
    }

    /// Receives the next UDP reply for this session, or `None` if closed.
    pub async fn recv(&mut self) -> Option<XudpReply> {
        self.reply_rx.recv().await
    }

    /// Explicitly closes the session and notifies the server with an `End` frame.
    pub async fn close(mut self) -> io::Result<()> {
        self.send_end_best_effort();
        Ok(())
    }

    fn send_end_best_effort(&mut self) {
        if let Ok(mut guard) = self.table.lock() {
            guard.remove(self.session_id);
        }
        if self.sent_new {
            let spec = FrameSpec {
                session_id: self.session_id,
                status: SessionStatus::End,
                option: FrameOption(0),
                network: None,
                destination: None,
                global_id: None,
                payload: &[],
            };
            let mut encoded = Vec::with_capacity(8);
            if encode_frame(&mut encoded, spec).is_ok() {
                let _ = self.outbound_tx.try_send(encoded);
            }
            self.sent_new = false;
        }
    }
}

impl Drop for XudpSession {
    fn drop(&mut self) {
        self.send_end_best_effort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Poll};

    /// Async writer that records every `poll_write` call and keeps the bytes.
    #[derive(Default)]
    struct CountingSink {
        writes: usize,
        flushes: usize,
        bytes: Vec<u8>,
    }

    impl tokio::io::AsyncWrite for CountingSink {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.writes += 1;
            self.bytes.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.flushes += 1;
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn encode_test_frame(session_id: u16, status: SessionStatus, payload: &[u8]) -> Vec<u8> {
        let dest = NetLocation {
            address: crate::address::Address::Ipv4(std::net::Ipv4Addr::new(9, 9, 9, 9)),
            port: 53,
        };
        let spec = FrameSpec {
            session_id,
            status,
            option: FrameOption::DATA,
            network: (status == SessionStatus::New).then_some(TargetNetwork::Udp),
            destination: (status == SessionStatus::New).then_some(&dest),
            global_id: None,
            payload,
        };
        let mut out = Vec::new();
        encode_frame(&mut out, spec).expect("encode frame");
        out
    }

    fn decode_all_frames(bytes: &[u8]) -> Vec<(u16, Vec<u8>)> {
        let mut frames = Vec::new();
        let mut offset = 0usize;
        while offset < bytes.len() {
            let (frame, consumed) = parse_frame(&bytes[offset..])
                .expect("frame parse")
                .expect("complete frame");
            frames.push((frame.session_id, frame.payload.to_vec()));
            offset += consumed;
        }
        assert_eq!(offset, bytes.len(), "trailing bytes after the last frame");
        frames
    }

    /// Builds a detached session whose frames land in the returned receiver.
    ///
    /// A fresh table gives every session id `1`, so two sessions built this way
    /// encode identical frames for identical calls.
    fn new_test_session() -> (
        XudpSession,
        mpsc::Receiver<Vec<u8>>,
        Arc<Mutex<SessionTable>>,
    ) {
        let table = Arc::new(Mutex::new(SessionTable::new(4)));
        let (reply_tx, reply_rx) = mpsc::channel(4);
        let session_id = table
            .lock()
            .expect("session table")
            .allocate(reply_tx)
            .expect("allocate session");
        let (outbound_tx, outbound_rx) = mpsc::channel(16);
        (
            XudpSession {
                session_id,
                default_dest: test_dest(false),
                sent_new: false,
                table: Arc::clone(&table),
                outbound_tx,
                reply_rx,
            },
            outbound_rx,
            table,
        )
    }

    fn test_dest(ipv6: bool) -> NetLocation {
        let address = if ipv6 {
            crate::address::Address::Ipv6("2001:db8::53".parse().expect("ipv6"))
        } else {
            crate::address::Address::Ipv4(std::net::Ipv4Addr::new(9, 9, 9, 9))
        };
        NetLocation {
            address,
            port: if ipv6 { 5353 } else { 53 },
        }
    }

    /// Encodes the frame both send paths must produce for the same arguments.
    fn expected_data_frame(status: SessionStatus, dest: &NetLocation, payload: &[u8]) -> Vec<u8> {
        let spec = FrameSpec {
            session_id: 1,
            status,
            option: FrameOption::DATA,
            network: Some(TargetNetwork::Udp),
            destination: Some(dest),
            global_id: None,
            payload,
        };
        let mut out = Vec::new();
        encode_frame(&mut out, spec).expect("encode reference frame");
        out
    }

    #[tokio::test]
    async fn send_owned_produces_the_same_frames_as_send_to() {
        // Payload sizes cover the reserved headroom, a typical DNS answer, and the
        // largest accepted datagram.
        let payloads = [
            vec![0x01u8; 1],
            vec![0x02u8; 512],
            vec![0x03u8; MAX_PAYLOAD_LEN],
        ];
        for ipv6 in [false, true] {
            let dest = test_dest(ipv6);
            for payload in &payloads {
                // `New` frame (first send on the session).
                let (mut by_copy, mut copy_rx, _copy_table) = new_test_session();
                by_copy
                    .send_to(dest.clone(), payload)
                    .await
                    .expect("send_to new");
                let copied = copy_rx.try_recv().expect("send_to frame");

                let (mut by_owned, mut owned_rx, _owned_table) = new_test_session();
                by_owned
                    .send_owned(dest.clone(), alloc_owned(payload))
                    .await
                    .expect("send_owned new");
                let owned = owned_rx.try_recv().expect("send_owned frame");

                let expected = expected_data_frame(SessionStatus::New, &dest, payload);
                assert_eq!(copied, expected, "send_to New frame (ipv6={ipv6})");
                assert_eq!(
                    owned,
                    expected,
                    "send_owned must be byte-identical for New frames (ipv6={ipv6}, {}-byte payload, {}-byte header)",
                    payload.len(),
                    expected.len() - payload.len()
                );

                // `Keep` frame (second send on the same session).
                let keep_payload = vec![0x04u8; 64];
                by_copy
                    .send_to(dest.clone(), &keep_payload)
                    .await
                    .expect("send_to keep");
                let copied = copy_rx.try_recv().expect("send_to keep frame");
                by_owned
                    .send_owned(dest.clone(), alloc_owned(&keep_payload))
                    .await
                    .expect("send_owned keep");
                let owned = owned_rx.try_recv().expect("send_owned keep frame");
                let expected = expected_data_frame(SessionStatus::Keep, &dest, &keep_payload);
                assert_eq!(copied, expected, "send_to Keep frame (ipv6={ipv6})");
                assert_eq!(
                    owned, expected,
                    "send_owned must be byte-identical for Keep frames (ipv6={ipv6})"
                );

                // Both frames must decode to the original payloads.
                let decoded = decode_all_frames(&owned);
                assert_eq!(decoded.len(), 1);
                assert_eq!(decoded[0].0, 1);
                assert_eq!(decoded[0].1, keep_payload);
            }
        }
    }

    /// Copies `payload` into a buffer with [`FRAME_HEADER_RESERVE`] headroom, the
    /// way callers of [`XudpSession::send_owned`] are expected to allocate.
    fn alloc_owned(payload: &[u8]) -> Vec<u8> {
        let mut buf = XudpSession::alloc_payload(payload.len());
        buf.extend_from_slice(payload);
        assert!(buf.capacity() >= payload.len() + FRAME_HEADER_RESERVE);
        buf
    }

    #[tokio::test]
    async fn send_owned_rejects_empty_oversize_and_closed_sessions() {
        let (mut session, mut rx, table) = new_test_session();
        let dest = test_dest(false);

        let err = session
            .send_owned(dest.clone(), Vec::new())
            .await
            .expect_err("empty payload");
        assert!(
            matches!(err, XudpClientError::InvalidPayloadLength { length: 0, .. }),
            "unexpected error: {err}"
        );

        let err = session
            .send_owned(dest.clone(), vec![0u8; MAX_PAYLOAD_LEN + 1])
            .await
            .expect_err("oversize payload");
        assert!(
            matches!(
                err,
                XudpClientError::InvalidPayloadLength { length, max }
                    if length == MAX_PAYLOAD_LEN + 1 && max == MAX_PAYLOAD_LEN
            ),
            "unexpected error: {err}"
        );

        assert!(
            rx.try_recv().is_err(),
            "rejected payloads must not be queued"
        );

        // A closed mux table makes the session no longer live.
        table.lock().expect("table").close_all();
        let err = session
            .send_owned(dest, vec![1u8; 8])
            .await
            .expect_err("closed session");
        assert!(
            matches!(err, XudpClientError::Closed),
            "unexpected error: {err}"
        );
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn writer_coalesces_queued_frames_without_splitting_them() {
        let (tx, mut rx) = mpsc::channel(8);
        let (closed_tx, mut closed_rx) = watch::channel(false);

        let payloads: Vec<Vec<u8>> = vec![b"one".to_vec(), b"two-two".to_vec(), vec![0x5a; 300]];
        let mut encoded = Vec::new();
        for (idx, payload) in payloads.iter().enumerate() {
            encoded.push(encode_test_frame(
                idx as u16 + 1,
                SessionStatus::New,
                payload,
            ));
        }
        for frame in &encoded {
            tx.send(frame.clone()).await.expect("queue frame");
        }
        drop(tx);

        let mut sink = CountingSink::default();
        run_writer(&mut sink, &mut rx, &mut closed_rx).await;

        assert_eq!(
            sink.writes, 1,
            "three queued frames must be coalesced into a single write"
        );
        assert_eq!(sink.flushes, 1, "flush only when the queue is empty");
        assert_eq!(
            sink.bytes.len(),
            encoded.iter().map(Vec::len).sum::<usize>()
        );
        let frames = decode_all_frames(&sink.bytes);
        assert_eq!(frames.len(), 3);
        for (idx, (session_id, payload)) in frames.iter().enumerate() {
            assert_eq!(*session_id, idx as u16 + 1);
            assert_eq!(
                payload, &payloads[idx],
                "frame {idx} payload must be intact"
            );
        }
        drop(closed_tx);
    }

    #[tokio::test]
    async fn writer_carries_a_frame_that_would_overflow_the_coalesce_cap() {
        let (tx, mut rx) = mpsc::channel(16);
        let (_closed_tx, mut closed_rx) = watch::channel(false);

        // Nine near-maximum frames exceed the 64 KiB coalesce cap.
        let frames = 9;
        let mut expected_len = 0usize;
        for idx in 0..frames {
            let payload = vec![idx as u8; 8000];
            let frame = encode_test_frame(idx as u16 + 1, SessionStatus::New, &payload);
            expected_len += frame.len();
            tx.send(frame).await.expect("queue frame");
        }
        drop(tx);

        let mut sink = CountingSink::default();
        run_writer(&mut sink, &mut rx, &mut closed_rx).await;

        assert_eq!(sink.bytes.len(), expected_len, "no frame byte may be lost");
        assert!(
            sink.writes >= 2,
            "a batch that would exceed the cap must be split, got {} writes",
            sink.writes
        );
        let decoded = decode_all_frames(&sink.bytes);
        assert_eq!(decoded.len(), frames);
        for (idx, (session_id, payload)) in decoded.iter().enumerate() {
            assert_eq!(*session_id, idx as u16 + 1);
            assert_eq!(payload.len(), 8000);
            assert!(payload.iter().all(|b| *b == idx as u8));
        }
    }

    struct DropFlag(Arc<AtomicBool>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn close_aborts_stalled_writer_on_timeout() {
        let writer_dropped = Arc::new(AtomicBool::new(false));
        let guard = DropFlag(Arc::clone(&writer_dropped));
        let (outbound_tx, _outbound_rx) = mpsc::channel(1);
        let table = Arc::new(Mutex::new(SessionTable::new(1)));

        let writer_task = tokio::spawn(async move {
            let _guard = guard;
            std::future::pending::<()>().await;
        });
        let reader_task = tokio::spawn(std::future::pending::<()>());

        let client = XudpClient {
            table,
            outbound_tx: Some(outbound_tx),
            reply_queue: 1,
            reader_task,
            writer_task: Some(writer_task),
        };

        client.close_with_timeout(Duration::from_millis(20)).await;

        assert!(
            writer_dropped.load(Ordering::SeqCst),
            "stalled writer task must be aborted on close timeout rather than detached"
        );
    }

    #[test]
    fn mux_idle_timeout_enforces_minimum_floor() {
        assert_eq!(
            effective_mux_idle_timeout(Duration::ZERO),
            MIN_MUX_IDLE_TIMEOUT
        );
        assert_eq!(
            effective_mux_idle_timeout(Duration::from_secs(1)),
            MIN_MUX_IDLE_TIMEOUT
        );
        assert_eq!(
            effective_mux_idle_timeout(Duration::from_secs(29)),
            MIN_MUX_IDLE_TIMEOUT
        );
        assert_eq!(
            effective_mux_idle_timeout(MIN_MUX_IDLE_TIMEOUT),
            MIN_MUX_IDLE_TIMEOUT
        );
        assert_eq!(
            effective_mux_idle_timeout(Duration::from_secs(300)),
            Duration::from_secs(300)
        );
    }
}
