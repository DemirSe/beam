//! Client-side XUDP multiplexer over VLESS `Command::Mux`.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::address::NetLocation;
use crate::vless::{Addons, Command};
use crate::xudp::frame::{
    FrameOption, FrameSpec, MAX_PAYLOAD_LEN, SessionStatus, TargetNetwork, encode_frame,
    parse_frame,
};

use super::{BeamClientConfig, ClientError, dial_vless};

const DEFAULT_MAX_SESSIONS: usize = 256;
const DEFAULT_OUTBOUND_QUEUE: usize = 256;
const DEFAULT_REPLY_QUEUE: usize = 64;
const READ_BUF_CAPACITY: usize = 16 * 1024;
const MAX_READ_BUF: usize = 64 * 1024;
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

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

        let writer_table = Arc::clone(&table);
        let writer_task = tokio::spawn(async move {
            while let Some(frame) = outbound_rx.recv().await {
                let res = timeout(WRITE_TIMEOUT, write_half.write_all(&frame)).await;
                match res {
                    Ok(Ok(())) => {}
                    _ => break,
                }
                if outbound_rx.is_empty()
                    && !matches!(timeout(WRITE_TIMEOUT, write_half.flush()).await, Ok(Ok(())))
                {
                    break;
                }
            }
            let _ = timeout(Duration::from_secs(1), write_half.shutdown()).await;
            if let Ok(mut guard) = writer_table.lock() {
                guard.close_all();
            }
        });

        let reader_table = Arc::clone(&table);
        let idle_timeout = config.idle_timeout;
        let reader_task = tokio::spawn(async move {
            let mut buf = Vec::with_capacity(READ_BUF_CAPACITY);
            let mut offset = 0usize;
            let mut chunk = vec![0u8; 8192];

            loop {
                match timeout(idle_timeout, read_half.read(&mut chunk)).await {
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
    pub async fn close(mut self) {
        self.outbound_tx.take();
        if let Some(writer) = self.writer_task.take() {
            let _ = timeout(Duration::from_secs(2), writer).await;
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

    async fn send_inner(
        &mut self,
        destination: Option<NetLocation>,
        payload: &[u8],
    ) -> Result<(), XudpClientError> {
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
