//! Record-bounded TLS stream over a `TcpStream`.
//!
//! [`TlsStream`] owns the TLS record boundary so Vision `Direct` can hand the
//! raw socket to the relay without losing bytes that rustls read ahead. It
//! reads exactly one TLS record at a time (five-byte header plus declared body)
//! and never asks the socket for more.

use std::future::poll_fn;
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::fd::{AsRawFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll};

use rustls::{ClientConnection, Connection, ServerConnection};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::tls::TLS_RECORD_HEADER_LEN;

const MAX_TLS_RECORD_BODY: usize = 16_384 + 256;
const MAX_PENDING_CIPHERTEXT: usize = TLS_RECORD_HEADER_LEN + MAX_TLS_RECORD_BODY;
const MAX_PLAINTEXT: usize = 64 * 1024;
const MAX_OUTGOING: usize = 64 * 1024;
const READ_CHUNK: usize = 8192;

/// Errors produced by [`TlsStream`].
#[derive(Debug, thiserror::Error)]
pub enum TlsStreamError {
    /// The underlying socket or a buffer operation failed.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// rustls rejected a record or a handshake message.
    #[error("rustls error: {0}")]
    Rustls(#[from] rustls::Error),

    /// A TLS record header was structurally invalid.
    #[error("invalid TLS record: {reason}")]
    InvalidRecord {
        /// Why the record was rejected.
        reason: &'static str,
    },

    /// A record body exceeded the TLS plaintext limit.
    #[error("TLS record body length {length} exceeds {max}")]
    RecordTooLarge {
        /// Declared body length.
        length: usize,
        /// Maximum accepted body length.
        max: usize,
    },

    /// A bounded buffer could not be allocated.
    #[error("TLS stream buffer allocation failed")]
    Allocation,

    /// Buffered plaintext exceeded its bound.
    #[error("buffered TLS plaintext exceeded its bound")]
    PlaintextOverflow,

    /// rustls accepted zero bytes from a non-empty input slice.
    #[error("rustls made no progress consuming a TLS record")]
    NoProgress,

    /// Raw handoff was requested while a record was partially read.
    #[error("raw handoff was requested with a partial TLS record")]
    PartialRecord,
}

impl From<TlsStreamError> for io::Error {
    fn from(error: TlsStreamError) -> Self {
        match error {
            TlsStreamError::Io(error) => error,
            other => io::Error::new(io::ErrorKind::InvalidData, other),
        }
    }
}

/// Capabilities Vision needs from its inner stream.
pub trait RawTlsHandoff: AsyncRead + AsyncWrite + Unpin {
    /// Stop feeding outer TLS records to rustls and read the raw socket instead.
    fn switch_read_to_raw(&mut self);

    /// Stop encrypting writes and write the raw socket instead.
    fn switch_write_to_raw(&mut self);

    /// Take any already-decrypted plaintext not yet delivered to the caller.
    ///
    /// Implementations must first drain any plaintext still buffered inside
    /// the TLS stack; otherwise a Direct handoff can bypass those bytes.
    fn take_plaintext(&mut self) -> Result<Vec<u8>, TlsStreamError>;
}

/// TLS stream that reads one record at a time from the socket.
pub struct TlsStream {
    socket: TcpStream,
    conn: Connection,
    record: RecordRead,
    pending: Vec<u8>,
    pending_offset: usize,
    plaintext: Vec<u8>,
    plaintext_offset: usize,
    outgoing: Vec<u8>,
    outgoing_offset: usize,
    pending_write: Option<usize>,
    read_raw: bool,
    write_raw: bool,
    /// rustls reported a clean `close_notify`.
    closed: bool,
}

impl TlsStream {
    /// Drives a server handshake, seeding rustls with an already-read
    /// ClientHello record.
    ///
    /// The caller is responsible for bounding this future with a timeout.
    pub async fn accept(
        socket: TcpStream,
        conn: ServerConnection,
        client_hello: Vec<u8>,
    ) -> Result<Self, TlsStreamError> {
        if client_hello.len() > MAX_PENDING_CIPHERTEXT {
            return Err(TlsStreamError::RecordTooLarge {
                length: client_hello.len(),
                max: MAX_PENDING_CIPHERTEXT,
            });
        }
        let mut stream = Self {
            socket,
            conn: Connection::Server(conn),
            record: RecordRead::default(),
            pending: client_hello,
            pending_offset: 0,
            plaintext: Vec::new(),
            plaintext_offset: 0,
            outgoing: Vec::new(),
            outgoing_offset: 0,
            pending_write: None,
            read_raw: false,
            write_raw: false,
            closed: false,
        };
        poll_fn(|cx| stream.poll_handshake(cx)).await?;
        Ok(stream)
    }

    /// Drives a client TLS handshake over `socket`.
    ///
    /// The caller is responsible for bounding this future with a timeout.
    pub async fn connect(
        socket: TcpStream,
        conn: ClientConnection,
    ) -> Result<Self, TlsStreamError> {
        let mut stream = Self {
            socket,
            conn: Connection::Client(conn),
            record: RecordRead::default(),
            pending: Vec::new(),
            pending_offset: 0,
            plaintext: Vec::new(),
            plaintext_offset: 0,
            outgoing: Vec::new(),
            outgoing_offset: 0,
            pending_write: None,
            read_raw: false,
            write_raw: false,
            closed: false,
        };
        poll_fn(|cx| stream.poll_handshake(cx)).await?;
        Ok(stream)
    }

    /// Returns `true` after the read direction switched to raw.
    pub const fn read_is_raw(&self) -> bool {
        self.read_raw
    }

    /// Returns `true` after the write direction switched to raw.
    pub const fn write_is_raw(&self) -> bool {
        self.write_raw
    }

    /// Switches the read path to the raw socket.
    ///
    /// The caller must drain plaintext first. Reading raw with pending
    /// ciphertext or a partial record returns an error.
    pub fn switch_read_to_raw(&mut self) {
        self.read_raw = true;
    }

    /// Switches the write path to the raw socket after queued TLS bytes flush.
    pub fn switch_write_to_raw(&mut self) {
        self.write_raw = true;
    }

    /// Takes buffered decrypted plaintext, preserving order.
    ///
    /// `drain_plaintext` first moves any bytes still held inside rustls into
    /// the local buffer. A Direct handoff must not leave plaintext behind:
    /// after `switch_read_to_raw` the relay reads the socket directly.
    pub fn take_plaintext(&mut self) -> Result<Vec<u8>, TlsStreamError> {
        self.drain_plaintext()?;
        if self.plaintext_offset == 0 {
            return Ok(std::mem::take(&mut self.plaintext));
        }
        self.plaintext.drain(..self.plaintext_offset);
        self.plaintext_offset = 0;
        Ok(std::mem::take(&mut self.plaintext))
    }

    fn poll_handshake(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), TlsStreamError>> {
        loop {
            if self.pending_offset < self.pending.len() {
                let consumed = self
                    .conn
                    .read_tls(&mut &self.pending[self.pending_offset..])?;
                if consumed == 0 {
                    return Poll::Ready(Err(TlsStreamError::NoProgress));
                }
                self.pending_offset += consumed;
                if self.pending_offset == self.pending.len() {
                    self.pending.clear();
                    self.pending_offset = 0;
                }
                self.conn.process_new_packets()?;
                self.drain_plaintext()?;
                if self.pending_offset < self.pending.len() {
                    continue;
                }
            }

            if self.conn.wants_write() {
                match self.poll_drain_outgoing(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            match self.flush_outgoing(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(TlsStreamError::Io(error))),
                Poll::Pending => return Poll::Pending,
            }

            if !self.conn.is_handshaking() {
                return Poll::Ready(Ok(()));
            }

            if self.record.filled() {
                let consumed = self.conn.read_tls(&mut self.record.feed())?;
                if consumed == 0 {
                    return Poll::Ready(Err(TlsStreamError::NoProgress));
                }
                self.record.advance(consumed);
                if self.record.complete() {
                    self.record.reset();
                    self.conn.process_new_packets()?;
                    self.drain_plaintext()?;
                }
                continue;
            }

            match self.record.poll(&mut self.socket, cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(TlsStreamError::Io(error))),
                Poll::Ready(Ok(None)) => {
                    return Poll::Ready(Err(TlsStreamError::Io(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "TLS peer closed during the handshake",
                    ))));
                }
                Poll::Ready(Ok(Some(_))) => {}
            }
        }
    }

    fn poll_read_inner(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), TlsStreamError>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if self.plaintext_offset < self.plaintext.len() {
                let remaining = &self.plaintext[self.plaintext_offset..];
                let count = remaining.len().min(buf.remaining());
                buf.put_slice(&remaining[..count]);
                self.plaintext_offset += count;
                if self.plaintext_offset == self.plaintext.len() {
                    self.plaintext.clear();
                    self.plaintext_offset = 0;
                }
                return Poll::Ready(Ok(()));
            }
            self.plaintext.clear();
            self.plaintext_offset = 0;

            if self.outgoing_offset < self.outgoing.len() || self.conn.wants_write() {
                match self.poll_drain_outgoing(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            // A client close_notify is a clean half-close even when its TCP
            // socket stays open. Once rustls reports it, stop reading the
            // socket so the relay can half-close the destination promptly.
            if self.closed {
                return Poll::Ready(Ok(()));
            }

            if self.read_raw {
                if self.record.is_partial() || self.pending_offset < self.pending.len() {
                    return Poll::Ready(Err(TlsStreamError::PartialRecord));
                }
                return Pin::new(&mut self.socket)
                    .poll_read(cx, buf)
                    .map_err(TlsStreamError::Io);
            }

            while self.pending_offset < self.pending.len() {
                let consumed = self
                    .conn
                    .read_tls(&mut &self.pending[self.pending_offset..])?;
                if consumed == 0 {
                    return Poll::Ready(Err(TlsStreamError::NoProgress));
                }
                self.pending_offset += consumed;
                if self.pending_offset == self.pending.len() {
                    self.pending.clear();
                    self.pending_offset = 0;
                }
                self.conn.process_new_packets()?;
                if self.drain_plaintext_into(buf)? {
                    return Poll::Ready(Ok(()));
                }
                if self.closed {
                    return Poll::Ready(Ok(()));
                }
            }
            if self.record.filled() {
                let consumed = self.conn.read_tls(&mut self.record.feed())?;
                if consumed == 0 {
                    return Poll::Ready(Err(TlsStreamError::NoProgress));
                }
                self.record.advance(consumed);
                if self.record.complete() {
                    self.record.reset();
                    self.conn.process_new_packets()?;
                }
                if self.drain_plaintext_into(buf)? {
                    return Poll::Ready(Ok(()));
                }
                if self.closed {
                    return Poll::Ready(Ok(()));
                }
                continue;
            }
            if self.plaintext_offset < self.plaintext.len() {
                continue;
            }
            // A close_notify may have been processed in the loop above. Do not
            // block on the socket after observing it; the relay must see EOF
            // without waiting for an unrelated wakeup.
            if self.closed {
                return Poll::Ready(Ok(()));
            }
            if self.drain_plaintext_into(buf)? {
                return Poll::Ready(Ok(()));
            }
            if self.closed {
                return Poll::Ready(Ok(()));
            }
            match self.record.poll(&mut self.socket, cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(TlsStreamError::Io(error))),
                Poll::Ready(Ok(None)) => {
                    // Let rustls classify the TCP EOF. A close_notify that
                    // arrived earlier yields a clean EOF; a bare FIN yields
                    // UnexpectedEof instead of being reported as a clean
                    // application close.
                    self.conn.read_tls(&mut &[][..])?;
                    self.conn.process_new_packets()?;
                    if self.drain_plaintext_into(buf)? {
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Ok(Some(_))) => {}
            }
        }
    }

    fn poll_write_inner(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, TlsStreamError>> {
        if let Some(accepted) = self.pending_write {
            return match self.poll_drain_outgoing(cx) {
                Poll::Ready(Ok(())) => {
                    self.pending_write = None;
                    Poll::Ready(Ok(accepted))
                }
                Poll::Ready(Err(error)) => {
                    self.pending_write = None;
                    Poll::Ready(Err(error))
                }
                Poll::Pending => Poll::Pending,
            };
        }

        match self.poll_drain_outgoing(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }

        if self.write_raw {
            return Pin::new(&mut self.socket)
                .poll_write(cx, buf)
                .map_err(TlsStreamError::Io);
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let written = match self.conn.writer().write(buf) {
            Ok(written) => written,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
            Err(error) => return Poll::Ready(Err(TlsStreamError::Io(error))),
        };
        if written == 0 {
            return Poll::Ready(Err(TlsStreamError::NoProgress));
        }

        match self.poll_drain_outgoing(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(written)),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => {
                self.pending_write = Some(written);
                Poll::Pending
            }
        }
    }

    fn poll_flush_inner(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), TlsStreamError>> {
        match self.poll_drain_outgoing(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        Pin::new(&mut self.socket)
            .poll_flush(cx)
            .map_err(TlsStreamError::Io)
    }

    fn poll_shutdown_inner(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), TlsStreamError>> {
        if !self.write_raw {
            self.conn.send_close_notify();
        }
        match self.poll_drain_outgoing(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        self.pending_write = None;
        Pin::new(&mut self.socket)
            .poll_shutdown(cx)
            .map_err(TlsStreamError::Io)
    }

    fn drain_plaintext(&mut self) -> Result<(), TlsStreamError> {
        let mut buffer = [0u8; READ_CHUNK];
        loop {
            match self.conn.reader().read(&mut buffer) {
                Ok(0) => {
                    self.closed = true;
                    return Ok(());
                }
                Ok(count) => {
                    if self.plaintext_offset > 0 {
                        self.plaintext.drain(..self.plaintext_offset);
                        self.plaintext_offset = 0;
                    }
                    if self.plaintext.len().saturating_add(count) > MAX_PLAINTEXT {
                        return Err(TlsStreamError::PlaintextOverflow);
                    }
                    self.plaintext.extend_from_slice(&buffer[..count]);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) => return Err(TlsStreamError::Io(error)),
            }
        }
    }

    /// Reads rustls plaintext directly into the caller's buffer.
    ///
    /// The normal data path used to copy every plaintext byte stack -> Vec ->
    /// caller. This keeps the byte in the caller's `ReadBuf` and lets rustls
    /// retain any excess for the next poll. Returns `true` when at least one
    /// byte was written.
    fn drain_plaintext_into(&mut self, buf: &mut ReadBuf<'_>) -> Result<bool, TlsStreamError> {
        if buf.remaining() == 0 {
            return Ok(false);
        }
        match self.conn.reader().read(buf.initialize_unfilled()) {
            Ok(0) => {
                self.closed = true;
                Ok(false)
            }
            Ok(count) => {
                buf.advance(count);
                Ok(true)
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
            Err(error) => Err(TlsStreamError::Io(error)),
        }
    }

    fn poll_drain_outgoing(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), TlsStreamError>> {
        loop {
            if self.conn.wants_write() {
                self.pump_outgoing()?;
            }
            match self.flush_outgoing(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(TlsStreamError::Io(error))),
                Poll::Pending => return Poll::Pending,
            }
            if !self.conn.wants_write() && self.outgoing.is_empty() {
                return Poll::Ready(Ok(()));
            }
        }
    }

    fn pump_outgoing(&mut self) -> Result<(), TlsStreamError> {
        if self.outgoing_offset > 0 {
            self.outgoing.drain(..self.outgoing_offset);
            self.outgoing_offset = 0;
        }
        while self.conn.wants_write() {
            let room = MAX_OUTGOING.saturating_sub(self.outgoing.len());
            if room == 0 {
                break;
            }
            // rustls appends one whole record per call, which would cross the
            // bound when the socket is blocked. The window accepts at most the
            // remaining room; rustls keeps the unsent tail queued.
            let written = self
                .conn
                .write_tls(&mut OutgoingWindow::new(&mut self.outgoing, room))?;
            if written == 0 {
                return Err(TlsStreamError::NoProgress);
            }
        }
        Ok(())
    }

    fn flush_outgoing(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.outgoing_offset < self.outgoing.len() {
            let remaining = &self.outgoing[self.outgoing_offset..];
            match Pin::new(&mut self.socket).poll_write(cx, remaining) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "TLS socket accepted zero bytes",
                    )));
                }
                Poll::Ready(Ok(count)) => self.outgoing_offset += count,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.outgoing.clear();
        self.outgoing_offset = 0;
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for TlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.as_mut()
            .get_mut()
            .poll_read_inner(cx, buf)
            .map(|result| result.map_err(io::Error::from))
    }
}

impl AsyncWrite for TlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.as_mut()
            .get_mut()
            .poll_write_inner(cx, buf)
            .map(|result| result.map_err(io::Error::from))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.as_mut()
            .get_mut()
            .poll_flush_inner(cx)
            .map(|result| result.map_err(io::Error::from))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.as_mut()
            .get_mut()
            .poll_shutdown_inner(cx)
            .map(|result| result.map_err(io::Error::from))
    }
}

impl RawTlsHandoff for TlsStream {
    fn switch_read_to_raw(&mut self) {
        TlsStream::switch_read_to_raw(self);
    }

    fn switch_write_to_raw(&mut self) {
        TlsStream::switch_write_to_raw(self);
    }

    fn take_plaintext(&mut self) -> Result<Vec<u8>, TlsStreamError> {
        TlsStream::take_plaintext(self)
    }
}

#[cfg(unix)]
impl AsRawFd for TlsStream {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}

/// Bounded write window into the outgoing ciphertext buffer.
///
/// One `write_tls` call emits at most one TLS record. Refusing bytes beyond
/// `room` keeps the queued ciphertext inside its hard bound even when the
/// socket is blocked, without losing the rest of the record.
struct OutgoingWindow<'a> {
    buffer: &'a mut Vec<u8>,
    room: usize,
}

impl<'a> OutgoingWindow<'a> {
    const fn new(buffer: &'a mut Vec<u8>, room: usize) -> Self {
        Self { buffer, room }
    }
}

impl Write for OutgoingWindow<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let take = buf.len().min(self.room);
        self.buffer.extend_from_slice(&buf[..take]);
        self.room -= take;
        Ok(take)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct RecordRead {
    header: [u8; TLS_RECORD_HEADER_LEN],
    header_filled: usize,
    body: Vec<u8>,
    body_len: usize,
    body_filled: usize,
    body_fed: usize,
    ready: bool,
}

impl Default for RecordRead {
    fn default() -> Self {
        Self {
            header: [0; TLS_RECORD_HEADER_LEN],
            header_filled: 0,
            body: vec![0; TLS_RECORD_HEADER_LEN + MAX_TLS_RECORD_BODY],
            body_len: 0,
            body_filled: 0,
            body_fed: 0,
            ready: false,
        }
    }
}

impl RecordRead {
    fn is_partial(&self) -> bool {
        self.header_filled != 0 || self.body_len != 0
    }

    fn filled(&self) -> bool {
        self.ready
    }

    fn complete(&self) -> bool {
        self.ready && self.body_fed == self.body_len
    }

    fn feed(&self) -> &[u8] {
        &self.body[self.body_fed..self.body_len]
    }

    fn advance(&mut self, consumed: usize) {
        self.body_fed += consumed;
    }

    fn reset(&mut self) {
        self.header_filled = 0;
        self.body_len = 0;
        self.body_filled = 0;
        self.body_fed = 0;
        self.ready = false;
    }

    fn poll<R>(&mut self, socket: &mut R, cx: &mut Context<'_>) -> Poll<io::Result<Option<usize>>>
    where
        R: AsyncRead + Unpin,
    {
        loop {
            if self.header_filled < TLS_RECORD_HEADER_LEN {
                let mut buf = ReadBuf::new(&mut self.header[self.header_filled..]);
                match Pin::new(&mut *socket).poll_read(cx, &mut buf) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) => {
                        let filled = buf.filled().len();
                        if filled == 0 {
                            if self.header_filled == 0 {
                                return Poll::Ready(Ok(None));
                            }
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "TLS stream ended inside a record header",
                            )));
                        }
                        self.header_filled += filled;
                        if self.header_filled < TLS_RECORD_HEADER_LEN {
                            continue;
                        }
                    }
                }

                validate_header(&self.header)?;
                let body_len = usize::from(u16::from_be_bytes([self.header[3], self.header[4]]));
                self.body[..TLS_RECORD_HEADER_LEN].copy_from_slice(&self.header);
                self.body_len = TLS_RECORD_HEADER_LEN + body_len;
                self.body_filled = TLS_RECORD_HEADER_LEN;
                self.body_fed = 0;
                self.ready = false;
            }

            if self.body_filled < self.body_len {
                let mut buf = ReadBuf::new(&mut self.body[self.body_filled..self.body_len]);
                match Pin::new(&mut *socket).poll_read(cx, &mut buf) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) => {
                        let filled = buf.filled().len();
                        if filled == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "TLS stream ended inside a record body",
                            )));
                        }
                        self.body_filled += filled;
                        if self.body_filled < self.body_len {
                            continue;
                        }
                    }
                }
            }

            self.header_filled = 0;
            self.body_filled = 0;
            self.body_fed = 0;
            self.ready = true;
            return Poll::Ready(Ok(Some(self.body_len)));
        }
    }
}

fn validate_header(header: &[u8; TLS_RECORD_HEADER_LEN]) -> io::Result<()> {
    if !matches!(header[0], 20..=23) {
        return Err(TlsStreamError::InvalidRecord {
            reason: "unsupported TLS record content type",
        }
        .into());
    }
    if header[1] != 0x03 {
        return Err(TlsStreamError::InvalidRecord {
            reason: "unsupported TLS record version",
        }
        .into());
    }
    let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if length > MAX_TLS_RECORD_BODY {
        return Err(TlsStreamError::RecordTooLarge {
            length,
            max: MAX_TLS_RECORD_BODY,
        }
        .into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
    use tokio::sync::oneshot;
    use tokio::time::timeout;

    use crate::tls::test_support::{test_client_config, test_server_config};

    async fn read_record<R>(
        reader: &mut RecordRead,
        socket: &mut R,
        _recycled: Vec<u8>,
    ) -> io::Result<Option<Vec<u8>>>
    where
        R: AsyncRead + Unpin,
    {
        let length = poll_fn(|cx| reader.poll(socket, cx)).await?;
        Ok(length.map(|length| reader.body[..length].to_vec()))
    }

    fn record(content_type: u8, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(content_type);
        out.extend_from_slice(&[0x03, 0x03]);
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    #[tokio::test]
    async fn record_read_handles_split_records() {
        let (mut peer, mut socket) = duplex(8);
        let bytes = record(0x17, b"split body");
        let expected = bytes.clone();
        let writer = tokio::spawn(async move {
            for chunk in bytes.chunks(3) {
                peer.write_all(chunk).await.expect("write record chunk");
                tokio::task::yield_now().await;
            }
            peer.shutdown().await.expect("shutdown peer");
        });

        let mut reader = RecordRead::default();
        let parsed = read_record(&mut reader, &mut socket, Vec::new())
            .await
            .expect("record read")
            .expect("complete record");
        assert_eq!(parsed, expected);
        writer.await.expect("writer task");
    }

    #[tokio::test]
    async fn record_read_keeps_coalesced_records_and_read_ahead() {
        let (mut peer, mut socket) = duplex(64 * 1024);
        let first = record(0x17, b"first");
        let second = record(0x16, b"2");
        let mut wire = Vec::new();
        wire.extend_from_slice(&first);
        wire.extend_from_slice(&second);
        wire.extend_from_slice(b"raw");
        peer.write_all(&wire).await.expect("write wire bytes");

        let mut reader = RecordRead::default();
        let parsed_first = read_record(&mut reader, &mut socket, Vec::new())
            .await
            .expect("first record read")
            .expect("first record");
        assert_eq!(parsed_first, first);
        let parsed_second = read_record(&mut reader, &mut socket, parsed_first)
            .await
            .expect("second record read")
            .expect("second record");
        assert_eq!(parsed_second, second);

        let mut raw = [0u8; 3];
        socket.read_exact(&mut raw).await.expect("raw bytes");
        assert_eq!(&raw, b"raw");
    }

    #[tokio::test]
    async fn record_read_rejects_oversized_body() {
        let (mut peer, mut socket) = duplex(64);
        let mut header = vec![0x17, 0x03, 0x03];
        header.extend_from_slice(&((MAX_TLS_RECORD_BODY + 1) as u16).to_be_bytes());
        peer.write_all(&header).await.expect("write header");

        let mut reader = RecordRead::default();
        let error = read_record(&mut reader, &mut socket, Vec::new())
            .await
            .expect_err("oversized record must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn raw_handoff_preserves_ordered_prefixes() {
        let (mut client, server) = loopback_pair().await;
        let mut stream = test_stream(server);
        stream.plaintext = b"plain".to_vec();
        assert_eq!(stream.take_plaintext().expect("drain plaintext"), b"plain");
        stream.switch_read_to_raw();
        stream.switch_write_to_raw();
        stream.write_all(b"ok").await.expect("raw write");
        let mut received = [0u8; 2];
        client.read_exact(&mut received).await.expect("raw read");
        assert_eq!(&received, b"ok");
    }

    #[tokio::test]
    async fn raw_read_rejects_unfed_outer_ciphertext() {
        let (_client, server) = loopback_pair().await;
        let mut stream = test_stream(server);
        stream.pending = b"outer-ciphertext".to_vec();
        stream.switch_read_to_raw();
        let error = stream
            .read(&mut [0u8; 1])
            .await
            .expect_err("pending TLS record must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    async fn loopback_pair() -> (TcpStream, TcpStream) {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        let client = TcpStream::connect(address).await.expect("client");
        let (server, _) = listener.accept().await.expect("accept");
        (client, server)
    }

    fn test_stream(socket: TcpStream) -> TlsStream {
        let conn = ServerConnection::new(test_server_config()).expect("server connection");
        TlsStream {
            socket,
            conn: Connection::Server(conn),
            record: RecordRead::default(),
            pending: Vec::new(),
            pending_offset: 0,
            plaintext: Vec::new(),
            plaintext_offset: 0,
            outgoing: Vec::new(),
            outgoing_offset: 0,
            pending_write: None,
            read_raw: false,
            write_raw: false,
            closed: false,
        }
    }

    #[tokio::test]
    async fn handshake_and_bidirectional_data() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        let server_config = test_server_config();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            let conn = ServerConnection::new(server_config).expect("server connection");
            let mut tls = TlsStream::accept(socket, conn, Vec::new())
                .await
                .expect("server handshake");
            let mut request = [0u8; 4];
            tls.read_exact(&mut request).await.expect("read request");
            assert_eq!(&request, b"ping");
            tls.write_all(b"pong").await.expect("write response");
            tls.flush().await.expect("flush response");
            tls.shutdown().await.expect("server shutdown");
        });

        let socket = TcpStream::connect(address).await.expect("client connect");
        let connector = tokio_rustls::TlsConnector::from(test_client_config());
        let name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");
        let mut client = connector
            .connect(name, socket)
            .await
            .expect("client handshake");
        client.write_all(b"ping").await.expect("write request");
        let mut response = [0u8; 4];
        client
            .read_exact(&mut response)
            .await
            .expect("read response");
        assert_eq!(&response, b"pong");
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn outgoing_queue_stays_within_cap_under_backpressure() {
        // The client finishes the handshake and then stops reading, so the
        // server socket fills while rustls still holds plaintext. The queued
        // ciphertext must stay inside MAX_OUTGOING and lose no bytes.
        const PAYLOAD_LEN: usize = 8 * 1024 * 1024;
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        let server_config = test_server_config();
        let (blocked_tx, blocked_rx) = oneshot::channel();

        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            let conn = ServerConnection::new(server_config).expect("server connection");
            let mut tls = TlsStream::accept(socket, conn, Vec::new())
                .await
                .expect("server handshake");
            let mut payload = vec![0u8; PAYLOAD_LEN];
            for (index, byte) in payload.iter_mut().enumerate() {
                *byte = (index % 251) as u8;
            }

            let mut offset = 0usize;
            let mut blocked_tx = Some(blocked_tx);
            let mut peak = 0usize;
            while offset < payload.len() {
                let polled = {
                    let mut cx = Context::from_waker(std::task::Waker::noop());
                    Pin::new(&mut tls).poll_write(&mut cx, &payload[offset..])
                };
                match polled {
                    Poll::Ready(Ok(0)) => panic!("server accepted zero plaintext bytes"),
                    Poll::Ready(Ok(count)) => offset += count,
                    Poll::Ready(Err(error)) => panic!("server write failed: {error}"),
                    Poll::Pending => {
                        let queued = tls.outgoing.len();
                        assert!(
                            queued <= MAX_OUTGOING,
                            "queued {queued} ciphertext bytes exceed the cap"
                        );
                        assert!(queued > 0, "blocked write queued no ciphertext");
                        peak = peak.max(queued);
                        if let Some(tx) = blocked_tx.take() {
                            // The first blocked write fills the window exactly.
                            assert_eq!(queued, MAX_OUTGOING, "cap was not reached");
                            tx.send(queued).expect("signal blocked write");
                        }
                        tokio::task::yield_now().await;
                    }
                }
            }
            tls.flush().await.expect("flush payload");
            tls.shutdown().await.expect("server shutdown");
            peak
        });

        let socket = TcpStream::connect(address).await.expect("client connect");
        let connector = tokio_rustls::TlsConnector::from(test_client_config());
        let name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");
        let mut client = connector
            .connect(name, socket)
            .await
            .expect("client handshake");

        let queued = timeout(Duration::from_secs(10), blocked_rx)
            .await
            .expect("server never reached backpressure")
            .expect("blocked notification");
        assert_eq!(queued, MAX_OUTGOING);

        let mut received = 0usize;
        let mut buffer = [0u8; 8192];
        loop {
            let count = timeout(Duration::from_secs(20), client.read(&mut buffer))
                .await
                .expect("client read timed out")
                .expect("client read");
            if count == 0 {
                break;
            }
            for byte in &buffer[..count] {
                assert_eq!(*byte, (received % 251) as u8, "byte {received} differs");
                received += 1;
            }
        }
        assert_eq!(received, PAYLOAD_LEN, "payload was truncated or extended");

        let peak = timeout(Duration::from_secs(20), server)
            .await
            .expect("server timed out")
            .expect("server task");
        assert_eq!(peak, MAX_OUTGOING);
    }

    #[tokio::test]
    async fn raw_handoff_keeps_plaintext_still_buffered_in_rustls() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        let server_config = test_server_config();
        let payload: Vec<u8> = (0..12_000).map(|value| (value % 251) as u8).collect();
        let expected_tail = payload[4096..].to_vec();
        let (tail_tx, tail_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            let conn = ServerConnection::new(server_config).expect("server connection");
            let mut tls = TlsStream::accept(socket, conn, Vec::new())
                .await
                .expect("server handshake");
            let mut first = vec![0u8; 4096];
            tls.read_exact(&mut first).await.expect("read prefix");
            tls.switch_read_to_raw();
            let tail = tls.take_plaintext().expect("drain buffered plaintext");
            tail_tx.send(tail).expect("send tail");
        });

        let socket = TcpStream::connect(address).await.expect("client connect");
        let connector = tokio_rustls::TlsConnector::from(test_client_config());
        let name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");
        let mut client = connector
            .connect(name, socket)
            .await
            .expect("client handshake");
        client.write_all(&payload).await.expect("write payload");
        client.flush().await.expect("flush payload");
        let tail = timeout(Duration::from_secs(2), tail_rx)
            .await
            .expect("plaintext tail timed out")
            .expect("tail task");
        assert_eq!(tail, expected_tail);
        drop(client);
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn vision_direct_handoff_preserves_rustls_plaintext_and_raw_bytes() {
        use crate::vision::{Command, VisionStream, encode_block};
        use rand::SeedableRng;
        use rand::rngs::SmallRng;

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        let server_config = test_server_config();
        let user_id = [0x42u8; 16];
        // The Direct block and the passthrough bytes share one outer TLS
        // record. A small caller buffer forces the Direct content through
        // read_out, leaving part of the record inside rustls at the handoff.
        let content = vec![0x5a_u8; 4096];
        let passthrough = vec![0x33u8; 8000];
        let raw_tail = b"raw";
        let mut wire = Vec::new();
        encode_block(&mut wire, Some(user_id), Command::Direct, &content, 0)
            .expect("encode Direct block");
        wire.extend_from_slice(&passthrough);

        let mut expected = content.clone();
        expected.extend_from_slice(&passthrough);
        expected.extend_from_slice(raw_tail);

        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            let conn = ServerConnection::new(server_config).expect("server connection");
            let tls = TlsStream::accept(socket, conn, Vec::new())
                .await
                .expect("server handshake");
            let mut vision =
                VisionStream::new(tls, user_id, Vec::new(), SmallRng::seed_from_u64(31));
            let handoff = vision.read_handoff_watch();
            let mut output = Vec::new();
            let mut buffer = [0u8; 100];
            loop {
                let count = timeout(Duration::from_secs(2), vision.read(&mut buffer))
                    .await
                    .expect("Vision read timed out")
                    .expect("Vision read");
                if count == 0 {
                    break;
                }
                output.extend_from_slice(&buffer[..count]);
            }
            (output, *handoff.borrow())
        });

        let socket = TcpStream::connect(address).await.expect("client connect");
        let connector = tokio_rustls::TlsConnector::from(test_client_config());
        let name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");
        let mut client = connector
            .connect(name, socket)
            .await
            .expect("client handshake");
        client.write_all(&wire).await.expect("write Vision wire");
        client.flush().await.expect("flush Vision wire");
        let (socket, _) = client.get_mut();
        socket.write_all(raw_tail).await.expect("write raw tail");
        socket.shutdown().await.expect("shutdown raw tail");

        let (output, handed_off) = timeout(Duration::from_secs(2), server)
            .await
            .expect("server timed out")
            .expect("server task");
        assert!(handed_off, "read handoff was not published");
        assert_eq!(output, expected);
    }

    #[tokio::test]
    async fn vision_first_block_split_across_initial_body_and_tls_plaintext() {
        use crate::vision::{Command, VisionStream, encode_block};
        use rand::SeedableRng;
        use rand::rngs::SmallRng;

        let user_id = [0x42u8; 16];
        let content = b"split-first-block".to_vec();
        let mut wire = Vec::new();
        encode_block(&mut wire, Some(user_id), Command::Continue, &content, 0)
            .expect("encode first block");
        encode_block(&mut wire, None, Command::Continue, b"after-first-block", 0)
            .expect("encode second block");
        let mut expected = content.clone();
        expected.extend_from_slice(b"after-first-block");

        // Split inside the block UUID, inside its length fields, and inside
        // its content: the parser must join `initial_body` and TLS plaintext
        // into one block without reordering or repeating bytes.
        for split in [1usize, 18, 30] {
            assert!(split < wire.len());
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
                .await
                .expect("listener");
            let address = listener.local_addr().expect("address");
            let server_config = test_server_config();
            let initial_body = wire[..split].to_vec();
            let rest = wire[split..].to_vec();
            let expected = expected.clone();

            let server = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.expect("accept");
                let conn = ServerConnection::new(server_config).expect("server connection");
                let tls = TlsStream::accept(socket, conn, Vec::new())
                    .await
                    .expect("server handshake");
                let mut vision =
                    VisionStream::new(tls, user_id, initial_body, SmallRng::seed_from_u64(41));
                let mut output = Vec::new();
                let mut buffer = [0u8; 7];
                loop {
                    let count = timeout(Duration::from_secs(2), vision.read(&mut buffer))
                        .await
                        .expect("Vision read timed out")
                        .expect("Vision read");
                    if count == 0 {
                        break;
                    }
                    output.extend_from_slice(&buffer[..count]);
                }
                assert_eq!(output, expected, "split at {split}");
            });

            let socket = TcpStream::connect(address).await.expect("client connect");
            let connector = tokio_rustls::TlsConnector::from(test_client_config());
            let name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");
            let mut client = connector
                .connect(name, socket)
                .await
                .expect("client handshake");
            client
                .write_all(&rest)
                .await
                .expect("write block remainder");
            client.flush().await.expect("flush block remainder");
            client.shutdown().await.expect("client shutdown");
            timeout(Duration::from_secs(2), server)
                .await
                .expect("server timed out")
                .expect("server task");
        }
    }

    #[tokio::test]
    async fn close_notify_is_clean_eof_without_tcp_fin() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        let server_config = test_server_config();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            let conn = ServerConnection::new(server_config).expect("server connection");
            let mut tls = TlsStream::accept(socket, conn, Vec::new())
                .await
                .expect("server handshake");
            let mut request = [0u8; 4];
            tls.read_exact(&mut request).await.expect("read request");
            assert_eq!(&request, b"ping");
            let mut eof = [0u8; 1];
            let count = timeout(Duration::from_millis(200), tls.read(&mut eof))
                .await
                .expect("close_notify must be delivered as EOF without another socket wakeup")
                .expect("read after close_notify");
            assert_eq!(count, 0);
        });

        let socket = TcpStream::connect(address).await.expect("client connect");
        let connector = tokio_rustls::TlsConnector::from(test_client_config());
        let name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");
        let mut client = connector
            .connect(name, socket)
            .await
            .expect("client handshake");
        client.write_all(b"ping").await.expect("write request");
        {
            let (socket, connection) = client.get_mut();
            connection.send_close_notify();
            let mut wire = Vec::new();
            while connection.wants_write() {
                connection
                    .write_tls(&mut wire)
                    .expect("encode close_notify");
            }
            socket.write_all(&wire).await.expect("write close_notify");
            socket.flush().await.expect("flush close_notify");
        }
        // Keep the client object (and its TCP socket) alive while the server
        // observes the close_notify. Dropping it here would also send FIN.
        timeout(Duration::from_secs(2), server)
            .await
            .expect("server did not observe close_notify")
            .expect("server task");
        drop(client);
    }
}
