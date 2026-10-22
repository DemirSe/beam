//! Stateful XTLS Vision stream adapter.
//!
//! [`VisionStream`] wraps an outer TLS stream and turns the VLESS body into
//! Vision blocks. The first block in each direction carries the raw VLESS user
//! id; later blocks do not. The reader strips padding and stops framing on
//! `End`. On `Direct`, the inner record-bounded TLS stream switches to the raw
//! socket; the caller can continue through this wrapper or call
//! [`VisionStream::into_raw`] once both directions have switched.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use rand::Rng;
use rand::rngs::SmallRng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::watch;

use crate::tls::stream::{RawTls, RawTlsHandoff, TlsStreamError};

use super::frame::{
    Command, MAX_BLOCK_LEN, MAX_CONTENT_LEN, VisionError, encode_block, parse_block,
};
use super::state::{VisionReaderMode, VisionReaderState, VisionStateError, VisionWriterState};

/// Chunk size used when reading framing bytes from the inner stream.
const READ_CHUNK: usize = 4096;

/// Largest TLS record body accepted by the inner stream.
const MAX_INNER_TLS_BODY: usize = 16_384 + 256;

/// Maximum plaintext accepted by one `poll_write` call.
///
/// Larger caller buffers are accepted on later polls. Within one call the
/// plaintext is split into [`MAX_CONTENT_LEN`] blocks. The batch is large
/// enough to contain one complete maximum-size inner TLS record so the Direct
/// trigger sees the same record boundary as the stock writer.
const MAX_WRITE_BATCH: usize = 5 + MAX_INNER_TLS_BODY;

/// Maximum empty Vision blocks processed in one `poll_read` call before
/// yielding to the executor.
const MAX_EMPTY_BLOCKS_PER_POLL: usize = 64;

/// A Vision-framed stream over an outer TLS stream.
///
/// `R` is the padding RNG. It defaults to [`SmallRng`]; callers may inject a
/// deterministic RNG for tests. Padding is not cryptographic authentication,
/// but using an unpredictable RNG matches stock traffic shaping.
pub struct VisionStream<S, R = SmallRng> {
    inner: S,
    user_id: [u8; 16],
    reader: VisionReaderState,
    first_read_block: bool,
    read_buf: Vec<u8>,
    read_out: Vec<u8>,
    read_out_offset: usize,
    direct_plaintext: Vec<u8>,
    direct_plaintext_offset: usize,
    writer: VisionWriterState,
    write_direct: bool,
    pending_direct_switch: bool,
    direct_tx: watch::Sender<bool>,
    rng: R,
    write_queue: Vec<u8>,
    write_queue_offset: usize,
    pending_accept: Option<usize>,
}

impl<S, R> VisionStream<S, R>
where
    S: RawTlsHandoff,
    R: Rng + Unpin,
{
    /// Wraps `inner`, using `initial_body` as the first buffered Vision bytes.
    ///
    /// The VLESS request parser may have consumed part or all of the first
    /// Vision block together with the request header. Those trailing bytes are
    /// passed here; any remaining block bytes are read from `inner`.
    pub fn new(inner: S, user_id: [u8; 16], initial_body: Vec<u8>, rng: R) -> Self {
        let (direct_tx, _) = watch::channel(false);
        Self {
            inner,
            user_id,
            reader: VisionReaderState::new(),
            first_read_block: true,
            read_buf: initial_body,
            read_out: Vec::new(),
            read_out_offset: 0,
            direct_plaintext: Vec::new(),
            direct_plaintext_offset: 0,
            writer: VisionWriterState::new(),
            write_direct: false,
            pending_direct_switch: false,
            direct_tx,
            rng,
            write_queue: Vec::new(),
            write_queue_offset: 0,
            pending_accept: None,
        }
    }

    /// Returns the shared Vision TLS detector's current state.
    pub fn is_tls(&self) -> bool {
        self.writer.is_tls()
    }

    /// Returns the shared Vision TLS detector's current state.
    pub fn is_tls12_or_above(&self) -> bool {
        self.writer.is_tls12_or_above()
    }

    /// Returns whether the writer has stopped padding this direction.
    pub fn padding_enabled(&self) -> bool {
        self.writer.padding_enabled()
    }

    /// Returns `true` after the read direction switched to the raw socket.
    pub fn read_is_raw(&self) -> bool {
        matches!(self.reader.mode(), VisionReaderMode::Direct)
    }

    /// Returns `true` after the write direction switched to the raw socket.
    pub fn write_is_raw(&self) -> bool {
        self.write_direct
    }

    /// Watches whether both directions have switched to Direct.
    ///
    /// The value is `false` until both the read and write sides are raw. It is
    /// latched: once `true`, the stream is ready for [`Self::into_raw`].
    pub fn direct_watch(&self) -> watch::Receiver<bool> {
        self.direct_tx.subscribe()
    }

    fn publish_direct(&self) {
        self.direct_tx
            .send_replace(self.read_is_raw() && self.write_is_raw());
    }

    /// Consumes the stream once both directions have switched to Direct.
    pub fn into_raw(self) -> Result<RawTls, TlsStreamError> {
        if !self.read_is_raw() || !self.write_is_raw() {
            return Err(TlsStreamError::RawNotEnabled);
        }

        let Self {
            inner,
            read_buf,
            read_out,
            read_out_offset,
            direct_plaintext,
            direct_plaintext_offset,
            write_queue,
            write_queue_offset,
            ..
        } = self;

        let mut inbound = Vec::new();
        if read_out_offset < read_out.len() {
            inbound.extend_from_slice(&read_out[read_out_offset..]);
        }
        inbound.extend_from_slice(&read_buf);
        if direct_plaintext_offset < direct_plaintext.len() {
            inbound.extend_from_slice(&direct_plaintext[direct_plaintext_offset..]);
        }

        let mut raw = inner.into_raw()?;
        inbound.extend_from_slice(&raw.inbound);
        raw.inbound = inbound;

        if write_queue_offset < write_queue.len() {
            let mut outbound = Vec::new();
            outbound.extend_from_slice(&write_queue[write_queue_offset..]);
            outbound.extend_from_slice(&raw.outbound);
            raw.outbound = outbound;
        }

        Ok(raw)
    }

    fn poll_flush_queue(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.write_queue_offset < self.write_queue.len() {
            let remaining = &self.write_queue[self.write_queue_offset..];
            match Pin::new(&mut self.inner).poll_write(cx, remaining) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "Vision inner stream accepted zero bytes",
                    )));
                }
                Poll::Ready(Ok(count)) => {
                    self.write_queue_offset += count;
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.write_queue.clear();
        self.write_queue_offset = 0;
        Poll::Ready(Ok(()))
    }

    fn queue_block(
        &mut self,
        plan: &super::state::VisionBlockPlan,
        content: &[u8],
    ) -> io::Result<()> {
        let uuid = plan.uuid.then_some(self.user_id);
        encode_block(
            &mut self.write_queue,
            uuid,
            plan.command,
            content,
            plan.padding_len,
        )
        .map_err(vision_error)
    }

    fn plan_and_queue(
        &mut self,
        accepted: &[u8],
        complete_app_data_records: bool,
    ) -> io::Result<bool> {
        let chunks: Vec<&[u8]> = accepted.chunks(MAX_CONTENT_LEN).collect();
        let plan = self
            .writer
            .plan_write(&chunks, complete_app_data_records, &mut self.rng);

        for (index, block_plan) in plan.blocks.iter().enumerate() {
            let Some(content) = chunks.get(index) else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Vision writer planned more blocks than input chunks",
                ));
            };
            self.queue_block(block_plan, content)?;
        }

        if let Some(raw_from) = plan.raw_from {
            for chunk in chunks.iter().skip(raw_from) {
                self.write_queue.extend_from_slice(chunk);
            }
        }
        Ok(plan.switch_to_direct)
    }

    fn finish_pending_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let Some(accepted) = self.pending_accept else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Vision writer lost its pending write",
            )));
        };

        match self.poll_flush_queue(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => {
                self.pending_accept = None;
                return Poll::Ready(Err(error));
            }
            Poll::Pending => return Poll::Pending,
        }

        if self.pending_direct_switch {
            match Pin::new(&mut self.inner).poll_flush(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => {
                    self.pending_accept = None;
                    return Poll::Ready(Err(error));
                }
                Poll::Pending => return Poll::Pending,
            }
            self.inner.switch_write_to_raw();
            self.write_direct = true;
            self.pending_direct_switch = false;
            self.publish_direct();
            tracing::debug!("Vision writer switched to raw");
        }

        self.pending_accept = None;
        Poll::Ready(Ok(accepted))
    }

    fn finish_direct_switch(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.pending_direct_switch {
            return Poll::Ready(Ok(()));
        }
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                self.inner.switch_write_to_raw();
                self.write_direct = true;
                self.pending_direct_switch = false;
                self.publish_direct();
                tracing::debug!("Vision writer switched to raw");
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S, R> AsyncRead for VisionStream<S, R>
where
    S: RawTlsHandoff,
    R: Rng + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        let mut empty_blocks = 0usize;
        loop {
            if this.read_out_offset < this.read_out.len() {
                let remaining = &this.read_out[this.read_out_offset..];
                let count = remaining.len().min(buf.remaining());
                buf.put_slice(&remaining[..count]);
                this.read_out_offset += count;
                if this.read_out_offset == this.read_out.len() {
                    this.read_out.clear();
                    this.read_out_offset = 0;
                }
                return Poll::Ready(Ok(()));
            }

            if !this.reader.is_framed() {
                if !this.read_buf.is_empty() {
                    let count = this.read_buf.len().min(buf.remaining());
                    buf.put_slice(&this.read_buf[..count]);
                    this.read_buf.drain(..count);
                    return Poll::Ready(Ok(()));
                }
                if this.direct_plaintext_offset < this.direct_plaintext.len() {
                    let remaining = &this.direct_plaintext[this.direct_plaintext_offset..];
                    let count = remaining.len().min(buf.remaining());
                    buf.put_slice(&remaining[..count]);
                    this.direct_plaintext_offset += count;
                    if this.direct_plaintext_offset == this.direct_plaintext.len() {
                        this.direct_plaintext.clear();
                        this.direct_plaintext_offset = 0;
                    }
                    return Poll::Ready(Ok(()));
                }
                return Pin::new(&mut this.inner).poll_read(cx, buf);
            }

            match parse_block(&this.read_buf, this.first_read_block) {
                Ok(Some((block, used))) => {
                    let command = block.command;
                    let uuid = block.uuid;
                    if this.first_read_block && uuid != Some(this.user_id) {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Vision first block does not carry the request UUID",
                        )));
                    }
                    let content = block.content.to_vec();
                    this.read_buf.drain(..used);
                    this.first_read_block = false;

                    if let Err(error) = this.reader.on_command(command) {
                        return Poll::Ready(Err(state_error(error)));
                    }
                    if command == Command::Direct {
                        this.inner.switch_read_to_raw();
                        this.direct_plaintext = this.inner.take_plaintext();
                        this.direct_plaintext_offset = 0;
                        this.publish_direct();
                        tracing::debug!("Vision reader switched to Direct");
                    }
                    if !content.is_empty() {
                        this.writer.inspect(&content);
                        this.read_out = content;
                        this.read_out_offset = 0;
                        continue;
                    }

                    empty_blocks += 1;
                    if empty_blocks >= MAX_EMPTY_BLOCKS_PER_POLL {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Ok(None) => {
                    if this.read_buf.len() >= MAX_BLOCK_LEN {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Vision block exceeds the maximum block size",
                        )));
                    }
                    let room = MAX_BLOCK_LEN - this.read_buf.len();
                    let read_limit = room.min(READ_CHUNK);
                    let mut temporary = [0u8; READ_CHUNK];
                    let mut read_buf = ReadBuf::new(&mut temporary[..read_limit]);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) => {
                            let filled = read_buf.filled();
                            if filled.is_empty() {
                                if this.read_buf.is_empty() {
                                    return Poll::Ready(Ok(()));
                                }
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "Vision stream ended inside a block",
                                )));
                            }
                            this.read_buf.extend_from_slice(filled);
                        }
                    }
                }
                Err(error) => return Poll::Ready(Err(vision_error(error))),
            }
        }
    }
}

impl<S, R> AsyncWrite for VisionStream<S, R>
where
    S: RawTlsHandoff,
    R: Rng + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.as_mut().get_mut();

        if this.pending_accept.is_some() {
            return this.finish_pending_write(cx);
        }

        if !this.write_queue.is_empty() {
            match this.poll_flush_queue(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if !this.writer.padding_enabled() {
            if this.pending_direct_switch {
                match this.finish_direct_switch(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let take = buf.len().min(MAX_WRITE_BATCH);
        let complete = is_complete_app_data_records(&buf[..take]);
        match this.plan_and_queue(&buf[..take], complete) {
            Ok(switch_direct) => {
                if switch_direct {
                    tracing::debug!("Vision writer planned Direct");
                }
                this.pending_direct_switch = switch_direct;
            }
            Err(error) => return Poll::Ready(Err(error)),
        }
        this.pending_accept = Some(take);
        this.finish_pending_write(cx)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        match this.poll_flush_queue(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        match this.finish_direct_switch(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        match this.poll_flush_queue(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        match this.finish_direct_switch(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        this.pending_accept = None;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

fn is_complete_app_data_records(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let mut offset = 0usize;
    while offset < data.len() {
        let Some(remaining) = data.get(offset..) else {
            return false;
        };
        let Some(header) = remaining.get(..5) else {
            return false;
        };
        if header[0] != 0x17 || header[1] != 0x03 || header[2] != 0x03 {
            return false;
        }
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if length > MAX_INNER_TLS_BODY {
            return false;
        }
        let Some(end) = offset.checked_add(5 + length) else {
            return false;
        };
        if end > data.len() {
            return false;
        }
        offset = end;
    }
    true
}

fn vision_error(error: VisionError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

fn state_error(error: VisionStateError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vision::frame::{Block, parse_block};
    use rand::SeedableRng;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
    use tokio::time::{Duration, timeout};

    const USER_ID: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];

    impl RawTlsHandoff for tokio::io::DuplexStream {
        fn switch_read_to_raw(&mut self) {}

        fn switch_write_to_raw(&mut self) {}

        fn take_plaintext(&mut self) -> Vec<u8> {
            Vec::new()
        }

        fn into_raw(self) -> Result<RawTls, TlsStreamError> {
            Err(TlsStreamError::RawNotEnabled)
        }
    }

    fn server_hello() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x42; 32]);
        body.push(32);
        body.extend(std::iter::repeat_n(0x33, 32));
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(0);
        body.extend_from_slice(&[0x00, 0x06]);
        body.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);

        let mut record = Vec::new();
        record.extend_from_slice(&[0x16, 0x03, 0x03]);
        record.extend_from_slice(&((4 + body.len()) as u16).to_be_bytes());
        record.push(0x02);
        record.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        record.extend_from_slice(&body);
        record
    }

    fn app_data_record(payload: &[u8]) -> Vec<u8> {
        let mut record = Vec::new();
        record.extend_from_slice(&[0x17, 0x03, 0x03]);
        record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        record.extend_from_slice(payload);
        record
    }

    fn rng(seed: u64) -> SmallRng {
        SmallRng::seed_from_u64(seed)
    }

    fn block_bytes(
        uuid: Option<[u8; 16]>,
        command: Command,
        content: &[u8],
        padding: u16,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        encode_block(&mut bytes, uuid, command, content, padding).expect("test block");
        bytes
    }

    fn read_raw_blocks(raw: &[u8]) -> Vec<Block<'_>> {
        let mut blocks = Vec::new();
        let mut offset = 0;
        let mut first = true;
        while offset < raw.len() {
            let (block, used) = parse_block(&raw[offset..], first)
                .expect("raw block must parse")
                .expect("raw block must be complete");
            blocks.push(block);
            offset += used;
            first = false;
        }
        blocks
    }

    async fn writer_output(writes: &[&[u8]], seed: u64) -> Vec<u8> {
        let (client, mut peer) = duplex(256 * 1024);
        let mut vision = VisionStream::new(client, USER_ID, Vec::new(), rng(seed));
        for write in writes {
            vision.write_all(write).await.expect("write Vision block");
        }
        vision.shutdown().await.expect("shutdown Vision writer");
        let mut raw = Vec::new();
        peer.read_to_end(&mut raw)
            .await
            .expect("read raw Vision output");
        raw
    }

    #[tokio::test]
    async fn writes_exact_first_uuid_and_padding() {
        let raw = writer_output(&[b"hello"], 1).await;
        let blocks = read_raw_blocks(&raw);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].uuid, Some(USER_ID));
        assert_eq!(blocks[0].command, Command::Continue);
        assert_eq!(blocks[0].content, b"hello");
        assert!(blocks[0].padding_len < 256);
    }

    #[tokio::test]
    async fn long_padding_uses_tls_detection() {
        let hello = [0x16, 0x03, 0x01, 0x00, 0x00, 0x01, 0x01];
        let raw = writer_output(&[&hello], 2).await;
        let blocks = read_raw_blocks(&raw);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].uuid, Some(USER_ID));
        assert_eq!(blocks[0].content, hello);
        assert!(usize::from(blocks[0].padding_len) >= 900 - hello.len());
    }

    #[tokio::test]
    async fn oversize_writes_split_into_blocks_without_repeating_uuid() {
        let input = vec![0x42u8; MAX_CONTENT_LEN + 100];
        let raw = writer_output(&[&input], 3).await;
        let blocks = read_raw_blocks(&raw);

        assert!(blocks.len() > 1);
        assert_eq!(blocks[0].uuid, Some(USER_ID));
        for block in &blocks[1..] {
            assert_eq!(block.uuid, None);
        }
        let content: Vec<u8> = blocks
            .iter()
            .flat_map(|block| block.content.iter().copied())
            .collect();
        assert_eq!(content, input);
    }

    #[tokio::test]
    async fn end_stops_framing_and_later_writes_are_raw() {
        let chunk = [0x5a_u8; 4];
        let mut writes: Vec<&[u8]> = (0..8).map(|_| chunk.as_slice()).collect();
        writes.push(b"raw");
        let raw = writer_output(&writes, 4).await;

        let mut offset = 0;
        let mut first = true;
        let mut commands = Vec::new();
        for _ in 0..8 {
            let (block, used) = parse_block(&raw[offset..], first)
                .expect("block must parse")
                .expect("block must be complete");
            commands.push(block.command);
            offset += used;
            first = false;
        }

        assert_eq!(commands[7], Command::End);
        assert_eq!(&raw[offset..], b"raw");
    }

    #[tokio::test]
    async fn reader_strips_padding_and_passes_end_remainder() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&block_bytes(Some(USER_ID), Command::Continue, b"hello", 5));
        raw.extend_from_slice(&block_bytes(None, Command::Continue, b"world", 3));
        raw.extend_from_slice(&block_bytes(None, Command::End, b"end", 2));
        raw.extend_from_slice(b"raw!");

        let (mut peer, client) = duplex(64 * 1024);
        peer.write_all(&raw).await.expect("write raw Vision stream");
        peer.shutdown().await.expect("shutdown raw writer");

        let mut vision = VisionStream::new(client, USER_ID, Vec::new(), rng(5));
        let mut output = Vec::new();
        vision
            .read_to_end(&mut output)
            .await
            .expect("read Vision stream");

        assert_eq!(output, b"helloworldendraw!");
    }

    #[tokio::test]
    async fn split_reads_across_initial_body_and_inner_stream() {
        let encoded = block_bytes(Some(USER_ID), Command::Continue, b"split", 3);
        let (client, mut peer) = duplex(16);
        let mut vision = VisionStream::new(client, USER_ID, encoded[..10].to_vec(), rng(6));

        let writer = tokio::spawn(async move {
            peer.write_all(&encoded[10..])
                .await
                .expect("write split block");
            peer.shutdown().await.expect("shutdown split writer");
        });

        let mut output = [0u8; 5];
        timeout(Duration::from_secs(1), vision.read_exact(&mut output))
            .await
            .expect("split read timed out")
            .expect("read split block");
        assert_eq!(&output, b"split");
        writer.await.expect("split writer task");
    }

    #[tokio::test]
    async fn reader_handles_empty_padding_only_blocks() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&block_bytes(Some(USER_ID), Command::Continue, b"", 900));
        raw.extend_from_slice(&block_bytes(None, Command::Continue, b"", 12));
        raw.extend_from_slice(&block_bytes(None, Command::Continue, b"data", 0));

        let (mut peer, client) = duplex(64 * 1024);
        peer.write_all(&raw).await.expect("write empty blocks");
        peer.shutdown().await.expect("shutdown raw writer");

        let mut vision = VisionStream::new(client, USER_ID, Vec::new(), rng(9));
        let mut output = Vec::new();
        vision
            .read_to_end(&mut output)
            .await
            .expect("read Vision stream");
        assert_eq!(output, b"data");
    }

    #[tokio::test]
    async fn rejects_wrong_first_uuid() {
        let raw = block_bytes(Some([0xaa; 16]), Command::Continue, b"x", 0);
        let (mut peer, client) = duplex(64 * 1024);
        peer.write_all(&raw).await.expect("write raw block");
        peer.shutdown().await.expect("shutdown raw writer");

        let mut vision = VisionStream::new(client, USER_ID, Vec::new(), rng(7));
        let mut output = Vec::new();
        let error = vision
            .read_to_end(&mut output)
            .await
            .expect_err("wrong UUID must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn direct_mode_switches_to_passthrough() {
        let mut raw = block_bytes(Some(USER_ID), Command::Direct, b"direct", 2);
        let block_len = raw.len();
        raw.extend_from_slice(b"raw");

        let (mut peer, client) = duplex(64 * 1024);
        peer.write_all(&raw).await.expect("write Direct block");
        peer.shutdown().await.expect("shutdown Direct writer");

        let mut vision = VisionStream::new(client, USER_ID, Vec::new(), rng(8));
        let mut output = Vec::new();
        vision
            .read_to_end(&mut output)
            .await
            .expect("read Direct stream");
        assert_eq!(output, b"directraw");
        assert_eq!(raw.len() - block_len, 3);
        assert!(vision.read_is_raw());
        assert!(!vision.write_is_raw());
    }

    #[tokio::test]
    async fn writer_emits_direct_after_server_hello_with_uuid() {
        let (client, mut peer) = duplex(64 * 1024);
        let mut vision = VisionStream::new(client, USER_ID, Vec::new(), rng(10));
        vision.writer.inspect(&server_hello());

        let app = app_data_record(b"payload");
        vision
            .write_all(&app)
            .await
            .expect("write application data");
        vision.write_all(b"raw").await.expect("write raw bytes");
        vision.shutdown().await.expect("shutdown Vision writer");

        let mut raw = Vec::new();
        peer.read_to_end(&mut raw)
            .await
            .expect("read raw Vision output");
        let (block, used) = parse_block(&raw, true)
            .expect("Direct block must parse")
            .expect("Direct block must be complete");
        assert_eq!(block.uuid, Some(USER_ID));
        assert_eq!(block.command, Command::Direct);
        assert_eq!(block.content, app);
        assert_eq!(&raw[used..], b"raw");
        assert!(vision.write_is_raw());
        assert!(!vision.read_is_raw());
    }
}
