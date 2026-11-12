//! Stateful XTLS Vision stream adapter.
//!
//! [`VisionStream`] wraps an outer TLS stream and turns the VLESS body into
//! Vision blocks. The first block in each direction carries the raw VLESS user
//! id; later blocks do not. The reader strips padding and stops framing on
//! `End`. On `Direct`, the inner record-bounded TLS stream switches to the raw
//! socket; the relay hands off each direction only after its ordered buffers
//! have drained.

use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll};

use rand::Rng;
use rand::rngs::SmallRng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::watch;

use crate::tls::stream::RawTlsHandoff;

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

/// Maximum consecutive empty Vision blocks accepted in one `poll_read` call.
/// Reaching this with no coalesced content is treated as malformed input; a
/// self-wake here would busy-spin an authenticated connection.
const MAX_EMPTY_BLOCKS_PER_POLL: usize = 64;

/// Maximum plaintext coalesced from complete Vision blocks in one poll.
///
/// Returning several blocks together prevents one tiny destination write per
/// six-byte block and keeps a bounded amount of memory per connection.
const MAX_READ_OUT: usize = 64 * 1024;

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
    read_buf_offset: usize,
    read_out: Vec<u8>,
    read_out_offset: usize,
    direct_plaintext: Vec<u8>,
    direct_plaintext_offset: usize,
    writer: VisionWriterState,
    write_direct: bool,
    pending_direct_switch: bool,
    /// The raw switch is active, but the carry must finish before the relay
    /// may start writing the socket from another task.
    direct_publish_pending: bool,
    write_direct_tx: watch::Sender<bool>,
    read_handoff_tx: watch::Sender<bool>,
    rng: R,
    write_queue: Vec<u8>,
    write_queue_offset: usize,
    /// Tail of an inner TLS record that arrived split across two writes.
    write_carry: Vec<u8>,
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
        let (write_direct_tx, _) = watch::channel(false);
        let (read_handoff_tx, _) = watch::channel(false);
        Self {
            inner,
            user_id,
            reader: VisionReaderState::new(),
            first_read_block: true,
            read_buf: initial_body,
            read_buf_offset: 0,
            read_out: Vec::new(),
            read_out_offset: 0,
            direct_plaintext: Vec::new(),
            direct_plaintext_offset: 0,
            writer: VisionWriterState::new(),
            write_direct: false,
            pending_direct_switch: false,
            direct_publish_pending: false,
            write_direct_tx,
            read_handoff_tx,
            rng,
            write_queue: Vec::new(),
            write_queue_offset: 0,
            write_carry: Vec::new(),
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

    /// Watches whether the write direction has switched to the raw socket.
    pub fn write_direct_watch(&self) -> watch::Receiver<bool> {
        self.write_direct_tx.subscribe()
    }

    /// Watches the upload handoff boundary.
    ///
    /// The value becomes `true` only after the read side is Direct and all
    /// already-buffered Vision block bytes, raw block remainder, and decrypted
    /// TLS read-ahead have been drained. At that point the next read goes to
    /// the raw socket, so the client read side can be handed to a one-way
    /// splice without losing ordered plaintext.
    pub fn read_handoff_watch(&self) -> watch::Receiver<bool> {
        self.read_handoff_tx.subscribe()
    }

    fn publish_write_direct(&self) {
        self.write_direct_tx.send_replace(self.write_is_raw());
    }

    /// Publishes the raw-write handoff only after any carried tail is written.
    fn publish_direct_when_drained(&mut self) {
        if self.direct_publish_pending && self.write_carry.is_empty() {
            self.publish_write_direct();
            self.direct_publish_pending = false;
        }
    }

    /// Drops the consumed prefix of the framing buffer.
    ///
    /// Blocks are consumed with a cursor; compacting only when more input is
    /// needed keeps parsing linear instead of shifting the tail for every
    /// tiny block.
    fn compact_read_buf(&mut self) {
        if self.read_buf_offset == 0 {
            return;
        }
        if self.read_buf_offset >= self.read_buf.len() {
            self.read_buf.clear();
            self.read_buf_offset = 0;
            return;
        }
        self.read_buf.copy_within(self.read_buf_offset.., 0);
        let remaining = self.read_buf.len() - self.read_buf_offset;
        self.read_buf.truncate(remaining);
        self.read_buf_offset = 0;
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

    /// Writes the carried raw tail after the inner stream switched to raw.
    ///
    /// The tail belongs to the same inner TLS record as the Direct block but
    /// arrived after the complete-record prefix. It must not be flushed
    /// through outer TLS; it follows the switch on the raw socket.
    fn poll_flush_raw_carry(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.write_carry.is_empty() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.write_carry) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "Vision raw socket accepted zero carried bytes",
                    )));
                }
                Poll::Ready(Ok(count)) => {
                    self.write_carry.drain(..count);
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.publish_direct_when_drained();
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
            self.direct_publish_pending = true;
            tracing::debug!("Vision writer switched to raw");
        }

        if !self.writer.padding_enabled() && !self.write_carry.is_empty() {
            // Direct and End both stop framing. The carried tail now belongs
            // to the outer byte stream: for Direct it is raw socket data, for
            // End it is ordinary outer-TLS plaintext. It must be written
            // before any later poll_write.
            match self.poll_flush_raw_carry(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => {
                    self.pending_accept = None;
                    return Poll::Ready(Err(error));
                }
                Poll::Pending => return Poll::Pending,
            }
        } else {
            self.publish_direct_when_drained();
        }

        self.pending_accept = None;
        Poll::Ready(Ok(accepted))
    }

    fn finish_direct_switch(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.pending_direct_switch {
            if !self.writer.padding_enabled() && !self.write_carry.is_empty() {
                return self.poll_flush_raw_carry(cx);
            }
            self.publish_direct_when_drained();
            return Poll::Ready(Ok(()));
        }
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                self.inner.switch_write_to_raw();
                self.write_direct = true;
                self.pending_direct_switch = false;
                self.direct_publish_pending = true;
                tracing::debug!("Vision writer switched to raw");
                self.poll_flush_raw_carry(cx)
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S, R> VisionStream<S, R>
where
    S: AsRawFd,
{
    /// Returns the underlying socket descriptor.
    ///
    /// Valid only while this stream is alive. Callers duplicate it before the
    /// owner drops; the relay duplicates lazily at a direction's raw handoff.
    pub fn raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
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
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut empty_blocks = 0usize;
        let mut coalescing = false;
        loop {
            if !coalescing && this.read_out_offset < this.read_out.len() {
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
                if this.read_buf_offset < this.read_buf.len() {
                    let remaining = &this.read_buf[this.read_buf_offset..];
                    let count = remaining.len().min(buf.remaining());
                    buf.put_slice(&remaining[..count]);
                    this.read_buf_offset += count;
                    if this.read_buf_offset == this.read_buf.len() {
                        this.read_buf.clear();
                        this.read_buf_offset = 0;
                    }
                    return Poll::Ready(Ok(()));
                }
                this.read_buf.clear();
                this.read_buf_offset = 0;
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
                if this.read_is_raw() {
                    // All ordered plaintext before the raw socket is drained.
                    // Publish before polling the socket so the async relay can
                    // stop without consuming the first raw bytes.
                    this.read_handoff_tx.send_replace(true);
                }
                return Pin::new(&mut this.inner).poll_read(cx, buf);
            }

            match parse_block(
                &this.read_buf[this.read_buf_offset..],
                this.first_read_block,
            ) {
                Ok(Some((block, used))) => {
                    let command = block.command;
                    let uuid = block.uuid;
                    if this.first_read_block && uuid != Some(this.user_id) {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Vision first block does not carry the request UUID",
                        )));
                    }
                    let content = block.content;
                    let content_len = content.len();
                    // Large blocks (typically one inner TLS record) are
                    // copied straight into the caller instead of taking an
                    // extra trip through read_out.
                    let direct_content = content_len >= READ_CHUNK && this.read_out.is_empty();
                    if !content.is_empty() {
                        this.writer.inspect(content);
                        if direct_content {
                            let count = content_len.min(buf.remaining());
                            buf.put_slice(&content[..count]);
                            if count < content_len {
                                this.read_out.extend_from_slice(&content[count..]);
                            }
                        } else {
                            this.read_out.extend_from_slice(content);
                        }
                    }
                    this.read_buf_offset = this.read_buf_offset.saturating_add(used);
                    if this.read_buf_offset >= this.read_buf.len() {
                        this.read_buf.clear();
                        this.read_buf_offset = 0;
                    }
                    this.first_read_block = false;

                    if let Err(error) = this.reader.on_command(command) {
                        return Poll::Ready(Err(state_error(error)));
                    }
                    if command == Command::Direct {
                        this.inner.switch_read_to_raw();
                        this.direct_plaintext = this.inner.take_plaintext()?;
                        this.direct_plaintext_offset = 0;
                        tracing::debug!(content = content_len, "Vision reader switched to Direct");
                    }
                    // End and Direct stop framing. Buffered block content must
                    // be delivered before passthrough bytes and before the raw
                    // read handoff is published, so stop coalescing even when
                    // the closing block itself is empty.
                    if !this.reader.is_framed() {
                        coalescing = false;
                    }
                    if content_len > 0 {
                        if direct_content {
                            return Poll::Ready(Ok(()));
                        }
                        if this.read_out.len() >= MAX_READ_OUT {
                            // Drain the batch through the normal output path;
                            // an empty success would be read as EOF.
                            coalescing = false;
                            continue;
                        }
                        // Keep parsing complete blocks while framing is still
                        // active; if Direct/End switched the mode, return the
                        // accumulated block content before the raw remainder.
                        coalescing = this.reader.is_framed();
                        continue;
                    }

                    empty_blocks += 1;
                    if empty_blocks >= MAX_EMPTY_BLOCKS_PER_POLL {
                        if !this.read_out.is_empty() || !this.reader.is_framed() {
                            // Drain buffered output before yielding; an empty
                            // success would be read as EOF.
                            coalescing = false;
                            continue;
                        }
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "too many consecutive empty Vision blocks",
                        )));
                    }
                }
                Ok(None) => {
                    if !this.read_out.is_empty() {
                        // We have complete content but the next block is
                        // incomplete. Return the batch before waiting for more
                        // input.
                        coalescing = false;
                        continue;
                    }
                    this.compact_read_buf();
                    let available = this.read_buf.len();
                    if available >= MAX_BLOCK_LEN {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Vision block exceeds the maximum block size",
                        )));
                    }
                    let room = MAX_BLOCK_LEN - available;
                    let read_limit = room.min(READ_CHUNK);
                    let mut temporary = [0u8; READ_CHUNK];
                    let mut read_buf = ReadBuf::new(&mut temporary[..read_limit]);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) => {
                            let filled = read_buf.filled();
                            if filled.is_empty() {
                                if available == 0 {
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
            } else if !this.write_carry.is_empty() {
                match this.poll_flush_raw_carry(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
            } else {
                this.publish_direct_when_drained();
            }
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Only a detected TLS stream gets record-alignment buffering. A
        // non-TLS protocol whose data happens to start with 0x16/0x03 must
        // not be held waiting for a record that will never complete.
        let carry_ok = this.writer.is_tls() || this.writer.is_tls12_or_above();
        let accepted;
        let switch_direct = if !this.write_carry.is_empty() {
            let room = MAX_WRITE_BATCH.saturating_sub(this.write_carry.len());
            let take = buf.len().min(room);
            this.write_carry.extend_from_slice(&buf[..take]);
            accepted = take;

            let prefix = complete_tls_records_len(&this.write_carry);
            if prefix == this.write_carry.len() {
                let data = std::mem::take(&mut this.write_carry);
                this.plan_and_queue(&data, true)?
            } else if prefix > 0 {
                let tail = this.write_carry.split_off(prefix);
                let data = std::mem::take(&mut this.write_carry);
                let switch = this.plan_and_queue(&data, true)?;
                let tls_after = this.writer.is_tls() || this.writer.is_tls12_or_above();
                if switch
                    || !this.writer.padding_enabled()
                    || (tls_after && is_partial_tls_record(&tail))
                {
                    this.write_carry = tail;
                    switch
                } else {
                    this.plan_and_queue(&tail, false)?;
                    false
                }
            } else if carry_ok && is_partial_tls_record(&this.write_carry) {
                false
            } else {
                let data = std::mem::take(&mut this.write_carry);
                this.plan_and_queue(&data, false)?
            }
        } else {
            let take = buf.len().min(MAX_WRITE_BATCH);
            accepted = take;
            let prefix = complete_tls_records_len(&buf[..take]);
            if prefix == take {
                this.plan_and_queue(&buf[..take], true)?
            } else if prefix > 0 {
                let tail = buf[prefix..take].to_vec();
                let switch = this.plan_and_queue(&buf[..prefix], true)?;
                let tls_after = this.writer.is_tls() || this.writer.is_tls12_or_above();
                if switch
                    || !this.writer.padding_enabled()
                    || (tls_after && is_partial_tls_record(&tail))
                {
                    this.write_carry = tail;
                    switch
                } else {
                    this.plan_and_queue(&tail, false)?;
                    false
                }
            } else if carry_ok && is_partial_tls_record(&buf[..take]) {
                this.write_carry.extend_from_slice(&buf[..take]);
                false
            } else {
                this.plan_and_queue(&buf[..take], false)?
            }
        };

        if switch_direct {
            tracing::debug!(
                accepted,
                enable_xtls = this.writer.enable_xtls(),
                filter_budget = this.writer.filter_budget(),
                "Vision writer planned Direct"
            );
        }
        this.pending_direct_switch = switch_direct;
        this.pending_accept = Some(accepted);
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
        if !this.write_carry.is_empty() {
            if this.write_direct {
                let data = std::mem::take(&mut this.write_carry);
                this.write_queue.extend_from_slice(&data);
            } else if !this.pending_direct_switch && this.writer.padding_enabled() {
                // Still framing: finish the partial record as a Vision block.
                let data = std::mem::take(&mut this.write_carry);
                if let Err(error) = this.plan_and_queue(&data, false) {
                    return Poll::Ready(Err(error));
                }
            }
            // With framing stopped, End/Direct carry is written after the
            // queued closing block, either through outer TLS or raw.
        }
        match this.poll_flush_queue(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        if !this.writer.padding_enabled()
            && !this.pending_direct_switch
            && !this.write_carry.is_empty()
        {
            match this.poll_flush_raw_carry(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
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

/// Returns the length of complete TLS records at the start of `data`.
///
/// This covers handshake, change-cipher-spec, alert, and application-data
/// records so a ServerHello and the first application record are aligned
/// independently. A partial or non-TLS tail is not included.
fn complete_tls_records_len(data: &[u8]) -> usize {
    let mut offset = 0usize;
    while let Some(remaining) = data.get(offset..) {
        let Some(header) = remaining.get(..5) else {
            break;
        };
        if !matches!(header[0], 0x14..=0x17)
            || header[1] != 0x03
            || !matches!(header[2], 0x01 | 0x03)
        {
            break;
        }
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if length > MAX_INNER_TLS_BODY {
            break;
        }
        let Some(end) = offset.checked_add(5 + length) else {
            break;
        };
        if end > data.len() {
            break;
        }
        offset = end;
    }
    offset
}

/// Returns `true` if `data` is a prefix of one TLS record.
fn is_partial_tls_record(data: &[u8]) -> bool {
    if data.is_empty() || !matches!(data[0], 0x14..=0x17) {
        return false;
    }
    if data.len() >= 2 && data[1] != 0x03 {
        return false;
    }
    if data.len() >= 3 && !matches!(data[2], 0x01 | 0x03) {
        return false;
    }
    if data.len() < 5 {
        return true;
    }
    let length = usize::from(u16::from_be_bytes([data[3], data[4]]));
    length <= MAX_INNER_TLS_BODY && data.len() < 5 + length
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

        fn take_plaintext(&mut self) -> Result<Vec<u8>, crate::tls::stream::TlsStreamError> {
            Ok(Vec::new())
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
        let hello = [0x16, 0x03, 0x01, 0x00, 0x02, 0x01, 0x01];
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
    async fn reader_coalesces_many_tiny_blocks() {
        // 2,000 five-byte framing blocks exercise the cursor path that would
        // previously memmove the reassembly tail for every block.
        let mut raw = Vec::new();
        for index in 0..2_000 {
            let uuid = (index == 0).then_some(USER_ID);
            raw.extend_from_slice(&block_bytes(uuid, Command::Continue, b"x", 0));
        }
        let (mut peer, client) = duplex(256 * 1024);
        peer.write_all(&raw).await.expect("write tiny blocks");
        peer.shutdown().await.expect("shutdown tiny writer");

        let mut vision = VisionStream::new(client, USER_ID, Vec::new(), rng(11));
        let mut output = Vec::new();
        let mut buffer = [0u8; 8192];
        let mut reads = 0usize;
        loop {
            let count = vision.read(&mut buffer).await.expect("read tiny blocks");
            if count == 0 {
                break;
            }
            reads += 1;
            output.extend_from_slice(&buffer[..count]);
        }
        assert_eq!(output.len(), 2_000);
        assert!(output.iter().all(|byte| *byte == b'x'));
        // The 2,000 one-byte blocks must be coalesced into a small number of
        // reads, not returned one block at a time.
        assert!(reads < 10, "tiny blocks were not coalesced: {reads} reads");
    }

    #[tokio::test]
    async fn reader_returns_a_large_block_in_one_read() {
        let payload = vec![0x5a_u8; 8000];
        let raw = block_bytes(Some(USER_ID), Command::Continue, &payload, 0);
        let (mut peer, client) = duplex(64 * 1024);
        peer.write_all(&raw).await.expect("write large block");
        peer.shutdown().await.expect("shutdown large writer");

        let mut vision = VisionStream::new(client, USER_ID, Vec::new(), rng(17));
        let mut buffer = vec![0u8; 16 * 1024];
        let count = vision.read(&mut buffer).await.expect("read large block");
        assert_eq!(count, payload.len());
        assert_eq!(&buffer[..count], &payload[..]);
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
        let handoff = vision.read_handoff_watch();
        let mut output = Vec::new();
        vision
            .read_to_end(&mut output)
            .await
            .expect("read Direct stream");
        assert_eq!(output, b"directraw");
        assert_eq!(raw.len() - block_len, 3);
        assert!(vision.read_is_raw());
        assert!(!vision.write_is_raw());
        assert!(*handoff.borrow());
    }

    #[tokio::test]
    async fn empty_end_flushes_coalesced_content_before_passthrough() {
        // One poll sees Continue("a"), empty End, then passthrough "b".
        // "a" must come out first even though End stops framing.
        let mut raw = Vec::new();
        raw.extend_from_slice(&block_bytes(Some(USER_ID), Command::Continue, b"a", 0));
        raw.extend_from_slice(&block_bytes(None, Command::End, b"", 0));
        raw.extend_from_slice(b"b");

        let (mut peer, client) = duplex(64 * 1024);
        peer.shutdown().await.expect("shutdown End writer");
        let mut vision = VisionStream::new(client, USER_ID, raw, rng(18));
        let mut output = Vec::new();
        vision
            .read_to_end(&mut output)
            .await
            .expect("read End stream");
        assert_eq!(output, b"ab");
    }

    #[tokio::test]
    async fn empty_end_returns_coalesced_content_without_more_input() {
        // End ends framing, but the coalesced batch must not wait for the
        // socket or be mistaken for EOF.
        let mut raw = Vec::new();
        raw.extend_from_slice(&block_bytes(Some(USER_ID), Command::Continue, b"a", 0));
        raw.extend_from_slice(&block_bytes(None, Command::End, b"", 0));

        let (_peer, client) = duplex(64 * 1024);
        let mut vision = VisionStream::new(client, USER_ID, raw, rng(19));
        let mut buffer = [0u8; 8];
        let count = timeout(Duration::from_secs(1), vision.read(&mut buffer))
            .await
            .expect("coalesced content was withheld")
            .expect("read coalesced content");
        assert_eq!(&buffer[..count], b"a");
    }

    #[tokio::test]
    async fn empty_direct_flushes_coalesced_content_before_handoff() {
        // Direct ends framing. The raw handoff must not be published and the
        // socket must not be polled while block content is still buffered.
        let mut raw = Vec::new();
        raw.extend_from_slice(&block_bytes(Some(USER_ID), Command::Continue, b"a", 0));
        raw.extend_from_slice(&block_bytes(None, Command::Direct, b"", 0));

        let (mut peer, client) = duplex(64 * 1024);
        let mut vision = VisionStream::new(client, USER_ID, raw, rng(20));
        let handoff = vision.read_handoff_watch();
        let mut buffer = [0u8; 8];
        let count = timeout(Duration::from_secs(1), vision.read(&mut buffer))
            .await
            .expect("coalesced content was withheld")
            .expect("read coalesced content");
        assert_eq!(&buffer[..count], b"a");
        assert!(
            !*handoff.borrow(),
            "raw handoff published before buffered content was delivered"
        );

        peer.write_all(b"b").await.expect("write raw byte");
        let count = timeout(Duration::from_secs(1), vision.read(&mut buffer))
            .await
            .expect("raw read timed out")
            .expect("read raw byte");
        assert_eq!(&buffer[..count], b"b");
        assert!(*handoff.borrow(), "raw handoff was not published");
    }

    #[tokio::test]
    async fn empty_direct_keeps_order_with_trailing_bytes() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&block_bytes(Some(USER_ID), Command::Continue, b"a", 0));
        raw.extend_from_slice(&block_bytes(None, Command::Direct, b"", 0));
        raw.extend_from_slice(b"b");

        let (mut peer, client) = duplex(64 * 1024);
        peer.shutdown().await.expect("shutdown raw writer");
        let mut vision = VisionStream::new(client, USER_ID, raw, rng(21));
        let mut output = Vec::new();
        vision
            .read_to_end(&mut output)
            .await
            .expect("read Direct stream");
        assert_eq!(output, b"ab");
    }

    #[tokio::test]
    async fn empty_block_limit_returns_coalesced_content() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&block_bytes(Some(USER_ID), Command::Continue, b"a", 0));
        for _ in 0..MAX_EMPTY_BLOCKS_PER_POLL {
            raw.extend_from_slice(&block_bytes(None, Command::Continue, b"", 0));
        }

        let (_peer, client) = duplex(64 * 1024);
        let mut vision = VisionStream::new(client, USER_ID, raw, rng(22));
        let mut buffer = [0u8; 8];
        let count = timeout(Duration::from_secs(1), vision.read(&mut buffer))
            .await
            .expect("empty-block limit withheld buffered content")
            .expect("read buffered content");
        assert_eq!(&buffer[..count], b"a");
    }

    #[tokio::test]
    async fn empty_block_limit_without_content_is_rejected() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&block_bytes(Some(USER_ID), Command::Continue, b"", 0));
        for _ in 1..MAX_EMPTY_BLOCKS_PER_POLL {
            raw.extend_from_slice(&block_bytes(None, Command::Continue, b"", 0));
        }

        let (_peer, client) = duplex(64 * 1024);
        let mut vision = VisionStream::new(client, USER_ID, raw, rng(22));
        let mut buffer = [0u8; 8];
        let error = timeout(Duration::from_secs(1), vision.read(&mut buffer))
            .await
            .expect("empty-block limit busy-spun")
            .expect_err("empty-only stream must be rejected");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn read_out_limit_returns_coalesced_content() {
        let content = vec![0x5a_u8; 4_000];
        let mut raw = Vec::new();
        raw.extend_from_slice(&block_bytes(Some(USER_ID), Command::Continue, &content, 0));
        for _ in 0..(MAX_READ_OUT / content.len()) {
            raw.extend_from_slice(&block_bytes(None, Command::Continue, &content, 0));
        }
        let expected = content.len() * (1 + MAX_READ_OUT / content.len());
        assert!(expected > MAX_READ_OUT);

        let (_peer, client) = duplex(256 * 1024);
        let mut vision = VisionStream::new(client, USER_ID, raw, rng(23));
        let mut buffer = vec![0u8; expected];
        let count = timeout(Duration::from_secs(1), vision.read(&mut buffer))
            .await
            .expect("read_out limit withheld buffered content")
            .expect("read buffered content");
        assert_eq!(count, expected);
        assert!(buffer[..count].iter().all(|byte| *byte == 0x5a));
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

    #[tokio::test]
    async fn handshake_and_partial_app_share_a_write() {
        let (client, mut peer) = duplex(64 * 1024);
        let mut vision = VisionStream::new(client, USER_ID, Vec::new(), rng(15));
        let hello = server_hello();
        let app = app_data_record(b"payload");
        let mut first = hello.clone();
        first.extend_from_slice(&app[..5]);
        vision
            .write_all(&first)
            .await
            .expect("write handshake plus app header");
        vision.write_all(&app[5..]).await.expect("write app body");
        vision.shutdown().await.expect("shutdown Vision writer");

        let mut raw = Vec::new();
        peer.read_to_end(&mut raw)
            .await
            .expect("read raw Vision output");
        let (first_block, first_used) = parse_block(&raw, true)
            .expect("first block must parse")
            .expect("first block must be complete");
        assert_eq!(first_block.command, Command::Continue);
        assert_eq!(first_block.content, hello);
        let (direct, direct_used) = parse_block(&raw[first_used..], false)
            .expect("Direct block must parse")
            .expect("Direct block must be complete");
        assert_eq!(direct.command, Command::Direct);
        assert_eq!(direct.content, app);
        assert_eq!(&raw[first_used + direct_used..], b"");
    }

    #[tokio::test]
    async fn direct_survives_arbitrary_write_boundaries() {
        for chunk in [1usize, 2, 3, 5, 7, 11] {
            let (client, mut peer) = duplex(64 * 1024);
            let mut vision = VisionStream::new(client, USER_ID, Vec::new(), rng(14));
            vision.writer.inspect(&server_hello());

            let app = app_data_record(b"boundary-payload");
            let next = app_data_record(b"next-record");
            let mut wire = app.clone();
            wire.extend_from_slice(&next);
            for piece in wire.chunks(chunk) {
                vision
                    .write_all(piece)
                    .await
                    .expect("write arbitrary boundary");
            }
            vision.shutdown().await.expect("shutdown Vision writer");

            let mut raw = Vec::new();
            peer.read_to_end(&mut raw)
                .await
                .expect("read raw Vision output");
            let (block, used) = parse_block(&raw, true)
                .expect("Direct block must parse")
                .expect("Direct block must be complete");
            assert_eq!(block.command, Command::Direct, "chunk size {chunk}");
            assert_eq!(block.content, app, "chunk size {chunk}");
            assert_eq!(&raw[used..], &next, "chunk size {chunk}");
        }
    }

    #[tokio::test]
    async fn end_carry_is_flushed_before_later_writes() {
        let (client, mut peer) = duplex(64 * 1024);
        let mut vision = VisionStream::new(client, USER_ID, Vec::new(), rng(16));
        // Cipher 0x1305 is recognized as TLS but does not enable XTLS, so the
        // first complete app record plans End rather than Direct.
        let mut hello = server_hello();
        hello[76..78].copy_from_slice(&[0x13, 0x05]);
        vision.writer.inspect(&hello);
        assert!(vision.writer.is_tls());
        assert!(!vision.writer.enable_xtls());

        let app = app_data_record(b"payload");
        let next = app_data_record(b"next");
        let mut first = app.clone();
        first.extend_from_slice(&next[..3]);
        vision
            .write_all(&first)
            .await
            .expect("write End block plus partial raw");
        vision
            .write_all(&next[3..])
            .await
            .expect("write remaining raw");
        vision.shutdown().await.expect("shutdown Vision writer");

        let mut raw = Vec::new();
        peer.read_to_end(&mut raw)
            .await
            .expect("read raw Vision output");
        let (block, used) = parse_block(&raw, true)
            .expect("End block must parse")
            .expect("End block must be complete");
        assert_eq!(block.command, Command::End);
        assert_eq!(block.content, app);
        assert_eq!(&raw[used..], &next);
    }

    #[tokio::test]
    async fn direct_tail_in_the_same_write_is_raw() {
        let (client, mut peer) = duplex(64 * 1024);
        let mut vision = VisionStream::new(client, USER_ID, Vec::new(), rng(13));
        vision.writer.inspect(&server_hello());

        let app = app_data_record(b"payload");
        let next = app_data_record(b"next");
        let mut first = app.clone();
        first.extend_from_slice(&next[..3]);
        vision
            .write_all(&first)
            .await
            .expect("write complete record plus partial next");
        vision
            .write_all(&next[3..])
            .await
            .expect("complete raw tail");
        vision.shutdown().await.expect("shutdown Vision writer");

        let mut raw = Vec::new();
        peer.read_to_end(&mut raw)
            .await
            .expect("read raw Vision output");
        let (block, used) = parse_block(&raw, true)
            .expect("Direct block must parse")
            .expect("Direct block must be complete");
        assert_eq!(block.command, Command::Direct);
        assert_eq!(block.content, app);
        assert_eq!(&raw[used..], &next);
    }

    #[tokio::test]
    async fn split_app_data_record_still_triggers_direct() {
        let (client, mut peer) = duplex(64 * 1024);
        let mut vision = VisionStream::new(client, USER_ID, Vec::new(), rng(12));
        vision.writer.inspect(&server_hello());

        let app = app_data_record(b"split-payload");
        // Split inside the TLS header and again inside the body. The writer
        // must carry the partial record instead of framing an incomplete one
        // and losing the Direct transition.
        vision
            .write_all(&app[..2])
            .await
            .expect("write header prefix");
        vision
            .write_all(&app[2..9])
            .await
            .expect("write header remainder and body prefix");
        vision
            .write_all(&app[9..])
            .await
            .expect("write body remainder");
        vision.write_all(b"raw-tail").await.expect("write raw tail");
        vision.shutdown().await.expect("shutdown Vision writer");

        let mut raw = Vec::new();
        peer.read_to_end(&mut raw)
            .await
            .expect("read raw Vision output");
        let (block, used) = parse_block(&raw, true)
            .expect("Direct block must parse")
            .expect("Direct block must be complete");
        assert_eq!(block.command, Command::Direct);
        assert_eq!(block.content, app);
        assert_eq!(&raw[used..], b"raw-tail");
        assert!(vision.write_is_raw());
    }
}
