//! Stateful XTLS Vision stream adapter.
//!
//! [`VisionStream`] wraps an outer TLS stream and turns the VLESS body into
//! Vision blocks. The first block in each direction carries the raw VLESS user
//! id; later blocks do not. The reader strips padding and stops framing on
//! `End`. Direct mode is rejected: bypassing the outer TLS layer requires relay
//! plumbing that this milestone does not implement.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use rand::Rng;
use rand::rngs::SmallRng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::frame::{
    Command, MAX_BLOCK_LEN, MAX_CONTENT_LEN, VisionError, encode_block, parse_block,
};
use super::state::{VisionReaderState, VisionStateError, VisionWriterState};

/// Chunk size used when reading framing bytes from the inner stream.
const READ_CHUNK: usize = 4096;

/// Maximum plaintext accepted by one `poll_write` call.
///
/// Larger caller buffers are accepted on later polls. Within one call the
/// plaintext is split into [`MAX_CONTENT_LEN`] blocks.
const MAX_WRITE_BATCH: usize = MAX_BLOCK_LEN;

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
    writer: VisionWriterState,
    rng: R,
    write_queue: Vec<u8>,
    write_queue_offset: usize,
    pending_accept: Option<usize>,
}

impl<S, R> VisionStream<S, R>
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: Rng + Unpin,
{
    /// Wraps `inner`, using `initial_body` as the first buffered Vision bytes.
    ///
    /// The VLESS request parser may have consumed part or all of the first
    /// Vision block together with the request header. Those trailing bytes are
    /// passed here; any remaining block bytes are read from `inner`.
    pub fn new(inner: S, user_id: [u8; 16], initial_body: Vec<u8>, rng: R) -> Self {
        Self {
            inner,
            user_id,
            reader: VisionReaderState::new(),
            first_read_block: true,
            read_buf: initial_body,
            read_out: Vec::new(),
            read_out_offset: 0,
            writer: VisionWriterState::new(),
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

    fn plan_and_queue(&mut self, accepted: &[u8]) -> io::Result<()> {
        let chunks: Vec<&[u8]> = accepted.chunks(MAX_CONTENT_LEN).collect();
        let plan = self.writer.plan_write(&chunks, false, &mut self.rng);
        if plan.switch_to_direct {
            return Err(direct_error());
        }

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
        Ok(())
    }
}

impl<S, R> AsyncRead for VisionStream<S, R>
where
    S: AsyncRead + AsyncWrite + Unpin,
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
                        return Poll::Ready(Err(direct_error()));
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
    S: AsyncRead + AsyncWrite + Unpin,
    R: Rng + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.as_mut().get_mut();

        if let Some(accepted) = this.pending_accept {
            match this.poll_flush_queue(cx) {
                Poll::Ready(Ok(())) => {
                    this.pending_accept = None;
                    return Poll::Ready(Ok(accepted));
                }
                Poll::Ready(Err(error)) => {
                    this.pending_accept = None;
                    return Poll::Ready(Err(error));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        if !this.write_queue.is_empty() {
            match this.poll_flush_queue(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if !this.writer.padding_enabled() {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let take = buf.len().min(MAX_WRITE_BATCH);
        if let Err(error) = this.plan_and_queue(&buf[..take]) {
            return Poll::Ready(Err(error));
        }
        this.pending_accept = Some(take);

        match this.poll_flush_queue(cx) {
            Poll::Ready(Ok(())) => {
                this.pending_accept = None;
                Poll::Ready(Ok(take))
            }
            Poll::Ready(Err(error)) => {
                this.pending_accept = None;
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        match this.poll_flush_queue(cx) {
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
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

fn vision_error(error: VisionError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

fn state_error(error: VisionStateError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

fn direct_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "Vision Direct mode is not supported in this milestone",
    )
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
    async fn direct_mode_is_unsupported() {
        let raw = block_bytes(Some(USER_ID), Command::Direct, b"x", 0);
        let (mut peer, client) = duplex(64 * 1024);
        peer.write_all(&raw).await.expect("write Direct block");
        peer.shutdown().await.expect("shutdown Direct writer");

        let mut vision = VisionStream::new(client, USER_ID, Vec::new(), rng(8));
        let mut output = Vec::new();
        let error = vision
            .read_to_end(&mut output)
            .await
            .expect_err("Direct must be rejected");
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }
}
