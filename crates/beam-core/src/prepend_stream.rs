//! A stream wrapper that serves a prefix before the inner stream.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Serves `prefix` bytes before reading from `inner`.
///
/// Writes and flushes always go directly to the inner stream.
#[derive(Debug)]
pub struct PrependStream<S> {
    prefix: Vec<u8>,
    offset: usize,
    inner: S,
}

impl<S> PrependStream<S> {
    /// Wraps `inner`, serving `prefix` first.
    pub fn new(inner: S, prefix: Vec<u8>) -> Self {
        Self {
            prefix,
            offset: 0,
            inner,
        }
    }

    /// Returns the inner stream and the unread part of the prefix.
    pub fn into_inner(self) -> (S, Vec<u8>) {
        let remaining = self.prefix.get(self.offset..).unwrap_or(&[]).to_vec();
        (self.inner, remaining)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrependStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if this.offset < this.prefix.len() {
            let remaining = &this.prefix[this.offset..];
            let count = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..count]);
            this.offset += count;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrependStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.as_mut().get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.as_mut().get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.as_mut().get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.as_mut().get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use super::PrependStream;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn serves_prefix_before_inner_bytes() {
        let (inner, mut peer) = tokio::io::duplex(64);
        peer.write_all(b"inner").await.unwrap();
        peer.shutdown().await.unwrap();

        let mut stream = PrependStream::new(inner, b"prefix".to_vec());
        let mut output = Vec::new();
        stream.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, b"prefixinner");
    }

    #[tokio::test]
    async fn writes_go_to_inner() {
        let (inner, mut peer) = tokio::io::duplex(64);
        let mut stream = PrependStream::new(inner, b"unused".to_vec());
        stream.write_all(b"hello").await.unwrap();
        stream.shutdown().await.unwrap();

        let mut output = Vec::new();
        peer.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, b"hello");
    }
}
