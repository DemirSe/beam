//! Pipe creation and zero-copy `splice(2)` wrappers.

use std::io;
use std::ops::{BitOr, BitOrAssign};
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::ptr;

/// Flags accepted by [`splice`].
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct SpliceFlags(u32);

impl SpliceFlags {
    /// No flags.
    pub const NONE: Self = Self(0);
    /// Move pages instead of copying when the kernel can.
    pub const MOVE: Self = Self(libc::SPLICE_F_MOVE);
    /// Do not block; report `WouldBlock` instead.
    pub const NONBLOCK: Self = Self(libc::SPLICE_F_NONBLOCK);

    /// Returns the raw flag bits.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Returns `true` if every bit in `other` is also set in `self`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl BitOr for SpliceFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for SpliceFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// Creates a nonblocking pipe with close-on-exec set on both ends.
///
/// Returns the read end first and the write end second.
pub fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds: [libc::c_int; 2] = [0; 2];

    // SAFETY: `fds` points to storage for two `c_int` values. On success
    // `pipe2` writes two descriptors; on failure it writes none.
    let result = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: `pipe2` succeeded, so `fds[0]` is a valid descriptor that we
    // own and transfer exactly once.
    let read_end = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    // SAFETY: `fds[1]` is the other valid, newly owned descriptor from the
    // same successful `pipe2` call.
    let write_end = unsafe { OwnedFd::from_raw_fd(fds[1]) };

    Ok((read_end, write_end))
}

/// Moves up to `len` bytes from `fd_in` to `fd_out`.
///
/// A return value of `Ok(0)` means end of input. `EAGAIN` is mapped to
/// [`io::ErrorKind::WouldBlock`].
pub fn splice(fd_in: RawFd, fd_out: RawFd, len: usize, flags: SpliceFlags) -> io::Result<usize> {
    // SAFETY: Both descriptors are supplied by the caller; the kernel
    // validates them and reports invalid or unsupported descriptors as an
    // error. Null offsets select the current file offset, so no user pointer
    // is dereferenced.
    let result = unsafe {
        libc::splice(
            fd_in,
            ptr::null_mut(),
            fd_out,
            ptr::null_mut(),
            len,
            flags.bits(),
        )
    };

    if result < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EAGAIN) {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        return Err(error);
    }

    Ok(result as usize)
}

#[cfg(test)]
mod tests {
    use super::{SpliceFlags, pipe, splice};
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::net::UnixStream;

    fn socket_pair() -> (UnixStream, UnixStream) {
        let mut fds: [libc::c_int; 2] = [-1; 2];

        // SAFETY: `fds` points to storage for two descriptors. On success
        // `socketpair` initializes both entries; on failure it writes none.
        let result =
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        assert_eq!(
            result,
            0,
            "socketpair failed: {}",
            std::io::Error::last_os_error()
        );

        // SAFETY: `socketpair` succeeded, so `fds[0]` is a valid descriptor
        // that we own and transfer exactly once.
        let first = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        // SAFETY: `fds[1]` is the other valid, newly owned descriptor from the
        // same successful `socketpair` call.
        let second = unsafe { OwnedFd::from_raw_fd(fds[1]) };

        (UnixStream::from(first), UnixStream::from(second))
    }

    #[test]
    fn splice_moves_socket_bytes_through_pipe() {
        let (source, mut sink) = socket_pair();
        let (pipe_read, pipe_write) = pipe().unwrap();
        let payload = b"beam splice test payload";

        sink.write_all(payload).unwrap();
        sink.flush().unwrap();

        let mut moved = 0;
        while moved < payload.len() {
            let count = splice(
                source.as_raw_fd(),
                pipe_write.as_raw_fd(),
                payload.len() - moved,
                SpliceFlags::MOVE | SpliceFlags::NONBLOCK,
            )
            .unwrap();
            assert!(count > 0, "splice returned zero before EOF");
            moved += count;
        }

        drop(pipe_write);
        let mut pipe_read = File::from(pipe_read);
        let mut received = Vec::new();
        pipe_read.read_to_end(&mut received).unwrap();
        assert_eq!(received, payload);
    }

    #[test]
    fn splice_returns_zero_at_eof() {
        let (source, sink) = socket_pair();
        drop(sink);

        let (_pipe_read, pipe_write) = pipe().unwrap();
        let count = splice(
            source.as_raw_fd(),
            pipe_write.as_raw_fd(),
            64,
            SpliceFlags::NONBLOCK,
        )
        .unwrap();

        assert_eq!(count, 0);
    }

    #[test]
    fn splice_maps_eagain_to_would_block() {
        let (source, _sink) = socket_pair();
        crate::fd::set_nonblocking(source.as_raw_fd()).unwrap();

        let (_pipe_read, pipe_write) = pipe().unwrap();
        let error = splice(
            source.as_raw_fd(),
            pipe_write.as_raw_fd(),
            1,
            SpliceFlags::NONBLOCK,
        )
        .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
    }
}
