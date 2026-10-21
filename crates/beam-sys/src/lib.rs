#![allow(unsafe_code)]

//! Isolated Linux syscall layer for beam.
//!
//! Every `unsafe` block in this crate must carry a safety comment that
//! explains the invariants the caller must uphold.

use std::io;
use std::os::fd::RawFd;

pub mod fd;
pub mod poll;
pub mod socket;
pub mod splice;

pub use fd::{set_cloexec, set_nonblocking};
pub use poll::{PollEvents, PollFd, poll};
pub use socket::{set_reuse_addr, set_tcp_keepalive, set_tcp_nodelay};
pub use splice::{SpliceFlags, pipe, splice};

/// Resizes the kernel buffer of a pipe.
///
/// The kernel rounds the request up to a whole number of pages and caps it at
/// `/proc/sys/fs/pipe-max-size`. Returns the size actually granted.
pub fn set_pipe_size(fd: RawFd, size: usize) -> io::Result<usize> {
    let size = libc::c_int::try_from(size).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "pipe size does not fit in c_int",
        )
    })?;
    if size <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "pipe size must be positive",
        ));
    }

    // SAFETY: `F_SETPIPE_SZ` consumes the integer argument by value and does
    // not dereference a user pointer. The kernel validates the descriptor and
    // the requested size, reporting invalid values as an error.
    let result = unsafe { libc::fcntl(fd, libc::F_SETPIPE_SZ, size) };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result as usize)
    }
}

/// Shuts down the write half of a connected socket.
///
/// The read half stays usable, which is what a relay needs after its source
/// reaches EOF. `ENOTCONN` is treated as success because a socket whose peer is
/// already gone has nothing left to shut down.
pub fn shutdown_write(fd: RawFd) -> io::Result<()> {
    // SAFETY: `shutdown` only reads the descriptor and the `how` argument. The
    // kernel validates the descriptor; no user pointer is dereferenced and
    // nothing is retained after the call.
    let result = unsafe { libc::shutdown(fd, libc::SHUT_WR) };
    if result == -1 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOTCONN) {
            return Ok(());
        }
        return Err(error);
    }
    Ok(())
}
