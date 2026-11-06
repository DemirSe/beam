#![allow(unsafe_code)]

//! Isolated Linux syscall layer for beam.
//!
//! Every `unsafe` block in this crate must carry a safety comment that
//! explains the invariants the caller must uphold.

use std::io;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

pub mod eventfd;
pub mod fd;
pub mod poll;
pub mod socket;
pub mod splice;

pub use eventfd::EventFd;
pub use fd::{set_cloexec, set_nonblocking};
pub use poll::{PollEvents, PollFd, poll};
pub use socket::{
    get_tcp_maxseg, set_reuse_addr, set_tcp_keepalive, set_tcp_maxseg, set_tcp_nodelay,
    set_udp_recv_buffer,
};
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

/// Returns the soft `RLIMIT_NOFILE` limit when it is finite.
#[must_use]
pub fn open_file_limit() -> Option<u64> {
    let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    // SAFETY: `getrlimit` initializes the provided `rlimit` structure on
    // success. The pointer is valid for the duration of the call and the
    // kernel writes at most one structure.
    let result = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) };
    if result != 0 {
        return None;
    }
    // SAFETY: `getrlimit` returned success, so it initialized the structure.
    let limit = unsafe { limit.assume_init() };
    if limit.rlim_cur == libc::RLIM_INFINITY {
        None
    } else {
        Some(limit.rlim_cur)
    }
}

/// Duplicates a descriptor with close-on-exec set.
pub fn try_clone_fd(fd: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: `F_DUPFD_CLOEXEC` only reads the integer descriptor and returns a
    // new descriptor owned by the caller. It does not dereference a pointer.
    let result = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `result` is a newly duplicated descriptor owned by this call.
    Ok(unsafe { OwnedFd::from_raw_fd(result) })
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
