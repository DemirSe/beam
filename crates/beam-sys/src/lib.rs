#![allow(unsafe_code)]

//! Isolated Linux syscall layer for beam.
//!
//! Every `unsafe` block in this crate must carry a safety comment that
//! explains the invariants the caller must uphold.

#[cfg(not(target_os = "linux"))]
compile_error!("beam-sys only supports Linux targets; beam is a Linux-only server");

#[cfg(target_os = "linux")]
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

#[cfg(target_os = "linux")]
pub mod eventfd;
#[cfg(target_os = "linux")]
pub mod fd;
#[cfg(target_os = "linux")]
pub mod poll;
#[cfg(target_os = "linux")]
pub mod socket;
#[cfg(target_os = "linux")]
pub mod splice;

#[cfg(target_os = "linux")]
pub use eventfd::EventFd;
#[cfg(target_os = "linux")]
pub use fd::{set_cloexec, set_nonblocking};
#[cfg(target_os = "linux")]
pub use poll::{PollEvents, PollFd, poll};
#[cfg(target_os = "linux")]
pub use socket::{
    AcceptError, get_tcp_maxseg, set_reuse_addr, set_tcp_keepalive, set_tcp_maxseg,
    set_tcp_nodelay, set_udp_recv_buffer,
};
#[cfg(target_os = "linux")]
pub use splice::{SpliceFlags, pipe, splice};

/// Resizes the kernel buffer of a pipe.
///
/// The kernel rounds the request up to a whole number of pages and caps it at
/// `/proc/sys/fs/pipe-max-size`. Returns the size actually granted.
#[cfg(target_os = "linux")]
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

/// Queries the kernel page size via `sysconf(_SC_PAGESIZE)`, returning `None`
/// if the query fails or returns a non-positive value.
#[cfg(target_os = "linux")]
#[must_use]
pub fn query_page_size() -> Option<u64> {
    // SAFETY: `sysconf(_SC_PAGESIZE)` takes no pointer arguments and returns
    // the page size or -1 on error.
    let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    (value > 0).then_some(value as u64)
}

/// Returns the kernel page size used by pipe and splice accounting, falling
/// back to 4 KiB if `sysconf(_SC_PAGESIZE)` fails.
#[cfg(target_os = "linux")]
#[must_use]
pub fn page_size() -> u64 {
    query_page_size().unwrap_or(4096)
}

/// Reads the per-user soft limit on pipe pages.
#[cfg(target_os = "linux")]
#[must_use]
pub fn pipe_user_pages_soft() -> Option<u64> {
    std::fs::read_to_string("/proc/sys/fs/pipe-user-pages-soft")
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Returns the soft `RLIMIT_NOFILE` limit. `None` means unlimited.
#[cfg(target_os = "linux")]
pub fn open_file_limit() -> io::Result<Option<u64>> {
    let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    // SAFETY: `getrlimit` initializes the provided `rlimit` structure on
    // success. The pointer is valid for the duration of the call and the
    // kernel writes at most one structure.
    let result = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `getrlimit` returned success, so it initialized the structure.
    let limit = unsafe { limit.assume_init() };
    Ok((limit.rlim_cur != libc::RLIM_INFINITY).then_some(limit.rlim_cur))
}

/// Duplicates a descriptor with close-on-exec set.
#[cfg(target_os = "linux")]
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
#[cfg(target_os = "linux")]
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
