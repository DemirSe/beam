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
    AcceptError, get_ipv6_v6only, get_tcp_maxseg, set_reuse_addr, set_tcp_keepalive,
    set_tcp_maxseg, set_tcp_nodelay, set_udp_recv_buffer,
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

/// Returns the current kernel buffer capacity of a pipe in bytes.
#[cfg(target_os = "linux")]
pub fn get_pipe_size(fd: RawFd) -> io::Result<usize> {
    // SAFETY: `F_GETPIPE_SZ` takes no pointer arguments and queries the
    // kernel's current capacity for `fd`, returning -1 on error.
    let result = unsafe { libc::fcntl(fd, libc::F_GETPIPE_SZ) };
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

/// Reads the host TCP listen backlog ceiling (`net.core.somaxconn`).
#[cfg(target_os = "linux")]
#[must_use]
pub fn tcp_somaxconn() -> Option<u32> {
    let raw = std::fs::read_to_string("/proc/sys/net/core/somaxconn").ok()?;
    parse_positive_u32(&raw)
}

#[cfg(target_os = "linux")]
fn parse_positive_u32(raw: &str) -> Option<u32> {
    raw.trim().parse::<u32>().ok().filter(|&value| value > 0)
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;

    #[test]
    fn try_clone_fd_returns_distinct_cloexec_fd_and_keeps_original_usable() {
        let (read_end, write_end) = pipe().unwrap();
        let orig_fd = write_end.as_raw_fd();
        let cloned = try_clone_fd(orig_fd).unwrap();
        let cloned_fd = cloned.as_raw_fd();

        assert_ne!(cloned_fd, orig_fd, "clone must be a distinct descriptor");

        // SAFETY: `F_GETFD` takes no pointer argument and queries descriptor
        // flags on the live owned `cloned_fd`.
        let flags = unsafe { libc::fcntl(cloned_fd, libc::F_GETFD) };
        assert_ne!(flags, -1, "F_GETFD failed: {}", io::Error::last_os_error());
        assert_ne!(
            flags & libc::FD_CLOEXEC,
            0,
            "cloned descriptor must have FD_CLOEXEC set"
        );

        // Dropping the clone must not close or invalidate the original.
        drop(cloned);
        let mut writer = File::from(write_end);
        writer.write_all(b"still open").unwrap();
        drop(writer);

        let mut reader = File::from(read_end);
        let mut received = Vec::new();
        reader.read_to_end(&mut received).unwrap();
        assert_eq!(received, b"still open");
    }

    #[test]
    fn try_clone_fd_stays_usable_after_original_is_dropped() {
        let (read_end, write_end) = pipe().unwrap();
        let cloned = try_clone_fd(write_end.as_raw_fd()).unwrap();

        // Dropping the original must not close or invalidate the clone.
        drop(write_end);
        let mut writer = File::from(cloned);
        writer.write_all(b"clone alive").unwrap();
        drop(writer);

        let mut reader = File::from(read_end);
        let mut received = Vec::new();
        reader.read_to_end(&mut received).unwrap();
        assert_eq!(received, b"clone alive");
    }

    #[test]
    fn try_clone_fd_rejects_invalid_descriptor() {
        let error = try_clone_fd(-1).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EBADF));
    }

    #[test]
    fn shutdown_write_treats_unconnected_socket_as_success() {
        // An unconnected TCP socket causes `shutdown(2)` to return ENOTCONN.
        // SAFETY: `socket` takes no pointers and returns a new fd or -1.
        let raw_fd =
            unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        assert!(
            raw_fd >= 0,
            "socket creation failed: {}",
            io::Error::last_os_error()
        );
        // SAFETY: `raw_fd` was just returned by `socket` and is uniquely owned.
        let sock = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        shutdown_write(sock.as_raw_fd()).expect("ENOTCONN must be treated as success");
    }

    #[test]
    fn shutdown_write_treats_disconnected_tcp_socket_as_success() {
        use std::net::{Ipv4Addr, TcpListener, TcpStream};

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(address).unwrap();
        let (server, _) = listener.accept().unwrap();

        // Force an immediate RST on close so the client socket transitions to
        // a disconnected state where `shutdown(SHUT_WR)` returns ENOTCONN.
        let linger = libc::linger {
            l_onoff: 1,
            l_linger: 0,
        };
        // SAFETY: `linger` is a live `libc::linger` value and its exact byte
        // size is passed to `setsockopt` for `SO_LINGER`.
        let set = unsafe {
            libc::setsockopt(
                server.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_LINGER,
                (&raw const linger).cast::<libc::c_void>(),
                std::mem::size_of::<libc::linger>() as libc::socklen_t,
            )
        };
        assert_eq!(set, 0, "SO_LINGER failed: {}", io::Error::last_os_error());
        drop(server);

        // Observe the reset so the kernel marks the client socket disconnected.
        let mut byte = [0_u8; 1];
        let _ = client.read(&mut byte);

        shutdown_write(client.as_raw_fd())
            .expect("disconnected TCP socket must be treated as success");
    }

    #[test]
    fn shutdown_write_propagates_invalid_descriptor_error() {
        let error = shutdown_write(-1).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EBADF));
    }

    #[test]
    fn set_pipe_size_resizes_and_reports_effective_capacity() {
        let (_read_end, write_end) = pipe().unwrap();
        let fd = write_end.as_raw_fd();
        let page = usize::try_from(page_size()).unwrap_or(4096);
        let pipe_max = std::fs::read_to_string("/proc/sys/fs/pipe-max-size")
            .ok()
            .and_then(|raw| raw.trim().parse::<usize>().ok());
        // Request two pages (or one page if the host cap is smaller) so the
        // resize stays well within ordinary unprivileged limits.
        let requested = match pipe_max {
            Some(max) if max < page.saturating_mul(2) => page.min(max).max(1),
            _ => page.saturating_mul(2),
        };
        let required = std::env::var_os("BEAM_REQUIRE_PIPE_RESIZE_TEST").is_some();

        match set_pipe_size(fd, requested) {
            Ok(actual) => {
                assert!(
                    actual >= requested,
                    "granted pipe size {actual} must be at least requested {requested}"
                );
                assert_eq!(
                    get_pipe_size(fd).unwrap(),
                    actual,
                    "F_GETPIPE_SZ must match the capacity returned by set_pipe_size"
                );
            }
            Err(error)
                if !required
                    && matches!(error.raw_os_error(), Some(libc::EPERM | libc::ENOMEM)) =>
            {
                // Host pipe limits prevented resizing on an unprivileged host;
                // eligible runners set BEAM_REQUIRE_PIPE_RESIZE_TEST=1.
            }
            Err(error) => {
                panic!("set_pipe_size({requested}) failed unexpectedly: {error}");
            }
        }
    }

    #[test]
    fn parse_positive_u32_validates_sysctl_values() {
        assert_eq!(parse_positive_u32("4096\n"), Some(4096));
        assert_eq!(parse_positive_u32("0\n"), None);
        assert_eq!(parse_positive_u32("-1\n"), None);
        assert_eq!(parse_positive_u32("not-a-number"), None);
    }
}
