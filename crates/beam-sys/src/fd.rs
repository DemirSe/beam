//! File descriptor flag helpers.

use std::io;
use std::os::fd::RawFd;

/// Marks `fd` as nonblocking.
///
/// The flag is set on the open file description, so it also affects other
/// descriptors that refer to the same description.
pub fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = get_status_flags(fd)?;
    set_status_flags(fd, flags | libc::O_NONBLOCK)
}

/// Sets close-on-exec on `fd`.
pub fn set_cloexec(fd: RawFd) -> io::Result<()> {
    let flags = get_descriptor_flags(fd)?;
    set_descriptor_flags(fd, flags | libc::FD_CLOEXEC)
}

fn get_status_flags(fd: RawFd) -> io::Result<libc::c_int> {
    // SAFETY: `F_GETFL` takes no variadic argument and does not dereference a
    // user pointer. The kernel reports an invalid descriptor as `EBADF`.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(flags)
    }
}

fn set_status_flags(fd: RawFd, flags: libc::c_int) -> io::Result<()> {
    // SAFETY: `F_SETFL` consumes the `c_int` passed by value and does not
    // dereference user pointers. An invalid descriptor is reported as an
    // error by the kernel.
    let result = unsafe { libc::fcntl(fd, libc::F_SETFL, flags) };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn get_descriptor_flags(fd: RawFd) -> io::Result<libc::c_int> {
    // SAFETY: `F_GETFD` takes no variadic argument and does not dereference a
    // user pointer. The kernel reports an invalid descriptor as `EBADF`.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(flags)
    }
}

fn set_descriptor_flags(fd: RawFd, flags: libc::c_int) -> io::Result<()> {
    // SAFETY: `F_SETFD` consumes the `c_int` passed by value and does not
    // dereference user pointers. An invalid descriptor is reported as an
    // error by the kernel.
    let result = unsafe { libc::fcntl(fd, libc::F_SETFD, flags) };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{set_cloexec, set_nonblocking};
    use std::io::{self, Read};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    #[test]
    fn set_nonblocking_makes_empty_socket_read_would_block() {
        let (mut reader, _writer) = UnixStream::pair().unwrap();

        set_nonblocking(reader.as_raw_fd()).unwrap();

        let mut byte = [0_u8; 1];
        let error = reader.read(&mut byte).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn set_cloexec_sets_close_on_exec() {
        let (stream, _peer) = UnixStream::pair().unwrap();

        set_cloexec(stream.as_raw_fd()).unwrap();

        // SAFETY: `F_GETFD` takes no variadic argument and does not
        // dereference a user pointer. `stream` owns a valid descriptor.
        let flags = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0, "F_GETFD failed: {}", io::Error::last_os_error());
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
    }
}
