//! Socket option helpers.

use std::io;
use std::mem::size_of;
use std::os::fd::RawFd;
use std::time::Duration;

/// Enables `TCP_NODELAY` on `fd`.
pub fn set_tcp_nodelay(fd: RawFd) -> io::Result<()> {
    setsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY, 1)
}

/// Enables TCP keepalive on `fd` with the given idle time and probe interval.
///
/// Both durations are in whole seconds. Durations that do not fit in a
/// `c_int` are rejected before any socket option is changed.
pub fn set_tcp_keepalive(fd: RawFd, idle: Duration, interval: Duration) -> io::Result<()> {
    let idle = duration_secs(idle, "keepalive idle")?;
    let interval = duration_secs(interval, "keepalive interval")?;

    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1)?;
    setsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPIDLE, idle)?;
    setsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL, interval)
}

/// Enables `SO_REUSEADDR` on `fd`.
pub fn set_reuse_addr(fd: RawFd) -> io::Result<()> {
    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)
}

fn duration_secs(value: Duration, name: &str) -> io::Result<libc::c_int> {
    let seconds = value.as_secs();
    if seconds == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} duration must be at least one second"),
        ));
    }

    libc::c_int::try_from(seconds).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} duration does not fit in c_int"),
        )
    })
}

fn setsockopt_int(
    fd: RawFd,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    let length = size_of::<libc::c_int>() as libc::socklen_t;

    // SAFETY: `value` is a live `c_int` and `length` describes exactly its
    // size. `setsockopt` reads at most that many bytes and does not retain
    // the pointer. The kernel validates the descriptor and option name.
    let result = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            (&raw const value).cast::<libc::c_void>(),
            length,
        )
    };

    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{set_reuse_addr, set_tcp_keepalive, set_tcp_nodelay};
    use std::io;
    use std::net::{TcpListener, TcpStream};
    use std::os::fd::AsRawFd;
    use std::time::Duration;

    fn loopback_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    #[test]
    fn tcp_nodelay_succeeds_on_loopback_stream() {
        let (client, server) = loopback_pair();

        set_tcp_nodelay(client.as_raw_fd()).unwrap();
        set_tcp_nodelay(server.as_raw_fd()).unwrap();
    }

    #[test]
    fn keepalive_succeeds_on_loopback_stream() {
        let (client, server) = loopback_pair();

        set_tcp_keepalive(
            client.as_raw_fd(),
            Duration::from_secs(30),
            Duration::from_secs(5),
        )
        .unwrap();
        set_tcp_keepalive(
            server.as_raw_fd(),
            Duration::from_secs(30),
            Duration::from_secs(5),
        )
        .unwrap();
    }

    #[test]
    fn reuse_addr_succeeds_on_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();

        set_reuse_addr(listener.as_raw_fd()).unwrap();
    }

    #[test]
    fn keepalive_rejects_zero_duration() {
        let (client, _server) = loopback_pair();

        let error = set_tcp_keepalive(
            client.as_raw_fd(),
            Duration::from_millis(500),
            Duration::from_secs(5),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn keepalive_rejects_durations_larger_than_c_int() {
        let (client, _server) = loopback_pair();
        let too_large = Duration::from_secs(libc::c_int::MAX as u64 + 1);

        let idle_error =
            set_tcp_keepalive(client.as_raw_fd(), too_large, Duration::from_secs(5)).unwrap_err();
        assert_eq!(idle_error.kind(), io::ErrorKind::InvalidInput);

        let interval_error =
            set_tcp_keepalive(client.as_raw_fd(), Duration::from_secs(30), too_large).unwrap_err();
        assert_eq!(interval_error.kind(), io::ErrorKind::InvalidInput);
    }
}
