//! Socket option helpers.

use std::io;
use std::mem::size_of;
use std::os::fd::RawFd;
use std::time::Duration;

/// Classifies a listener `accept` error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcceptError {
    /// The process or the system is short of a resource (`EMFILE`, `ENFILE`,
    /// `ENOBUFS`, `ENOMEM`). A retry cannot succeed until something is freed.
    ResourceShortage,
    /// The failure applies to one connection (`ECONNABORTED`) or the call was
    /// interrupted. The listener is still usable.
    Transient,
}

impl AcceptError {
    /// Classifies an `accept` error.
    #[must_use]
    pub fn classify(error: &io::Error) -> Self {
        match error.raw_os_error() {
            Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM) => {
                Self::ResourceShortage
            }
            _ => Self::Transient,
        }
    }

    /// Returns a stable label for logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ResourceShortage => "resource_shortage",
            Self::Transient => "transient",
        }
    }
}

/// Enables `TCP_NODELAY` on `fd`.
pub fn set_tcp_nodelay(fd: RawFd) -> io::Result<()> {
    setsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY, 1)
}

/// Enables TCP keepalive on `fd` with the given idle time and probe interval.
///
/// Both durations are in whole seconds. Durations that do not fit in a
/// `c_int` are rejected before any socket option is changed. Timing options
/// are applied before activation, so an error leaves keepalive disabled.
pub fn set_tcp_keepalive(fd: RawFd, idle: Duration, interval: Duration) -> io::Result<()> {
    let idle = duration_secs(idle, "keepalive idle")?;
    let interval = duration_secs(interval, "keepalive interval")?;

    setsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPIDLE, idle)?;
    setsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL, interval)?;
    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1)
}

/// Sets `TCP_KEEPCNT`, the number of unanswered keepalive probes after which
/// the kernel drops the connection.
///
/// The count is applied only as a tuning hint: keepalive stays disabled until
/// [`set_tcp_keepalive`] enables `SO_KEEPALIVE`. A zero count is rejected.
pub fn set_tcp_keepcnt(fd: RawFd, count: u32) -> io::Result<()> {
    let count = libc::c_int::try_from(count).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "TCP keepalive count does not fit in c_int",
        )
    })?;
    if count <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TCP keepalive count must be positive",
        ));
    }
    setsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPCNT, count)
}

/// Sets `TCP_USER_TIMEOUT` on `fd`.
///
/// The timeout is expressed in milliseconds as a positive `c_int`. Zero
/// (sub-millisecond) durations and values that overflow `c_int` are rejected
/// before any socket option is changed.
pub fn set_tcp_user_timeout(fd: RawFd, timeout: Duration) -> io::Result<()> {
    let millis = duration_millis(timeout, "TCP user timeout")?;
    setsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_USER_TIMEOUT, millis)
}

/// Sets the TCP maximum segment size for `fd`.
///
/// On Linux this must be called before `connect` to change the MSS advertised
/// in the SYN and the maximum payload used for local sends. The kernel clamps
/// the value to its supported range.
pub fn set_tcp_maxseg(fd: RawFd, mss: u16) -> io::Result<()> {
    if mss == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TCP maximum segment size must be positive",
        ));
    }
    setsockopt_int(
        fd,
        libc::IPPROTO_TCP,
        libc::TCP_MAXSEG,
        libc::c_int::from(mss),
    )
}

/// Returns the current TCP maximum segment size for `fd`.
pub fn get_tcp_maxseg(fd: RawFd) -> io::Result<u16> {
    let value = getsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_MAXSEG)?;
    u16::try_from(value).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "TCP maximum segment size does not fit in u16",
        )
    })
}

/// Enables `SO_REUSEADDR` on `fd`.
pub fn set_reuse_addr(fd: RawFd) -> io::Result<()> {
    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)
}

/// Returns whether `IPV6_V6ONLY` is enabled on an IPv6 socket descriptor.
pub fn get_ipv6_v6only(fd: RawFd) -> io::Result<bool> {
    getsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY).map(|value| value != 0)
}

/// Sets the receive buffer for a UDP socket.
///
/// The kernel may clamp the request to `net.core.rmem_max` and doubles the
/// stored value. The caller should treat a success as a best-effort tuning
/// hint, not as a guaranteed buffer size.
pub fn set_udp_recv_buffer(fd: RawFd, bytes: usize) -> io::Result<()> {
    let size = libc::c_int::try_from(bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "UDP receive buffer size does not fit in c_int",
        )
    })?;
    if size <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "UDP receive buffer size must be positive",
        ));
    }
    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, size)
}

fn duration_millis(value: Duration, name: &str) -> io::Result<libc::c_int> {
    let millis = value.as_millis();
    if millis == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} duration must be at least one millisecond"),
        ));
    }

    libc::c_int::try_from(millis).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} duration does not fit in c_int"),
        )
    })
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

fn getsockopt_int(fd: RawFd, level: libc::c_int, name: libc::c_int) -> io::Result<libc::c_int> {
    let mut value: libc::c_int = 0;
    let mut length = size_of::<libc::c_int>() as libc::socklen_t;

    // SAFETY: `value` is a live `c_int` and `length` describes exactly its
    // size. `getsockopt` writes at most that many bytes and does not retain
    // the pointer. The kernel validates the descriptor and option name.
    let result = unsafe {
        libc::getsockopt(
            fd,
            level,
            name,
            (&raw mut value).cast::<libc::c_void>(),
            &mut length,
        )
    };

    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(value)
    }
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
    use super::{
        AcceptError, get_ipv6_v6only, get_tcp_maxseg, getsockopt_int, set_reuse_addr,
        set_tcp_keepalive, set_tcp_keepcnt, set_tcp_maxseg, set_tcp_nodelay, set_tcp_user_timeout,
        set_udp_recv_buffer,
    };
    use std::io;
    use std::net::{TcpListener, TcpStream, UdpSocket};
    use std::os::fd::AsRawFd;
    use std::time::Duration;

    fn rmem_max() -> Option<libc::c_int> {
        std::fs::read_to_string("/proc/sys/net/core/rmem_max")
            .ok()?
            .trim()
            .parse()
            .ok()
    }

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
    fn tcp_maxseg_round_trips_before_connect() {
        // The dial path sets the option on an unconnected socket, which is the
        // only point where Linux uses it for the SYN and the local send limit.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();

        set_tcp_maxseg(listener.as_raw_fd(), 1400).unwrap();
        let observed = get_tcp_maxseg(listener.as_raw_fd()).unwrap();
        // Linux 6.5 and later report the value that was set on an unconnected
        // socket. Older kernels report `mss_cache` (536) until connect, so the
        // requested value is only observable on the newer kernels.
        assert!(
            observed == 1400 || observed == 536,
            "an unconnected socket reports the requested size or the pre-6.5 default, got {observed}"
        );
    }

    #[test]
    fn tcp_maxseg_accepts_loopback_stream_and_rejects_zero() {
        let (client, _server) = loopback_pair();

        // A connected socket keeps the MSS its handshake negotiated: a later
        // set does not lower it, so `dial` sets the option before `connect`.
        let negotiated = get_tcp_maxseg(client.as_raw_fd()).unwrap();
        assert!(negotiated >= 48, "a connected socket reports an MSS");
        set_tcp_maxseg(client.as_raw_fd(), 1400).unwrap();
        assert_eq!(get_tcp_maxseg(client.as_raw_fd()).unwrap(), negotiated);

        let error = set_tcp_maxseg(client.as_raw_fd(), 0).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
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
    fn keepcnt_round_trips_and_rejects_zero() {
        let (client, _server) = loopback_pair();

        set_tcp_keepcnt(client.as_raw_fd(), 4).unwrap();
        let observed =
            getsockopt_int(client.as_raw_fd(), libc::IPPROTO_TCP, libc::TCP_KEEPCNT).unwrap();
        assert_eq!(observed, 4);

        let error = set_tcp_keepcnt(client.as_raw_fd(), 0).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn reuse_addr_succeeds_on_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();

        set_reuse_addr(listener.as_raw_fd()).unwrap();
    }

    #[test]
    fn udp_recv_buffer_reports_the_effective_size() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let requested = 32 * 1024;
        set_udp_recv_buffer(socket.as_raw_fd(), requested).unwrap();

        let effective =
            getsockopt_int(socket.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVBUF).unwrap();
        let doubled = libc::c_int::try_from(requested * 2).unwrap();
        assert!(
            effective <= doubled,
            "the kernel must not report more than twice the request"
        );
        match rmem_max() {
            // Linux stores twice the request, clamped to `rmem_max` before the
            // doubling, so a cap at or above the request yields an exact value.
            Some(cap) if cap >= libc::c_int::try_from(requested).unwrap() => assert_eq!(
                effective, doubled,
                "a receive buffer below rmem_max reads back doubled"
            ),
            // The buffer may be capped below the request, or `/proc` may be
            // unreadable and the cap unknown; the bound above is the only
            // assertable part.
            _ => {}
        }

        let error = set_udp_recv_buffer(socket.as_raw_fd(), 0).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn keepalive_stays_disabled_when_a_timing_option_is_rejected() {
        // A UDP socket accepts SO_KEEPALIVE but rejects the TCP timing
        // options, so the option order is observable without a faulty host.
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();

        let error = set_tcp_keepalive(
            socket.as_raw_fd(),
            Duration::from_secs(30),
            Duration::from_secs(5),
        )
        .unwrap_err();
        assert!(
            error.raw_os_error().is_some(),
            "a real socket error is reported"
        );
        assert_eq!(
            getsockopt_int(socket.as_raw_fd(), libc::SOL_SOCKET, libc::SO_KEEPALIVE).unwrap(),
            0
        );
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
        assert_eq!(
            getsockopt_int(client.as_raw_fd(), libc::SOL_SOCKET, libc::SO_KEEPALIVE).unwrap(),
            0
        );
    }

    #[test]
    fn accept_errors_separate_a_resource_shortage_from_one_bad_connection() {
        for errno in [libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM] {
            let error = io::Error::from_raw_os_error(errno);
            assert_eq!(
                AcceptError::classify(&error),
                AcceptError::ResourceShortage,
                "errno {errno} is a resource shortage"
            );
        }
        for error in [
            io::Error::from_raw_os_error(libc::ECONNABORTED),
            io::Error::from_raw_os_error(libc::EINVAL),
            io::Error::new(io::ErrorKind::Interrupted, "signal"),
        ] {
            assert_eq!(AcceptError::classify(&error), AcceptError::Transient);
        }
        assert_eq!(AcceptError::ResourceShortage.as_str(), "resource_shortage");
        assert_eq!(AcceptError::Transient.as_str(), "transient");
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
        assert_eq!(
            getsockopt_int(client.as_raw_fd(), libc::SOL_SOCKET, libc::SO_KEEPALIVE).unwrap(),
            0
        );
    }

    #[test]
    fn ipv6_v6only_reports_effective_socket_mode() {
        let required = std::env::var_os("BEAM_REQUIRE_IPV6_TESTS").is_some();
        let loopback = match TcpListener::bind("[::1]:0") {
            Ok(listener) => listener,
            Err(error)
                if !required
                    && matches!(
                        error.raw_os_error(),
                        Some(libc::EAFNOSUPPORT | libc::EADDRNOTAVAIL)
                    ) =>
            {
                return;
            }
            Err(error) => panic!("IPv6 loopback bind failed: {error}"),
        };
        // Linux forces IPV6_V6ONLY=1 on non-wildcard IPv6 binds such as ::1.
        assert!(get_ipv6_v6only(loopback.as_raw_fd()).unwrap());

        // A wildcard [::] bind inherits the host net.ipv6.bindv6only default.
        if let Ok(wildcard) = TcpListener::bind("[::]:0") {
            let effective = get_ipv6_v6only(wildcard.as_raw_fd()).unwrap();
            if let Ok(raw) = std::fs::read_to_string("/proc/sys/net/ipv6/bindv6only")
                && let Ok(sysctl) = raw.trim().parse::<u8>()
            {
                assert_eq!(effective, sysctl != 0);
            }
        }
    }

    #[test]
    fn tcp_user_timeout_round_trips_and_validates_bounds() {
        let (client, _server) = loopback_pair();

        set_tcp_user_timeout(client.as_raw_fd(), Duration::from_secs(30)).unwrap();
        let observed = getsockopt_int(
            client.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_USER_TIMEOUT,
        )
        .unwrap();
        assert_eq!(observed, 30_000);

        let zero_err = set_tcp_user_timeout(client.as_raw_fd(), Duration::ZERO).unwrap_err();
        assert_eq!(zero_err.kind(), io::ErrorKind::InvalidInput);

        let sub_ms_err =
            set_tcp_user_timeout(client.as_raw_fd(), Duration::from_micros(500)).unwrap_err();
        assert_eq!(sub_ms_err.kind(), io::ErrorKind::InvalidInput);

        let overflow = Duration::from_millis(libc::c_int::MAX as u64 + 1);
        let overflow_err = set_tcp_user_timeout(client.as_raw_fd(), overflow).unwrap_err();
        assert_eq!(overflow_err.kind(), io::ErrorKind::InvalidInput);
    }
}
