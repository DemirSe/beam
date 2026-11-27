//! Windows socket option helpers.
//!
//! WinSock reports failures through `WSAGetLastError` instead of `errno`, so
//! every helper here converts the WinSock error code into an [`io::Error`].
//! Option values are passed as the four initialized bytes WinSock copies
//! during the call; no buffer is retained.

use std::io;
use std::mem::size_of;
use std::os::windows::io::RawSocket;
use std::time::Duration;

use windows_sys::Win32::Networking::WinSock::{
    IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPPROTO_TCP, IPV6_UNICAST_IF, SIO_KEEPALIVE_VALS,
    SO_KEEPALIVE, SOCKET, SOCKET_ERROR, SOL_SOCKET, TCP_KEEPCNT, TCP_KEEPIDLE, TCP_KEEPINTVL,
    TCP_NODELAY, WSAENOPROTOOPT, WSAGetLastError, WSAIoctl, setsockopt, tcp_keepalive,
};

/// Maximum `TCP_KEEPCNT` value accepted by Windows (`1..=255`).
const MAX_TCP_KEEPCNT: u32 = 255;

/// Enables `TCP_NODELAY` on `sock`.
pub fn set_tcp_nodelay(sock: RawSocket) -> io::Result<()> {
    setsockopt_uint(sock, IPPROTO_TCP, TCP_NODELAY, 1)
}

/// Enables TCP keepalive on `sock` with the given idle time and probe interval.
///
/// Both durations are whole seconds. Windows 10 1709 and later accept
/// `TCP_KEEPIDLE` and `TCP_KEEPINTVL`; an older build reports
/// `WSAENOPROTOOPT` for them, so the call falls back to the
/// `SIO_KEEPALIVE_VALS` ioctl. Either path reports its own failure and leaves
/// keepalive disabled when it returns an error.
pub fn set_tcp_keepalive(sock: RawSocket, idle: Duration, interval: Duration) -> io::Result<()> {
    let idle = duration_secs(idle, "keepalive idle")?;
    let interval = duration_secs(interval, "keepalive interval")?;

    match set_keepalive_seconds(sock, idle, interval) {
        Err(error) if error.raw_os_error() == Some(WSAENOPROTOOPT) => {
            set_keepalive_ioctl(sock, idle, interval)
        }
        result => result,
    }
}

/// Sets `TCP_KEEPCNT`, the number of unanswered keepalive probes after which
/// Windows drops the connection.
///
/// Windows rejects values outside `1..=255`; keepalive stays disabled until
/// [`set_tcp_keepalive`] enables `SO_KEEPALIVE`.
pub fn set_tcp_keepcnt(sock: RawSocket, count: u32) -> io::Result<()> {
    if count == 0 || count > MAX_TCP_KEEPCNT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("TCP keepalive count must be in 1..={MAX_TCP_KEEPCNT}"),
        ));
    }
    setsockopt_uint(sock, IPPROTO_TCP, TCP_KEEPCNT, count)
}

/// Rejects a zero maximum segment size and reports that `TCP_MAXSEG` is
/// unavailable.
///
/// Windows has no socket option that sets the advertised MSS, so the tunnel
/// pays the segment size through the WinTun adapter MTU instead.
pub fn set_tcp_maxseg(_sock: RawSocket, mss: u16) -> io::Result<()> {
    if mss == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TCP maximum segment size must be positive",
        ));
    }
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "TCP_MAXSEG is not supported on Windows",
    ))
}

/// Rejects a zero timeout and reports that `TCP_USER_TIMEOUT` is unavailable.
///
/// Windows has no equivalent socket option, so the relay relies on keepalive
/// probes and the relay's own read and write deadlines instead.
pub fn set_tcp_user_timeout(_sock: RawSocket, timeout: Duration) -> io::Result<()> {
    if timeout.as_millis() == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TCP user timeout must be at least one millisecond",
        ));
    }
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "TCP_USER_TIMEOUT is not supported on Windows",
    ))
}

/// Pins an IPv4 socket to the interface with index `if_index`.
///
/// `IP_UNICAST_IF` alone takes its index in network byte order; `IPV6_UNICAST_IF`
/// takes host byte order.
pub fn bind_socket_to_interface_v4(sock: RawSocket, if_index: u32) -> io::Result<()> {
    if if_index == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface index must be positive",
        ));
    }
    setsockopt_word(
        sock,
        IPPROTO_IP,
        IP_UNICAST_IF,
        v4_unicast_if_bytes(if_index),
    )
}

/// Pins an IPv6 socket to the interface with index `if_index`.
pub fn bind_socket_to_interface_v6(sock: RawSocket, if_index: u32) -> io::Result<()> {
    if if_index == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface index must be positive",
        ));
    }
    setsockopt_word(
        sock,
        IPPROTO_IPV6,
        IPV6_UNICAST_IF,
        v6_unicast_if_bytes(if_index),
    )
}

/// Encodes `if_index` for `IP_UNICAST_IF`, which expects network byte order.
fn v4_unicast_if_bytes(if_index: u32) -> [u8; 4] {
    if_index.to_be_bytes()
}

/// Encodes `if_index` for `IPV6_UNICAST_IF`, which expects host byte order.
fn v6_unicast_if_bytes(if_index: u32) -> [u8; 4] {
    if_index.to_ne_bytes()
}

/// Applies a host-byte-order 32-bit socket option.
fn setsockopt_uint(sock: RawSocket, level: i32, name: i32, value: u32) -> io::Result<()> {
    setsockopt_word(sock, level, name, value.to_ne_bytes())
}

/// Applies a socket option whose value is the given four bytes.
fn setsockopt_word(sock: RawSocket, level: i32, name: i32, value: [u8; 4]) -> io::Result<()> {
    // SAFETY: `value` is a live four-byte array, so the pointer is valid for
    // reads and the declared length matches it exactly. `setsockopt` copies at
    // most those four bytes into WinSock and retains no pointer; the socket
    // handle is supplied by the caller and validated by the kernel.
    let result = unsafe { setsockopt(native_socket(sock), level, name, value.as_ptr(), 4) };
    if result == SOCKET_ERROR {
        Err(last_socket_error())
    } else {
        Ok(())
    }
}

/// Applies `TCP_KEEPIDLE`, `TCP_KEEPINTVL` and `SO_KEEPALIVE` in that order.
fn set_keepalive_seconds(sock: RawSocket, idle: u32, interval: u32) -> io::Result<()> {
    setsockopt_uint(sock, IPPROTO_TCP, TCP_KEEPIDLE, idle)?;
    setsockopt_uint(sock, IPPROTO_TCP, TCP_KEEPINTVL, interval)?;
    setsockopt_uint(sock, SOL_SOCKET, SO_KEEPALIVE, 1)
}

/// Applies `SIO_KEEPALIVE_VALS`, the pre-1709 way to set keepalive timing.
fn set_keepalive_ioctl(sock: RawSocket, idle: u32, interval: u32) -> io::Result<()> {
    let keepalivetime = idle.checked_mul(1_000).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "keepalive idle milliseconds overflow u32",
        )
    })?;
    let keepaliveinterval = interval.checked_mul(1_000).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "keepalive interval milliseconds overflow u32",
        )
    })?;
    let request = tcp_keepalive {
        onoff: 1,
        keepalivetime,
        keepaliveinterval,
    };
    let input_len = size_of::<tcp_keepalive>() as u32;
    let mut returned = 0_u32;
    // SAFETY: `request` is a fully initialized `tcp_keepalive` local and
    // `input_len` states exactly its size, so WinSock reads only initialized
    // bytes. `returned` is a live `u32` for the byte-count output; the output
    // buffer is null with a zero length because `SIO_KEEPALIVE_VALS` produces
    // no data. `OVERLAPPED` and the completion routine are null so WinSock
    // executes synchronously and retains neither pointer.
    let result = unsafe {
        WSAIoctl(
            native_socket(sock),
            SIO_KEEPALIVE_VALS,
            (&raw const request).cast(),
            input_len,
            std::ptr::null_mut(),
            0,
            &raw mut returned,
            std::ptr::null_mut(),
            None,
        )
    };
    if result == SOCKET_ERROR {
        Err(last_socket_error())
    } else {
        Ok(())
    }
}

/// Narrows the standard `RawSocket` alias to the WinSock handle type.
///
/// `RawSocket` is `u64` on every target while `SOCKET` is `usize`. A WinSock
/// handle occupies at most 32 bits, so narrowing never loses a handle bit, even
/// in a 32-bit build.
fn native_socket(sock: RawSocket) -> SOCKET {
    sock as SOCKET
}

/// Reads the thread-local WinSock error code.
fn last_socket_error() -> io::Error {
    // SAFETY: `WSAGetLastError` takes no arguments, dereferences no pointer,
    // and returns the calling thread's WinSock error code.
    let code = unsafe { WSAGetLastError() };
    io::Error::from_raw_os_error(code)
}

/// Converts a duration into whole seconds that fit a 32-bit option value.
fn duration_secs(value: Duration, name: &str) -> io::Result<u32> {
    let seconds = value.as_secs();
    if seconds == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} duration must be at least one second"),
        ));
    }
    u32::try_from(seconds)
        .ok()
        .filter(|&seconds| i32::try_from(seconds).is_ok())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{name} duration does not fit in a 32-bit option value"),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::{
        bind_socket_to_interface_v4, bind_socket_to_interface_v6, duration_secs, set_tcp_keepalive,
        set_tcp_keepcnt, set_tcp_maxseg, set_tcp_nodelay, set_tcp_user_timeout,
        v4_unicast_if_bytes, v6_unicast_if_bytes,
    };
    use std::io;
    use std::net::{Ipv4Addr, TcpListener, TcpStream};
    use std::os::windows::io::AsRawSocket;
    use std::time::Duration;

    #[test]
    fn unicast_if_encoders_use_the_documented_byte_order() {
        // `IP_UNICAST_IF` wants network byte order, so index 1 is 0.0.0.1.
        assert_eq!(v4_unicast_if_bytes(1), [0, 0, 0, 1]);
        assert_eq!(v4_unicast_if_bytes(0x0102_0304), [1, 2, 3, 4]);
        // `IPV6_UNICAST_IF` wants host byte order, so the bytes match the value.
        assert_eq!(
            v6_unicast_if_bytes(0x0102_0304),
            0x0102_0304_u32.to_ne_bytes()
        );
        #[cfg(target_endian = "little")]
        assert_eq!(v6_unicast_if_bytes(1), [1, 0, 0, 0]);
    }

    #[test]
    fn interface_binding_rejects_a_zero_index() {
        // Socket handle 0 is never valid, so the index check has to run first.
        assert_eq!(
            bind_socket_to_interface_v4(0, 0).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            bind_socket_to_interface_v6(0, 0).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn duration_secs_requires_positive_whole_seconds_that_fit() {
        assert_eq!(duration_secs(Duration::from_secs(1), "idle").unwrap(), 1);
        assert_eq!(
            duration_secs(Duration::from_secs(3600), "idle").unwrap(),
            3600
        );
        assert_eq!(
            duration_secs(Duration::ZERO, "idle").unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            duration_secs(Duration::from_millis(999), "idle")
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        let too_large = Duration::from_secs(u64::try_from(i32::MAX).unwrap() + 1);
        assert_eq!(
            duration_secs(too_large, "idle").unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn unsupported_options_report_the_documented_errors() {
        assert_eq!(
            set_tcp_maxseg(0, 0).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        let error = set_tcp_maxseg(0, 1400).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(error.to_string().contains("TCP_MAXSEG"));

        assert_eq!(
            set_tcp_user_timeout(0, Duration::ZERO).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        let error = set_tcp_user_timeout(0, Duration::from_millis(1)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(error.to_string().contains("TCP_USER_TIMEOUT"));
    }

    #[test]
    fn keepalive_timing_rejects_sub_second_durations_before_any_syscall() {
        assert_eq!(
            set_tcp_keepalive(0, Duration::ZERO, Duration::from_secs(1))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            set_tcp_keepalive(0, Duration::from_secs(1), Duration::from_millis(500))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn keepcnt_rejects_zero_and_overflow_before_any_syscall() {
        assert_eq!(
            set_tcp_keepcnt(0, 0).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            set_tcp_keepcnt(0, 256).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            set_tcp_keepcnt(0, u32::try_from(i32::MAX).unwrap() + 1)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn tcp_options_apply_to_a_loopback_stream() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let sock = client.as_raw_socket();

        set_tcp_nodelay(sock).unwrap();
        set_tcp_keepalive(sock, Duration::from_secs(30), Duration::from_secs(5)).unwrap();
        set_tcp_keepcnt(sock, 5).unwrap();
    }
}
