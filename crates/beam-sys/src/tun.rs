//! Linux `/dev/net/tun` device opener.
//!
//! Opens a Layer 3 TUN interface (`IFF_TUN | IFF_NO_PI`) in non-blocking,
//! close-on-exec mode. All `unsafe` syscall boundaries live here.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

/// Maximum length of a Linux network interface name excluding the NUL byte.
pub const MAX_IFNAME_LEN: usize = libc::IFNAMSIZ - 1;

// Linux TUNSETIFF ioctl request code (`_IOW('T', 202, int)` = 0x400454ca).
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;

const MAX_EINTR_RETRIES: usize = 32;

/// Minimal `struct ifreq` layout needed for `TUNSETIFF`.
#[repr(C, align(8))]
struct IfReq {
    ifr_name: [libc::c_char; libc::IFNAMSIZ],
    ifr_flags: libc::c_short,
    _pad: [u8; 22],
}

const _: () = assert!(std::mem::size_of::<IfReq>() == std::mem::size_of::<libc::ifreq>());
const _: () = assert!(std::mem::align_of::<IfReq>() == std::mem::align_of::<libc::ifreq>());

/// An owned Linux TUN file descriptor (`IFF_TUN | IFF_NO_PI`).
pub struct LinuxTun {
    fd: OwnedFd,
    name: String,
}

impl LinuxTun {
    /// Opens `/dev/net/tun` and attaches to or creates the TUN interface `name`.
    ///
    /// Requires `CAP_NET_ADMIN` (or a pre-created persistent TUN owned by the
    /// process user).
    pub fn open(name: &str) -> io::Result<Self> {
        validate_ifname(name)?;

        let path = CString::new("/dev/net/tun")
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid tun device path"))?;

        // SAFETY: `path` is a valid NUL-terminated C string. `open` returns a
        // new owned file descriptor or -1 on error.
        let raw_fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if raw_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw_fd` was just returned by `open(2)` and is uniquely owned.
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        let mut req = IfReq {
            ifr_name: [0; libc::IFNAMSIZ],
            ifr_flags: IFF_TUN | IFF_NO_PI,
            _pad: [0; 22],
        };
        for (dst, &src) in req.ifr_name.iter_mut().zip(name.as_bytes()) {
            *dst = src as libc::c_char;
        }

        // SAFETY: `fd` is a valid `/dev/net/tun` descriptor and `req` is a
        // properly initialized `IfReq` with NUL-terminated `ifr_name` matching
        // Linux's `struct ifreq` layout for `TUNSETIFF`.
        let rc = unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF as _, &mut req) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }

        let actual_len = req
            .ifr_name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(MAX_IFNAME_LEN);
        let actual_bytes: Vec<u8> = req.ifr_name[..actual_len]
            .iter()
            .map(|&b| b as u8)
            .collect();
        let actual_name = String::from_utf8(actual_bytes).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "kernel returned non-UTF-8 TUN interface name",
            )
        })?;

        Ok(Self {
            fd,
            name: actual_name,
        })
    }

    /// Wraps a TUN descriptor that another layer created and detached.
    ///
    /// `raw_fd` is the descriptor Android's
    /// `ParcelFileDescriptor.detachFd()` returns. Ownership transfers to this
    /// [`LinuxTun`] at the call, so the caller must never use, duplicate, or
    /// close `raw_fd` again. Every error path closes it, so a failed start
    /// cannot leak the descriptor.
    ///
    /// The descriptor must already be attached to a TUN interface, because a
    /// detached `VpnService` fd cannot be re-configured with `TUNSETIFF`.
    pub fn from_detached_fd(raw_fd: RawFd, name: &str) -> io::Result<Self> {
        if raw_fd < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "detached TUN file descriptor must not be negative",
            ));
        }
        // SAFETY: `detachFd()` handed over the only owner of `raw_fd`, so this
        // call takes exclusive ownership. `OwnedFd` closes the descriptor on
        // every early return below, which keeps the transfer leak-free.
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        validate_ifname(name)?;
        crate::fd::set_nonblocking(fd.as_raw_fd())?;
        crate::fd::set_cloexec(fd.as_raw_fd())?;
        Ok(Self {
            fd,
            name: name.to_owned(),
        })
    }

    /// Returns the kernel-assigned interface name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Performs a non-blocking read of one IP packet from the TUN device,
    /// retrying bounded `EINTR` interruptions.
    pub fn read_packet(&self, buf: &mut [u8]) -> io::Result<usize> {
        for _ in 0..MAX_EINTR_RETRIES {
            // SAFETY: `buf` is a valid writable slice of length `buf.len()`, and
            // `self.fd` is a valid owned file descriptor.
            let n = unsafe {
                libc::read(
                    self.fd.as_raw_fd(),
                    buf.as_mut_ptr().cast::<libc::c_void>(),
                    buf.len(),
                )
            };
            if n >= 0 {
                return Ok(n as usize);
            }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "TUN read interrupted repeatedly",
        ))
    }

    /// Performs a non-blocking write of one IP packet to the TUN device,
    /// retrying bounded `EINTR` interruptions.
    pub fn write_packet(&self, buf: &[u8]) -> io::Result<usize> {
        for _ in 0..MAX_EINTR_RETRIES {
            // SAFETY: `buf` is a valid readable slice of length `buf.len()`, and
            // `self.fd` is a valid owned file descriptor.
            let n = unsafe {
                libc::write(
                    self.fd.as_raw_fd(),
                    buf.as_ptr().cast::<libc::c_void>(),
                    buf.len(),
                )
            };
            if n >= 0 {
                return Ok(n as usize);
            }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "TUN write interrupted repeatedly",
        ))
    }
}

impl AsRawFd for LinuxTun {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl AsFd for LinuxTun {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

/// Validates a Linux interface name (`1..=15` ASCII alphanumerics, `-`, or `_`).
pub fn validate_ifname(name: &str) -> io::Result<()> {
    if name.is_empty() || name.len() > MAX_IFNAME_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("TUN interface name must be 1..={MAX_IFNAME_LEN} bytes"),
        ));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TUN interface name may contain only ASCII letters, digits, '-' and '_'",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_ifname_accepts_valid_and_rejects_invalid_names() {
        assert!(validate_ifname("beamtun0").is_ok());
        assert!(validate_ifname("tun_1-a").is_ok());
        assert!(validate_ifname("").is_err());
        assert!(validate_ifname("0123456789abcdef").is_err()); // 16 bytes
        assert!(validate_ifname("tun/0").is_err());
        assert!(validate_ifname("tun 0").is_err());
    }

    mod detached_fd {
        use super::*;
        use std::io::Read;
        use std::os::fd::IntoRawFd;
        use std::os::unix::net::UnixStream;

        /// Returns a detached raw fd plus its live peer, like `detachFd()`.
        fn detached_socket() -> (RawFd, UnixStream) {
            let (stream, peer) = UnixStream::pair().expect("socketpair");
            peer.set_nonblocking(true).expect("nonblocking peer");
            (stream.into_raw_fd(), peer)
        }

        /// Observes closure via peer EOF instead of probing the raw fd number,
        /// avoiding flakes when another parallel test thread reuses the closed fd.
        fn peer_saw_eof(peer: &mut UnixStream) -> bool {
            let mut byte = [0u8; 1];
            matches!(peer.read(&mut byte), Ok(0))
        }

        fn get_flags(fd: RawFd, command: libc::c_int) -> libc::c_int {
            // SAFETY: `F_GETFL` and `F_GETFD` take no variadic argument and do
            // not dereference a user pointer. `fd` is a valid descriptor in
            // these tests.
            unsafe { libc::fcntl(fd, command) }
        }

        #[test]
        fn rejects_negative_fd() {
            let Err(error) = LinuxTun::from_detached_fd(-1, "tun0") else {
                panic!("a negative descriptor must be rejected");
            };
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }

        #[test]
        fn invalid_name_closes_the_detached_fd() {
            for name in ["", "0123456789abcdef", "tun\0", "tun/0"] {
                let (raw, mut peer) = detached_socket();
                let Err(error) = LinuxTun::from_detached_fd(raw, name) else {
                    panic!("an invalid interface name {name:?} must be rejected");
                };
                assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{name:?}");
                assert!(
                    peer_saw_eof(&mut peer),
                    "{name:?} must close the descriptor"
                );
            }
        }

        #[test]
        fn valid_detached_fd_is_nonblocking_cloexec_and_owned() {
            let (raw, mut peer) = detached_socket();
            // Clear both flags first, so the assertions prove that
            // `from_detached_fd` sets them instead of inheriting them.
            // SAFETY: `F_SETFD`/`F_SETFL` consume their `c_int` argument by
            // value and `raw` is a valid owned descriptor here.
            unsafe {
                assert!(libc::fcntl(raw, libc::F_SETFD, 0) >= 0);
                let flags = libc::fcntl(raw, libc::F_GETFL);
                assert!(flags >= 0);
                assert!(libc::fcntl(raw, libc::F_SETFL, flags & !libc::O_NONBLOCK) >= 0);
            }
            assert_eq!(get_flags(raw, libc::F_GETFL) & libc::O_NONBLOCK, 0);
            assert_eq!(get_flags(raw, libc::F_GETFD) & libc::FD_CLOEXEC, 0);

            let tun = LinuxTun::from_detached_fd(raw, "beamtun0").expect("valid detached fd");

            assert_eq!(tun.name(), "beamtun0");
            assert_ne!(get_flags(raw, libc::F_GETFL) & libc::O_NONBLOCK, 0);
            assert_ne!(get_flags(raw, libc::F_GETFD) & libc::FD_CLOEXEC, 0);

            drop(tun);
            assert!(
                peer_saw_eof(&mut peer),
                "dropping the TUN must close its descriptor"
            );
        }
    }
}
