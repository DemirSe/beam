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

/// Minimal `struct ifreq` layout needed for `TUNSETIFF`.
#[repr(C)]
struct IfReq {
    ifr_name: [libc::c_char; libc::IFNAMSIZ],
    ifr_flags: libc::c_short,
    _pad: [u8; 22],
}

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

    /// Returns the kernel-assigned interface name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Performs a non-blocking read of one IP packet from the TUN device.
    pub fn read_packet(&self, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: `buf` is a valid writable slice of length `buf.len()`, and
        // `self.fd` is a valid owned file descriptor.
        let n = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
            )
        };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    /// Performs a non-blocking write of one IP packet to the TUN device.
    pub fn write_packet(&self, buf: &[u8]) -> io::Result<usize> {
        // SAFETY: `buf` is a valid readable slice of length `buf.len()`, and
        // `self.fd` is a valid owned file descriptor.
        let n = unsafe {
            libc::write(
                self.fd.as_raw_fd(),
                buf.as_ptr().cast::<libc::c_void>(),
                buf.len(),
            )
        };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
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
}
