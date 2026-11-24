//! Linux `AF_NETLINK` (`NETLINK_ROUTE`) passive route/link change watcher.
//!
//! Subscribes to kernel IPv4/IPv6 route and link multicast groups so
//! `beam-client` reacts immediately to Wi-Fi switches, gateway changes, and
//! link flaps with zero idle polling or subprocess forks.

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

const MAX_DRAIN_MESSAGES: usize = 64;
const DRAIN_BUF_BYTES: usize = 8192;

/// Non-blocking Linux `NETLINK_ROUTE` socket subscribed to IPv4/IPv6 route and
/// link multicast notifications.
pub struct NetlinkRouteWatcher {
    fd: OwnedFd,
}

impl NetlinkRouteWatcher {
    /// Opens and binds a non-blocking, close-on-exec `NETLINK_ROUTE` socket
    /// listening for `RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE | RTMGRP_LINK`.
    pub fn open() -> io::Result<Self> {
        // SAFETY: `socket(2)` takes integer arguments only and returns a new
        // owned file descriptor or -1 on error.
        let raw_fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if raw_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw_fd` was just returned by `socket(2)` and is uniquely owned.
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        let groups = (libc::RTMGRP_IPV4_ROUTE | libc::RTMGRP_IPV6_ROUTE | libc::RTMGRP_LINK) as u32;
        // SAFETY: `sockaddr_nl` is a plain-old-data C struct; zero-initializing
        // it produces a valid struct before setting the required fields.
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        addr.nl_pid = 0; // Let the kernel assign a unique port ID.
        addr.nl_groups = groups;

        // SAFETY: `fd` is a valid `AF_NETLINK` socket and `addr` is a properly
        // initialized `sockaddr_nl` whose exact byte size is passed to `bind`.
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&raw const addr).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self { fd })
    }

    /// Drains all currently queued netlink notifications without blocking.
    ///
    /// Returns `Ok(true)` if at least one notification was received (or if the
    /// kernel reported `ENOBUFS`, meaning events occurred and the caller should
    /// reconcile), or `Ok(false)` if no events were pending.
    pub fn drain_events(&self) -> io::Result<bool> {
        let mut buf = [0u8; DRAIN_BUF_BYTES];
        let mut saw_event = false;

        for _ in 0..MAX_DRAIN_MESSAGES {
            // SAFETY: `buf` is a valid writable buffer of length `buf.len()`,
            // and `self.fd` is a valid owned non-blocking netlink descriptor.
            let n = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    buf.as_mut_ptr().cast::<libc::c_void>(),
                    buf.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if n > 0 {
                saw_event = true;
                continue;
            }
            if n == 0 {
                break;
            }
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::EAGAIN) => break,
                // Kernel dropped netlink messages due to burst; treat as an
                // event so the caller reconciles routing state.
                Some(libc::ENOBUFS) => {
                    saw_event = true;
                    break;
                }
                _ => return Err(err),
            }
        }

        Ok(saw_event)
    }
}

impl AsRawFd for NetlinkRouteWatcher {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl AsFd for NetlinkRouteWatcher {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netlink_route_watcher_opens_and_drains_when_idle() {
        let watcher = NetlinkRouteWatcher::open().expect("open netlink route watcher");
        assert!(watcher.as_raw_fd() >= 0);
        // Immediately after open with no route changes, drain should succeed
        // without blocking (returning false or true if a concurrent event fired).
        let _ = watcher.drain_events().expect("drain netlink events");
    }
}
