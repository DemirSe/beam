//! Safe wrapper over `poll(2)`.

use std::fmt;
use std::io;
use std::os::fd::RawFd;
use std::ptr;
use std::time::Duration;

/// A set of `poll(2)` event flags.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct PollEvents(libc::c_short);

impl PollEvents {
    /// Data is available to read.
    pub const READ: Self = Self(libc::POLLIN);
    /// Space is available to write.
    pub const WRITE: Self = Self(libc::POLLOUT);
    /// An error condition occurred.
    pub const ERROR: Self = Self(libc::POLLERR);
    /// The peer closed its end of the stream.
    pub const HUP: Self = Self(libc::POLLHUP);
    /// No events.
    pub const EMPTY: Self = Self(0);

    /// Returns the raw event bits.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0 as u16
    }

    /// Returns `true` if every bit in `other` is also set in `self`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Returns `true` if no event bits are set.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl std::ops::BitOr for PollEvents {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for PollEvents {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// A single entry passed to [`poll`].
///
/// The type is layout-compatible with `libc::pollfd`.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct PollFd {
    inner: libc::pollfd,
}

impl PollFd {
    /// Creates an entry that watches `fd` for `events`.
    #[must_use]
    pub const fn new(fd: RawFd, events: PollEvents) -> Self {
        Self {
            inner: libc::pollfd {
                fd,
                events: events.0,
                revents: 0,
            },
        }
    }

    /// Creates an entry that [`poll`] ignores.
    #[must_use]
    pub const fn ignored() -> Self {
        Self::new(-1, PollEvents::EMPTY)
    }

    /// Returns the watched descriptor.
    #[must_use]
    pub const fn fd(&self) -> RawFd {
        self.inner.fd
    }

    /// Returns the requested event mask.
    #[must_use]
    pub const fn events(&self) -> PollEvents {
        PollEvents(self.inner.events)
    }

    /// Returns the events reported by the most recent [`poll`] call.
    #[must_use]
    pub const fn revents(&self) -> PollEvents {
        PollEvents(self.inner.revents)
    }

    /// Replaces the requested event mask.
    pub fn set_events(&mut self, events: PollEvents) {
        self.inner.events = events.0;
    }

    /// Clears the events reported by a previous [`poll`] call.
    pub fn clear_revents(&mut self) {
        self.inner.revents = 0;
    }
}

impl fmt::Debug for PollFd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PollFd")
            .field("fd", &self.fd())
            .field("events", &self.events())
            .field("revents", &self.revents())
            .finish()
    }
}

/// Longest finite timeout accepted by [`poll`].
///
/// `poll(2)` stores the timeout in a signed 32-bit millisecond count. Longer
/// durations are clamped to this value, not rejected, so a caller with a very
/// long deadline keeps waiting instead of failing and spinning.
pub const MAX_POLL_TIMEOUT: Duration = Duration::from_millis(libc::c_int::MAX as u64);

const MAX_POLL_MILLIS: u128 = libc::c_int::MAX as u128;

/// Waits until one of `fds` is ready or `timeout` expires.
///
/// `timeout` is rounded up to whole milliseconds and clamped to
/// [`MAX_POLL_TIMEOUT`]; a non-zero duration below one millisecond waits for
/// one millisecond instead of spinning. `None` blocks indefinitely.
///
/// Returns the number of entries with a non-zero `revents` field, or `0` on
/// timeout. `EINTR` is reported as [`io::ErrorKind::Interrupted`] so callers
/// can re-check their own deadlines.
pub fn poll(fds: &mut [PollFd], timeout: Option<Duration>) -> io::Result<usize> {
    let nfds = libc::nfds_t::try_from(fds.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "too many poll descriptors"))?;
    let timeout = timeout_millis(timeout);

    // `as_mut_ptr` is dangling for an empty slice, so pass null when there is
    // nothing to watch. `poll` accepts a null array when `nfds` is zero.
    let fds_ptr = if fds.is_empty() {
        ptr::null_mut()
    } else {
        fds.as_mut_ptr().cast::<libc::pollfd>()
    };

    // SAFETY: `PollFd` is `repr(transparent)` over `libc::pollfd`, so
    // `fds_ptr` points to `fds.len()` valid, writable `pollfd` values for the
    // duration of the call. The slice is exclusively borrowed and is not
    // accessed through another path while `poll` runs. The kernel only writes
    // the `revents` field of each entry. A null pointer is valid when `nfds`
    // is zero.
    let result = unsafe { libc::poll(fds_ptr, nfds, timeout) };

    if result < 0 {
        return Err(map_poll_error(io::Error::last_os_error()));
    }

    Ok(result as usize)
}

/// Classifies a `poll(2)` OS error, mapping `EINTR` to `ErrorKind::Interrupted`
/// so relay loops can retry while re-checking their deadlines.
fn map_poll_error(error: io::Error) -> io::Error {
    if error.raw_os_error() == Some(libc::EINTR) {
        io::Error::from(io::ErrorKind::Interrupted)
    } else {
        error
    }
}

fn timeout_millis(timeout: Option<Duration>) -> libc::c_int {
    let Some(timeout) = timeout else {
        return -1;
    };

    let millis = timeout.as_nanos().div_ceil(1_000_000).min(MAX_POLL_MILLIS);
    libc::c_int::try_from(millis).unwrap_or(libc::c_int::MAX)
}

#[cfg(test)]
mod tests {
    use super::{MAX_POLL_TIMEOUT, PollEvents, PollFd, map_poll_error, poll, timeout_millis};
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    fn pair() -> (UnixStream, UnixStream) {
        UnixStream::pair().unwrap()
    }

    #[test]
    fn timeout_maps_to_whole_milliseconds_with_a_documented_cap() {
        assert_eq!(timeout_millis(None), -1);
        assert_eq!(timeout_millis(Some(Duration::ZERO)), 0);
        assert_eq!(timeout_millis(Some(Duration::from_nanos(1))), 1);
        assert_eq!(timeout_millis(Some(Duration::from_nanos(1_000_001))), 2);
        assert_eq!(timeout_millis(Some(Duration::from_millis(1_999))), 1_999);
        assert_eq!(timeout_millis(Some(MAX_POLL_TIMEOUT)), libc::c_int::MAX);
        assert_eq!(
            timeout_millis(Some(MAX_POLL_TIMEOUT + Duration::from_nanos(1))),
            libc::c_int::MAX
        );
        assert_eq!(
            timeout_millis(Some(Duration::from_secs(u64::MAX))),
            libc::c_int::MAX
        );
    }

    #[test]
    fn read_ready_is_reported() {
        let (reader, mut writer) = pair();
        writer.write_all(b"x").unwrap();

        let mut fds = [PollFd::new(reader.as_raw_fd(), PollEvents::READ)];
        let ready = poll(&mut fds, Some(Duration::ZERO)).unwrap();

        assert_eq!(ready, 1);
        assert!(fds[0].revents().contains(PollEvents::READ));
    }

    #[test]
    fn write_ready_is_reported() {
        let (writer, _reader) = pair();

        let mut fds = [PollFd::new(writer.as_raw_fd(), PollEvents::WRITE)];
        let ready = poll(&mut fds, Some(Duration::ZERO)).unwrap();

        assert_eq!(ready, 1);
        assert!(fds[0].revents().contains(PollEvents::WRITE));
    }

    #[test]
    fn zero_timeout_reports_no_events() {
        let (reader, _writer) = pair();

        let mut fds = [PollFd::new(reader.as_raw_fd(), PollEvents::READ)];
        let ready = poll(&mut fds, Some(Duration::ZERO)).unwrap();

        assert_eq!(ready, 0);
        assert!(fds[0].revents().is_empty());
    }

    #[test]
    fn timeout_is_bounded() {
        let (reader, _writer) = pair();

        let mut fds = [PollFd::new(reader.as_raw_fd(), PollEvents::READ)];
        let started = Instant::now();
        let ready = poll(&mut fds, Some(Duration::from_millis(20))).unwrap();
        let elapsed = started.elapsed();

        assert_eq!(ready, 0);
        assert!(elapsed >= Duration::from_millis(10), "returned too early");
        assert!(elapsed < Duration::from_secs(2), "returned too late");
    }

    #[test]
    fn peer_close_reports_hup_or_read() {
        let (reader, writer) = pair();
        drop(writer);

        let mut fds = [PollFd::new(reader.as_raw_fd(), PollEvents::READ)];
        let ready = poll(&mut fds, Some(Duration::from_secs(1))).unwrap();

        assert_eq!(ready, 1);
        let revents = fds[0].revents();
        assert!(
            revents.contains(PollEvents::HUP) || revents.contains(PollEvents::READ),
            "unexpected revents: {revents:?}"
        );
    }

    #[test]
    fn negative_fd_is_ignored() {
        let mut fds = [PollFd::ignored()];

        let ready = poll(&mut fds, Some(Duration::ZERO)).unwrap();

        assert_eq!(ready, 0);
        assert!(fds[0].revents().is_empty());
    }

    #[test]
    fn empty_slice_with_zero_timeout_returns_immediately() {
        assert_eq!(poll(&mut [], Some(Duration::ZERO)).unwrap(), 0);
    }

    #[test]
    fn invalid_fd_reports_unknown_bits() {
        let mut fds = [PollFd::new(libc::c_int::MAX, PollEvents::READ)];

        let ready = poll(&mut fds, Some(Duration::ZERO)).unwrap();

        assert_eq!(ready, 1);
        let known = PollEvents::READ | PollEvents::WRITE | PollEvents::ERROR | PollEvents::HUP;
        assert_ne!(fds[0].revents().bits() & !known.bits(), 0);
    }

    #[test]
    fn events_combine_and_contain() {
        let both = PollEvents::READ | PollEvents::HUP;

        assert!(both.contains(PollEvents::READ));
        assert!(both.contains(PollEvents::HUP));
        assert!(!both.contains(PollEvents::WRITE));
        assert_eq!(
            both.bits(),
            PollEvents::READ.bits() | PollEvents::HUP.bits()
        );
        assert!(PollEvents::EMPTY.is_empty());
    }

    #[test]
    fn poll_fd_matches_libc_layout() {
        assert_eq!(
            std::mem::size_of::<PollFd>(),
            std::mem::size_of::<libc::pollfd>()
        );
        assert_eq!(
            std::mem::align_of::<PollFd>(),
            std::mem::align_of::<libc::pollfd>()
        );
    }

    #[test]
    fn shutdown_write_preserves_the_read_half() {
        let (mut client, mut server) = pair();

        crate::shutdown_write(client.as_raw_fd()).unwrap();

        let mut byte = [0_u8; 1];
        assert_eq!(server.read(&mut byte).unwrap(), 0);

        server.write_all(b"reply").unwrap();
        let mut reply = [0_u8; 5];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"reply");
    }

    #[test]
    fn set_pipe_size_rejects_invalid_values() {
        let (_read_end, write_end) = crate::pipe().unwrap();

        let zero = crate::set_pipe_size(write_end.as_raw_fd(), 0).unwrap_err();
        assert_eq!(zero.kind(), std::io::ErrorKind::InvalidInput);

        let oversized = crate::set_pipe_size(write_end.as_raw_fd(), usize::MAX).unwrap_err();
        assert_eq!(oversized.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn map_poll_error_classifies_eintr_as_interrupted() {
        let interrupted = map_poll_error(std::io::Error::from_raw_os_error(libc::EINTR));
        assert_eq!(interrupted.kind(), std::io::ErrorKind::Interrupted);

        let nomem = map_poll_error(std::io::Error::from_raw_os_error(libc::ENOMEM));
        assert_eq!(nomem.raw_os_error(), Some(libc::ENOMEM));
        assert_ne!(nomem.kind(), std::io::ErrorKind::Interrupted);
    }

    #[test]
    fn poll_reports_eintr_as_interrupted() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Mutex};

        static SIGNAL_LOCK: Mutex<()> = Mutex::new(());
        extern "C" fn noop_handler(_sig: libc::c_int) {}

        struct SigactionGuard {
            previous: libc::sigaction,
        }

        impl Drop for SigactionGuard {
            fn drop(&mut self) {
                // SAFETY: `self.previous` was populated by `sigaction(2)` and
                // restoring the previous `SIGUSR1` handler uses valid pointers.
                unsafe {
                    libc::sigaction(
                        libc::SIGUSR1,
                        &raw const self.previous,
                        std::ptr::null_mut(),
                    );
                }
            }
        }

        let _lock = SIGNAL_LOCK.lock().unwrap();
        let mut previous = std::mem::MaybeUninit::<libc::sigaction>::zeroed();
        // SAFETY: `sigaction` structs are plain-old-data C structs initialized
        // with `sigemptyset` and a valid async-signal-safe no-op handler with
        // no `SA_RESTART`, so `poll(2)` returns `EINTR` when `SIGUSR1` arrives.
        let _guard = unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            libc::sigemptyset(&raw mut action.sa_mask);
            action.sa_flags = 0;
            action.sa_sigaction = noop_handler as *const () as usize;
            assert_eq!(
                libc::sigaction(libc::SIGUSR1, &raw const action, previous.as_mut_ptr()),
                0,
                "sigaction(SIGUSR1) failed: {}",
                std::io::Error::last_os_error()
            );
            SigactionGuard {
                previous: previous.assume_init(),
            }
        };

        let (read_end, _write_end) = crate::pipe().unwrap();
        // SAFETY: `pthread_self` takes no arguments and returns the calling
        // thread's handle, which remains valid until this test joins `sender`.
        let target = unsafe { libc::pthread_self() };
        let done = Arc::new(AtomicBool::new(false));
        let done_sender = Arc::clone(&done);
        let sender = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_millis(1500);
            while !done_sender.load(Ordering::Acquire) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
                if done_sender.load(Ordering::Acquire) {
                    break;
                }
                // SAFETY: `target` is the live parent test thread waiting to
                // join this thread; `SIGUSR1` has our no-op handler installed.
                unsafe {
                    libc::pthread_kill(target, libc::SIGUSR1);
                }
            }
        });

        let mut fds = [PollFd::new(read_end.as_raw_fd(), PollEvents::READ)];
        let outcome = poll(&mut fds, Some(Duration::from_secs(2)));
        done.store(true, Ordering::Release);
        sender.join().unwrap();

        let error = outcome.expect_err("SIGUSR1 without SA_RESTART must interrupt poll");
        assert_eq!(error.kind(), std::io::ErrorKind::Interrupted);
    }
}
