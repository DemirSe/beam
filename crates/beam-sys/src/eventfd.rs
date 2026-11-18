//! A safe, nonblocking `eventfd(2)` wrapper.
//!
//! The relay uses one descriptor per shared activity clock to wake every
//! direction blocked in `poll(2)` when the opposite direction stops. The
//! descriptor is level-triggered and deliberately left readable: after the
//! stop flag is observed, both waiters return without polling again.

use std::fmt;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// Maximum number of nonblocking writes in one [`EventFd::notify`] call.
///
/// The relay's cancellation poll is capped at 250 ms, so a few EINTR retries
/// are enough. After the bound, `Interrupted` is returned and that cap still
/// bounds a missed wakeup.
const MAX_NOTIFY_ATTEMPTS: usize = 4;

/// Repeats a nonblocking write while it reports interruption.
///
/// `Ok(true)` means the wakeup succeeded: the counter was incremented or was
/// already readable. `Ok(false)` means the write was interrupted.
fn notify_with_attempts(mut attempt: impl FnMut() -> io::Result<bool>) -> io::Result<()> {
    for _ in 0..MAX_NOTIFY_ATTEMPTS {
        if attempt()? {
            return Ok(());
        }
    }
    Err(io::Error::new(
        io::ErrorKind::Interrupted,
        "eventfd write was interrupted too often",
    ))
}

/// An owned, close-on-exec, nonblocking eventfd descriptor.
pub struct EventFd {
    fd: OwnedFd,
}

impl EventFd {
    /// Creates an eventfd with an initial counter of zero.
    pub fn new() -> io::Result<Self> {
        // SAFETY: `eventfd` creates a new descriptor owned by the caller. The
        // flags are valid and no user pointer is passed. A failure returns -1
        // and does not produce a descriptor to close.
        let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` was just created by `eventfd` and is uniquely owned by
        // this call, so transferring it into `OwnedFd` is valid.
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }

    /// Increments the event counter, waking every poller.
    ///
    /// A counter overflow (`EAGAIN`) means the descriptor is already readable,
    /// so the wakeup goal is satisfied and the error is treated as success.
    /// Interrupted writes are retried up to four times; further interruption
    /// is returned as [`io::ErrorKind::Interrupted`].
    pub fn notify(&self) -> io::Result<()> {
        let value = 1_u64;
        let length = std::mem::size_of::<u64>();
        notify_with_attempts(|| {
            // SAFETY: `value` is a live `u64` and `length` is exactly its size.
            // `write` reads at most that many bytes and does not retain the
            // pointer. The descriptor is owned by `self` and remains open for
            // the duration of the call.
            let written = unsafe {
                libc::write(
                    self.fd.as_raw_fd(),
                    (&raw const value).cast::<libc::c_void>(),
                    length,
                )
            };
            if written == length as isize {
                return Ok(true);
            }
            if written < 0 {
                let error = io::Error::last_os_error();
                // A signal may interrupt the write before the counter is
                // incremented. The retry helper bounds these attempts.
                if error.kind() == io::ErrorKind::Interrupted {
                    return Ok(false);
                }
                // Counter overflow means the descriptor is already readable,
                // so the wakeup goal is satisfied.
                if error.kind() == io::ErrorKind::WouldBlock {
                    return Ok(true);
                }
                return Err(error);
            }
            Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "eventfd write wrote a partial value",
            ))
        })
    }
}

impl AsRawFd for EventFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl fmt::Debug for EventFd {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EventFd")
            .field("fd", &self.fd.as_raw_fd())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{EventFd, MAX_NOTIFY_ATTEMPTS, notify_with_attempts};
    use crate::poll::{PollEvents, PollFd, poll};
    use std::io;
    use std::os::fd::AsRawFd;
    use std::time::{Duration, Instant};

    #[test]
    fn notify_makes_the_descriptor_readable() {
        let event = EventFd::new().unwrap();
        let mut fds = [PollFd::new(event.as_raw_fd(), PollEvents::READ)];

        assert_eq!(poll(&mut fds, Some(Duration::ZERO)).unwrap(), 0);
        event.notify().unwrap();
        assert_eq!(poll(&mut fds, Some(Duration::ZERO)).unwrap(), 1);
        assert!(fds[0].revents().contains(PollEvents::READ));

        // The descriptor stays readable, so a second waiter also observes the
        // stop without consuming the counter.
        let mut second = [PollFd::new(event.as_raw_fd(), PollEvents::READ)];
        assert_eq!(poll(&mut second, Some(Duration::ZERO)).unwrap(), 1);
    }

    #[test]
    fn notify_retries_interrupted_writes() {
        let mut attempts = 0;

        notify_with_attempts(|| {
            attempts += 1;
            Ok(attempts == 2)
        })
        .unwrap();
        assert_eq!(attempts, 2);
    }

    #[test]
    fn notify_returns_after_bounded_interrupted_writes() {
        let mut attempts = 0;

        let error = notify_with_attempts(|| {
            attempts += 1;
            Ok(false)
        })
        .unwrap_err();
        assert_eq!(attempts, MAX_NOTIFY_ATTEMPTS);
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    }

    #[test]
    fn notify_reports_terminal_errors() {
        let error =
            notify_with_attempts(|| Err(io::Error::from(io::ErrorKind::BrokenPipe))).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn notify_wakes_a_blocked_poll() {
        let event = EventFd::new().unwrap();
        let fd = event.as_raw_fd();
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut fds = [PollFd::new(fd, PollEvents::READ)];
            let result = poll(&mut fds, Some(Duration::from_secs(5)));
            let _ = sender.send(result);
        });

        std::thread::sleep(Duration::from_millis(50));
        let started = Instant::now();
        event.notify().unwrap();
        let result = receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("blocked poll did not wake");
        assert_eq!(result.unwrap(), 1);
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "eventfd wake took {:?}",
            started.elapsed()
        );
    }
}
