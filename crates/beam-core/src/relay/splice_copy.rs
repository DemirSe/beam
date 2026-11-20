use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use beam_sys::{EventFd, PollEvents, PollFd, SpliceFlags, pipe, poll, splice};

/// Avoid one warning per relay if the kernel refuses the pipe-size request.
static PIPE_SIZE_WARNED: AtomicBool = AtomicBool::new(false);

fn warn_pipe_size_once(error: &io::Error, pipe_size: usize, message: &'static str) {
    if !PIPE_SIZE_WARNED.swap(true, Ordering::Relaxed) {
        tracing::warn!(%error, pipe_size, "{message}");
    } else {
        tracing::debug!(%error, pipe_size, "{message}");
    }
}

/// Default kernel pipe capacity used for each direction.
pub const DEFAULT_PIPE_SIZE: usize = 512 * 1024;

/// Smallest accepted pipe size.
pub const MIN_PIPE_SIZE: usize = 4096;

/// Largest accepted pipe size.
///
/// The architecture document starts the relay at 512 KiB. A larger value needs
/// a new measurement, so the accepted range stays deliberately small.
pub const MAX_PIPE_SIZE: usize = 1024 * 1024;

/// Pages reserved for other pipes owned by the same uid.
const RESERVE_PAGES: u64 = 1024;

/// Selects the largest power-of-two pipe size that keeps every splice permit
/// under the per-uid pipe-page soft limit.
///
/// Each permitted splice direction owns one pipe, and a fully spliced
/// connection needs two permits. A fixed reserve of 1024 pages covers other
/// pipes owned by the same uid (the Tokio signal self-pipe and short-lived
/// pipes). When the kernel refuses growth, a fresh pipe is clamped to its
/// 8 KiB allocation-time default, not 64 KiB, so staying below the limit is
/// the only way to avoid an 8x-64x splice-syscall cliff.
#[must_use]
pub fn pipe_size_for_budget(soft_pages: u64, splice_tasks: usize, page_size: u64) -> usize {
    if soft_pages == 0 {
        return MIN_PIPE_SIZE;
    }
    if splice_tasks == 0 {
        return DEFAULT_PIPE_SIZE;
    }
    let page = page_size.max(1);
    let budget_pages = soft_pages.saturating_sub(RESERVE_PAGES);
    let per_pipe = budget_pages.saturating_mul(page) / splice_tasks as u64;
    let capped = per_pipe.min(MAX_PIPE_SIZE as u64);
    if capped < MIN_PIPE_SIZE as u64 {
        return MIN_PIPE_SIZE;
    }
    let mut size = 1_u64;
    while size * 2 <= capped {
        size *= 2;
    }
    size as usize
}

/// Maximum bytes moved by one fill or drain phase in one loop iteration.
/// Bounds the work before the relay checks cancellation and timeouts again.
const WORK_PER_ROUND: usize = 1024 * 1024;

/// Bytes after which a slow bulk direction starts batching reads.
const BATCH_THRESHOLD: u64 = 256 * 1024;

/// Directions below this measured rate start batching.
const BATCH_RATE_LIMIT: f64 = 500.0 * 1024.0 * 1024.0;

/// Paced streams below this rate must not pay the batching sleep.
///
/// Video calls and games send small datagrams every few milliseconds. Waiting
/// 500 µs to coalesce them adds latency without creating a useful burst.
const BATCH_MIN_RATE: f64 = 2.0 * 1024.0 * 1024.0;

/// A batching direction above this rate stops batching again.
const BATCH_DISABLE_RATE: f64 = 800.0 * 1024.0 * 1024.0;

/// Grace period used to accumulate source data before one splice.
const BATCH_SLEEP: Duration = Duration::from_micros(500);

/// Disable batching after this much idle time so later small responses keep
/// their normal latency.
const BATCH_RESET: Duration = Duration::from_millis(100);

/// Rate-check window used to decide whether a bulk direction is still slow.
const BATCH_RATE_WINDOW_BYTES: u64 = 2 * 1024 * 1024;
const BATCH_RATE_WINDOW_TIME: Duration = Duration::from_millis(50);

/// Cancellation poll interval for a relay that shares an activity clock.
///
/// The normal path wakes immediately through the shared [`EventFd`]. The
/// eventfd write has a bounded retry count, though, so this cap also bounds a
/// poller that missed the wakeup because the write failed.
const STOP_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Relay tuning and limits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayConfig {
    /// Kernel pipe capacity for each direction.
    ///
    /// Must be a power of two between [`MIN_PIPE_SIZE`] and [`MAX_PIPE_SIZE`].
    /// If the kernel refuses the request, the relay keeps the default pipe
    /// size and continues.
    pub pipe_size: usize,
    /// Maximum bytes read from the source, or `None` for no limit.
    ///
    /// When the limit is reached the relay stops reading, drains what it has
    /// already buffered, half-closes the destination, and returns normally.
    pub max_bytes: Option<u64>,
    /// Inactivity timeout while the source is open.
    ///
    /// Must be non-zero.
    pub idle_timeout: Duration,
    /// Inactivity timeout after the source closes or after `max_bytes` is
    /// reached.
    ///
    /// A direction that is still moving bytes is not interrupted. Must be
    /// non-zero.
    pub shutdown_timeout: Duration,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            pipe_size: DEFAULT_PIPE_SIZE,
            max_bytes: None,
            idle_timeout: Duration::from_secs(300),
            shutdown_timeout: Duration::from_secs(30),
        }
    }
}

impl RelayConfig {
    /// Returns how many splice tasks fit in `soft_pages` at [`MIN_PIPE_SIZE`].
    ///
    /// Linux uses zero to disable the soft pipe-page limit, so that case needs
    /// no clamp. The result saturates at `usize::MAX`. A soft limit that leaves
    /// no capacity above [`RESERVE_PAGES`] returns zero; a zero-permit limiter
    /// makes every direction use the async copy fallback.
    #[must_use]
    pub fn supported_splice_tasks(soft_pages: u64, page_size: u64) -> usize {
        if soft_pages == 0 {
            return usize::MAX;
        }
        let page = page_size.max(1);
        let pages_per_task = (MIN_PIPE_SIZE as u64).div_ceil(page);
        let tasks = soft_pages.saturating_sub(RESERVE_PAGES) / pages_per_task;
        usize::try_from(tasks).unwrap_or(usize::MAX)
    }

    /// Returns the default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the kernel pipe capacity for each direction.
    #[must_use]
    pub fn with_pipe_size(mut self, pipe_size: usize) -> Self {
        self.pipe_size = pipe_size;
        self
    }

    /// Sets the total byte limit.
    #[must_use]
    pub fn with_max_bytes(mut self, max_bytes: Option<u64>) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    /// Sets the idle timeout.
    #[must_use]
    pub fn with_idle_timeout(mut self, idle_timeout: Duration) -> Self {
        self.idle_timeout = idle_timeout;
        self
    }

    /// Sets the post-half-close inactivity timeout.
    #[must_use]
    pub fn with_shutdown_timeout(mut self, shutdown_timeout: Duration) -> Self {
        self.shutdown_timeout = shutdown_timeout;
        self
    }

    /// Checks that the pipe size and timeouts are supported.
    pub fn validate(&self) -> io::Result<()> {
        if !self.pipe_size.is_power_of_two()
            || !(MIN_PIPE_SIZE..=MAX_PIPE_SIZE).contains(&self.pipe_size)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "relay pipe size must be a power of two between {MIN_PIPE_SIZE} and \
                     {MAX_PIPE_SIZE} bytes"
                ),
            ));
        }
        if self.idle_timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "relay idle timeout must be non-zero",
            ));
        }
        if self.shutdown_timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "relay shutdown timeout must be non-zero",
            ));
        }
        Ok(())
    }
}

/// Counters collected by [`copy_one_way`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RelayStats {
    /// Bytes delivered from source to sink.
    pub bytes_a_to_b: u64,
    /// Reserved for the reverse direction; zero for a one-way relay.
    pub bytes_b_to_a: u64,
    /// `splice(2)` calls attempted, including calls that returned `EAGAIN` or
    /// observed EOF.
    pub splice_calls: u64,
    /// `poll(2)` calls attempted.
    pub polls: u64,
    /// Source EOF observations, zero or one.
    pub eofs: u64,
    /// Successful `shutdown(SHUT_WR)` calls, zero or one.
    pub half_closes: u64,
}

impl RelayStats {
    /// Returns the total number of delivered bytes.
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.bytes_a_to_b.saturating_add(self.bytes_b_to_a)
    }
}

struct Direction {
    source: RawFd,
    sink: RawFd,
    pipe_read: OwnedFd,
    pipe_write: OwnedFd,
    /// Bytes handed to the pipe by `fill` but not yet delivered by `drain`.
    in_pipe: usize,
    /// The last `fill` call found the pipe full.
    pipe_full: bool,
    /// No more bytes will be read from `source`.
    read_done: bool,
    /// `shutdown(SHUT_WR)` has been sent to `sink`.
    shutdown_sent: bool,
    /// Bytes delivered to `sink`.
    bytes: u64,
    /// The main poll reported source readiness since the last fill.
    read_ready: bool,
    /// Start of the current rate-check window.
    rate_at: Option<Instant>,
    /// Bytes delivered at the start of the current rate-check window.
    rate_bytes: u64,
    /// Slow bulk direction: wait briefly so one splice moves a larger chunk.
    batch_enabled: bool,
}

impl Direction {
    fn new(source: RawFd, sink: RawFd, pipe_read: OwnedFd, pipe_write: OwnedFd) -> Self {
        Self {
            source,
            sink,
            pipe_read,
            pipe_write,
            in_pipe: 0,
            pipe_full: false,
            read_done: false,
            shutdown_sent: false,
            bytes: 0,
            read_ready: true,
            rate_at: None,
            rate_bytes: 0,
            batch_enabled: false,
        }
    }

    fn is_done(&self) -> bool {
        self.read_done && self.in_pipe == 0 && self.shutdown_sent
    }
}

/// Shared activity clock for the two halves of an asymmetric Vision relay.
///
/// The async upload and the blocking download relay both touch this clock. An
/// idle timeout is measured from the most recent activity in either direction,
/// which preserves the bidirectional relay's idle semantics after the
/// directions are split.
#[derive(Debug)]
pub struct RelayActivity {
    last: Mutex<Instant>,
    stopped: AtomicBool,
    /// Wakes every direction blocked in `poll` when [`Self::stop`] runs.
    ///
    /// Eventfd creation is best-effort: if the process is out of descriptors,
    /// the relay keeps its bounded-poll cancellation path instead of failing
    /// the connection.
    stop_fd: Option<EventFd>,
    /// Test-only: models a wakeup that the bounded eventfd retries gave up on.
    /// The descriptor stays in the poll set, so only the poll cap can end a
    /// blocked relay.
    #[cfg(test)]
    fail_notify: AtomicBool,
}

impl RelayActivity {
    /// Creates a clock starting at the current instant.
    #[must_use]
    pub fn new() -> Self {
        Self {
            last: Mutex::new(Instant::now()),
            stopped: AtomicBool::new(false),
            stop_fd: EventFd::new().ok(),
            #[cfg(test)]
            fail_notify: AtomicBool::new(false),
        }
    }

    /// Test-only clock with a live stop descriptor whose wakeup fails.
    #[cfg(test)]
    fn with_failing_notify() -> Self {
        Self {
            fail_notify: AtomicBool::new(true),
            ..Self::new()
        }
    }

    /// Records activity now.
    pub fn touch(&self) {
        if let Ok(mut last) = self.last.lock() {
            *last = Instant::now();
        }
    }

    /// Returns how long ago the most recent activity happened.
    #[must_use]
    pub fn elapsed(&self) -> Option<Duration> {
        self.last.lock().ok().map(|last| last.elapsed())
    }

    /// Asks every relay sharing this clock to stop and wakes blocked pollers.
    ///
    /// The flag alone cannot end a poller that is already blocked, so a failed
    /// wakeup relies on the [`STOP_POLL_INTERVAL`] poll cap in
    /// [`copy_one_way`].
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        #[cfg(test)]
        if self.fail_notify.load(Ordering::Relaxed) {
            return;
        }
        if let Some(stop_fd) = &self.stop_fd
            && let Err(error) = stop_fd.notify()
        {
            tracing::debug!(%error, "could not wake a stopped relay");
        }
    }

    /// Returns `true` after [`Self::stop`].
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }

    /// Returns the wakeup descriptor used in `poll`, when one is available.
    fn stop_fd(&self) -> Option<RawFd> {
        self.stop_fd.as_ref().map(AsRawFd::as_raw_fd)
    }
}

impl Default for RelayActivity {
    fn default() -> Self {
        Self::new()
    }
}

/// Copies one direction between two connected, nonblocking stream sockets.
///
/// It is used when only one Vision direction has switched to raw, so the bulk
/// download can use `splice(2)` while the framed upload continues on its async
/// path. It shuts down the sink's write half when the source reaches EOF.
///
/// `activity_clock` is shared with the opposite async direction so the idle
/// timeout measures activity in either direction. Slow bulk transfers batch
/// source reads; fast and small transfers keep the low-latency path.
pub fn copy_one_way(
    source: RawFd,
    sink: RawFd,
    config: &RelayConfig,
    activity_clock: Option<&RelayActivity>,
) -> io::Result<RelayStats> {
    config.validate()?;

    let (pipe_read, pipe_write) = pipe()?;
    match beam_sys::set_pipe_size(pipe_write.as_raw_fd(), config.pipe_size) {
        Ok(actual) => tracing::debug!(requested = config.pipe_size, actual, "one-way pipe sized"),
        Err(error) => warn_pipe_size_once(
            &error,
            config.pipe_size,
            "could not resize one-way relay pipe; using the kernel default",
        ),
    }

    let mut direction = Direction::new(source, sink, pipe_read, pipe_write);
    let mut stats = RelayStats::default();
    let result = run_one_way(&mut direction, &mut stats, config, activity_clock);

    stats.bytes_a_to_b = direction.bytes;
    let bytes_per_splice = stats
        .bytes_a_to_b
        .checked_div(stats.splice_calls)
        .unwrap_or(0);
    tracing::debug!(
        pipe_size = config.pipe_size,
        bytes = stats.bytes_a_to_b,
        splice_calls = stats.splice_calls,
        polls = stats.polls,
        bytes_per_splice,
        batch_enabled = direction.batch_enabled,
        error = ?result.as_ref().err(),
        "one-way relay finished"
    );

    result?;
    Ok(stats)
}

fn run_one_way(
    direction: &mut Direction,
    stats: &mut RelayStats,
    config: &RelayConfig,
    activity_clock: Option<&RelayActivity>,
) -> io::Result<()> {
    let mut committed = 0_u64;
    let mut last_activity = Instant::now();
    let mut shutdown_started: Option<Instant> = None;
    let stop_fd = activity_clock.and_then(RelayActivity::stop_fd);

    loop {
        if activity_clock.is_some_and(RelayActivity::is_stopped) {
            return Ok(());
        }
        let now = Instant::now();
        let local_elapsed = now.saturating_duration_since(last_activity);
        let idle_elapsed = activity_clock
            .and_then(RelayActivity::elapsed)
            .map_or(local_elapsed, |shared| shared.min(local_elapsed));
        let limit = inactivity_limit(config, shutdown_started.is_some());
        if idle_elapsed >= limit {
            // A shutdown that still holds undelivered bytes never sent
            // `SHUT_WR`, so the sink is stalled and the copy did not finish.
            // Reporting success here would hide the half-open sink.
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                if shutdown_started.is_some() {
                    "one-way relay shutdown timeout with undelivered bytes"
                } else {
                    "one-way relay idle timeout"
                },
            ));
        }

        if direction.batch_enabled && direction.in_pipe == 0 && !direction.read_done {
            if now.saturating_duration_since(last_activity) > BATCH_RESET {
                direction.batch_enabled = false;
                direction.rate_at = None;
                direction.rate_bytes = direction.bytes;
            } else {
                std::thread::sleep(BATCH_SLEEP);
            }
        }

        let mut activity = false;
        if direction.read_ready {
            activity |= fill(
                direction,
                WORK_PER_ROUND,
                config.max_bytes,
                &mut committed,
                stats,
            )?;
            direction.read_ready = false;
        }
        if config.max_bytes.is_some_and(|limit| committed >= limit) {
            direction.read_done = true;
        }

        activity |= drain(direction, WORK_PER_ROUND, stats)?;
        maybe_update_batch(direction);
        maybe_shutdown(direction, stats)?;

        let now = Instant::now();
        if activity {
            last_activity = now;
            if let Some(clock) = activity_clock {
                clock.touch();
            }
        }
        if shutdown_started.is_none() && direction.read_done {
            shutdown_started = Some(now);
            last_activity = now;
        }
        if direction.is_done() {
            break;
        }

        let mut fds = [
            poll_source(direction),
            poll_pipe_write(direction),
            poll_sink(direction),
            stop_fd.map_or(PollFd::ignored(), |fd| PollFd::new(fd, PollEvents::READ)),
        ];
        stats.polls = stats.polls.saturating_add(1);
        let poll_timeout =
            inactivity_limit(config, shutdown_started.is_some()).saturating_sub(idle_elapsed);
        // The eventfd wakes both directions immediately, but its write is
        // bounded and can fail. An already blocked poller would then sleep
        // until the idle timeout with its pipe, sockets, and thread retained.
        // Cap every poll of a shared clock so a missed wakeup costs at most
        // STOP_POLL_INTERVAL; the cost is four wakeups per second while a
        // direction is blocked.
        let poll_timeout = if activity_clock.is_some() {
            poll_timeout.min(STOP_POLL_INTERVAL)
        } else {
            poll_timeout
        };
        match poll(&mut fds, Some(poll_timeout)) {
            Ok(_) => {
                direction.read_ready = !fds[0].revents().is_empty() || !fds[1].revents().is_empty();
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }

    Ok(())
}

fn maybe_update_batch(direction: &mut Direction) {
    if direction.bytes < BATCH_THRESHOLD {
        return;
    }
    let now = Instant::now();
    let Some(start) = direction.rate_at else {
        direction.rate_at = Some(now);
        direction.rate_bytes = direction.bytes;
        return;
    };
    let elapsed = now.saturating_duration_since(start);
    let bytes = direction.bytes.saturating_sub(direction.rate_bytes);
    if bytes < BATCH_RATE_WINDOW_BYTES && elapsed < BATCH_RATE_WINDOW_TIME {
        return;
    }
    let seconds = elapsed.as_secs_f64();
    if seconds > 0.0 {
        let rate = bytes as f64 / seconds;
        if direction.batch_enabled {
            if rate > BATCH_DISABLE_RATE || rate < BATCH_MIN_RATE {
                direction.batch_enabled = false;
            }
        } else if (BATCH_MIN_RATE..BATCH_RATE_LIMIT).contains(&rate) {
            direction.batch_enabled = true;
        }
    }
    direction.rate_at = Some(now);
    direction.rate_bytes = direction.bytes;
}

fn fill(
    direction: &mut Direction,
    budget: usize,
    max_bytes: Option<u64>,
    committed: &mut u64,
    stats: &mut RelayStats,
) -> io::Result<bool> {
    if direction.read_done {
        return Ok(false);
    }

    let allowance = match max_bytes {
        Some(limit) => limit.saturating_sub(*committed),
        None => u64::MAX,
    };
    if allowance == 0 {
        direction.read_done = true;
        return Ok(false);
    }

    let len = budget.min(usize::try_from(allowance).unwrap_or(usize::MAX));
    if len == 0 {
        return Ok(false);
    }

    stats.splice_calls = stats.splice_calls.saturating_add(1);
    match splice(
        direction.source,
        direction.pipe_write.as_raw_fd(),
        len,
        SpliceFlags::MOVE | SpliceFlags::NONBLOCK,
    ) {
        Ok(0) => {
            direction.read_done = true;
            stats.eofs = stats.eofs.saturating_add(1);
            Ok(true)
        }
        Ok(moved) => {
            direction.in_pipe = direction.in_pipe.saturating_add(moved);
            *committed = committed.saturating_add(u64::try_from(moved).unwrap_or(u64::MAX));
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            // `EAGAIN` can mean the source is empty or the pipe is full.
            // If the source still has data, the pipe must be full.
            direction.pipe_full =
                direction.in_pipe > 0 && source_has_data(direction.source, stats)?;
            Ok(false)
        }
        Err(error) if error.kind() == io::ErrorKind::Interrupted => Ok(false),
        Err(error) => Err(error),
    }
}

fn source_has_data(fd: RawFd, stats: &mut RelayStats) -> io::Result<bool> {
    let mut fds = [PollFd::new(fd, PollEvents::READ)];

    stats.polls = stats.polls.saturating_add(1);
    match poll(&mut fds, Some(Duration::ZERO)) {
        Ok(ready) => Ok(ready > 0 && fds[0].revents().contains(PollEvents::READ)),
        Err(error) if error.kind() == io::ErrorKind::Interrupted => Ok(false),
        Err(error) => Err(error),
    }
}

fn drain(direction: &mut Direction, budget: usize, stats: &mut RelayStats) -> io::Result<bool> {
    let mut progress = false;
    let mut remaining = budget;
    while direction.in_pipe > 0 && remaining > 0 {
        let len = direction.in_pipe.min(remaining);
        stats.splice_calls = stats.splice_calls.saturating_add(1);
        match splice(
            direction.pipe_read.as_raw_fd(),
            direction.sink,
            len,
            SpliceFlags::MOVE | SpliceFlags::NONBLOCK,
        ) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "relay pipe reported EOF with buffered data",
                ));
            }
            Ok(moved) => {
                direction.in_pipe = direction.in_pipe.saturating_sub(moved);
                direction.bytes = direction
                    .bytes
                    .saturating_add(u64::try_from(moved).unwrap_or(u64::MAX));
                remaining = remaining.saturating_sub(moved);
                direction.pipe_full = false;
                progress = true;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(progress),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => return Ok(progress),
            Err(error) => return Err(error),
        }
    }

    Ok(progress)
}

fn maybe_shutdown(direction: &mut Direction, stats: &mut RelayStats) -> io::Result<()> {
    if direction.read_done && direction.in_pipe == 0 && !direction.shutdown_sent {
        beam_sys::shutdown_write(direction.sink)?;
        direction.shutdown_sent = true;
        stats.half_closes = stats.half_closes.saturating_add(1);
    }
    Ok(())
}

fn poll_source(direction: &Direction) -> PollFd {
    if !direction.read_done && !direction.pipe_full {
        PollFd::new(direction.source, PollEvents::READ)
    } else {
        PollFd::ignored()
    }
}

fn poll_pipe_write(direction: &Direction) -> PollFd {
    if !direction.read_done && direction.pipe_full {
        PollFd::new(direction.pipe_write.as_raw_fd(), PollEvents::WRITE)
    } else {
        PollFd::ignored()
    }
}

fn poll_sink(direction: &Direction) -> PollFd {
    if direction.in_pipe > 0 {
        PollFd::new(direction.sink, PollEvents::WRITE)
    } else {
        PollFd::ignored()
    }
}

fn inactivity_limit(config: &RelayConfig, shutting_down: bool) -> Duration {
    if shutting_down {
        config.idle_timeout.min(config.shutdown_timeout)
    } else {
        config.idle_timeout
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_PIPE_SIZE, MAX_PIPE_SIZE, MIN_PIPE_SIZE, RelayConfig, RelayStats, copy_one_way,
        pipe_size_for_budget,
    };
    use std::io::{self, Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;
    use std::sync::mpsc::{self, Receiver};
    use std::thread;
    use std::time::{Duration, Instant};

    fn relay_pair() -> (UnixStream, UnixStream, UnixStream, UnixStream) {
        let (client, relay_a) = UnixStream::pair().unwrap();
        let (relay_b, target) = UnixStream::pair().unwrap();
        (client, relay_a, relay_b, target)
    }

    fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    fn config() -> RelayConfig {
        RelayConfig {
            pipe_size: 16 * 1024,
            max_bytes: None,
            idle_timeout: Duration::from_secs(5),
            shutdown_timeout: Duration::from_secs(5),
        }
    }

    fn run_relay<A, B>(
        relay_a: A,
        relay_b: B,
        config: RelayConfig,
    ) -> Receiver<io::Result<RelayStats>>
    where
        A: AsRawFd + Send + 'static,
        B: AsRawFd + Send + 'static,
    {
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let result = (|| {
                beam_sys::set_nonblocking(relay_a.as_raw_fd())?;
                beam_sys::set_nonblocking(relay_b.as_raw_fd())?;
                copy_one_way(relay_a.as_raw_fd(), relay_b.as_raw_fd(), &config, None)
            })();
            let _ = sender.send(result);
        });
        receiver
    }

    fn wait(receiver: Receiver<io::Result<RelayStats>>) -> io::Result<RelayStats> {
        receiver
            .recv_timeout(Duration::from_secs(10))
            .expect("relay did not finish within the test deadline")
    }

    #[test]
    fn one_way_copies_and_half_closes() {
        let (client, relay_a, relay_b, mut target) = relay_pair();
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let result = (|| {
                beam_sys::set_nonblocking(relay_a.as_raw_fd())?;
                beam_sys::set_nonblocking(relay_b.as_raw_fd())?;
                copy_one_way(relay_a.as_raw_fd(), relay_b.as_raw_fd(), &config(), None)
            })();
            let _ = sender.send(result);
        });

        let payload = vec![0x5a; 2 * 1024 * 1024 + 17];
        let expected = payload.clone();
        let mut client_writer = client.try_clone().unwrap();
        let client_thread = thread::spawn(move || {
            client_writer.write_all(&payload).unwrap();
            client_writer.shutdown(Shutdown::Write).unwrap();
        });

        let mut received = Vec::new();
        target.read_to_end(&mut received).unwrap();
        client_thread.join().unwrap();

        let stats = receiver
            .recv_timeout(Duration::from_secs(10))
            .expect("one-way relay did not finish")
            .unwrap();
        assert_eq!(received, expected);
        assert_eq!(stats.bytes_a_to_b, expected.len() as u64);
        assert_eq!(stats.bytes_b_to_a, 0);
        assert_eq!(stats.eofs, 1);
        assert_eq!(stats.half_closes, 1);
        assert!(stats.splice_calls > 0);
        assert!(stats.polls > 0);
    }

    #[test]
    fn stop_wakes_a_blocked_one_way_relay() {
        let (_client, relay_a, relay_b, _target) = relay_pair();
        let activity = Arc::new(super::RelayActivity::new());
        let relay_activity = Arc::clone(&activity);
        let config = RelayConfig {
            idle_timeout: Duration::from_secs(30),
            shutdown_timeout: Duration::from_secs(30),
            ..config()
        };
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let result = (|| {
                beam_sys::set_nonblocking(relay_a.as_raw_fd())?;
                beam_sys::set_nonblocking(relay_b.as_raw_fd())?;
                copy_one_way(
                    relay_a.as_raw_fd(),
                    relay_b.as_raw_fd(),
                    &config,
                    Some(&relay_activity),
                )
            })();
            let _ = sender.send(result);
        });

        thread::sleep(Duration::from_millis(50));
        activity.stop();
        let result = receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("stopped relay did not wake");
        assert!(result.is_ok(), "stopped relay failed: {result:?}");
    }

    #[test]
    fn an_idle_relay_polls_within_the_stop_bound() {
        let (_client, relay_a, relay_b, _target) = relay_pair();
        let activity = Arc::new(super::RelayActivity::new());
        assert!(
            activity.stop_fd().is_some(),
            "the test requires eventfd support"
        );
        let relay_activity = Arc::clone(&activity);
        let config = RelayConfig {
            idle_timeout: Duration::from_secs(30),
            shutdown_timeout: Duration::from_secs(30),
            ..config()
        };
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let result = (|| {
                beam_sys::set_nonblocking(relay_a.as_raw_fd())?;
                beam_sys::set_nonblocking(relay_b.as_raw_fd())?;
                copy_one_way(
                    relay_a.as_raw_fd(),
                    relay_b.as_raw_fd(),
                    &config,
                    Some(&relay_activity),
                )
            })();
            let _ = sender.send(result);
        });

        // An idle shared clock still polls at the cancellation bound; the
        // eventfd only makes the usual wakeup immediate.
        thread::sleep(Duration::from_millis(600));
        let started = Instant::now();
        activity.stop();
        let result = receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("stopped relay did not wake");
        let stats = result.expect("stopped relay failed");
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "cancellation took {:?}",
            started.elapsed()
        );
        // It polls at the cap instead of sleeping through the idle timeout.
        assert!(
            (2..=8).contains(&stats.polls),
            "an idle relay polled {} times in 600 ms",
            stats.polls
        );
    }

    #[test]
    fn a_failed_wakeup_still_bounds_a_blocked_relay() {
        let (_client, relay_a, relay_b, _target) = relay_pair();
        let activity = Arc::new(super::RelayActivity::with_failing_notify());
        assert!(
            activity.stop_fd().is_some(),
            "the test requires eventfd support"
        );
        let relay_activity = Arc::clone(&activity);
        let config = RelayConfig {
            idle_timeout: Duration::from_secs(30),
            shutdown_timeout: Duration::from_secs(30),
            ..config()
        };
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let result = (|| {
                beam_sys::set_nonblocking(relay_a.as_raw_fd())?;
                beam_sys::set_nonblocking(relay_b.as_raw_fd())?;
                copy_one_way(
                    relay_a.as_raw_fd(),
                    relay_b.as_raw_fd(),
                    &config,
                    Some(&relay_activity),
                )
            })();
            let _ = sender.send(result);
        });

        // Let the worker block in poll before the wakeup fails.
        thread::sleep(Duration::from_millis(50));
        let started = Instant::now();
        activity.stop();
        let result = receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("a failed wakeup left the relay blocked past the idle timeout");
        assert!(result.is_ok(), "stopped relay failed: {result:?}");
        assert!(
            started.elapsed() < Duration::from_millis(800),
            "cancellation took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn shared_activity_keeps_one_way_alive() {
        let (client, relay_a, relay_b, mut target) = relay_pair();
        let activity = Arc::new(super::RelayActivity::new());
        let relay_activity = Arc::clone(&activity);
        let config = RelayConfig {
            idle_timeout: Duration::from_millis(300),
            shutdown_timeout: Duration::from_secs(1),
            ..config()
        };

        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let result = (|| {
                beam_sys::set_nonblocking(relay_a.as_raw_fd())?;
                beam_sys::set_nonblocking(relay_b.as_raw_fd())?;
                copy_one_way(
                    relay_a.as_raw_fd(),
                    relay_b.as_raw_fd(),
                    &config,
                    Some(&relay_activity),
                )
            })();
            let _ = sender.send(result);
        });

        let heartbeat = thread::spawn(move || {
            for _ in 0..10 {
                thread::sleep(Duration::from_millis(50));
                activity.touch();
            }
        });

        heartbeat.join().unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut received = Vec::new();
        target.read_to_end(&mut received).unwrap();
        assert!(received.is_empty());

        let stats = receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("one-way relay did not finish")
            .unwrap();
        assert_eq!(stats.bytes_a_to_b, 0);
        assert_eq!(stats.eofs, 1);
        assert_eq!(stats.half_closes, 1);
    }

    #[test]
    fn one_way_relays_over_tcp_loopback() {
        let (mut client, relay_a) = tcp_pair();
        let (relay_b, mut target) = tcp_pair();
        let receiver = run_relay(relay_a, relay_b, config());
        client.write_all(b"hello").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut received = Vec::new();
        target.read_to_end(&mut received).unwrap();
        let stats = wait(receiver).unwrap();
        assert_eq!(received, b"hello");
        assert_eq!(stats.bytes_a_to_b, 5);
        assert_eq!(stats.eofs, 1);
        assert_eq!(stats.half_closes, 1);
    }

    #[test]
    fn one_way_drains_after_a_slow_sink() {
        let (mut client, relay_a, relay_b, mut target) = relay_pair();
        let receiver = run_relay(relay_a, relay_b, config());
        let (written_tx, written_rx) = mpsc::channel();
        let writer = thread::spawn(move || {
            client.write_all(&vec![0x33; 2 * 1024 * 1024]).unwrap();
            client.shutdown(Shutdown::Write).unwrap();
            written_tx.send(()).unwrap();
        });

        // A stalled sink fills the socket and pipe before reading resumes.
        assert!(written_rx.recv_timeout(Duration::from_millis(50)).is_err());
        let mut received = Vec::new();
        target.read_to_end(&mut received).unwrap();
        writer.join().unwrap();
        let stats = wait(receiver).unwrap();
        assert_eq!(received.len(), 2 * 1024 * 1024);
        assert!(received.iter().all(|&byte| byte == 0x33));
        assert_eq!(stats.bytes_a_to_b, received.len() as u64);
        assert_eq!(stats.half_closes, 1);
    }

    #[test]
    fn a_stalled_sink_reports_the_shutdown_deadline() {
        let (mut client, relay_a, relay_b, target) = relay_pair();
        // Pre-fill the sink's send queue so the sink cannot accept the bytes
        // the source still has. The relay then reaches EOF with data stuck in
        // its pipe and cannot send the half-close.
        relay_b.set_nonblocking(true).unwrap();
        let chunk = [0_u8; 4096];
        loop {
            match (&relay_b).write(&chunk) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("could not fill the sink queue: {error}"),
            }
        }
        let receiver = run_relay(
            relay_a,
            relay_b,
            RelayConfig {
                idle_timeout: Duration::from_secs(5),
                shutdown_timeout: Duration::from_millis(100),
                ..config()
            },
        );

        client.write_all(&[0x5a; 128]).unwrap();
        client.shutdown(Shutdown::Write).unwrap();

        let error = wait(receiver).expect_err("a stalled sink must not report success");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        drop(client);
        drop(target);
    }

    #[test]
    fn idle_timeout_returns_timed_out() {
        let (client, relay_a, relay_b, target) = relay_pair();
        let started = Instant::now();
        let receiver = run_relay(
            relay_a,
            relay_b,
            RelayConfig {
                idle_timeout: Duration::from_millis(50),
                ..config()
            },
        );

        let result = wait(receiver);
        let elapsed = started.elapsed();

        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(elapsed >= Duration::from_millis(30));
        assert!(elapsed < Duration::from_secs(2));

        drop(client);
        drop(target);
    }

    #[test]
    fn max_bytes_stops_the_relay_cleanly() {
        let (mut client, relay_a, relay_b, mut target) = relay_pair();
        let receiver = run_relay(
            relay_a,
            relay_b,
            RelayConfig {
                max_bytes: Some(1024),
                ..config()
            },
        );

        let payload = vec![0x7c; 8 * 1024];
        client.write_all(&payload).unwrap();
        client.shutdown(Shutdown::Write).unwrap();

        let mut received = Vec::new();
        target.read_to_end(&mut received).unwrap();
        assert_eq!(received, &payload[..1024]);

        let stats = wait(receiver).unwrap();
        assert_eq!(stats.bytes_a_to_b, 1024);
        assert_eq!(stats.bytes_b_to_a, 0);
        assert_eq!(stats.total_bytes(), 1024);
        assert_eq!(stats.half_closes, 1);
    }

    #[test]
    fn invalid_pipe_sizes_are_rejected() {
        let (a, b) = UnixStream::pair().unwrap();

        for pipe_size in [0, 1, 1000, MIN_PIPE_SIZE / 2, MAX_PIPE_SIZE * 2] {
            let config = RelayConfig {
                pipe_size,
                ..RelayConfig::default()
            };
            let error = copy_one_way(a.as_raw_fd(), b.as_raw_fd(), &config, None).unwrap_err();
            assert_eq!(
                error.kind(),
                io::ErrorKind::InvalidInput,
                "pipe size {pipe_size} was accepted"
            );
        }
    }

    #[test]
    fn boundary_pipe_sizes_validate() {
        RelayConfig::default().validate().unwrap();
        for pipe_size in [MIN_PIPE_SIZE, DEFAULT_PIPE_SIZE, MAX_PIPE_SIZE] {
            RelayConfig {
                pipe_size,
                ..RelayConfig::default()
            }
            .validate()
            .unwrap();
        }
    }

    #[test]
    fn builders_update_the_configuration() {
        let config = RelayConfig::new()
            .with_pipe_size(64 * 1024)
            .with_max_bytes(Some(4096))
            .with_idle_timeout(Duration::from_secs(10))
            .with_shutdown_timeout(Duration::from_secs(1));

        assert_eq!(config.pipe_size, 64 * 1024);
        assert_eq!(config.max_bytes, Some(4096));
        assert_eq!(config.idle_timeout, Duration::from_secs(10));
        assert_eq!(config.shutdown_timeout, Duration::from_secs(1));
    }

    #[test]
    fn zero_timeouts_are_rejected() {
        let zero_idle = RelayConfig {
            idle_timeout: Duration::ZERO,
            ..RelayConfig::default()
        };
        assert_eq!(
            zero_idle.validate().unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );

        let zero_shutdown = RelayConfig {
            shutdown_timeout: Duration::ZERO,
            ..RelayConfig::default()
        };
        assert_eq!(
            zero_shutdown.validate().unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn pipe_budget_fits_the_soft_limit() {
        assert_eq!(pipe_size_for_budget(16_384, 120, 4096), 512 * 1024);
        assert_eq!(pipe_size_for_budget(16_384, 472, 4096), 128 * 1024);
        assert_eq!(pipe_size_for_budget(4_096, 120, 4096), 64 * 1024);
        assert_eq!(pipe_size_for_budget(1_024, 120, 4096), MIN_PIPE_SIZE);
        assert_eq!(pipe_size_for_budget(0, 120, 4096), MIN_PIPE_SIZE);
        assert_eq!(pipe_size_for_budget(16_384, 0, 4096), DEFAULT_PIPE_SIZE);
    }

    #[test]
    fn supported_splice_tasks_returns_zero_when_the_reserve_uses_the_budget() {
        // No capacity above the reserve: zero permits, so startup selects the
        // async fallback instead of oversubscribing the pipe-page soft limit.
        assert_eq!(RelayConfig::supported_splice_tasks(1_023, 4096), 0);
        assert_eq!(RelayConfig::supported_splice_tasks(1_024, 4096), 0);
        assert_eq!(RelayConfig::supported_splice_tasks(1_025, 4096), 1);
        assert_eq!(RelayConfig::supported_splice_tasks(1_025, 8_192), 1);
    }

    #[test]
    fn supported_splice_tasks_respects_the_pipe_budget() {
        assert_eq!(RelayConfig::supported_splice_tasks(0, 4096), usize::MAX);
        assert_eq!(RelayConfig::supported_splice_tasks(2_048, 4096), 1_024);
        assert_eq!(RelayConfig::supported_splice_tasks(2_048, 0), 0);
        assert_eq!(
            RelayConfig::supported_splice_tasks(u64::MAX, 4096),
            usize::try_from(u64::MAX - 1_024).unwrap_or(usize::MAX)
        );
        assert_eq!(RelayConfig::supported_splice_tasks(16_384, 4096), 15_360);
    }

    #[test]
    fn pipe_budget_rounds_down_to_a_valid_pipe_size() {
        let size = pipe_size_for_budget(16_384, 121, 4096);
        assert!(size.is_power_of_two());
        assert!(size <= 512 * 1024);
        assert!(size >= MIN_PIPE_SIZE);
        assert_eq!(size, 256 * 1024);
    }

    #[test]
    fn total_bytes_saturates() {
        let stats = RelayStats {
            bytes_a_to_b: u64::MAX,
            bytes_b_to_a: 1,
            ..RelayStats::default()
        };

        assert_eq!(stats.total_bytes(), u64::MAX);
    }
}
