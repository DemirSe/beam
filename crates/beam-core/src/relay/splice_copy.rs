use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};

use beam_sys::{PollEvents, PollFd, SpliceFlags, pipe, poll, splice};

/// Default kernel pipe capacity used for each direction.
pub const DEFAULT_PIPE_SIZE: usize = 512 * 1024;

/// Smallest accepted pipe size.
pub const MIN_PIPE_SIZE: usize = 4096;

/// Largest accepted pipe size.
///
/// The architecture document starts the relay at 512 KiB. A larger value needs
/// a new measurement, so the accepted range stays deliberately small.
pub const MAX_PIPE_SIZE: usize = 1024 * 1024;

/// Maximum bytes moved by one fill or drain phase in one loop iteration.
///
/// Both directions get a fill and a drain budget before the relay polls again,
/// so a bulk transfer cannot starve a small request in the opposite direction.
const WORK_PER_ROUND: usize = 1024 * 1024;

/// Relay tuning and limits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayConfig {
    /// Kernel pipe capacity for each direction.
    ///
    /// Must be a power of two between [`MIN_PIPE_SIZE`] and [`MAX_PIPE_SIZE`].
    /// If the kernel refuses the request, the relay keeps the default pipe
    /// size and continues.
    pub pipe_size: usize,
    /// Maximum total bytes read from both sources, or `None` for no limit.
    ///
    /// When the limit is reached the relay stops reading, drains what it has
    /// already buffered, half-closes both destinations, and returns normally.
    pub max_bytes: Option<u64>,
    /// Inactivity timeout while both directions are still open.
    ///
    /// Must be non-zero.
    pub idle_timeout: Duration,
    /// Inactivity timeout after the first half-close or after `max_bytes` is
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

/// Counters collected by [`copy_bidirectional`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RelayStats {
    /// Bytes delivered from `a` to `b`.
    pub bytes_a_to_b: u64,
    /// Bytes delivered from `b` to `a`.
    pub bytes_b_to_a: u64,
    /// `splice(2)` calls attempted, including calls that returned `EAGAIN` or
    /// observed EOF.
    pub splice_calls: u64,
    /// `poll(2)` calls attempted.
    pub polls: u64,
    /// Source EOF observations, from zero to two.
    pub eofs: u64,
    /// Successful `shutdown(SHUT_WR)` calls, from zero to two.
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
        }
    }

    fn is_done(&self) -> bool {
        self.read_done && self.in_pipe == 0 && self.shutdown_sent
    }
}

/// Copies bytes in both directions between two connected, nonblocking streams.
///
/// The descriptors are borrowed, not owned: the caller closes them after this
/// function returns, including on error. `a` and `b` must be stream sockets;
/// the relay uses `splice(2)` and `shutdown(2)`.
///
/// Returns once both directions have reached EOF (or `max_bytes` has been
/// reached), the buffered bytes have been delivered, and both write halves
/// have been shut down. An idle connection returns
/// [`io::ErrorKind::TimedOut`] while both directions are still open;
/// inactivity after a half-close or after `max_bytes` ends the relay normally.
/// If the shutdown timeout expires, any bytes still buffered in the pipes are
/// discarded before the normal return.
pub fn copy_bidirectional(a: RawFd, b: RawFd, config: &RelayConfig) -> io::Result<RelayStats> {
    config.validate()?;

    let (a_pipe_read, a_pipe_write) = pipe()?;
    let (b_pipe_read, b_pipe_write) = pipe()?;

    for fd in [a_pipe_write.as_raw_fd(), b_pipe_write.as_raw_fd()] {
        if let Err(error) = beam_sys::set_pipe_size(fd, config.pipe_size) {
            tracing::debug!(
                ?error,
                pipe_size = config.pipe_size,
                "could not resize relay pipe; using the kernel default"
            );
        }
    }

    let mut forward = Direction::new(a, b, a_pipe_read, a_pipe_write);
    let mut backward = Direction::new(b, a, b_pipe_read, b_pipe_write);
    let mut stats = RelayStats::default();
    let mut committed = 0_u64;
    let mut last_activity = Instant::now();
    let mut shutdown_started: Option<Instant> = None;
    let mut forward_first = true;

    loop {
        let now = Instant::now();
        let limit = inactivity_limit(config, shutdown_started.is_some());
        if now.saturating_duration_since(last_activity) >= limit {
            if shutdown_started.is_some() {
                break;
            }
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "relay idle timeout",
            ));
        }

        let mut activity = false;

        // Fill both pipes before draining them so neither direction waits for
        // the other to finish a full round.
        if forward_first {
            activity |= fill(
                &mut forward,
                WORK_PER_ROUND,
                config.max_bytes,
                &mut committed,
                &mut stats,
            )?;
            activity |= fill(
                &mut backward,
                WORK_PER_ROUND,
                config.max_bytes,
                &mut committed,
                &mut stats,
            )?;
        } else {
            activity |= fill(
                &mut backward,
                WORK_PER_ROUND,
                config.max_bytes,
                &mut committed,
                &mut stats,
            )?;
            activity |= fill(
                &mut forward,
                WORK_PER_ROUND,
                config.max_bytes,
                &mut committed,
                &mut stats,
            )?;
        }

        if config.max_bytes.is_some_and(|limit| committed >= limit) {
            forward.read_done = true;
            backward.read_done = true;
        }

        activity |= drain(&mut forward, WORK_PER_ROUND, &mut stats)?;
        activity |= drain(&mut backward, WORK_PER_ROUND, &mut stats)?;

        maybe_shutdown(&mut forward, &mut stats)?;
        maybe_shutdown(&mut backward, &mut stats)?;

        let now = Instant::now();
        if activity {
            last_activity = now;
        }
        if shutdown_started.is_none() && (forward.read_done || backward.read_done) {
            shutdown_started = Some(now);
            last_activity = now;
        }

        if forward.is_done() && backward.is_done() {
            break;
        }

        forward_first = !forward_first;

        let mut fds = [
            poll_source(&forward),
            poll_pipe_write(&forward),
            poll_sink(&forward),
            poll_source(&backward),
            poll_pipe_write(&backward),
            poll_sink(&backward),
        ];

        stats.polls = stats.polls.saturating_add(1);
        match poll(
            &mut fds,
            Some(inactivity_timeout(
                config,
                shutdown_started.is_some(),
                last_activity,
            )),
        ) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }

        let known = PollEvents::READ | PollEvents::WRITE | PollEvents::ERROR | PollEvents::HUP;
        for entry in &fds {
            if entry.revents().bits() & !known.bits() != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "relay poll reported an unexpected event",
                ));
            }
        }
    }

    stats.bytes_a_to_b = forward.bytes;
    stats.bytes_b_to_a = backward.bytes;
    Ok(stats)
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

    let mut progress = false;
    let mut remaining = budget;
    while remaining > 0 {
        let allowance = match max_bytes {
            Some(limit) => limit.saturating_sub(*committed),
            None => u64::MAX,
        };
        if allowance == 0 {
            direction.read_done = true;
            return Ok(progress);
        }

        let len = remaining.min(usize::try_from(allowance).unwrap_or(usize::MAX));
        if len == 0 {
            break;
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
                return Ok(true);
            }
            Ok(moved) => {
                direction.in_pipe = direction.in_pipe.saturating_add(moved);
                *committed = committed.saturating_add(u64::try_from(moved).unwrap_or(u64::MAX));
                remaining = remaining.saturating_sub(moved);
                progress = true;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                // `EAGAIN` can mean the source is empty or the pipe is full.
                // If the source still has data, the pipe must be full.
                direction.pipe_full =
                    direction.in_pipe > 0 && source_has_data(direction.source, stats)?;
                return Ok(progress);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => return Ok(progress),
            Err(error) => return Err(error),
        }
    }

    Ok(progress)
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

fn inactivity_timeout(
    config: &RelayConfig,
    shutting_down: bool,
    last_activity: Instant,
) -> Duration {
    inactivity_limit(config, shutting_down)
        .saturating_sub(Instant::now().saturating_duration_since(last_activity))
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_PIPE_SIZE, MAX_PIPE_SIZE, MIN_PIPE_SIZE, RelayConfig, RelayStats,
        copy_bidirectional,
    };
    use std::io::{self, Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
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
                copy_bidirectional(relay_a.as_raw_fd(), relay_b.as_raw_fd(), &config)
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
    fn copies_large_payload_in_both_directions() {
        let (mut client, relay_a, relay_b, mut target) = relay_pair();
        let receiver = run_relay(relay_a, relay_b, config());

        let payload_a = vec![0xa5; 2 * 1024 * 1024 + 17];
        let payload_b = vec![0x5a; 1024 * 1024 + 3];
        let expected_a = payload_a.clone();
        let expected_b = payload_b.clone();

        let mut client_writer = client.try_clone().unwrap();
        let mut target_writer = target.try_clone().unwrap();
        let client_thread = thread::spawn(move || {
            client_writer.write_all(&payload_a).unwrap();
            client_writer.shutdown(Shutdown::Write).unwrap();
        });
        let target_thread = thread::spawn(move || {
            target_writer.write_all(&payload_b).unwrap();
            target_writer.shutdown(Shutdown::Write).unwrap();
        });

        let mut received_a = Vec::new();
        target.read_to_end(&mut received_a).unwrap();
        let mut received_b = Vec::new();
        client.read_to_end(&mut received_b).unwrap();

        client_thread.join().unwrap();
        target_thread.join().unwrap();

        let stats = wait(receiver).unwrap();
        assert_eq!(received_a, expected_a);
        assert_eq!(received_b, expected_b);
        assert_eq!(stats.bytes_a_to_b, expected_a.len() as u64);
        assert_eq!(stats.bytes_b_to_a, expected_b.len() as u64);
        assert_eq!(
            stats.total_bytes(),
            (expected_a.len() + expected_b.len()) as u64
        );
        assert_eq!(stats.eofs, 2);
        assert_eq!(stats.half_closes, 2);
        assert!(stats.splice_calls > 0);
        assert!(stats.polls > 0);
    }

    #[test]
    fn half_close_keeps_the_other_direction_alive() {
        let (mut client, relay_a, relay_b, target) = relay_pair();
        let receiver = run_relay(relay_a, relay_b, config());

        let mut client_writer = client.try_clone().unwrap();
        let client_thread = thread::spawn(move || {
            client_writer.write_all(b"request").unwrap();
            client_writer.shutdown(Shutdown::Write).unwrap();
        });

        let target_thread = thread::spawn(move || {
            let mut target = target;
            let mut request = Vec::new();
            target.read_to_end(&mut request).unwrap();
            assert_eq!(request, b"request");
            target.write_all(b"response").unwrap();
            target.shutdown(Shutdown::Write).unwrap();
        });

        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();

        client_thread.join().unwrap();
        target_thread.join().unwrap();

        let stats = wait(receiver).unwrap();
        assert_eq!(response, b"response");
        assert_eq!(stats.bytes_a_to_b, b"request".len() as u64);
        assert_eq!(stats.bytes_b_to_a, b"response".len() as u64);
        assert_eq!(stats.eofs, 2);
        assert_eq!(stats.half_closes, 2);
    }

    #[test]
    fn nonblocking_streams_relay_without_waiting_for_the_other_direction() {
        let (mut client, relay_a, relay_b, mut target) = relay_pair();
        let receiver = run_relay(relay_a, relay_b, config());

        client.write_all(b"one-way").unwrap();
        client.shutdown(Shutdown::Write).unwrap();

        let mut received = Vec::new();
        target.read_to_end(&mut received).unwrap();
        assert_eq!(received, b"one-way");

        target.shutdown(Shutdown::Write).unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert!(reply.is_empty());

        let stats = wait(receiver).unwrap();
        assert_eq!(stats.bytes_a_to_b, 7);
        assert_eq!(stats.bytes_b_to_a, 0);
        assert_eq!(stats.eofs, 2);
        assert_eq!(stats.half_closes, 2);
    }

    #[test]
    fn relays_over_tcp_loopback() {
        let (mut client, relay_a) = tcp_pair();
        let (relay_b, mut target) = tcp_pair();
        let receiver = run_relay(relay_a, relay_b, config());

        let mut client_writer = client.try_clone().unwrap();
        let client_thread = thread::spawn(move || {
            client_writer.write_all(b"hello").unwrap();
            client_writer.shutdown(Shutdown::Write).unwrap();
        });

        let target_thread = thread::spawn(move || {
            let mut request = Vec::new();
            target.read_to_end(&mut request).unwrap();
            assert_eq!(request, b"hello");
            target.write_all(b"world").unwrap();
            target.shutdown(Shutdown::Write).unwrap();
        });

        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();

        client_thread.join().unwrap();
        target_thread.join().unwrap();

        let stats = wait(receiver).unwrap();
        assert_eq!(response, b"world");
        assert_eq!(stats.bytes_a_to_b, 5);
        assert_eq!(stats.bytes_b_to_a, 5);
        assert_eq!(stats.eofs, 2);
        assert_eq!(stats.half_closes, 2);
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
    fn shutdown_timeout_bounds_a_half_closed_idle_connection() {
        let (mut client, relay_a, relay_b, mut target) = relay_pair();
        let started = Instant::now();
        let receiver = run_relay(
            relay_a,
            relay_b,
            RelayConfig {
                idle_timeout: Duration::from_secs(60),
                shutdown_timeout: Duration::from_millis(50),
                ..config()
            },
        );

        client.write_all(b"x").unwrap();
        client.shutdown(Shutdown::Write).unwrap();

        let mut received = Vec::new();
        target.read_to_end(&mut received).unwrap();
        assert_eq!(received, b"x");

        let stats = wait(receiver).unwrap();
        let elapsed = started.elapsed();

        assert_eq!(stats.bytes_a_to_b, 1);
        assert_eq!(stats.bytes_b_to_a, 0);
        assert_eq!(stats.eofs, 1);
        assert_eq!(stats.half_closes, 1);
        assert!(elapsed >= Duration::from_millis(30));
        assert!(elapsed < Duration::from_secs(2));
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

        let mut reply = Vec::new();
        match client.read_to_end(&mut reply) {
            Ok(_) => assert!(reply.is_empty()),
            // The relay stopped reading at the cap, so its close can reset the
            // peer while unread bytes remain in the receive queue.
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
            Err(error) => panic!("unexpected client read error: {error}"),
        }

        let stats = wait(receiver).unwrap();
        assert_eq!(stats.bytes_a_to_b, 1024);
        assert_eq!(stats.bytes_b_to_a, 0);
        assert_eq!(stats.total_bytes(), 1024);
        assert_eq!(stats.half_closes, 2);
    }

    #[test]
    fn immediate_eof_shuts_down_both_destinations() {
        let (client, relay_a, relay_b, target) = relay_pair();
        let receiver = run_relay(relay_a, relay_b, config());

        client.shutdown(Shutdown::Write).unwrap();
        target.shutdown(Shutdown::Write).unwrap();

        let stats = wait(receiver).unwrap();
        assert_eq!(stats.bytes_a_to_b, 0);
        assert_eq!(stats.bytes_b_to_a, 0);
        assert_eq!(stats.eofs, 2);
        assert_eq!(stats.half_closes, 2);
    }

    #[test]
    fn ping_is_not_starved_by_one_way_bulk() {
        let (mut client, relay_a, relay_b, mut target) = relay_pair();
        let receiver = run_relay(relay_a, relay_b, config());

        let bulk = vec![0x33; 8 * 1024 * 1024];
        let bulk_len = bulk.len();
        let mut client_writer = client.try_clone().unwrap();
        let mut target_writer = target.try_clone().unwrap();

        let bulk_thread = thread::spawn(move || {
            client_writer.write_all(&bulk).unwrap();
            client_writer.shutdown(Shutdown::Write).unwrap();
        });
        let ping_thread = thread::spawn(move || {
            target_writer.write_all(b"ping").unwrap();
            target_writer.shutdown(Shutdown::Write).unwrap();
        });

        // Let the bulk direction fill the pipe and the target's receive
        // buffer. The ping must still arrive while that direction is blocked.
        thread::sleep(Duration::from_millis(50));

        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut ping = [0_u8; 4];
        client.read_exact(&mut ping).unwrap();
        client.set_read_timeout(None).unwrap();
        assert_eq!(&ping, b"ping");

        let mut tail = Vec::new();
        client.read_to_end(&mut tail).unwrap();
        let mut received_bulk = Vec::new();
        target.read_to_end(&mut received_bulk).unwrap();

        bulk_thread.join().unwrap();
        ping_thread.join().unwrap();

        let stats = wait(receiver).unwrap();
        assert_eq!(received_bulk.len(), bulk_len);
        assert!(received_bulk.iter().all(|&byte| byte == 0x33));
        assert_eq!(stats.bytes_a_to_b, bulk_len as u64);
        assert_eq!(stats.bytes_b_to_a, 4);
        assert_eq!(stats.eofs, 2);
        assert_eq!(stats.half_closes, 2);
    }

    #[test]
    fn invalid_pipe_sizes_are_rejected() {
        let (a, b) = UnixStream::pair().unwrap();

        for pipe_size in [0, 1, 1000, MIN_PIPE_SIZE / 2, MAX_PIPE_SIZE * 2] {
            let config = RelayConfig {
                pipe_size,
                ..RelayConfig::default()
            };
            let error = copy_bidirectional(a.as_raw_fd(), b.as_raw_fd(), &config).unwrap_err();
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
    fn total_bytes_saturates() {
        let stats = RelayStats {
            bytes_a_to_b: u64::MAX,
            bytes_b_to_a: 1,
            ..RelayStats::default()
        };

        assert_eq!(stats.total_bytes(), u64::MAX);
    }
}
