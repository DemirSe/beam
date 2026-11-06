//! Process-wide bounded resolver for blocking DNS lookups.
//!
//! `lookup_host` uses `getaddrinfo`, which runs on Tokio's shared blocking
//! pool. Without an explicit bound, a burst of authenticated destination
//! lookups can queue an arbitrary number of blocking jobs behind the splice
//! tasks and delay unrelated relay work. This type admits a fixed number of
//! lookups at a time and rejects excess work immediately.
//!
//! The permit is moved into the blocking closure. A timeout therefore stops
//! the caller from waiting, but does not release the slot until the blocking
//! resolver actually returns. That is deliberate: `getaddrinfo` cannot be
//! cancelled safely, and releasing the slot early would recreate the same
//! unbounded pool pressure.

use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;
use tokio::task::JoinError;

/// Default number of concurrent blocking resolver jobs.
///
/// With the default 160-thread blocking pool and 120 splice permits, this
/// leaves room for the resolver without starving splice handoffs.
pub const DEFAULT_MAX_CONCURRENT_RESOLVES: usize = 32;

/// Slots reserved for cover dials when normal destination lookups saturate.
const DEFAULT_COVER_RESERVE: usize = 4;

/// Who is asking for a lookup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolverPriority {
    /// Normal target, XUDP, or legacy UDP lookup.
    Normal,
    /// Cover-dial lookup; may use the small emergency reserve.
    Cover,
}

/// A process-wide bounded resolver.
#[derive(Clone, Debug)]
pub struct Resolver {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    normal: Arc<Semaphore>,
    cover: Arc<Semaphore>,
    max: usize,
    in_flight: AtomicUsize,
    timeouts: AtomicU64,
    last_timeout_log: Mutex<Option<Instant>>,
}

/// Failure while resolving a hostname.
#[derive(Debug, thiserror::Error)]
pub enum ResolverError {
    /// Every resolver slot is occupied.
    #[error("resolver concurrency limit reached")]
    Busy,
    /// The caller's deadline elapsed.
    #[error("resolver timed out")]
    Timeout,
    /// The platform resolver failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// The blocking resolver task failed.
    #[error(transparent)]
    Join(#[from] JoinError),
}

impl Default for Resolver {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_CONCURRENT_RESOLVES)
    }
}

impl Resolver {
    /// Creates a resolver with at least one slot.
    #[must_use]
    pub fn new(max: usize) -> Self {
        let max = max.max(1);
        let cover = if max > 1 {
            (max / 8).clamp(1, DEFAULT_COVER_RESERVE).min(max - 1)
        } else {
            0
        };
        let normal = max - cover;
        Self {
            inner: Arc::new(Inner {
                normal: Arc::new(Semaphore::new(normal)),
                cover: Arc::new(Semaphore::new(cover)),
                max,
                in_flight: AtomicUsize::new(0),
                timeouts: AtomicU64::new(0),
                last_timeout_log: Mutex::new(None),
            }),
        }
    }

    /// Returns the configured total concurrency limit.
    #[must_use]
    pub fn max(&self) -> usize {
        self.inner.max
    }

    /// Returns the number of unused resolver slots.
    ///
    /// This is intended for diagnostics and tests; it is not a reservation.
    #[must_use]
    pub fn available_permits(&self) -> usize {
        self.inner.normal.available_permits() + self.inner.cover.available_permits()
    }

    /// Returns a point-in-time resolver snapshot.
    #[must_use]
    pub fn stats(&self) -> ResolverStats {
        ResolverStats {
            max: self.inner.max,
            normal_available: self.inner.normal.available_permits(),
            cover_available: self.inner.cover.available_permits(),
            in_flight: self.inner.in_flight.load(Ordering::Relaxed),
            timeouts: self.inner.timeouts.load(Ordering::Relaxed),
        }
    }

    /// Resolves a normal target hostname.
    ///
    /// The timeout bounds how long the caller waits. If the timeout expires,
    /// the blocking resolver may continue to hold its slot until the platform
    /// resolver returns.
    pub async fn lookup_host(
        &self,
        host: &str,
        port: u16,
        timeout: Duration,
    ) -> Result<Vec<SocketAddr>, ResolverError> {
        self.lookup_host_priority(host, port, timeout, ResolverPriority::Normal)
            .await
    }

    /// Resolves a hostname with an explicit priority.
    ///
    /// Cover dials are allowed to use a small emergency lane after normal
    /// destination lookups saturate. Normal target, XUDP, and legacy UDP
    /// lookups cannot consume that lane.
    pub async fn lookup_host_priority(
        &self,
        host: &str,
        port: u16,
        timeout: Duration,
        priority: ResolverPriority,
    ) -> Result<Vec<SocketAddr>, ResolverError> {
        let host = host.to_owned();
        self.lookup_with_priority(priority, timeout, move || {
            (host.as_str(), port)
                .to_socket_addrs()
                .map(|addresses| addresses.collect())
        })
        .await
    }

    /// Runs one test-visible blocking lookup closure.
    #[cfg(test)]
    async fn lookup_with<F>(
        &self,
        timeout: Duration,
        lookup: F,
    ) -> Result<Vec<SocketAddr>, ResolverError>
    where
        F: FnOnce() -> io::Result<Vec<SocketAddr>> + Send + 'static,
    {
        self.lookup_with_priority(ResolverPriority::Normal, timeout, lookup)
            .await
    }

    /// Runs one blocking lookup while holding the global and activity guards
    /// until the platform resolver actually returns.
    async fn lookup_with_priority<F>(
        &self,
        priority: ResolverPriority,
        timeout: Duration,
        lookup: F,
    ) -> Result<Vec<SocketAddr>, ResolverError>
    where
        F: FnOnce() -> io::Result<Vec<SocketAddr>> + Send + 'static,
    {
        let permit = self.try_acquire(priority).ok_or(ResolverError::Busy)?;
        let in_flight = InFlightGuard {
            inner: Arc::clone(&self.inner),
        };
        self.inner.in_flight.fetch_add(1, Ordering::Relaxed);

        let task = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _in_flight = in_flight;
            lookup()
        });

        match tokio::time::timeout(timeout, task).await {
            Ok(Ok(Ok(addresses))) => Ok(addresses),
            Ok(Ok(Err(error))) => Err(ResolverError::Io(error)),
            Ok(Err(error)) => Err(ResolverError::Join(error)),
            Err(_) => {
                self.note_timeout();
                Err(ResolverError::Timeout)
            }
        }
    }

    fn try_acquire(&self, priority: ResolverPriority) -> Option<tokio::sync::OwnedSemaphorePermit> {
        match priority {
            ResolverPriority::Normal => Arc::clone(&self.inner.normal).try_acquire_owned().ok(),
            ResolverPriority::Cover => Arc::clone(&self.inner.cover)
                .try_acquire_owned()
                .ok()
                .or_else(|| Arc::clone(&self.inner.normal).try_acquire_owned().ok()),
        }
    }

    fn note_timeout(&self) {
        let timeouts = self.inner.timeouts.fetch_add(1, Ordering::Relaxed) + 1;
        let now = Instant::now();
        let due = {
            let mut last = lock(&self.inner.last_timeout_log);
            if last.is_some_and(|previous| now.duration_since(previous) < Duration::from_secs(30)) {
                false
            } else {
                *last = Some(now);
                true
            }
        };
        if due {
            tracing::warn!(
                in_flight = self.inner.in_flight.load(Ordering::Relaxed),
                normal_available = self.inner.normal.available_permits(),
                cover_available = self.inner.cover.available_permits(),
                timeouts,
                "resolver lookup timed out; its blocking slot remains reserved"
            );
        }
    }
}

/// A point-in-time resolver snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolverStats {
    /// Configured total concurrency limit.
    pub max: usize,
    /// Available normal slots.
    pub normal_available: usize,
    /// Available cover emergency slots.
    pub cover_available: usize,
    /// Blocking lookups currently occupying a slot.
    pub in_flight: usize,
    /// Lookups whose caller deadline expired.
    pub timeouts: u64,
}

/// Decrements the in-flight gauge when the blocking lookup returns.
struct InFlightGuard {
    inner: Arc<Inner>,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.inner.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::{Resolver, ResolverError, ResolverPriority};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};
    use tokio::time::sleep;

    /// Observes the maximum number of concurrent blocking lookups.
    async fn observe_concurrency(limit: usize, lookups: usize) -> (usize, usize) {
        let resolver = Resolver::new(limit);
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let busy = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(AtomicBool::new(false));
        let mut handles = Vec::new();

        for _ in 0..lookups {
            let resolver = resolver.clone();
            let active = Arc::clone(&active);
            let maximum = Arc::clone(&maximum);
            let busy = Arc::clone(&busy);
            let release = Arc::clone(&release);
            handles.push(tokio::spawn(async move {
                let result = resolver
                    .lookup_with(Duration::from_secs(2), move || {
                        let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                        maximum.fetch_max(current, Ordering::SeqCst);
                        while !release.load(Ordering::SeqCst) {
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        active.fetch_sub(1, Ordering::SeqCst);
                        Ok(Vec::new())
                    })
                    .await;
                if matches!(result, Err(ResolverError::Busy)) {
                    busy.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }

        // Wait until every task has either acquired a slot or observed Busy.
        let deadline = Instant::now() + Duration::from_secs(2);
        while active.load(Ordering::SeqCst) + busy.load(Ordering::SeqCst) < lookups
            && Instant::now() < deadline
        {
            sleep(Duration::from_millis(1)).await;
        }
        let maximum = maximum.load(Ordering::SeqCst);
        let busy = busy.load(Ordering::SeqCst);
        release.store(true, Ordering::SeqCst);
        for handle in handles {
            handle.await.expect("resolver test task");
        }
        (maximum, busy)
    }

    #[tokio::test]
    async fn unbounded_policy_admits_all_blocking_lookups() {
        // This is the old policy represented through a high limit: no
        // practical admission cap for the test's 64 lookups.
        let (maximum, busy) = observe_concurrency(1024, 64).await;
        println!("unbounded policy: max_concurrent={maximum} busy={busy}");
        assert_eq!(maximum, 64, "unbounded resolver should admit every lookup");
        assert_eq!(busy, 0);
    }

    #[tokio::test]
    async fn bounded_policy_caps_blocking_lookups() {
        let (maximum, busy) = observe_concurrency(8, 64).await;
        println!("bounded policy: normal_max={maximum} busy={busy}");
        assert_eq!(
            maximum, 7,
            "normal lookups must leave the cover reserve free"
        );
        assert_eq!(busy, 57, "the remaining normal lookups must be rejected");
    }

    #[tokio::test]
    async fn default_policy_caps_at_32() {
        let (maximum, busy) =
            observe_concurrency(crate::resolver::DEFAULT_MAX_CONCURRENT_RESOLVES, 64).await;
        println!("default policy: normal_max={maximum} busy={busy}");
        assert_eq!(maximum, 28, "28 normal slots plus four cover slots");
        assert_eq!(busy, 36);
    }

    #[tokio::test]
    async fn timeout_keeps_the_blocking_slot_until_lookup_finishes() {
        let resolver = Resolver::new(1);
        let (started, started_rx) = tokio::sync::oneshot::channel();

        let first = resolver.lookup_with(Duration::from_millis(20), move || {
            let _ = started.send(());
            std::thread::sleep(Duration::from_millis(250));
            Ok(Vec::new())
        });
        assert!(matches!(first.await, Err(ResolverError::Timeout)));
        started_rx.await.expect("blocking lookup did not start");

        assert!(matches!(
            resolver
                .lookup_with(Duration::from_millis(20), || Ok(Vec::new()))
                .await,
            Err(ResolverError::Busy)
        ));

        sleep(Duration::from_millis(300)).await;
        resolver
            .lookup_with(Duration::from_secs(1), || Ok(Vec::new()))
            .await
            .expect("slot should be released after the blocking resolver returns");
    }

    #[tokio::test]
    async fn same_host_lookups_use_more_than_four_slots() {
        let resolver = Resolver::new(8);
        let mut tasks = Vec::new();
        for _ in 0..5 {
            let resolver = resolver.clone();
            tasks.push(tokio::spawn(async move {
                resolver
                    .lookup_host_priority(
                        "localhost",
                        9,
                        Duration::from_secs(5),
                        ResolverPriority::Normal,
                    )
                    .await
            }));
        }
        for task in tasks {
            task.await
                .expect("same-host lookup task")
                .expect("same host must not have a four-lookup cap");
        }
        println!("same-host policy: 5 concurrent lookups accepted");
    }

    #[tokio::test]
    async fn cover_lookup_uses_the_reserved_lane() {
        let resolver = Resolver::new(8);
        let held: Vec<_> = (0..7)
            .map(|_| {
                Arc::clone(&resolver.inner.normal)
                    .try_acquire_owned()
                    .expect("normal reserve")
            })
            .collect();
        let (started, started_rx) = tokio::sync::oneshot::channel();
        let (release, release_rx) = std::sync::mpsc::channel();
        let cover_resolver = resolver.clone();
        let cover = tokio::spawn(async move {
            cover_resolver
                .lookup_with_priority(ResolverPriority::Cover, Duration::from_secs(2), move || {
                    let _ = started.send(());
                    let _ = release_rx.recv_timeout(Duration::from_secs(1));
                    Ok(Vec::new())
                })
                .await
        });
        started_rx.await.expect("cover lookup did not start");
        assert_eq!(resolver.inner.normal.available_permits(), 0);
        assert_eq!(resolver.inner.cover.available_permits(), 0);
        println!("cover lane: normal=0 cover=0 second_cover=Busy");

        assert!(matches!(
            resolver
                .lookup_with_priority(ResolverPriority::Cover, Duration::from_secs(1), || Ok(
                    Vec::new()
                ),)
                .await,
            Err(ResolverError::Busy)
        ));
        release.send(()).expect("release cover lookup");
        cover
            .await
            .expect("cover lookup task")
            .expect("cover lookup result");
        drop(held);
    }

    #[tokio::test]
    async fn timeout_is_counted_for_watchdog() {
        let resolver = Resolver::new(1);
        let result = resolver
            .lookup_with(Duration::from_millis(10), || {
                std::thread::sleep(Duration::from_millis(50));
                Ok(Vec::new())
            })
            .await;
        assert!(matches!(result, Err(ResolverError::Timeout)));
        assert_eq!(resolver.stats().timeouts, 1);
    }
}
