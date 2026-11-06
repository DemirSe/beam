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
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;
use tokio::task::JoinError;

/// Default number of concurrent blocking resolver jobs.
///
/// With the default 160-thread blocking pool and 120 splice permits, this
/// leaves room for the resolver without starving splice handoffs.
pub const DEFAULT_MAX_CONCURRENT_RESOLVES: usize = 32;

/// A process-wide bounded resolver.
#[derive(Clone, Debug)]
pub struct Resolver {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    permits: Arc<Semaphore>,
    max: usize,
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
        Self {
            inner: Arc::new(Inner {
                permits: Arc::new(Semaphore::new(max)),
                max,
            }),
        }
    }

    /// Returns the configured concurrency limit.
    #[must_use]
    pub fn max(&self) -> usize {
        self.inner.max
    }

    /// Returns the number of unused resolver slots.
    ///
    /// This is intended for diagnostics and tests; it is not a reservation.
    #[must_use]
    pub fn available_permits(&self) -> usize {
        self.inner.permits.available_permits()
    }

    /// Resolves a hostname under the process-wide concurrency limit.
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
        let host = host.to_owned();
        self.lookup_with(timeout, move || {
            (host.as_str(), port)
                .to_socket_addrs()
                .map(|addresses| addresses.collect())
        })
        .await
    }

    /// Runs one test-visible blocking lookup closure.
    ///
    /// The closure owns the resolver permit, so a timeout cannot free the
    /// slot while the synthetic or real resolver is still running.
    async fn lookup_with<F>(
        &self,
        timeout: Duration,
        lookup: F,
    ) -> Result<Vec<SocketAddr>, ResolverError>
    where
        F: FnOnce() -> io::Result<Vec<SocketAddr>> + Send + 'static,
    {
        let permit = Arc::clone(&self.inner.permits)
            .try_acquire_owned()
            .map_err(|_| ResolverError::Busy)?;
        let task = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            lookup()
        });

        match tokio::time::timeout(timeout, task).await {
            Ok(Ok(Ok(addresses))) => Ok(addresses),
            Ok(Ok(Err(error))) => Err(ResolverError::Io(error)),
            Ok(Err(error)) => Err(ResolverError::Join(error)),
            Err(_) => Err(ResolverError::Timeout),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Resolver, ResolverError};
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
        println!("bounded policy: max_concurrent={maximum} busy={busy}");
        assert_eq!(maximum, 8, "only eight lookups may run concurrently");
        assert_eq!(busy, 56, "the remaining lookups must be rejected");
    }

    #[tokio::test]
    async fn default_policy_caps_at_32() {
        let (maximum, busy) =
            observe_concurrency(crate::resolver::DEFAULT_MAX_CONCURRENT_RESOLVES, 64).await;
        println!("default policy: max_concurrent={maximum} busy={busy}");
        assert_eq!(maximum, 32);
        assert_eq!(busy, 32);
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
}
