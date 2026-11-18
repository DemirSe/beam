//! Bounded DNS lookups shared by the TCP dial, XUDP, and legacy UDP paths.
//!
//! `tokio::net::lookup_host` runs `getaddrinfo` on the blocking pool. A caller
//! timeout cancels only the caller's wait: the blocking job keeps running
//! until the resolver returns. During a resolver outage those orphaned jobs
//! compete with relay work for the same pool. Each lookup therefore holds a
//! process-wide admission permit inside its own task, and the permit is
//! released only when the blocking job finishes, so one outage is bounded at
//! [`MAX_CONCURRENT_JOBS`] jobs instead of the blocking-pool size.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};

use tokio::net::lookup_host;
use tokio::sync::Semaphore;
use tokio::time::{Instant, timeout_at};

/// Blocking resolver jobs allowed to run at the same time process-wide.
///
/// The TCP dial, XUDP, and legacy UDP share this budget. It is small enough
/// that a resolver outage leaves blocking threads for relay work, and large
/// enough for a browser's parallel connection burst.
const MAX_CONCURRENT_JOBS: usize = 32;

fn limiter() -> &'static Arc<Semaphore> {
    static LIMITER: OnceLock<Arc<Semaphore>> = OnceLock::new();
    LIMITER.get_or_init(|| Arc::new(Semaphore::new(MAX_CONCURRENT_JOBS)))
}

/// Resolves `host:port` before `deadline` and holds a DNS admission permit
/// until the blocking job really finishes.
///
/// A numeric literal returns directly: it needs no `getaddrinfo`, so a full
/// admission budget (or a resolver outage) must never delay an IP target.
///
/// A [`io::ErrorKind::TimedOut`] error releases the caller, not the job: the
/// job keeps its permit and exits on its own, so many slow lookups
/// backpressure new ones instead of growing the blocking pool. Resolver
/// failures keep their own error kind.
pub async fn lookup_host_until(
    host: &str,
    port: u16,
    deadline: Instant,
) -> io::Result<Vec<SocketAddr>> {
    if let Ok(address) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(address, port)]);
    }
    let host = host.to_owned();
    admitted_lookup(Arc::clone(limiter()), deadline, move || async move {
        lookup_host((host.as_str(), port))
            .await
            .map(|addresses| addresses.collect::<Vec<_>>())
    })
    .await
}

/// Runs one resolver job under an admission permit.
///
/// The spawned task owns the permit, so a caller that gives up cannot release
/// it while the job is still running. The job is a parameter so tests can
/// synchronize one instead of depending on a real stalled resolver.
async fn admitted_lookup<F, Fut>(
    limiter: Arc<Semaphore>,
    deadline: Instant,
    job: F,
) -> io::Result<Vec<SocketAddr>>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = io::Result<Vec<SocketAddr>>> + Send + 'static,
{
    let permit = timeout_at(deadline, limiter.acquire_owned())
        .await
        .map_err(|_| timed_out())?
        .map_err(|_| io::Error::other("DNS admission limiter closed"))?;
    let mut job = tokio::spawn(async move {
        let _permit = permit;
        job().await
    });
    match timeout_at(deadline, &mut job).await {
        Ok(joined) => joined.map_err(|error| io::Error::other(error.to_string()))?,
        Err(_) => Err(timed_out()),
    }
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "DNS lookup deadline elapsed")
}

/// Holds every admission permit so a test can prove a path bypasses the
/// limiter. The permit is released when the caller drops it.
#[cfg(test)]
pub(crate) async fn hold_all_permits_for_test() -> tokio::sync::OwnedSemaphorePermit {
    Arc::clone(limiter())
        .acquire_many_owned(MAX_CONCURRENT_JOBS as u32)
        .await
        .expect("the DNS admission limiter is open")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;
    use std::time::Duration;

    #[tokio::test]
    async fn resolves_a_local_name_before_the_deadline() {
        let deadline = Instant::now() + Duration::from_secs(5);
        let addresses = lookup_host_until("localhost", 80, deadline)
            .await
            .expect("localhost must resolve");
        assert!(!addresses.is_empty(), "a resolved name has an address");
    }

    #[tokio::test]
    async fn an_exhausted_budget_reports_a_timeout() {
        // Hold every permit so the next lookup waits instead of resolving.
        let held = hold_all_permits_for_test().await;
        let deadline = Instant::now() + Duration::from_millis(20);
        let error = lookup_host_until("localhost", 80, deadline)
            .await
            .expect_err("a full DNS budget must not resolve");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        drop(held);
    }

    #[tokio::test]
    async fn numeric_literals_bypass_an_exhausted_budget() {
        let held = hold_all_permits_for_test().await;
        let deadline = Instant::now() + Duration::from_millis(20);
        assert_eq!(
            lookup_host_until("127.0.0.1", 443, deadline)
                .await
                .expect("an IPv4 literal needs no resolver job"),
            vec![SocketAddr::from(([127, 0, 0, 1], 443))]
        );
        assert_eq!(
            lookup_host_until("::1", 443, deadline)
                .await
                .expect("an IPv6 literal needs no resolver job"),
            vec![SocketAddr::from((Ipv6Addr::LOCALHOST, 443))]
        );
        drop(held);
    }

    #[tokio::test]
    async fn a_cancelled_caller_keeps_the_permit_until_the_job_ends() {
        let limiter = Arc::new(Semaphore::new(1));
        let (release, wait) = tokio::sync::oneshot::channel::<()>();
        let caller = tokio::spawn(admitted_lookup(
            Arc::clone(&limiter),
            Instant::now() + Duration::from_secs(30),
            move || async move {
                let _ = wait.await;
                Ok(vec![SocketAddr::from(([127, 0, 0, 1], 53))])
            },
        ));
        // Let the job acquire the permit and block.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(limiter.available_permits(), 0);
        caller.abort();
        let _ = caller.await;
        assert_eq!(
            limiter.available_permits(),
            0,
            "cancelling the caller must not release the job's permit"
        );
        release.send(()).expect("the job is still waiting");
        timeout_at(Instant::now() + Duration::from_secs(5), async {
            while limiter.available_permits() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the permit returns only after the job ends");
    }

    #[tokio::test]
    async fn a_timed_out_caller_keeps_the_permit_until_the_job_ends() {
        let limiter = Arc::new(Semaphore::new(1));
        let (release, wait) = tokio::sync::oneshot::channel::<()>();
        let deadline = Instant::now() + Duration::from_millis(20);
        let error = admitted_lookup(Arc::clone(&limiter), deadline, move || async move {
            let _ = wait.await;
            Ok(vec![SocketAddr::from(([127, 0, 0, 1], 53))])
        })
        .await
        .expect_err("the caller deadline elapses before the job ends");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(
            limiter.available_permits(),
            0,
            "the blocking job still owns the admission permit"
        );
        release.send(()).expect("the job is still waiting");
        timeout_at(Instant::now() + Duration::from_secs(5), async {
            while limiter.available_permits() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the permit returns only after the job ends");
    }
}
