//! Bounded per-source admission limits.
//!
//! A process-wide semaphore alone lets one source hold every permit. The
//! limiter keeps the global bound and adds a per-IP bound so a scanner cannot
//! deny admission to every other peer. The map is bounded by the global permit
//! count because an entry is removed as soon as its last permit is released.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Why an [`IpLimiter`] rejected a permit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpLimitReject {
    /// The process-wide permit pool is exhausted.
    Global,
    /// This source already holds its per-IP share.
    PerIp,
}

/// A process-wide and per-source permit limiter.
#[derive(Debug)]
pub struct IpLimiter {
    global: Arc<Semaphore>,
    per_ip: Mutex<HashMap<IpAddr, u32>>,
    max_per_ip: u32,
}

impl IpLimiter {
    /// Creates a limiter with a global bound and a per-IP bound.
    ///
    /// `max_global` must be non-zero. `max_per_ip` is clamped to the global
    /// bound by the caller; zero rejects every source.
    #[must_use]
    pub fn new(max_global: usize, max_per_ip: u32) -> Self {
        Self {
            global: Arc::new(Semaphore::new(max_global)),
            per_ip: Mutex::new(HashMap::new()),
            max_per_ip,
        }
    }

    /// Reserves one global and one per-IP permit.
    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Result<IpPermit, IpLimitReject> {
        if self.max_per_ip == 0 {
            return Err(IpLimitReject::PerIp);
        }
        // A dual-stack listener can report the same IPv4 source as either
        // `1.2.3.4` or `::ffff:1.2.3.4`; both must share one per-IP bucket.
        let ip = ip.to_canonical();
        let global = self
            .global
            .clone()
            .try_acquire_owned()
            .map_err(|_| IpLimitReject::Global)?;
        {
            let mut counts = lock(&self.per_ip);
            match counts.get_mut(&ip) {
                Some(count) if *count >= self.max_per_ip => {
                    return Err(IpLimitReject::PerIp);
                }
                Some(count) => *count += 1,
                None => {
                    counts.insert(ip, 1);
                }
            }
        }
        Ok(IpPermit {
            limiter: Arc::clone(self),
            ip,
            _global: global,
        })
    }

    /// Returns the number of unused global permits.
    #[must_use]
    pub fn available_permits(&self) -> usize {
        self.global.available_permits()
    }

    /// Returns the number of currently tracked source addresses.
    #[cfg(test)]
    fn tracked_ips(&self) -> usize {
        lock(&self.per_ip).len()
    }
}

/// One reserved global and per-IP permit.
#[derive(Debug)]
pub struct IpPermit {
    limiter: Arc<IpLimiter>,
    ip: IpAddr,
    _global: OwnedSemaphorePermit,
}

impl Drop for IpPermit {
    fn drop(&mut self) {
        let mut counts = lock(&self.limiter.per_ip);
        if let Some(count) = counts.get_mut(&self.ip) {
            *count -= 1;
            if *count == 0 {
                counts.remove(&self.ip);
            }
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, last])
    }

    #[test]
    fn enforces_the_global_limit() {
        let limiter = Arc::new(IpLimiter::new(2, 1));
        let first = limiter.try_acquire(ip(1)).expect("first permit");
        let second = limiter.try_acquire(ip(2)).expect("second permit");
        assert_eq!(
            limiter.try_acquire(ip(3)).expect_err("global limit"),
            IpLimitReject::Global
        );
        drop(first);
        assert!(limiter.try_acquire(ip(3)).is_ok());
        drop(second);
    }

    #[test]
    fn enforces_the_per_ip_limit() {
        let limiter = Arc::new(IpLimiter::new(4, 2));
        let first = limiter.try_acquire(ip(1)).expect("first permit");
        let second = limiter.try_acquire(ip(1)).expect("second permit");
        assert_eq!(
            limiter.try_acquire(ip(1)).expect_err("per-IP limit"),
            IpLimitReject::PerIp
        );
        assert!(limiter.try_acquire(ip(2)).is_ok());
        drop(first);
        assert!(limiter.try_acquire(ip(1)).is_ok());
        drop(second);
    }

    #[test]
    fn zero_per_ip_limit_rejects_every_source_without_consuming_global() {
        let limiter = Arc::new(IpLimiter::new(2, 0));
        assert_eq!(
            limiter.try_acquire(ip(1)).expect_err("zero per-IP limit"),
            IpLimitReject::PerIp
        );
        assert_eq!(
            limiter.try_acquire(ip(2)).expect_err("zero per-IP limit"),
            IpLimitReject::PerIp
        );
        assert_eq!(limiter.available_permits(), 2);
        assert_eq!(limiter.tracked_ips(), 0);
    }

    #[test]
    fn ipv4_mapped_and_plain_sources_share_one_bucket() {
        let limiter = Arc::new(IpLimiter::new(4, 1));
        let v4 = IpAddr::from([10, 0, 0, 1]);
        let mapped: IpAddr = "::ffff:10.0.0.1".parse().expect("mapped address");
        let permit = limiter.try_acquire(v4).expect("IPv4 permit");
        assert_eq!(
            limiter
                .try_acquire(mapped)
                .expect_err("mapped source must share the IPv4 bucket"),
            IpLimitReject::PerIp
        );
        drop(permit);
        assert!(limiter.try_acquire(mapped).is_ok());
    }

    #[test]
    fn removes_idle_sources_and_reuses_the_slot() {
        let limiter = Arc::new(IpLimiter::new(2, 1));
        let permit = limiter.try_acquire(ip(1)).expect("permit");
        assert_eq!(limiter.tracked_ips(), 1);
        drop(permit);
        assert_eq!(limiter.tracked_ips(), 0);
        let permit = limiter.try_acquire(ip(2)).expect("permit");
        assert_eq!(limiter.tracked_ips(), 1);
        drop(permit);
    }

    #[test]
    fn available_permits_tracks_releases() {
        let limiter = Arc::new(IpLimiter::new(2, 2));
        assert_eq!(limiter.available_permits(), 2);
        let permit = limiter.try_acquire(ip(1)).expect("permit");
        assert_eq!(limiter.available_permits(), 1);
        drop(permit);
        assert_eq!(limiter.available_permits(), 2);
    }
}
