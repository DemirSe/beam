//! Minimal process-wide admission counters.
//!
//! Counters are logged periodically instead of exposing a statistics API,
//! which is out of scope for the first release.

use std::sync::atomic::{AtomicU64, Ordering};

/// Counters for admission and cover-limit decisions.
#[derive(Debug, Default)]
pub struct Metrics {
    preauth_rejected: AtomicU64,
    cover_limited: AtomicU64,
    connection_limited: AtomicU64,
    accept_errors: AtomicU64,
}

/// A point-in-time copy of the counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MetricsSnapshot {
    /// Connections dropped because no pre-auth permit was available.
    pub preauth_rejected: u64,
    /// Probes closed because the cover limiter was full.
    pub cover_limited: u64,
    /// Authenticated connections closed because the connection limit was full.
    pub connection_limited: u64,
    /// Listener accept errors.
    pub accept_errors: u64,
}

impl Metrics {
    /// Counts one pre-auth rejection.
    pub fn record_preauth_rejection(&self) {
        self.preauth_rejected.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts one cover-limit rejection.
    pub fn record_cover_limit(&self) {
        self.cover_limited.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts one authenticated-connection limit rejection.
    pub fn record_connection_limit(&self) {
        self.connection_limited.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts one listener accept error.
    pub fn record_accept_error(&self) {
        self.accept_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns a snapshot of all counters.
    #[must_use]
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            preauth_rejected: self.preauth_rejected.load(Ordering::Relaxed),
            cover_limited: self.cover_limited.load(Ordering::Relaxed),
            connection_limited: self.connection_limited.load(Ordering::Relaxed),
            accept_errors: self.accept_errors.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_accumulate() {
        let metrics = Metrics::default();
        assert_eq!(metrics.snapshot(), MetricsSnapshot::default());
        metrics.record_preauth_rejection();
        metrics.record_preauth_rejection();
        metrics.record_cover_limit();
        metrics.record_connection_limit();
        metrics.record_accept_error();
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.preauth_rejected, 2);
        assert_eq!(snapshot.cover_limited, 1);
        assert_eq!(snapshot.connection_limited, 1);
        assert_eq!(snapshot.accept_errors, 1);
    }
}
