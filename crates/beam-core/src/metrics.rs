//! Minimal process-wide admission counters.
//!
//! Counters are logged periodically instead of exposing a statistics API,
//! which is out of scope for the first release.

use std::sync::atomic::{AtomicU64, Ordering};

/// Counters for admission, XUDP pressure, and relay fallbacks.
#[derive(Debug, Default)]
pub struct Metrics {
    preauth_rejected: AtomicU64,
    cover_limited: AtomicU64,
    connection_limited: AtomicU64,
    accept_errors: AtomicU64,
    xudp_rejected_per_stream: AtomicU64,
    xudp_rejected_global: AtomicU64,
    xudp_retained_evicted: AtomicU64,
    xudp_replies_dropped: AtomicU64,
    xudp_end_dropped: AtomicU64,
    legacy_udp_limited: AtomicU64,
    splice_fallback: AtomicU64,
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
    /// XUDP `New` frames rejected by the per-stream session limit.
    pub xudp_rejected_per_stream: u64,
    /// XUDP `New` frames rejected by the process-wide session limit.
    pub xudp_rejected_global: u64,
    /// Retained XUDP sockets evicted to admit a live session.
    pub xudp_retained_evicted: u64,
    /// XUDP reply datagrams dropped at the queue, byte budget, or size checks.
    pub xudp_replies_dropped: u64,
    /// XUDP `End` frames that could not be queued before their deadline.
    pub xudp_end_dropped: u64,
    /// Legacy UDP / packetaddr streams rejected by their separate cap.
    pub legacy_udp_limited: u64,
    /// Vision relays that used the async copy path because splice was full.
    pub splice_fallback: u64,
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

    /// Counts one XUDP per-stream session rejection.
    pub fn record_xudp_rejected_per_stream(&self) {
        self.xudp_rejected_per_stream
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Counts one XUDP global session rejection.
    pub fn record_xudp_rejected_global(&self) {
        self.xudp_rejected_global.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts one evicted retained XUDP socket.
    pub fn record_xudp_retained_evicted(&self) {
        self.xudp_retained_evicted.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts one dropped XUDP reply datagram.
    pub fn record_xudp_reply_dropped(&self) {
        self.xudp_replies_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts one XUDP `End` frame that could not be queued in time.
    pub fn record_xudp_end_dropped(&self) {
        self.xudp_end_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts one legacy UDP / packetaddr limit rejection.
    pub fn record_legacy_udp_limit(&self) {
        self.legacy_udp_limited.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts one Vision relay async fallback.
    pub fn record_splice_fallback(&self) {
        self.splice_fallback.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns a snapshot of all counters.
    #[must_use]
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            preauth_rejected: self.preauth_rejected.load(Ordering::Relaxed),
            cover_limited: self.cover_limited.load(Ordering::Relaxed),
            connection_limited: self.connection_limited.load(Ordering::Relaxed),
            accept_errors: self.accept_errors.load(Ordering::Relaxed),
            xudp_rejected_per_stream: self.xudp_rejected_per_stream.load(Ordering::Relaxed),
            xudp_rejected_global: self.xudp_rejected_global.load(Ordering::Relaxed),
            xudp_retained_evicted: self.xudp_retained_evicted.load(Ordering::Relaxed),
            xudp_replies_dropped: self.xudp_replies_dropped.load(Ordering::Relaxed),
            xudp_end_dropped: self.xudp_end_dropped.load(Ordering::Relaxed),
            legacy_udp_limited: self.legacy_udp_limited.load(Ordering::Relaxed),
            splice_fallback: self.splice_fallback.load(Ordering::Relaxed),
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
        metrics.record_xudp_rejected_per_stream();
        metrics.record_xudp_rejected_global();
        metrics.record_xudp_retained_evicted();
        metrics.record_xudp_reply_dropped();
        metrics.record_xudp_end_dropped();
        metrics.record_legacy_udp_limit();
        metrics.record_splice_fallback();
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.preauth_rejected, 2);
        assert_eq!(snapshot.cover_limited, 1);
        assert_eq!(snapshot.connection_limited, 1);
        assert_eq!(snapshot.accept_errors, 1);
        assert_eq!(snapshot.xudp_rejected_per_stream, 1);
        assert_eq!(snapshot.xudp_rejected_global, 1);
        assert_eq!(snapshot.xudp_retained_evicted, 1);
        assert_eq!(snapshot.xudp_replies_dropped, 1);
        assert_eq!(snapshot.xudp_end_dropped, 1);
        assert_eq!(snapshot.legacy_udp_limited, 1);
        assert_eq!(snapshot.splice_fallback, 1);
    }
}
