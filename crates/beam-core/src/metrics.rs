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
    xudp_send_dropped: AtomicU64,
    replay_rejected: AtomicU64,
    replay_cache_full: AtomicU64,
    xudp_end_dropped: AtomicU64,
    legacy_udp_limited: AtomicU64,
    splice_fallback: AtomicU64,
    xudp_new_frames: AtomicU64,
    xudp_new_global_id: AtomicU64,
    xudp_end_frames: AtomicU64,
    xudp_admitted_fresh: AtomicU64,
    xudp_admitted_reattach: AtomicU64,
    xudp_closed_end: AtomicU64,
    xudp_closed_idle: AtomicU64,
    xudp_closed_error: AtomicU64,
    xudp_closed_mux: AtomicU64,
    xudp_retained_inserted: AtomicU64,
    xudp_retained_reattached: AtomicU64,
    xudp_retained_expired: AtomicU64,
    xudp_retained_discarded: AtomicU64,
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
    /// XUDP request datagrams dropped because the send queue or socket was full.
    pub xudp_send_dropped: u64,
    /// Authenticated ClientHellos refused by the replay cache, either before the
    /// TLS handshake (reservation) or after it (settled id or full cache).
    pub replay_rejected: u64,
    /// Authenticated handshakes rejected because the replay cache was full;
    /// distinct from a duplicate ClientHello.
    pub replay_cache_full: u64,
    /// XUDP `End` frames that could not be queued before their deadline.
    pub xudp_end_dropped: u64,
    /// Legacy UDP / packetaddr streams rejected by their separate cap.
    pub legacy_udp_limited: u64,
    /// Vision relays that used the async copy path because a splice permit was
    /// unavailable or a raw descriptor could not be duplicated.
    pub splice_fallback: u64,
    /// XUDP `New` frames observed.
    pub xudp_new_frames: u64,
    /// XUDP `New` frames carrying a nonzero GlobalID.
    pub xudp_new_global_id: u64,
    /// XUDP `End` frames observed.
    pub xudp_end_frames: u64,
    /// Fresh XUDP sessions inserted into an active table.
    pub xudp_admitted_fresh: u64,
    /// Retained XUDP sockets successfully reattached and inserted.
    pub xudp_admitted_reattach: u64,
    /// Active sessions closed after an `End` frame.
    pub xudp_closed_end: u64,
    /// Active sessions selected for idle expiry.
    pub xudp_closed_idle: u64,
    /// Active sessions closed after a relay/socket error.
    pub xudp_closed_error: u64,
    /// Active sessions drained when the mux stream ended.
    pub xudp_closed_mux: u64,
    /// Retained sockets inserted after a clean GlobalID close.
    pub xudp_retained_inserted: u64,
    /// Retained sockets successfully reattached.
    pub xudp_retained_reattached: u64,
    /// Retained sockets removed by expiry.
    pub xudp_retained_expired: u64,
    /// Retained sockets discarded because the family changed or reattachment
    /// failed before the first datagram was sent.
    pub xudp_retained_discarded: u64,
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

    /// Records an authenticated handshake rejected by the replay cache.
    pub fn record_replay_rejected(&self) {
        self.replay_rejected.fetch_add(1, Ordering::Relaxed);
    }

    /// Records an authenticated handshake rejected because the replay cache
    /// reached its configured bound.
    pub fn record_replay_cache_full(&self) {
        self.replay_cache_full.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts one XUDP request datagram dropped by the send path.
    pub fn record_xudp_send_dropped(&self) {
        self.xudp_send_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts one legacy UDP / packetaddr limit rejection.
    pub fn record_legacy_udp_limit(&self) {
        self.legacy_udp_limited.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts one Vision relay async fallback after a splice permit was
    /// unavailable or a raw descriptor could not be duplicated.
    pub fn record_splice_fallback(&self) {
        self.splice_fallback.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts one XUDP `New` frame and whether it carried a GlobalID.
    pub fn record_xudp_new(&self, global_id: bool) {
        self.xudp_new_frames.fetch_add(1, Ordering::Relaxed);
        if global_id {
            self.xudp_new_global_id.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Counts one XUDP `End` frame.
    pub fn record_xudp_end(&self) {
        self.xudp_end_frames.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts one successfully inserted fresh XUDP session.
    pub fn record_xudp_admitted_fresh(&self) {
        self.xudp_admitted_fresh.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts one successfully inserted retained XUDP reattachment.
    pub fn record_xudp_admitted_reattach(&self) {
        self.xudp_admitted_reattach.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts a session closure for the given reason.
    pub fn record_xudp_closed_end(&self) {
        self.xudp_closed_end.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts one idle-selected session.
    pub fn record_xudp_closed_idle(&self) {
        self.xudp_closed_idle.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts one relay/socket error closure.
    pub fn record_xudp_closed_error(&self) {
        self.xudp_closed_error.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts one mux-teardown closure.
    pub fn record_xudp_closed_mux(&self) {
        self.xudp_closed_mux.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts one retained socket insertion.
    pub fn record_xudp_retained_inserted(&self) {
        self.xudp_retained_inserted.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts one successful retained socket reattachment.
    pub fn record_xudp_retained_reattached(&self) {
        self.xudp_retained_reattached
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Counts retained sockets removed by expiry.
    pub fn record_xudp_retained_expired(&self, count: usize) {
        self.xudp_retained_expired
            .fetch_add(count as u64, Ordering::Relaxed);
    }

    /// Counts retained sockets discarded on a family change or failed
    /// reattachment.
    pub fn record_xudp_retained_discarded(&self) {
        self.xudp_retained_discarded.fetch_add(1, Ordering::Relaxed);
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
            xudp_send_dropped: self.xudp_send_dropped.load(Ordering::Relaxed),
            replay_rejected: self.replay_rejected.load(Ordering::Relaxed),
            replay_cache_full: self.replay_cache_full.load(Ordering::Relaxed),
            xudp_end_dropped: self.xudp_end_dropped.load(Ordering::Relaxed),
            legacy_udp_limited: self.legacy_udp_limited.load(Ordering::Relaxed),
            splice_fallback: self.splice_fallback.load(Ordering::Relaxed),
            xudp_new_frames: self.xudp_new_frames.load(Ordering::Relaxed),
            xudp_new_global_id: self.xudp_new_global_id.load(Ordering::Relaxed),
            xudp_end_frames: self.xudp_end_frames.load(Ordering::Relaxed),
            xudp_admitted_fresh: self.xudp_admitted_fresh.load(Ordering::Relaxed),
            xudp_admitted_reattach: self.xudp_admitted_reattach.load(Ordering::Relaxed),
            xudp_closed_end: self.xudp_closed_end.load(Ordering::Relaxed),
            xudp_closed_idle: self.xudp_closed_idle.load(Ordering::Relaxed),
            xudp_closed_error: self.xudp_closed_error.load(Ordering::Relaxed),
            xudp_closed_mux: self.xudp_closed_mux.load(Ordering::Relaxed),
            xudp_retained_inserted: self.xudp_retained_inserted.load(Ordering::Relaxed),
            xudp_retained_reattached: self.xudp_retained_reattached.load(Ordering::Relaxed),
            xudp_retained_expired: self.xudp_retained_expired.load(Ordering::Relaxed),
            xudp_retained_discarded: self.xudp_retained_discarded.load(Ordering::Relaxed),
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
        metrics.record_replay_rejected();
        metrics.record_replay_cache_full();
        metrics.record_splice_fallback();
        metrics.record_xudp_new(true);
        metrics.record_xudp_end();
        metrics.record_xudp_admitted_fresh();
        metrics.record_xudp_admitted_reattach();
        metrics.record_xudp_closed_end();
        metrics.record_xudp_closed_idle();
        metrics.record_xudp_closed_error();
        metrics.record_xudp_closed_mux();
        metrics.record_xudp_retained_inserted();
        metrics.record_xudp_retained_reattached();
        metrics.record_xudp_retained_expired(2);
        metrics.record_xudp_retained_discarded();
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
        assert_eq!(snapshot.replay_rejected, 1);
        assert_eq!(snapshot.replay_cache_full, 1);
        assert_eq!(snapshot.splice_fallback, 1);
        assert_eq!(snapshot.xudp_new_frames, 1);
        assert_eq!(snapshot.xudp_new_global_id, 1);
        assert_eq!(snapshot.xudp_end_frames, 1);
        assert_eq!(snapshot.xudp_admitted_fresh, 1);
        assert_eq!(snapshot.xudp_admitted_reattach, 1);
        assert_eq!(snapshot.xudp_closed_end, 1);
        assert_eq!(snapshot.xudp_closed_idle, 1);
        assert_eq!(snapshot.xudp_closed_error, 1);
        assert_eq!(snapshot.xudp_closed_mux, 1);
        assert_eq!(snapshot.xudp_retained_inserted, 1);
        assert_eq!(snapshot.xudp_retained_reattached, 1);
        assert_eq!(snapshot.xudp_retained_expired, 2);
        assert_eq!(snapshot.xudp_retained_discarded, 1);
    }
}
