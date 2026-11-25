//! Lock-free diagnostic counters for silent packet drops and DNS outcomes.
//!
//! Every counter is a relaxed `AtomicU64`: incrementing costs one atomic add
//! and never allocates, blocks, or logs, so counters can live on the packet
//! fast path. Snapshots are plain `Copy` structs for periodic/on-change
//! reporting.

use std::sync::atomic::{AtomicU64, Ordering};

/// One relaxed counter, isolated so drop sites stay one line long.
#[derive(Debug, Default)]
pub struct Counter(AtomicU64);

impl Counter {
    /// Increments by one.
    pub fn incr(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    /// Adds `n`.
    pub fn add(&self, n: u64) {
        self.0.fetch_add(n, Ordering::Relaxed);
    }

    /// Reads the current value.
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Packet-drop counters grouped by reason, shared by the TUN engine, UDP
/// bridge, and DNS interceptor.
#[derive(Debug, Default)]
pub struct DropCounters {
    /// `tun_tx` channel full (RST/ICMP replies, UDP replies, DNS replies).
    pub tun_tx_full: Counter,
    /// Packet rejected by the IP/UDP parser (truncated, bad header, ...).
    pub ip_parse: Counter,
    /// Packet rejected because it was fragmented (never reassembled).
    pub fragment: Counter,
    /// Packet dropped by routing policy (excluded IP, bypass CIDR, private).
    pub route: Counter,
    /// New TCP flow aborted with RST because `max_tcp_connections` was reached.
    pub tcp_limit: Counter,
    /// TCP packet dropped because the stack RX queue was full.
    pub tcp_rx_overflow: Counter,
    /// UDP frame dropped by a full XUDP mux queue (outbound or inbound).
    pub udp_mux_q: Counter,
    /// Per-session UDP send queue full.
    pub udp_session_queue_full: Counter,
    /// Pre-connect UDP queue full or cleared.
    pub udp_pending_full: Counter,
    /// UDP payload empty or larger than the XUDP limit.
    pub udp_payload_invalid: Counter,
    /// UDP NAT session table full after the lazy idle sweep.
    pub udp_session_table_full: Counter,
}

/// Immutable snapshot of [`DropCounters`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DropSnapshot {
    pub tun_tx_full: u64,
    pub ip_parse: u64,
    pub fragment: u64,
    pub route: u64,
    pub tcp_limit: u64,
    pub tcp_rx_overflow: u64,
    pub udp_mux_q: u64,
    pub udp_session_queue_full: u64,
    pub udp_pending_full: u64,
    pub udp_payload_invalid: u64,
    pub udp_session_table_full: u64,
}

impl DropCounters {
    /// Takes a consistent-enough snapshot for diagnostics.
    pub fn snapshot(&self) -> DropSnapshot {
        DropSnapshot {
            tun_tx_full: self.tun_tx_full.get(),
            ip_parse: self.ip_parse.get(),
            fragment: self.fragment.get(),
            route: self.route.get(),
            tcp_limit: self.tcp_limit.get(),
            tcp_rx_overflow: self.tcp_rx_overflow.get(),
            udp_mux_q: self.udp_mux_q.get(),
            udp_session_queue_full: self.udp_session_queue_full.get(),
            udp_pending_full: self.udp_pending_full.get(),
            udp_payload_invalid: self.udp_payload_invalid.get(),
            udp_session_table_full: self.udp_session_table_full.get(),
        }
    }
}

impl DropSnapshot {
    /// Returns `true` when every counter is zero.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Compact `key:value` form for the `beam-client` status file.
    pub fn as_status_value(&self) -> String {
        format!(
            "tun_tx_full:{},ip_parse:{},frag:{},route:{},tcp_limit:{},tcp_rx_ovf:{},udp_mux_q:{},udp_sess_q:{},udp_pending:{},udp_payload:{},udp_sess_tbl:{}",
            self.tun_tx_full,
            self.ip_parse,
            self.fragment,
            self.route,
            self.tcp_limit,
            self.tcp_rx_overflow,
            self.udp_mux_q,
            self.udp_session_queue_full,
            self.udp_pending_full,
            self.udp_payload_invalid,
            self.udp_session_table_full
        )
    }
}

/// Lock-free DNS outcome counters exposed for degraded-state diagnostics.
#[derive(Debug, Default)]
pub struct DnsCounters {
    /// Queries answered from the local cache.
    pub hits: Counter,
    /// Queries that reached the upstream resolver.
    pub misses: Counter,
    /// SERVFAIL because `MAX_INFLIGHT_DNS_QUERIES` was reached.
    pub servfail_concurrency: Counter,
    /// SERVFAIL because the upstream/local resolver failed or timed out.
    pub servfail_upstream: Counter,
    /// SERVFAIL because the reply question did not match the query.
    pub servfail_mismatch: Counter,
    /// Upstream responses or queries that exceeded `query_timeout`.
    pub timeout: Counter,
    /// Queries refused by the local-upstream loop guard.
    pub loop_guard: Counter,
    /// Replies dropped because the `tun_tx` channel was full.
    pub tun_tx_dropped: Counter,
    /// Queries rejected because `parse_dns_query` returned `None`.
    pub dropped_malformed: Counter,
}

/// Immutable snapshot of [`DnsCounters`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DnsSnapshot {
    pub hits: u64,
    pub misses: u64,
    pub servfail_concurrency: u64,
    pub servfail_upstream: u64,
    pub servfail_mismatch: u64,
    pub timeout: u64,
    pub loop_guard: u64,
    pub tun_tx_dropped: u64,
    pub dropped_malformed: u64,
}

impl DnsCounters {
    /// Takes a snapshot for diagnostics.
    pub fn snapshot(&self) -> DnsSnapshot {
        DnsSnapshot {
            hits: self.hits.get(),
            misses: self.misses.get(),
            servfail_concurrency: self.servfail_concurrency.get(),
            servfail_upstream: self.servfail_upstream.get(),
            servfail_mismatch: self.servfail_mismatch.get(),
            timeout: self.timeout.get(),
            loop_guard: self.loop_guard.get(),
            tun_tx_dropped: self.tun_tx_dropped.get(),
            dropped_malformed: self.dropped_malformed.get(),
        }
    }
}

impl DnsSnapshot {
    /// Compact `key:value` form for the `beam-client` status file.
    pub fn as_status_value(&self) -> String {
        format!(
            "hits:{},misses:{},sf_busy:{},sf_upstream:{},sf_mismatch:{},timeout:{},loop:{},tun_tx_dropped:{},malformed:{}",
            self.hits,
            self.misses,
            self.servfail_concurrency,
            self.servfail_upstream,
            self.servfail_mismatch,
            self.timeout,
            self.loop_guard,
            self.tun_tx_dropped,
            self.dropped_malformed
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_snapshot_and_status_value() {
        let counters = DropCounters::default();
        assert!(counters.snapshot().is_empty());
        counters.tun_tx_full.incr();
        counters.route.add(2);
        counters.tcp_limit.incr();
        counters.tcp_rx_overflow.add(3);
        counters.udp_mux_q.add(4);
        let snap = counters.snapshot();
        assert_eq!(snap.tun_tx_full, 1);
        assert_eq!(snap.route, 2);
        assert_eq!(snap.tcp_limit, 1);
        assert_eq!(snap.tcp_rx_overflow, 3);
        assert_eq!(snap.udp_mux_q, 4);
        assert!(!snap.is_empty());
        assert!(snap.as_status_value().starts_with("tun_tx_full:1,"));
        assert!(snap.as_status_value().contains("route:2"));
        assert!(snap.as_status_value().contains("tcp_limit:1"));
        assert!(snap.as_status_value().contains("tcp_rx_ovf:3"));
        assert!(snap.as_status_value().contains("udp_mux_q:4"));

        let dns = DnsCounters::default();
        dns.hits.incr();
        dns.timeout.add(3);
        dns.dropped_malformed.incr();
        assert_eq!(dns.snapshot().hits, 1);
        assert_eq!(dns.snapshot().timeout, 3);
        assert_eq!(dns.snapshot().dropped_malformed, 1);
        assert!(dns.snapshot().as_status_value().contains("timeout:3"));
        assert!(dns.snapshot().as_status_value().contains("malformed:1"));
    }
}
