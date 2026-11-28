//! Lightweight, proxy-oriented IPv4 + IPv6 TCP/IP stack with RFC 7323 Window
//! Scaling, zero-copy `VecDeque::as_slices()` TX segmentation, lossless
//! bounded receive backpressure, zero-window persist, OOO FIN handling, and
//! cumulative ACK coalescing.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::{Notify, mpsc};

use crate::packet::{
    IP_PROTO_TCP, TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN, build_ip_tcp_packet_slices,
    build_ip_tcp_packet_slices_into, parse_ip, parse_tcp, parse_tcp_syn_options,
};
use crate::stack::{
    AcceptedTcpStream, FlowWaker, NetStack, RelayBufPool, TcpStackConfig, TunTcpStream,
};
use crate::stats::DropCounters;

const OUR_WSCALE: u8 = 7; // 128x multiplier -> up to ~8 MiB window; capped at max_rcv_buf
const MIN_TCP_BUF: usize = 64 * 1024;
const MAX_TCP_BUF: usize = 8 * 1024 * 1024;
const MAX_INCOMING_PACKETS: usize = 2048;
const MAX_INCOMING_BYTES: usize = 4 * 1024 * 1024;
const MAX_OOO_SEGMENTS: usize = 256;
const STREAM_CHANNEL_CAP: usize = 16;
/// Upper bound on relay -> stack reply bytes queued per flow. This is charged
/// on top of the two socket buffers.
pub(crate) const S2C_QUEUE_BYTES_PER_FLOW: usize = 64 * 1024;
/// Relay read chunk size. Keep in sync with `engine::S2C_READ_BUF_BYTES`.
#[cfg(target_os = "android")]
pub(crate) const S2C_READ_CHUNK_BYTES: usize = 16 * 1024;
#[cfg(not(target_os = "android"))]
pub(crate) const S2C_READ_CHUNK_BYTES: usize = 64 * 1024;
/// Depth of the per-flow relay -> stack reply queue, derived from the chunk
/// size so queued bytes never exceed [`S2C_QUEUE_BYTES_PER_FLOW`].
pub(crate) const S2C_STREAM_CHANNEL_CAP: usize = S2C_QUEUE_BYTES_PER_FLOW / S2C_READ_CHUNK_BYTES;
const RELAY_COALESCE_BYTES: usize = 64 * 1024;
/// Upper bound on recycled outbound IP/TCP packet buffers held by [`ProxyTcpStack`].
/// Capped at 128 entries <= 4096 B each (<= 512 KiB worst case, ~192 KiB at MTU).
const TX_BUF_POOL_MAX: usize = 128;
/// Do not retain oversized buffers in `tx_buf_pool`.
const TX_BUF_MAX_RETAIN_CAP: usize = 4096;
const INITIAL_RTO_MS: i64 = 200;
const MAX_RTO_MS: i64 = 4_000;
/// Data retransmit ceiling: 200 ms doubling to the 4 s cap, 20 retransmits
/// cover about 66 s, so a brief network flap or handover does not RST a flow
/// that is still being used.
const MAX_RETRIES: u8 = 20;
/// Zero-window persist probe ceiling: 225 probes at the 4 s cap cover about
/// 15 min, so a peer that answers every probe with `window = 0` cannot pin a
/// TCP slot forever.
const MAX_PERSIST_PROBES: u16 = 225;
const CLOSING_TIMEOUT_MS: i64 = 5_000;
/// Release an oversized `ProxyTcpStack::incoming_buf` once the burst is polled.
const INCOMING_BUF_SHRINK_THRESHOLD: usize = 256 * 1024;
const INCOMING_BUF_SHRINK_TARGET: usize = 64 * 1024;
/// Same for the per-packet length list (`incoming_lens`).
const INCOMING_LENS_SHRINK_THRESHOLD: usize = 256;
const INCOMING_LENS_SHRINK_TARGET: usize = 64;
/// Shrink an empty `TcpConn::tx_buf` once it has been idle for this long so
/// long-lived keep-alive/push sockets release burst capacity with zero timers.
const IDLE_TX_BUF_SHRINK_THRESHOLD: usize = 16 * 1024;
const IDLE_BUF_SHRINK_AFTER_MS: i64 = 5_000;
/// Minimum age before a half-open `SynReceived` flow can be evicted under table pressure.
const SOFT_EVICT_SYN_MIN_AGE_MS: i64 = 3_000;
/// Minimum idle duration before a quiescent `Established` flow can be evicted as a last resort.
const SOFT_EVICT_ESTABLISHED_IDLE_MS: i64 = 180_000;
/// Mobile adaptive buffer threshold: flows admitted above 128 on high-RAM mobile
/// profiles use half the per-socket buffer (64 KiB) to preserve the native RAM ceiling.
const ADAPTIVE_BUF_HALVE_FLOW_THRESHOLD: usize = 128;

/// Well-known mobile push / messaging ports exempt from Tier-3 idle eviction so
/// Google Play Services FCM (`5228..=5230`), WhatsApp/XMPP (`5222`/`5223`), and
/// MQTT TLS (`8883`) never receive spurious RSTs or enter reconnect backoff.
const fn is_protected_push_port(dst_port: u16) -> bool {
    matches!(dst_port, 5222 | 5223 | 5228 | 5229 | 5230 | 8883)
}

type FlowKey = (IpAddr, u16, IpAddr, u16);

fn handshake_timeout_ms(config: &TcpStackConfig) -> i64 {
    i64::try_from(config.handshake_timeout_ms)
        .unwrap_or(i64::MAX)
        .max(1)
}

struct DirtyFlowQueue {
    queue: Mutex<VecDeque<FlowKey>>,
    waker: Arc<Notify>,
}

struct FlowDirtyHandle {
    flow: FlowKey,
    queued: AtomicBool,
    dirty: Arc<DirtyFlowQueue>,
}

impl FlowDirtyHandle {
    fn new(flow: FlowKey, dirty: Arc<DirtyFlowQueue>) -> Self {
        Self {
            flow,
            queued: AtomicBool::new(false),
            dirty,
        }
    }

    fn clear_queued(&self) {
        self.queued.store(false, Ordering::SeqCst);
    }
}

impl FlowWaker for FlowDirtyHandle {
    fn wake(&self) {
        if !self.queued.swap(true, Ordering::SeqCst) {
            self.dirty
                .queue
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push_back(self.flow);
        }
        self.dirty.waker.notify_one();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpState {
    SynReceived,
    Established,
    CloseWait,
    FinWait1,
    FinWait2,
    Closing,
    LastAck,
    Closed,
}

impl TcpState {
    /// `true` after the handshake completed, where a fresh pure SYN for the same
    /// 4-tuple means the local peer restarted instead of resending its SYN.
    fn is_synchronized(self) -> bool {
        matches!(
            self,
            TcpState::Established
                | TcpState::CloseWait
                | TcpState::FinWait1
                | TcpState::FinWait2
                | TcpState::Closing
                | TcpState::LastAck
        )
    }
}

/// `true` when sequence number `a` is strictly after `b` in TCP sequence space.
fn seq_after(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

struct TcpConn {
    flow: FlowKey,
    state: TcpState,
    mss: usize,
    peer_wscale: u8,
    our_wscale: u8,
    // Receive state (peer -> proxy)
    /// ISN from the SYN that created this flow, so a late duplicate SYN can be
    /// told apart from a new connection reusing the same 4-tuple.
    rcv_isn: u32,
    rcv_nxt: u32,
    rcv_coalesce: Vec<u8>,
    pending_to_relay: VecDeque<Vec<u8>>,
    pending_to_relay_bytes: usize,
    ooo: BTreeMap<u32, Vec<u8>>,
    ooo_bytes: usize,
    in_flight_relay: Arc<AtomicUsize>,
    max_rcv_buf: usize,
    last_advertised_wnd: u32,
    need_ack: bool,
    peer_fin_received: bool,
    /// Sequence number of an out-of-order FIN waiting for missing preceding data.
    peer_fin_seq: Option<u32>,
    // Send state (proxy -> peer)
    snd_una: u32,
    snd_nxt: u32,
    snd_wnd: u32,
    /// SEG.SEQ of the segment that last updated `snd_wnd` (RFC 793 SND.WL1).
    snd_wl1: u32,
    /// SEG.ACK of the segment that last updated `snd_wnd` (RFC 793 SND.WL2).
    snd_wl2: u32,
    tx_buf: VecDeque<u8>,
    max_snd_buf: usize,
    fin_sent: bool,
    fin_seq: u32,
    dup_acks: u8,
    rto_ms: i64,
    rto_deadline_ms: Option<i64>,
    /// Zero-window persist timer when `snd_wnd == 0` and `tx_buf` has unsent bytes.
    persist_ms: i64,
    persist_deadline_ms: Option<i64>,
    /// Zero-window probes sent since `snd_wnd` was last open, capped by
    /// [`MAX_PERSIST_PROBES`]. Kept separate from `retries`.
    persist_probes: u16,
    retries: u8,
    state_deadline_ms: Option<i64>,
    last_activity_ms: i64,
    /// Earliest deadline currently pushed to `ProxyTcpStack::timers` for this flow.
    heap_deadline_ms: Option<i64>,
    /// Deduplication guard while building the per-poll dirty batch.
    in_poll_batch: bool,
    // Async relay channels
    accepted: bool,
    dirty_handle: Option<Arc<FlowDirtyHandle>>,
    to_relay: Option<mpsc::Sender<Vec<u8>>>,
    from_relay: Option<mpsc::Receiver<Vec<u8>>>,
    /// Relay chunk bytes and offset when only part of a chunk fits `tx_buf`.
    relay_pending: Option<(Vec<u8>, usize)>,
    relay_eof: bool,
    aborted: Arc<AtomicBool>,
}

impl TcpConn {
    fn in_order_rcv_bytes(&self) -> usize {
        self.in_flight_relay
            .load(Ordering::Acquire)
            .saturating_add(self.pending_to_relay_bytes)
            .saturating_add(self.rcv_coalesce.len())
    }

    fn rcv_wnd_bytes(&self) -> u32 {
        let used = self.in_order_rcv_bytes().saturating_add(self.ooo_bytes);
        let avail = self.max_rcv_buf.saturating_sub(used);
        let max_scaled = (u32::from(u16::MAX)) << self.our_wscale;
        u32::try_from(avail).unwrap_or(max_scaled).min(max_scaled)
    }

    /// `true` when eviction would discard bytes that are still queued.
    fn has_buffered_data(&self) -> bool {
        !self.tx_buf.is_empty()
            || !self.pending_to_relay.is_empty()
            || !self.rcv_coalesce.is_empty()
            || !self.ooo.is_empty()
            || self.in_flight_relay.load(Ordering::Acquire) > 0
            || self.from_relay.as_ref().is_some_and(|rx| !rx.is_empty())
            || self.relay_pending.is_some()
    }

    fn advertised_window(&self) -> u16 {
        let wnd = self.rcv_wnd_bytes() >> self.our_wscale;
        u16::try_from(wnd).unwrap_or(u16::MAX)
    }

    fn build_packet_slices_pooled(
        &mut self,
        flags: u8,
        options: &[u8],
        payload_a: &[u8],
        payload_b: &[u8],
        seq: u32,
        mut tx_pool: Option<&mut Vec<Vec<u8>>>,
    ) -> Option<Vec<u8>> {
        let wnd_scaled = self.advertised_window();
        self.last_advertised_wnd = u32::from(wnd_scaled) << self.our_wscale;
        let mut pkt = tx_pool
            .as_deref_mut()
            .and_then(Vec::pop)
            .unwrap_or_default();
        if build_ip_tcp_packet_slices_into(
            &mut pkt,
            self.flow.2,
            self.flow.3,
            self.flow.0,
            self.flow.1,
            seq,
            self.rcv_nxt,
            flags,
            wnd_scaled,
            options,
            payload_a,
            payload_b,
        ) {
            Some(pkt)
        } else {
            if let Some(pool) = tx_pool
                && pkt.capacity() > 0
                && pool.len() < TX_BUF_POOL_MAX
                && pkt.capacity() <= TX_BUF_MAX_RETAIN_CAP
            {
                pool.push(pkt);
            }
            None
        }
    }

    fn build_packet_slices(
        &mut self,
        flags: u8,
        options: &[u8],
        payload_a: &[u8],
        payload_b: &[u8],
        seq: u32,
    ) -> Option<Vec<u8>> {
        self.build_packet_slices_pooled(flags, options, payload_a, payload_b, seq, None)
    }

    /// Emits a TCP segment slicing `tx_buf[offset..offset+len]` directly via
    /// `VecDeque::as_slices()` with zero intermediate payload allocation.
    ///
    /// Returns the number of bytes actually sent (`0` when the range does not
    /// fit in `tx_buf`), so the caller never advances `snd_nxt` past sent bytes.
    fn emit_tx_segment(
        &mut self,
        offset: usize,
        len: usize,
        flags: u8,
        seq: u32,
        tx_out: &mut Vec<Vec<u8>>,
        mut tx_pool: Option<&mut Vec<Vec<u8>>>,
    ) -> usize {
        if len == 0
            || !offset
                .checked_add(len)
                .is_some_and(|end| end <= self.tx_buf.len())
        {
            return 0;
        }
        let (s1, s2) = self.tx_buf.as_slices();
        let (part_a, part_b) = if offset < s1.len() {
            let a_len = (s1.len() - offset).min(len);
            let a = &s1[offset..offset + a_len];
            let rem = len - a_len;
            let b = if rem > 0 {
                &s2[..rem.min(s2.len())]
            } else {
                &[]
            };
            (a, b)
        } else {
            let s2_off = offset - s1.len();
            let b = &s2[s2_off..(s2_off + len).min(s2.len())];
            (&[][..], b)
        };
        debug_assert_eq!(
            part_a.len() + part_b.len(),
            len,
            "TX segment must resolve exactly len bytes from tx_buf"
        );
        let wnd_scaled = self.advertised_window();
        self.last_advertised_wnd = u32::from(wnd_scaled) << self.our_wscale;
        let mut pkt = tx_pool
            .as_deref_mut()
            .and_then(Vec::pop)
            .unwrap_or_default();
        if build_ip_tcp_packet_slices_into(
            &mut pkt,
            self.flow.2,
            self.flow.3,
            self.flow.0,
            self.flow.1,
            seq,
            self.rcv_nxt,
            flags,
            wnd_scaled,
            &[],
            part_a,
            part_b,
        ) {
            tx_out.push(pkt);
            return len;
        }
        if let Some(pool) = tx_pool
            && pkt.capacity() > 0
            && pool.len() < TX_BUF_POOL_MAX
            && pkt.capacity() <= TX_BUF_MAX_RETAIN_CAP
        {
            pool.push(pkt);
        }
        0
    }

    fn send_syn_ack(&mut self, now_ms: i64, tx_out: &mut Vec<Vec<u8>>) {
        let mss_bytes = (self.mss as u16).to_be_bytes();
        // Fixed stack buffer: SYN|ACK is the first packet of every flow, so it
        // must not allocate an options `Vec`.
        let mut options_buf = [0u8; 8];
        options_buf[..4].copy_from_slice(&[2, 4, mss_bytes[0], mss_bytes[1]]);
        if self.our_wscale > 0 {
            options_buf[4..].copy_from_slice(&[1, 3, 3, self.our_wscale]);
        }
        let options: &[u8] = if self.our_wscale > 0 {
            &options_buf
        } else {
            &options_buf[..4]
        };
        // RFC 7323 §2.2: the Window field in a SYN / SYN+ACK segment MUST NOT be scaled.
        let unscaled_wnd = self.rcv_wnd_bytes().min(u32::from(u16::MAX)) as u16;
        self.last_advertised_wnd = u32::from(unscaled_wnd);
        if let Some(pkt) = build_ip_tcp_packet_slices(
            self.flow.2,
            self.flow.3,
            self.flow.0,
            self.flow.1,
            self.snd_una,
            self.rcv_nxt,
            TCP_SYN | TCP_ACK,
            unscaled_wnd,
            options,
            &[],
            &[],
        ) {
            tx_out.push(pkt);
        }
        self.snd_nxt = self.snd_una.wrapping_add(1);
        self.rto_deadline_ms = Some(now_ms + self.rto_ms);
    }

    /// Releases oversized empty per-flow buffers once the connection has been
    /// quiet past `IDLE_BUF_SHRINK_AFTER_MS`. Opportunistic only — never arms a
    /// timer or causes a Doze wakeup.
    fn shrink_idle_bufs(&mut self, now_ms: i64) {
        if self.tx_buf.is_empty()
            && self.tx_buf.capacity() > IDLE_TX_BUF_SHRINK_THRESHOLD
            && now_ms.saturating_sub(self.last_activity_ms) >= IDLE_BUF_SHRINK_AFTER_MS
        {
            self.tx_buf.shrink_to(0);
        }
        if self.pending_to_relay.is_empty() && self.pending_to_relay.capacity() > 16 {
            self.pending_to_relay.shrink_to(0);
        }
    }

    fn send_rst(&mut self, seq: u32, tx_out: &mut Vec<Vec<u8>>) {
        if let Some(pkt) = build_ip_tcp_packet_slices(
            self.flow.2,
            self.flow.3,
            self.flow.0,
            self.flow.1,
            seq,
            self.rcv_nxt,
            TCP_RST | TCP_ACK,
            0,
            &[],
            &[],
            &[],
        ) {
            tx_out.push(pkt);
        }
        self.state = TcpState::Closed;
        self.to_relay.take();
        self.from_relay.take();
        self.relay_pending = None;
        self.pending_to_relay.clear();
        self.pending_to_relay_bytes = 0;
    }

    fn on_segment(
        &mut self,
        seg: &crate::packet::TcpSegmentView<'_>,
        now_ms: i64,
        tx_out: &mut Vec<Vec<u8>>,
        tx_pool: &mut Vec<Vec<u8>>,
    ) {
        self.last_activity_ms = now_ms;

        if (seg.flags & TCP_RST) != 0 {
            self.state = TcpState::Closed;
            self.to_relay.take();
            self.from_relay.take();
            self.relay_pending = None;
            self.pending_to_relay.clear();
            self.pending_to_relay_bytes = 0;
            return;
        }

        if (seg.flags & TCP_SYN) != 0 && (seg.flags & TCP_ACK) == 0 {
            // A pure SYN repeating the flow's ISN is a duplicate of the
            // original SYN: re-send SYN|ACK. A pure SYN with a different ISN
            // is a new connection attempt and is replaced in `poll` before it
            // can reach here.
            if self.state == TcpState::SynReceived && seg.seq == self.rcv_isn {
                self.send_syn_ack(now_ms, tx_out);
            } else if self.state.is_synchronized() && seg.seq == self.rcv_isn {
                // RFC 5961: a SYN that repeats the ISN of the live connection is
                // a late or reordered duplicate, not a new connection. Challenge
                // it with an ACK and keep the flow instead of resetting it.
                if let Some(pkt) = self.build_packet_slices(TCP_ACK, &[], &[], &[], self.snd_nxt) {
                    tx_out.push(pkt);
                }
            }
            return;
        }

        if (seg.flags & TCP_ACK) != 0 {
            self.process_ack(seg.seq, seg.ack, seg.window, now_ms, tx_out, tx_pool);
        }

        if self.state == TcpState::Closed {
            return;
        }

        // A zero-window persist probe uses the peer's send / our receive
        // sequence space: `seq = rcv_nxt - 1` from our side. Answer it once when
        // our window has reopened, even below the ordinary update threshold, so
        // the peer does not stay stalled after a small drain.
        if self.last_advertised_wnd == 0
            && seg.seq == self.rcv_nxt.wrapping_sub(1)
            && seg.payload.is_empty()
            && self.rcv_wnd_bytes() > 0
        {
            self.need_ack = true;
        }

        let mut emit_dup_ack = false;
        if !seg.payload.is_empty() {
            if matches!(
                self.state,
                TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2
            ) {
                if self.process_data(seg.seq, seg.payload) {
                    emit_dup_ack = true;
                } else {
                    self.need_ack = true;
                }
            } else if matches!(self.state, TcpState::CloseWait | TcpState::LastAck) {
                // Peer already sent FIN; emit a cumulative ACK for duplicate or
                // retransmitted bytes to avoid peer retransmit storms.
                self.need_ack = true;
            }
        }

        // Handle in-order or out-of-order FIN.
        if (seg.flags & TCP_FIN) != 0 {
            if matches!(
                self.state,
                TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2
            ) {
                let fin_seq = seg.seq.wrapping_add(seg.payload.len() as u32);
                if fin_seq == self.rcv_nxt {
                    self.consume_peer_fin(now_ms, tx_out);
                } else if (fin_seq.wrapping_sub(self.rcv_nxt) as i32) > 0 {
                    // Record OOO FIN so it triggers once preceding data arrives.
                    self.peer_fin_seq = Some(fin_seq);
                    emit_dup_ack = true;
                }
            } else if matches!(self.state, TcpState::CloseWait | TcpState::LastAck) {
                self.need_ack = true;
            }
        }

        // Check if `drain_ooo()` advanced `rcv_nxt` up to a recorded OOO FIN.
        if let Some(fin_seq) = self.peer_fin_seq
            && fin_seq == self.rcv_nxt
            && !self.peer_fin_received
        {
            self.peer_fin_seq = None;
            self.consume_peer_fin(now_ms, tx_out);
        }

        if emit_dup_ack && self.state != TcpState::Closed {
            // RFC 5681: emit an immediate duplicate ACK for every out-of-order
            // segment/FIN so the local OS triggers Fast Retransmit in 0 ms.
            if let Some(pkt) = self.build_packet_slices(TCP_ACK, &[], &[], &[], self.snd_nxt) {
                tx_out.push(pkt);
            }
            self.need_ack = false;
        }
    }

    fn consume_peer_fin(&mut self, now_ms: i64, tx_out: &mut Vec<Vec<u8>>) {
        self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
        self.need_ack = true;
        self.peer_fin_received = true;
        self.flush_rcv_to_relay();
        match self.state {
            TcpState::Established => {
                self.state = TcpState::CloseWait;
            }
            TcpState::FinWait1 => {
                self.state = TcpState::Closing;
                self.state_deadline_ms = Some(now_ms + CLOSING_TIMEOUT_MS);
            }
            TcpState::FinWait2 => {
                if let Some(pkt) = self.build_packet_slices(TCP_ACK, &[], &[], &[], self.snd_nxt) {
                    tx_out.push(pkt);
                }
                self.need_ack = false;
                self.state = TcpState::Closed;
            }
            _ => {}
        }
    }

    fn process_ack(
        &mut self,
        seg_seq: u32,
        ack: u32,
        raw_window: u16,
        now_ms: i64,
        tx_out: &mut Vec<Vec<u8>>,
        tx_pool: &mut Vec<Vec<u8>>,
    ) {
        // RFC 793 §3.9 SND.WL1 / SND.WL2: only a segment newer than the one that
        // last updated the window may change `snd_wnd`, so a reordered stale ACK
        // cannot rewind the send window or re-arm the persist timer.
        if seq_after(seg_seq, self.snd_wl1)
            || (seg_seq == self.snd_wl1 && !seq_after(self.snd_wl2, ack))
        {
            self.snd_wnd = u32::from(raw_window) << self.peer_wscale;
            self.snd_wl1 = seg_seq;
            self.snd_wl2 = ack;
            if self.snd_wnd > 0 {
                self.persist_deadline_ms = None;
                self.persist_ms = INITIAL_RTO_MS;
                self.persist_probes = 0;
            }
        }

        if self.state == TcpState::SynReceived {
            if ack == self.snd_nxt {
                self.snd_una = ack;
                self.state = TcpState::Established;
                self.state_deadline_ms = None;
                self.rto_deadline_ms = None;
                self.rto_ms = INITIAL_RTO_MS;
                self.retries = 0;
            }
            return;
        }

        let advance = ack.wrapping_sub(self.snd_una) as i32;
        let in_flight = self.snd_nxt.wrapping_sub(self.snd_una) as i32;

        if advance > 0 && advance <= in_flight {
            let mut acked = advance as usize;
            let data_acked = acked.min(self.tx_buf.len());
            self.tx_buf.drain(..data_acked);
            acked -= data_acked;

            self.snd_una = ack;
            self.dup_acks = 0;
            self.rto_ms = INITIAL_RTO_MS;
            self.retries = 0;

            if self.snd_una == self.snd_nxt {
                self.rto_deadline_ms = None;
            } else {
                self.rto_deadline_ms = Some(now_ms + self.rto_ms);
            }

            if self.fin_sent && acked > 0 && ack == self.fin_seq.wrapping_add(1) {
                match self.state {
                    TcpState::FinWait1 => {
                        self.state = TcpState::FinWait2;
                        self.state_deadline_ms = Some(now_ms + CLOSING_TIMEOUT_MS);
                    }
                    TcpState::Closing | TcpState::LastAck => {
                        self.state = TcpState::Closed;
                    }
                    _ => {}
                }
            }
        } else if advance == 0 && in_flight > 0 && !self.tx_buf.is_empty() {
            self.dup_acks = self.dup_acks.saturating_add(1);
            if self.dup_acks == 3 {
                let len = self.tx_buf.len().min(self.mss);
                self.emit_tx_segment(
                    0,
                    len,
                    TCP_ACK | TCP_PSH,
                    self.snd_una,
                    tx_out,
                    Some(tx_pool),
                );
                self.rto_deadline_ms = Some(now_ms + self.rto_ms);
            }
        }
    }

    /// Returns `true` if the segment arrived ahead of `rcv_nxt` (out-of-order).
    fn process_data(&mut self, seq: u32, payload: &[u8]) -> bool {
        let rel = seq.wrapping_sub(self.rcv_nxt) as i32;
        if rel <= 0 {
            // Use `wrapping_sub` (not `-rel`) to avoid overflow on `rel == i32::MIN`.
            let skip = self.rcv_nxt.wrapping_sub(seq) as usize;
            if skip >= payload.len() {
                return false;
            }
            let avail = self.rcv_wnd_bytes() as usize;
            if avail == 0 {
                // Receive buffer is full; do not advance `rcv_nxt` or grow buffers.
                return false;
            }
            let fresh = &payload[skip..];
            let accept = fresh.len().min(avail);
            self.rcv_coalesce.extend_from_slice(&fresh[..accept]);
            self.rcv_nxt = self.rcv_nxt.wrapping_add(accept as u32);
            if self.rcv_coalesce.len() >= RELAY_COALESCE_BYTES {
                self.queue_coalesce_chunk();
            }
            self.drain_ooo();
            false
        } else {
            let existing = self.ooo.get(&seq).map_or(0, Vec::len);
            let delta = payload.len().saturating_sub(existing);
            // `rcv_wnd_bytes()` already subtracts `ooo_bytes`, so bounding the
            // *growth* by it keeps `in_order + ooo_bytes <= max_rcv_buf` exactly,
            // without counting the queued bytes twice.
            if self.ooo.len() < MAX_OOO_SEGMENTS && delta <= self.rcv_wnd_bytes() as usize {
                let entry = self.ooo.entry(seq).or_default();
                if payload.len() > entry.len() {
                    self.ooo_bytes = self.ooo_bytes.saturating_add(delta);
                    *entry = payload.to_vec();
                }
            }
            true
        }
    }

    fn drain_ooo(&mut self) {
        // A queued segment `k` is ready iff `(k.wrapping_sub(rcv_nxt) as i32) <= 0`,
        // i.e. `k` lies in the wrapping half-space `[rcv_nxt - 2^31, rcv_nxt]`.
        // Splitting that interval at `u32::MAX` gives at most two numeric ranges
        // in `BTreeMap`, so we always pop the oldest ready segment in wrapping
        // sequence order in O(log n).
        while let Some(seq) = self.next_ready_ooo_seq() {
            // The key was just found in the same map, so the removal cannot
            // miss; `break` keeps the loop terminating regardless.
            let Some(seg) = self.ooo.remove(&seq) else {
                break;
            };
            self.ooo_bytes = self.ooo_bytes.saturating_sub(seg.len());
            let skip = self.rcv_nxt.wrapping_sub(seq) as usize;
            if skip >= seg.len() {
                // Fully stale: every byte is already delivered, so drop it.
                continue;
            }
            let avail = self.rcv_wnd_bytes() as usize;
            if avail == 0 {
                // Receive window is full: keep the bytes queued so a window
                // update delivers them instead of waiting for a retransmit.
                self.ooo_bytes = self.ooo_bytes.saturating_add(seg.len());
                self.ooo.insert(seq, seg);
                break;
            }
            let fresh_len = seg.len() - skip;
            let accept = fresh_len.min(avail);
            if accept > 0 {
                self.rcv_coalesce
                    .extend_from_slice(&seg[skip..skip + accept]);
                self.rcv_nxt = self.rcv_nxt.wrapping_add(accept as u32);
                if self.rcv_coalesce.len() >= RELAY_COALESCE_BYTES {
                    self.queue_coalesce_chunk();
                }
            }
            if accept < fresh_len {
                // Only part of the segment fit: re-queue the remainder at the
                // new `rcv_nxt` instead of discarding fresh bytes. A segment
                // already queued at that key is kept unless the remainder is
                // longer, so `ooo_bytes` stays the exact map footprint.
                let rest = seg[skip + accept..].to_vec();
                let entry = self.ooo.entry(self.rcv_nxt).or_default();
                if rest.len() > entry.len() {
                    self.ooo_bytes = self.ooo_bytes.saturating_add(rest.len() - entry.len());
                    *entry = rest;
                }
                break;
            }
        }
    }

    fn next_ready_ooo_seq(&self) -> Option<u32> {
        let lo = self.rcv_nxt.wrapping_sub(0x8000_0000);
        if lo <= self.rcv_nxt {
            self.ooo.range(lo..=self.rcv_nxt).next().map(|(&k, _)| k)
        } else {
            self.ooo
                .range(lo..=u32::MAX)
                .next()
                .or_else(|| self.ooo.range(0..=self.rcv_nxt).next())
                .map(|(&k, _)| k)
        }
    }

    fn queue_coalesce_chunk(&mut self) {
        if self.rcv_coalesce.is_empty() {
            return;
        }
        let chunk = if self.rcv_coalesce.len() >= RELAY_COALESCE_BYTES {
            // Keep one full coalesce window allocated for the next upload
            // instead of reallocating on every flushed bulk chunk.
            std::mem::replace(
                &mut self.rcv_coalesce,
                Vec::with_capacity(RELAY_COALESCE_BYTES),
            )
        } else {
            std::mem::take(&mut self.rcv_coalesce)
        };
        self.pending_to_relay_bytes = self.pending_to_relay_bytes.saturating_add(chunk.len());
        self.pending_to_relay.push_back(chunk);
    }

    /// Losslessly delivers queued in-order receive chunks to the upstream relay
    /// channel. Clears pending buffers immediately if `to_relay` is closed.
    fn flush_rcv_to_relay(&mut self) {
        self.queue_coalesce_chunk();
        let mut closed = self.to_relay.is_none();
        if let Some(tx) = self.to_relay.as_ref() {
            while let Some(front) = self.pending_to_relay.front() {
                let len = front.len();
                match tx.try_reserve() {
                    Ok(permit) => {
                        if let Some(chunk) = self.pending_to_relay.pop_front() {
                            self.pending_to_relay_bytes =
                                self.pending_to_relay_bytes.saturating_sub(len);
                            self.in_flight_relay.fetch_add(len, Ordering::AcqRel);
                            permit.send(chunk);
                        }
                    }
                    Err(mpsc::error::TrySendError::Full(())) => break,
                    Err(mpsc::error::TrySendError::Closed(())) => {
                        closed = true;
                        break;
                    }
                }
            }
        }
        if closed {
            self.pending_to_relay.clear();
            self.pending_to_relay_bytes = 0;
            self.to_relay.take();
        }
        if self.peer_fin_received && self.pending_to_relay.is_empty() {
            self.to_relay.take();
        }
    }

    fn drain_from_relay(&mut self, now_ms: i64, pool: &RelayBufPool) {
        let Some(rx) = self.from_relay.as_mut() else {
            return;
        };
        while self.tx_buf.len() < self.max_snd_buf {
            if let Some((chunk, offset)) = self.relay_pending.take() {
                let room = self.max_snd_buf.saturating_sub(self.tx_buf.len());
                let take = chunk.len().saturating_sub(offset).min(room);
                self.tx_buf
                    .extend(&chunk[offset..offset.saturating_add(take)]);
                let next = offset.saturating_add(take);
                if next < chunk.len() {
                    self.relay_pending = Some((chunk, next));
                    break;
                }
                pool.put(chunk);
                continue;
            }

            match rx.try_recv() {
                Ok(chunk) => {
                    self.last_activity_ms = now_ms;
                    let room = self.max_snd_buf.saturating_sub(self.tx_buf.len());
                    if chunk.len() > room {
                        self.relay_pending = Some((chunk, 0));
                        continue;
                    }
                    // `tx_buf` is a `VecDeque`, so this is the bulk slice form
                    // (`extend_from_slice` exists only on `Vec`).
                    self.tx_buf.extend(chunk.as_slice());
                    // Recycle the relay buffer so steady-state downloads stop
                    // allocating one chunk allocation per read (#168).
                    pool.put(chunk);
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    self.from_relay.take();
                    self.relay_eof = true;
                    break;
                }
            }
        }
    }

    fn flush_tx(&mut self, now_ms: i64, tx_out: &mut Vec<Vec<u8>>, tx_pool: &mut Vec<Vec<u8>>) {
        if !matches!(self.state, TcpState::Established | TcpState::CloseWait) {
            return;
        }

        loop {
            let in_flight = self.snd_nxt.wrapping_sub(self.snd_una) as usize;
            if in_flight >= self.tx_buf.len() {
                break;
            }
            let wnd_avail = (self.snd_wnd as usize).saturating_sub(in_flight);
            if wnd_avail == 0 {
                // Zero-window persist: if nothing is in flight but data is queued,
                // arm persist timer to probe for window updates.
                if in_flight == 0 && self.persist_deadline_ms.is_none() {
                    self.persist_deadline_ms = Some(now_ms + self.persist_ms);
                }
                break;
            }
            self.persist_deadline_ms = None;
            let unsent = self.tx_buf.len() - in_flight;
            let seg_len = unsent.min(wnd_avail).min(self.mss);
            if seg_len == 0 {
                break;
            }
            let flags = if in_flight + seg_len >= self.tx_buf.len() {
                TCP_ACK | TCP_PSH
            } else {
                TCP_ACK
            };
            let seq = self.snd_nxt;
            let sent = self.emit_tx_segment(in_flight, seg_len, flags, seq, tx_out, Some(tx_pool));
            if sent == 0 {
                break;
            }
            self.snd_nxt = self.snd_nxt.wrapping_add(sent as u32);
            self.need_ack = false;
            if self.rto_deadline_ms.is_none() {
                self.rto_deadline_ms = Some(now_ms + self.rto_ms);
            }
        }

        if self.relay_eof
            && !self.fin_sent
            && (self.snd_nxt.wrapping_sub(self.snd_una) as usize) >= self.tx_buf.len()
        {
            let seq = self.snd_nxt;
            if let Some(pkt) = self.build_packet_slices_pooled(
                TCP_FIN | TCP_ACK,
                &[],
                &[],
                &[],
                seq,
                Some(tx_pool),
            ) {
                tx_out.push(pkt);
            }
            self.fin_sent = true;
            self.fin_seq = seq;
            self.snd_nxt = self.snd_nxt.wrapping_add(1);
            self.need_ack = false;
            self.rto_deadline_ms = Some(now_ms + self.rto_ms);
            // Do NOT arm `CLOSING_TIMEOUT_MS` while `tx_buf` still has unacked
            // bytes (`rto_deadline_ms` bounds unacked data). Arm it only on
            // `LastAck` or once `FinWait1 -> FinWait2`.
            self.state = match self.state {
                TcpState::Established => TcpState::FinWait1,
                TcpState::CloseWait => {
                    if self.tx_buf.is_empty() {
                        self.state_deadline_ms = Some(now_ms + CLOSING_TIMEOUT_MS);
                    }
                    TcpState::LastAck
                }
                other => other,
            };
        }
    }

    fn next_deadline_ms(&self, idle_timeout_ms: i64) -> Option<i64> {
        if self.state == TcpState::Closed {
            return None;
        }
        let idle_deadline = matches!(self.state, TcpState::Established | TcpState::CloseWait)
            .then_some(self.last_activity_ms.saturating_add(idle_timeout_ms));
        [
            self.rto_deadline_ms,
            self.persist_deadline_ms,
            self.state_deadline_ms,
            idle_deadline,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    fn check_timers(
        &mut self,
        now_ms: i64,
        idle_timeout_ms: i64,
        tx_out: &mut Vec<Vec<u8>>,
        tx_pool: &mut Vec<Vec<u8>>,
    ) {
        if let Some(deadline) = self.state_deadline_ms
            && now_ms >= deadline
        {
            self.state = TcpState::Closed;
            self.to_relay.take();
            self.from_relay.take();
            self.relay_pending = None;
            self.pending_to_relay.clear();
            self.pending_to_relay_bytes = 0;
            return;
        }

        // Bound idle `Established` / `CloseWait` connections so abandoned flows
        // cannot leak indefinitely.
        if matches!(self.state, TcpState::Established | TcpState::CloseWait)
            && now_ms.saturating_sub(self.last_activity_ms) >= idle_timeout_ms
        {
            self.send_rst(self.snd_nxt, tx_out);
            return;
        }

        // Zero-window persist probe. Probes are spaced by at most `MAX_RTO_MS`
        // and never touch the data retransmit counter, so a long zero-window
        // stall cannot exhaust the data RTO budget. They stop after
        // `MAX_PERSIST_PROBES` so a peer that keeps answering with `window = 0`
        // cannot pin the socket forever.
        if let Some(persist_at) = self.persist_deadline_ms
            && now_ms >= persist_at
        {
            if self.persist_probes >= MAX_PERSIST_PROBES {
                self.send_rst(self.snd_nxt, tx_out);
                return;
            }
            self.persist_probes += 1;
            self.persist_ms = (self.persist_ms * 2).min(MAX_RTO_MS);
            self.persist_deadline_ms = Some(now_ms + self.persist_ms);
            // Send a zero-window probe ACK (`seq = snd_una - 1`) to elicit a
            // window update from the peer without advancing `snd_nxt`.
            let probe_seq = self.snd_una.wrapping_sub(1);
            if let Some(pkt) = self.build_packet_slices(TCP_ACK, &[], &[], &[], probe_seq) {
                tx_out.push(pkt);
            }
        }

        if let Some(rto_at) = self.rto_deadline_ms
            && now_ms >= rto_at
        {
            if self.retries >= MAX_RETRIES {
                self.send_rst(self.snd_nxt, tx_out);
                return;
            }
            self.retries += 1;
            self.rto_ms = (self.rto_ms * 2).min(MAX_RTO_MS);
            self.rto_deadline_ms = Some(now_ms + self.rto_ms);

            match self.state {
                TcpState::SynReceived => {
                    self.send_syn_ack(now_ms, tx_out);
                }
                TcpState::Established
                | TcpState::CloseWait
                | TcpState::FinWait1
                | TcpState::LastAck => {
                    if !self.tx_buf.is_empty() {
                        let len = self.tx_buf.len().min(self.mss);
                        self.emit_tx_segment(
                            0,
                            len,
                            TCP_ACK | TCP_PSH,
                            self.snd_una,
                            tx_out,
                            Some(tx_pool),
                        );
                    } else if self.fin_sent
                        && self.snd_una == self.fin_seq
                        && let Some(pkt) =
                            self.build_packet_slices(TCP_FIN | TCP_ACK, &[], &[], &[], self.fin_seq)
                    {
                        tx_out.push(pkt);
                    }
                }
                _ => {}
            }
        }
    }
}

/// Custom proxy-oriented [`NetStack`] implementation supporting IPv4 + IPv6,
/// RFC 7323 Window Scaling, zero-copy TX segmentation, and ACK coalescing.
pub struct ProxyTcpStack {
    config: TcpStackConfig,
    conns: HashMap<FlowKey, TcpConn>,
    incoming_buf: Vec<u8>,
    incoming_lens: Vec<usize>,
    dirty: Arc<DirtyFlowQueue>,
    timers: BinaryHeap<Reverse<(i64, FlowKey)>>,
    poll_batch: Vec<FlowKey>,
    relay_pool: Arc<RelayBufPool>,
    tx_buf_pool: Vec<Vec<u8>>,
    drops: Option<Arc<DropCounters>>,
    #[cfg(test)]
    last_poll_count: usize,
}

impl ProxyTcpStack {
    /// Creates a new custom proxy TCP stack.
    pub fn new(config: TcpStackConfig) -> Self {
        Self {
            config,
            conns: HashMap::new(),
            incoming_buf: Vec::with_capacity(64 * 1024),
            incoming_lens: Vec::with_capacity(128),
            dirty: Arc::new(DirtyFlowQueue {
                queue: Mutex::new(VecDeque::with_capacity(64)),
                waker: Arc::new(Notify::new()),
            }),
            timers: BinaryHeap::new(),
            poll_batch: Vec::with_capacity(64),
            relay_pool: RelayBufPool::new(),
            tx_buf_pool: Vec::with_capacity(64),
            drops: None,
            #[cfg(test)]
            last_poll_count: 0,
        }
    }

    fn idle_timeout_ms(&self) -> i64 {
        i64::try_from(self.config.idle_timeout_ms)
            .unwrap_or(i64::MAX)
            .max(1)
    }

    /// Releases the oversized inbound buffers a burst left behind, so a single
    /// burst does not pin its peak allocation for the life of the stack.
    fn shrink_incoming_bufs(&mut self) {
        if self.incoming_buf.capacity() > INCOMING_BUF_SHRINK_THRESHOLD {
            self.incoming_buf.shrink_to(INCOMING_BUF_SHRINK_TARGET);
        }
        if self.incoming_lens.capacity() > INCOMING_LENS_SHRINK_THRESHOLD {
            self.incoming_lens.shrink_to(INCOMING_LENS_SHRINK_TARGET);
        }
    }

    fn schedule_conn_timer(
        timers: &mut BinaryHeap<Reverse<(i64, FlowKey)>>,
        flow: FlowKey,
        conn: &mut TcpConn,
        idle_timeout_ms: i64,
    ) {
        if let Some(actual) = conn.next_deadline_ms(idle_timeout_ms) {
            let need_push = match conn.heap_deadline_ms {
                None => true,
                Some(h) => actual < h,
            };
            if need_push {
                conn.heap_deadline_ms = Some(actual);
                timers.push(Reverse((actual, flow)));
            }
        }
    }

    /// Tiered soft eviction when the TCP table is full so closing/stale flows
    /// yield their slot before a new SYN is rejected with `tcp_limit`:
    /// 1. Oldest closing flow (`FinWait1`/`FinWait2`/`Closing`/`LastAck`/
    ///    `CloseWait`) with empty buffers idle for at least
    ///    `SOFT_EVICT_ESTABLISHED_IDLE_MS`.
    /// 2. Oldest half-open `SynReceived` flow idle for at least `SOFT_EVICT_SYN_MIN_AGE_MS`.
    /// 3. Oldest quiescent `Established` flow with empty buffers idle for at
    ///    least `SOFT_EVICT_ESTABLISHED_IDLE_MS`.
    ///
    /// A fresh closing flow or a buffered half-closed transfer is not a victim,
    /// so an old idle `Established` flow yields its slot instead.
    fn evict_one_stale_conn(
        conns: &mut HashMap<FlowKey, TcpConn>,
        poll_batch: &mut Vec<FlowKey>,
        now_ms: i64,
        tx_out: &mut Vec<Vec<u8>>,
    ) -> bool {
        let mut best_closing: Option<(i64, FlowKey)> = None;
        let mut best_syn: Option<(i64, FlowKey)> = None;
        let mut best_idle: Option<(i64, FlowKey)> = None;

        for (&flow, conn) in conns.iter() {
            let age_ms = now_ms.saturating_sub(conn.last_activity_ms);
            match conn.state {
                TcpState::FinWait1
                | TcpState::FinWait2
                | TcpState::Closing
                | TcpState::LastAck
                | TcpState::CloseWait
                    if age_ms >= SOFT_EVICT_ESTABLISHED_IDLE_MS
                        && !conn.has_buffered_data()
                        && best_closing.is_none_or(|(ts, _)| conn.last_activity_ms < ts) =>
                {
                    best_closing = Some((conn.last_activity_ms, flow));
                }
                TcpState::SynReceived if age_ms >= SOFT_EVICT_SYN_MIN_AGE_MS => {
                    if best_syn.is_none_or(|(ts, _)| conn.last_activity_ms < ts) {
                        best_syn = Some((conn.last_activity_ms, flow));
                    }
                }
                TcpState::Established
                    if age_ms >= SOFT_EVICT_ESTABLISHED_IDLE_MS
                        && !is_protected_push_port(flow.3)
                        && !conn.has_buffered_data()
                        && best_idle.is_none_or(|(ts, _)| conn.last_activity_ms < ts) =>
                {
                    best_idle = Some((conn.last_activity_ms, flow));
                }
                _ => {}
            }
        }

        let Some((_, victim_flow)) = best_closing.or(best_syn).or(best_idle) else {
            return false;
        };
        if let Some(mut victim) = conns.remove(&victim_flow) {
            victim.aborted.store(true, Ordering::Release);
            victim.send_rst(victim.snd_nxt, tx_out);
            poll_batch.retain(|queued| *queued != victim_flow);
            // Dropping `victim` closes `to_relay`/`from_relay`, waking and
            // tearing down any attached Tokio relay task and upstream socket.
            drop(victim);
            return true;
        }
        false
    }

    /// Creates a socket for a pure SYN, or answers `RST|ACK` when the connection
    /// table is full. Returns `true` when a socket was inserted.
    #[allow(clippy::too_many_arguments)]
    fn insert_new_conn(
        config: &TcpStackConfig,
        conns: &mut HashMap<FlowKey, TcpConn>,
        poll_batch: &mut Vec<FlowKey>,
        flow: FlowKey,
        ip: &crate::packet::IpPacketView<'_>,
        seg: &crate::packet::TcpSegmentView<'_>,
        now_ms: i64,
        tx_out: &mut Vec<Vec<u8>>,
        drops: Option<&DropCounters>,
    ) -> bool {
        if conns.len() >= config.max_connections
            && !Self::evict_one_stale_conn(conns, poll_batch, now_ms, tx_out)
        {
            if let Some(drops) = drops {
                drops.tcp_limit.incr();
            }
            if let Some(rst) = build_ip_tcp_packet_slices(
                ip.dst_ip,
                seg.dst_port,
                ip.src_ip,
                seg.src_port,
                0,
                seg.seq.wrapping_add(1),
                TCP_RST | TCP_ACK,
                0,
                &[],
                &[],
                &[],
            ) {
                tx_out.push(rst);
            }
            return false;
        }
        let (peer_mss, peer_wscale) = parse_tcp_syn_options(seg.options);
        let header_overhead = match ip.src_ip {
            IpAddr::V4(_) => 40,
            IpAddr::V6(_) => 60,
        };
        let max_mss = config.mtu.saturating_sub(header_overhead).clamp(536, 1460);
        let mss = peer_mss
            .map(|m| usize::from(m).clamp(536, max_mss))
            .unwrap_or(max_mss);
        let (our_wscale, negotiated_peer_wscale) = match peer_wscale {
            Some(ws) => (OUR_WSCALE, ws),
            None => (0, 0),
        };
        let iss = next_iss();
        let base_buf = config.socket_buffer_bytes.clamp(MIN_TCP_BUF, MAX_TCP_BUF);
        // On high-RAM mobile profiles (>128 flows, <=128 KiB base buffer), halve
        // the per-flow buffer above 128 concurrent flows so worst-case native RSS
        // stays tightly bounded without sacrificing local-TUN throughput (~1 Gbps).
        let max_buf = if conns.len() >= ADAPTIVE_BUF_HALVE_FLOW_THRESHOLD
            && config.max_connections > ADAPTIVE_BUF_HALVE_FLOW_THRESHOLD
            && config.socket_buffer_bytes <= 128 * 1024
        {
            (base_buf / 2).max(MIN_TCP_BUF)
        } else {
            base_buf
        };
        let mut conn = TcpConn {
            flow,
            state: TcpState::SynReceived,
            mss,
            peer_wscale: negotiated_peer_wscale,
            our_wscale,
            rcv_isn: seg.seq,
            rcv_nxt: seg.seq.wrapping_add(1),
            rcv_coalesce: Vec::new(),
            pending_to_relay: VecDeque::new(),
            pending_to_relay_bytes: 0,
            ooo: BTreeMap::new(),
            ooo_bytes: 0,
            in_flight_relay: Arc::new(AtomicUsize::new(0)),
            max_rcv_buf: max_buf,
            last_advertised_wnd: max_buf.min(usize::from(u16::MAX)) as u32,
            need_ack: false,
            peer_fin_received: false,
            peer_fin_seq: None,
            snd_una: iss,
            snd_nxt: iss,
            snd_wnd: u32::from(seg.window),
            snd_wl1: seg.seq,
            snd_wl2: seg.ack,
            tx_buf: VecDeque::new(),
            max_snd_buf: max_buf,
            fin_sent: false,
            fin_seq: 0,
            dup_acks: 0,
            rto_ms: INITIAL_RTO_MS,
            rto_deadline_ms: None,
            persist_ms: INITIAL_RTO_MS,
            persist_deadline_ms: None,
            persist_probes: 0,
            retries: 0,
            state_deadline_ms: Some(now_ms.saturating_add(handshake_timeout_ms(config))),
            last_activity_ms: now_ms,
            heap_deadline_ms: None,
            in_poll_batch: false,
            accepted: false,
            dirty_handle: None,
            to_relay: None,
            from_relay: None,
            relay_pending: None,
            relay_eof: false,
            aborted: Arc::new(AtomicBool::new(false)),
        };
        conn.send_syn_ack(now_ms, tx_out);
        conns.insert(flow, conn);
        true
    }
}

impl NetStack for ProxyTcpStack {
    fn push_ip_tcp(&mut self, packet: &[u8]) {
        if self.incoming_lens.len() < MAX_INCOMING_PACKETS
            && self.incoming_buf.len().saturating_add(packet.len()) <= MAX_INCOMING_BYTES
        {
            self.incoming_buf.extend_from_slice(packet);
            self.incoming_lens.push(packet.len());
        } else if let Some(drops) = self.drops.as_ref() {
            drops.tcp_rx_overflow.incr();
        }
    }

    fn set_drop_counters(&mut self, drops: Arc<DropCounters>) {
        self.drops = Some(drops);
    }

    fn recycle_tx_buf(&mut self, mut buf: Vec<u8>) {
        if buf.capacity() > 0
            && self.tx_buf_pool.len() < TX_BUF_POOL_MAX
            && buf.capacity() <= TX_BUF_MAX_RETAIN_CAP
        {
            buf.clear();
            self.tx_buf_pool.push(buf);
        }
    }

    fn poll(
        &mut self,
        now_ms: i64,
        tx_out: &mut Vec<Vec<u8>>,
        accepted: &mut Vec<AcceptedTcpStream>,
    ) {
        let idle_timeout_ms = self.idle_timeout_ms();
        self.poll_batch.clear();

        let mut offset = 0usize;
        for idx in 0..self.incoming_lens.len() {
            let len = self.incoming_lens[idx];
            let pkt = &self.incoming_buf[offset..offset + len];
            offset += len;
            let Some(ip) = parse_ip(pkt) else {
                continue;
            };
            if ip.protocol != IP_PROTO_TCP {
                continue;
            }
            let Some(seg) = parse_tcp(ip.payload) else {
                continue;
            };
            let flow: FlowKey = (ip.src_ip, seg.src_port, ip.dst_ip, seg.dst_port);
            let pure_syn = (seg.flags & TCP_SYN) != 0 && (seg.flags & TCP_ACK) == 0;

            // A pure SYN for a 4-tuple that is already tracked (`SynReceived`
            // or synchronized) and carries a different ISN than the live flow
            // is a new connection attempt: the local peer restarted and its
            // old socket is gone. Reset the stale flow and accept the new SYN
            // instead of dropping the handshake. This assumes a local TUN
            // peer, which keeps one socket per 4-tuple, so a repeated ISN can
            // only be a duplicate of the original SYN (which re-sends
            // SYN|ACK via `on_segment`).
            if pure_syn
                && self.conns.get(&flow).is_some_and(|conn| {
                    (conn.state.is_synchronized() || conn.state == TcpState::SynReceived)
                        && seg.seq != conn.rcv_isn
                })
                && let Some(mut stale) = self.conns.remove(&flow)
            {
                stale.send_rst(stale.snd_nxt, tx_out);
                self.poll_batch.retain(|queued| *queued != flow);
            }

            if let Some(conn) = self.conns.get_mut(&flow) {
                conn.on_segment(&seg, now_ms, tx_out, &mut self.tx_buf_pool);
                if !conn.in_poll_batch {
                    conn.in_poll_batch = true;
                    self.poll_batch.push(flow);
                }
            } else if pure_syn {
                if Self::insert_new_conn(
                    &self.config,
                    &mut self.conns,
                    &mut self.poll_batch,
                    flow,
                    &ip,
                    &seg,
                    now_ms,
                    tx_out,
                    self.drops.as_deref(),
                ) && let Some(conn) = self.conns.get_mut(&flow)
                {
                    conn.in_poll_batch = true;
                    self.poll_batch.push(flow);
                }
            } else if (seg.flags & TCP_RST) == 0 {
                let rst_seq = if (seg.flags & TCP_ACK) != 0 {
                    seg.ack
                } else {
                    0
                };
                if let Some(rst) = build_ip_tcp_packet_slices(
                    ip.dst_ip,
                    seg.dst_port,
                    ip.src_ip,
                    seg.src_port,
                    rst_seq,
                    seg.seq.wrapping_add(seg.payload.len() as u32),
                    TCP_RST | TCP_ACK,
                    0,
                    &[],
                    &[],
                    &[],
                ) {
                    tx_out.push(rst);
                }
            }
        }
        self.incoming_buf.clear();
        self.incoming_lens.clear();
        self.shrink_incoming_bufs();

        // Drain flows dirtied by async relay tasks (`TunTcpStream` / Reader / Writer).
        {
            let mut q = self.dirty.queue.lock().unwrap_or_else(|e| e.into_inner());
            while let Some(flow) = q.pop_front() {
                if let Some(conn) = self.conns.get_mut(&flow) {
                    if let Some(handle) = conn.dirty_handle.as_ref() {
                        handle.clear_queued();
                    }
                    if !conn.in_poll_batch {
                        conn.in_poll_batch = true;
                        self.poll_batch.push(flow);
                    }
                }
            }
        }

        // Pop flows whose timer deadline is due (`<= now_ms`), lazily rescheduling
        // flows whose true deadline moved forward since insertion.
        while let Some(&Reverse((deadline, flow))) = self.timers.peek() {
            if deadline > now_ms {
                break;
            }
            self.timers.pop();
            let Some(conn) = self.conns.get_mut(&flow) else {
                continue;
            };
            if conn.heap_deadline_ms != Some(deadline) {
                continue;
            }
            conn.heap_deadline_ms = None;
            if let Some(actual) = conn.next_deadline_ms(idle_timeout_ms) {
                if actual <= now_ms {
                    if !conn.in_poll_batch {
                        conn.in_poll_batch = true;
                        self.poll_batch.push(flow);
                    }
                } else {
                    conn.heap_deadline_ms = Some(actual);
                    self.timers.push(Reverse((actual, flow)));
                }
            }
        }

        #[cfg(test)]
        {
            self.last_poll_count = self.poll_batch.len();
        }

        let mut poll_batch = std::mem::take(&mut self.poll_batch);
        for flow in poll_batch.drain(..) {
            let mut keep = false;
            if let Some(conn) = self.conns.get_mut(&flow) {
                conn.in_poll_batch = false;
                if let Some(handle) = conn.dirty_handle.as_ref() {
                    handle.clear_queued();
                }

                if !conn.accepted
                    && matches!(conn.state, TcpState::Established | TcpState::CloseWait)
                {
                    let (to_relay_tx, to_relay_rx) = mpsc::channel(STREAM_CHANNEL_CAP);
                    let (from_relay_tx, from_relay_rx) = mpsc::channel(S2C_STREAM_CHANNEL_CAP);
                    let handle = Arc::new(FlowDirtyHandle::new(flow, Arc::clone(&self.dirty)));
                    let flow_waker: Arc<dyn FlowWaker> = Arc::clone(&handle) as Arc<dyn FlowWaker>;
                    conn.accepted = true;
                    conn.dirty_handle = Some(handle);
                    conn.to_relay = Some(to_relay_tx);
                    conn.from_relay = Some(from_relay_rx);
                    accepted.push(AcceptedTcpStream {
                        src: SocketAddr::new(conn.flow.0, conn.flow.1),
                        dst: SocketAddr::new(conn.flow.2, conn.flow.3),
                        stream: TunTcpStream::new_with_accounting(
                            to_relay_rx,
                            from_relay_tx,
                            Arc::clone(&self.dirty.waker),
                            Some(flow_waker),
                            Some(Arc::clone(&conn.in_flight_relay)),
                            Some(Arc::clone(&conn.aborted)),
                            Arc::clone(&self.relay_pool),
                        ),
                    });
                }

                if conn.aborted.load(Ordering::Acquire) {
                    if conn.state != TcpState::Closed {
                        conn.send_rst(conn.snd_nxt, tx_out);
                    }
                } else {
                    conn.flush_rcv_to_relay();
                    if !conn.ooo.is_empty()
                        && !conn.peer_fin_received
                        && matches!(
                            conn.state,
                            TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2
                        )
                        && conn.in_order_rcv_bytes() < conn.max_rcv_buf
                    {
                        let rcv_before = conn.rcv_nxt;
                        conn.drain_ooo();
                        if conn.rcv_nxt != rcv_before {
                            if let Some(fin_seq) = conn.peer_fin_seq
                                && fin_seq == conn.rcv_nxt
                                && !conn.peer_fin_received
                            {
                                conn.peer_fin_seq = None;
                                conn.consume_peer_fin(now_ms, tx_out);
                            }
                            if conn.state != TcpState::Closed {
                                conn.need_ack = true;
                            }
                            conn.flush_rcv_to_relay();
                        }
                    }
                    conn.drain_from_relay(now_ms, &self.relay_pool);
                    conn.flush_tx(now_ms, tx_out, &mut self.tx_buf_pool);

                    // Emit a Window Update ACK promptly when:
                    // 1. Reopening from a low/zero advertised window to >= reopen_threshold, OR
                    // 2. Available receive window has grown by >= growth_step above
                    //    `last_advertised_wnd` (RFC 1122 / Linux tcp_select_window).
                    // Thresholds are derived from `effective_max_wnd` so peers without
                    // RFC 7323 Window Scale (`our_wscale == 0`, max 65_535) still reopen.
                    let effective_max_wnd =
                        (conn.max_rcv_buf as u32).min(u32::from(u16::MAX) << conn.our_wscale);
                    let current_wnd = conn.rcv_wnd_bytes();
                    let reopen_threshold = (effective_max_wnd / 4).clamp(1, 256 * 1024);
                    let growth_step = (effective_max_wnd / 4).clamp(1, 1024 * 1024);
                    if !conn.need_ack
                        && matches!(
                            conn.state,
                            TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2
                        )
                        && ((conn.last_advertised_wnd < reopen_threshold
                            && current_wnd >= reopen_threshold)
                            || current_wnd.saturating_sub(conn.last_advertised_wnd) >= growth_step)
                    {
                        conn.need_ack = true;
                    }

                    if conn.need_ack && conn.state != TcpState::Closed {
                        if let Some(pkt) = conn.build_packet_slices_pooled(
                            TCP_ACK,
                            &[],
                            &[],
                            &[],
                            conn.snd_nxt,
                            Some(&mut self.tx_buf_pool),
                        ) {
                            tx_out.push(pkt);
                        }
                        conn.need_ack = false;
                    }

                    conn.check_timers(now_ms, idle_timeout_ms, tx_out, &mut self.tx_buf_pool);
                    keep = conn.state != TcpState::Closed;
                    if keep {
                        conn.shrink_idle_bufs(now_ms);
                        Self::schedule_conn_timer(&mut self.timers, flow, conn, idle_timeout_ms);
                    }
                }
            }
            if !keep {
                self.conns.remove(&flow);
            }
        }
        self.poll_batch = poll_batch;

        // Keep the timer heap strictly bounded against stale entries.
        let max_heap_entries = self.conns.len().saturating_mul(4).saturating_add(64);
        if self.timers.len() > max_heap_entries {
            self.timers.clear();
            for (&flow, conn) in &mut self.conns {
                conn.heap_deadline_ms = conn.next_deadline_ms(idle_timeout_ms);
                if let Some(d) = conn.heap_deadline_ms {
                    self.timers.push(Reverse((d, flow)));
                }
            }
        }
    }

    fn poll_delay_ms(&mut self, now_ms: i64) -> Option<u64> {
        let idle_timeout_ms = self.idle_timeout_ms();
        while let Some(&Reverse((deadline, flow))) = self.timers.peek() {
            let Some(conn) = self.conns.get_mut(&flow) else {
                self.timers.pop();
                continue;
            };
            if conn.heap_deadline_ms != Some(deadline) {
                self.timers.pop();
                continue;
            }
            match conn.next_deadline_ms(idle_timeout_ms) {
                None => {
                    conn.heap_deadline_ms = None;
                    self.timers.pop();
                }
                Some(actual) if actual > deadline => {
                    self.timers.pop();
                    conn.heap_deadline_ms = Some(actual);
                    self.timers.push(Reverse((actual, flow)));
                }
                Some(actual) => {
                    return Some(actual.saturating_sub(now_ms).max(1) as u64);
                }
            }
        }
        None
    }

    fn waker(&self) -> Arc<Notify> {
        Arc::clone(&self.dirty.waker)
    }

    fn reset_all(&mut self, tx_out: &mut Vec<Vec<u8>>) {
        for (_, mut conn) in self.conns.drain() {
            conn.send_rst(conn.snd_nxt, tx_out);
        }
        self.incoming_buf.clear();
        self.incoming_lens.clear();
        self.shrink_incoming_bufs();
        self.timers.clear();
        self.poll_batch.clear();
        self.dirty
            .queue
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }
}

/// Returns a fresh TCP initial sequence number from the system CSPRNG, so the
/// ISN of one connection does not predict the ISN of the next. A failed RNG
/// read falls back to the system clock and counter instead of panicking.
fn next_iss() -> u32 {
    static RNG: std::sync::OnceLock<&'static dyn rustls::crypto::SecureRandom> =
        std::sync::OnceLock::new();
    let rng = *RNG.get_or_init(|| rustls::crypto::aws_lc_rs::default_provider().secure_random);
    let mut buf = [0u8; 4];
    if rng.fill(&mut buf).is_ok() {
        return u32::from_be_bytes(buf);
    }
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    (now ^ n.wrapping_mul(0x9e37_79b9_7f4a_7c15)) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const SRC_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(172, 19, 0, 1));
    const DST_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
    const SRC_PORT: u16 = 40_000;
    const DST_PORT: u16 = 443;

    fn make_seg(
        seq: u32,
        ack: u32,
        flags: u8,
        window: u16,
        opts: &[u8],
        payload: &[u8],
    ) -> Vec<u8> {
        build_ip_tcp_packet_slices(
            SRC_IP,
            SRC_PORT,
            DST_IP,
            DST_PORT,
            seq,
            ack,
            flags,
            window,
            opts,
            payload,
            &[],
        )
        .expect("build tcp seg")
    }

    fn handshake(stack: &mut ProxyTcpStack, client_isn: u32) -> (u32, AcceptedTcpStream) {
        // SYN with MSS=1460 and WScale=6
        let opts = [2, 4, 0x05, 0xb4, 1, 3, 3, 6];
        stack.push_ip_tcp(&make_seg(client_isn, 0, TCP_SYN, 65535, &opts, &[]));
        let mut tx = Vec::new();
        let mut accepted = Vec::new();
        stack.poll(10, &mut tx, &mut accepted);
        assert_eq!(tx.len(), 1);
        let syn_ack = parse_tcp(parse_ip(&tx[0]).expect("ip").payload).expect("tcp");
        assert_eq!(syn_ack.flags, TCP_SYN | TCP_ACK);
        // RFC 7323 §2.2: SYN+ACK window must be unscaled (65535 for >=64 KiB buffer).
        assert_eq!(syn_ack.window, u16::MAX);

        let srv_isn = syn_ack.seq;
        stack.push_ip_tcp(&make_seg(
            client_isn.wrapping_add(1),
            srv_isn.wrapping_add(1),
            TCP_ACK,
            1024,
            &[],
            &[],
        ));
        tx.clear();
        stack.poll(20, &mut tx, &mut accepted);
        assert_eq!(accepted.len(), 1);
        (srv_isn.wrapping_add(1), accepted.pop().expect("accepted"))
    }

    #[test]
    fn i32_min_sequence_offset_does_not_panic() {
        let mut stack = ProxyTcpStack::new(TcpStackConfig::default());
        let (srv_nxt, _stream) = handshake(&mut stack, 1000);
        // `seq = rcv_nxt + 0x8000_0000` produces `rel == i32::MIN`.
        let hostile_seq = 1001u32.wrapping_add(0x8000_0000);
        stack.push_ip_tcp(&make_seg(hostile_seq, srv_nxt, TCP_ACK, 1024, &[], b"boom"));
        let mut tx = Vec::new();
        let mut accepted = Vec::new();
        stack.poll(30, &mut tx, &mut accepted);
        // Must survive without panicking and without advancing rcv_nxt.
        let conn = stack.conns.values().next().expect("conn alive");
        assert_eq!(conn.rcv_nxt, 1001);
    }

    #[tokio::test]
    async fn ooo_reassembly_and_ooo_fin_deliver_in_order_and_emit_dup_acks() {
        let mut stack = ProxyTcpStack::new(TcpStackConfig::default());
        let (srv_nxt, acc) = handshake(&mut stack, 5000);
        let (mut reader, _writer) = acc.stream.into_split();

        // Send second chunk + FIN out-of-order (ahead of rcv_nxt = 5001).
        stack.push_ip_tcp(&make_seg(
            5006,
            srv_nxt,
            TCP_ACK | TCP_FIN,
            1024,
            &[],
            b"world",
        ));
        let mut tx = Vec::new();
        let mut accepted = Vec::new();
        stack.poll(30, &mut tx, &mut accepted);
        // Must emit an immediate dup-ACK for the OOO segment.
        assert_eq!(tx.len(), 1);
        let dup_ack = parse_tcp(parse_ip(&tx[0]).expect("ip").payload).expect("tcp");
        assert_eq!(dup_ack.ack, 5001);

        // Now send the missing first chunk ("hello").
        tx.clear();
        stack.push_ip_tcp(&make_seg(5001, srv_nxt, TCP_ACK, 1024, &[], b"hello"));
        stack.poll(40, &mut tx, &mut accepted);

        let chunk = reader.recv_chunk().await.expect("reassembled data");
        assert_eq!(chunk, b"helloworld");
        // OOO FIN must now have closed the reader cleanly (EOF).
        assert!(reader.recv_chunk().await.is_none());
    }

    #[tokio::test]
    async fn full_coalesce_window_keeps_its_capacity_while_a_small_flush_releases_it() {
        let mut stack = ProxyTcpStack::new(TcpStackConfig::default());
        let (_srv_nxt, stream) = handshake(&mut stack, 1000);
        let (mut reader, _writer) = stream.stream.into_split();
        let conn = stack.conns.values_mut().next().expect("conn");

        conn.rcv_coalesce = vec![0xab; RELAY_COALESCE_BYTES];
        conn.flush_rcv_to_relay();
        assert!(reader.try_recv_chunk().is_some(), "full window delivered");
        assert!(
            conn.rcv_coalesce.capacity() >= RELAY_COALESCE_BYTES,
            "a full window must stay allocated for the next bulk chunk"
        );

        conn.rcv_coalesce = vec![0xcd; 1024];
        conn.flush_rcv_to_relay();
        assert!(reader.try_recv_chunk().is_some(), "partial chunk delivered");
        assert_eq!(
            conn.rcv_coalesce.capacity(),
            0,
            "a partial chunk must not pin a 64 KiB buffer"
        );
    }

    #[test]
    fn drain_ooo_delivers_across_the_u32_wraparound() {
        let mut stack = ProxyTcpStack::new(TcpStackConfig::default());
        let (_srv_nxt, _acc) = handshake(&mut stack, 1000);
        let conn = stack.conns.values_mut().next().expect("conn");

        // Start two bytes before the wrap so the queued segments cross it.
        conn.rcv_nxt = u32::MAX - 1;
        conn.rcv_coalesce.clear();
        conn.ooo.clear();
        conn.ooo_bytes = 0;
        for (seq, payload) in [(u32::MAX - 1, &b"ab"[..]), (0, &b"cd"[..]), (2, &b"ef"[..])] {
            conn.ooo.insert(seq, payload.to_vec());
            conn.ooo_bytes += payload.len();
        }

        conn.drain_ooo();
        assert_eq!(conn.rcv_coalesce, b"abcdef");
        assert_eq!(conn.rcv_nxt, 4);
        assert!(conn.ooo.is_empty());
        assert_eq!(conn.ooo_bytes, 0);
    }

    #[test]
    fn drain_ooo_skips_stale_and_keeps_unready_segments() {
        let mut stack = ProxyTcpStack::new(TcpStackConfig::default());
        let (_srv_nxt, _acc) = handshake(&mut stack, 1000);
        let conn = stack.conns.values_mut().next().expect("conn");
        conn.rcv_nxt = 100;
        conn.rcv_coalesce.clear();
        conn.ooo.clear();
        conn.ooo_bytes = 0;

        conn.ooo.insert(90, b"stale".to_vec()); // fully behind: dropped
        conn.ooo.insert(99, b"overlap".to_vec()); // last byte is in window
        conn.ooo.insert(112, b"gap".to_vec()); // still ahead: stays
        conn.ooo_bytes = 5 + 7 + 3;
        conn.drain_ooo();

        // "overlap" starts at 99, so byte 100 onward is accepted.
        assert_eq!(conn.rcv_coalesce, b"verlap");
        assert_eq!(conn.rcv_nxt, 106);
        assert_eq!(conn.ooo.keys().copied().collect::<Vec<_>>(), vec![112]);
        assert_eq!(conn.ooo_bytes, 3);
    }

    #[test]
    fn drain_ooo_preserves_future_and_drains_stale_across_wraparound() {
        let mut stack = ProxyTcpStack::new(TcpStackConfig::default());
        let (_srv_nxt, _acc) = handshake(&mut stack, 1000);
        let conn = stack.conns.values_mut().next().expect("conn");

        // Hole right before u32::MAX: wrapped future segments at 0 and 2 must
        // stay queued, NOT be discarded as stale.
        conn.rcv_nxt = u32::MAX - 1;
        conn.rcv_coalesce.clear();
        conn.ooo.clear();
        conn.ooo_bytes = 0;
        conn.ooo.insert(0, b"cd".to_vec());
        conn.ooo.insert(2, b"ef".to_vec());
        conn.ooo_bytes = 4;
        conn.drain_ooo();
        assert!(conn.rcv_coalesce.is_empty());
        assert_eq!(conn.rcv_nxt, u32::MAX - 1);
        assert_eq!(conn.ooo.keys().copied().collect::<Vec<_>>(), vec![0, 2]);
        assert_eq!(conn.ooo_bytes, 4);

        // Stale segment behind u32::MAX when rcv_nxt has already wrapped to 1
        // must be drained so it cannot pin ooo_bytes forever.
        conn.rcv_nxt = 1;
        conn.ooo.clear();
        conn.ooo.insert(u32::MAX - 1, b"ab".to_vec()); // bytes MAX-1..=MAX (stale)
        conn.ooo.insert(3, b"gh".to_vec()); // future: stays
        conn.ooo_bytes = 4;
        conn.drain_ooo();
        assert!(conn.rcv_coalesce.is_empty());
        assert_eq!(conn.rcv_nxt, 1);
        assert_eq!(conn.ooo.keys().copied().collect::<Vec<_>>(), vec![3]);
        assert_eq!(conn.ooo_bytes, 2);

        // Overlapping ready segments resolve oldest-first.
        conn.rcv_nxt = 100;
        conn.ooo.clear();
        conn.ooo.insert(98, b"xxOLD!".to_vec()); // covers 98..104 -> "OLD!"
        conn.ooo.insert(100, b"NEW!".to_vec()); // covers 100..104 -> skipped after 98 advances rcv_nxt
        conn.ooo_bytes = 10;
        conn.drain_ooo();
        assert_eq!(conn.rcv_coalesce, b"OLD!");
        assert_eq!(conn.rcv_nxt, 104);
        assert!(conn.ooo.is_empty());
        assert_eq!(conn.ooo_bytes, 0);

        // Non-wrapping boundary (`rcv_nxt = 0x8000_0000`, `lo = 0`): ready set
        // is `0..=0x8000_0000` (oldest ready key `0` is stale and dropped, then
        // `0x8000_0000` is delivered; `0x8000_0004` stays queued).
        conn.rcv_nxt = 0x8000_0000;
        conn.rcv_coalesce.clear();
        conn.ooo.clear();
        conn.ooo.insert(0, b"stale".to_vec());
        conn.ooo.insert(0x8000_0000, b"ok".to_vec());
        conn.ooo.insert(0x8000_0004, b"later".to_vec());
        conn.ooo_bytes = 12;
        conn.drain_ooo();
        assert_eq!(conn.rcv_coalesce, b"ok");
        assert_eq!(conn.rcv_nxt, 0x8000_0002);
        assert_eq!(
            conn.ooo.keys().copied().collect::<Vec<_>>(),
            vec![0x8000_0004]
        );
        assert_eq!(conn.ooo_bytes, 5);
    }

    #[test]
    fn iss_is_not_constant_across_connections() {
        let first = next_iss();
        let mut distinct = 0;
        for _ in 0..64 {
            if next_iss() != first {
                distinct += 1;
            }
        }
        assert!(distinct >= 32, "ISN looks constant: {distinct}/64 differ");
    }

    #[test]
    fn out_of_order_segments_are_not_admitted_into_a_full_window() {
        let cfg = TcpStackConfig {
            socket_buffer_bytes: MIN_TCP_BUF, // 64 KiB
            ..TcpStackConfig::default()
        };
        let mut stack = ProxyTcpStack::new(cfg);
        let (_srv_nxt, _acc) = handshake(&mut stack, 1000);
        let conn = stack.conns.values_mut().next().expect("conn");
        conn.rcv_nxt = 5001;
        conn.ooo.clear();
        conn.ooo_bytes = 0;
        // In-order data already fills the whole receive buffer.
        conn.rcv_coalesce = vec![0xab; MIN_TCP_BUF];
        assert_eq!(conn.rcv_wnd_bytes(), 0);

        assert!(
            conn.process_data(6001, b"out-of-order"),
            "a segment ahead of rcv_nxt is out-of-order"
        );
        assert!(conn.ooo.is_empty(), "a full window must admit no OOO bytes");
        assert_eq!(conn.ooo_bytes, 0);
        assert_eq!(conn.rcv_nxt, 5001, "rcv_nxt must not move for OOO data");
    }

    #[test]
    fn drain_ooo_keeps_queued_data_until_the_window_opens() {
        let cfg = TcpStackConfig {
            socket_buffer_bytes: MIN_TCP_BUF, // 64 KiB
            ..TcpStackConfig::default()
        };
        let mut stack = ProxyTcpStack::new(cfg);
        let (_srv_nxt, _acc) = handshake(&mut stack, 1000);
        let conn = stack.conns.values_mut().next().expect("conn");
        conn.rcv_nxt = 5001;
        conn.rcv_coalesce.clear();
        conn.ooo.clear();
        conn.ooo.insert(5001, b"hello".to_vec());
        conn.ooo_bytes = 5;

        // Window closed by in-order data: the ready segment must stay queued.
        conn.rcv_coalesce = vec![0xab; MIN_TCP_BUF];
        assert_eq!(conn.rcv_wnd_bytes(), 0);
        conn.drain_ooo();
        assert_eq!(
            conn.ooo.get(&5001).map(Vec::as_slice),
            Some(&b"hello"[..]),
            "a full window must not drop queued OOO data"
        );
        assert_eq!(conn.ooo_bytes, 5);
        assert_eq!(conn.rcv_nxt, 5001);

        // Window opens: notify the flow's dirty handle (as `TunTcpReader` does
        // when draining `in_flight_relay`) so `poll()` delivers the preserved
        // OOO bytes automatically without waiting for a peer retransmit.
        conn.rcv_coalesce.clear();
        conn.dirty_handle.as_ref().expect("dirty handle").wake();
        let mut tx_out = Vec::new();
        let mut accepted = Vec::new();
        stack.poll(1010, &mut tx_out, &mut accepted);
        let conn = stack.conns.values_mut().next().expect("conn");
        assert!(conn.ooo.is_empty());
        assert_eq!(conn.ooo_bytes, 0);
        assert_eq!(conn.rcv_nxt, 5006);
        assert!(
            !tx_out.is_empty(),
            "poll() must emit a cumulative ACK when OOO data advances rcv_nxt"
        );
        assert_eq!(
            conn.in_flight_relay.swap(0, Ordering::AcqRel),
            5,
            "the 5 preserved OOO bytes must have been flushed to the relay"
        );

        // Partial accept: only the free window bytes advance and the rest is
        // re-queued at the new `rcv_nxt` instead of being dropped.
        conn.rcv_nxt = 6000;
        conn.rcv_coalesce = vec![0xab; MIN_TCP_BUF - 4];
        conn.ooo.clear();
        conn.ooo.insert(6000, b"abcdef".to_vec());
        conn.ooo_bytes = 6;
        conn.drain_ooo();
        // The in-order buffer reaches the coalesce flush size here, so the
        // accepted prefix is checked on the relay queue.
        let delivered: Vec<u8> = conn
            .pending_to_relay
            .iter()
            .flat_map(|chunk| chunk.iter().copied())
            .collect();
        assert!(
            delivered.ends_with(b"abcd"),
            "the accepted prefix must be delivered to the relay"
        );
        assert_eq!(conn.rcv_nxt, 6004, "only the free window bytes may advance");
        assert_eq!(
            conn.ooo.get(&6004).map(Vec::as_slice),
            Some(&b"ef"[..]),
            "the remainder must be re-queued at the new rcv_nxt"
        );
        assert_eq!(conn.ooo_bytes, 2);

        // A segment already queued at the new `rcv_nxt` must survive the
        // re-queue, and the accounting must match the map footprint.
        conn.rcv_nxt = 7000;
        conn.pending_to_relay.clear();
        conn.pending_to_relay_bytes = 0;
        // Leaves exactly 4 bytes of window once the popped segment is released.
        conn.rcv_coalesce = vec![0xab; MIN_TCP_BUF - 8];
        conn.ooo.clear();
        conn.ooo.insert(7000, b"abcdef".to_vec());
        conn.ooo.insert(7004, b"efgh".to_vec());
        conn.ooo_bytes = 10;
        conn.drain_ooo();
        assert_eq!(conn.rcv_nxt, 7004);
        assert_eq!(
            conn.ooo.get(&7004).map(Vec::as_slice),
            Some(&b"efgh"[..]),
            "an overlapping queued segment must not be overwritten"
        );
        assert_eq!(
            conn.ooo_bytes,
            conn.ooo.values().map(Vec::len).sum::<usize>(),
            "ooo_bytes must match the queued map footprint"
        );

        // Even when `in_order + ooo_bytes == max_rcv_buf` (so `rcv_wnd_bytes()`
        // is still 0), freeing enough in-order space for the ready OOO segment
        // must allow `poll()` to drain it without deadlocking.
        conn.rcv_nxt = 8000;
        conn.rcv_coalesce.clear();
        conn.pending_to_relay.clear();
        conn.pending_to_relay_bytes = 0;
        conn.in_flight_relay
            .store(MIN_TCP_BUF - 2, Ordering::Release);
        conn.ooo.clear();
        conn.ooo.insert(8000, b"ef".to_vec());
        conn.ooo_bytes = 2;
        assert_eq!(conn.rcv_wnd_bytes(), 0);
        conn.dirty_handle.as_ref().expect("dirty handle").wake();
        tx_out.clear();
        stack.poll(1020, &mut tx_out, &mut accepted);
        let conn = stack.conns.values_mut().next().expect("conn");
        assert!(conn.ooo.is_empty());
        assert_eq!(conn.ooo_bytes, 0);
        assert_eq!(conn.rcv_nxt, 8002);

        // Once the peer's FIN is consumed, `poll()` must not drain any bogus
        // OOO segment sitting past the FIN sequence number.
        conn.in_flight_relay.store(0, Ordering::Release);
        conn.ooo.insert(8003, b"post-fin".to_vec());
        conn.ooo_bytes = 8;
        let fin_seg = make_seg(8002, conn.snd_nxt, TCP_FIN | TCP_ACK, 65535, &[], &[]);
        stack.push_ip_tcp(&fin_seg);
        tx_out.clear();
        stack.poll(1030, &mut tx_out, &mut accepted);
        let conn = stack.conns.values().next().expect("conn");
        assert_eq!(conn.state, TcpState::CloseWait);
        assert_eq!(
            conn.rcv_nxt, 8003,
            "rcv_nxt must stop at FIN+1 and never advance over post-FIN OOO data"
        );
    }

    #[test]
    fn receive_buffer_is_strictly_bounded_by_max_rcv_buf() {
        let cfg = TcpStackConfig {
            socket_buffer_bytes: MIN_TCP_BUF, // 64 KiB
            ..TcpStackConfig::default()
        };
        let mut stack = ProxyTcpStack::new(cfg);
        let (srv_nxt, _acc) = handshake(&mut stack, 100);

        // Blast 128 KiB without reading from the relay.
        let mut seq = 101u32;
        let payload = vec![0x42u8; 1024];
        let mut tx = Vec::new();
        let mut accepted = Vec::new();
        for _ in 0..128 {
            stack.push_ip_tcp(&make_seg(seq, srv_nxt, TCP_ACK, 1024, &[], &payload));
            seq = seq.wrapping_add(payload.len() as u32);
        }
        stack.poll(50, &mut tx, &mut accepted);

        let conn = stack.conns.values().next().expect("conn");
        assert_eq!(
            conn.rcv_nxt,
            101 + MIN_TCP_BUF as u32,
            "stack must never accept/ACK bytes past max_rcv_buf"
        );
        assert_eq!(conn.rcv_wnd_bytes(), 0);
    }

    #[test]
    fn zero_window_persist_probes_and_idle_reclaims_stalled_conn() {
        let mut stack = ProxyTcpStack::new(TcpStackConfig::default());
        let (srv_nxt, acc) = handshake(&mut stack, 200);
        let (_reader, writer) = acc.stream.into_split();

        // Peer advertises zero window.
        stack.push_ip_tcp(&make_seg(201, srv_nxt, TCP_ACK, 0, &[], &[]));
        let mut tx = Vec::new();
        let mut accepted = Vec::new();
        stack.poll(30, &mut tx, &mut accepted);

        // Queue data from relay -> triggers persist timer.
        let conn = stack.conns.values_mut().next().expect("conn");
        conn.tx_buf.extend(b"blocked-by-zero-window");
        conn.dirty_handle.as_ref().expect("dirty handle").wake();
        tx.clear();
        stack.poll(40, &mut tx, &mut accepted);
        assert!(tx.is_empty(), "must not transmit into zero window");

        // Advance past INITIAL_RTO_MS -> persist probe must fire.
        stack.poll(40 + INITIAL_RTO_MS, &mut tx, &mut accepted);
        assert_eq!(tx.len(), 1, "persist probe ACK must be emitted");

        // Advance past default idle_timeout_ms -> stalled connection must be reclaimed.
        let idle_timeout_ms = TcpStackConfig::default().idle_timeout_ms as i64;
        drop(writer);
        tx.clear();
        stack.poll(40 + idle_timeout_ms + 1000, &mut tx, &mut accepted);
        assert!(stack.conns.is_empty(), "idle connection must be reclaimed");
    }

    #[test]
    fn zero_window_persist_probes_indefinitely_without_consuming_data_rto_budget() {
        let cfg = TcpStackConfig {
            idle_timeout_ms: 600_000,
            ..TcpStackConfig::default()
        };
        let mut stack = ProxyTcpStack::new(cfg);
        let (srv_nxt, acc) = handshake(&mut stack, 300);
        let (_reader, _writer) = acc.stream.into_split();

        stack.push_ip_tcp(&make_seg(301, srv_nxt, TCP_ACK, 0, &[], &[]));
        let mut tx = Vec::new();
        let mut accepted = Vec::new();
        stack.poll(30, &mut tx, &mut accepted);

        let conn = stack.conns.values_mut().next().expect("conn");
        conn.tx_buf.extend(b"blocked-by-zero-window");
        conn.dirty_handle.as_ref().expect("dirty handle").wake();
        tx.clear();
        stack.poll(40, &mut tx, &mut accepted);
        assert!(tx.is_empty(), "must not transmit into zero window");

        // Far more probes than the retransmit ceiling the data path uses.
        let mut now = 40;
        for probe in 0..40 {
            now += MAX_RTO_MS;
            tx.clear();
            stack.poll(now, &mut tx, &mut accepted);
            assert_eq!(tx.len(), 1, "persist probe {probe} must be emitted");
            let conn = stack.conns.values().next().expect("flow stays open");
            assert_eq!(conn.state, TcpState::Established);
            assert_eq!(
                conn.retries, 0,
                "persist probes must not consume the data retransmit budget"
            );
            assert!(
                conn.persist_ms <= MAX_RTO_MS,
                "probe spacing must stay capped at MAX_RTO_MS"
            );
            if probe >= 4 {
                assert_eq!(conn.persist_ms, MAX_RTO_MS, "probe spacing reaches the cap");
            }
            let probe_seq = parse_tcp(parse_ip(&tx[0]).expect("ip").payload)
                .expect("tcp")
                .seq;
            assert_eq!(
                probe_seq,
                conn.snd_una.wrapping_sub(1),
                "probe must not advance snd_nxt"
            );
            assert_eq!(conn.snd_nxt, conn.snd_una);
        }
    }

    #[test]
    fn zero_window_persist_probes_are_capped_when_the_peer_keeps_zeroing() {
        let cfg = TcpStackConfig {
            idle_timeout_ms: 3_600_000,
            ..TcpStackConfig::default()
        };
        let mut stack = ProxyTcpStack::new(cfg);
        let (srv_nxt, acc) = handshake(&mut stack, 300);
        let (_reader, _writer) = acc.stream.into_split();

        stack.push_ip_tcp(&make_seg(301, srv_nxt, TCP_ACK, 0, &[], &[]));
        let mut tx = Vec::new();
        let mut accepted = Vec::new();
        stack.poll(30, &mut tx, &mut accepted);

        let conn = stack.conns.values_mut().next().expect("conn");
        conn.tx_buf.extend(b"blocked-by-zero-window");
        conn.dirty_handle.as_ref().expect("dirty handle").wake();
        tx.clear();
        stack.poll(40, &mut tx, &mut accepted);
        assert!(tx.is_empty(), "must not transmit into zero window");

        // The peer answers every probe with another zero-window ACK, so the idle
        // timeout never fires and only the probe cap can reclaim the flow.
        let mut now = 40;
        let mut peer_seq = 302u32;
        for probe in 1..=MAX_PERSIST_PROBES {
            now += MAX_RTO_MS;
            let snd_una = stack.conns.values().next().expect("conn").snd_una;
            peer_seq = peer_seq.wrapping_add(1);
            stack.push_ip_tcp(&make_seg(peer_seq, snd_una, TCP_ACK, 0, &[], &[]));
            tx.clear();
            stack.poll(now, &mut tx, &mut accepted);
            assert_eq!(tx.len(), 1, "probe {probe} must be emitted");
            let seg = parse_tcp(parse_ip(&tx[0]).expect("ip").payload).expect("tcp");
            assert_eq!(seg.flags, TCP_ACK, "probe {probe} must not reset");
            assert_eq!(seg.seq, snd_una.wrapping_sub(1));
            let conn = stack.conns.values().next().expect("flow stays open");
            assert_eq!(conn.persist_probes, probe);
            assert_eq!(
                conn.retries, 0,
                "persist probes must not consume the data retransmit budget"
            );
        }

        // The probe budget is exhausted: the next expiry resets the flow.
        now += MAX_RTO_MS;
        peer_seq = peer_seq.wrapping_add(1);
        stack.push_ip_tcp(&make_seg(
            peer_seq,
            stack.conns.values().next().expect("c").snd_una,
            TCP_ACK,
            0,
            &[],
            &[],
        ));
        tx.clear();
        stack.poll(now, &mut tx, &mut accepted);
        assert!(
            stack.conns.is_empty(),
            "an exhausted persist budget must reset the flow"
        );
        assert!(
            tx.iter().any(|pkt| parse_ip(pkt)
                .and_then(|ip| parse_tcp(ip.payload))
                .is_some_and(|seg| (seg.flags & TCP_RST) != 0)),
            "expected a TCP RST after the persist probe budget"
        );
    }

    #[test]
    fn data_rto_survives_twenty_retransmits_before_resetting() {
        let mut stack = ProxyTcpStack::new(TcpStackConfig::default());
        let (_srv_nxt, acc) = handshake(&mut stack, 400);
        let (_reader, _writer) = acc.stream.into_split();

        let conn = stack.conns.values_mut().next().expect("conn");
        conn.tx_buf.extend(b"unacked-rto-payload");
        conn.dirty_handle.as_ref().expect("dirty handle").wake();
        let mut tx = Vec::new();
        let mut accepted = Vec::new();
        stack.poll(50, &mut tx, &mut accepted);
        assert_eq!(tx.len(), 1, "queued data must be sent once");

        let mut now = 50;
        for retransmit in 1..=MAX_RETRIES {
            now += MAX_RTO_MS;
            tx.clear();
            stack.poll(now, &mut tx, &mut accepted);
            let conn = stack.conns.values().next().expect("flow must survive");
            assert_eq!(conn.retries, retransmit);
            assert!(
                tx.iter().all(|pkt| {
                    parse_ip(pkt)
                        .and_then(|ip| parse_tcp(ip.payload))
                        .is_some_and(|seg| (seg.flags & TCP_RST) == 0)
                }),
                "retransmit {retransmit} must not reset the flow"
            );
        }

        // The retransmit budget is now exhausted: the next expiry resets.
        now += MAX_RTO_MS;
        tx.clear();
        stack.poll(now, &mut tx, &mut accepted);
        assert!(stack.conns.is_empty(), "exhausted RTO budget must reset");
        assert!(
            tx.iter().any(|pkt| parse_ip(pkt)
                .and_then(|ip| parse_tcp(ip.payload))
                .is_some_and(|seg| (seg.flags & TCP_RST) != 0)),
            "expected a TCP RST after the retransmit budget"
        );
    }

    #[tokio::test]
    async fn unexpected_syn_on_established_flow_resets_old_and_accepts_new() {
        let mut stack = ProxyTcpStack::new(TcpStackConfig::default());
        let (_srv_nxt, acc) = handshake(&mut stack, 500);
        let (mut reader, _writer) = acc.stream.into_split();

        // The local peer restarted and reuses the 4-tuple with a fresh ISN.
        let new_isn = 9_000u32;
        let opts = [2, 4, 0x05, 0xb4, 1, 3, 3, 6];
        stack.push_ip_tcp(&make_seg(new_isn, 0, TCP_SYN, 65_535, &opts, &[]));
        let mut tx = Vec::new();
        let mut accepted = Vec::new();
        stack.poll(30, &mut tx, &mut accepted);

        assert_eq!(tx.len(), 2, "expected RST for the stale flow then SYN|ACK");
        let rst = parse_tcp(parse_ip(&tx[0]).expect("ip").payload).expect("tcp");
        assert_ne!(rst.flags & TCP_RST, 0, "stale flow must be reset");
        let syn_ack = parse_tcp(parse_ip(&tx[1]).expect("ip").payload).expect("tcp");
        assert_eq!(syn_ack.flags, TCP_SYN | TCP_ACK);
        let new_srv_isn = syn_ack.seq;

        assert_eq!(stack.conns.len(), 1, "only the new socket may remain");
        let conn = stack.conns.values().next().expect("conn");
        assert_eq!(conn.state, TcpState::SynReceived);
        assert_eq!(conn.rcv_nxt, new_isn.wrapping_add(1));
        assert!(
            reader.recv_chunk().await.is_none(),
            "the stale relay stream must close"
        );

        // The new handshake must complete on the same 4-tuple.
        tx.clear();
        stack.push_ip_tcp(&make_seg(
            new_isn.wrapping_add(1),
            new_srv_isn.wrapping_add(1),
            TCP_ACK,
            4096,
            &[],
            &[],
        ));
        stack.poll(40, &mut tx, &mut accepted);
        assert_eq!(accepted.len(), 1, "new flow must be accepted immediately");
    }

    #[tokio::test]
    async fn late_duplicate_syn_keeps_flow_while_a_new_isn_replaces_it() {
        let mut stack = ProxyTcpStack::new(TcpStackConfig::default());
        let client_isn = 700u32;
        let (srv_nxt, acc) = handshake(&mut stack, client_isn);
        let (mut reader, _writer) = acc.stream.into_split();
        let opts = [2, 4, 0x05, 0xb4, 1, 3, 3, 6];
        let mut tx = Vec::new();
        let mut accepted = Vec::new();

        // Reordered duplicate of the original SYN (same ISN): challenge ACK only.
        stack.push_ip_tcp(&make_seg(client_isn, 0, TCP_SYN, 65_535, &opts, &[]));
        stack.poll(30, &mut tx, &mut accepted);
        assert_eq!(tx.len(), 1, "a duplicate SYN must get exactly one ACK");
        let challenge = parse_tcp(parse_ip(&tx[0]).expect("ip").payload).expect("tcp");
        assert_eq!(challenge.flags, TCP_ACK, "duplicate SYN must not be reset");
        assert_eq!(stack.conns.len(), 1, "the live flow must survive");
        let conn = stack.conns.values().next().expect("conn");
        assert_eq!(conn.state, TcpState::Established);
        assert_eq!(conn.rcv_isn, client_isn);
        assert_eq!(conn.rcv_nxt, client_isn.wrapping_add(1));

        // The kept flow still carries data.
        tx.clear();
        stack.push_ip_tcp(&make_seg(
            client_isn.wrapping_add(1),
            srv_nxt,
            TCP_ACK,
            1024,
            &[],
            b"still-alive",
        ));
        stack.poll(40, &mut tx, &mut accepted);
        assert_eq!(reader.recv_chunk().await.expect("data"), b"still-alive");

        // A different ISN means a new connection on the same 4-tuple: RST + SYN|ACK.
        let new_isn = 9_000u32;
        tx.clear();
        stack.push_ip_tcp(&make_seg(new_isn, 0, TCP_SYN, 65_535, &opts, &[]));
        stack.poll(50, &mut tx, &mut accepted);
        assert_eq!(tx.len(), 2, "expected RST then SYN|ACK");
        let rst = parse_tcp(parse_ip(&tx[0]).expect("ip").payload).expect("tcp");
        assert_ne!(rst.flags & TCP_RST, 0, "the stale flow must be reset");
        let syn_ack = parse_tcp(parse_ip(&tx[1]).expect("ip").payload).expect("tcp");
        assert_eq!(syn_ack.flags, TCP_SYN | TCP_ACK);
        let conn = stack.conns.values().next().expect("conn");
        assert_eq!(conn.state, TcpState::SynReceived);
        assert_eq!(conn.rcv_isn, new_isn);
        assert!(reader.recv_chunk().await.is_none(), "old relay must close");
    }

    fn small_buffer_stack() -> ProxyTcpStack {
        ProxyTcpStack::new(TcpStackConfig {
            socket_buffer_bytes: MIN_TCP_BUF,
            ..TcpStackConfig::default()
        })
    }

    /// Fills the receive path with 64 KiB so the relay channel holds the whole
    /// receive buffer and the advertised window is zero.
    fn fill_receive_path(stack: &mut ProxyTcpStack, srv_nxt: u32) {
        let payload = vec![0x42u8; 1024];
        let mut seq = 101u32;
        for _ in 0..64 {
            stack.push_ip_tcp(&make_seg(seq, srv_nxt, TCP_ACK, 1024, &[], &payload));
            seq = seq.wrapping_add(payload.len() as u32);
        }
        let mut tx = Vec::new();
        let mut accepted = Vec::new();
        stack.poll(30, &mut tx, &mut accepted);
    }

    #[tokio::test]
    async fn dropping_the_relay_reader_releases_in_flight_bytes() {
        let mut stack = small_buffer_stack();
        let (srv_nxt, acc) = handshake(&mut stack, 100);
        let (reader, _writer) = acc.stream.into_split();
        fill_receive_path(&mut stack, srv_nxt);

        let conn = stack.conns.values().next().expect("conn");
        assert_eq!(conn.in_flight_relay.load(Ordering::Acquire), MIN_TCP_BUF);
        assert_eq!(conn.rcv_wnd_bytes(), 0);

        // The relay dies without reading; the queued bytes must not stay charged.
        drop(reader);
        let conn = stack.conns.values().next().expect("conn");
        assert_eq!(
            conn.in_flight_relay.load(Ordering::Acquire),
            0,
            "unread queued chunks must be released on drop"
        );
        assert_eq!(
            conn.rcv_wnd_bytes(),
            MIN_TCP_BUF as u32,
            "the receive window must reopen after the relay closes"
        );
    }

    #[tokio::test]
    async fn dropping_an_unsplit_stream_releases_in_flight_bytes() {
        let mut stack = small_buffer_stack();
        let (srv_nxt, acc) = handshake(&mut stack, 100);
        fill_receive_path(&mut stack, srv_nxt);

        let conn = stack.conns.values().next().expect("conn");
        assert_eq!(conn.in_flight_relay.load(Ordering::Acquire), MIN_TCP_BUF);

        drop(acc.stream);
        let conn = stack.conns.values().next().expect("conn");
        assert_eq!(conn.in_flight_relay.load(Ordering::Acquire), 0);
        assert_eq!(conn.rcv_wnd_bytes(), MIN_TCP_BUF as u32);
    }

    #[test]
    fn rx_queue_overflow_is_counted() {
        let drops = Arc::new(DropCounters::default());
        let mut stack = ProxyTcpStack::new(TcpStackConfig::default());
        stack.set_drop_counters(Arc::clone(&drops));

        let syn = make_seg(1000, 0, TCP_SYN, 65_535, &[], &[]);
        for _ in 0..MAX_INCOMING_PACKETS {
            stack.push_ip_tcp(&syn);
        }
        assert_eq!(drops.snapshot().tcp_rx_overflow, 0);

        stack.push_ip_tcp(&syn);
        assert_eq!(drops.snapshot().tcp_rx_overflow, 1);
        assert!(
            drops.snapshot().as_status_value().contains("tcp_rx_ovf:1"),
            "overflow must be visible in the status value"
        );

        // The bounded queue still drains normally.
        let mut tx = Vec::new();
        let mut accepted = Vec::new();
        stack.poll(10, &mut tx, &mut accepted);
        assert_eq!(stack.conns.len(), 1);
    }

    #[test]
    fn stale_window_advertisement_cannot_rewind_snd_wnd() {
        let mut stack = ProxyTcpStack::new(TcpStackConfig::default());
        let (srv_nxt, _acc) = handshake(&mut stack, 1000);
        let mut tx = Vec::new();
        let mut accepted = Vec::new();

        let conn = stack.conns.values().next().expect("conn");
        let window = conn.snd_wnd;
        assert_eq!(conn.snd_wl1, 1001);
        assert_eq!(conn.snd_wl2, srv_nxt);
        assert!(window > 0);

        // Reordered stale ACK: same SEG.SEQ as SND.WL1, older SEG.ACK, zero window.
        stack.push_ip_tcp(&make_seg(
            1001,
            srv_nxt.wrapping_sub(1),
            TCP_ACK,
            0,
            &[],
            &[],
        ));
        stack.poll(30, &mut tx, &mut accepted);
        let conn = stack.conns.values().next().expect("conn");
        assert_eq!(conn.snd_wnd, window, "stale ACK must not rewind snd_wnd");

        // A newer segment may still update the window.
        stack.push_ip_tcp(&make_seg(1002, srv_nxt, TCP_ACK, 512, &[], &[]));
        stack.poll(40, &mut tx, &mut accepted);
        let conn = stack.conns.values().next().expect("conn");
        assert_eq!(conn.snd_wnd, 512u32 << 6);
        assert_eq!(conn.snd_wl1, 1002);
    }

    #[tokio::test]
    async fn u32_sequence_wraparound_transfers_cleanly() {
        let mut stack = ProxyTcpStack::new(TcpStackConfig::default());
        let client_isn = u32::MAX - 3;
        let (srv_nxt, acc) = handshake(&mut stack, client_isn);
        let (mut reader, _writer) = acc.stream.into_split();

        let seq1 = client_isn.wrapping_add(1); // u32::MAX - 2
        stack.push_ip_tcp(&make_seg(seq1, srv_nxt, TCP_ACK, 1024, &[], b"123456"));
        let mut tx = Vec::new();
        let mut accepted = Vec::new();
        stack.poll(30, &mut tx, &mut accepted);

        let chunk = reader.recv_chunk().await.expect("wrapped data");
        assert_eq!(chunk, b"123456");
    }

    #[tokio::test]
    async fn window_growth_emits_prompt_window_update_ack() {
        let cfg = TcpStackConfig {
            socket_buffer_bytes: 1024 * 1024, // 1 MiB -> growth_step = 256 KiB
            ..TcpStackConfig::default()
        };
        let mut stack = ProxyTcpStack::new(cfg);
        let (srv_nxt, acc) = handshake(&mut stack, 1000);
        let (mut reader, _writer) = acc.stream.into_split();

        // Fill 512 KiB so advertised window drops to 512 KiB (still above reopen_threshold).
        let payload = vec![0x5a_u8; 1024];
        let mut seq = 1001u32;
        let mut tx = Vec::new();
        let mut accepted = Vec::new();
        for _ in 0..512 {
            stack.push_ip_tcp(&make_seg(seq, srv_nxt, TCP_ACK, 1024, &[], &payload));
            seq = seq.wrapping_add(payload.len() as u32);
        }
        stack.poll(30, &mut tx, &mut accepted);
        tx.clear();

        // Drain >= 256 KiB from the relay reader; next poll must emit a Window Update ACK.
        let mut drained = 0usize;
        while drained < 300 * 1024 {
            let chunk = reader.recv_chunk().await.expect("chunk");
            drained += chunk.len();
        }
        stack.poll(40, &mut tx, &mut accepted);
        assert_eq!(
            tx.len(),
            1,
            "expected prompt window-update ACK after >=256 KiB drain"
        );
        let ack_seg = parse_tcp(parse_ip(&tx[0]).expect("ip").payload).expect("tcp");
        assert_eq!(ack_seg.flags, TCP_ACK);
        assert_eq!(ack_seg.ack, seq);
    }

    #[tokio::test]
    async fn zero_window_persist_probe_acknowledges_the_reopened_window() {
        // The client config derives 512 KiB per direction at 256 flows.
        let cfg = TcpStackConfig {
            socket_buffer_bytes: 512 * 1024,
            ..TcpStackConfig::default()
        };
        let mut stack = ProxyTcpStack::new(cfg);
        let (srv_nxt, acc) = handshake(&mut stack, 1000);
        let (mut reader, _writer) = acc.stream.into_split();

        // Fill the 512 KiB receive buffer so the advertised window reaches zero.
        let payload = vec![0x5a_u8; 1024];
        let mut seq = 1001u32;
        for _ in 0..512 {
            stack.push_ip_tcp(&make_seg(seq, srv_nxt, TCP_ACK, 1024, &[], &payload));
            seq = seq.wrapping_add(payload.len() as u32);
        }
        let mut tx = Vec::new();
        let mut accepted = Vec::new();
        stack.poll(30, &mut tx, &mut accepted);
        let conn = stack.conns.values().next().expect("conn");
        assert_eq!(conn.rcv_wnd_bytes(), 0);
        assert_eq!(conn.last_advertised_wnd, 0);

        // One drained 64 KiB chunk reopens the window below the 128 KiB
        // ordinary update threshold, so no unsolicited ACK is expected.
        let chunk = reader.recv_chunk().await.expect("queued chunk");
        assert_eq!(chunk.len(), RELAY_COALESCE_BYTES);
        tx.clear();
        stack.poll(40, &mut tx, &mut accepted);
        assert!(tx.is_empty(), "small window growth must stay silent");

        let conn = stack.conns.values().next().expect("conn");
        // A persist probe carries the peer's send sequence space: its
        // seq is one before the next byte we expect from it (`rcv_nxt`).
        let probe_seq = conn.rcv_nxt.wrapping_sub(1);
        let unrelated_seq = conn.rcv_nxt.wrapping_sub(2);
        stack.push_ip_tcp(&make_seg(unrelated_seq, srv_nxt, TCP_ACK, 0, &[], &[]));
        stack.poll(45, &mut tx, &mut accepted);
        assert!(tx.is_empty(), "an unrelated seq must not reopen the window");

        stack.push_ip_tcp(&make_seg(probe_seq, srv_nxt, TCP_ACK, 0, &[], &[]));
        stack.poll(50, &mut tx, &mut accepted);
        assert_eq!(tx.len(), 1, "persist probe must get one window ACK");
        let ack_seg = parse_tcp(parse_ip(&tx[0]).expect("ip").payload).expect("tcp");
        assert_eq!(ack_seg.flags, TCP_ACK);
        assert_eq!(ack_seg.seq, srv_nxt);
        assert_eq!(
            ack_seg.window, 512,
            "64 KiB scaled by 128 must be advertised"
        );

        tx.clear();
        stack.push_ip_tcp(&make_seg(probe_seq, srv_nxt, TCP_ACK, 0, &[], &[]));
        stack.poll(60, &mut tx, &mut accepted);
        assert!(tx.is_empty(), "repeated must not flood window ACKs");
    }

    #[tokio::test]
    async fn reset_all_emits_rst_and_closes_relay_streams() {
        let mut stack = ProxyTcpStack::new(TcpStackConfig::default());
        let (_srv_nxt, acc) = handshake(&mut stack, 4000);
        let (mut reader, _writer) = acc.stream.into_split();

        let mut tx = Vec::new();
        stack.reset_all(&mut tx);
        assert!(stack.conns.is_empty());
        assert_eq!(tx.len(), 1);
        let rst = parse_tcp(parse_ip(&tx[0]).expect("ip").payload).expect("tcp");
        assert_ne!(rst.flags & TCP_RST, 0, "expected TCP RST on reset_all");
        assert!(
            reader.recv_chunk().await.is_none(),
            "relay stream must close"
        );
    }

    #[tokio::test]
    async fn ipv6_tcp_handshake_data_and_fin() {
        let src6: IpAddr = "fd00:be:a::1".parse().expect("src6");
        let dst6: IpAddr = "2001:db8::1".parse().expect("dst6");
        let mut stack = ProxyTcpStack::new(TcpStackConfig::default());

        let syn = build_ip_tcp_packet_slices(
            src6,
            44_000,
            dst6,
            443,
            9000,
            0,
            TCP_SYN,
            65535,
            &[2, 4, 0x05, 0xa0, 1, 3, 3, 6],
            &[],
            &[],
        )
        .expect("v6 syn");
        stack.push_ip_tcp(&syn);
        let mut tx = Vec::new();
        let mut accepted = Vec::new();
        stack.poll(10, &mut tx, &mut accepted);
        assert_eq!(tx.len(), 1);
        let syn_ack_ip = parse_ip(&tx[0]).expect("v6 ip");
        assert_eq!(syn_ack_ip.src_ip, dst6);
        assert_eq!(syn_ack_ip.dst_ip, src6);
        let syn_ack = parse_tcp(syn_ack_ip.payload).expect("v6 syn-ack");
        assert_eq!(syn_ack.flags, TCP_SYN | TCP_ACK);

        let ack_data = build_ip_tcp_packet_slices(
            src6,
            44_000,
            dst6,
            443,
            9001,
            syn_ack.seq.wrapping_add(1),
            TCP_ACK | TCP_PSH,
            1024,
            &[],
            b"hello-ipv6",
            &[],
        )
        .expect("v6 data");
        tx.clear();
        stack.push_ip_tcp(&ack_data);
        stack.poll(20, &mut tx, &mut accepted);
        assert_eq!(accepted.len(), 1);

        let (mut reader, mut writer) = accepted.pop().expect("acc").stream.into_split();
        assert_eq!(reader.recv_chunk().await.expect("data"), b"hello-ipv6");

        writer
            .send_chunk(b"reply-ipv6".to_vec())
            .await
            .expect("send");
        writer.shutdown();
        tx.clear();
        stack.poll(30, &mut tx, &mut accepted);
        assert!(tx.iter().any(|p| {
            parse_ip(p)
                .and_then(|ip| parse_tcp(ip.payload))
                .is_some_and(|seg| seg.payload == b"reply-ipv6")
        }));
    }

    #[tokio::test]
    async fn zero_window_reopens_without_wscale() {
        let cfg = TcpStackConfig {
            socket_buffer_bytes: 4 * 1024 * 1024,
            ..TcpStackConfig::default()
        };
        let mut stack = ProxyTcpStack::new(cfg);
        // SYN with MSS only (no RFC 7323 WScale -> our_wscale == 0, effective_max_wnd == 65_535).
        let opts = [2, 4, 0x05, 0xb4];
        stack.push_ip_tcp(&make_seg(1000, 0, TCP_SYN, 65535, &opts, &[]));
        let mut tx = Vec::new();
        let mut accepted = Vec::new();
        stack.poll(10, &mut tx, &mut accepted);
        let syn_ack = parse_tcp(parse_ip(&tx[0]).expect("ip").payload).expect("tcp");
        let srv_nxt = syn_ack.seq.wrapping_add(1);
        stack.push_ip_tcp(&make_seg(1001, srv_nxt, TCP_ACK, 65535, &[], &[]));
        tx.clear();
        stack.poll(20, &mut tx, &mut accepted);
        let (_reader, _writer) = accepted.pop().expect("acc").stream.into_split();

        // Simulate last advertised window = 0 while current_wnd is now full (65_535).
        let conn = stack.conns.values_mut().next().expect("conn");
        assert_eq!(conn.our_wscale, 0);
        conn.last_advertised_wnd = 0;
        conn.need_ack = false;
        conn.dirty_handle.as_ref().expect("dirty handle").wake();
        tx.clear();
        stack.poll(30, &mut tx, &mut accepted);
        assert_eq!(
            tx.len(),
            1,
            "zero-window must reopen even when our_wscale == 0"
        );
    }

    #[test]
    fn syn_rejected_with_rst_ack_when_at_max_connections() {
        let cfg = TcpStackConfig {
            max_connections: 1,
            ..TcpStackConfig::default()
        };
        let mut stack = ProxyTcpStack::new(cfg);
        let (_srv_nxt, _acc) = handshake(&mut stack, 1000);
        assert_eq!(stack.conns.len(), 1);

        let syn_seq = 7777u32;
        let second_src_port = SRC_PORT + 1;
        let syn = build_ip_tcp_packet_slices(
            SRC_IP,
            second_src_port,
            DST_IP,
            DST_PORT,
            syn_seq,
            0,
            TCP_SYN,
            65535,
            &[],
            &[],
            &[],
        )
        .expect("build second syn");
        stack.push_ip_tcp(&syn);

        let mut tx = Vec::new();
        let mut accepted = Vec::new();
        stack.poll(30, &mut tx, &mut accepted);

        assert!(accepted.is_empty());
        assert_eq!(stack.conns.len(), 1);
        assert_eq!(tx.len(), 1, "expected immediate RST|ACK for rejected SYN");
        let ip = parse_ip(&tx[0]).expect("ip");
        assert_eq!(ip.src_ip, DST_IP);
        assert_eq!(ip.dst_ip, SRC_IP);
        let rst = parse_tcp(ip.payload).expect("tcp");
        assert_eq!(rst.src_port, DST_PORT);
        assert_eq!(rst.dst_port, second_src_port);
        assert_eq!(rst.flags, TCP_RST | TCP_ACK);
        assert_eq!(rst.seq, 0);
        assert_eq!(rst.ack, syn_seq.wrapping_add(1));
    }

    #[tokio::test]
    async fn failed_dial_abort_resets_early_acked_bytes() {
        let mut stack = ProxyTcpStack::new(TcpStackConfig::default());
        let (srv_nxt, acc) = handshake(&mut stack, 6000);
        let (mut reader, mut writer) = acc.stream.into_split();

        // Application data can arrive while the upstream dial is still pending.
        // The local stack ACKs it and hands it to the relay.
        stack.push_ip_tcp(&make_seg(
            6001,
            srv_nxt,
            TCP_ACK | TCP_PSH,
            65535,
            &[],
            b"POST /",
        ));
        let mut tx = Vec::new();
        let mut accepted = Vec::new();
        stack.poll(30, &mut tx, &mut accepted);
        assert_eq!(tx.len(), 1, "early bytes must be ACKed locally");
        let ack = parse_tcp(parse_ip(&tx[0]).expect("ip").payload).expect("tcp");
        assert_eq!(ack.flags, TCP_ACK);
        assert_eq!(ack.ack, 6001 + 6);
        assert_eq!(reader.recv_chunk().await.expect("early bytes"), b"POST /");

        // The engine calls `abort()` when the upstream dial fails or times out.
        writer.abort();
        tx.clear();
        stack.poll(40, &mut tx, &mut accepted);
        assert!(stack.conns.is_empty(), "failed dial must not hang the flow");
        assert_eq!(tx.len(), 1, "failed dial must emit one RST");
        let rst = parse_tcp(parse_ip(&tx[0]).expect("ip").payload).expect("tcp");
        assert_eq!(rst.flags, TCP_RST | TCP_ACK);
        assert_eq!(rst.flags & TCP_FIN, 0, "a failed dial must not send FIN");
        assert_eq!(rst.seq, srv_nxt);
        assert_eq!(rst.ack, 6001 + 6);
    }

    #[tokio::test]
    async fn dirty_queue_avoids_polling_idle_flows_and_tracks_earliest_deadline() {
        let cfg = TcpStackConfig {
            max_connections: 64,
            idle_timeout_ms: 10_000,
            ..TcpStackConfig::default()
        };
        let mut stack = ProxyTcpStack::new(cfg);
        let mut streams = Vec::new();
        let mut srv_nxts = Vec::new();
        let mut tx = Vec::new();
        let mut accepted = Vec::new();

        // Establish 32 flows staggered by 100 ms each (last_activity_ms = 1000 + i * 100).
        for i in 0u16..32 {
            let port = SRC_PORT + i;
            let now = 1000 + i64::from(i) * 100;
            let syn = build_ip_tcp_packet_slices(
                SRC_IP,
                port,
                DST_IP,
                DST_PORT,
                1000,
                0,
                TCP_SYN,
                65535,
                &[],
                &[],
                &[],
            )
            .expect("syn");
            stack.push_ip_tcp(&syn);
            tx.clear();
            stack.poll(now, &mut tx, &mut accepted);
            let syn_ack = parse_tcp(parse_ip(&tx[0]).expect("ip").payload).expect("tcp");
            let srv_nxt = syn_ack.seq.wrapping_add(1);
            let ack = build_ip_tcp_packet_slices(
                SRC_IP,
                port,
                DST_IP,
                DST_PORT,
                1001,
                srv_nxt,
                TCP_ACK,
                65535,
                &[],
                &[],
                &[],
            )
            .expect("ack");
            stack.push_ip_tcp(&ack);
            tx.clear();
            stack.poll(now, &mut tx, &mut accepted);
            srv_nxts.push(srv_nxt);
            streams.push(accepted.pop().expect("accepted").stream.into_split());
        }
        assert_eq!(stack.conns.len(), 32);

        // Earliest deadline is flow 0 at 1000 + 10_000 = 11_000.
        assert_eq!(stack.poll_delay_ms(5000), Some(6000));

        // Wake only flow 5 via relay writer -> poll must touch ONLY flow 5, not the 31 idle flows.
        streams[5]
            .1
            .send_chunk(b"only-flow-5".to_vec())
            .await
            .expect("send");
        tx.clear();
        stack.poll(5100, &mut tx, &mut accepted);
        assert_eq!(
            stack.last_poll_count, 1,
            "idle flows must not be re-polled on single-flow wakeup"
        );
        assert_eq!(tx.len(), 1);
        // Flow 5 now has an RTO deadline at 5100 + INITIAL_RTO_MS = 5300 (earlier than flow 0's 11_000).
        assert_eq!(stack.poll_delay_ms(5100), Some(INITIAL_RTO_MS as u64));

        // ACK flow 5's data so its RTO clears; earliest deadline must lazily return to flow 0 (11_000).
        let ack5 = build_ip_tcp_packet_slices(
            SRC_IP,
            SRC_PORT + 5,
            DST_IP,
            DST_PORT,
            1001,
            srv_nxts[5].wrapping_add(11),
            TCP_ACK,
            65535,
            &[],
            &[],
            &[],
        )
        .expect("ack5");
        stack.push_ip_tcp(&ack5);
        tx.clear();
        stack.poll(5150, &mut tx, &mut accepted);
        assert_eq!(stack.last_poll_count, 1);
        assert_eq!(stack.poll_delay_ms(5150), Some(11_000 - 5150));

        // reset_all must clear conns, dirty queue, and timers cleanly.
        tx.clear();
        stack.reset_all(&mut tx);
        assert!(stack.conns.is_empty());
        assert_eq!(tx.len(), 32);
        assert_eq!(stack.poll_delay_ms(5200), None);
    }

    #[tokio::test]
    async fn data_arriving_in_close_wait_and_last_ack_emits_cumulative_ack() {
        let mut stack = ProxyTcpStack::new(TcpStackConfig::default());
        let (srv_nxt, acc) = handshake(&mut stack, 2000);
        let (_reader, mut writer) = acc.stream.into_split();

        let mut tx = Vec::new();
        let mut accepted = Vec::new();

        // Peer sends data ("abc") + FIN -> state transitions to CloseWait, rcv_nxt = 2005.
        stack.push_ip_tcp(&make_seg(
            2001,
            srv_nxt,
            TCP_ACK | TCP_FIN,
            1024,
            &[],
            b"abc",
        ));
        stack.poll(30, &mut tx, &mut accepted);
        let conn = stack.conns.values().next().expect("conn");
        assert_eq!(conn.state, TcpState::CloseWait);
        assert_eq!(conn.rcv_nxt, 2005);

        // Retransmitted/duplicate data arrives in CloseWait -> must emit cumulative ACK (ack = 2005).
        tx.clear();
        stack.push_ip_tcp(&make_seg(2001, srv_nxt, TCP_ACK, 1024, &[], b"abc"));
        stack.poll(40, &mut tx, &mut accepted);
        assert_eq!(tx.len(), 1, "expected cumulative ACK in CloseWait");
        let ack_cw = parse_tcp(parse_ip(&tx[0]).expect("ip").payload).expect("tcp");
        assert_eq!(ack_cw.flags, TCP_ACK);
        assert_eq!(ack_cw.ack, 2005);
        assert_eq!(stack.conns.values().next().expect("conn").rcv_nxt, 2005);

        // Relay shuts down write side -> stack sends FIN and transitions to LastAck.
        writer.shutdown();
        tx.clear();
        stack.poll(50, &mut tx, &mut accepted);
        assert_eq!(
            stack.conns.values().next().expect("conn").state,
            TcpState::LastAck
        );

        // Retransmitted/duplicate data arrives in LastAck -> must emit cumulative ACK (ack = 2005).
        tx.clear();
        stack.push_ip_tcp(&make_seg(2001, srv_nxt, TCP_ACK, 1024, &[], b"abc"));
        stack.poll(60, &mut tx, &mut accepted);
        assert_eq!(tx.len(), 1, "expected cumulative ACK in LastAck");
        let ack_la = parse_tcp(parse_ip(&tx[0]).expect("ip").payload).expect("tcp");
        assert_eq!(ack_la.flags, TCP_ACK);
        assert_eq!(ack_la.ack, 2005);
        assert_eq!(stack.conns.values().next().expect("conn").rcv_nxt, 2005);
    }

    #[test]
    fn custom_handshake_and_idle_timeouts_take_effect() {
        let cfg = TcpStackConfig {
            handshake_timeout_ms: 1_500,
            idle_timeout_ms: 4_000,
            ..TcpStackConfig::default()
        };
        let mut stack = ProxyTcpStack::new(cfg);
        let mut tx = Vec::new();
        let mut accepted = Vec::new();

        // 1. Half-open SYN expires at custom handshake_timeout_ms (1_500 ms), not 10_000 ms.
        stack.push_ip_tcp(&make_seg(100, 0, TCP_SYN, 65535, &[], &[]));
        stack.poll(100, &mut tx, &mut accepted);
        assert_eq!(stack.conns.len(), 1);
        tx.clear();
        stack.poll(1599, &mut tx, &mut accepted);
        assert_eq!(stack.conns.len(), 1);
        tx.clear();
        stack.poll(1600, &mut tx, &mut accepted);
        assert!(
            stack.conns.is_empty(),
            "half-open handshake must expire at custom handshake_timeout_ms"
        );

        // 2. Established connection expires at custom idle_timeout_ms (4_000 ms), not 300_000 ms.
        let (_srv_nxt, _acc) = handshake(&mut stack, 500);
        assert_eq!(stack.conns.len(), 1);
        // `handshake()` completes at now_ms = 20, so idle deadline is 4020.
        assert_eq!(stack.poll_delay_ms(20), Some(4_000));
        tx.clear();
        stack.poll(4019, &mut tx, &mut accepted);
        assert_eq!(stack.conns.len(), 1);
        tx.clear();
        stack.poll(4020, &mut tx, &mut accepted);
        assert!(
            stack.conns.is_empty(),
            "established connection must expire at custom idle_timeout_ms"
        );
        assert_eq!(tx.len(), 1, "idle expiration must emit RST");
        let rst = parse_tcp(parse_ip(&tx[0]).expect("ip").payload).expect("tcp");
        assert_ne!(rst.flags & TCP_RST, 0);
    }

    #[test]
    fn incoming_buffers_shrink_after_a_large_burst_is_polled() {
        let mut stack = ProxyTcpStack::new(TcpStackConfig::default());
        let (srv_nxt, _acc) = handshake(&mut stack, 1000);

        // Queue one burst that is well above both shrink thresholds.
        let payload = vec![0x11u8; 1200];
        let mut seq = 1001u32;
        for _ in 0..512 {
            stack.push_ip_tcp(&make_seg(seq, srv_nxt, TCP_ACK, 65535, &[], &payload));
            seq = seq.wrapping_add(payload.len() as u32);
        }
        assert!(
            stack.incoming_buf.capacity() > INCOMING_BUF_SHRINK_THRESHOLD,
            "burst must grow the buffer past the shrink threshold"
        );
        assert!(stack.incoming_lens.capacity() > INCOMING_LENS_SHRINK_THRESHOLD);

        let mut tx = Vec::new();
        let mut accepted = Vec::new();
        stack.poll(50, &mut tx, &mut accepted);

        assert!(
            stack.incoming_buf.capacity() <= INCOMING_BUF_SHRINK_THRESHOLD,
            "polling a burst must release its peak allocation"
        );
        assert!(
            stack.incoming_lens.capacity() <= INCOMING_LENS_SHRINK_THRESHOLD,
            "polling a burst must release its peak length-vector allocation"
        );
    }

    #[test]
    fn tx_buf_pool_recycles_within_bounds_and_clears_stale_bytes() {
        let mut stack = ProxyTcpStack::new(TcpStackConfig::default());
        // Oversized buffer must be rejected.
        stack.recycle_tx_buf(vec![0xAA; TX_BUF_MAX_RETAIN_CAP + 1]);
        assert!(stack.tx_buf_pool.is_empty());

        // Pool caps at TX_BUF_POOL_MAX entries.
        for _ in 0..(TX_BUF_POOL_MAX + 16) {
            stack.recycle_tx_buf(vec![0xFF; 1500]);
        }
        assert_eq!(stack.tx_buf_pool.len(), TX_BUF_POOL_MAX);

        // Reusing a dirty buffer must produce an identical packet to a fresh allocation.
        let mut dirty = vec![0xDE; 1500];
        let ptr = dirty.as_ptr();
        assert!(build_ip_tcp_packet_slices_into(
            &mut dirty,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            50000,
            1000,
            2000,
            TCP_ACK | TCP_PSH,
            1024,
            &[],
            b"hello ",
            b"world",
        ));
        assert_eq!(dirty.as_ptr(), ptr, "buffer capacity must be reused");
        let fresh = build_ip_tcp_packet_slices(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            50000,
            1000,
            2000,
            TCP_ACK | TCP_PSH,
            1024,
            &[],
            b"hello ",
            b"world",
        )
        .expect("fresh packet");
        assert_eq!(dirty, fresh);

        // Same stale-byte check for IPv6 packets.
        let mut dirty6 = vec![0xCD; 1500];
        let ptr6 = dirty6.as_ptr();
        let src6 = IpAddr::V6("2001:db8::2".parse().expect("ipv6"));
        let dst6 = IpAddr::V6("2001:db8::1".parse().expect("ipv6"));
        assert!(build_ip_tcp_packet_slices_into(
            &mut dirty6,
            src6,
            443,
            dst6,
            50001,
            3000,
            4000,
            TCP_ACK | TCP_PSH,
            2048,
            &[],
            b"ipv6-",
            b"reuse",
        ));
        assert_eq!(dirty6.as_ptr(), ptr6, "IPv6 buffer capacity must be reused");
        let fresh6 = build_ip_tcp_packet_slices(
            src6,
            443,
            dst6,
            50001,
            3000,
            4000,
            TCP_ACK | TCP_PSH,
            2048,
            &[],
            b"ipv6-",
            b"reuse",
        )
        .expect("fresh ipv6 packet");
        assert_eq!(dirty6, fresh6);
    }

    #[test]
    fn soft_eviction_prefers_closing_then_stale_syn_then_idle_established_and_never_active() {
        let mut stack = ProxyTcpStack::new(TcpStackConfig {
            max_connections: 2,
            ..TcpStackConfig::mobile()
        });
        let drops = Arc::new(DropCounters::default());
        stack.set_drop_counters(Arc::clone(&drops));

        let client = IpAddr::V4(Ipv4Addr::new(198, 19, 0, 1));
        let server = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let mut tx = Vec::new();
        let mut accepted = Vec::new();

        // Admit two active Established flows (ports 40001 and 40002).
        for (port, seq) in [(40001u16, 1000u32), (40002u16, 2000u32)] {
            let syn = build_ip_tcp_packet_slices(
                client,
                port,
                server,
                443,
                seq,
                0,
                TCP_SYN,
                65535,
                &[],
                &[],
                &[],
            )
            .expect("syn");
            stack.push_ip_tcp(&syn);
            stack.poll(100, &mut tx, &mut accepted);
            let syn_ack_pkt = tx.pop().expect("synack");
            let syn_ack = parse_tcp(parse_ip(&syn_ack_pkt).unwrap().payload).unwrap();
            let ack = build_ip_tcp_packet_slices(
                client,
                port,
                server,
                443,
                seq + 1,
                syn_ack.seq + 1,
                TCP_ACK,
                65535,
                &[],
                &[],
                &[],
            )
            .expect("ack");
            stack.push_ip_tcp(&ack);
            stack.poll(100, &mut tx, &mut accepted);
        }
        assert_eq!(stack.conns.len(), 2);

        // Both flows are fresh (<60 s idle): a 3rd SYN must NOT evict them.
        let syn3 = build_ip_tcp_packet_slices(
            client,
            40003,
            server,
            443,
            3000,
            0,
            TCP_SYN,
            65535,
            &[],
            &[],
            &[],
        )
        .expect("syn3");
        stack.push_ip_tcp(&syn3);
        stack.poll(200, &mut tx, &mut accepted);
        assert_eq!(stack.conns.len(), 2);
        assert_eq!(drops.tcp_limit.get(), 1);
        tx.clear();

        // Mark flow 40001 as Closing (FinWait2) and keep 40002 active with queued tx_buf.
        let flow1: FlowKey = (client, 40001, server, 443);
        let flow2: FlowKey = (client, 40002, server, 443);
        let aborted1 = Arc::clone(&stack.conns.get(&flow1).unwrap().aborted);
        stack.conns.get_mut(&flow1).unwrap().state = TcpState::FinWait2;
        stack.conns.get_mut(&flow1).unwrap().last_activity_ms =
            300 - SOFT_EVICT_ESTABLISHED_IDLE_MS;
        stack
            .conns
            .get_mut(&flow2)
            .unwrap()
            .tx_buf
            .extend(b"active");

        // Now a 3rd SYN evicts the Closing flow1, sends RST, sets aborted, and admits 40003.
        stack.push_ip_tcp(&syn3);
        stack.poll(300, &mut tx, &mut accepted);
        assert!(
            aborted1.load(Ordering::Acquire),
            "evicted flow must be marked aborted"
        );
        assert!(
            !stack.conns.contains_key(&flow1),
            "closing flow must be evicted first"
        );
        assert!(stack.conns.contains_key(&flow2), "active flow must survive");
        assert!(stack.conns.contains_key(&(client, 40003, server, 443)));
        assert_eq!(drops.tcp_limit.get(), 1, "eviction avoids tcp_limit drop");
        assert!(
            tx.iter()
                .any(|p| (parse_tcp(parse_ip(p).unwrap().payload).unwrap().flags & TCP_RST) != 0),
            "evicted flow must emit RST"
        );
        tx.clear();

        // Flow 40003 is SynReceived; after >=3 s it becomes Tier-2 evictable while
        // active flow2 (with buffered data) still cannot be evicted.
        let syn4 = build_ip_tcp_packet_slices(
            client,
            40004,
            server,
            443,
            4000,
            0,
            TCP_SYN,
            65535,
            &[],
            &[],
            &[],
        )
        .expect("syn4");
        stack.push_ip_tcp(&syn4);
        stack.poll(300 + SOFT_EVICT_SYN_MIN_AGE_MS, &mut tx, &mut accepted);
        assert!(!stack.conns.contains_key(&(client, 40003, server, 443)));
        assert!(stack.conns.contains_key(&flow2));
        assert!(stack.conns.contains_key(&(client, 40004, server, 443)));

        // A buffered, stalled CloseWait is not a tier-1 victim. When an idle
        // established flow is available, that flow yields its slot instead.
        let close_wait_flow: FlowKey = (client, 40004, server, 443);
        let conn = stack
            .conns
            .get_mut(&close_wait_flow)
            .expect("close wait flow");
        conn.state = TcpState::CloseWait;
        conn.state_deadline_ms = None;
        conn.tx_buf.extend(b"unacked-download-tail");
        conn.snd_wnd = 0; // peer's zero window keeps the tail buffered
        let idle_at = 300 + SOFT_EVICT_SYN_MIN_AGE_MS;
        let conn = stack.conns.get_mut(&flow2).expect("idle flow");
        conn.tx_buf.clear();
        conn.last_activity_ms = idle_at;

        let syn5 = build_ip_tcp_packet_slices(
            client,
            40005,
            server,
            443,
            5000,
            0,
            TCP_SYN,
            65535,
            &[],
            &[],
            &[],
        )
        .expect("syn5");
        stack.push_ip_tcp(&syn5);
        stack.poll(
            idle_at + SOFT_EVICT_ESTABLISHED_IDLE_MS,
            &mut tx,
            &mut accepted,
        );
        assert!(
            stack.conns.contains_key(&close_wait_flow),
            "buffered CloseWait must not be evicted"
        );
        assert!(
            !stack
                .conns
                .get(&close_wait_flow)
                .expect("close wait")
                .tx_buf
                .is_empty(),
            "its unacked tail must survive"
        );
        assert!(
            !stack.conns.contains_key(&flow2),
            "idle empty flow must be evicted instead"
        );
        assert!(stack.conns.contains_key(&(client, 40005, server, 443)));
    }

    #[test]
    fn idle_buffer_shrink_releases_burst_capacity_without_adding_timers() {
        let mut stack = ProxyTcpStack::new(TcpStackConfig::mobile());
        let client = IpAddr::V4(Ipv4Addr::new(198, 19, 0, 1));
        let server = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let flow: FlowKey = (client, 41000, server, 443);
        let mut tx = Vec::new();
        let mut accepted = Vec::new();

        let syn = build_ip_tcp_packet_slices(
            client,
            41000,
            server,
            443,
            1000,
            0,
            TCP_SYN,
            65535,
            &[],
            &[],
            &[],
        )
        .expect("syn");
        stack.push_ip_tcp(&syn);
        stack.poll(100, &mut tx, &mut accepted);
        let syn_ack_pkt = tx.pop().expect("synack");
        let syn_ack = parse_tcp(parse_ip(&syn_ack_pkt).unwrap().payload).unwrap();
        let ack = build_ip_tcp_packet_slices(
            client,
            41000,
            server,
            443,
            1001,
            syn_ack.seq + 1,
            TCP_ACK,
            65535,
            &[],
            &[],
            &[],
        )
        .expect("ack");
        stack.push_ip_tcp(&ack);
        stack.poll(100, &mut tx, &mut accepted);

        // Simulate a completed burst leaving oversized empty capacity.
        let conn = stack.conns.get_mut(&flow).expect("flow");
        conn.tx_buf.reserve(64 * 1024);
        assert!(conn.tx_buf.capacity() > IDLE_TX_BUF_SHRINK_THRESHOLD);

        // Before IDLE_BUF_SHRINK_AFTER_MS, buffer stays retained (no hot-path churn).
        conn.shrink_idle_bufs(100 + IDLE_BUF_SHRINK_AFTER_MS - 1);
        assert!(conn.tx_buf.capacity() > IDLE_TX_BUF_SHRINK_THRESHOLD);

        // After IDLE_BUF_SHRINK_AFTER_MS while empty, capacity shrinks to 0.
        conn.shrink_idle_bufs(100 + IDLE_BUF_SHRINK_AFTER_MS);
        assert_eq!(conn.tx_buf.capacity(), 0);

        // Zero extra wakeup timers: next delay is still the 30-minute idle timeout.
        let delay = stack.poll_delay_ms(100).expect("idle deadline");
        assert_eq!(delay, TcpStackConfig::mobile().idle_timeout_ms);
    }

    #[test]
    fn mobile_high_ram_profile_halves_buffers_above_128_flows() {
        let mut stack = ProxyTcpStack::new(TcpStackConfig {
            max_connections: 256,
            ..TcpStackConfig::mobile()
        });
        let client = IpAddr::V4(Ipv4Addr::new(198, 19, 0, 1));
        let server = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let mut tx = Vec::new();
        let mut accepted = Vec::new();

        for i in 0..130u16 {
            let syn = build_ip_tcp_packet_slices(
                client,
                30000 + i,
                server,
                443,
                1000 + u32::from(i),
                0,
                TCP_SYN,
                65535,
                &[],
                &[],
                &[],
            )
            .expect("syn");
            stack.push_ip_tcp(&syn);
            stack.poll(100, &mut tx, &mut accepted);
            tx.clear();
        }
        assert_eq!(stack.conns.len(), 130);
        let first = stack.conns.get(&(client, 30000, server, 443)).unwrap();
        let overflow = stack.conns.get(&(client, 30129, server, 443)).unwrap();
        assert_eq!(first.max_rcv_buf, 128 * 1024);
        assert_eq!(overflow.max_rcv_buf, 64 * 1024);
    }

    #[test]
    fn soft_eviction_requires_idle_age_for_an_empty_close_wait() {
        let mut stack = ProxyTcpStack::new(TcpStackConfig::default());
        let client = IpAddr::V4(Ipv4Addr::new(198, 19, 0, 1));
        let server = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let mut tx = Vec::new();
        let mut accepted = Vec::new();

        for (port, seq) in [(40001u16, 1000u32), (40002u16, 2000u32)] {
            let syn = build_ip_tcp_packet_slices(
                client,
                port,
                server,
                443,
                seq,
                0,
                TCP_SYN,
                65_535,
                &[],
                &[],
                &[],
            )
            .expect("syn");
            stack.push_ip_tcp(&syn);
            stack.poll(100, &mut tx, &mut accepted);
            let syn_ack_pkt = tx.pop().expect("synack");
            let syn_ack = parse_tcp(parse_ip(&syn_ack_pkt).expect("ip").payload).expect("tcp");
            let ack = build_ip_tcp_packet_slices(
                client,
                port,
                server,
                443,
                seq + 1,
                syn_ack.seq + 1,
                TCP_ACK,
                65_535,
                &[],
                &[],
                &[],
            )
            .expect("ack");
            stack.push_ip_tcp(&ack);
            stack.poll(100, &mut tx, &mut accepted);
        }

        let fresh: FlowKey = (client, 40001, server, 443);
        let idle: FlowKey = (client, 40002, server, 443);
        let now = 100 + SOFT_EVICT_ESTABLISHED_IDLE_MS;
        stack.conns.get_mut(&fresh).expect("fresh flow").state = TcpState::CloseWait;
        stack
            .conns
            .get_mut(&fresh)
            .expect("fresh flow")
            .last_activity_ms = now;
        stack
            .conns
            .get_mut(&idle)
            .expect("idle flow")
            .last_activity_ms = now - SOFT_EVICT_ESTABLISHED_IDLE_MS;

        let mut batch = Vec::new();
        assert!(ProxyTcpStack::evict_one_stale_conn(
            &mut stack.conns,
            &mut batch,
            now,
            &mut tx
        ));
        assert!(
            !stack.conns.contains_key(&idle),
            "the old idle established flow must be evicted"
        );
        assert!(
            stack.conns.contains_key(&fresh),
            "a fresh empty CloseWait must not be evicted first"
        );
    }

    #[test]
    fn soft_eviction_never_evicts_protected_push_ports_and_respects_3m_idle_threshold() {
        let mut stack = ProxyTcpStack::new(TcpStackConfig {
            max_connections: 2,
            ..TcpStackConfig::mobile()
        });
        let drops = Arc::new(DropCounters::default());
        stack.set_drop_counters(Arc::clone(&drops));

        let client = IpAddr::V4(Ipv4Addr::new(198, 19, 0, 1));
        let server = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let mut tx = Vec::new();
        let mut accepted = Vec::new();

        // Establish one FCM push socket (port 5228) at t=100 and one HTTPS socket (443) at t=200.
        for (sport, dport, t, seq) in [
            (42001u16, 5228u16, 100i64, 1000u32),
            (42002, 443, 200, 2000),
        ] {
            let syn = build_ip_tcp_packet_slices(
                client,
                sport,
                server,
                dport,
                seq,
                0,
                TCP_SYN,
                65535,
                &[],
                &[],
                &[],
            )
            .expect("syn");
            stack.push_ip_tcp(&syn);
            stack.poll(t, &mut tx, &mut accepted);
            let syn_ack_pkt = tx.pop().expect("synack");
            let syn_ack = parse_tcp(parse_ip(&syn_ack_pkt).unwrap().payload).unwrap();
            let ack = build_ip_tcp_packet_slices(
                client,
                sport,
                server,
                dport,
                seq + 1,
                syn_ack.seq + 1,
                TCP_ACK,
                65535,
                &[],
                &[],
                &[],
            )
            .expect("ack");
            stack.push_ip_tcp(&ack);
            stack.poll(t, &mut tx, &mut accepted);
        }

        let push_flow: FlowKey = (client, 42001, server, 5228);
        let https_flow: FlowKey = (client, 42002, server, 443);

        // At t = 200 + 180_000 - 1: push_flow is past 180 s idle but protected;
        // https_flow is 1 ms short of 180 s -> neither may be evicted.
        let syn3 = build_ip_tcp_packet_slices(
            client,
            42003,
            server,
            443,
            3000,
            0,
            TCP_SYN,
            65535,
            &[],
            &[],
            &[],
        )
        .expect("syn3");
        stack.push_ip_tcp(&syn3);
        stack.poll(
            200 + SOFT_EVICT_ESTABLISHED_IDLE_MS - 1,
            &mut tx,
            &mut accepted,
        );
        assert!(
            stack.conns.contains_key(&push_flow),
            "FCM port 5228 must be exempt"
        );
        assert!(stack.conns.contains_key(&https_flow));
        assert_eq!(drops.tcp_limit.get(), 1);
        tx.clear();

        // At t = 200 + 180_000: https_flow reaches 180 s idle and yields its slot,
        // while the older FCM push_flow (5228) stays untouched.
        stack.push_ip_tcp(&syn3);
        stack.poll(200 + SOFT_EVICT_ESTABLISHED_IDLE_MS, &mut tx, &mut accepted);
        assert!(
            stack.conns.contains_key(&push_flow),
            "FCM port 5228 must survive"
        );
        assert!(
            !stack.conns.contains_key(&https_flow),
            "idle 443 flow should be evicted"
        );
        assert!(stack.conns.contains_key(&(client, 42003, server, 443)));
    }

    #[cfg(not(target_os = "android"))]
    #[test]
    fn relay_read_chunk_matches_linux_production() {
        assert_eq!(S2C_READ_CHUNK_BYTES, 64 * 1024);
        assert_eq!(S2C_STREAM_CHANNEL_CAP, 1);
    }

    #[test]
    fn relay_drain_bounds_tx_buf_before_extending() {
        let mut stack = ProxyTcpStack::new(TcpStackConfig::default());
        let (_srv_nxt, _acc) = handshake(&mut stack, 500);
        let (relay_tx, relay_rx) = mpsc::channel(S2C_STREAM_CHANNEL_CAP);
        let pool = RelayBufPool::new();
        let max_snd_buf = {
            let conn = stack.conns.values_mut().next().expect("conn");
            conn.tx_buf
                .extend(vec![1u8; conn.max_snd_buf - S2C_READ_CHUNK_BYTES / 2]);
            conn.from_relay = Some(relay_rx);
            conn.max_snd_buf
        };
        relay_tx
            .try_send(vec![2u8; S2C_READ_CHUNK_BYTES])
            .expect("one queued relay chunk");

        let conn = stack.conns.values_mut().next().expect("conn");
        conn.drain_from_relay(30, &pool);
        assert_eq!(
            conn.tx_buf.len(),
            max_snd_buf,
            "tx_buf must not grow past the send buffer bound"
        );
        assert!(conn.relay_pending.is_some(), "remainder must be retained");

        conn.tx_buf.drain(..S2C_READ_CHUNK_BYTES / 2);
        conn.drain_from_relay(31, &pool);
        assert!(conn.relay_pending.is_none(), "remainder must be drained");
        assert!(
            conn.tx_buf
                .iter()
                .rev()
                .take(S2C_READ_CHUNK_BYTES)
                .all(|&byte| byte == 2),
            "staged bytes must keep their order"
        );
    }
}
