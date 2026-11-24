//! Lightweight, proxy-oriented IPv4 + IPv6 TCP/IP stack with RFC 7323 Window
//! Scaling, zero-copy `VecDeque::as_slices()` TX segmentation, lossless
//! bounded receive backpressure, zero-window persist, OOO FIN handling, and
//! cumulative ACK coalescing.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use tokio::sync::{Notify, mpsc};

use crate::packet::{
    IP_PROTO_TCP, TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN, build_ip_tcp_packet_slices,
    parse_ip, parse_tcp, parse_tcp_syn_options,
};
use crate::stack::{AcceptedTcpStream, NetStack, TcpStackConfig, TunTcpStream};

const OUR_WSCALE: u8 = 7; // 128x multiplier -> up to ~8 MiB window; capped at max_rcv_buf
const MIN_TCP_BUF: usize = 64 * 1024;
const MAX_TCP_BUF: usize = 8 * 1024 * 1024;
const MAX_INCOMING_PACKETS: usize = 2048;
const MAX_INCOMING_BYTES: usize = 4 * 1024 * 1024;
const MAX_OOO_SEGMENTS: usize = 256;
const STREAM_CHANNEL_CAP: usize = 96;
const RELAY_COALESCE_BYTES: usize = 64 * 1024;
const INITIAL_RTO_MS: i64 = 200;
const MAX_RTO_MS: i64 = 4_000;
const MAX_RETRIES: u8 = 8;
const HANDSHAKE_TIMEOUT_MS: i64 = 10_000;
const CLOSING_TIMEOUT_MS: i64 = 5_000;
const IDLE_TIMEOUT_MS: i64 = 300_000;

type FlowKey = (IpAddr, u16, IpAddr, u16);

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

struct TcpConn {
    flow: FlowKey,
    state: TcpState,
    mss: usize,
    peer_wscale: u8,
    our_wscale: u8,
    // Receive state (peer -> proxy)
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
    retries: u8,
    state_deadline_ms: Option<i64>,
    last_activity_ms: i64,
    // Async relay channels
    accepted: bool,
    to_relay: Option<mpsc::Sender<Vec<u8>>>,
    from_relay: Option<mpsc::Receiver<Vec<u8>>>,
    relay_eof: bool,
}

impl TcpConn {
    fn rcv_wnd_bytes(&self) -> u32 {
        let used = self
            .in_flight_relay
            .load(Ordering::Acquire)
            .saturating_add(self.pending_to_relay_bytes)
            .saturating_add(self.ooo_bytes)
            .saturating_add(self.rcv_coalesce.len());
        let avail = self.max_rcv_buf.saturating_sub(used);
        let max_scaled = (u32::from(u16::MAX)) << self.our_wscale;
        u32::try_from(avail).unwrap_or(max_scaled).min(max_scaled)
    }

    fn advertised_window(&self) -> u16 {
        let wnd = self.rcv_wnd_bytes() >> self.our_wscale;
        u16::try_from(wnd).unwrap_or(u16::MAX)
    }

    fn build_packet_slices(
        &mut self,
        flags: u8,
        options: &[u8],
        payload_a: &[u8],
        payload_b: &[u8],
        seq: u32,
    ) -> Option<Vec<u8>> {
        let wnd_scaled = self.advertised_window();
        self.last_advertised_wnd = u32::from(wnd_scaled) << self.our_wscale;
        build_ip_tcp_packet_slices(
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
        )
    }

    /// Emits a TCP segment slicing `tx_buf[offset..offset+len]` directly via
    /// `VecDeque::as_slices()` with zero intermediate payload allocation.
    fn emit_tx_segment(
        &mut self,
        offset: usize,
        len: usize,
        flags: u8,
        seq: u32,
        tx_out: &mut Vec<Vec<u8>>,
    ) {
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
        let wnd_scaled = self.advertised_window();
        self.last_advertised_wnd = u32::from(wnd_scaled) << self.our_wscale;
        if let Some(pkt) = build_ip_tcp_packet_slices(
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
        }
    }

    fn send_syn_ack(&mut self, now_ms: i64, tx_out: &mut Vec<Vec<u8>>) {
        let mss_u16 = self.mss as u16;
        let mss_bytes = mss_u16.to_be_bytes();
        let options: Vec<u8> = if self.our_wscale > 0 {
            vec![2, 4, mss_bytes[0], mss_bytes[1], 1, 3, 3, self.our_wscale]
        } else {
            vec![2, 4, mss_bytes[0], mss_bytes[1]]
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
            &options,
            &[],
            &[],
        ) {
            tx_out.push(pkt);
        }
        self.snd_nxt = self.snd_una.wrapping_add(1);
        self.rto_deadline_ms = Some(now_ms + self.rto_ms);
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
        self.pending_to_relay.clear();
        self.pending_to_relay_bytes = 0;
    }

    fn on_segment(
        &mut self,
        seg: &crate::packet::TcpSegmentView<'_>,
        now_ms: i64,
        tx_out: &mut Vec<Vec<u8>>,
    ) {
        self.last_activity_ms = now_ms;

        if (seg.flags & TCP_RST) != 0 {
            self.state = TcpState::Closed;
            self.to_relay.take();
            self.from_relay.take();
            self.pending_to_relay.clear();
            self.pending_to_relay_bytes = 0;
            return;
        }

        if (seg.flags & TCP_SYN) != 0 && (seg.flags & TCP_ACK) == 0 {
            if self.state == TcpState::SynReceived {
                self.send_syn_ack(now_ms, tx_out);
            }
            return;
        }

        if (seg.flags & TCP_ACK) != 0 {
            self.process_ack(seg.ack, seg.window, now_ms, tx_out);
        }

        if self.state == TcpState::Closed {
            return;
        }

        let mut emit_dup_ack = false;
        if !seg.payload.is_empty()
            && matches!(
                self.state,
                TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2
            )
        {
            if self.process_data(seg.seq, seg.payload) {
                emit_dup_ack = true;
            } else {
                self.need_ack = true;
            }
        }

        // Handle in-order or out-of-order FIN.
        if (seg.flags & TCP_FIN) != 0
            && matches!(
                self.state,
                TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2
            )
        {
            let fin_seq = seg.seq.wrapping_add(seg.payload.len() as u32);
            if fin_seq == self.rcv_nxt {
                self.consume_peer_fin(now_ms, tx_out);
            } else if (fin_seq.wrapping_sub(self.rcv_nxt) as i32) > 0 {
                // Record OOO FIN so it triggers once preceding data arrives.
                self.peer_fin_seq = Some(fin_seq);
                emit_dup_ack = true;
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

    fn process_ack(&mut self, ack: u32, raw_window: u16, now_ms: i64, tx_out: &mut Vec<Vec<u8>>) {
        self.snd_wnd = u32::from(raw_window) << self.peer_wscale;
        if self.snd_wnd > 0 {
            self.persist_deadline_ms = None;
            self.persist_ms = INITIAL_RTO_MS;
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
                self.emit_tx_segment(0, len, TCP_ACK | TCP_PSH, self.snd_una, tx_out);
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
            if self.ooo.len() < MAX_OOO_SEGMENTS
                && self.ooo_bytes.saturating_add(payload.len()) <= self.max_rcv_buf
            {
                let entry = self.ooo.entry(seq).or_default();
                if payload.len() > entry.len() {
                    self.ooo_bytes = self.ooo_bytes.saturating_add(payload.len() - entry.len());
                    *entry = payload.to_vec();
                }
            }
            true
        }
    }

    fn drain_ooo(&mut self) {
        loop {
            let next_key = self
                .ooo
                .keys()
                .copied()
                .find(|&k| (k.wrapping_sub(self.rcv_nxt) as i32) <= 0);
            let Some(seq) = next_key else {
                break;
            };
            if let Some(seg) = self.ooo.remove(&seq) {
                self.ooo_bytes = self.ooo_bytes.saturating_sub(seg.len());
                let skip = self.rcv_nxt.wrapping_sub(seq) as usize;
                if skip < seg.len() {
                    let avail = self.rcv_wnd_bytes() as usize;
                    let fresh = &seg[skip..];
                    let accept = fresh.len().min(avail);
                    if accept > 0 {
                        self.rcv_coalesce.extend_from_slice(&fresh[..accept]);
                        self.rcv_nxt = self.rcv_nxt.wrapping_add(accept as u32);
                        if self.rcv_coalesce.len() >= RELAY_COALESCE_BYTES {
                            self.queue_coalesce_chunk();
                        }
                    }
                }
            }
        }
    }

    fn queue_coalesce_chunk(&mut self) {
        if self.rcv_coalesce.is_empty() {
            return;
        }
        let chunk = std::mem::take(&mut self.rcv_coalesce);
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

    fn drain_from_relay(&mut self, now_ms: i64) {
        let Some(rx) = self.from_relay.as_mut() else {
            return;
        };
        while self.tx_buf.len() < self.max_snd_buf {
            match rx.try_recv() {
                Ok(chunk) => {
                    self.last_activity_ms = now_ms;
                    self.tx_buf.extend(chunk);
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

    fn flush_tx(&mut self, now_ms: i64, tx_out: &mut Vec<Vec<u8>>) {
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
            self.emit_tx_segment(in_flight, seg_len, flags, seq, tx_out);
            self.snd_nxt = self.snd_nxt.wrapping_add(seg_len as u32);
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
            if let Some(pkt) = self.build_packet_slices(TCP_FIN | TCP_ACK, &[], &[], &[], seq) {
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

    fn check_timers(&mut self, now_ms: i64, tx_out: &mut Vec<Vec<u8>>) {
        if let Some(deadline) = self.state_deadline_ms
            && now_ms >= deadline
        {
            self.state = TcpState::Closed;
            self.to_relay.take();
            self.from_relay.take();
            self.pending_to_relay.clear();
            self.pending_to_relay_bytes = 0;
            return;
        }

        // Bound idle `Established` / `CloseWait` connections so abandoned flows
        // cannot leak indefinitely.
        if matches!(self.state, TcpState::Established | TcpState::CloseWait)
            && now_ms.saturating_sub(self.last_activity_ms) >= IDLE_TIMEOUT_MS
        {
            self.send_rst(self.snd_nxt, tx_out);
            return;
        }

        // Zero-window persist probe.
        if let Some(persist_at) = self.persist_deadline_ms
            && now_ms >= persist_at
        {
            if self.retries >= MAX_RETRIES {
                self.send_rst(self.snd_nxt, tx_out);
                return;
            }
            self.retries += 1;
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
                        self.emit_tx_segment(0, len, TCP_ACK | TCP_PSH, self.snd_una, tx_out);
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
    waker: Arc<Notify>,
}

impl ProxyTcpStack {
    /// Creates a new custom proxy TCP stack.
    pub fn new(config: TcpStackConfig) -> Self {
        Self {
            config,
            conns: HashMap::new(),
            incoming_buf: Vec::with_capacity(64 * 1024),
            incoming_lens: Vec::with_capacity(128),
            waker: Arc::new(Notify::new()),
        }
    }
}

impl NetStack for ProxyTcpStack {
    fn push_ip_tcp(&mut self, packet: &[u8]) {
        if self.incoming_lens.len() < MAX_INCOMING_PACKETS
            && self.incoming_buf.len().saturating_add(packet.len()) <= MAX_INCOMING_BYTES
        {
            self.incoming_buf.extend_from_slice(packet);
            self.incoming_lens.push(packet.len());
        }
    }

    fn poll(
        &mut self,
        now_ms: i64,
        tx_out: &mut Vec<Vec<u8>>,
        accepted: &mut Vec<AcceptedTcpStream>,
    ) {
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

            if let Some(conn) = self.conns.get_mut(&flow) {
                conn.on_segment(&seg, now_ms, tx_out);
            } else if (seg.flags & TCP_SYN) != 0 && (seg.flags & TCP_ACK) == 0 {
                if self.conns.len() >= self.config.max_connections {
                    continue;
                }
                let (peer_mss, peer_wscale) = parse_tcp_syn_options(seg.options);
                let header_overhead = match ip.src_ip {
                    IpAddr::V4(_) => 40,
                    IpAddr::V6(_) => 60,
                };
                let max_mss = self
                    .config
                    .mtu
                    .saturating_sub(header_overhead)
                    .clamp(536, 1460);
                let mss = peer_mss
                    .map(|m| usize::from(m).clamp(536, max_mss))
                    .unwrap_or(max_mss);
                let (our_wscale, negotiated_peer_wscale) = match peer_wscale {
                    Some(ws) => (OUR_WSCALE, ws),
                    None => (0, 0),
                };
                let iss = next_iss();
                let max_buf = self
                    .config
                    .socket_buffer_bytes
                    .clamp(MIN_TCP_BUF, MAX_TCP_BUF);
                let mut conn = TcpConn {
                    flow,
                    state: TcpState::SynReceived,
                    mss,
                    peer_wscale: negotiated_peer_wscale,
                    our_wscale,
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
                    tx_buf: VecDeque::new(),
                    max_snd_buf: max_buf,
                    fin_sent: false,
                    fin_seq: 0,
                    dup_acks: 0,
                    rto_ms: INITIAL_RTO_MS,
                    rto_deadline_ms: None,
                    persist_ms: INITIAL_RTO_MS,
                    persist_deadline_ms: None,
                    retries: 0,
                    state_deadline_ms: Some(now_ms + HANDSHAKE_TIMEOUT_MS),
                    last_activity_ms: now_ms,
                    accepted: false,
                    to_relay: None,
                    from_relay: None,
                    relay_eof: false,
                };
                conn.send_syn_ack(now_ms, tx_out);
                self.conns.insert(flow, conn);
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

        self.conns.retain(|_, conn| {
            if !conn.accepted && matches!(conn.state, TcpState::Established | TcpState::CloseWait) {
                let (to_relay_tx, to_relay_rx) = mpsc::channel(STREAM_CHANNEL_CAP);
                let (from_relay_tx, from_relay_rx) = mpsc::channel(STREAM_CHANNEL_CAP);
                conn.accepted = true;
                conn.to_relay = Some(to_relay_tx);
                conn.from_relay = Some(from_relay_rx);
                accepted.push(AcceptedTcpStream {
                    src: SocketAddr::new(conn.flow.0, conn.flow.1),
                    dst: SocketAddr::new(conn.flow.2, conn.flow.3),
                    stream: TunTcpStream::new_with_accounting(
                        to_relay_rx,
                        from_relay_tx,
                        Arc::clone(&self.waker),
                        Some(Arc::clone(&conn.in_flight_relay)),
                    ),
                });
            }

            conn.flush_rcv_to_relay();
            conn.drain_from_relay(now_ms);
            conn.flush_tx(now_ms, tx_out);

            // Emit a Window Update ACK promptly when:
            // 1. Reopening from a low/zero advertised window to >= reopen_threshold, OR
            // 2. Available receive window has grown by >= max(256 KiB, max_rcv_buf / 4)
            //    above `last_advertised_wnd` (RFC 1122 / Linux tcp_select_window).
            let current_wnd = conn.rcv_wnd_bytes();
            let reopen_threshold = (conn.max_rcv_buf as u32 / 4).min(256 * 1024);
            let growth_step = (conn.max_rcv_buf as u32 / 4).max(256 * 1024);
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
                if let Some(pkt) = conn.build_packet_slices(TCP_ACK, &[], &[], &[], conn.snd_nxt) {
                    tx_out.push(pkt);
                }
                conn.need_ack = false;
            }

            conn.check_timers(now_ms, tx_out);
            conn.state != TcpState::Closed
        });
    }

    fn poll_delay_ms(&mut self, now_ms: i64) -> Option<u64> {
        let mut earliest: Option<i64> = None;
        for conn in self.conns.values() {
            for d in [
                conn.rto_deadline_ms,
                conn.persist_deadline_ms,
                conn.state_deadline_ms,
            ]
            .into_iter()
            .flatten()
            {
                earliest = Some(earliest.map_or(d, |cur| cur.min(d)));
            }
        }
        earliest.map(|d| d.saturating_sub(now_ms).max(1) as u64)
    }

    fn waker(&self) -> Arc<Notify> {
        Arc::clone(&self.waker)
    }
}

fn next_iss() -> u32 {
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
        tx.clear();
        stack.poll(40, &mut tx, &mut accepted);
        assert!(tx.is_empty(), "must not transmit into zero window");

        // Advance past INITIAL_RTO_MS -> persist probe must fire.
        stack.poll(40 + INITIAL_RTO_MS, &mut tx, &mut accepted);
        assert_eq!(tx.len(), 1, "persist probe ACK must be emitted");

        // Advance past IDLE_TIMEOUT_MS -> stalled connection must be reclaimed.
        drop(writer);
        tx.clear();
        stack.poll(40 + IDLE_TIMEOUT_MS + 1000, &mut tx, &mut accepted);
        assert!(stack.conns.is_empty(), "idle connection must be reclaimed");
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
}
