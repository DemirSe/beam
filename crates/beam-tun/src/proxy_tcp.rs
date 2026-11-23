//! Lightweight, proxy-oriented IPv4 + IPv6 TCP/IP stack with RFC 7323 Window
//! Scaling, zero-copy `VecDeque::as_slices()` TX segmentation, lossless
//! receive backpressure, and cumulative ACK coalescing.

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

const OUR_WSCALE: u8 = 6; // 64x multiplier -> up to ~4 MiB window; capped at max_rcv_buf (2 MiB)
const DEFAULT_MAX_RCV_BUF: usize = 2 * 1024 * 1024;
const DEFAULT_MAX_SND_BUF: usize = 2 * 1024 * 1024;
const MAX_OOO_SEGMENTS: usize = 256;
const STREAM_CHANNEL_CAP: usize = 64;
const RELAY_COALESCE_BYTES: usize = 64 * 1024;
const INITIAL_RTO_MS: i64 = 200;
const MAX_RTO_MS: i64 = 4_000;
const MAX_RETRIES: u8 = 8;
const HANDSHAKE_TIMEOUT_MS: i64 = 10_000;
const CLOSING_TIMEOUT_MS: i64 = 5_000;

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
    retries: u8,
    state_deadline_ms: Option<i64>,
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
        if let Some(pkt) =
            self.build_packet_slices(TCP_SYN | TCP_ACK, &options, &[], &[], self.snd_una)
        {
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
    }

    fn on_segment(
        &mut self,
        seg: &crate::packet::TcpSegmentView<'_>,
        now_ms: i64,
        tx_out: &mut Vec<Vec<u8>>,
    ) {
        if (seg.flags & TCP_RST) != 0 {
            self.state = TcpState::Closed;
            self.to_relay.take();
            self.from_relay.take();
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

        if !seg.payload.is_empty()
            && matches!(
                self.state,
                TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2
            )
        {
            let out_of_order = self.process_data(seg.seq, seg.payload);
            if out_of_order {
                // RFC 5681: emit an immediate duplicate ACK for every
                // out-of-order segment so the local OS triggers Fast
                // Retransmit (3 dup-ACKs) in 0 ms instead of a 200 ms RTO.
                if let Some(pkt) = self.build_packet_slices(TCP_ACK, &[], &[], &[], self.snd_nxt) {
                    tx_out.push(pkt);
                }
                self.need_ack = false;
            } else {
                self.need_ack = true;
            }
        }

        let fin_seq = seg.seq.wrapping_add(seg.payload.len() as u32);
        if (seg.flags & TCP_FIN) != 0 && fin_seq == self.rcv_nxt {
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
                    if let Some(pkt) =
                        self.build_packet_slices(TCP_ACK, &[], &[], &[], self.snd_nxt)
                    {
                        tx_out.push(pkt);
                    }
                    self.need_ack = false;
                    self.state = TcpState::Closed;
                }
                _ => {}
            }
        }
    }

    fn process_ack(&mut self, ack: u32, raw_window: u16, now_ms: i64, tx_out: &mut Vec<Vec<u8>>) {
        self.snd_wnd = u32::from(raw_window) << self.peer_wscale;

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
            let skip = (-rel) as usize;
            if skip >= payload.len() {
                return false;
            }
            let fresh = &payload[skip..];
            self.rcv_coalesce.extend_from_slice(fresh);
            self.rcv_nxt = self.rcv_nxt.wrapping_add(fresh.len() as u32);
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
                let rel = seq.wrapping_sub(self.rcv_nxt) as i32;
                let skip = (-rel) as usize;
                if skip < seg.len() {
                    let fresh = &seg[skip..];
                    self.rcv_coalesce.extend_from_slice(fresh);
                    self.rcv_nxt = self.rcv_nxt.wrapping_add(fresh.len() as u32);
                    if self.rcv_coalesce.len() >= RELAY_COALESCE_BYTES {
                        self.queue_coalesce_chunk();
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
    /// channel. If the channel is momentarily full, chunks stay in
    /// `pending_to_relay` and reduce `rcv_wnd_bytes()` until drained.
    fn flush_rcv_to_relay(&mut self) {
        self.queue_coalesce_chunk();
        let mut closed = false;
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

    fn drain_from_relay(&mut self) {
        let Some(rx) = self.from_relay.as_mut() else {
            return;
        };
        while self.tx_buf.len() < self.max_snd_buf {
            match rx.try_recv() {
                Ok(chunk) => self.tx_buf.extend(chunk),
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
                break;
            }
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
            self.state_deadline_ms = Some(now_ms + CLOSING_TIMEOUT_MS);
            self.state = match self.state {
                TcpState::Established => TcpState::FinWait1,
                TcpState::CloseWait => TcpState::LastAck,
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
            return;
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
    incoming: VecDeque<Vec<u8>>,
    waker: Arc<Notify>,
}

impl ProxyTcpStack {
    /// Creates a new custom proxy TCP stack.
    pub fn new(config: TcpStackConfig) -> Self {
        Self {
            config,
            conns: HashMap::new(),
            incoming: VecDeque::with_capacity(128),
            waker: Arc::new(Notify::new()),
        }
    }
}

impl NetStack for ProxyTcpStack {
    fn push_ip_tcp(&mut self, packet: &[u8]) {
        if self.incoming.len() < 2048 {
            self.incoming.push_back(packet.to_vec());
        }
    }

    fn poll(
        &mut self,
        now_ms: i64,
        tx_out: &mut Vec<Vec<u8>>,
        accepted: &mut Vec<AcceptedTcpStream>,
    ) {
        while let Some(pkt) = self.incoming.pop_front() {
            let Some(ip) = parse_ip(&pkt) else {
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
                let max_buf = self.config.socket_buffer_bytes.max(DEFAULT_MAX_RCV_BUF);
                let mut conn = TcpConn {
                    flow,
                    state: TcpState::SynReceived,
                    mss,
                    peer_wscale: negotiated_peer_wscale,
                    our_wscale,
                    rcv_nxt: seg.seq.wrapping_add(1),
                    rcv_coalesce: Vec::with_capacity(RELAY_COALESCE_BYTES),
                    pending_to_relay: VecDeque::new(),
                    pending_to_relay_bytes: 0,
                    ooo: BTreeMap::new(),
                    ooo_bytes: 0,
                    in_flight_relay: Arc::new(AtomicUsize::new(0)),
                    max_rcv_buf: max_buf,
                    last_advertised_wnd: max_buf as u32,
                    need_ack: false,
                    peer_fin_received: false,
                    snd_una: iss,
                    snd_nxt: iss,
                    snd_wnd: u32::from(seg.window),
                    tx_buf: VecDeque::new(),
                    max_snd_buf: self.config.socket_buffer_bytes.max(DEFAULT_MAX_SND_BUF),
                    fin_sent: false,
                    fin_seq: 0,
                    dup_acks: 0,
                    rto_ms: INITIAL_RTO_MS,
                    rto_deadline_ms: None,
                    retries: 0,
                    state_deadline_ms: Some(now_ms + HANDSHAKE_TIMEOUT_MS),
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
            conn.drain_from_relay();
            conn.flush_tx(now_ms, tx_out);

            // Emit a Window Update ACK promptly once the relay reopens >= 256 KiB
            // after a low/zero window so the local OS sender never stalls in
            // zero-window persist waiting for megabytes to drain.
            let current_wnd = conn.rcv_wnd_bytes();
            let reopen_threshold = (conn.max_rcv_buf as u32 / 4).min(256 * 1024);
            if !conn.need_ack
                && matches!(conn.state, TcpState::Established)
                && conn.last_advertised_wnd < reopen_threshold
                && current_wnd >= reopen_threshold
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
            for d in [conn.rto_deadline_ms, conn.state_deadline_ms]
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
