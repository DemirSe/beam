//! Built-in DNS interceptor for `beam-tun`:
//! - Resolves regular queries through the `beam` tunnel via DoH (HTTPS/POST)
//!   or plain DNS (TCP/53 or XUDP UDP/53).
//! - Routes `.lan`, `.local`, `.internal`, and user-configured `bypass_domains`
//!   directly to the pre-VPN local DNS upstream (outside the tunnel).
//! - Caches answers in a bounded LRU TTL cache with instant `tx_id` rewriting.
//! - Zero panics / zero `unwrap` on network input.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use beam_core::address::{Address, NetLocation};
use beam_core::client::{BeamClientConfig, BeamTcpStream, XudpClient, XudpClientConfig, dial_tcp};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{Semaphore, mpsc};
use tokio::time::{Instant as TokioInstant, timeout, timeout_at};
use tokio_rustls::TlsConnector;
use tracing::{debug, info, warn};

use crate::packet::build_ip_udp_packet_patched;
use crate::ratelimit::RateLimiter;
use crate::stats::{DnsCounters, DnsSnapshot};

const MAX_DNS_QUERY_BYTES: usize = 1232;
/// Maximum DNS response size accepted from DoH or DNS-over-TCP upstreams
/// (e.g. large TXT, DNSSEC, or SVCB responses).
const MAX_DOH_RESPONSE_BYTES: usize = 16_384;
/// Maximum DNS response size delivered over UDP back to the local TUN stub
/// (RFC 9715 / IPv6 minimum-MTU fragmentation-safe ceiling).
const MAX_UDP_DNS_RESPONSE_BYTES: usize = 1232;
/// Classic RFC 1035 UDP DNS payload limit when the client query omits EDNS0 OPT.
const CLASSIC_UDP_DNS_RESPONSE_BYTES: usize = 512;
/// Receive buffer size for local UDP DNS upstream replies.
const MAX_LOCAL_UDP_RECV_BYTES: usize = 4096;
const MAX_HTTP_HEADER_BYTES: usize = 8192;
const MAX_INFLIGHT_DNS_QUERIES: usize = 128;
const DEFAULT_CACHE_SIZE: usize = 1024;
const MAX_CACHE_SIZE: usize = 16_384;
const MIN_CACHE_TTL_SECS: u32 = 5;
const MAX_CACHE_TTL_SECS: u32 = 3600;
const NEGATIVE_CACHE_TTL_SECS: u32 = 15;
const DEFAULT_QUERY_TIMEOUT: Duration = Duration::from_secs(4);
const MAX_DOH_POOL_SIZE: usize = 4;
const DOH_POOL_IDLE_TTL: Duration = Duration::from_secs(30);
const MAX_TCP_DNS_POOL_SIZE: usize = 4;
const TCP_DNS_POOL_IDLE_TTL: Duration = Duration::from_secs(30);
const MAX_LOCAL_UDP_POOL_SIZE: usize = 4;
const LOCAL_UDP_POOL_IDLE_TTL: Duration = Duration::from_secs(30);
/// Stale replies discarded while waiting for the reply to the current query.
const MAX_LOCAL_UDP_STALE_REPLIES: usize = 8;
const DNS_XUDP_REPLY_QUEUE: usize = 8;
const MAX_DNS_NAME_LEN: usize = 255;
const MAX_DNS_LABELS: usize = 128;
const MAX_POINTER_HOPS: usize = 16;
const MAX_RR_COUNT: usize = 128;
/// Minimal RFC 6891 EDNS0 OPT pseudo-RR (root `.`, TYPE=41, UDP payload=1232,
/// extended RCODE/version/flags=0, RDLENGTH=0).
/// At most 3 upstream DNS failure warnings per 30 s window.
static DNS_UPSTREAM_LOG: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::new(3, Duration::from_secs(30)));
/// At most 2 concurrency-limit SERVFAIL warnings per 30 s window.
static DNS_BUSY_LOG: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::new(2, Duration::from_secs(30)));

const EDNS0_OPT_RR: [u8; 11] = [
    0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Upstream DNS transport used for tunneled queries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsUpstream {
    /// DNS-over-HTTPS (`POST /path`, `application/dns-message`) over `beam`.
    Doh {
        host: String,
        port: u16,
        path: String,
    },
    /// RFC 1035 DNS-over-TCP (2-byte length prefix) over `beam`.
    PlainTcp(SocketAddr),
    /// Plain DNS-over-UDP over `beam` XUDP.
    PlainUdp(SocketAddr),
}

impl DnsUpstream {
    /// Short transport name used in structured logs (`doh`, `tcp`, `udp`).
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Doh { .. } => "doh",
            Self::PlainTcp(_) => "tcp",
            Self::PlainUdp(_) => "udp",
        }
    }

    /// Parses a DNS upstream URI or address:
    /// - `https://host[:port]/path` -> [`DnsUpstream::Doh`]
    /// - `tcp://ip:port` -> [`DnsUpstream::PlainTcp`]
    /// - `udp://ip:port` or bare `ip:port` -> [`DnsUpstream::PlainUdp`]
    pub fn parse(raw: &str) -> Result<Self, String> {
        let s = raw.trim();
        if s.is_empty() {
            return Err("dns upstream must not be empty".into());
        }
        if s.bytes().any(|b| b.is_ascii_control() || b == b' ') {
            return Err("dns upstream must not contain whitespace or control chars".into());
        }
        if let Some(rest) = s.strip_prefix("https://") {
            let (authority, path) = match rest.find('/') {
                Some(idx) => (&rest[..idx], &rest[idx..]),
                None => (rest, "/dns-query"),
            };
            if authority.is_empty() || authority.contains('@') {
                return Err("invalid DoH authority".into());
            }
            let (host, port) = split_host_port(authority, 443)?;
            if host.is_empty() || host.len() > 255 {
                return Err("invalid DoH host".into());
            }
            if ServerName::try_from(host.to_owned()).is_err() {
                return Err(format!("invalid DoH TLS server name: {host}"));
            }
            if !path.starts_with('/') || path.len() > 512 {
                return Err("invalid DoH path".into());
            }
            return Ok(Self::Doh {
                host: host.to_owned(),
                port,
                path: path.to_owned(),
            });
        }
        if let Some(rest) = s.strip_prefix("tcp://") {
            let addr: SocketAddr = rest
                .parse()
                .map_err(|_| format!("invalid tcp:// DNS address: {rest}"))?;
            if addr.port() == 0 {
                return Err("tcp:// DNS port must be non-zero".into());
            }
            return Ok(Self::PlainTcp(addr));
        }
        if let Some(rest) = s.strip_prefix("udp://") {
            let addr: SocketAddr = rest
                .parse()
                .map_err(|_| format!("invalid udp:// DNS address: {rest}"))?;
            if addr.port() == 0 {
                return Err("udp:// DNS port must be non-zero".into());
            }
            return Ok(Self::PlainUdp(addr));
        }
        let addr: SocketAddr = s
            .parse()
            .map_err(|_| format!("invalid DNS upstream (use https://, tcp://, or ip:port): {s}"))?;
        if addr.port() == 0 {
            return Err("DNS upstream port must be non-zero".into());
        }
        Ok(Self::PlainUdp(addr))
    }
}

impl std::fmt::Display for DnsUpstream {
    /// Renders the upstream without the DoH path: profile IDs and tokens live in
    /// that path, and this string reaches startup logs and `--check` stdout.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Doh { host, port, .. } => write!(f, "https://{host}:{port}"),
            Self::PlainTcp(addr) => write!(f, "tcp://{addr}"),
            Self::PlainUdp(addr) => write!(f, "udp://{addr}"),
        }
    }
}

fn split_host_port(authority: &str, default_port: u16) -> Result<(&str, u16), String> {
    if let Some(bracketed) = authority.strip_prefix('[') {
        let end = bracketed
            .find(']')
            .ok_or_else(|| "unclosed IPv6 bracket in DoH authority".to_owned())?;
        let host = &bracketed[..end];
        if host.parse::<Ipv6Addr>().is_err() {
            return Err(format!("invalid IPv6 literal in DoH authority: [{host}]"));
        }
        let rest = &bracketed[end + 1..];
        if rest.is_empty() {
            return Ok((host, default_port));
        }
        let port_str = rest
            .strip_prefix(':')
            .ok_or_else(|| "expected :port after IPv6 literal".to_owned())?;
        let port: u16 = port_str
            .parse()
            .map_err(|_| "invalid DoH port".to_owned())?;
        if port == 0 {
            return Err("DoH port must be non-zero".into());
        }
        return Ok((host, port));
    }
    if let Some((host, port_str)) = authority.rsplit_once(':') {
        let port: u16 = port_str
            .parse()
            .map_err(|_| "invalid DoH port".to_owned())?;
        if port == 0 {
            return Err("DoH port must be non-zero".into());
        }
        return Ok((host, port));
    }
    Ok((authority, default_port))
}

/// Callback invoked when a `bypass_domains` query resolves to one or more IPs.
pub type BypassIpCallback = Arc<dyn Fn(&[IpAddr]) + Send + Sync>;

/// Optional callback invoked on network transitions to refresh the local DNS server.
pub type LocalDnsRefresh = Arc<dyn Fn() -> Option<SocketAddr> + Send + Sync>;

/// Configuration for the built-in [`DnsInterceptor`].
#[derive(Clone)]
pub struct DnsConfig {
    /// Upstream resolver reached through the `beam` tunnel.
    pub upstream: DnsUpstream,
    /// Optional local DNS server reached directly (outside the tunnel) for
    /// `local_suffixes` and `bypass_domains`.
    pub local_upstream: Option<SocketAddr>,
    /// Optional callback invoked on network transitions to re-detect the
    /// host's local DNS server when `local_upstream` was auto-detected.
    pub refresh_local_upstream: Option<LocalDnsRefresh>,
    /// Local-only suffixes (e.g. `["lan", "local", "internal"]`).
    pub local_suffixes: Vec<String>,
    /// Additional user-configured bypass domain suffixes.
    pub bypass_domains: Vec<String>,
    /// Maximum cached DNS responses (`0` disables caching).
    pub cache_size: usize,
    /// Per-query upstream timeout.
    pub query_timeout: Duration,
    /// When `true`, immediately answer tunneled `AAAA` (IPv6) queries with an
    /// empty `NOERROR` response so IPv4-only upstream servers never cause
    /// dual-stack clients to stall or close on unreachable IPv6 destinations.
    pub ipv4_only: bool,
    /// Optional extra trust anchors for DoH TLS verification (used in tests).
    pub custom_root_certs: Vec<CertificateDer<'static>>,
    /// Optional callback notified with resolved IPs for `bypass_domains`.
    pub on_bypass_ips: Option<BypassIpCallback>,
}

impl std::fmt::Debug for DnsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsConfig")
            .field("upstream", &self.upstream)
            .field("local_upstream", &self.local_upstream)
            .field("local_suffixes", &self.local_suffixes)
            .field("bypass_domains", &self.bypass_domains)
            .field("cache_size", &self.cache_size)
            .field("query_timeout", &self.query_timeout)
            .field("ipv4_only", &self.ipv4_only)
            .field("custom_root_certs_len", &self.custom_root_certs.len())
            .finish()
    }
}

impl DnsConfig {
    /// Returns the default local-only suffixes (`.lan`, `.local`, `.internal`).
    pub fn default_local_suffixes() -> Vec<String> {
        vec!["lan".to_owned(), "local".to_owned(), "internal".to_owned()]
    }

    /// Creates a new [`DnsConfig`] with sensible defaults.
    pub fn new(upstream: DnsUpstream, local_upstream: Option<SocketAddr>) -> Self {
        Self {
            upstream,
            local_upstream,
            refresh_local_upstream: None,
            local_suffixes: Self::default_local_suffixes(),
            bypass_domains: Vec::new(),
            cache_size: DEFAULT_CACHE_SIZE,
            query_timeout: DEFAULT_QUERY_TIMEOUT,
            ipv4_only: false,
            custom_root_certs: Vec::new(),
            on_bypass_ips: None,
        }
    }
}

/// Parsed DNS query header and first question.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsQuery {
    pub tx_id: u16,
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
    /// EDNS0 `DO` (DNSSEC OK) bit, part of the cache key because an upstream
    /// answer differs with and without DNSSEC records.
    pub dnssec_ok: bool,
}

/// Zero-panic RFC 1035 DNS query parser.
pub fn parse_dns_query(wire: &[u8]) -> Option<DnsQuery> {
    if wire.len() < 12 || wire.len() > MAX_DNS_QUERY_BYTES {
        return None;
    }
    let tx_id = u16::from_be_bytes([wire[0], wire[1]]);
    let flags = u16::from_be_bytes([wire[2], wire[3]]);
    // QR bit (0x8000) must be 0 for a query.
    if (flags & 0x8000) != 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([wire[4], wire[5]]);
    if qdcount != 1 {
        return None;
    }
    let (qname, next_offset) = parse_dns_name(wire, 12)?;
    if next_offset.checked_add(4)? > wire.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([wire[next_offset], wire[next_offset + 1]]);
    let qclass = u16::from_be_bytes([wire[next_offset + 2], wire[next_offset + 3]]);
    Some(DnsQuery {
        tx_id,
        qname,
        qtype,
        qclass,
        dnssec_ok: query_edns0(wire).is_some_and(|(_, dnssec_ok)| dnssec_ok),
    })
}

/// Returns `true` when the response has `QR=1`, `QDCOUNT=1`, and its question
/// matches the query.
///
/// An upstream resolver is untrusted: a reply with extra questions or for a
/// different name, type, or class is rejected before it is delivered or cached.
fn response_question_matches(query: &DnsQuery, resp: &[u8]) -> bool {
    if resp.len() < 12 || resp.len() > MAX_DOH_RESPONSE_BYTES {
        return false;
    }
    let flags = u16::from_be_bytes([resp[2], resp[3]]);
    if (flags & 0x8000) == 0 {
        return false;
    }
    if u16::from_be_bytes([resp[4], resp[5]]) != 1 {
        return false;
    }
    let Some((qname, next)) = parse_dns_name(resp, 12) else {
        return false;
    };
    let Some(after) = next.checked_add(4) else {
        return false;
    };
    if after > resp.len() {
        return false;
    }
    let qtype = u16::from_be_bytes([resp[next], resp[next + 1]]);
    let qclass = u16::from_be_bytes([resp[next + 2], resp[next + 3]]);
    qname.eq_ignore_ascii_case(&query.qname) && qtype == query.qtype && qclass == query.qclass
}

/// Parses a domain name at `start` (supporting RFC 1035 compression pointers
/// with strict hop and length limits). Returns `(lowercase_name, offset_after_name)`.
fn parse_dns_name(wire: &[u8], start: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut pos = start;
    let mut end_offset = None;
    let mut labels = 0usize;
    let mut hops = 0usize;

    loop {
        let b = *wire.get(pos)?;
        if b == 0 {
            let final_offset = end_offset.unwrap_or(pos + 1);
            return Some((name, final_offset));
        }
        if (b & 0xc0) == 0xc0 {
            hops += 1;
            if hops > MAX_POINTER_HOPS {
                return None;
            }
            let b2 = *wire.get(pos + 1)?;
            let ptr = usize::from(u16::from_be_bytes([b & 0x3f, b2]));
            if ptr >= wire.len() {
                return None;
            }
            if end_offset.is_none() {
                end_offset = Some(pos + 2);
            }
            pos = ptr;
            continue;
        }
        if (b & 0xc0) != 0 {
            // Reserved label type.
            return None;
        }
        let len = usize::from(b);
        if len > 63 {
            return None;
        }
        labels += 1;
        if labels > MAX_DNS_LABELS {
            return None;
        }
        let label_start = pos + 1;
        let label_end = label_start.checked_add(len)?;
        let label = wire.get(label_start..label_end)?;
        if !name.is_empty() {
            name.push('.');
        }
        if name.len().saturating_add(len) > MAX_DNS_NAME_LEN {
            return None;
        }
        for &ch in label {
            name.push((ch as char).to_ascii_lowercase());
        }
        pos = label_end;
    }
}

/// Extracts `(cache_ttl_secs, resolved_ips)` from an RFC 1035 DNS response.
/// Never panics on malformed input.
pub fn parse_dns_response_meta(wire: &[u8]) -> (Option<u32>, Vec<IpAddr>) {
    if wire.len() < 12 || wire.len() > MAX_DOH_RESPONSE_BYTES {
        return (None, Vec::new());
    }
    let flags = u16::from_be_bytes([wire[2], wire[3]]);
    if (flags & 0x8000) == 0 {
        return (None, Vec::new());
    }
    // Never cache truncated (`TC=1`) responses.
    let truncated = (flags & 0x0200) != 0;
    let rcode = flags & 0x000f;
    let qdcount = usize::from(u16::from_be_bytes([wire[4], wire[5]])).min(MAX_RR_COUNT);
    let ancount = usize::from(u16::from_be_bytes([wire[6], wire[7]])).min(MAX_RR_COUNT);

    let mut pos = 12usize;
    for _ in 0..qdcount {
        let Some((_, next)) = parse_dns_name(wire, pos) else {
            return (None, Vec::new());
        };
        let Some(after_q) = next.checked_add(4) else {
            return (None, Vec::new());
        };
        if after_q > wire.len() {
            return (None, Vec::new());
        }
        pos = after_q;
    }

    let mut min_ttl: Option<u32> = None;
    let mut ips = Vec::new();
    for _ in 0..ancount {
        let Some((_, next)) = parse_dns_name(wire, pos) else {
            return (None, Vec::new());
        };
        let Some(rd_header_end) = next.checked_add(10) else {
            return (None, Vec::new());
        };
        if rd_header_end > wire.len() {
            return (None, Vec::new());
        }
        let rtype = u16::from_be_bytes([wire[next], wire[next + 1]]);
        let rclass = u16::from_be_bytes([wire[next + 2], wire[next + 3]]);
        let ttl = u32::from_be_bytes([
            wire[next + 4],
            wire[next + 5],
            wire[next + 6],
            wire[next + 7],
        ]);
        let rdlength = usize::from(u16::from_be_bytes([wire[next + 8], wire[next + 9]]));
        let Some(rdata_end) = rd_header_end.checked_add(rdlength) else {
            return (None, Vec::new());
        };
        if rdata_end > wire.len() {
            return (None, Vec::new());
        }
        let rdata = &wire[rd_header_end..rdata_end];
        min_ttl = Some(min_ttl.map_or(ttl, |cur| cur.min(ttl)));
        if rcode == 0 && rclass == 1 {
            if rtype == 1 && rdata.len() == 4 {
                ips.push(IpAddr::V4(Ipv4Addr::new(
                    rdata[0], rdata[1], rdata[2], rdata[3],
                )));
            } else if rtype == 28 && rdata.len() == 16 {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(rdata);
                ips.push(IpAddr::V6(Ipv6Addr::from(octets)));
            }
        }
        pos = rdata_end;
    }

    if truncated {
        return (None, ips);
    }

    let ttl = match rcode {
        0 => match min_ttl {
            // RFC 1035 §3.2.1: a TTL of 0 tells the receiver not to cache.
            Some(0) => None,
            Some(t) => Some(t.clamp(MIN_CACHE_TTL_SECS, MAX_CACHE_TTL_SECS)),
            None => Some(NEGATIVE_CACHE_TTL_SECS), // Cache NOERROR NODATA briefly
        },
        3 => Some(NEGATIVE_CACHE_TTL_SECS), // NXDOMAIN
        _ => None,                          // Do not cache SERVFAIL/REFUSED
    };
    (ttl, ips)
}

/// Builds a minimal RFC 1035 `SERVFAIL` reply matching `query_wire`'s `tx_id`
/// and question section.
pub fn build_servfail_response(query_wire: &[u8]) -> Option<Vec<u8>> {
    if query_wire.len() < 12 || query_wire.len() > MAX_DNS_QUERY_BYTES {
        return None;
    }
    let (_, q_end) = parse_dns_name(query_wire, 12)?;
    let question_end = q_end.checked_add(4)?;
    if question_end > query_wire.len() {
        return None;
    }
    build_empty_dns_response(query_wire, question_end, 2)
}

/// Builds a minimal `NOERROR` (0 answers) response matching `query_wire`'s
/// `tx_id` and question (used to suppress `AAAA` records in `ipv4_only` mode).
pub fn build_empty_noerror_response(query_wire: &[u8]) -> Option<Vec<u8>> {
    if query_wire.len() < 12 {
        return None;
    }
    let (_, next_offset) = parse_dns_name(query_wire, 12)?;
    let question_end = next_offset.checked_add(4)?;
    if question_end > query_wire.len() {
        return None;
    }
    build_empty_dns_response(query_wire, question_end, 0)
}

/// Builds a minimal RFC 1035 `NOERROR` response with `TC=1` (truncated)
/// matching `query_wire`'s `tx_id`, question section, and optional EDNS0 OPT
/// record so local UDP stubs fall back cleanly to TCP.
pub fn build_truncated_response(query_wire: &[u8]) -> Option<Vec<u8>> {
    build_truncated_response_with_rcode(query_wire, 0)
}

fn build_truncated_response_with_rcode(query_wire: &[u8], rcode: u8) -> Option<Vec<u8>> {
    if query_wire.len() < 12 || query_wire.len() > MAX_DNS_QUERY_BYTES {
        return None;
    }
    let (_, q_end) = parse_dns_name(query_wire, 12)?;
    let question_end = q_end.checked_add(4)?;
    if question_end > query_wire.len() {
        return None;
    }
    build_synthetic_dns_response(query_wire, question_end, rcode, true)
}

/// Returns the client's advertised RFC 6891 EDNS0 UDP payload size (clamped to
/// at least 512 bytes per RFC 6891 §6.2.3) if `query_wire` carries an `OPT`
/// (type 41) pseudo-RR in its Additional section. Strictly bounded and never
/// panics.
fn query_edns0_udp_payload_size(query_wire: &[u8]) -> Option<usize> {
    query_edns0(query_wire).map(|(payload_size, _)| payload_size)
}

/// Returns `(advertised_udp_payload_size, dnssec_ok)` for the query's first
/// EDNS0 `OPT` (type 41) pseudo-RR. Strictly bounded and never panics.
fn query_edns0(query_wire: &[u8]) -> Option<(usize, bool)> {
    if query_wire.len() < 12 || query_wire.len() > MAX_DNS_QUERY_BYTES {
        return None;
    }
    let qdcount = usize::from(u16::from_be_bytes([query_wire[4], query_wire[5]])).min(MAX_RR_COUNT);
    let ancount = usize::from(u16::from_be_bytes([query_wire[6], query_wire[7]])).min(MAX_RR_COUNT);
    let nscount = usize::from(u16::from_be_bytes([query_wire[8], query_wire[9]])).min(MAX_RR_COUNT);
    let arcount =
        usize::from(u16::from_be_bytes([query_wire[10], query_wire[11]])).min(MAX_RR_COUNT);
    if arcount == 0 {
        return None;
    }

    let mut pos = 12usize;
    for _ in 0..qdcount {
        let (_, next) = parse_dns_name(query_wire, pos)?;
        let after_q = next.checked_add(4)?;
        if after_q > query_wire.len() {
            return None;
        }
        pos = after_q;
    }

    for _ in 0..ancount.saturating_add(nscount) {
        let (_, next) = parse_dns_name(query_wire, pos)?;
        let rd_header_end = next.checked_add(10)?;
        if rd_header_end > query_wire.len() {
            return None;
        }
        let rdlength = usize::from(u16::from_be_bytes([
            query_wire[next + 8],
            query_wire[next + 9],
        ]));
        let rdata_end = rd_header_end.checked_add(rdlength)?;
        if rdata_end > query_wire.len() {
            return None;
        }
        pos = rdata_end;
    }

    for _ in 0..arcount {
        let (_, next) = parse_dns_name(query_wire, pos)?;
        let rd_header_end = next.checked_add(10)?;
        if rd_header_end > query_wire.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([query_wire[next], query_wire[next + 1]]);
        if rtype == 41 {
            let advertised = usize::from(u16::from_be_bytes([
                query_wire[next + 2],
                query_wire[next + 3],
            ]));
            // RFC 3225: DO is the top bit of the OPT TTL flags word.
            let dnssec_ok = query_wire[next + 6] & 0x80 != 0;
            return Some((advertised.max(CLASSIC_UDP_DNS_RESPONSE_BYTES), dnssec_ok));
        }
        let rdlength = usize::from(u16::from_be_bytes([
            query_wire[next + 8],
            query_wire[next + 9],
        ]));
        let rdata_end = rd_header_end.checked_add(rdlength)?;
        if rdata_end > query_wire.len() {
            return None;
        }
        pos = rdata_end;
    }

    None
}

/// Returns `true` if `query_wire` carries an RFC 6891 EDNS0 `OPT` (type 41)
/// pseudo-RR in its Additional section.
fn query_has_edns0_opt(query_wire: &[u8]) -> bool {
    query_edns0_udp_payload_size(query_wire).is_some()
}

/// Computes the safe UDP DNS reply size limit for `query_wire`, respecting the
/// client's EDNS0 UDP payload size (or classic 512 bytes when EDNS0 is absent)
/// while never exceeding [`MAX_UDP_DNS_RESPONSE_BYTES`] for MTU safety.
fn udp_dns_response_limit(query_wire: &[u8]) -> usize {
    match query_edns0_udp_payload_size(query_wire) {
        Some(client_max) => client_max.min(MAX_UDP_DNS_RESPONSE_BYTES),
        None => CLASSIC_UDP_DNS_RESPONSE_BYTES,
    }
}

/// Returns `resp` unchanged if it fits within the client's safe UDP DNS reply
/// limit, or synthesizes a `TC=1` truncated DNS response so the stub retries
/// cleanly over TCP.
fn fit_response_for_udp(query_wire: &[u8], resp: Vec<u8>) -> Option<Vec<u8>> {
    if resp.len() <= udp_dns_response_limit(query_wire) {
        return Some(resp);
    }
    let rcode = resp.get(3).map_or(0, |b| b & 0x0f);
    build_truncated_response_with_rcode(query_wire, rcode)
}

fn build_empty_dns_response(query_wire: &[u8], question_end: usize, rcode: u8) -> Option<Vec<u8>> {
    build_synthetic_dns_response(query_wire, question_end, rcode, false)
}

fn build_synthetic_dns_response(
    query_wire: &[u8],
    question_end: usize,
    rcode: u8,
    truncated: bool,
) -> Option<Vec<u8>> {
    let has_opt = query_has_edns0_opt(query_wire);
    let mut resp = Vec::with_capacity(question_end + if has_opt { EDNS0_OPT_RR.len() } else { 0 });
    resp.extend_from_slice(&query_wire[..2]); // tx_id
    let rd = query_wire[2] & 0x01;
    let tc = if truncated { 0x02 } else { 0x00 };
    resp.push(0x80 | tc | rd); // QR=1, optional TC=1, RD preserved
    resp.push(0x80 | (rcode & 0x0f)); // RA=1, RCODE
    resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    resp.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT=0
    resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT=0
    resp.extend_from_slice(&(if has_opt { 1u16 } else { 0u16 }).to_be_bytes()); // ARCOUNT
    resp.extend_from_slice(&query_wire[12..question_end]);
    if has_opt {
        resp.extend_from_slice(&EDNS0_OPT_RR);
    }
    Some(resp)
}

/// Returns `true` if `qname` equals `suffix` or is a subdomain of `suffix`
/// (case-insensitive, leading/trailing dots normalized).
pub fn matches_domain_suffix(qname: &str, suffix: &str) -> bool {
    let q = qname.trim_matches('.').to_ascii_lowercase();
    let s = suffix.trim_matches('.').to_ascii_lowercase();
    if q.is_empty() || s.is_empty() {
        return false;
    }
    if q == s {
        return true;
    }
    q.len() > s.len() && q.ends_with(&s) && q.as_bytes()[q.len() - s.len() - 1] == b'.'
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct CacheKey {
    qname: String,
    qtype: u16,
    qclass: u16,
    dnssec_ok: bool,
}

struct CacheEntry {
    /// Shared wire response; the `tx_id` is patched at reply time so a cache
    /// hit never clones the whole DNS message (#168).
    wire: Arc<[u8]>,
    expires_at: Instant,
    last_used: u64,
    is_local: bool,
}

/// Bounded LRU + TTL DNS response cache.
pub struct DnsCache {
    max_entries: usize,
    seq: u64,
    entries: HashMap<CacheKey, CacheEntry>,
}

impl DnsCache {
    /// Creates a new bounded cache (`max_entries == 0` disables caching).
    pub fn new(max_entries: usize) -> Self {
        let cap = max_entries.min(MAX_CACHE_SIZE);
        Self {
            max_entries: cap,
            seq: 0,
            entries: HashMap::with_capacity(cap.min(256)),
        }
    }

    /// Looks up a cached response.
    ///
    /// The returned buffer still carries the original responder's `tx_id`; the
    /// caller patches bytes `0..2` when it builds the reply packet.
    pub fn get(&mut self, query: &DnsQuery, now: Instant) -> Option<Arc<[u8]>> {
        if self.max_entries == 0 {
            return None;
        }
        let key = CacheKey {
            qname: query.qname.clone(),
            qtype: query.qtype,
            qclass: query.qclass,
            dnssec_ok: query.dnssec_ok,
        };
        let expired = self
            .entries
            .get(&key)
            .is_some_and(|entry| now >= entry.expires_at);
        if expired {
            self.entries.remove(&key);
            return None;
        }
        let entry = self.entries.get_mut(&key)?;
        self.seq = self.seq.wrapping_add(1);
        entry.last_used = self.seq;
        Some(Arc::clone(&entry.wire))
    }

    /// Inserts a DNS response with `ttl_secs`, evicting expired or LRU entries
    /// if the cache is full.
    pub fn insert(
        &mut self,
        query: &DnsQuery,
        wire: Arc<[u8]>,
        ttl_secs: u32,
        is_local: bool,
        now: Instant,
    ) {
        if self.max_entries == 0 || wire.len() < 12 || wire.len() > MAX_DOH_RESPONSE_BYTES {
            return;
        }
        let key = CacheKey {
            qname: query.qname.clone(),
            qtype: query.qtype,
            qclass: query.qclass,
            dnssec_ok: query.dnssec_ok,
        };
        if !self.entries.contains_key(&key) && self.entries.len() >= self.max_entries {
            self.entries.retain(|_, v| now < v.expires_at);
            if self.entries.len() >= self.max_entries
                && let Some(oldest_key) = self
                    .entries
                    .iter()
                    .min_by_key(|(_, v)| v.last_used)
                    .map(|(k, _)| k.clone())
            {
                self.entries.remove(&oldest_key);
            }
        }
        self.seq = self.seq.wrapping_add(1);
        self.entries.insert(
            key,
            CacheEntry {
                wire,
                expires_at: now + Duration::from_secs(u64::from(ttl_secs)),
                last_used: self.seq,
                is_local,
            },
        );
    }

    /// Evicts local-network DNS entries (called on network/gateway switches).
    pub fn clear_local(&mut self) {
        self.entries.retain(|_, v| !v.is_local);
    }

    /// Clears all cached entries.
    pub fn clear_all(&mut self) {
        self.entries.clear();
    }
}

type DohTlsStream = tokio_rustls::client::TlsStream<BeamTcpStream>;

struct PooledDohConn<S> {
    stream: S,
    last_used: Instant,
}

/// Passive, bounded HTTP/1.1 keep-alive pool for DoH connections.
///
/// Uses zero background timers or reaper tasks so idle battery consumption is
/// strictly zero; stale entries are discarded passively on borrow or cleared
/// immediately on network transitions. A monotonic generation counter prevents
/// connections dialed before a network transition from being returned to the
/// pool after `clear()`.
struct DohPool<S = DohTlsStream> {
    idle: Vec<PooledDohConn<S>>,
    generation: u64,
}

impl<S> Default for DohPool<S> {
    fn default() -> Self {
        Self {
            idle: Vec::new(),
            generation: 0,
        }
    }
}

impl<S> DohPool<S> {
    fn generation(&self) -> u64 {
        self.generation
    }

    fn take(&mut self, now: Instant) -> (Option<S>, u64) {
        let generation = self.generation;
        while let Some(entry) = self.idle.pop() {
            if now.saturating_duration_since(entry.last_used) < DOH_POOL_IDLE_TTL {
                return (Some(entry.stream), generation);
            }
        }
        (None, generation)
    }

    fn put(&mut self, stream: S, expected_generation: u64, now: Instant) {
        if self.generation != expected_generation {
            return;
        }
        self.idle
            .retain(|entry| now.saturating_duration_since(entry.last_used) < DOH_POOL_IDLE_TTL);
        if self.idle.len() < MAX_DOH_POOL_SIZE {
            self.idle.push(PooledDohConn {
                stream,
                last_used: now,
            });
        }
    }

    fn clear(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.idle.clear();
    }
}

struct PooledTcpDnsConn<S> {
    stream: S,
    last_used: Instant,
}

/// Passive, bounded keep-alive pool for RFC 1035 DNS-over-TCP connections.
///
/// Mirrors [`DohPool`]: zero background timers; expired entries are discarded
/// passively on borrow/return or cleared immediately on network transitions.
struct TcpDnsPool<S = BeamTcpStream> {
    idle: Vec<PooledTcpDnsConn<S>>,
    generation: u64,
}

impl<S> Default for TcpDnsPool<S> {
    fn default() -> Self {
        Self {
            idle: Vec::new(),
            generation: 0,
        }
    }
}

impl<S> TcpDnsPool<S> {
    fn generation(&self) -> u64 {
        self.generation
    }

    fn take(&mut self, now: Instant) -> (Option<S>, u64) {
        let generation = self.generation;
        while let Some(entry) = self.idle.pop() {
            if now.saturating_duration_since(entry.last_used) < TCP_DNS_POOL_IDLE_TTL {
                return (Some(entry.stream), generation);
            }
        }
        (None, generation)
    }

    fn put(&mut self, stream: S, expected_gen: u64, now: Instant) {
        if self.generation != expected_gen {
            return;
        }
        self.idle
            .retain(|entry| now.saturating_duration_since(entry.last_used) < TCP_DNS_POOL_IDLE_TTL);
        if self.idle.len() < MAX_TCP_DNS_POOL_SIZE {
            self.idle.push(PooledTcpDnsConn {
                stream,
                last_used: now,
            });
        }
    }

    fn clear(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.idle.clear();
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.idle.len()
    }
}

trait MuxHealth {
    fn is_open(&self) -> bool;
}

impl MuxHealth for XudpClient {
    fn is_open(&self) -> bool {
        XudpClient::is_open(self)
    }
}

struct PooledLocalUdp {
    sock: UdpSocket,
    key: SocketAddr,
    last_used: Instant,
}

#[derive(Default)]
struct LocalUdpPoolState {
    idle: Vec<PooledLocalUdp>,
    generation: u64,
}

/// Passive, bounded pool of connected local DNS `UdpSocket`s keyed by
/// `local_upstream`.
///
/// Reusing the connected socket removes a `bind`/`connect` pair (and its port
/// churn) from every `.lan` query. There are zero background timers: stale
/// entries are dropped passively on borrow, and a generation counter bumped by
/// [`Self::clear`] on network transitions rejects sockets dialed before the
/// change. A socket is only returned to the pool after a fully successful
/// exchange, so a late reply can never poison a pooled socket.
#[derive(Default)]
struct LocalUdpPool {
    state: Mutex<LocalUdpPoolState>,
}

impl LocalUdpPool {
    fn take(&self, key: SocketAddr, now: Instant) -> (Option<UdpSocket>, u64) {
        let Ok(mut state) = self.state.lock() else {
            return (None, 0);
        };
        let generation = state.generation;
        state.idle.retain(|entry| {
            now.saturating_duration_since(entry.last_used) < LOCAL_UDP_POOL_IDLE_TTL
        });
        let found = state
            .idle
            .iter()
            .position(|entry| entry.key == key)
            .map(|idx| state.idle.swap_remove(idx));
        (found.map(|entry| entry.sock), generation)
    }

    fn put(&self, sock: UdpSocket, key: SocketAddr, expected_generation: u64, now: Instant) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if state.generation != expected_generation {
            return;
        }
        state.idle.retain(|entry| {
            now.saturating_duration_since(entry.last_used) < LOCAL_UDP_POOL_IDLE_TTL
        });
        if state.idle.len() < MAX_LOCAL_UDP_POOL_SIZE {
            state.idle.push(PooledLocalUdp {
                sock,
                key,
                last_used: now,
            });
        }
    }

    fn clear(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.generation = state.generation.wrapping_add(1);
            state.idle.clear();
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.state.lock().map(|s| s.idle.len()).unwrap_or(0)
    }
}

struct UdpDnsMuxSlot<C> {
    mux: Option<Arc<C>>,
    generation: u64,
}

/// Lazily-connected shared XUDP mux pool for `PlainUdp` DNS queries.
///
/// Concurrent queries reuse one open [`XudpClient`] mux; reconnects are
/// serialized so a burst on a cold or stale mux performs at most one dial.
/// [`Self::clear`] immediately drops any cached mux and bumps the generation
/// so an in-flight dial from before a network transition is not cached.
struct UdpDnsMuxPool<C = XudpClient> {
    slot: Mutex<UdpDnsMuxSlot<C>>,
    connect_lock: tokio::sync::Mutex<()>,
}

impl<C: MuxHealth> UdpDnsMuxPool<C> {
    fn new() -> Self {
        Self {
            slot: Mutex::new(UdpDnsMuxSlot {
                mux: None,
                generation: 0,
            }),
            connect_lock: tokio::sync::Mutex::new(()),
        }
    }

    async fn get_or_connect<F, Fut>(&self, connect: F) -> io::Result<(Arc<C>, bool)>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = io::Result<C>>,
    {
        if let Ok(guard) = self.slot.lock()
            && let Some(existing) = guard.mux.as_ref()
            && existing.is_open()
        {
            return Ok((Arc::clone(existing), true));
        }

        let _connect_guard = self.connect_lock.lock().await;
        let generation = {
            let Ok(mut guard) = self.slot.lock() else {
                return Err(io::Error::other("DNS XUDP mux slot poisoned"));
            };
            if let Some(existing) = guard.mux.as_ref() {
                if existing.is_open() {
                    return Ok((Arc::clone(existing), true));
                }
                guard.mux = None;
            }
            guard.generation
        };

        let fresh = Arc::new(connect().await?);
        if let Ok(mut guard) = self.slot.lock()
            && guard.generation == generation
        {
            guard.mux = Some(Arc::clone(&fresh));
        }
        Ok((fresh, false))
    }

    fn invalidate(&self, stale: &Arc<C>) {
        if let Ok(mut guard) = self.slot.lock()
            && guard
                .mux
                .as_ref()
                .is_some_and(|cur| Arc::ptr_eq(cur, stale))
        {
            guard.mux = None;
        }
    }

    fn clear(&self) {
        if let Ok(mut guard) = self.slot.lock() {
            guard.generation = guard.generation.wrapping_add(1);
            guard.mux = None;
        }
    }
}

fn dns_xudp_config() -> XudpClientConfig {
    XudpClientConfig {
        max_sessions: MAX_INFLIGHT_DNS_QUERIES,
        outbound_queue: MAX_INFLIGHT_DNS_QUERIES * 2,
        reply_queue: DNS_XUDP_REPLY_QUEUE,
    }
}

/// Non-blocking DNS interceptor embedded in `beam-tun`'s engine loop.
pub struct DnsInterceptor {
    client_config: BeamClientConfig,
    dns_config: DnsConfig,
    local_upstream: Arc<Mutex<Option<SocketAddr>>>,
    tls_config: Arc<ClientConfig>,
    doh_pool: Arc<Mutex<DohPool>>,
    tcp_pool: Arc<Mutex<TcpDnsPool>>,
    udp_mux_pool: Arc<UdpDnsMuxPool>,
    cache: Arc<Mutex<DnsCache>>,
    inflight: Arc<Semaphore>,
    tun_tx: mpsc::Sender<Vec<u8>>,
    local_udp_pool: Arc<LocalUdpPool>,
    counters: Arc<DnsCounters>,
}

impl DnsInterceptor {
    /// Creates a new [`DnsInterceptor`] writing synthesized UDP/53 replies into `tun_tx`.
    pub fn new(
        client_config: BeamClientConfig,
        dns_config: DnsConfig,
        tun_tx: mpsc::Sender<Vec<u8>>,
    ) -> Self {
        let interceptor = Self::with_pool(client_config, dns_config, tun_tx);
        info!(
            upstream = %interceptor.dns_config.upstream,
            upstream_kind = interceptor.dns_config.upstream.kind(),
            local_upstream = ?interceptor.dns_config.local_upstream,
            cache_size = interceptor.dns_config.cache_size,
            ipv4_only = interceptor.dns_config.ipv4_only,
            local_suffixes = interceptor.dns_config.local_suffixes.len(),
            bypass_domains = interceptor.dns_config.bypass_domains.len(),
            "DNS interceptor configured"
        );
        interceptor
    }

    fn with_pool(
        client_config: BeamClientConfig,
        dns_config: DnsConfig,
        tun_tx: mpsc::Sender<Vec<u8>>,
    ) -> Self {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        for cert in &dns_config.custom_root_certs {
            let _ = roots.add(cert.clone());
        }
        let tls_config = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let cache = Arc::new(Mutex::new(DnsCache::new(dns_config.cache_size)));
        let local_upstream = Arc::new(Mutex::new(dns_config.local_upstream));
        Self {
            client_config,
            dns_config,
            local_upstream,
            tls_config,
            doh_pool: Arc::new(Mutex::new(DohPool::default())),
            tcp_pool: Arc::new(Mutex::new(TcpDnsPool::default())),
            udp_mux_pool: Arc::new(UdpDnsMuxPool::new()),
            cache,
            inflight: Arc::new(Semaphore::new(MAX_INFLIGHT_DNS_QUERIES)),
            tun_tx,
            local_udp_pool: Arc::new(LocalUdpPool::default()),
            counters: Arc::new(DnsCounters::default()),
        }
    }

    /// Returns a snapshot of the DNS outcome counters for diagnostics.
    pub fn stats(&self) -> DnsSnapshot {
        self.counters.snapshot()
    }

    /// Clears local-only cache entries, drops pooled DoH/TCP/UDP connections,
    /// and refreshes auto-detected local DNS upstream on network transitions.
    pub fn on_network_change(&self) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.clear_local();
        }
        if let Ok(mut pool) = self.doh_pool.lock() {
            pool.clear();
        }
        if let Ok(mut pool) = self.tcp_pool.lock() {
            pool.clear();
        }
        self.local_udp_pool.clear();
        self.udp_mux_pool.clear();
        if let Some(refresher) = self.dns_config.refresh_local_upstream.as_ref() {
            let refreshed = refresher();
            if let Ok(mut guard) = self.local_upstream.lock() {
                *guard = refreshed;
            }
        }
    }

    /// Handles one intercepted UDP/53 query packet without blocking the TUN loop.
    pub fn handle_query(&self, src: SocketAddr, dst: SocketAddr, wire: &[u8]) {
        let Some(query) = parse_dns_query(wire) else {
            return;
        };

        let current_local = self.local_upstream.lock().ok().and_then(|g| *g);
        let is_local = self
            .dns_config
            .local_suffixes
            .iter()
            .any(|s| matches_domain_suffix(&query.qname, s));
        let is_bypass_domain = self
            .dns_config
            .bypass_domains
            .iter()
            .any(|s| matches_domain_suffix(&query.qname, s));
        let use_local = (is_local || is_bypass_domain) && current_local.is_some();

        // Loop guard: if a local/bypass query destined for `local_upstream`
        // itself re-entered the TUN (e.g. bypass route vanished mid-transition),
        // refuse to recurse into `resolve_local_udp` so we can never self-DoS.
        if use_local && current_local.is_some_and(|local| local.ip() == dst.ip()) {
            self.counters.loop_guard.incr();
            if let Some(suppressed) = DNS_UPSTREAM_LOG.allow() {
                warn!(
                    qtype = query.qtype,
                    local = true,
                    stage = "loop_guard",
                    suppressed,
                    "local DNS query re-entered the tunnel; replying with SERVFAIL"
                );
            }
            if let Some(sf) = build_servfail_response(wire) {
                send_udp_reply(&self.tun_tx, &self.counters, src, dst, &sf, None);
            }
            return;
        }

        // In `ipv4_only` mode, immediately answer tunneled `AAAA` (type 28)
        // queries with an empty `NOERROR` response so IPv4-only upstream
        // servers never cause dual-stack apps to stall or fail on IPv6.
        if self.dns_config.ipv4_only && !use_local && query.qtype == 28 {
            if let Some(empty) = build_empty_noerror_response(wire) {
                send_udp_reply(&self.tun_tx, &self.counters, src, dst, &empty, None);
            }
            return;
        }

        // Fast path: synchronous cache hit (0 ms latency). The hit shares the
        // cached wire buffer and patches only the 2-byte `tx_id` (#168).
        let cached = self
            .cache
            .lock()
            .ok()
            .and_then(|mut cache| cache.get(&query, Instant::now()));
        if let Some(cached) = cached {
            self.counters.hits.incr();
            if cached.len() <= udp_dns_response_limit(wire) {
                send_udp_reply(
                    &self.tun_tx,
                    &self.counters,
                    src,
                    dst,
                    &cached,
                    Some(query.tx_id),
                );
            } else if let Some(reply) =
                fit_response_for_udp(wire, patch_tx_id(&cached, query.tx_id))
            {
                send_udp_reply(&self.tun_tx, &self.counters, src, dst, &reply, None);
            }
            return;
        }

        let Ok(permit) = Arc::clone(&self.inflight).try_acquire_owned() else {
            self.counters.servfail_concurrency.incr();
            debug!(qname = %query.qname, "DNS concurrency limit reached; replying with SERVFAIL");
            if let Some(suppressed) = DNS_BUSY_LOG.allow() {
                warn!(
                    qtype = query.qtype,
                    local = use_local,
                    inflight_limit = MAX_INFLIGHT_DNS_QUERIES,
                    stage = "concurrency_limit",
                    suppressed,
                    "DNS concurrency limit reached; replying with SERVFAIL"
                );
            }
            if let Some(sf) = build_servfail_response(wire) {
                send_udp_reply(&self.tun_tx, &self.counters, src, dst, &sf, None);
            }
            return;
        };
        self.counters.misses.incr();

        let wire_owned = wire.to_vec();
        let client_cfg = self.client_config.clone();
        let dns_cfg = self.dns_config.clone();
        let tls_cfg = Arc::clone(&self.tls_config);
        let doh_pool = Arc::clone(&self.doh_pool);
        let tcp_pool = Arc::clone(&self.tcp_pool);
        let udp_mux_pool = Arc::clone(&self.udp_mux_pool);
        let local_udp_pool = Arc::clone(&self.local_udp_pool);
        let cache = Arc::clone(&self.cache);
        let counters = Arc::clone(&self.counters);
        let tun_tx = self.tun_tx.clone();
        let upstream_kind = if use_local {
            "local_udp"
        } else {
            dns_cfg.upstream.kind()
        };

        tokio::spawn(async move {
            let _permit = permit;
            let result = if use_local {
                match current_local {
                    Some(local_addr) => {
                        resolve_local_udp(
                            &local_udp_pool,
                            local_addr,
                            &wire_owned,
                            query.tx_id,
                            dns_cfg.query_timeout,
                        )
                        .await
                    }
                    None => Err(io::Error::other("no local DNS upstream configured")),
                }
            } else {
                resolve_tunneled(
                    &client_cfg,
                    &dns_cfg.upstream,
                    &tls_cfg,
                    &doh_pool,
                    &tcp_pool,
                    &udp_mux_pool,
                    &wire_owned,
                    dns_cfg.query_timeout,
                )
                .await
            };

            let reply_wire = match result {
                Ok(mut resp) if resp.len() >= 12 && resp.len() <= MAX_DOH_RESPONSE_BYTES => {
                    if !response_question_matches(&query, &resp) {
                        counters.servfail_mismatch.incr();
                        debug!(
                            qname = %query.qname,
                            local = use_local,
                            "DNS response question does not match the query; replying with SERVFAIL"
                        );
                        if let Some(suppressed) = DNS_UPSTREAM_LOG.allow() {
                            warn!(
                                qtype = query.qtype,
                                upstream_kind,
                                local = use_local,
                                stage = "question_mismatch",
                                suppressed,
                                "DNS response rejected; replying with SERVFAIL"
                            );
                        }
                        build_servfail_response(&wire_owned)
                    } else {
                        // Rewrite tx_id to match the client query. DoH uses tx_id 0
                        // per RFC 8484 and TCP/XUDP are 1-to-1 exchanges, so question
                        // matching above is what prevents cross-query injection.
                        let id = query.tx_id.to_be_bytes();
                        resp[0] = id[0];
                        resp[1] = id[1];
                        let (maybe_ttl, ips) = parse_dns_response_meta(&resp);
                        if is_bypass_domain
                            && !ips.is_empty()
                            && let Some(cb) = dns_cfg.on_bypass_ips.as_ref()
                        {
                            cb(&ips);
                        }
                        if let Some(ttl) = maybe_ttl
                            && let Ok(mut guard) = cache.lock()
                        {
                            guard.insert(
                                &query,
                                Arc::from(resp.as_slice()),
                                ttl,
                                use_local,
                                Instant::now(),
                            );
                        }
                        fit_response_for_udp(&wire_owned, resp)
                    }
                }
                Ok(_) => {
                    counters.servfail_upstream.incr();
                    build_servfail_response(&wire_owned)
                }
                Err(err) => {
                    counters.servfail_upstream.incr();
                    let stage = if err.kind() == io::ErrorKind::TimedOut {
                        counters.timeout.incr();
                        "timeout"
                    } else if use_local {
                        "local_upstream"
                    } else {
                        upstream_kind
                    };
                    debug!(
                        qname = %query.qname,
                        local = use_local,
                        stage,
                        error = %err,
                        kind = ?err.kind(),
                        "DNS resolution failed"
                    );
                    if let Some(suppressed) = DNS_UPSTREAM_LOG.allow() {
                        warn!(
                            qtype = query.qtype,
                            upstream_kind,
                            local = use_local,
                            stage,
                            error = %err,
                            kind = ?err.kind(),
                            suppressed,
                            "DNS resolution failed; replying with SERVFAIL"
                        );
                    }
                    build_servfail_response(&wire_owned)
                }
            };

            if let Some(resp) = reply_wire {
                send_udp_reply(&tun_tx, &counters, src, dst, &resp, None);
            }
        });
    }
}

/// Copies `wire` and overwrites its 2-byte `tx_id`.
fn patch_tx_id(wire: &[u8], tx_id: u16) -> Vec<u8> {
    let mut out = wire.to_vec();
    if out.len() >= 2 {
        out[0..2].copy_from_slice(&tx_id.to_be_bytes());
    }
    out
}

/// Builds and queues one synthesized UDP/53 reply, counting `tun_tx` drops.
///
/// `tx_id` rewrites the first two payload bytes while the packet is assembled,
/// so a cache hit never clones its shared wire buffer.
fn send_udp_reply(
    tun_tx: &mpsc::Sender<Vec<u8>>,
    counters: &DnsCounters,
    src: SocketAddr,
    dst: SocketAddr,
    payload: &[u8],
    tx_id: Option<u16>,
) {
    let patch = tx_id.map(|id| (0usize, id.to_be_bytes()));
    let pkt =
        build_ip_udp_packet_patched(dst.ip(), dst.port(), src.ip(), src.port(), payload, patch);
    match pkt {
        Some(pkt) => {
            if tun_tx.try_send(pkt).is_err() {
                counters.tun_tx_dropped.incr();
            }
        }
        // A payload the packet builder cannot frame is dropped like a full
        // channel so the loss shows up in diagnostics instead of silently.
        None => counters.tun_tx_dropped.incr(),
    }
}

async fn resolve_local_udp(
    pool: &LocalUdpPool,
    local_upstream: SocketAddr,
    query: &[u8],
    expected_tx_id: u16,
    query_timeout: Duration,
) -> io::Result<Vec<u8>> {
    let (pooled, generation) = pool.take(local_upstream, Instant::now());
    let sock = match pooled {
        Some(sock) => sock,
        None => {
            let bind_addr: SocketAddr = match local_upstream {
                SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
            };
            let sock = UdpSocket::bind(bind_addr).await?;
            sock.connect(local_upstream).await?;
            sock
        }
    };

    // Any timeout, I/O error, or `tx_id` mismatch drops the socket instead of
    // returning it, so a late reply can never be delivered to a later query.
    match exchange_local_udp(&sock, query, expected_tx_id, query_timeout).await {
        Ok((reply, clean)) => {
            if clean {
                pool.put(sock, local_upstream, generation, Instant::now());
            }
            Ok(reply)
        }
        Err(err) => Err(err),
    }
}

/// Exchanges one query on `sock`, dropping stale replies that belong to an
/// earlier query served by the same pooled socket.
///
/// Returns the reply and whether the exchange was clean (no stale reply and no
/// discarded datagram), so only a clean socket goes back to the pool.
async fn exchange_local_udp(
    sock: &UdpSocket,
    query: &[u8],
    expected_tx_id: u16,
    query_timeout: Duration,
) -> io::Result<(Vec<u8>, bool)> {
    let deadline = TokioInstant::now() + query_timeout;
    timeout_at(deadline, sock.send(query))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "local DNS send timed out"))??;
    let mut buf = vec![0u8; MAX_LOCAL_UDP_RECV_BYTES];
    let mut clean = true;
    for _ in 0..=MAX_LOCAL_UDP_STALE_REPLIES {
        let n = timeout_at(deadline, sock.recv(&mut buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "local DNS recv timed out"))??;
        if n < 12 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "local DNS reply too short",
            ));
        }
        if u16::from_be_bytes([buf[0], buf[1]]) == expected_tx_id {
            buf.truncate(n);
            return Ok((buf, clean));
        }
        clean = false;
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "local DNS reply tx_id mismatch",
    ))
}

#[allow(clippy::too_many_arguments)]
async fn resolve_tunneled(
    client_cfg: &BeamClientConfig,
    upstream: &DnsUpstream,
    tls_cfg: &Arc<ClientConfig>,
    doh_pool: &Arc<Mutex<DohPool>>,
    tcp_pool: &Arc<Mutex<TcpDnsPool>>,
    udp_mux_pool: &Arc<UdpDnsMuxPool>,
    query: &[u8],
    query_timeout: Duration,
) -> io::Result<Vec<u8>> {
    timeout(query_timeout, async {
        match upstream {
            DnsUpstream::Doh { host, port, path } => {
                resolve_doh_over_beam(client_cfg, tls_cfg, doh_pool, host, *port, path, query).await
            }
            DnsUpstream::PlainTcp(addr) => {
                resolve_tcp_over_beam(client_cfg, tcp_pool, *addr, query).await
            }
            DnsUpstream::PlainUdp(addr) => {
                resolve_udp_over_beam(client_cfg, udp_mux_pool, *addr, query).await
            }
        }
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tunneled DNS query timed out"))?
}

async fn send_tcp_dns_request<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    query: &[u8],
) -> io::Result<Vec<u8>> {
    let len_u16 = u16::try_from(query.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "DNS query too large"))?;
    stream.write_all(&len_u16.to_be_bytes()).await?;
    stream.write_all(query).await?;
    stream.flush().await?;

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let resp_len = usize::from(u16::from_be_bytes(len_buf));
    if !(12..=MAX_DOH_RESPONSE_BYTES).contains(&resp_len) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid DNS-over-TCP response length",
        ));
    }
    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp).await?;
    Ok(resp)
}

async fn resolve_tcp_over_beam(
    client_cfg: &BeamClientConfig,
    tcp_pool: &Arc<Mutex<TcpDnsPool>>,
    addr: SocketAddr,
    query: &[u8],
) -> io::Result<Vec<u8>> {
    // Fast path: reuse an idle DNS-over-TCP connection (1 RTT).
    let (pooled, pool_gen) = tcp_pool
        .lock()
        .ok()
        .map(|mut pool| pool.take(Instant::now()))
        .unwrap_or((None, 0));
    if let Some(mut stream) = pooled {
        match send_tcp_dns_request(&mut stream, query).await {
            Ok(resp) => {
                if let Ok(mut pool) = tcp_pool.lock() {
                    pool.put(stream, pool_gen, Instant::now());
                }
                return Ok(resp);
            }
            Err(err) => {
                debug!(error = %err, "pooled TCP DNS connection stale; retrying with fresh dial");
            }
        }
    }

    let dest = NetLocation {
        address: match addr.ip() {
            IpAddr::V4(ip) => Address::Ipv4(ip),
            IpAddr::V6(ip) => Address::Ipv6(ip),
        },
        port: addr.port(),
    };
    // Sample the current pool generation right before dialing a fresh
    // connection (after any stale-pooled attempt above), so a post-reset dial
    // is pooled under the current generation while a transition during dial
    // still drops it.
    let pool_gen = tcp_pool.lock().ok().map(|pool| pool.generation());
    let mut stream = dial_tcp(client_cfg, dest)
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;
    let resp = send_tcp_dns_request(&mut stream, query).await?;
    if let (Some(gen_id), Ok(mut pool)) = (pool_gen, tcp_pool.lock()) {
        pool.put(stream, gen_id, Instant::now());
    }
    Ok(resp)
}

async fn run_udp_dns_query(
    mux: &XudpClient,
    dest: NetLocation,
    query: &[u8],
) -> io::Result<Vec<u8>> {
    let mut session = mux
        .open_session(dest.clone())
        .map_err(|e| io::Error::other(e.to_string()))?;
    if let Err(err) = session.send_to(dest, query).await {
        let _ = session.close().await;
        return Err(io::Error::other(err.to_string()));
    }
    let reply = match session.recv().await {
        Some(reply) => reply,
        None => {
            let _ = session.close().await;
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "XUDP closed before DNS reply",
            ));
        }
    };
    let _ = session.close().await;
    Ok(reply.payload)
}

async fn resolve_udp_over_beam(
    client_cfg: &BeamClientConfig,
    udp_mux_pool: &Arc<UdpDnsMuxPool>,
    addr: SocketAddr,
    query: &[u8],
) -> io::Result<Vec<u8>> {
    let dest = NetLocation {
        address: match addr.ip() {
            IpAddr::V4(ip) => Address::Ipv4(ip),
            IpAddr::V6(ip) => Address::Ipv6(ip),
        },
        port: addr.port(),
    };

    let (mux, reused) = udp_mux_pool
        .get_or_connect(|| async {
            XudpClient::connect(client_cfg, dns_xudp_config())
                .await
                .map_err(|e| io::Error::other(e.to_string()))
        })
        .await?;

    match run_udp_dns_query(&mux, dest.clone(), query).await {
        Ok(payload) => Ok(payload),
        Err(err) if reused && !mux.is_open() => {
            debug!(error = %err, "shared DNS XUDP mux closed; retrying with fresh mux");
            udp_mux_pool.invalidate(&mux);
            let (fresh_mux, _) = udp_mux_pool
                .get_or_connect(|| async {
                    XudpClient::connect(client_cfg, dns_xudp_config())
                        .await
                        .map_err(|e| io::Error::other(e.to_string()))
                })
                .await?;
            match run_udp_dns_query(&fresh_mux, dest, query).await {
                Ok(payload) => Ok(payload),
                Err(retry_err) => {
                    if !fresh_mux.is_open() {
                        udp_mux_pool.invalidate(&fresh_mux);
                    }
                    Err(retry_err)
                }
            }
        }
        Err(err) => {
            if !mux.is_open() {
                udp_mux_pool.invalidate(&mux);
            }
            Err(err)
        }
    }
}

async fn send_doh_http_request<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    host_header: &str,
    path: &str,
    query: &[u8],
) -> io::Result<(Vec<u8>, bool)> {
    let req = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host_header}\r\n\
         Content-Type: application/dns-message\r\n\
         Accept: application/dns-message\r\n\
         Content-Length: {}\r\n\
         Connection: keep-alive\r\n\r\n",
        query.len()
    );
    stream.write_all(req.as_bytes()).await?;
    stream.write_all(query).await?;
    stream.flush().await?;
    read_doh_http_response_keepalive(stream).await
}

async fn resolve_doh_over_beam(
    client_cfg: &BeamClientConfig,
    tls_cfg: &Arc<ClientConfig>,
    doh_pool: &Arc<Mutex<DohPool>>,
    host: &str,
    port: u16,
    path: &str,
    query: &[u8],
) -> io::Result<Vec<u8>> {
    let host_header = format_http_host_header(host, port);

    // Fast path: reuse an idle HTTP/1.1 keep-alive DoH connection (1 RTT).
    let (pooled, pooled_gen) = doh_pool
        .lock()
        .ok()
        .map(|mut pool| pool.take(Instant::now()))
        .unwrap_or((None, 0));
    if let Some(mut tls) = pooled {
        match send_doh_http_request(&mut tls, &host_header, path, query).await {
            Ok((body, reusable)) => {
                if reusable && let Ok(mut pool) = doh_pool.lock() {
                    pool.put(tls, pooled_gen, Instant::now());
                }
                return Ok(body);
            }
            Err(err) => {
                debug!(error = %err, "pooled DoH connection stale; retrying with fresh dial");
            }
        }
    }

    let dial_gen = doh_pool.lock().ok().map(|pool| pool.generation());
    let address = if let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => Address::Ipv4(v4),
            IpAddr::V6(v6) => Address::Ipv6(v6),
        }
    } else {
        Address::Domain(host.to_owned())
    };
    let dest = NetLocation { address, port };
    let beam_stream = dial_tcp(client_cfg, dest)
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;

    let server_name = ServerName::try_from(host.to_owned())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid DoH TLS server name"))?;
    let connector = TlsConnector::from(Arc::clone(tls_cfg));
    let mut tls = connector.connect(server_name, beam_stream).await?;

    let (body, reusable) = send_doh_http_request(&mut tls, &host_header, path, query).await?;
    if reusable && let (Some(gen_id), Ok(mut pool)) = (dial_gen, doh_pool.lock()) {
        pool.put(tls, gen_id, Instant::now());
    }
    Ok(body)
}

/// Formats an RFC 9110 §7.2 `Host` header value, bracketing IPv6 literals.
pub fn format_http_host_header(host: &str, port: u16) -> String {
    let needs_brackets = host.contains(':') && !host.starts_with('[');
    match (needs_brackets, port == 443) {
        (true, true) => format!("[{host}]"),
        (true, false) => format!("[{host}]:{port}"),
        (false, true) => host.to_owned(),
        (false, false) => format!("{host}:{port}"),
    }
}

/// Parses an HTTP/1.1 DoH response from `stream` (supporting incremental
/// `Transfer-Encoding: chunked`, strict `Content-Length`, or bounded EOF).
pub async fn read_doh_http_response<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
) -> io::Result<Vec<u8>> {
    read_doh_http_response_keepalive(stream)
        .await
        .map(|(body, _)| body)
}

async fn read_doh_http_response_keepalive<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
) -> io::Result<(Vec<u8>, bool)> {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];
    let header_end = loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF before DoH HTTP response headers",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(idx) = find_crlf_crlf(&buf) {
            break idx;
        }
        if buf.len() > MAX_HTTP_HEADER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DoH HTTP headers exceeded bound",
            ));
        }
    };

    let header_str = std::str::from_utf8(&buf[..header_end])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF8 DoH HTTP headers"))?;
    let mut lines = header_str.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let is_http_11 = status_line.starts_with("HTTP/1.1");
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    if status_code != 200 {
        return Err(io::Error::other(format!(
            "DoH HTTP status {status_code} != 200"
        )));
    }

    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    let mut conn_close = !is_http_11;
    let mut content_type_valid = false;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim();
            let val = v.trim();
            if key.eq_ignore_ascii_case("content-length") {
                let parsed = val.parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid DoH Content-Length")
                })?;
                if let Some(prev) = content_length
                    && prev != parsed
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "conflicting DoH Content-Length headers",
                    ));
                }
                content_length = Some(parsed);
            } else if key.eq_ignore_ascii_case("content-type") {
                let media_type = val.split(';').next().unwrap_or("").trim();
                if !media_type.eq_ignore_ascii_case("application/dns-message") {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unexpected DoH Content-Type: {media_type}"),
                    ));
                }
                content_type_valid = true;
            } else if key.eq_ignore_ascii_case("transfer-encoding")
                && val.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
            } else if key.eq_ignore_ascii_case("connection") {
                let lower = val.to_ascii_lowercase();
                if lower.split(',').any(|tok| tok.trim() == "close") {
                    conn_close = true;
                } else if lower.split(',').any(|tok| tok.trim() == "keep-alive") {
                    conn_close = false;
                }
            }
        }
    }
    if !content_type_valid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing DoH Content-Type header",
        ));
    }

    let mut body = buf[header_end + 4..].to_vec();

    // RFC 9112 §6.3: Transfer-Encoding takes precedence over Content-Length.
    if chunked {
        loop {
            match try_decode_chunked_body(&body)? {
                Some(decoded) => {
                    // Only reuse if no unexpected pipelined bytes remain.
                    let reusable = !conn_close && is_exact_chunked_end(&body);
                    return Ok((decoded, reusable));
                }
                None => {
                    if body.len() > MAX_DOH_RESPONSE_BYTES + 512 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "chunked DoH stream exceeded bound",
                        ));
                    }
                    let n = stream.read(&mut tmp).await?;
                    if n == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "EOF before terminal chunk in DoH body",
                        ));
                    }
                    body.extend_from_slice(&tmp[..n]);
                }
            }
        }
    }

    if let Some(len) = content_length {
        if !(12..=MAX_DOH_RESPONSE_BYTES).contains(&len) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DoH Content-Length out of bounds",
            ));
        }
        let mut extra_bytes = body.len() > len;
        while body.len() < len {
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "EOF reading DoH body",
                ));
            }
            if body.len() + n > len {
                extra_bytes = true;
            }
            let take = n.min(len - body.len());
            body.extend_from_slice(&tmp[..take]);
        }
        body.truncate(len);
        return Ok((body, !conn_close && !extra_bytes));
    }

    // Read until EOF (bounded) for close-delimited responses without Content-Length.
    while body.len() <= MAX_DOH_RESPONSE_BYTES {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }

    if body.len() <= MAX_DOH_RESPONSE_BYTES {
        Ok((body, false))
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DoH response body exceeded bound",
        ))
    }
}

fn is_exact_chunked_end(raw: &[u8]) -> bool {
    raw.ends_with(b"0\r\n\r\n")
}

fn find_crlf_crlf(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Incrementally decodes an HTTP/1.1 chunked body.
/// Returns `Ok(Some(body))` once the terminal `0\r\n` chunk and trailing CRLF
/// have arrived, `Ok(None)` when more bytes are needed, or `Err` on malformed data.
pub fn try_decode_chunked_body(raw: &[u8]) -> io::Result<Option<Vec<u8>>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    loop {
        let Some(rel_end) = raw[pos..].windows(2).position(|w| w == b"\r\n") else {
            return Ok(None);
        };
        let size_line = std::str::from_utf8(&raw[pos..pos + rel_end])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid chunk size UTF-8"))?;
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let chunk_len = usize::from_str_radix(size_hex, 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid chunk size hex"))?;
        pos += rel_end + 2;
        if chunk_len == 0 {
            // Require terminating CRLF (or trailers ending in \r\n\r\n).
            if raw[pos..].starts_with(b"\r\n") {
                return Ok(Some(out));
            }
            if find_crlf_crlf(&raw[pos..]).is_some() {
                return Ok(Some(out));
            }
            return Ok(None);
        }
        if out.len().saturating_add(chunk_len) > MAX_DOH_RESPONSE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunked DoH body exceeded bound",
            ));
        }
        let Some(data_end) = pos.checked_add(chunk_len) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunk length overflow",
            ));
        };
        let Some(after_crlf) = data_end.checked_add(2) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunk length overflow",
            ));
        };
        if after_crlf > raw.len() {
            return Ok(None);
        }
        if &raw[data_end..after_crlf] != b"\r\n" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "missing CRLF after chunk payload",
            ));
        }
        out.extend_from_slice(&raw[pos..data_end]);
        pos = after_crlf;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_query(tx_id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&tx_id.to_be_bytes());
        out.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
        out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes()); // IN
        out
    }

    fn build_a_response(query: &[u8], ip: Ipv4Addr, ttl: u32) -> Vec<u8> {
        let mut out = query.to_vec();
        out[2] = 0x81; // QR=1, RD=1
        out[3] = 0x80; // RA=1, NOERROR
        out[6] = 0;
        out[7] = 1; // ANCOUNT=1
        out.extend_from_slice(&[0xc0, 0x0c]); // pointer to qname at offset 12
        out.extend_from_slice(&1u16.to_be_bytes()); // A
        out.extend_from_slice(&1u16.to_be_bytes()); // IN
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&4u16.to_be_bytes());
        out.extend_from_slice(&ip.octets());
        out
    }

    #[test]
    fn parses_valid_query_and_rejects_malformed_or_looped() {
        let q = build_query(0x1234, "Example.COM", 1);
        let parsed = parse_dns_query(&q).expect("valid query");
        assert_eq!(parsed.tx_id, 0x1234);
        assert_eq!(parsed.qname, "example.com");
        assert_eq!(parsed.qtype, 1);
        assert_eq!(parsed.qclass, 1);

        // Truncated
        assert!(parse_dns_query(&q[..11]).is_none());
        // Self-referencing compression pointer loop at offset 12
        let mut looped = q[..12].to_vec();
        looped.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
        assert!(parse_dns_query(&looped).is_none());
    }

    #[test]
    fn extracts_response_ttl_and_ips() {
        let q = build_query(0xabcd, "nas.lan", 1);
        let r = build_a_response(&q, Ipv4Addr::new(192, 168, 1, 50), 120);
        let (ttl, ips) = parse_dns_response_meta(&r);
        assert_eq!(ttl, Some(120));
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50))]);
    }

    #[test]
    fn suffix_matching_handles_boundaries() {
        assert!(matches_domain_suffix("router.lan", "lan"));
        assert!(matches_domain_suffix("printer.local.", ".local"));
        assert!(matches_domain_suffix("lan", "lan"));
        assert!(!matches_domain_suffix("notlan.com", "lan"));
        assert!(!matches_domain_suffix("mylan", "lan"));
    }

    #[test]
    fn cache_hit_shares_wire_and_evicts_lru() {
        let mut cache = DnsCache::new(2);
        let t0 = Instant::now();
        let q1 = parse_dns_query(&build_query(0x1111, "a.example", 1)).expect("q1");
        let q2 = parse_dns_query(&build_query(0x2222, "b.example", 1)).expect("q2");
        let q3 = parse_dns_query(&build_query(0x3333, "c.example", 1)).expect("q3");

        let r1 = build_a_response(
            &build_query(0x1111, "a.example", 1),
            Ipv4Addr::new(1, 1, 1, 1),
            30,
        );
        let r2 = build_a_response(
            &build_query(0x2222, "b.example", 1),
            Ipv4Addr::new(2, 2, 2, 2),
            30,
        );
        let r3 = build_a_response(
            &build_query(0x3333, "c.example", 1),
            Ipv4Addr::new(3, 3, 3, 3),
            30,
        );

        cache.insert(&q1, Arc::from(r1), 30, false, t0);
        cache.insert(&q2, Arc::from(r2), 30, true, t0);

        // A hit shares the cached wire buffer and refreshes LRU; the cached
        // buffer keeps its original `tx_id` because the reply path patches it.
        let q1_again = DnsQuery {
            tx_id: 0x9999,
            ..q1.clone()
        };
        let hit = cache
            .get(&q1_again, t0 + Duration::from_secs(5))
            .expect("hit");
        assert_eq!(u16::from_be_bytes([hit[0], hit[1]]), 0x1111);

        // Insert q3 -> evicts LRU (q2).
        cache.insert(&q3, Arc::from(r3), 30, false, t0 + Duration::from_secs(6));
        assert!(cache.get(&q2, t0 + Duration::from_secs(7)).is_none());
        assert!(cache.get(&q1, t0 + Duration::from_secs(7)).is_some());

        // Expired after TTL.
        assert!(cache.get(&q1, t0 + Duration::from_secs(31)).is_none());
    }

    #[test]
    fn ttl_zero_answer_is_not_cached() {
        let q = build_query(0x4242, "nocache.example", 1);
        // RFC 1035 §3.2.1: TTL 0 means "do not cache".
        assert_eq!(
            parse_dns_response_meta(&build_a_response(&q, Ipv4Addr::new(1, 2, 3, 4), 0)).0,
            None
        );
        // Non-zero TTLs keep the `MIN_CACHE_TTL_SECS` floor.
        assert_eq!(
            parse_dns_response_meta(&build_a_response(&q, Ipv4Addr::new(1, 2, 3, 4), 1)).0,
            Some(MIN_CACHE_TTL_SECS)
        );
        assert_eq!(
            parse_dns_response_meta(&build_a_response(&q, Ipv4Addr::new(1, 2, 3, 4), 120)).0,
            Some(120)
        );
    }

    #[test]
    fn cache_separates_dnssec_ok_from_plain_queries() {
        let mut cache = DnsCache::new(4);
        let now = Instant::now();
        let plain_wire = build_query_with_edns0_do(0x1234, "dnssec.example", 1, false);
        let signed_wire = build_query_with_edns0_do(0x1234, "dnssec.example", 1, true);
        let q_plain = parse_dns_query(&plain_wire).expect("plain query");
        let q_signed = parse_dns_query(&signed_wire).expect("signed query");
        assert!(!q_plain.dnssec_ok);
        assert!(q_signed.dnssec_ok);

        cache.insert(
            &q_plain,
            Arc::from(build_a_response(
                &build_query(0x1234, "dnssec.example", 1),
                Ipv4Addr::new(1, 2, 3, 4),
                60,
            )),
            60,
            false,
            now,
        );
        cache.insert(
            &q_signed,
            Arc::from(build_a_response(
                &build_query(0x1234, "dnssec.example", 1),
                Ipv4Addr::new(5, 6, 7, 8),
                60,
            )),
            60,
            false,
            now,
        );

        let plain_hit = cache.get(&q_plain, now).expect("plain hit");
        let signed_hit = cache.get(&q_signed, now).expect("signed hit");
        assert_eq!(
            parse_dns_response_meta(&plain_hit).1,
            vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]
        );
        assert_eq!(
            parse_dns_response_meta(&signed_hit).1,
            vec![IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8))]
        );
    }

    #[test]
    fn rejects_response_question_mismatch() {
        let query = parse_dns_query(&build_query(0x1111, "good.example", 1)).expect("query");

        // Case-insensitive match on the same name/type/class is accepted.
        let matching = build_a_response(
            &build_query(0x1111, "Good.Example", 1),
            Ipv4Addr::new(1, 2, 3, 4),
            60,
        );
        assert!(response_question_matches(&query, &matching));

        let wrong_name = build_a_response(
            &build_query(0x1111, "evil.example", 1),
            Ipv4Addr::new(1, 2, 3, 4),
            60,
        );
        assert!(!response_question_matches(&query, &wrong_name));

        let wrong_type = build_a_response(
            &build_query(0x1111, "good.example", 28),
            Ipv4Addr::new(1, 2, 3, 4),
            60,
        );
        assert!(!response_question_matches(&query, &wrong_type));

        let mut class_query = build_query(0x1111, "good.example", 1);
        let class_at = class_query.len() - 2;
        class_query[class_at..].copy_from_slice(&3u16.to_be_bytes());
        let wrong_class = build_a_response(&class_query, Ipv4Addr::new(1, 2, 3, 4), 60);
        assert!(!response_question_matches(&query, &wrong_class));

        // Truncated, question-less, multi-question, and QR=0 responses never match.
        assert!(!response_question_matches(&query, &matching[..11]));
        let mut no_question = matching.clone();
        no_question[4] = 0;
        no_question[5] = 0;
        assert!(!response_question_matches(&query, &no_question));

        let mut two_questions = matching.clone();
        two_questions[4] = 0;
        two_questions[5] = 2;
        assert!(!response_question_matches(&query, &two_questions));

        let mut qr_zero = matching.clone();
        qr_zero[2] &= !0x80;
        assert!(!response_question_matches(&query, &qr_zero));

        let mut multi_q_query = build_query(0x1111, "good.example", 1);
        multi_q_query[4] = 0;
        multi_q_query[5] = 2;
        assert!(parse_dns_query(&multi_q_query).is_none());
    }

    #[test]
    fn parses_dns_upstreams() {
        assert_eq!(
            DnsUpstream::parse("https://dns.nextdns.io/abc123").expect("doh"),
            DnsUpstream::Doh {
                host: "dns.nextdns.io".into(),
                port: 443,
                path: "/abc123".into(),
            }
        );
        assert_eq!(
            DnsUpstream::parse("https://1.1.1.1:8443/dns-query").expect("doh port"),
            DnsUpstream::Doh {
                host: "1.1.1.1".into(),
                port: 8443,
                path: "/dns-query".into(),
            }
        );
        assert_eq!(
            DnsUpstream::parse("tcp://1.1.1.1:53").expect("tcp"),
            DnsUpstream::PlainTcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53))
        );
        assert_eq!(
            DnsUpstream::parse("8.8.8.8:53").expect("udp"),
            DnsUpstream::PlainUdp(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53))
        );
        assert!(DnsUpstream::parse("https://evil.com/\r\nX: y").is_err());
        assert!(DnsUpstream::parse("https://[bad]/dns-query").is_err());
        assert!(DnsUpstream::parse("http://1.1.1.1/dns-query").is_err());
        assert!(DnsUpstream::parse("tcp://1.1.1.1:0").is_err());
        assert!(DnsUpstream::parse("udp://1.1.1.1:0").is_err());
    }

    #[test]
    fn dns_upstream_display_omits_the_doh_path() {
        // Profile IDs and tokens live in the DoH path, and this string reaches
        // startup logs and `--check` stdout.
        let doh = DnsUpstream::parse("https://dns.nextdns.io/sekret-profile-id").expect("doh");
        assert_eq!(doh.to_string(), "https://dns.nextdns.io:443");
        assert!(!doh.to_string().contains("sekret-profile-id"));

        let custom = DnsUpstream::parse("https://1.1.1.1:8443/SECRET/dns-query").expect("doh");
        assert_eq!(custom.to_string(), "https://1.1.1.1:8443");
        assert!(!custom.to_string().contains("SECRET"));

        assert_eq!(
            DnsUpstream::PlainTcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53))
                .to_string(),
            "tcp://1.1.1.1:53"
        );
        assert_eq!(
            DnsUpstream::PlainUdp(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5353))
                .to_string(),
            "udp://[::1]:5353"
        );
    }

    #[tokio::test]
    async fn doh_http_response_handles_ipv6_host_incremental_chunked_and_te_precedence() {
        assert_eq!(
            format_http_host_header("2606:4700:4700::1111", 443),
            "[2606:4700:4700::1111]"
        );
        assert_eq!(
            format_http_host_header("2606:4700:4700::1111", 8443),
            "[2606:4700:4700::1111]:8443"
        );
        assert_eq!(
            format_http_host_header("dns.nextdns.io", 443),
            "dns.nextdns.io"
        );

        // Incremental chunked response must return immediately on 0\r\n\r\n
        // without waiting for EOF, and Transfer-Encoding must win over Content-Length.
        let (mut client, mut server) = tokio::io::duplex(512);
        let wire_body = build_a_response(
            &build_query(0x5555, "chunked.test", 1),
            Ipv4Addr::new(1, 2, 3, 4),
            60,
        );
        let expected = wire_body.clone();
        let writer = tokio::spawn(async move {
            let hdr = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 9999\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n",
                wire_body.len()
            );
            server.write_all(hdr.as_bytes()).await.expect("hdr");
            server.write_all(&wire_body).await.expect("body");
            server.write_all(b"\r\n0\r\n\r\n").await.expect("term");
            // Deliberately keep `server` open to prove we do not wait for EOF!
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let parsed = timeout(Duration::from_secs(1), read_doh_http_response(&mut client))
            .await
            .expect("chunked DoH must not block waiting for EOF")
            .expect("valid chunked response");
        assert_eq!(parsed, expected);
        writer.abort();

        // Malformed chunk missing CRLF after payload must error.
        assert!(try_decode_chunked_body(b"4\r\nabcdXX0\r\n\r\n").is_err());

        // TC=1 truncated DNS response must NOT be cached; NOERROR NODATA must be cached briefly.
        let mut tc_resp = build_a_response(
            &build_query(0x6666, "trunc.test", 1),
            Ipv4Addr::new(5, 6, 7, 8),
            120,
        );
        tc_resp[2] |= 0x02; // TC=1
        assert_eq!(parse_dns_response_meta(&tc_resp).0, None);

        let mut nodata = build_query(0x7777, "nodata.test", 28);
        nodata[2] = 0x81;
        nodata[3] = 0x80; // QR=1, NOERROR, ANCOUNT=0
        assert_eq!(
            parse_dns_response_meta(&nodata).0,
            Some(NEGATIVE_CACHE_TTL_SECS)
        );
    }

    #[test]
    fn builds_valid_servfail() {
        let q = build_query(0x4242, "fail.example", 1);
        let sf = build_servfail_response(&q).expect("servfail");
        assert_eq!(u16::from_be_bytes([sf[0], sf[1]]), 0x4242);
        assert_eq!(sf[2] & 0x80, 0x80); // QR=1
        assert_eq!(sf[3] & 0x0f, 2); // SERVFAIL
    }

    #[tokio::test]
    async fn local_suffix_bypasses_tunnel_and_caches_reply() {
        let local_dns = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let local_addr = local_dns.local_addr().expect("addr");
        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, peer) = local_dns.recv_from(&mut buf).await.expect("recv");
            let resp = build_a_response(&buf[..n], Ipv4Addr::new(192, 168, 1, 99), 60);
            local_dns.send_to(&resp, peer).await.expect("send");
        });

        let (tun_tx, mut tun_rx) = mpsc::channel(8);
        let dummy_reality = beam_core::reality::RealityClientConfig::new(
            [1u8; 32],
            "0123456789abcdef",
            "whatsapp.net",
        )
        .expect("reality");
        let client_cfg = BeamClientConfig::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1),
            dummy_reality,
            [2u8; 16],
        );
        let dns_cfg = DnsConfig::new(
            DnsUpstream::PlainTcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53)),
            Some(local_addr),
        );
        let interceptor = DnsInterceptor::new(client_cfg, dns_cfg, tun_tx);

        let q1 = build_query(0x7001, "nas.lan", 1);
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 1)), 54000);
        let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 2)), 53);
        interceptor.handle_query(src, dst, &q1);

        let reply_pkt = timeout(Duration::from_secs(2), tun_rx.recv())
            .await
            .expect("timeout")
            .expect("reply pkt");
        let ip = crate::packet::parse_ip(&reply_pkt).expect("ip");
        let udp = crate::packet::parse_udp(ip.payload).expect("udp");
        let (ttl, ips) = parse_dns_response_meta(udp.payload);
        assert_eq!(ttl, Some(60));
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 99))]);
        server_task.await.expect("server done");

        // Second query with different tx_id must hit cache (mock server already exited!).
        let q2 = build_query(0x7002, "nas.lan", 1);
        interceptor.handle_query(src, dst, &q2);
        let cached_pkt = tun_rx.try_recv().expect("sync cache hit");
        let udp2 =
            crate::packet::parse_udp(crate::packet::parse_ip(&cached_pkt).expect("ip").payload)
                .expect("udp");
        assert_eq!(
            u16::from_be_bytes([udp2.payload[0], udp2.payload[1]]),
            0x7002
        );
        // One upstream miss, one cache hit, no SERVFAIL.
        let stats = interceptor.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.servfail_upstream, 0);
        assert_eq!(stats.servfail_mismatch, 0);
    }

    fn test_interceptor(
        local_upstream: Option<SocketAddr>,
    ) -> (DnsInterceptor, mpsc::Receiver<Vec<u8>>) {
        let (tun_tx, tun_rx) = mpsc::channel(8);
        let dummy_reality = beam_core::reality::RealityClientConfig::new(
            [1u8; 32],
            "0123456789abcdef",
            "whatsapp.net",
        )
        .expect("reality");
        let client_cfg = BeamClientConfig::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1),
            dummy_reality,
            [2u8; 16],
        );
        let mut dns_cfg = DnsConfig::new(
            DnsUpstream::PlainTcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53)),
            local_upstream,
        );
        dns_cfg.query_timeout = Duration::from_millis(300);
        (DnsInterceptor::new(client_cfg, dns_cfg, tun_tx), tun_rx)
    }

    #[tokio::test]
    async fn counters_track_concurrency_limit_servfail() {
        let (interceptor, mut tun_rx) = test_interceptor(None);
        // Hold every inflight permit so the next query hits the limit.
        let permits = interceptor
            .inflight
            .clone()
            .try_acquire_many_owned(MAX_INFLIGHT_DNS_QUERIES as u32)
            .expect("reserve inflight permits");

        let wire = build_query(0x8001, "example.com", 1);
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 1)), 55_001);
        let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 2)), 53);
        interceptor.handle_query(src, dst, &wire);

        let reply = tun_rx.recv().await.expect("servfail reply");
        let udp = crate::packet::parse_udp(crate::packet::parse_ip(&reply).expect("ip").payload)
            .expect("udp");
        assert_eq!(udp.payload[3] & 0x0f, 2, "must be SERVFAIL");
        assert_eq!(interceptor.stats().servfail_concurrency, 1);
        assert_eq!(interceptor.stats().servfail_upstream, 0);
        drop(permits);
    }

    #[tokio::test]
    async fn counters_track_loop_guard_and_upstream_failures() {
        // A local upstream whose address equals the query destination triggers
        // the loop guard before any packet leaves the process.
        let (interceptor, mut tun_rx) = test_interceptor(Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(172, 19, 0, 2)),
            53,
        )));
        let wire = build_query(0x8101, "nas.lan", 1);
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 1)), 55_002);
        let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 2)), 53);
        interceptor.handle_query(src, dst, &wire);
        let reply = tun_rx.recv().await.expect("loop-guard servfail");
        let udp = crate::packet::parse_udp(crate::packet::parse_ip(&reply).expect("ip").payload)
            .expect("udp");
        assert_eq!(udp.payload[3] & 0x0f, 2);
        assert_eq!(interceptor.stats().loop_guard, 1);

        // A tunneled upstream that cannot be reached fails fast and counts an
        // upstream SERVFAIL (the client config points at a closed loopback port).
        let (failing, mut failing_rx) = test_interceptor(None);
        let wire = build_query(0x8202, "example.com", 1);
        failing.handle_query(src, dst, &wire);
        let reply = timeout(Duration::from_secs(3), failing_rx.recv())
            .await
            .expect("servfail within timeout")
            .expect("reply");
        let udp = crate::packet::parse_udp(crate::packet::parse_ip(&reply).expect("ip").payload)
            .expect("udp");
        assert_eq!(udp.payload[3] & 0x0f, 2);
        let stats = failing.stats();
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.servfail_upstream, 1);
        assert_eq!(stats.hits, 0);
    }

    #[tokio::test]
    async fn cache_hits_count_tun_tx_full_drops() {
        // A 1-slot reply channel: the second cached hit cannot be queued.
        let (tun_tx, tun_rx) = mpsc::channel(1);
        let dummy_reality = beam_core::reality::RealityClientConfig::new(
            [1u8; 32],
            "0123456789abcdef",
            "whatsapp.net",
        )
        .expect("reality");
        let client_cfg = BeamClientConfig::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1),
            dummy_reality,
            [2u8; 16],
        );
        let mut dns_cfg = DnsConfig::new(
            DnsUpstream::PlainUdp(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53)),
            None,
        );
        dns_cfg.cache_size = 8;
        let interceptor = DnsInterceptor::new(client_cfg, dns_cfg, tun_tx);

        let query = parse_dns_query(&build_query(0x9101, "cached.example", 1)).expect("query");
        interceptor.cache.lock().expect("cache").insert(
            &query,
            Arc::from(build_a_response(
                &build_query(0x9101, "cached.example", 1),
                Ipv4Addr::new(203, 0, 113, 5),
                60,
            )),
            60,
            false,
            Instant::now(),
        );

        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 1)), 55_010);
        let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 2)), 53);
        let wire = build_query(0x9101, "cached.example", 1);
        // The channel holds one reply; every further cached hit is dropped.
        for _ in 0..4 {
            interceptor.handle_query(src, dst, &wire);
        }
        let stats = interceptor.stats();
        assert_eq!(stats.hits, 4);
        assert_eq!(stats.tun_tx_dropped, 3);
        assert_eq!(tun_rx.len(), 1);
    }

    #[tokio::test]
    async fn counters_track_question_mismatch() {
        // The local server answers with a different question, so the reply is
        // rejected before it can be cached or delivered.
        let local_dns = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let local_addr = local_dns.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, peer) = local_dns.recv_from(&mut buf).await.expect("recv");
            assert_eq!(n, build_query(0x8301, "nas.lan", 1).len());
            // Same tx_id, wrong question name: the socket-level check passes and
            // the question check is what must reject it.
            let evil = build_query(0x8301, "evil.example", 1);
            let resp = build_a_response(&evil, Ipv4Addr::new(6, 6, 6, 6), 60);
            local_dns.send_to(&resp, peer).await.expect("send");
        });

        let (interceptor, mut tun_rx) = test_interceptor(Some(local_addr));
        let wire = build_query(0x8301, "nas.lan", 1);
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 1)), 55_003);
        let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 2)), 53);
        interceptor.handle_query(src, dst, &wire);
        let reply = timeout(Duration::from_secs(2), tun_rx.recv())
            .await
            .expect("reply")
            .expect("packet");
        let udp = crate::packet::parse_udp(crate::packet::parse_ip(&reply).expect("ip").payload)
            .expect("udp");
        assert_eq!(u16::from_be_bytes([udp.payload[0], udp.payload[1]]), 0x8301);
        assert_eq!(
            udp.payload[3] & 0x0f,
            2,
            "mismatched replies become SERVFAIL"
        );
        assert_eq!(interceptor.stats().servfail_mismatch, 1);
        server.await.expect("server done");
    }

    #[tokio::test]
    async fn local_udp_pool_reuses_sockets_and_evicts_stale_ones() {
        let local_dns = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let local_addr = local_dns.local_addr().expect("addr");
        let peers = Arc::new(Mutex::new(Vec::new()));
        let peers_srv = Arc::clone(&peers);
        let server = tokio::spawn(async move {
            for _ in 0..3 {
                let mut buf = [0u8; 512];
                let (n, peer) = local_dns.recv_from(&mut buf).await.expect("recv");
                peers_srv.lock().expect("lock").push(peer);
                let resp = build_a_response(&buf[..n], Ipv4Addr::new(192, 168, 1, 7), 60);
                local_dns.send_to(&resp, peer).await.expect("send");
            }
        });

        let pool = LocalUdpPool::default();
        let q1 = build_query(0x9001, "nas.lan", 1);
        resolve_local_udp(&pool, local_addr, &q1, 0x9001, Duration::from_secs(2))
            .await
            .expect("first resolve");
        assert_eq!(
            pool.len(),
            1,
            "successful exchange returns the socket to the pool"
        );

        let q2 = build_query(0x9002, "nas.lan", 1);
        resolve_local_udp(&pool, local_addr, &q2, 0x9002, Duration::from_secs(2))
            .await
            .expect("second resolve");
        let used = peers.lock().expect("lock").clone();
        assert_eq!(used.len(), 2);
        assert_eq!(
            used[0], used[1],
            "the pooled socket must be reused (same source port)"
        );

        // A generation bump on network change invalidates the pooled socket.
        pool.clear();
        assert_eq!(pool.len(), 0);
        let stale_generation = 0u64;
        let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        pool.put(sock, local_addr, stale_generation, Instant::now());
        assert_eq!(
            pool.len(),
            0,
            "a socket dialed before the network change must not be pooled"
        );

        // A `tx_id` mismatch must drop the socket instead of pooling it.
        let q3 = build_query(0x9003, "nas.lan", 1);
        assert!(
            resolve_local_udp(&pool, local_addr, &q3, 0xffff, Duration::from_secs(2))
                .await
                .is_err()
        );
        assert_eq!(pool.len(), 0, "mismatched replies must not poison the pool");
        server.await.expect("server done");
    }

    #[tokio::test]
    async fn local_udp_pool_evicts_idle_sockets_and_stays_bounded() {
        let pool = LocalUdpPool::default();
        let key = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53);

        // The pool is capped: extra sockets are dropped instead of queued.
        for _ in 0..(MAX_LOCAL_UDP_POOL_SIZE + 2) {
            let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("bind");
            pool.put(sock, key, 0, Instant::now());
        }
        assert_eq!(pool.len(), MAX_LOCAL_UDP_POOL_SIZE);

        // A socket past the idle TTL is evicted on the next borrow, never handed out.
        {
            let mut state = pool.state.lock().expect("pool state");
            let stale = Instant::now()
                .checked_sub(LOCAL_UDP_POOL_IDLE_TTL + Duration::from_secs(1))
                .expect("monotonic clock");
            for entry in state.idle.iter_mut() {
                entry.last_used = stale;
            }
        }
        let (taken, _) = pool.take(key, Instant::now());
        assert!(taken.is_none(), "an expired socket must not be reused");
        assert_eq!(pool.len(), 0);

        // A fresh entry is handed out exactly once.
        let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        pool.put(sock, key, 0, Instant::now());
        assert!(pool.take(key, Instant::now()).0.is_some());
        assert_eq!(pool.len(), 0);
    }

    #[tokio::test]
    async fn stale_local_udp_reply_is_discarded_and_never_repooled() {
        let local_dns = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let local_addr = local_dns.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, peer) = local_dns.recv_from(&mut buf).await.expect("recv");
            // A late duplicate from an earlier query on the same socket.
            let stale = build_a_response(
                &build_query(0x7001, "nas.lan", 1),
                Ipv4Addr::new(1, 1, 1, 1),
                60,
            );
            local_dns.send_to(&stale, peer).await.expect("send stale");
            let resp = build_a_response(&buf[..n], Ipv4Addr::new(192, 168, 1, 9), 60);
            local_dns.send_to(&resp, peer).await.expect("send valid");
        });

        let pool = LocalUdpPool::default();
        let query = build_query(0x7002, "nas.lan", 1);
        let reply = resolve_local_udp(&pool, local_addr, &query, 0x7002, Duration::from_secs(2))
            .await
            .expect("the stale reply must be skipped, not failed on");
        assert_eq!(u16::from_be_bytes([reply[0], reply[1]]), 0x7002);
        assert_eq!(
            pool.len(),
            0,
            "a socket that saw a stale reply must not return to the pool"
        );
        server.await.expect("server done");

        // The discard loop is bounded: a flood of stale replies still fails.
        let local_dns = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let local_addr = local_dns.local_addr().expect("addr");
        let flood = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (_n, peer) = local_dns.recv_from(&mut buf).await.expect("recv");
            let stale = build_a_response(
                &build_query(0x7003, "nas.lan", 1),
                Ipv4Addr::new(1, 1, 1, 1),
                60,
            );
            for _ in 0..=MAX_LOCAL_UDP_STALE_REPLIES {
                local_dns.send_to(&stale, peer).await.expect("send stale");
            }
        });
        let pool = LocalUdpPool::default();
        assert!(
            resolve_local_udp(&pool, local_addr, &query, 0x7002, Duration::from_secs(2))
                .await
                .is_err(),
            "a stale-reply flood must give up instead of looping forever"
        );
        flood.await.expect("flood done");
    }

    #[tokio::test]
    async fn unframeable_dns_reply_counts_as_a_tun_tx_drop() {
        let (tun_tx, mut tun_rx) = mpsc::channel(4);
        let counters = DnsCounters::default();
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 1)), 55_010);
        let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 2)), 53);

        // Larger than a UDP datagram can carry: building the packet returns None.
        send_udp_reply(&tun_tx, &counters, src, dst, &vec![0u8; 70_000], None);

        assert_eq!(counters.tun_tx_dropped.get(), 1);
        assert!(tun_rx.try_recv().is_err());
    }

    #[test]
    fn empty_noerror_response_for_aaaa_in_ipv4_only_mode() {
        let q = build_query(0xabcd, "example.com", 28);
        let resp = build_empty_noerror_response(&q).expect("noerror");
        assert_eq!(&resp[0..2], &[0xab, 0xcd]);
        assert_eq!(resp[2] & 0x80, 0x80); // QR=1
        assert_eq!(resp[3] & 0x0f, 0); // RCODE=0 (NOERROR)
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0); // ANCOUNT=0
        assert_eq!(u16::from_be_bytes([resp[10], resp[11]]), 0); // ARCOUNT=0 (no OPT in query)

        // When the query includes an EDNS0 OPT record, synthetic replies must
        // preserve EDNS0 OPT (ARCOUNT=1) so systemd-resolved does not degrade.
        let mut q_edns = build_query(0x1234, "example.com", 28);
        q_edns[11] = 1; // ARCOUNT=1
        q_edns.extend_from_slice(&EDNS0_OPT_RR);
        assert!(query_has_edns0_opt(&q_edns));

        let resp_edns = build_empty_noerror_response(&q_edns).expect("noerror edns0");
        assert_eq!(u16::from_be_bytes([resp_edns[10], resp_edns[11]]), 1);
        assert!(resp_edns.ends_with(&EDNS0_OPT_RR));

        let sf_edns = build_servfail_response(&q_edns).expect("servfail edns0");
        assert_eq!(sf_edns[3] & 0x0f, 2); // SERVFAIL
        assert_eq!(u16::from_be_bytes([sf_edns[10], sf_edns[11]]), 1);
        assert!(sf_edns.ends_with(&EDNS0_OPT_RR));

        // Malformed/truncated Additional section must never panic.
        let mut q_trunc = build_query(0x5678, "example.com", 28);
        q_trunc[11] = 1;
        q_trunc.extend_from_slice(&[0x00, 0x00, 0x29]); // truncated OPT
        assert!(!query_has_edns0_opt(&q_trunc));
    }

    #[tokio::test]
    async fn doh_keepalive_reuses_single_stream_for_sequential_queries() {
        let (mut client, mut server) = tokio::io::duplex(2048);
        let q1 = build_query(0x1111, "one.example", 1);
        let q2 = build_query(0x2222, "two.example", 1);
        let r1 = build_a_response(&q1, Ipv4Addr::new(1, 1, 1, 1), 60);
        let r2 = build_a_response(&q2, Ipv4Addr::new(2, 2, 2, 2), 60);
        let r1_srv = r1.clone();
        let r2_srv = r2.clone();

        let srv_task = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            for resp in [&r1_srv, &r2_srv] {
                let n = server.read(&mut buf).await.expect("read req");
                assert!(n > 0);
                let hdr = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                    resp.len()
                );
                server.write_all(hdr.as_bytes()).await.expect("write hdr");
                server.write_all(resp).await.expect("write body");
                server.flush().await.expect("flush");
            }
        });

        let (got1, reusable1) = send_doh_http_request(&mut client, "1.1.1.1", "/dns-query", &q1)
            .await
            .expect("req1");
        assert_eq!(got1, r1);
        assert!(reusable1, "keep-alive response must be marked reusable");

        let (got2, reusable2) = send_doh_http_request(&mut client, "1.1.1.1", "/dns-query", &q2)
            .await
            .expect("req2");
        assert_eq!(got2, r2);
        assert!(reusable2);

        srv_task.await.expect("server done");
    }

    #[tokio::test]
    async fn tcp_dns_pool_reuses_expires_bounds_and_clears() {
        let t0 = Instant::now();
        let mut pool: TcpDnsPool<u32> = TcpDnsPool::default();

        // LIFO reuse within idle TTL.
        let (_, g0) = pool.take(t0);
        pool.put(1, g0, t0);
        pool.put(2, g0, t0 + Duration::from_secs(1));
        assert_eq!(pool.len(), 2);
        assert_eq!(pool.take(t0 + Duration::from_secs(5)).0, Some(2));
        assert_eq!(pool.take(t0 + Duration::from_secs(5)).0, Some(1));
        assert_eq!(pool.take(t0 + Duration::from_secs(5)).0, None);

        // Idle expiry discards stale streams passively.
        pool.put(10, g0, t0);
        assert_eq!(pool.take(t0 + TCP_DNS_POOL_IDLE_TTL).0, None);

        // Bounded to MAX_TCP_DNS_POOL_SIZE.
        for i in 0..(MAX_TCP_DNS_POOL_SIZE as u32 + 3) {
            pool.put(i, g0, t0);
        }
        assert_eq!(pool.len(), MAX_TCP_DNS_POOL_SIZE);

        // Clear empties the pool and rejects stale-generation puts.
        pool.clear();
        assert_eq!(pool.len(), 0);
        pool.put(99, g0, t0);
        assert_eq!(pool.len(), 0);
        assert_eq!(pool.take(t0).0, None);

        // Sequential RFC 1035 DNS-over-TCP queries reuse a single stream.
        let (mut client, mut server) = tokio::io::duplex(2048);
        let q1 = build_query(0x3131, "tcp-one.example", 1);
        let q2 = build_query(0x3232, "tcp-two.example", 1);
        let r1 = build_a_response(&q1, Ipv4Addr::new(9, 9, 9, 9), 60);
        let r2 = build_a_response(&q2, Ipv4Addr::new(8, 8, 4, 4), 60);
        let r1_srv = r1.clone();
        let r2_srv = r2.clone();

        let srv = tokio::spawn(async move {
            for resp in [&r1_srv, &r2_srv] {
                let mut len_buf = [0u8; 2];
                server.read_exact(&mut len_buf).await.expect("read len");
                let qlen = usize::from(u16::from_be_bytes(len_buf));
                let mut qbuf = vec![0u8; qlen];
                server.read_exact(&mut qbuf).await.expect("read query");

                let rlen = u16::try_from(resp.len()).expect("resp len");
                server
                    .write_all(&rlen.to_be_bytes())
                    .await
                    .expect("write rlen");
                server.write_all(resp).await.expect("write resp");
                server.flush().await.expect("flush");
            }
        });

        assert_eq!(
            send_tcp_dns_request(&mut client, &q1).await.expect("q1"),
            r1
        );
        assert_eq!(
            send_tcp_dns_request(&mut client, &q2).await.expect("q2"),
            r2
        );
        srv.await.expect("srv");
    }

    #[tokio::test]
    async fn plain_udp_shared_mux_reuses_invalidates_and_resets() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        struct FakeMux {
            id: usize,
            open: AtomicBool,
        }

        impl MuxHealth for FakeMux {
            fn is_open(&self) -> bool {
                self.open.load(Ordering::Acquire)
            }
        }

        let pool = Arc::new(UdpDnsMuxPool::<FakeMux>::new());
        let dials = Arc::new(AtomicUsize::new(0));

        // Initial connect dials once and caches.
        let dials1 = Arc::clone(&dials);
        let (m1, reused1) = pool
            .get_or_connect(|| async move {
                let id = dials1.fetch_add(1, Ordering::SeqCst) + 1;
                Ok(FakeMux {
                    id,
                    open: AtomicBool::new(true),
                })
            })
            .await
            .expect("first connect");
        assert_eq!(m1.id, 1);
        assert!(!reused1);
        assert_eq!(dials.load(Ordering::SeqCst), 1);

        // Concurrent queries reuse the same open mux without re-dialing.
        let (m1_a, reused_a) = pool
            .get_or_connect(|| async {
                dials.fetch_add(1, Ordering::SeqCst);
                Ok(FakeMux {
                    id: 99,
                    open: AtomicBool::new(true),
                })
            })
            .await
            .expect("reused connect");
        assert!(reused_a);
        assert!(Arc::ptr_eq(&m1, &m1_a));
        assert_eq!(dials.load(Ordering::SeqCst), 1);

        // Stale mux invalidation triggers one fresh dial; re-invalidating the
        // old handle does NOT evict the new mux.
        pool.invalidate(&m1);
        let dials2 = Arc::clone(&dials);
        let (m2, reused2) = pool
            .get_or_connect(|| async move {
                let id = dials2.fetch_add(1, Ordering::SeqCst) + 1;
                Ok(FakeMux {
                    id,
                    open: AtomicBool::new(true),
                })
            })
            .await
            .expect("reconnect after invalidate");
        assert_eq!(m2.id, 2);
        assert!(!reused2);
        pool.invalidate(&m1); // stale handle must not evict m2
        let (m2_again, reused2_again) = pool
            .get_or_connect(|| async {
                dials.fetch_add(1, Ordering::SeqCst);
                Ok(FakeMux {
                    id: 99,
                    open: AtomicBool::new(true),
                })
            })
            .await
            .expect("still m2");
        assert!(reused2_again);
        assert!(Arc::ptr_eq(&m2, &m2_again));

        // Closed mux triggers automatic reconnect.
        m2.open.store(false, Ordering::Release);
        let dials3 = Arc::clone(&dials);
        let (m3, reused3) = pool
            .get_or_connect(|| async move {
                let id = dials3.fetch_add(1, Ordering::SeqCst) + 1;
                Ok(FakeMux {
                    id,
                    open: AtomicBool::new(true),
                })
            })
            .await
            .expect("reconnect after close");
        assert_eq!(m3.id, 3);
        assert!(!reused3);

        // `clear()` (called on network change) drops the cached mux AND
        // prevents an in-flight dial from an older generation from repopulating.
        pool.clear();
        let entered = Arc::new(tokio::sync::Notify::new());
        let proceed = Arc::new(tokio::sync::Notify::new());
        let pool_bg = Arc::clone(&pool);
        let entered_bg = Arc::clone(&entered);
        let proceed_bg = Arc::clone(&proceed);
        let dials_bg = Arc::clone(&dials);
        let inflight = tokio::spawn(async move {
            pool_bg
                .get_or_connect(|| async move {
                    entered_bg.notify_one();
                    proceed_bg.notified().await;
                    let id = dials_bg.fetch_add(1, Ordering::SeqCst) + 1;
                    Ok(FakeMux {
                        id,
                        open: AtomicBool::new(true),
                    })
                })
                .await
        });
        entered.notified().await;
        pool.clear(); // network changed mid-dial
        proceed.notify_one();
        let (stale_fresh, _) = inflight.await.expect("join").expect("old dial ok");
        assert_eq!(stale_fresh.id, 4);

        // Next caller must dial again because the generation changed mid-dial.
        let dials5 = Arc::clone(&dials);
        let (m5, reused5) = pool
            .get_or_connect(|| async move {
                let id = dials5.fetch_add(1, Ordering::SeqCst) + 1;
                Ok(FakeMux {
                    id,
                    open: AtomicBool::new(true),
                })
            })
            .await
            .expect("post-clear dial");
        assert_eq!(m5.id, 5);
        assert!(!reused5);
    }

    fn build_query_with_edns0(
        tx_id: u16,
        name: &str,
        qtype: u16,
        udp_payload_size: u16,
    ) -> Vec<u8> {
        let mut q = build_query(tx_id, name, qtype);
        q[11] = 1; // ARCOUNT = 1
        q.push(0x00); // root name
        q.extend_from_slice(&41u16.to_be_bytes()); // TYPE = OPT
        q.extend_from_slice(&udp_payload_size.to_be_bytes()); // CLASS = UDP payload size
        q.extend_from_slice(&0u32.to_be_bytes()); // extended RCODE / version / flags
        q.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH = 0
        q
    }

    /// Builds a query with an EDNS0 `OPT` record and the given DNSSEC OK bit.
    fn build_query_with_edns0_do(tx_id: u16, name: &str, qtype: u16, dnssec_ok: bool) -> Vec<u8> {
        let mut q = build_query_with_edns0(tx_id, name, qtype, 1232);
        if dnssec_ok {
            // DO is the top bit of the OPT TTL flags word, 4 bytes from the end
            // of the record when RDLENGTH is 0.
            let do_byte = q.len() - 4;
            q[do_byte] |= 0x80;
        }
        q
    }

    #[tokio::test]
    async fn concurrency_limit_full_replies_with_servfail() {
        let (tun_tx, mut tun_rx) = mpsc::channel(8);
        let dummy_reality = beam_core::reality::RealityClientConfig::new(
            [1u8; 32],
            "0123456789abcdef",
            "whatsapp.net",
        )
        .expect("reality");
        let client_cfg = BeamClientConfig::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
            dummy_reality,
            [2u8; 16],
        );
        let dns_cfg = DnsConfig::new(
            DnsUpstream::PlainTcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53)),
            None,
        );
        let interceptor = DnsInterceptor::new(client_cfg, dns_cfg, tun_tx);

        // Exhaust all inflight DNS query permits.
        let _held_permits = interceptor
            .inflight
            .acquire_many(MAX_INFLIGHT_DNS_QUERIES as u32)
            .await
            .expect("acquire all permits");

        let q = build_query_with_edns0(0xBEEF, "saturated.example", 1, 1232);
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 1)), 54_123);
        let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 2)), 53);
        interceptor.handle_query(src, dst, &q);

        let pkt = tun_rx
            .try_recv()
            .expect("concurrency saturation must reply with SERVFAIL immediately");
        let ip = crate::packet::parse_ip(&pkt).expect("ip");
        let udp = crate::packet::parse_udp(ip.payload).expect("udp");
        assert_eq!(udp.src_port, 53);
        assert_eq!(udp.dst_port, 54_123);
        assert_eq!(u16::from_be_bytes([udp.payload[0], udp.payload[1]]), 0xBEEF);
        assert_eq!(udp.payload[2] & 0x80, 0x80); // QR=1
        assert_eq!(udp.payload[3] & 0x0f, 2); // RCODE=2 (SERVFAIL)
        assert_eq!(u16::from_be_bytes([udp.payload[10], udp.payload[11]]), 1); // EDNS0 OPT preserved
        assert!(udp.payload.ends_with(&EDNS0_OPT_RR));
    }

    #[tokio::test]
    async fn doh_oversized_response_parsed_cleanly_and_truncated_for_udp() {
        let q_edns = build_query_with_edns0(0xCAFE, "large.example", 16, 4096);
        let q_plain = build_query(0xCAFE, "large.example", 16);

        // Build a valid DNS response > 4096 bytes: 1 A record + 25 TXT records (~5.3 KiB).
        let mut big_resp = build_a_response(&q_plain, Ipv4Addr::new(203, 0, 113, 42), 120);
        let txt_records: u16 = 25;
        let total_ancount: u16 = 1 + txt_records;
        big_resp[6..8].copy_from_slice(&total_ancount.to_be_bytes());
        for _ in 0..txt_records {
            big_resp.extend_from_slice(&[0xc0, 0x0c]); // pointer to qname
            big_resp.extend_from_slice(&16u16.to_be_bytes()); // TXT
            big_resp.extend_from_slice(&1u16.to_be_bytes()); // IN
            big_resp.extend_from_slice(&120u32.to_be_bytes()); // TTL
            big_resp.extend_from_slice(&201u16.to_be_bytes()); // RDLENGTH
            big_resp.push(200u8); // TXT string length
            big_resp.extend_from_slice(&[b'x'; 200]);
        }
        assert!(
            big_resp.len() > 4096 && big_resp.len() <= MAX_DOH_RESPONSE_BYTES,
            "test response should exceed legacy 4096 cap (len={})",
            big_resp.len()
        );

        let (mut client, mut server) = tokio::io::duplex(16_384);
        let wire_for_srv = big_resp.clone();
        let srv = tokio::spawn(async move {
            let hdr = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: Application/DNS-Message; charset=utf-8\r\nContent-Length: {}\r\n\r\n",
                wire_for_srv.len()
            );
            server.write_all(hdr.as_bytes()).await.expect("hdr");
            server.write_all(&wire_for_srv).await.expect("body");
            server.flush().await.expect("flush");
        });

        let parsed = read_doh_http_response(&mut client)
            .await
            .expect("oversized DoH response up to MAX_DOH_RESPONSE_BYTES must parse cleanly");
        srv.await.expect("srv");
        assert_eq!(parsed, big_resp);

        let (ttl, ips) = parse_dns_response_meta(&parsed);
        assert_eq!(ttl, Some(120));
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42))]);

        // For UDP delivery, oversized response must be synthesized as TC=1
        // preserving tx_id, question, and EDNS0 OPT.
        let udp_reply_edns =
            fit_response_for_udp(&q_edns, parsed.clone()).expect("truncated edns reply");
        assert!(udp_reply_edns.len() <= MAX_UDP_DNS_RESPONSE_BYTES);
        assert_eq!(
            u16::from_be_bytes([udp_reply_edns[0], udp_reply_edns[1]]),
            0xCAFE
        );
        assert_eq!(udp_reply_edns[2] & 0x80, 0x80); // QR=1
        assert_eq!(udp_reply_edns[2] & 0x02, 0x02); // TC=1
        assert_eq!(udp_reply_edns[3] & 0x0f, 0); // NOERROR
        assert_eq!(
            u16::from_be_bytes([udp_reply_edns[4], udp_reply_edns[5]]),
            1
        ); // QDCOUNT=1
        assert_eq!(
            u16::from_be_bytes([udp_reply_edns[6], udp_reply_edns[7]]),
            0
        ); // ANCOUNT=0
        assert_eq!(
            u16::from_be_bytes([udp_reply_edns[10], udp_reply_edns[11]]),
            1
        ); // ARCOUNT=1 (EDNS0 OPT preserved)
        assert!(udp_reply_edns.ends_with(&EDNS0_OPT_RR));

        // Non-EDNS0 query must truncate without adding OPT.
        let udp_reply_plain =
            fit_response_for_udp(&q_plain, parsed).expect("truncated plain reply");
        assert!(udp_reply_plain.len() <= CLASSIC_UDP_DNS_RESPONSE_BYTES);
        assert_eq!(udp_reply_plain[2] & 0x02, 0x02); // TC=1
        assert_eq!(
            u16::from_be_bytes([udp_reply_plain[10], udp_reply_plain[11]]),
            0
        );

        // Client EDNS0 UDP payload size (e.g. 600 bytes) is respected when smaller than 1232.
        let q_edns_600 = build_query_with_edns0(0x1234, "mid.example", 16, 600);
        let mut resp_550 = build_a_response(
            &build_query(0x1234, "mid.example", 16),
            Ipv4Addr::new(1, 2, 3, 4),
            60,
        );
        resp_550.resize(550, 0);
        assert_eq!(
            fit_response_for_udp(&q_edns_600, resp_550.clone()).expect("fits 600"),
            resp_550
        );
        let mut resp_700 = resp_550;
        resp_700.resize(700, 0);
        let trunc_700 = fit_response_for_udp(&q_edns_600, resp_700).expect("exceeds 600");
        assert_eq!(trunc_700[2] & 0x02, 0x02); // TC=1
    }

    #[tokio::test]
    async fn doh_rejects_invalid_or_missing_content_type() {
        let valid_body = build_a_response(
            &build_query(0x9001, "ct.example", 1),
            Ipv4Addr::new(9, 9, 9, 9),
            60,
        );

        // 1. HTML error page with 200 status must be rejected.
        {
            let (mut client, mut server) = tokio::io::duplex(1024);
            let html = b"<html><body>Captive portal</body></html>";
            let hdr = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\r\n",
                html.len()
            );
            server.write_all(hdr.as_bytes()).await.expect("hdr");
            server.write_all(html).await.expect("body");
            drop(server);
            let err = read_doh_http_response(&mut client)
                .await
                .expect_err("text/html must be rejected");
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        }

        // 2. Non-DNS application/* Content-Type must be rejected.
        {
            let (mut client, mut server) = tokio::io::duplex(1024);
            let hdr = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                valid_body.len()
            );
            server.write_all(hdr.as_bytes()).await.expect("hdr");
            server.write_all(&valid_body).await.expect("body");
            drop(server);
            let err = read_doh_http_response(&mut client)
                .await
                .expect_err("application/json must be rejected");
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        }

        // 3. Missing Content-Type must be rejected.
        {
            let (mut client, mut server) = tokio::io::duplex(1024);
            let hdr = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                valid_body.len()
            );
            server.write_all(hdr.as_bytes()).await.expect("hdr");
            server.write_all(&valid_body).await.expect("body");
            drop(server);
            let err = read_doh_http_response(&mut client)
                .await
                .expect_err("missing Content-Type must be rejected");
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        }

        // 4. Case-insensitive application/dns-message with parameters must succeed.
        {
            let (mut client, mut server) = tokio::io::duplex(1024);
            let hdr = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: APPLICATION/DNS-MESSAGE; charset=binary\r\nContent-Length: {}\r\n\r\n",
                valid_body.len()
            );
            server.write_all(hdr.as_bytes()).await.expect("hdr");
            server.write_all(&valid_body).await.expect("body");
            drop(server);
            let got = read_doh_http_response(&mut client)
                .await
                .expect("case-insensitive application/dns-message with params must succeed");
            assert_eq!(got, valid_body);
        }
    }

    #[test]
    fn doh_pool_generation_rejects_stale_put_after_clear() {
        let mut pool: DohPool<u32> = DohPool::default();
        let now = Instant::now();
        let gen0 = pool.generation();
        pool.put(1, gen0, now);

        let (taken, taken_gen) = pool.take(now);
        assert_eq!(taken, Some(1));
        assert_eq!(taken_gen, gen0);

        // Network change clears the pool and advances generation.
        pool.clear();
        assert_ne!(pool.generation(), gen0);

        // Returning the pre-transition stream must be silently dropped.
        pool.put(1, taken_gen, now);
        assert_eq!(pool.take(now).0, None);

        // A freshly dialed stream at the current generation is accepted.
        let gen1 = pool.generation();
        pool.put(2, gen1, now);
        assert_eq!(pool.take(now).0, Some(2));
    }
}
