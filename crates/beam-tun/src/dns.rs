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
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use beam_core::address::{Address, NetLocation};
use beam_core::client::{BeamClientConfig, XudpClient, XudpClientConfig, dial_tcp};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{Semaphore, mpsc};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tracing::debug;

use crate::packet::build_ip_udp_packet;

const MAX_DNS_QUERY_BYTES: usize = 1232;
const MAX_DNS_RESPONSE_BYTES: usize = 4096;
const MAX_HTTP_HEADER_BYTES: usize = 8192;
const MAX_INFLIGHT_DNS_QUERIES: usize = 128;
const DEFAULT_CACHE_SIZE: usize = 1024;
const MAX_CACHE_SIZE: usize = 16_384;
const MIN_CACHE_TTL_SECS: u32 = 5;
const MAX_CACHE_TTL_SECS: u32 = 3600;
const NEGATIVE_CACHE_TTL_SECS: u32 = 15;
const DEFAULT_QUERY_TIMEOUT: Duration = Duration::from_secs(4);
const MAX_DNS_NAME_LEN: usize = 255;
const MAX_DNS_LABELS: usize = 128;
const MAX_POINTER_HOPS: usize = 16;
const MAX_RR_COUNT: usize = 128;

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
            return Ok(Self::PlainTcp(addr));
        }
        if let Some(rest) = s.strip_prefix("udp://") {
            let addr: SocketAddr = rest
                .parse()
                .map_err(|_| format!("invalid udp:// DNS address: {rest}"))?;
            return Ok(Self::PlainUdp(addr));
        }
        let addr: SocketAddr = s
            .parse()
            .map_err(|_| format!("invalid DNS upstream (use https://, tcp://, or ip:port): {s}"))?;
        Ok(Self::PlainUdp(addr))
    }
}

fn split_host_port(authority: &str, default_port: u16) -> Result<(&str, u16), String> {
    if let Some(bracketed) = authority.strip_prefix('[') {
        let end = bracketed
            .find(']')
            .ok_or_else(|| "unclosed IPv6 bracket in DoH authority".to_owned())?;
        let host = &bracketed[..end];
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

/// Configuration for the built-in [`DnsInterceptor`].
#[derive(Clone)]
pub struct DnsConfig {
    /// Upstream resolver reached through the `beam` tunnel.
    pub upstream: DnsUpstream,
    /// Optional local DNS server reached directly (outside the tunnel) for
    /// `local_suffixes` and `bypass_domains`.
    pub local_upstream: Option<SocketAddr>,
    /// Local-only suffixes (e.g. `["lan", "local", "internal"]`).
    pub local_suffixes: Vec<String>,
    /// Additional user-configured bypass domain suffixes.
    pub bypass_domains: Vec<String>,
    /// Maximum cached DNS responses (`0` disables caching).
    pub cache_size: usize,
    /// Per-query upstream timeout.
    pub query_timeout: Duration,
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
            local_suffixes: Self::default_local_suffixes(),
            bypass_domains: Vec::new(),
            cache_size: DEFAULT_CACHE_SIZE,
            query_timeout: DEFAULT_QUERY_TIMEOUT,
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
    if qdcount == 0 {
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
    })
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
    if wire.len() < 12 || wire.len() > MAX_DNS_RESPONSE_BYTES {
        return (None, Vec::new());
    }
    let flags = u16::from_be_bytes([wire[2], wire[3]]);
    if (flags & 0x8000) == 0 {
        return (None, Vec::new());
    }
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
            break;
        };
        let Some(rd_header_end) = next.checked_add(10) else {
            break;
        };
        if rd_header_end > wire.len() {
            break;
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
            break;
        };
        if rdata_end > wire.len() {
            break;
        }
        let rdata = &wire[rd_header_end..rdata_end];
        min_ttl = Some(min_ttl.map_or(ttl, |cur| cur.min(ttl)));
        if rclass == 1 {
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

    let ttl = match rcode {
        0 => min_ttl.map(|t| t.clamp(MIN_CACHE_TTL_SECS, MAX_CACHE_TTL_SECS)),
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
    let mut resp = Vec::with_capacity(question_end);
    resp.extend_from_slice(&query_wire[..2]); // tx_id
    let rd = query_wire[2] & 0x01;
    resp.push(0x80 | rd); // QR=1, RD preserved
    resp.push(0x82); // RA=1, RCODE=2 (SERVFAIL)
    resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    resp.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT=0
    resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT=0
    resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT=0
    resp.extend_from_slice(&query_wire[12..question_end]);
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
}

struct CacheEntry {
    wire: Vec<u8>,
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

    /// Looks up a cached response and rewrites its 2-byte `tx_id`.
    pub fn get(&mut self, query: &DnsQuery, now: Instant) -> Option<Vec<u8>> {
        if self.max_entries == 0 {
            return None;
        }
        let key = CacheKey {
            qname: query.qname.clone(),
            qtype: query.qtype,
            qclass: query.qclass,
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
        let mut wire = entry.wire.clone();
        if wire.len() >= 2 {
            let id = query.tx_id.to_be_bytes();
            wire[0] = id[0];
            wire[1] = id[1];
        }
        Some(wire)
    }

    /// Inserts a DNS response with `ttl_secs`, evicting expired or LRU entries
    /// if the cache is full.
    pub fn insert(
        &mut self,
        query: &DnsQuery,
        wire: Vec<u8>,
        ttl_secs: u32,
        is_local: bool,
        now: Instant,
    ) {
        if self.max_entries == 0 || wire.len() < 12 || wire.len() > MAX_DNS_RESPONSE_BYTES {
            return;
        }
        let key = CacheKey {
            qname: query.qname.clone(),
            qtype: query.qtype,
            qclass: query.qclass,
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

/// Non-blocking DNS interceptor embedded in `beam-tun`'s engine loop.
pub struct DnsInterceptor {
    client_config: BeamClientConfig,
    dns_config: DnsConfig,
    tls_config: Arc<ClientConfig>,
    cache: Arc<Mutex<DnsCache>>,
    inflight: Arc<Semaphore>,
    tun_tx: mpsc::Sender<Vec<u8>>,
}

impl DnsInterceptor {
    /// Creates a new [`DnsInterceptor`] writing synthesized UDP/53 replies into `tun_tx`.
    pub fn new(
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
        Self {
            client_config,
            dns_config,
            tls_config,
            cache,
            inflight: Arc::new(Semaphore::new(MAX_INFLIGHT_DNS_QUERIES)),
            tun_tx,
        }
    }

    /// Clears local-only cache entries on network transitions.
    pub fn on_network_change(&self) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.clear_local();
        }
    }

    /// Handles one intercepted UDP/53 query packet without blocking the TUN loop.
    pub fn handle_query(&self, src: SocketAddr, dst: SocketAddr, wire: &[u8]) {
        let Some(query) = parse_dns_query(wire) else {
            return;
        };

        // Fast path: synchronous cache hit (0 ms latency).
        if let Ok(mut cache) = self.cache.lock()
            && let Some(cached) = cache.get(&query, Instant::now())
        {
            if let Some(pkt) =
                build_ip_udp_packet(dst.ip(), dst.port(), src.ip(), src.port(), &cached)
            {
                let _ = self.tun_tx.try_send(pkt);
            }
            return;
        }

        let Ok(permit) = Arc::clone(&self.inflight).try_acquire_owned() else {
            debug!(qname = %query.qname, "DNS concurrency limit reached; dropping query");
            return;
        };

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
        let use_local = (is_local || is_bypass_domain) && self.dns_config.local_upstream.is_some();

        let wire_owned = wire.to_vec();
        let client_cfg = self.client_config.clone();
        let dns_cfg = self.dns_config.clone();
        let tls_cfg = Arc::clone(&self.tls_config);
        let cache = Arc::clone(&self.cache);
        let tun_tx = self.tun_tx.clone();

        tokio::spawn(async move {
            let _permit = permit;
            let result = if use_local {
                match dns_cfg.local_upstream {
                    Some(local_addr) => {
                        resolve_local_udp(local_addr, &wire_owned, dns_cfg.query_timeout).await
                    }
                    None => Err(io::Error::other("no local DNS upstream configured")),
                }
            } else {
                resolve_tunneled(
                    &client_cfg,
                    &dns_cfg.upstream,
                    &tls_cfg,
                    &wire_owned,
                    dns_cfg.query_timeout,
                )
                .await
            };

            let reply_wire = match result {
                Ok(mut resp) if resp.len() >= 12 && resp.len() <= MAX_DNS_RESPONSE_BYTES => {
                    // Ensure tx_id matches the client query.
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
                        guard.insert(&query, resp.clone(), ttl, use_local, Instant::now());
                    }
                    Some(resp)
                }
                Ok(_) => build_servfail_response(&wire_owned),
                Err(err) => {
                    debug!(qname = %query.qname, local = use_local, error = %err, "DNS resolution failed");
                    build_servfail_response(&wire_owned)
                }
            };

            if let Some(resp) = reply_wire
                && let Some(pkt) =
                    build_ip_udp_packet(dst.ip(), dst.port(), src.ip(), src.port(), &resp)
            {
                let _ = tun_tx.try_send(pkt);
            }
        });
    }
}

async fn resolve_local_udp(
    local_upstream: SocketAddr,
    query: &[u8],
    query_timeout: Duration,
) -> io::Result<Vec<u8>> {
    let bind_addr: SocketAddr = match local_upstream {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let sock = UdpSocket::bind(bind_addr).await?;
    sock.connect(local_upstream).await?;
    timeout(query_timeout, sock.send(query))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "local DNS send timed out"))??;
    let mut buf = vec![0u8; MAX_DNS_RESPONSE_BYTES];
    let n = timeout(query_timeout, sock.recv(&mut buf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "local DNS recv timed out"))??;
    buf.truncate(n);
    Ok(buf)
}

async fn resolve_tunneled(
    client_cfg: &BeamClientConfig,
    upstream: &DnsUpstream,
    tls_cfg: &Arc<ClientConfig>,
    query: &[u8],
    query_timeout: Duration,
) -> io::Result<Vec<u8>> {
    timeout(query_timeout, async {
        match upstream {
            DnsUpstream::Doh { host, port, path } => {
                resolve_doh_over_beam(client_cfg, tls_cfg, host, *port, path, query).await
            }
            DnsUpstream::PlainTcp(addr) => resolve_tcp_over_beam(client_cfg, *addr, query).await,
            DnsUpstream::PlainUdp(addr) => resolve_udp_over_beam(client_cfg, *addr, query).await,
        }
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tunneled DNS query timed out"))?
}

async fn resolve_tcp_over_beam(
    client_cfg: &BeamClientConfig,
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
    let mut stream = dial_tcp(client_cfg, dest)
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;
    let len_u16 = u16::try_from(query.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "DNS query too large"))?;
    stream.write_all(&len_u16.to_be_bytes()).await?;
    stream.write_all(query).await?;
    stream.flush().await?;

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let resp_len = usize::from(u16::from_be_bytes(len_buf));
    if !(12..=MAX_DNS_RESPONSE_BYTES).contains(&resp_len) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid DNS-over-TCP response length",
        ));
    }
    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp).await?;
    Ok(resp)
}

async fn resolve_udp_over_beam(
    client_cfg: &BeamClientConfig,
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
    let mux = XudpClient::connect(client_cfg, XudpClientConfig::default())
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;
    let mut session = mux
        .open_session(dest.clone())
        .map_err(|e| io::Error::other(e.to_string()))?;
    session
        .send_to(dest, query)
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;
    let reply = session.recv().await.ok_or_else(|| {
        io::Error::new(io::ErrorKind::UnexpectedEof, "XUDP closed before DNS reply")
    })?;
    let _ = session.close().await;
    Ok(reply.payload)
}

async fn resolve_doh_over_beam(
    client_cfg: &BeamClientConfig,
    tls_cfg: &Arc<ClientConfig>,
    host: &str,
    port: u16,
    path: &str,
    query: &[u8],
) -> io::Result<Vec<u8>> {
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

    let host_header = if port == 443 {
        host.to_owned()
    } else {
        format!("{host}:{port}")
    };
    let req = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host_header}\r\n\
         Content-Type: application/dns-message\r\n\
         Accept: application/dns-message\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        query.len()
    );
    tls.write_all(req.as_bytes()).await?;
    tls.write_all(query).await?;
    tls.flush().await?;

    read_doh_http_response(&mut tls).await
}

async fn read_doh_http_response<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
) -> io::Result<Vec<u8>> {
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
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim();
            let val = v.trim();
            if key.eq_ignore_ascii_case("content-length") {
                content_length = val.parse::<usize>().ok();
            } else if key.eq_ignore_ascii_case("transfer-encoding")
                && val.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
            }
        }
    }

    let mut body = buf[header_end + 4..].to_vec();
    if let Some(len) = content_length {
        if !(12..=MAX_DNS_RESPONSE_BYTES).contains(&len) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DoH Content-Length out of bounds",
            ));
        }
        while body.len() < len {
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "EOF reading DoH body",
                ));
            }
            let take = n.min(len - body.len());
            body.extend_from_slice(&tmp[..take]);
        }
        body.truncate(len);
        return Ok(body);
    }

    // Read until EOF (bounded) for chunked or Connection: close without Content-Length.
    while body.len() <= MAX_DNS_RESPONSE_BYTES + 256 {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }

    if chunked {
        decode_chunked_body(&body)
    } else if body.len() <= MAX_DNS_RESPONSE_BYTES {
        Ok(body)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DoH response body exceeded bound",
        ))
    }
}

fn find_crlf_crlf(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|w| w == b"\r\n\r\n")
}

fn decode_chunked_body(raw: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < raw.len() {
        let Some(rel_end) = raw[pos..].windows(2).position(|w| w == b"\r\n") else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed chunked DoH size line",
            ));
        };
        let size_line = std::str::from_utf8(&raw[pos..pos + rel_end])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid chunk size UTF-8"))?;
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let chunk_len = usize::from_str_radix(size_hex, 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid chunk size hex"))?;
        pos += rel_end + 2;
        if chunk_len == 0 {
            return Ok(out);
        }
        if out.len().saturating_add(chunk_len) > MAX_DNS_RESPONSE_BYTES
            || pos.saturating_add(chunk_len + 2) > raw.len()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunked DoH body exceeded bound",
            ));
        }
        out.extend_from_slice(&raw[pos..pos + chunk_len]);
        pos += chunk_len + 2;
    }
    Err(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "missing terminal 0 chunk in DoH body",
    ))
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
    fn cache_rewrites_tx_id_expires_and_evicts_lru() {
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

        cache.insert(&q1, r1, 30, false, t0);
        cache.insert(&q2, r2, 30, true, t0);

        // Touch q1 with a different tx_id -> must rewrite tx_id and refresh LRU.
        let q1_again = DnsQuery {
            tx_id: 0x9999,
            ..q1.clone()
        };
        let hit = cache
            .get(&q1_again, t0 + Duration::from_secs(5))
            .expect("hit");
        assert_eq!(u16::from_be_bytes([hit[0], hit[1]]), 0x9999);

        // Insert q3 -> evicts LRU (q2).
        cache.insert(&q3, r3, 30, false, t0 + Duration::from_secs(6));
        assert!(cache.get(&q2, t0 + Duration::from_secs(7)).is_none());
        assert!(cache.get(&q1, t0 + Duration::from_secs(7)).is_some());

        // Expired after TTL.
        assert!(cache.get(&q1, t0 + Duration::from_secs(31)).is_none());
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
        assert!(DnsUpstream::parse("http://1.1.1.1/dns-query").is_err());
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
    }
}
