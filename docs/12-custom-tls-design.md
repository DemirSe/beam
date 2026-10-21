# Minimal custom TLS 1.3 server for REALITY

Status: design only; no code or repository changes. **Reference only:** v1 uses
rustls + aws-lc-pq (ADR 0003). This design is kept for a future feature-flagged
exact-mirroring path.

Scope: an authenticated REALITY server flight that
mirrors `whatsapp.net:443`, with byte-exact fallback. `R/` =
`/tmp/opencode/xray-perf-gaps-ds/upstream/reality-9234c772ba8f`; `X/` =
`/tmp/opencode/xray-rewrite-prep/upstream/xray-v26.3.27-full`; `A/` =
`/tmp/opencode/beam-spike-tls/cover-artifacts/`.

## 1. Target and definition
Stock Xray reuses target ServerHello bytes, replacing only the key share
(`docs/07-reality-spec.md:89-99`; `R/handshake_server_tls13.go:101-129`), pads encrypted records to
target lengths (`docs/07-reality-spec.md:110-120`; `R/conn.go:526-565`), and serves a process-lifetime
Ed25519 cert whose 64-byte X.509 signature is overwritten with `HMAC-SHA512(AuthKey, ed25519_pub)`
(`docs/07-reality-spec.md:100-106`; `R/handshake_server_tls13.go:141-151`). The client checks that HMAC
and skips X.509 verification (`X/transport/internet/reality/reality.go:76-103`).
Captured cover flight (`A/rustls-aws-pq-serverflight.bin`; `docs/10-cover-parity.md:25-35`):

| record | type | bytes | contents / validation |
|---:|---:|---:|---|
| 0 | 22 | 1215 | ServerHello, TLS 1.3, `0x1301`, group `0x11ec`, 32 B session-id echo |
| 1 | 20 | 6 | ChangeCipherSpec `01` |
| 2 | 23 | 1022 | encrypted handshake (EE/Certificate, coalesced) |
| 3 | 23 | 1925 | encrypted handshake (certificate continuation) |
| 4 | 23 | 137 | encrypted handshake (CertificateVerify/Finished) |
The SH key_share extension is 1124 B: group `0x11ec`, key length **1120 B**. Spec clarification:
`docs/07-reality-spec.md:36-37` says 1216 B for the *client* hybrid share (1184 B ML-KEM-768
encapsulation key + 32 B X25519); `docs/07-reality-spec.md:76` gives `1088+32 = 1120 B` for the *server*
share (ML-KEM ciphertext + X25519 public key). The capture proves 1120 B; using 1216 B would make the SH
1311 B and fail. The X25519-only capture is a 127 B SH with a 32 B share (`A/rustls-ring-serverflight.bin`).
"Byte-for-byte" means identical SH bytes except the key share, identical CCS, encrypted record count and
lengths, and identical post-handshake empty-record lengths. Ciphertext cannot match because keys, random,
and key shares differ; the observable shape can.
## 2. Record layer
Module `beam-core::tls::record`; pure state machine, no sockets.
- Header `type:u8 || legacy_version:u16 || length:u16` (5 B). Accept `0x0301`/`0x0303` for the initial CH
  and `0x0303` for encrypted records; reject others.
- Limits: plaintext 16,384 B; TLSCiphertext 16,640 B; full record 16,645 B; handshake message 64 KiB;
  target flight 32 KiB. Never allocate from a wire length without a cap.
- Initial types: handshake 22, CCS 20, alert 21; after keys, outer application_data 23. Zero-length
  handshake/alert/CCS is an error; at most 32 empty app-data records post-handshake.
- AEAD: nonce = 12-byte `iv` XOR the 64-bit sequence in its last 8 bytes (big-endian); AAD = the 5-byte
  outer header with ciphertext length. Sequence starts at 0 per direction/epoch, increments per record,
  and must not wrap.
- Plaintext = `content || inner_type || zeros`. Encrypt, set outer type 23. Decrypt, scan backward for the
  last non-zero byte (inner type), strip trailing zeros, bound the scan by the record length, and reject
  all-zero plaintext.
- Padding: zeros after `inner_type`. For target record length `L`, content capacity is `L - 5 - 16 - 1`
  (header, tag, inner type). Reject `L < 22` or `L > 16,645`.
- CCS is a plaintext 6-byte record (`14 03 03 00 01 01`) and consumes no AEAD sequence.
- Absolute deadlines on every read/write; no `read_to_end`, unbounded `Vec`, or recursion. Fixed 16 KiB
  plaintext and 32 KiB flight buffers, `try_reserve`, hard caps.
## 3. Handshake and key schedule
Module `beam-core::tls::handshake`. ClientHello parsing reuses `beam_core::tls::ClientHello`
(`crates/beam-core/src/tls/client_hello.rs:476-660`); the existing parser handles one record with a
16 KiB cap (`client_hello.rs:26-41,519`). Phase 1 accepts one-record CH and falls back on fragmentation;
phase 2 adds bounded multi-record reassembly (stock accepts fragmented CH, `docs/07-reality-spec.md:174`).
1. Parse CH; run `beam_core::reality::authenticate` (constant-time short-id check,
   `reality/auth.rs:229-236`). Keep raw CH and `AuthKey`; zeroize both after use.
2. Read the cover SH/CCS and encrypted lengths (§4); select target suite/group. Reject if the client did
   not offer that suite or lacks the matching key share.
3. Transcript hash over raw CH handshake message, modified SH handshake message, EE, Certificate,
   CertificateVerify, Finished. Record headers are not hashed; 4-byte handshake headers are.
4. Key schedule (RFC 8446 §7.1; SHA-256 or SHA-384):
   `early=Extract(0,0)`; `derived=DS(early,"derived","")`; `hs=Extract(derived,ECDHE)`;
   `c hs traffic`/`s hs traffic = DS(hs, ..., CH..SH)`; `derived2=DS(hs,"derived","")`;
   `master=Extract(derived2,0)`; after server Finished, `c ap traffic`/`s ap traffic = DS(master, ...,
   CH..server Finished)`; `finished_key=Expand-Label(traffic,"finished","",Hash.len)`;
   `verify_data=HMAC(finished_key, transcript_hash)`. Expand-Label info =
   `u16 len || u8 label_len || "tls13 "+label || u8 context_len || context`; derive `key`/`iv` per secret.
5. EncryptedExtensions: empty body (`08 00 00 02 00 00`), matching stock's no-ALPN behavior
   (`docs/07-reality-spec.md:97-99`). The cover's EE is encrypted; do not guess it.
6. Certificate: one self-signed Ed25519 cert (serial 0, no SAN, fixed validity). Patch its 64-byte
   `signatureValue` with `HMAC-SHA512(AuthKey, ed25519_public_key)`. Locate the signature field by offset,
   not `len-64`; generate the template once and clone per connection. Message = request_context_len=0,
   cert_list_len, cert_len, DER, extensions_len=0.
7. CertificateVerify: scheme `0x0807`; sign `0x20*64 || "TLS 1.3, server CertificateVerify" || 0x00 ||
   transcript_hash` with the real Ed25519 key. This is a normal signature, not the HMAC.
8. Finished: server verify_data over transcript through CV; append Finished to transcript; derive app
   secrets. Read the client's encrypted Finished (ignore client CCS), verify in constant time with the
   client handshake key, install client app keys. Early app data or an unexpected message before Finished
   is fatal once the flight is sent.
9. Optional post-handshake empty app-data records (§4), then hand plaintext to VLESS/Vision.
Suites: `0x1301` AES-128-GCM-SHA256 is mandatory (whatsapp.net selects it,
`docs/10-cover-parity.md:9-10,28`); `0x1302` AES-256-GCM-SHA384 for cover diversity; `0x1303`
ChaCha20-Poly1305-SHA256 for stock clients; CCM `0x1304/0x1305` is not observed, fall back.
Key shares: X25519 group `0x001d`, 32 B, reject low-order/non-contributory results. X25519MLKEM768 group
`0x11ec`: client share 1216 B = 1184 B ML-KEM-768 encapsulation key + 32 B X25519. Generate an X25519
ephemeral, parse/validate the ML-KEM key, encapsulate, and send `ciphertext (1088) || x25519_pub (32)` =
1120 B. Shared secret = `mlkem_shared (32) || x25519_shared (32)` (stock order,
`R/handshake_server_tls13.go:124-128,381-386`). Replace exactly those 1120 bytes in the target SH; keep
group ID and extension lengths.
## 4. Cover mirroring
Adapter in `beam` over sockets; parser/planner pure in `beam-core`.
1. On accept, start `TcpStream::connect(dest)` with a 3 s deadline (stock dials before CH with no timeout,
   `docs/07-reality-spec.md:59-64`). Mirror every client byte as read, including CH and pipelined bytes.
2. Read the target flight into a 32 KiB bounded buffer. Parse without decrypting: SH (header, handshake
   type 2, legacy 0x0303, supported_versions 0x0304, known suite, group/share length 32 or 1120, keep all
   bytes); CCS exactly 6 B with payload 1; encrypted records type 23, length 22..16,645, record only
   lengths. EE/Cert/CV/Finished are encrypted, so their message boundaries are not visible; assign
   positions only for stock-compatible coalescing: records 2..5 map to EE/Cert/CV/Finished and 6 to NST
   (`docs/07-reality-spec.md:74-86`). Collect until 6 total records, 32 KiB, 3 s, or 10 ms
   idle after at least three encrypted records; document and test this heuristic against multiple covers.
3. Reuse target SH bytes; copy the new share into the existing key_share field in place; hash the modified
   handshake message. Keep target random, session-id echo, suite, extensions, and extension order. Send
   target CCS bytes.
4. Build `EE || Certificate || CertificateVerify || Finished` as one handshake byte stream. Do not map
   messages to records: TLS 1.3 permits messages to span records. Split the stream across target
   encrypted capacities (`L-22` each), reserve at least one content byte per record, pad with zeros after
   the inner type, and emit exactly the target lengths. This reproduces the cover's 1022/1925/137 records;
   stock collapses to one 1022 B record when the first encrypted record is >512 B
   (`docs/07-reality-spec.md:78,114-116`). If the stream cannot fit, or there are more records than bytes,
   use stock-compatible one-record coalescing; if that fails, close (never fabricate a flight).
5. One `write_all` for `SH || CCS || encrypted records` from a preallocated 32 KiB buffer; then read and
   verify the client Finished.
6. Post-handshake: bounded cache keyed by `(dest, SNI, alpn_class)` stores cover NST/empty-record lengths.
   Send empty app-data records of those lengths after client Finished, in one write, only if
   `length >= 22`, `length <= 16,645`, count ≤32. Never sleep/retry for a missing entry (stock's 5 s loop
   and `MaxUselessRecords` bugs, `docs/07-reality-spec.md:121-140`).
7. Close the target after parsing the flight (stock does too; it never sees client Finished). Do not send
   client Finished to the cover.
Fallback: any CH parse/auth/SNI/share/target-SH/parse failure before a client byte is sent → blind relay.
The target already has the mirrored CH; write buffered target bytes, then bidirectional copy with
half-close, 5 s idle/close timeouts, optional token bucket, and `splice(2)` where possible
(`docs/07-reality-spec.md:65-67,144-147`). Never send an alert on auth failure. After the server flight is
written, fallback is impossible; close both sides on error. If the target dial fails, close the client; do
not fake a cover.
## 5. Interfaces, errors, limits
`beam-core` boundary (safe Rust; sockets mocked in tests):

```rust
pub trait TlsIo: Read + Write { fn deadline(&mut self, at: Instant); fn shutdown(&mut self, how: Shutdown); }
pub trait CoverIo {
    fn dial(&mut self, dest: &HostPort, timeout: Duration) -> io::Result<()>;
    fn write_ch(&mut self, bytes: &[u8]) -> io::Result<()>;
    fn read_flight(&mut self, out: &mut FlightBuf) -> io::Result<()>;
    fn relay(&mut self, client: &mut dyn TlsIo) -> io::Result<()>;
}
pub struct TlsSession<T: TlsIo> { /* keys, seq, read/write buffers */ }
impl<T: TlsIo> TlsSession<T> {
    pub fn read_app_record(&mut self, out: &mut [u8]) -> Result<usize, TlsError>;
    pub fn write_app_record(&mut self, data: &[u8]) -> Result<(), TlsError>;
    pub fn into_raw(self) -> (T, Vec<u8>); // socket + pending plaintext; no ciphertext read-ahead
}
```

- `beam-core` owns record codec, key schedule, message builders, target parser, padding planner; `beam`
  owns `TcpStream`, deadlines, and `beam-sys` splice; state machine testable without root/network
  (`docs/02-architecture.md:42-55`).
- Exact record framing, no `BufReader`: Vision Direct must hand back the raw socket without losing bytes
  read ahead of the last outer record (`docs/08-vision-xudp-spec.md:55-56`); `into_raw` returns pending
  decrypted plaintext separately.
- `TlsError`: `Io`, `Timeout`, `RecordOverflow`, `UnexpectedType`, `BadHandshake`, `BadFinished`,
  `BadCertificate`, `Auth`, `CoverUnavailable`, `CoverInvalid`, `Limit`, `Cancelled`.
  `is_fallback_safe()` only for auth/parse/cover failures before any client flight byte.
- Cancellation: one absolute `Deadline` per connection plus `CancelToken`; supervisor calls
  `shutdown(Both)`; no blocking call without a deadline.
- Limits: CH 16 KiB (phase 1; 64 KiB reassembled later); target flight 32 KiB; encrypted record 16,645 B;
  post-handshake records 32; handshake 10 s; target dial 3 s; target flight 5 s; client Finished 5 s;
  fallback idle 300 s; replay cache 4,096 entries, TTL = `max_time_diff` or 60 s. Worst-case buffers
  ~80 KiB/connection.
- Replay cache: key = 32-byte session-id ciphertext (or client X25519 share); hit → fallback (stock has
  none, `docs/07-reality-spec.md:48-52`). Bounded, swept; never store raw CH or keys.
- Logging: no AuthKey, short id, cert signature, or raw CH. Auth failure logs debug with a generic reason;
  client-visible behavior is only cover relay.
## 6. Crates and build
Versions checked on crates.io 2026-10-22; toolchain 1.99.1 (all MSRV ≤1.88).

| crate | version | use | note |
|---|---|---|---|
| `ml-kem` | 0.3.3 | ML-KEM-768 | pure Rust; sizes verified 1184/1088/32; enable `zeroize`; **no hybrid group**, compose manually |
| `x25519-dalek` | 3.0.0 | X25519 | `static_secrets`, `zeroize`; 32/32 |
| `aes-gcm` | 0.11.1 | AES-128/256-GCM | 16 B tag, 12 B nonce |
| `chacha20poly1305` | 0.11.0 | ChaCha20-Poly1305 | 16 B tag |
| `sha2` | 0.11.1 | SHA-256/384 | transcript and HKDF |
| `hkdf` | 0.13.0 | HKDF-Extract/Expand | `expand` with RFC 8446 label info |
| `hmac` | 0.13.0 | Finished, cert HMAC | SHA-512 for cert |
| `ed25519-dalek` | 3.0.0 | cert key + CertificateVerify | 32 B pub, 64 B sig |
| `x509-cert` | 0.3.0 | minimal cert DER | builder supports `signature::Signer`; or small DER emitter |
| `zeroize` | 1.9.1 | secrets | derive/Zeroizing |
| `subtle` | 2.6.1 | Finished compare | constant time |
| `getrandom` | 0.4.3 | ephemeral seeds | OS RNG only |
`rcgen` 0.14.10 is viable but adds a crypto backend and extra extensions; prefer `x509-cert`/explicit DER
so the 64-byte signature offset is deterministic. No C/C++ dependency or CMake/libclang; add only to
`beam-core`, not `beam-sys`; `cargo build` remains a plain Rust build.
## 7. LOC, phases, tests

| phase | deliverable | production LOC | exit |
|---|---|---:|---|
| 0 | RFC 8448 + stock/cover fixtures; record/transcript harness | 150 | fixtures parse and hash |
| 1 | record codec, AEAD, padding, sequence | 900 | RFC 8448 records/keys match |
| 2 | key schedule, transcript, Finished | 450 | RFC 8448 secrets/verify_data match |
| 3 | SH/EE/Cert/CV/Finished, Ed25519, HMAC cert | 800 | stock Xray client completes handshake |
| 4 | target parser, SH reuse, split/pad planner, fallback | 1,100 | golden artifacts + live cover |
| 5 | hybrid X25519MLKEM768, all three suites | 500 | stock/sing-box PQ interop |
| 6 | post-handshake records, replay cache, limits | 500 | soak/fuzz clean |
| 7 | fuzz, differential, security review | tests 2,500 | release gates |
Estimate **~4,400 production LOC + ~2,500 test/fuzz LOC**; 8-12 engineer-weeks including review and
interop. The TLS state machine is small compared with the compatibility matrix and failure testing.
Test vectors: RFC 8448 §2 (simple 1-RTT, X25519/AES-128-GCM-SHA256) for secrets, keys, IVs, Finished; RFC
8448 §5 for HelloRetryRequest/transcript edges (not on the normal path); NIST ACVP ML-KEM-768 vectors plus
`ml-kem` crate tests; hybrid shared-secret order. Use the stock fixture
`crates/beam-core/tests/fixtures/stock-client-hello.bin` and existing auth tests. Golden tests on
`A/rustls-aws-pq-serverflight.bin`: SH parse, group/share lengths, exact record plan
`[1215,6,1022,1925,137]`, and every SH byte except the 1120-byte share preserved. Interop with live cover
and stock Xray/sing-box/Hiddify; replay, wrong SNI/short id, TLS 1.2, fragmented CH, oversized target
record, missing CCS, coalesced flight, NST cache miss, half-close, silent target. `cargo-fuzz` targets:
CH/record reassembly, record decrypt/padding, target-flight parser, split planner, cert DER offset; no
panic, unbounded allocation, or out-of-bounds read.
Security review: independent review of HKDF labels/key schedule, AEAD nonce reuse, constant-time Finished,
X25519 low-order/ML-KEM key validation, cert signature patch, fallback indistinguishability (no
alerts/timing oracle), replay cache, and every length/deadline.
## 8. Recommendation: custom vs rustls + aws-lc-pq

| property | rustls + aws-lc-pq | custom TLS |
|---|---|---|
| unauthenticated probe | exact cover relay (`docs/09-tls-stack-spike.md:116-118`) | exact cover relay |
| group/cipher/ALPN | matches cover (`docs/10-cover-parity.md:9-10,28`) | matches target SH |
| ServerHello bytes | generated; only size/group match | target bytes, key share replaced |
| cert chain | one small Ed25519 cert | one Ed25519 cert, padded |
| encrypted flight | no padding; shorter than cover (spike's rustls PQ flight 1961 B with ECDSA cert, `docs/09-tls-stack-spike.md:105`; cover 4305 B, `docs/10-cover-parity.md:28`) | exact target count/lengths |
| post-handshake records | not mirrored | cached target lengths |
| delivery / risk | 1-2 weeks / low | 8-12 weeks / high |
ADR 0003 acknowledges the cert/flight gap: the temporary Ed25519 cert is smaller than the cover's EC
chain (`docs/adr/0003-tls-stack.md:52-54`); docs/10 reports the cover's 4305 B. rustls cannot pad or reuse the target SH
(`docs/09-tls-stack-spike.md:129-130`), so it is **not byte-for-byte** on the authenticated path. The
4305 B figure is the cover's flight observed by a client probe, not a rustls server flight. Custom also
adds one cover TCP RTT to every authenticated handshake and leaves the cover with an incomplete handshake;
ADR 0003 deliberately removed that RTT for rustls (`docs/adr/0003-tls-stack.md:40-43`).
Necessity: if "byte-for-byte" is a literal release requirement, **custom TLS is necessary**; no stock
rustls API exposes handshake-record padding or target-SH reuse. For the ordinary REALITY threat model (an
unauthenticated prober), **custom TLS is over-engineering**: both relay the prober to the real cover
byte-for-byte. The residual difference is visible only to an authenticated client, or to an observer that
can capture/replay a valid ClientHello and compare the authenticated flight. Stock REALITY accepts replayed
CHs (no cache, `docs/07-reality-spec.md:48-52`), so replay-based active probing is the one scenario where
custom padding has real value. Recommended path: keep **rustls + aws-lc-pq** as the v1 production stack
(current ADR 0003, `docs/adr/0003-tls-stack.md:34-38`), build the cover-parity/replay harness first, and
implement this custom layer behind a compile-time feature only if the harness proves the flight-size gap
exploitable. If the owner makes literal byte-for-byte a blocker, treat this as the design and budget the
full 8-12 weeks plus external crypto review; do not ship a partial TLS stack.
