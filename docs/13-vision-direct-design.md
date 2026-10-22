# Vision `Direct`: record-bounded TLS stream and raw handoff

This document records the implemented post-Vision-Direct path. The original
plan required both directions to be raw before handoff; the benchmark results
in section 7 led to independent one-way handoffs for each direction.
Sources: `docs/08-vision-xudp-spec.md` §2.3–2.6, `docs/07-reality-spec.md`, `crates/beam-core/src/tls/server.rs`, `crates/beam-core/src/vision/{frame,state}.rs`.

## 1. Why `tokio-rustls` must go

The adapter pre-reads one ClientHello record (`tls/server.rs:395-430`), replays it through
`ReplayStream` (`tls/server.rs:304-337`), then calls `acceptor.accept` (`tls/server.rs:439-445`).
`tokio-rustls` hands the socket to `read_tls` with socket-sized reads; rustls's deframer can
hold bytes that arrived after the record that produced Direct. Those bytes are unreachable
through rustls's API and would be dropped with the connection (§2.3 line 56, §2.5 line 72).
Stock Xray drains `crypto/tls` `input`/`rawInput` (`X/proxy/proxy.go:244-283`), which rustls
does not expose, so the record boundary must belong to beam.

## 2. `TlsStream` (`crates/beam-core/src/tls/stream.rs`)

```rust
pub struct TlsStream {
    socket: TcpStream,
    conn: ServerConnection,
    rec: RecordRead,        // resumable 5-byte header + exact body
    pending: Vec<u8>,       // socket bytes read, not yet fed to rustls (<= 16_640)
    plaintext: Vec<u8>,     // decrypted, with an offset cursor
    outgoing: Vec<u8>,      // encrypted, with an offset cursor
    read_raw: bool,
    write_raw: bool,
}
```

`RecordRead` keeps partially-read header/body bytes, so a cancelled `poll_read` cannot
desynchronise the record stream. `pending` is only the unfed tail of the *current* record; it
exists because `read_tls` may accept a prefix (rustls 0.23.46 grows its deframer buffer in
4 KiB steps, `src/msgs/deframer/buffers.rs:199-214`).

**Read path** (`poll_read`):
1. Return buffered `plaintext` first.
2. If `read_raw`, delegate to the socket.
3. Otherwise, if `pending` is empty, read exactly one record: 5-byte header, validate type
   20/21/22/23, version `0x03xx`, `len <= 16_384 + 256` (RFC 8446 §5.2), then `read_exact`
   the declared body. Never use a larger read.
4. Feed `pending` with `conn.read_tls(&mut &pending[off..])` until the whole record is
   accepted; call `process_new_packets` after each successful feed; drain `conn.reader()`
   into `plaintext` until `WouldBlock`/`Ok(0)`. Return plaintext.

Draining after every `process_new_packets` is mandatory: `read_tls` fails with "received
plaintext buffer full" at 64 KiB (rustls `conn.rs:784-806`). One record yields at most 16 KiB.

**Write path** (`poll_write`):
1. Drain `outgoing` to the socket first; `Pending` stays `Pending` (the socket registers the waker).
2. If `write_raw`, delegate to the socket.
3. Otherwise `conn.writer().write(buf)`, then pump: while `conn.wants_write()` and
   `outgoing.len() < CAP`, call `write_tls` into `outgoing`. Try to flush; return the
   accepted plaintext count.

`poll_flush` pumps until `!wants_write && outgoing.is_empty()`. `poll_shutdown` sends
`send_close_notify()` and flushes only while `!write_raw`; in raw mode it is `shutdown(SHUT_WR)`.

**Handshake**:
```rust
pub async fn accept(socket: TcpStream, conn: ServerConnection, client_hello: Vec<u8>)
    -> io::Result<Self>
```
Seed `pending` with the already-read ClientHello record (no `ReplayStream`). Loop:
feed/process/drain, flush `outgoing`, and read one record while `is_handshaking()` and nothing
is pending. Keep the outer `timeout(config.handshake_timeout)` from `tls/server.rs:441`. After
completion the caller writes the unframed VLESS response header (spec §2.1 line 27) before
wrapping the stream in Vision.

**Raw switch API**:
```rust
pub fn switch_read_to_raw(&mut self);   // buffered plaintext is still returned first
pub fn switch_write_to_raw(&mut self);  // poll_write flushes `outgoing` first
pub fn take_plaintext(&mut self) -> Vec<u8>;
pub fn into_raw(self) -> Result<RawTls, TlsStreamError>;
pub struct RawTls { pub socket: TcpStream, pub inbound: Vec<u8>, pub outbound: Vec<u8> }
```
`inbound = plaintext || pending` (earlier plaintext first). `outbound` is queued outer
ciphertext: `into_raw` drains `sendable_tls` in memory, bounded, before dropping
`ServerConnection`. `into_raw` refuses unless `read_raw`; full handoff also requires
`write_raw`, because the socket is still the TLS writer otherwise.

## 3. Direct transition

1. The Vision reader parses blocks (`vision/frame.rs:115-159`); `VisionReaderState::on_command`
   returns `Direct` (`vision/state.rs:757-779`).
2. Copy `block.content` (it borrows the read buffer) and record the consumed length. Bytes
   after the block in the same outer record are already inner-TLS bytes: `rest`.
3. If the downlink is still framed, `switch_read_to_raw()`, write
   `content || rest || tls.take_plaintext()` to the target now, and continue. This is the
   required transient half-raw state.
4. When the downlink has also fired, call `tls.into_raw()`; the final inbound prefix is
   `content || rest || raw.inbound`. Write `raw.outbound` to the client before any raw
   downlink byte, then both directions are raw on the same socket.
5. No outer `close_notify` after step 4 (§2.3 line 60); raw shutdown sends FIN only.

Step 3 matters: the protocol switches directions independently (§2.4 line 65, §2.6 line 86).
Forcing `write_raw` at the uplink Direct would skip the downlink's first block/UUID and break
stock clients. "Both directions at the same point" is met at the socket handoff.

The coalesced case needs no replay: because the read path consumes one header plus exactly
one body, the first inner-TLS bytes of a Direct-record-plus-inner-ClientHello segment stay in
the kernel receive buffer (§2.3 line 59). `into_raw` yields the socket at exactly those bytes.

## 4. `VisionStream` and the relay

- `VisionStream<S: AsyncRead + AsyncWrite + Unpin>` wraps `TlsStream` after the response
  header. It owns `VisionReaderState`, `VisionWriterState`, the raw request UUID
  (`RequestHeader.user_id`, `vless/header.rs:270-292`), and a bounded buffer.
- Seed the reader with `OwnedRequest.body`; do **not** write it raw to the target as today
  (`tls/server.rs:468-474`). It is the start of the Vision stream, which may be coalesced
  with the header (spec §1 line 20).
- Reader: `Continue` writes content to the target; `End` passes through inside outer TLS;
  `Direct` follows §3.
- Writer: `plan_write` (`vision/state.rs:547-661`), `encode_block`; the first block carries
  the UUID. On `switch_to_direct`, write the Direct block, `flush()` the `TlsStream`, then
  `switch_write_to_raw()`.
- `VisionStream::into_raw()` requires both flags and returns
  `RawConnection { socket, read_prefix, write_prefix }`. Write `read_prefix` to the target,
  `write_prefix` to the client, then call `relay::copy_bidirectional(socket, target)`
  (`relay/splice_copy.rs:202`). Keep both `TcpStream`s alive inside the `spawn_blocking`
  closure; the relay only borrows fds.
- Ordering: prefix writes complete before splice starts. Half-close: splice shuts down the
  sink write half and keeps the other direction running (`splice_copy.rs:12-14`), matching
  §2.5; the pre-Direct loop does the same (`tls/server.rs:617-621`).
- `Direct` followed by an immediate client FIN: the raw read returns 0, the target gets
  `shutdown(SHUT_WR)`, and the downlink response still relays.

## 5. Test plan

Unit tests with a mock record peer; reuse the `NoVerifier` client and memory transport pattern
from `tests/tls_server.rs:22-58`.

- One record per `poll_read`: write `record A || record B || raw`; A yields only A's
  plaintext, and a counting socket still holds B and the raw bytes.
- Split feed: a 16 KiB record forces several `read_tls` calls; full plaintext, no loss, no
  double feed.
- `Direct` and the first inner ClientHello in one `write_all`: `into_raw().socket` starts
  exactly at the inner record; `inbound` is empty.
- Several app records decrypted before the Vision reader stops: `take_plaintext`/`inbound`
  preserve order.
- Direct split across outer records; multiple blocks per record; Direct last.
- FIN immediately after Direct; response still relays.
- Backpressure: small socket buffer, large write; `outgoing` stays bounded.
- Cancellation mid-record: timeout after the header; resumable or clean fatal error, never
  desync.
- After `switch_write_to_raw`, `poll_shutdown` emits no alert record; the first post-Direct
  byte is raw.
- Fuzz the record header/type/length validator.

Interop:
- Stock Xray Vision client (`docs/03-test-plan.md:57-66`) → beam → local HTTPS target:
  assert inner TLS 1.3, the HTTP body, the `direct` counter, and no outer record in a pcap.
- Repeat with sing-box; both clients per `docs/01-compatibility.md`. Force single-segment
  client writes to reproduce record-plus-raw coalescing (§2.3 line 59).

## 6. Risks

- **rustls API limits**: no deframer access, no plaintext length, `read_tls` may accept a
  prefix and errors when its plaintext buffer is full. Owning the record boundary and
  draining eagerly contains all three.
- **Buffer ownership**: Direct content borrows the Vision buffer; copy before `into_raw`.
  `into_raw` must drain `sendable_tls` before dropping `ServerConnection`, or the last outer
  flight is lost.
- **Double encryption**: every write after `switch_write_to_raw` must bypass `conn.writer()`.
  One flag, checked before constructing a `Writer`; never toggle back.
- **`close_notify`**: send it only while `!write_raw`; after Direct it is garbage in the raw stream.
- **Read-ahead loss**: any read larger than header+record body re-introduces it. Do not put
  this stream behind `BufReader` or `tokio::io::copy_buf`.
- **Timeouts**: `poll_read` can be cancelled between header and body; keep resumable state or
  make timeouts fatal (current `copy_direction` is), and cover slow bodies with the idle
  timeout. `write_all` inside `timeout` (`tls/server.rs:611-615`) is not cancellation-safe,
  but a timeout tears the connection down, so no duplicate bytes today.
- **KeyUpdate**: a post-handshake KeyUpdate can queue output on a read-only connection;
  flush `outgoing` opportunistically in `poll_read`.
- **Half-raw is mandatory**: either direction may be raw while the other is
  framed. Never force one socket's raw handoff from the other direction's state.
- **Splice handoff**: fds must be nonblocking (tokio sockets are) and the `TcpStream`s must
  outlive the blocking call.
- **TLS 1.2 / detector**: config rejects TLS 1.2 (`tls/server.rs:217-219`), matching §2.3
  line 57; the downlink writer still inspects target bytes and sees the inner ServerHello.

## 7. Symmetric handoff (implemented)

The local HTTPS benchmark exposed a case the both-directions handoff missed:
the server's Vision writer switches to Direct as soon as the target sends its
first application-data record, but the client may have no further upload to
send. The reader therefore stays framed until the connection closes, and the
old all-or-nothing rule kept the entire download on the tokio copy path
(`framed_down` equalled the full 256 MiB response in instrumentation).

The relay now watches each direction independently:

- **Download**: when `write_direct_watch` fires, duplicate the client write and
  target read descriptors and start a blocking one-way `splice(2)` from target
  to client.
- **Upload**: `read_handoff_watch` fires only after the reader is Direct and
  every already-buffered prefix has been drained: Direct block content, raw
  block remainder, and TLS read-ahead. The async loop has therefore already
  written the ordered plaintext prefix to the target. Duplicate the client read
  and target write descriptors and start a one-way splice from client to
  target.

If both directions become raw, beam keeps two independent one-way relays with
one shared `RelayActivity` deadline. There is no competing full bidirectional
relay and no handoff transition. Each duplicated descriptor is owned exactly
once; the originals remain with the async half until that half stops.

At the measured 211 MiB/s HTTPS rate the relay was waking for every 16-32 KiB
TLS record. Slow bulk directions now accumulate data for 500 µs before one
splice; the 2 MiB rate window disables batching again above 800 MiB/s. Fast
transfers stay on the low-latency path. This reduced the local 256 MiB HTTPS
download server cost from 0.320 to 0.107 s/GiB at throughput parity.

For upload, a 256 MiB HTTP `PUT` with `Expect: 100-continue` (so the stock
client enters upload Direct early) dropped server cost from 0.285-0.289 to
0.109-0.119 s/GiB at ~223 MiB/s. Without the early `100 Continue`, the stock
client sends the whole body framed and only sends a final 24-byte Direct block;
the upload handoff cannot help that client pattern (before 1.34, after 1.37
s/GiB, within noise).
