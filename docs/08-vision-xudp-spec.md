# VLESS Vision + XUDP wire specification

Roots: `X/` = `/tmp/opencode/xray-rewrite-prep/upstream/xray-v26.3.27-full`; `SB/` = sing-box v1.14.2; `SV/` = sing-vmess v0.2.8 (pinned by `SB/go.mod:60`). SB/SV are external upstream sources used for client compatibility; X/ citations are the requested tree. Markers: **[D]** direct code evidence, **[I]** inference/implementation requirement, **[U]** unverified.

## 1. VLESS request/response header

- [D] Request: `version(1)=0 | UUID(16) | addons_len(1) | addons | command(1) | [port(2 BE) | atyp(1) | address]`; address/port are omitted for Mux/Rvs. `X/proxy/vless/encoding/encoding.go:29-61`.
- [D] `atyp`: 1=IPv4(4), 2=domain(1-byte len+bytes), 3=IPv6(16); port is big-endian and precedes atyp. `X/common/protocol/payload.go:12-16`, `X/common/protocol/address.go:15-19,105-111,144-153,193-222`.
- [D] Commands: 1 TCP, 2 UDP, 3 Mux, 4 Rvs. `X/common/protocol/headers.go:15-18`.
- [D] Addons protobuf: `string Flow = 1; bytes Seed = 2`. Only `xtls-rprx-vision` is emitted; other flows get addons_len 0. Seed is unused. `X/proxy/vless/encoding/addons.proto:9-12`, `X/proxy/vless/vless.go:8-11`, `X/proxy/vless/encoding/addons.go:17-37`.
- [D] Vision addons use `addons_len=0x12` (18), followed by `0x0A 0x10` + `"xtls-rprx-vision"` (16 ASCII bytes). `X/proxy/vless/encoding/addons.go:19-29`, sing-box builds the same at `SV/vless/protocol.go:150-154`.
- [D] The decoder accepts any 1-byte addons length and protobuf-decodes it; it does not validate Flow at this layer. `X/proxy/vless/encoding/addons.go:39-63`.
- [D] Response: `version(1) | addons_len(1) | addons`; Xray always sends `00 00` and does not echo flow. `X/proxy/vless/encoding/encoding.go:134-152`, `X/proxy/vless/inbound/inbound.go:546-548,618-621`.
- [D] Response version must equal request version (0). `X/proxy/vless/encoding/encoding.go:155-173`.
- [D] Unknown version or malformed header is rejected, or falls back if configured; unknown flow and flow/account mismatch are rejected after header decode. `X/proxy/vless/encoding/encoding.go:129-131`, `X/proxy/vless/inbound/inbound.go:552-598`.
- [D] Authentication zeroes UUID bytes 6-7 before lookup (`ProcessUUID`); the raw 16 header bytes are retained as `userSentID` and drive `VlessRoute` and the Vision prefix. `X/proxy/vless/validator.go:21-25,42,63`, `X/proxy/vless/inbound/inbound.go:299,538,612`.
- [I] Accept any bytes in positions 6-7 for auth, but use the raw 16 bytes in the Vision prefix; do not substitute the stored UUID there.
- [D] The request body's first Vision block repeats the same 16 UUID bytes, so the UUID appears twice in the first flight; the server's first downlink block prefixes it once. `X/proxy/proxy.go:304-319,519-522`, `X/proxy/vless/inbound/inbound.go:612`.
- [D] Mux/Rvs carry no address; the server substitutes `v1.mux.cool`/`v1.rvs.cool`. Internal port 666 is never on the wire. `X/proxy/vless/encoding/encoding.go:50-53,114-124`, `X/proxy/vless/outbound/outbound.go:315-319`.
- [D] Clients may coalesce the request header with the first payload (sing-box `SV/vless/protocol.go:124-167`); the server must decode the header from a buffered stream and preserve trailing bytes as body. `X/proxy/vless/encoding/encoding.go:64-128`.
- [D] The default header read deadline is 60 s and is cleared after a successful decode. `X/proxy/vless/inbound/inbound.go:281-284,527-529`, `X/features/policy/policy.go:118-123`.

## 2. Vision framing

### 2.1 Block format and receive state

- [D] The VLESS request/response header is outside Vision framing and is never padded; only body bytes become Vision blocks. Header and first block are coalesced by the initial flush. `X/proxy/vless/outbound/outbound.go:324-356`, `X/proxy/vless/inbound/inbound.go:618-623`.
- [D] Block: `[UUID(16) first block only] | command(1) | content_len(2 BE) | padding_len(2 BE) | content | zero padding`. Padding is ignored. `X/proxy/proxy.go:496-532`.
- [D] Commands: `0x00` Continue (another header follows), `0x01` End (stop padding; remaining bytes raw inside outer transport), `0x02` Direct (stop padding; outer TLS/REALITY bypassed). `X/proxy/proxy.go:52-59`.
- [D] The UUID prefix is emitted once per direction; both client uplink and server downlink must send it at the start of their body. `X/proxy/proxy.go:298,519-522`.
- [D] Initial receive state is all lengths -1. Framing is recognized only if the first buffered chunk is >=21 bytes and its first 16 bytes equal the user UUID; otherwise the whole body is passed unframed. `X/proxy/proxy.go:142-171,551-557`.
- [I] Buffer at least 21 bytes before choosing "unframed"; otherwise a short first TCP read permanently disables unpadding.
- [D] The parser keeps state across reads, handles multiple blocks per read, strips padding, and emits content. `X/proxy/proxy.go:534-616`.

### 2.2 Padding rules (symmetric in both directions)

- [D] While writer `IsPadding` is true, every buffer is wrapped. Client uplink uses `Outbound.IsPadding`; server downlink uses `Inbound.IsPadding`. `X/proxy/proxy.go:322-332,352-394`.
- [D] Long padding: if `content_len < seed[0]` and TLS was detected, `padding_len = rand[0,seed[1]) + seed[2] - content_len`, so content+padding is 900..1399. Defaults `seed={900,500,900,256}`. `X/proxy/proxy.go:304-319,496-514`.
- [D] Short padding: otherwise `padding_len = rand[0,seed[3])` = 0..255. Even in long mode, content >=900 gets only short padding. `X/proxy/proxy.go:502-514`.
- [D] Padding is clamped to `8192-21-content_len`; buffers are split at a TLS app-data boundary or 4096 so content fits. `X/proxy/proxy.go:502-517,460-493`.
- [D] Long padding covers TLS handshake records and the first no-payload block; it stops when a write consists solely of complete application-data records, or after the non-TLS filter budget. `X/proxy/proxy.go:362-393`.
- [D] If the link reader supports a 500 ms timeout and no client payload arrives, the client sends an empty block (UUID + header + 900..1399 padding, command Continue) to hide the header length. `X/proxy/vless/outbound/outbound.go:334-349`, `X/proxy/proxy.go:356-359`.
- [D] Non-TLS: after at most 8 inspected buffers (`NumberOfPacketToFilter=8`), the current block is marked End and later buffers are raw. `X/proxy/proxy.go:145,379-383,624,666-669`.
- [D] Header + first block are flushed together: client via `SetBuffered(false)`, server via `SetFlushNext()`; later server writes are unbuffered. `X/proxy/vless/outbound/outbound.go:353-356`, `X/proxy/vless/inbound/inbound.go:618-623`, `X/common/buf/writer.go:144-146,165-169,211-216`.
- [D] All padded blocks from one `WriteMultiBuffer` go in one underlying write. `X/proxy/proxy.go:395`.

### 2.3 TLS detection and exact Direct trigger

- [D] Up to 8 buffers total (reader and writer share the counter) are scanned. Signatures: ClientHello `16 03` + type 1; ServerHello `16 03 03` + type 2; app data `17 03 03`. `X/proxy/proxy.go:37-41,618-669`.
- [D] `IsTLS` is set on ClientHello or ServerHello; `IsTLS12orAbove` on ServerHello. The cipher is the 2 bytes at offsets `43+session_id_len+1` and `+2`. `X/proxy/proxy.go:625-637`.
- [D] `EnableXtls` requires the ServerHello to contain supported_versions `00 2b 00 02 03 04`, a known TLS 1.3 cipher, and not `TLS_AES_128_CCM_8_SHA256` (0x1305); a ServerHello <79 bytes cannot enable it. `X/proxy/proxy.go:631-634,643-658`.
- [D] Direct trigger: `IsTLS && buffer[0:3]==17 03 03 && IsCompleteRecord(whole MultiBuffer) && EnableXtls`. The last padded block of that write gets Direct; earlier appdata blocks get Continue. `X/proxy/proxy.go:360-375,406-458`.
- [D] The writer switches at the next `WriteMultiBuffer`: the current batch (including Direct) still uses outer TLS, then `w.Writer` becomes the raw TCP writer. `X/proxy/proxy.go:334-347,395-403`.
- [D] Without `EnableXtls`, the first appdata record ends padding with End and traffic remains inside outer TLS. `X/proxy/proxy.go:364-376`.
- [D] Receiver on Direct: emits the block content, forwards leftover bytes after that block, drains TLS stack read-ahead (`input`/`rawInput`), then reads the raw conn. `X/proxy/proxy.go:244-253,259-283,603-609`.
- [I] A userspace TLS stack must preserve socket bytes read ahead beyond the last outer TLS record, or the first post-Direct inner-TLS bytes are lost. Xray reads crypto/tls `input`/`rawInput` at `X/proxy/vless/inbound/inbound.go:583-586` and replays them at `X/proxy/proxy.go:261-266`.
- [D] For standard TLS transport, Vision flow requires outer TLS 1.3; REALITY and the optional VLESS-encryption wrapper are also accepted, while plain TCP is rejected. Outer TLS 1.2 is rejected. `X/proxy/vless/inbound/inbound.go:552-598`, `X/proxy/vless/outbound/outbound.go:358-367`.
- [D] Raw writes go to `UnwrapRawConn`, which unwraps TLS, uTLS, REALITY, masks, and proxy-protocol wrappers. `X/proxy/proxy.go:334-347,672-713`.
- [U] Xray sends no gap before post-Direct raw writes; sing-box inserts 5 ms. Flush the Direct block and avoid coalescing raw bytes into the same TCP segment/read; 5 ms is the conservative choice. `SV/vless/vision.go:220-235`.
- [U] Close after Direct is unspecified. An outer TLS close_notify would appear as garbage in the raw stream; prefer aborting the raw socket. No special handling found at `X/app/proxyman/inbound/worker.go:130-134`.

### 2.4 Encryption boundary

- [D] Before Direct, Vision blocks and padding travel inside the outer TLS/REALITY connection; base VLESS adds no encryption (the optional VLESS-encryption handshake is a separate pre-layer). `X/proxy/vless/encoding/encoding.go:29-61`, `X/proxy/proxy.go:496-532`.
- [D] After Direct in a direction, that direction bypasses the outer record layer and writes raw TCP; the other direction stays outer-encrypted until its own Direct. `X/proxy/proxy.go:228-233,259-283,334-347`.
- [D] Direct is entered only on inner TLS app data, so raw bytes are inner-TLS ciphertext; the client's TLS session with the destination remains end-to-end encrypted. REALITY exists only in the outer handshake. `X/proxy/proxy.go:364-375`.
- [D] End (not Direct) means data remains inside the outer transport but is no longer Vision-framed. `X/proxy/proxy.go:600-609`.

### 2.5 Half-close, EOF, errors, timeouts

- [D] Vision has no close/fin frame; End stops padding, Direct changes transport only. `X/proxy/proxy.go:52-59,599-609`.
- [D] Underlying EOF is returned unchanged and `XtlsRead` maps `io.EOF` to success; a TCP FIN ends one relay direction without closing the other. `X/proxy/proxy.go:203-207`, `X/proxy/vless/encoding/encoding.go:175-204`.
- [D] Client runs upload/download concurrently; download completion closes the local app writer, while the VLESS connection closes only when `Process` returns. `X/proxy/vless/outbound/outbound.go:203,321-425`.
- [I] The server closes the whole TCP connection when the outbound `Process` returns; there is no VLESS-level half-close. `X/app/proxyman/inbound/worker.go:130-134`.
- [D] Unknown/malformed Vision command produces no error frame; stock logs debug and passes the remainder through unframed, which can desync. Reject unknown commands and overlong declared lengths. `X/proxy/proxy.go:244-253,560-598`.
- [D] Defaults: 60 s handshake, 300 s idle, 1 s uplink-only, 1 s downlink-only; splice timers are raised to 24 h. `X/features/policy/policy.go:114-124`, `X/proxy/proxy.go:752-759`.

### 2.6 Server compatibility checklist (Xray + sing-box)

- [D] Send `00 00` before the first response body block; do not require/echo flow. `X/proxy/vless/inbound/inbound.go:546-548,618-621`.
- [D] Prefix the first body block in each direction with the raw request UUID, once. `X/proxy/proxy.go:519-522`, `SV/vless/vision.go:310-322`.
- [D] Accept arbitrary content/padding lengths: stock writers randomize them. `X/proxy/proxy.go:502-514`, `SV/vless/vision.go:296-330`.
- [D] Handle multiple blocks per read and blocks split across reads. `X/proxy/proxy.go:560-612`.
- [D] Support Continue/End/Direct; sing-box uses the same values. `SV/vless/constant.go:16-20`.
- [D] On Direct, forward same-chunk leftovers and TLS read-ahead before raw reads. `X/proxy/proxy.go:259-270`.
- [D] Keep the other direction framed until it independently switches; there is no cross-direction message. `X/proxy/proxy.go:214-226,322-332`.
- [D] A server may answer End instead of Direct, but if the client sends Direct it must switch to raw reads or parse inner TLS as outer TLS. `X/proxy/proxy.go:244-253`.
- [I] Send no Vision bytes after End/Direct in that direction.

## 3. XUDP

### 3.1 Frame layout

XUDP is the ordinary mux frame format carried as VLESS body under command Mux (`v1.mux.cool`). `X/common/mux/frame.go:45-56`.

```
+0   meta_len (2 BE)       bytes following this field, 4..512
+2   session_id (2 BE)     XUDP writers use 0; replies echo it
+4   status (1)            1 New, 2 Keep, 3 End, 4 KeepAlive
+5   option (1)            0x01 Data, 0x02 Error
+6   network (1)           1 TCP, 2 UDP (New; Keep only if UDP target present)
+7   port (2 BE)
+9   atyp (1) + address
     [GlobalID (8)         only New + Data + UDP]
     [padding               extra metadata bytes ignored]
+2+meta_len  payload_len (2 BE)
+4+meta_len  payload
```

- [D] Status/option/network constants. `X/common/mux/frame.go:19-36`.
- [D] Metadata length excludes its own 2 bytes and includes session id through GlobalID. `X/common/mux/frame.go:67-110`, `X/common/xudp/xudp.go:109-114`.
- [D] Metadata is capped at 512 bytes; larger is rejected. `X/common/mux/frame.go:114-121`.
- [D] Session ID is 16-bit BE; XUDP always writes 0, so one mux TCP connection carries one XUDP flow. `X/common/xudp/xudp.go:91,109-111`.
- [D] New always has network+port+address. Keep normally has no address; if the datagram has a destination, it adds network(2)+port+address. `X/common/xudp/xudp.go:92-108`, `X/common/mux/frame.go:144-165`.
- [D] GlobalID is 8 bytes after the New target and only meaningful for New+Data+UDP with >=8 metadata bytes remaining; all-zero means none. Trailing metadata bytes are padding and ignored. `X/common/mux/frame.go:215-219`, `X/common/mux/server.go:195`.
- [D] Encoder caps datagrams at 7526 bytes (`length+666<=8192`) and drops empty/oversize packets. Decoder rejects metadata <4 bytes (EOF) and payloads that do not fit 8192. `X/common/xudp/xudp.go:84-88,141-148,174-188`, `X/common/buf/buffer.go:13`.

### 3.2 Statuses, options, errors

- [D] New creates/migrates; Keep appends to an existing session; End closes it; KeepAlive is accepted and data is discarded. `X/common/mux/frame.go:19-24`, `X/common/mux/server.go:336-355,158-163`.
- [D] XUDP clients emit only New and Keep; they never emit End/KeepAlive. Teardown is the TCP FIN. `X/common/xudp/xudp.go:92-108,151-171`, `SV/xudp.go:95-99,140-169`.
- [D] Sing-box's XUDP New carries no GlobalID, and every Keep carries network+address; a server must accept zero GlobalID and per-frame destinations. `SV/xudp.go:140-169`.
- [D] Server replies use Keep for every data frame (never New) and End on close. `X/common/mux/writer.go:35-60`, `X/common/mux/server.go:111-120`.
- [D] End carries OptionError if the relay copy failed, otherwise clean. `X/common/mux/writer.go:122-135`, `X/common/mux/server.go:111-119`.
- [D] A Keep for an unknown session causes a clean End reply. `X/common/mux/server.go:300-312`, `X/common/mux/client.go:352-359`.
- [D] OptionData means a 2-byte payload length follows; OptionError marks abnormal close; unknown option bits are ignored by stock checks. `X/common/mux/frame.go:26-29`, `X/common/mux/writer.go:89-94`.
- [D] Xray's XUDP reader treats End/New/unknown as EOF and never inspects OptionError; sing-box checks OptionError only for Keep/KeepAlive (End and New return earlier). `X/common/xudp/xudp.go:151-171`, `SV/xudp.go:73-104`.

### 3.3 Session lifecycle

- [D] New with nonzero GlobalID: look up the global table. Absent: dispatch and write the first datagram. Present: close the old mux attachment, reattach the same dispatcher link to the new connection/session ID, and hand over the datagram. `X/common/mux/server.go:195-261`.
- [D] A duplicate New while the entry is Initializing is dropped without error. `X/common/mux/server.go:200-215`.
- [D] New with zero GlobalID is an ordinary per-connection mux UDP session; no cross-connection reuse. `X/common/mux/server.go:195,264-297`.
- [D] Keep: lookup session ID, copy to the outbound link; if absent, reply End and discard. End: close and discard trailing data. `X/common/mux/server.go:300-334`.
- [D] On close, a nonzero-GlobalID entry becomes Expiring with `Expire=now+1min`, retaining the socket/state for reconnect. `X/common/mux/session.go:192-198`.
- [D] A 60 s sweeper interrupts/deletes entries past their 1-minute expiry. `X/common/mux/session.go:235-251`.
- [D] Reply data frames are Keep+Data+2-byte length; if the reply buffer has a UDP source, the frame also carries network/address so clients can distinguish responders. `X/common/mux/writer.go:71-94`, `X/common/mux/frame.go:103-106`, `X/proxy/freedom/freedom.go:281-306`.
- [D] End is emitted when the per-session copy goroutine exits. `X/common/mux/server.go:111-120`.
- [D] The mux worker closes itself after a 60 s tick if it has no sessions and its count did not change. `X/common/mux/server.go:95-109,122-140`, `X/common/mux/session.go:120-136`.

### 3.4 Destination and socket model

- [D] XUDP: one outbound UDP socket per session/GlobalID, created at New; by default it is unconnected and sends each datagram with `WriteTo` to that packet's destination. `X/proxy/freedom/freedom.go:112-158,354-410`, `X/transport/internet/system_dialer.go:50-88`.
- [D] Replies are stamped with their actual source; the server forwards that source in the Keep frame. `X/proxy/freedom/freedom.go:281-306`, `X/common/mux/frame.go:103-106`.
- [D] Legacy VLESS UDP: destination is fixed in the header; one socket per connection, no per-packet address. `X/proxy/vless/encoding/encoding.go:50-53`, `X/proxy/vless/encoding/addons.go:66-69`.
- [D] XUDP per-packet destinations are not re-dispatched/routed: routing runs once on New; Keep only updates `b.UDP`, which the single outbound socket writes. `X/common/mux/server.go:264-292`, `X/common/mux/frame.go:144-165`, `X/proxy/freedom/freedom.go:363-410`.
- [I] Enforce egress policy on every per-packet destination if routing must apply per destination.
- [D] There is no outbound source allowlist: the unconnected socket accepts datagrams from any sender and forwards their source. `X/transport/internet/system_dialer.go:50-88`, `X/proxy/freedom/freedom.go:281-306`.
- [I] If source filtering is required, accept replies only from destinations the session has sent to (or the same host for full-cone); stock Xray does neither.
- [I] Bind GlobalID sessions to the authenticated user; Xray's table is global, so a guessed 8-byte ID could attach to another user's session. `X/common/mux/session.go:230-251`.
- [D] Full-cone GlobalID is keyed BLAKE3-8 of the client's UDP `inbound.Source` (IP:port), only when cone is enabled and the inbound is dokodemo/socks/shadowsocks/tun/wireguard; key is random per process or `xray.xudp.basekey`. `X/common/xudp/xudp.go:34-65`, `X/core/xray.go:190`, `X/common/platform/platform.go:19,24`.
- [I] Treat GlobalID as opaque and scope it per user; never use it as identity/policy.

### 3.5 Limits and timeouts

- [D] Metadata <=512; frame payload <=8192; Xray XUDP client datagram <=7526; legacy writer datagram <=8190. `X/common/mux/frame.go:119-121`, `X/common/mux/reader.go:40-42`, `X/common/xudp/xudp.go:86-88`, `X/proxy/vless/encoding/addons.go:102-104`.
- [D] XUDP expiry is 1 minute after close, swept every minute (up to ~2 minutes retained). `X/common/mux/session.go:192-198,235-251`.
- [D] Default idle is 300 s; mux worker idle close is 60 s. `X/features/policy/policy.go:120-123`, `X/common/mux/server.go:101,122-140`.
- [D] No server-side XUDP concurrency cap exists; `xudpConcurrency` configures the client mux pool. `X/infra/conf/xray.go:105-122`, `X/app/proxyman/outbound/handler.go:229-235`.
- [I] Cap sessions per connection/user, cap the GlobalID table, cap queued datagrams, and apply backpressure; stock maps/queues are attacker-controlled.
- [I] Reject a duplicate session ID used with a different GlobalID; stock `SessionManager.Add` overwrites the map entry. `X/common/mux/session.go:75-86`.
- [D] A dispatch failure on New deletes the GlobalID and aborts the entire mux TCP connection. `X/common/mux/server.go:230-239`.
- [I] Prefer End+Error for that session instead of killing unrelated sessions; client-safe but a deliberate deviation.

## 4. Legacy VLESS UDP and packetaddr

- [D] Legacy VLESS UDP: command 2, destination in the header, body is `length(2 BE) | payload` per datagram in both directions. Xray drops zero-length and `length+2>8192` on send; the reader accepts a 16-bit length. `X/proxy/vless/encoding/addons.go:66-85,87-124,159-191`.
- [D] The server rejects command UDP with flow `xtls-rprx-vision`; stock clients convert such UDP to XUDP/Mux first. `X/proxy/vless/inbound/inbound.go:557-558`, `X/proxy/vless/outbound/outbound.go:315-319`.
- [D] Xray uses XUDP for Vision UDP and (with cone) for non-DNS/non-443 UDP; otherwise legacy UDP. Vision UDP/443 is rejected unless the client used `xtls-rprx-vision-udp443`, which is stripped to `xtls-rprx-vision` on the wire. `X/proxy/vless/outbound/outbound.go:251-266,315-319`.
- [D] Xray has no packetaddr symbol (grep of the full tree); it is a sing-box/sing-vmess feature. Default sing-box encoding is XUDP; `""` selects legacy; `"packetaddr"` selects packetaddr. `SB/protocol/vless/outbound.go:78-88`.
- [D] packetaddr: VLESS command UDP and destination is the magic FQDN `sp.packet-addr.v2fly.arpa`; each datagram payload starts with an inner address (ATYP 1=IPv4, 2=IPv6, no domain; port last), then payload. `SB/protocol/vless/inbound.go:199-203`, `SB/protocol/vless/outbound.go:173-184`, `SV/packetaddr/packetaddr.go:8-13`, `SV/packetaddr/conn.go:62-96`.
- [D] Sing-box rejects domain destinations in packetaddr mode. `SB/protocol/vless/outbound.go:176-178,213-215`, `SV/packetaddr/packetaddr.go:15`.
- [I] A packetaddr server must treat one VLESS UDP connection as a multi-destination session: strip/prepend the address per datagram and apply policy per inner destination, not once for the magic FQDN.
- [I] packetaddr datagram max is 8190 minus the inner address length, because it uses legacy 2-byte length framing.

## 5. Unverified / test recommendations

- [U] Post-Direct coalescing: Xray handles raw leftovers in the same chunk (`X/proxy/proxy.go:603-609`); sing-box assumes Direct is the last block and inserts 5 ms when sending (`SV/vless/vision.go:220-235`). Test server->sing-box with forced single-segment writes; keep the gap.
- [U] Direct close: verify whether an outer TLS close_notify after Direct is ignored by both clients; prefer raw abort.
- [U] Cross-user GlobalID hijack is not prevented in stock Xray; test per-user scoping against a real full-cone reconnect.
- [U] packetaddr was verified against sing-box/sing-vmess source, not captured traffic; add an interop test with `packet_encoding: "packetaddr"`.
- [U] Missing UUID prefix: both stock readers pass bytes through raw when the prefix is absent (`X/proxy/proxy.go:551-557`, `SV/vless/vision.go:333-345`); confirm this fallback never occurs in normal traffic.
- [I] Fuzz targets: Vision block lengths/state machine, XUDP metadata/payload lengths, legacy length-prefixed datagrams, packetaddr inner addresses.
