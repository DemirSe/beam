# REALITY server-side implementation specification
Pinned: `xtls/reality` `9234c772ba8f` (2026-03-22), per Xray v26.3.27 `go.mod:21`.
Read-only research; no repo changes, VPS contact, or services. `R/` =
`/tmp/opencode/xray-perf-gaps-ds/upstream/reality-9234c772ba8f`; `X/` =
`/tmp/opencode/xray-rewrite-prep/upstream/xray-v26.3.27-full`; `G/` =
`https://github.com/XTLS/reality/blob/9234c772ba8f` for `handshake_server.go` and
`handshake_messages.go`, absent from the local `R/` snapshot and read at the same tag.
`[E]` direct evidence, `[I]` inference; `X/.../` abbreviates `X/transport/internet/`.
## 1. ClientHello authentication envelope
The envelope is the TLS 1.3 `legacy_session_id`, set to 32 bytes and written at ClientHello
handshake-message offset 39 (`X/transport/internet/reality/reality.go:141-142,174-175`;
server comment confirming `sessionId == raw[39:]` at `R/tls.go:244`). Message layout:
`[0]` type 0x01, `[1:4]` u24 length, `[4:6]` 0x0303, `[6:38]` random, `[38]` length 32,
`[39:71]` session id; the entire message is AEAD AD. `original` includes the 4-byte header
(`G/handshake_messages.go#L418-L423`). The 32-byte session id is `C[16] || T[16]`
(AES-GCM ciphertext + tag); its plaintext `P` is never visible on the wire.

| P off | len | field | notes |
|---:|---:|---|---|
| 0 | 3 | client version x.y.z | Xray 26.3.27 sends `26,3,27` (`X/core/core.go:21-23`) |
| 3 | 1 | reserved | client writes 0; server does not check (`R/tls.go:249-251`) |
| 4 | 4 | Unix seconds, BE | `uint32(time.Now().Unix())` (`X/.../reality.go:147`) |
| 8 | 8 | short id | fixed `[8]byte`, zero-padded (`R/tls.go:251`) |
**Crypto** `[E]`: `S = X25519(client_eph_priv, server_static_pub)` / server mirror
(`X/.../reality.go:152-163`, `R/tls.go:230-231`); `K = HKDF-SHA256(ikm=S, salt=random[0:20],
info="REALITY", L=32)` (`R/tls.go:233`, `X/.../reality.go:167`); `C||T = AES-256-GCM-Seal(K,
nonce=random[20:32], P, AD=CH_with_32_zero_session_bytes)` (`R/tls.go:236-248`). The client
copies an all-zero 32-byte session id into `Raw[39:]` before sealing, then copies the
ciphertext in (`X/.../reality.go:141-142,174-175`); the server saves the ciphertext, zeroes
all 32 bytes in `original`, calls `Open`, and restores them (`R/tls.go:241-248`). There is
no HMAC in the envelope; HMAC-SHA512 authenticates the temporary certificate
(`R/handshake_server_tls13.go:149-151`; `X/.../reality.go:85-87`).

**Checks, in order** `[E]`:
1. CH parsed; negotiated `c.vers == TLS1.3`; exact `ServerNames[SNI]` match (`R/tls.go:210-211`).
2. A standalone 32-byte X25519 share, else the last 32 bytes of an `X25519MLKEM768` share of
   exactly 1216 bytes; otherwise no auth (`R/tls.go:214-228`).
3. X25519 succeeds (low-order points rejected by Go), HKDF, GCM `Open`; any failure silently
   skips auth (`R/tls.go:230-247`).
4. Split `ClientVer[0:3]`, `ClientTime = uint32 BE [4:8]`, `ClientShortId = [8:16]` (`R/tls.go:249-251`).
5. 24-bit compare against `MinClientVer`/`MaxClientVer`; if `MaxTimeDiff != 0`, require
   `abs(now-t) <= MaxTimeDiff`; require `ShortIds[ClientShortId]` (`R/tls.go:153-158,257-260`).
   `MaxTimeDiff == 0` disables the timestamp check.
6. Only then `hs.c.conn = conn` (drop the mirror); else fallback (`R/tls.go:261-271`).
No check of session-id length, reserved byte, `signature_algorithms`, or ALPN
(`R/tls.go:241-260`). Short-id lookup is a non-constant-time map access (`R/tls.go:260`);
GCM tag comparison is constant-time.
**Replay** `[E]`: no cache; `R/cache.go:14-42` is only a certificate cache. The optional
timestamp is the only freshness check (`R/tls.go:259`). A replayed CH passes auth and forces
a target dial/flight, but the replayer cannot produce the TLS Finished without the ephemeral
private key `[I]`; with `MaxTimeDiff == 0` the replay window is unlimited. A silent
replayer can hold resources because there is no handshake deadline (§2.7).
**Security consequence** `[I]`: the server's static public key is the client-side
"password" (`X/.../reality.go:152-163`). Anyone with it and a valid short id can produce a
valid envelope; the server check is possession of that credential, while the certificate
HMAC authenticates the server to the client. The short id is the only per-client secret;
require non-empty ones.
## 2. Server state machine
**Setup** `[E]`: `Server()` dials `config.Dest` immediately, with `context.Background()` and a
zero `net.Dialer` (no timeout) (`R/tls.go:168-172`; `X/.../reality.go:52-55`,
`X/.../reality/config.go:17-19`); optionally writes a PROXY-protocol header (`R/tls.go:174-180`);
wraps the client in `MirrorConn{Conn: client, Target: target}` (`R/tls.go:190-200`).
`MirrorConn.Read` mirrors every read chunk to the target, `Write`/`Close` return errors, and
all deadline methods are no-ops (`R/tls.go:59-102`).
**Auth/fallback fork** `[E]`: goroutine A reads the CH under the mutex and runs §1.3
(`R/tls.go:207-270`). Failure → `io.Copy(target, ratelimited(client))`, `CloseWrite(target)`
on clean EOF (`R/tls.go:271-286`). Success → `hs.c.conn = conn`, so later I/O bypasses the
mirror and the target is used only as a template (`R/tls.go:261,271`).
**Target flight parser** `[E]`: goroutine B reads the target under the same mutex into an
8 KiB buffer (`R/tls.go:290-306,140`). If unauthenticated, it sets `copying` and goes to
direct forwarding; >8 KiB buffered or any record >8 KiB aborts shaping
(`R/tls.go:307-313,334`). Records are positional:

| idx | target record | validation / action |
|---:|---|---|
| 0 | ServerHello | legacy 0x0303, supported_version 1.3, known TLS 1.3 suite, share exactly X25519(32) or X25519MLKEM768(1088+32) (`R/tls.go:353-361`) |
| 1 | ChangeCipherSpec | exactly 6 bytes, payload 1 (`R/tls.go:337-339`) |
| 2 | EncryptedExtensions | record type 23 (`R/tls.go:322-327`); if length > 512 the target coalesced the flight: set `handshakeLen[2]` and `handshakeBuf` (`R/tls.go:340-344`) |
| 3 | Certificate | record type 23; length recorded |
| 4 | CertificateVerify | record type 23; length recorded |
| 5 | Finished | record type 23; length recorded |
| 6 | NewSessionTicket | optional record type 23; length recorded (`R/tls.go:345-348`) |
`handshakeLen`/`handshakeBuf` live on the output half-connection (`R/conn.go:174-175`).
Normally parsing continues until the target's full flight through Finished (and any buffered
NST) is available, so all lengths are known before the server flight is built; an EE record
larger than 512 bytes breaks early and the whole flight is mimicked as one record
(`R/tls.go:340-368`). The client therefore waits for the target's full flight (or the
coalesced EE header), about one target RTT `[I]`.
**Server flight** `[E]`: `processClientHello`/`pickCertificate` are bypassed
(`R/handshake_server_tls13.go:96-100,133-140`). The suite is the target's; the client share
matching the target's group is used; a fresh ephemeral X25519 key is generated; its public
key is copied **into the target's parsed ServerHello bytes** (the field aliases `original`,
`G/handshake_messages.go#L871-L883`); for hybrid, ML-KEM encapsulation replaces the whole
share with `ciphertext||x25519_pub`, preserving length (`R/handshake_server_tls13.go:101-129`).
The ServerHello is sent as the target's exact bytes with only the share replaced, and hashed
identically (`R/handshake_server_tls13.go:854-859`); the target's random, session-id echo,
suite and extensions are reused. A 6-byte dummy CCS follows (`R/handshake_server_tls13.go:861-863`),
then an **empty** EncryptedExtensions (ALPN is never negotiated because
`processClientHello` is skipped: `R/handshake_server_tls13.go:865-874,895-896`).
Certificate `[E]`: a single process-lifetime Ed25519 key and minimal self-signed cert
(serial 0, no SAN, zero validity) are generated at init (`R/handshake_server_tls13.go:74-86`).
Per connection the cert is cloned and its 64-byte signature is overwritten with
`HMAC-SHA512(AuthKey, ed25519_pub)` (`R/handshake_server_tls13.go:141-151`); the client checks
that HMAC against `certs[0].Signature` and skips X.509 verification on match
(`X/.../reality.go:84-103`). CertificateVerify is a real Ed25519 transcript signature
(`R/handshake_server_tls13.go:970-999`). Optional ML-DSA-65 signs
`HMAC-SHA512(AuthKey, pub||ClientHello||ServerHello)` into the reserved 3309-byte extension at
`cert[126:]` (`R/handshake_server_tls13.go:143-158`; `X/.../reality.go:88-97`); the fixed
offset is fragile across Go/x509 encoders `[E]`.
Record shaping `[E]`: `c.buffering = true` (`R/handshake_server_tls13.go:166`). Each encrypted
handshake record is padded so its on-wire length equals the corresponding target length
`handshakeLen[i]`; padding is appended after the real content type and stripped by the
client (`R/conn.go:526-565`). The whole flight is one `conn.Write` (`R/conn.go:985-1006`,
`R/handshake_server_tls13.go:184-186`). If the target coalesced (idx 2 > 512), EE+Cert+CV+Finished
are concatenated into one record padded to the target's coalesced length
(`R/conn.go:532-557,1103-1133`). If the server message is longer than the target record,
padding goes negative and the handshake aborts (`R/conn.go:552-555`), most likely with ML-DSA.
If the target sent an NST record after its Finished, a 1-byte `typeNewSessionTicket` is padded and given an
application-data content type, decrypting as an empty app-data record of the target length
(`R/handshake_server_tls13.go:176-180`; `R/conn.go:546-551`).
**Client Finished and post-handshake** `[E]`: `readClientFinished` reads one handshake
message, requires `finishedMsg`, compares verify data in constant time, then installs the
client application secret (`R/handshake_server_tls13.go:1235-1258`). Before returning, the
server builds key `Dest + " " + SNI + " " + alpnClass` (0 = no ALPN, 2 = first is h2, else 1)
(`R/tls.go:396-403`), looks up `GlobalPostHandshakeRecordsLens`, and for each recorded length
sends an empty application-data record of exactly that on-wire length, encrypted with the
server app key and incremented sequence (`R/tls.go:404-421`). The plaintext is
`23||0x00||zeros`, which clients strip to a zero-length record and ignore
(`R/tls.go:407-416`; stripping `R/conn.go:423-434`, ignore `R/conn.go:809-811`). It then sets
`isHandshakeComplete` (`R/tls.go:429`). The detector (`R/record_detect.go:21-135`) probes the
target directly at listener start for every SNI and ALPN class, recording post-handshake
record lengths and CCS tolerance (1/16/32/MaxInt) (`R/record_detect.go:66-98,137-185`). Xray
calls it for RAW (`X/.../tcp/hub.go:82`); `NewListener` calls it automatically
(`R/tls.go:529-531`), and the package documents it as mandatory otherwise (`R/tls.go:160-161`).
Defects in this block `[E]`: (a) if the cache key is absent the loop never breaks, stalling
the connection forever in 5 s sleeps; (b) a `false` value (probe in flight) stalls the first
authenticated connections in 5 s steps; (c) the normal `[]int` path breaks **before** setting
`MaxUselessRecords`, so CCS detection applies only to connections that arrived during the
probe (`R/tls.go:404-428`); (d) a target record length <22 makes `make([]byte,length-16)` or
`plainText[5]` panic (`R/tls.go:407`; detector accepts any `23 03 03` length ≥5,
`R/record_detect.go:125-128`). `Server()` has no `recover`, and Xray's accept goroutine has
none (`X/.../tcp/hub.go:116-129`), so (d) is a crash vector for a malicious target.
**Unauthenticated forwarding** `[E]`: triggered by CH parse error, TLS <1.3, SNI mismatch,
no usable share, AEAD failure, version/time/short-id failure, target speaking first, or
invalid target ServerHello (`R/tls.go:211,214-228,230-260,308-311,353-361,433-447`). All
bytes are forwarded: the CH as read by the mirror, then `io.Copy(target, client)`; the
reverse is `conn.Write(s2cSaved)` + `io.Copy(client, target)` + `CloseWrite`
(`R/tls.go:275-285,437-446`). No byte cap, delay, padding, or alert: during handshake
`sendAlert` writes through `MirrorConn.Write`, which errors, so nothing reaches the client
(`R/conn.go:84-86,880-898`). Optional per-direction token buckets apply only here, after
`AfterBytes`, at `BytesPerSec` with burst ≥ rate; `BytesPerSec == 0` disables
(`R/tls.go:104-137,275,437,442`; `X/infra/conf/transport_internet.go:906-912`).
**Timing/lifetimes** `[E]`: target dial starts at accept, before the CH, so TCP setup
overlaps (`R/tls.go:168`); the server flight waits for the target's full flight (or the
coalesced EE header), adding about one target RTT `[I]`; the flight is one write, post-handshake padding records are immediate
separate writes, and there is no random delay (`R/handshake_server_tls13.go:184-186`,
`R/tls.go:416`). The target is closed immediately after the handshake (`R/tls.go:451-452`),
so it never receives the client Finished: every authenticated connection leaves an
incomplete TLS handshake at the cover site `[I]`. **No handshake timeout exists**: `Server`
sets no deadlines, mirror deadlines are no-ops, and `readClientFinished`/`target.Read` can
block forever (`R/tls.go:92-102,297,388,1235-1258`); the only deadlines are the 5 s
close-notify write (`R/conn.go:1542`) and the detector read (`R/record_detect.go:121`).
If the target's SH was accepted but a later record fails validation,
`handshakeLen[0] != 0`, the fallback block is skipped, no flight is sent, and `Server`
closes the client and returns an error (`R/tls.go:353-368,433-447,451-475`).
## 3. Edge cases

| Case | Behaviour | Evidence |
|---|---|---|
| Wrong short id | AEAD ok, map miss → fallback | `R/tls.go:257-261` |
| Wrong SNI | fails before auth → fallback; target sees the SNI | `R/tls.go:211,271-286` |
| Empty session id | 32 zero bytes, Open fails → fallback | `R/tls.go:241-247` |
| Replayed hello | passes auth, no cache; replayer cannot finish; server may block | `R/tls.go:259`; `R/handshake_server_tls13.go:1235-1258` |
| P-256-only share | no X25519/hybrid → fallback | `R/tls.go:214-228` |
| Fragmented CH | reassembled; AD over full message; fragments mirrored | `R/conn.go:1145-1188`; `R/tls.go:70-82` |
| Oversized record | >18432 → alert dropped, error → fallback forwards remainder | `R/common.go:64-69`; `R/conn.go:707-711` |
| Oversized hello | >65536 handshake → error → fallback | `R/conn.go:1178-1182` |
| TLS 1.2 | no auth → forward; TLS 1.2 server path never used | `R/tls.go:190-211` |
| Target no CCS / bad SH / record >8 KiB | shaping aborts; fallback if SH not accepted, else closed without a flight | `R/tls.go:312-313,334,337-361,433-447` |
| ML-DSA cert longer than target cert record | negative padding → handshake error, no forward | `R/conn.go:552-555` |
| Target post-handshake record <22 B | panic in server goroutine | `R/tls.go:407` |
| Detection key absent | 5 s sleep forever; connection never completes | `R/tls.go:404-428` |
| Flood of empty records | recursive `retryReadRecord`; `MaxUselessRecords` may be MaxInt → stack exhaustion | `R/conn.go:829-839`; `R/record_detect.go:181` |
| Client FIN mid-handshake | copy ends, target CloseWrite; stalled target keeps handler | `R/tls.go:275-285` |
| Target dial/read error | client closed, error returned, no cover | `R/tls.go:168-172,298-303` |
| Half-close after handshake | close_notify with 5 s write deadline, then close | `R/conn.go:1488-1560` |
## 4. Differences: `xtls/reality` vs stock Xray wrappers / Go `crypto/tls`
- `[E]` `xtls/reality` is the complete server-side TLS 1.3 fork implementing the envelope,
  mirroring, shaping and padding. Xray's `transport/internet/reality` only maps config and
  invokes it (`X/.../reality/config.go:16-59`); `goreality.Server` is called per accepted TCP
  connection, `NewListener` is used for gRPC/splitHTTP (`X/.../tcp/hub.go:80-124`,
  `X/.../splithttp/hub.go:573`).
- `[E]` The package's `Client()` is the ordinary Go TLS client, not a REALITY client
  (`R/tls.go:5-6,491-499`). Xray's client is uTLS plus the custom envelope
  (`X/.../reality.go:117-177`); on HMAC failure it runs the HTTP spider and fails the dial
  (`X/.../reality.go:183-275`).
- `[E]` ServerHello is the target's, with only the key share swapped; the certificate is a
  process-lifetime self-signed Ed25519 cert with a per-connection HMAC signature (optional
  ML-DSA extension). Stock Go generates a fresh ServerHello and selects a real certificate.
- `[E]` ALPN, PSK/resumption, client auth and ECH are not negotiated: relevant calls are
  bypassed (`R/handshake_server_tls13.go:96-100,133-140,895-896`), and Xray forces
  `NextProtos: nil`, `SessionTicketsDisabled: true` (`X/.../reality/config.go:31-32`).
  `ConnectionState.CurveID` stays 0 because `processClientHello` is skipped.
- `[E]` Xray's `Conn` wrapper only adds `HandshakeAddress` (`X/.../reality.go:37-55`). The
  JSON layer base64url-decodes keys, hex-decodes short ids into fixed 8-byte zero-padded
  arrays (`X/infra/conf/transport_internet.go:849-894,952-954`), and accepts fewer than three
  dotted version parts, leaving missing bytes zero (`X/infra/conf/transport_internet.go:856-880`).
## 5. What beam must implement
- [x] Envelope: 32-byte session id at CH offset 39; `ver[3]|rsv|ts_be32|shortid[8]`; AES-256-GCM
  with `K = HKDF-SHA256(X25519(static_priv, client_share), salt=random[0:20], info="REALITY",
  32)`, nonce `random[20:32]`, AD = full CH with all 32 session-id bytes zeroed. Test against
  Xray client vectors (`X/.../reality.go:141-175`).
- [x] Share selection: standalone X25519 first, else the last 32 bytes of an exactly 1216-byte
  `X25519MLKEM768` share (`R/tls.go:214-228`); reject low-order X25519.
- [x] Checks: TLS 1.3 only; exact SNI set; 24-bit version range; optional `|now-ts| <=
  MaxTimeDiff`; constant-time short-id compare (do not copy the map lookup). Fail closed to
  cover, never with an alert.
- [ ] Cover: dial target early; mirror every client byte; optional PROXY header; on failure
  full bidirectional `io.Copy`, optional token buckets, half-close, no cap/delay/alert. Add
  your own total fallback bound if desired (Xray has none).
- [ ] Target parser: SH/CCS/EE/Cert/CV/Finished/optional NST; validate SH version, suite,
  share group/length; 8 KiB limits; handle coalesced EE >512.
- [ ] Flight: reuse target SH bytes and swap the share (X25519 or ML-KEM ct + X25519); fresh
  ephemeral key; empty EE; Ed25519 cert with `HMAC-SHA512(AuthKey,pub)` in the signature;
  Ed25519 CertificateVerify; Finished; optional NST padding; pad each encrypted record to
  the target length; one write.
- [ ] Post-handshake: send empty app-data records matching the target's lengths, non-blocking,
  only if a cache entry exists; require `length >= 22`; hard-cap the count. Do not copy the
  5 s retry loop. Apply `MaxUselessRecords` unconditionally, cap it (e.g., 32), and replace
  recursive `retryReadRecord` with a loop.
- [ ] Robustness: no panics/unwrap on network or target input; check every
  `generateECDHEKey`, `NewPublicKey`, `ECDH`, `mlkem.NewEncapsulationKey768`, `Encapsulate`
  error (the fork ignores them; a malicious target can leave `peerData` nil and panic the
  hybrid slice, `R/handshake_server_tls13.go:106-129`); recover per connection if needed.
- [ ] Limits: handshake deadlines, target dial deadline, max CH size, connection/goroutine
  caps, bounded post-handshake padding, bounded replay cache (key = session-id ciphertext or
  client share; TTL = `MaxTimeDiff` or seconds; LRU).
- [ ] Interop knobs: client version bytes (respect server `minClientVer`), 8-byte zero-padded
  short id, ALPN class key, optional ML-DSA-65, `Xver`; document that the server public key is
  a client credential, not a server secret.
- [ ] Tests: CH builder + AEAD vectors; fragmented/oversized CH; wrong SNI/short id/empty
  sid/replay; P-256-only; TLS 1.2; target no-CCS/invalid-SH/8 KiB/ML-DSA-too-long;
  post-handshake length <22; missing detection key; silent client/stalled target; half-close;
  fuzz the CH and target-flight parsers.

**Unverified.** Other clients (sing-box etc.) were not inspected; uTLS fingerprint session-id
lengths (offset 39 assumes 32) were not tested across presets; ML-DSA `cert[126:]` across
Go/x509 versions was not tested; the client-visible effect of the no-flight close and 5 s stall
paths is inferred from code, not observed.
