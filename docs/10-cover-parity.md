# Cover TLS parity: whatsapp.net:443

Date: 2026-10-22. Scope: ordinary TLS 1.3 clients to the production cover, **no REALITY
authentication**. Network succeeded from this host; DNS resolved `whatsapp.net` to
`57.144.249.32` (`mmx-ds.cdn.whatsapp.net`). No VPS or local TLS server was used.
Work dir: `/tmp/opencode/beam-spike-tls`; `/home/demir/pi/beam` was not modified.

## Verdict
- **The cover is PQ-capable.** It negotiates `X25519MLKEM768` (group 0x11ec), TLS 1.3,
  `TLS_AES_128_GCM_SHA256`, ALPN `h2`, with a 2-certificate EC leaf chain.
- **ring connects**, but offers only classical groups, so it negotiates **X25519** (0x001d).
  Its ServerHello is 127 B and its flight 3217-3218 B, versus the cover's 1215 B / 4305-4306 B
  under PQ. The gap is **1088-1089 B, all in the ServerHello key_share**, and the group ID differs.
- **aws-lc-pq negotiates the cover's PQ group** and reproduces its ServerHello/flight sizes;
  BoringSSL default agrees on the same parameters. Ring does not.
- **Recommendation for beam v1: rustls + aws-lc-rs with `prefer-post-quantum`.** Do not ship ring
  for a PQ-capable cover such as whatsapp.net; the authenticated server flight is trivially
  distinguishable from the cover.

## Results
All probes offered ALPN `h2,http/1.1`; all negotiated `h2`. Three runs per stack; ranges shown
where they varied. Sizes include TLS record headers. Cipher is the IANA name from the raw
ServerHello; rustls prints the same suite as `TLS13_AES_128_GCM_SHA256`.

| stack | negotiated group | cipher | chain | leaf | ServerHello | server flight records (type:bytes) | flight bytes |
|---|---|---|---:|---|---:|---|---:|
| rustls + ring | X25519 (0x001d) | TLS_AES_128_GCM_SHA256 | 2 | EC | 127 | 22:127,20:6,23:1022,23:1925,23:137-138 | 3217-3218 |
| rustls + aws-lc-pq | **X25519MLKEM768 (0x11ec)** | TLS_AES_128_GCM_SHA256 | 2 | EC | **1215** | 22:1215,20:6,23:1022,23:1925,23:137-138 | 4305-4306 |
| boring default | **X25519MLKEM768 (0x11ec)** | TLS_AES_128_GCM_SHA256 | 2 | EC | **1215** | 22:1215,20:6,23:1022,23:1925,23:136-137 | 4304-4305 |
| boring X25519-only | X25519 (0x001d) | TLS_AES_128_GCM_SHA256 | 2 | EC | 127 | 22:127,20:6,23:1022,23:1925,23:137-138 | 3217-3218 |

Common ServerHello details: TLS version extension `0x0304` (TLS 1.3), legacy session id length 32,
extension order `[002b,0033]` (supported_versions, key_share) on every stack. The encrypted
EncryptedExtensions are not visible; ALPN came from the TLS library. The certificate records
(1022 B and 1925 B) are identical between PQ and X25519; only the ServerHello key_share differs.

ClientHello observations (client-side, not the cover's response):

| stack | CH record bytes | wire records/bytes incl CCS+Finished | CH SHA-256 |
|---|---:|---|---|
| rustls + ring | 237 | 3 / 301 | `a27ea48228fe394f6f0f77bbea4f388ec9926bfa7d493661701083ceaf7b3d21` |
| rustls + aws-lc-pq | 1467 | 3 / 1531 | `ef9aedc0045480bcd38ff7e0c3a9d230584d1f7281af53ac8c7e609c39168550` |
| boring default | 1442 | 3 / 1506 | `fb210626821f85eee8fb7fde17f1e75bc251d24bcbfbc9b2bdd441c8e0e80c38` |
| boring X25519-only | 214 | 3 / 278 | `fe8cb4560693faaf856a73d52500905f525989538769809c6a2ea4dc9352c19c` |

ServerHello SHA-256 (first record) for the same runs:
ring `0c424e2c01375a513deb864cafcd8254204e81d730a4da3809b92cccb93e12a3`,
aws-pq `03638992c3e94d9570ccb8286dd2ccbc23e8c43fed96a85ed64a3546e1a5d04a`,
boring default `da030315c7b16a0584534e189042832288f821d04e722fcf51f153068d7f625d`,
boring X25519 `bd0a53785d56ab9a4bcfaef493312cc1cb10b4ee2f50ead3f7704926dda9ad36`.
Hashes vary per connection because of random fields. JA3/JA4 is **not implemented** in the spike;
these are SHA-256 hashes of the raw first ClientHello/ServerHello records. Full raw bytes are saved.

## Ring vs cover gap
Ring completes the handshake because WhatsApp's server falls back to X25519 when the client does
not offer a PQ group. It is a working connection, not a cover-parity connection:

- group: cover chooses `X25519MLKEM768` for PQ clients; ring offers only classical groups (it negotiated `X25519`), so group IDs differ.
- ServerHello: 1215 B (PQ) vs 127 B (ring), a **1088 B** difference caused by the ML-KEM public key.
- Full server flight: 4305-4306 B vs 3217-3218 B, a **1088-1089 B** difference; record count is 5
  either way and the 1022 B / 1925 B encrypted records are unchanged.
- cipher, ALPN, chain count, leaf key type, and ServerHello extension order match.

A passive observer sees a 127-byte vs 1215-byte first record and a different named group. That is a
strong, cheap distinguisher, so ring is not suitable for this cover.

## Recommendation
**Use rustls + aws-lc-rs + `prefer-post-quantum` for beam v1.** It reproduces the cover's PQ group
and server flight, while avoiding BoringSSL's C++/libstdc++/libclang toolchain. In the earlier spike
aws-lc-pq was also faster than BoringSSL PQ (p50 ~256-338 us vs 515-521 us; server CPU ~301-354 us vs
311-318 us per handshake), so there is no performance reason to choose BoringSSL for this cover.

- Keep `prefer-post-quantum` enabled so the server prefers X25519MLKEM768 when a client offers it.
- Initialize `aws_lc_rs::default_provider()` at process start; the first handshake otherwise pays
  ~28 ms of provider initialization.
- Re-test from the deployment region/PoP before freezing the provider; this measurement is from one
  vantage point (57.144.249.32).
- If beam ever needs a non-PQ cover, ring remains the lower-CPU option; do not assume that choice
  carries over to whatsapp.net.

## Exact commands
```bash
cd /tmp/opencode/beam-spike-tls
# ring (default feature)
cargo build -p cover-probe --release
cp target/release/cover-probe cover-probe-ring
# aws-lc-pq
export PATH="/tmp/opencode/tools/bin:$HOME/.cargo/bin:$PATH"
export CC=/usr/bin/gcc CXX=/tmp/opencode/tools/bin/g++-portable CMAKE_GENERATOR=Ninja
export LIBRARY_PATH=/tmp/opencode/tools/fedora/usr/lib/gcc/x86_64-redhat-linux/16
cargo build -p cover-probe --release --no-default-features --features rustls-aws-pq
cp target/release/cover-probe cover-probe-awspq
# boring
export LIBCLANG_PATH=/tmp/opencode/tools/libclang/libclang-18.1.1.data/platlib/clang/native
export BINDGEN_EXTRA_CLANG_ARGS="-isystem /usr/lib/gcc/x86_64-redhat-linux/16/include -isystem /usr/include"
cargo build -p cover-probe --release --no-default-features --features boring
cp target/release/cover-probe cover-probe-boring

./cover-probe-ring whatsapp.net
./cover-probe-awspq whatsapp.net
./cover-probe-boring whatsapp.net
BORING_CLASSICAL=1 ./cover-probe-boring whatsapp.net
```
The probe offers TLS 1.3 (all runs negotiated 1.3), ALPN `h2,http/1.1`, disables certificate verification (measurement only;
this does not affect negotiated parameters), and taps the TCP stream to capture all handshake records.
Source: `cover-probe/src/{common,rtls,btls}.rs`.

## Local cover-parity harness

`scripts/cover-parity.sh` reproduces the authenticated server flight locally. It builds
`beam` in the current worktree, starts it on `127.0.0.1:18443` with the throwaway REALITY
key from `/tmp/opencode/beam-test/beam.toml`, and puts a recording TCP proxy on
`127.0.0.1:18444`. The stock Xray 26.3.27 no-flow client (`client-no-flow.json`) connects
through the proxy; a loopback HTTP request completes the VLESS/TCP path. The proxy
captures every server TLS record in the flight, and `scripts/cover-parity.py` prints the
ServerHello parameters and compares the capture with
`/tmp/opencode/beam-spike-tls/cover-artifacts/rustls-aws-pq-serverflight.bin`.

Prerequisites are `cargo`, `python3`, `curl`, the stock Xray binary at
`/tmp/opencode/xray-server-compare/xray`, the no-flow client config at
`/tmp/opencode/tls-server-harness/client-no-flow.json`, the test config, and the cover
artifact. Override paths with `XRAY_BIN`, `CLIENT_TEMPLATE`, `TEST_CONFIG`, and
`COVER_ARTIFACT`; ports can be changed with `BEAM_PORT`, `PROXY_PORT`, `SOCKS_PORT`, and
`HTTP_PORT`. The harness is loopback-only: the cover destination in the generated beam
config is a closed local port, so a failed authentication cannot reach the internet.

```bash
source scripts/dev-env.sh
bash scripts/cover-parity.sh
```

The run directory (`/tmp/opencode/beam-cover-parity.XXXXXX`) contains `report.txt`,
`report.json`, `capture/server-flight.bin`, and component logs. The script exits non-zero
only on build/start, handshake, or parse failure. Flight-size differences caused by
beam's temporary Ed25519 certificate are reported as quantified deltas and do not fail
the run.

Last local result (2026-10-22): group `X25519MLKEM768`, cipher
`TLS_AES_128_GCM_SHA256`, and the 1215-byte ServerHello match the cover. The extension
order differs: beam/rustls emits `key_share, supported_versions` (`0x0033, 0x002b`),
while the cover emits `supported_versions, key_share` (`0x002b, 0x0033`). This is a
plaintext distinguisher unrelated to the temporary certificate. The encrypted flight is
3 records / 416 B versus 5 records / 3085 B for the cover (-2669 B), as expected from one
temporary Ed25519 certificate instead of the cover's two-certificate EC chain.

## Raw artifacts
- Logs: `cover-ring-whatsapp.log`, `cover-awspq-whatsapp.log`, `cover-boring-whatsapp.log`,
  `cover-boring-x25519-whatsapp.log`, and `cover-*-3runs.log`.
- Raw bytes: `/tmp/opencode/beam-spike-tls/cover-artifacts/`
  `rustls-ring-{clienthello,serverflight}.bin`,
  `rustls-aws-pq-{clienthello,serverflight}.bin`,
  `boring-default-{clienthello,serverflight}.bin`,
  `boring-x25519-{clienthello,serverflight}.bin`.

Caveats: single host/CDN PoP; certificate verification was disabled; cipher choice is client-order
dependent (Python's OpenSSL negotiated ChaCha20 while these clients negotiated AES-128-GCM); last
flight record varies by 1 byte between runs.
