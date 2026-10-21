# TLS stack spike for beam REALITY

Date: 2026-10-22. Host: Fedora 44, Intel i5-1135G7 (8 threads), 16 GB RAM, `/tmp` tmpfs.
Toolchain: rustc/cargo 1.99.1 (installed under `~/.cargo/bin`, not on PATH). No sudo used.
Work dir: `/tmp/opencode/beam-spike-tls`. No files under `/home/demir/pi/beam` were modified.
All tests are loopback-only; no external server other than crates.io/PyPI/Fedora mirrors.

## TL;DR

- **Use rustls, not `boring`, for beam's production REALITY server.** rustls/ring is 2.1x faster
  than BoringSSL/X25519 (p50 177 vs 366 us) and 2.9x faster than BoringSSL's default PQ handshake,
  builds in 20 s vs 83 s, has no C++/libclang dependency, and produces a 1.85 MB stripped binary
  vs 2.96 MB plus a runtime `libstdc++.so.6` dependency.
- rustls' missing raw-ClientHello API is not a blocker: REALITY must pre-read and authenticate the
  ClientHello for fallback anyway. A thin `Read` tap + replay stream gives exact wire bytes, and
  `ResolvesServerCert` provides dynamic per-SNI certs. Both were demonstrated end-to-end.
- **Cover fidelity is the one reason to prefer aws-lc-rs over ring** (or BoringSSL): ring cannot
  negotiate X25519MLKEM768/GREASE, while rustls+aws-lc-rs with `prefer-post-quantum` and BoringSSL
  can. aws-lc-rs PQ costs ~2x ring server CPU but is still faster than BoringSSL PQ.
- Neither stack can pad or mirror arbitrary cover record sizes. Both only cap record size
  (rustls `max_fragment_size`; BoringSSL `SSL_set_max_send_fragment`, unwrapped). Strict flight-shape
  mirroring needs a custom record layer/fork; do not build that for v1.

## Tool provisioning (no sudo)

Baseline: `gcc`, `make`, `perl`, `python3` present; `cmake`, `ninja`, `clang/libclang`, `g++`,
`go`, `openssl` absent. Portable tools were placed under `/tmp/opencode/tools`:

```bash
# PyPI wheels, extracted with python zipfile (no pip):
#   cmake 4.4.4, ninja 1.13.2, libclang 18.1.1 (manylinux x86_64)
# Fedora 44 updates RPMs, extracted with rpm2cpio | cpio -idm:
#   gcc-c++-16.2.1-2.fc44.x86_64.rpm
#   libstdc++-devel-16.2.1-2.fc44.x86_64.rpm
#   -> /tmp/opencode/tools/fedora ; missing crt*.o/libgcc*/libstdc++.so symlinked
#      to the installed system files; wrapper /tmp/opencode/tools/bin/g++-portable
```

Exact build environment for `boring` and aws-lc:

```bash
export PATH="/tmp/opencode/tools/bin:$HOME/.cargo/bin:$PATH"
export CC=/usr/bin/gcc CXX=/tmp/opencode/tools/bin/g++-portable CMAKE_GENERATOR=Ninja
export LIBRARY_PATH=/tmp/opencode/tools/fedora/usr/lib/gcc/x86_64-redhat-linux/16
export LIBCLANG_PATH=/tmp/opencode/tools/libclang/libclang-18.1.1.data/platlib/clang/native
export BINDGEN_EXTRA_CLANG_ARGS="-isystem /usr/lib/gcc/x86_64-redhat-linux/16/include -isystem /usr/include"
```

Blockers encountered and resolved without sudo:
1. `CMAKE_CXX_COMPILER: c++ is not a full path and was not found` — no C++ compiler. Fixed with
   extracted `gcc-c++` + wrapper.
2. bindgen: `fatal error: 'stddef.h' file not found` — fixed with `BINDGEN_EXTRA_CLANG_ARGS`.
3. link: `unable to find library -lstdc++` — fixed with `LIBRARY_PATH`.
No Go was needed; BoringSSL built without it.

## Build commands and results

```bash
cd /tmp/opencode/beam-spike-tls
CARGO_TARGET_DIR=$PWD/target-time-ring  cargo build -p rustls-spike --release
CARGO_TARGET_DIR=$PWD/target-time-aws   cargo build -p rustls-spike --release \
    --no-default-features --features aws-lc        # or aws-lc-pq
CARGO_TARGET_DIR=$PWD/target-time-boring cargo build -p boring-spike --release
```

| variant | clean build (8 jobs) | build max RSS | unstripped | stripped | crate graph (normal/total) |
|---|---:|---:|---:|---:|---:|
| rustls 0.23 + ring | 20.0 s | 437 MB | 2.19 MB | 1.85 MB | 22 / 28 |
| rustls 0.23 + aws-lc-rs 1.18 | 39.9 s | 457 MB | 4.83 MB | 4.34 MB | 24 / 37 |
| boring 5.3 (BoringSSL) | 82.8 s | 584 MB | 3.39 MB | 2.96 MB | 29 / 55 |

BoringSSL source is 33 MB; build needs cmake+ninja+libclang+C++. `boring` binary links
`libstdc++.so.6` at runtime; rustls/ring links only libc/libgcc_s. aws-lc build needs cmake+CC but no
libclang/C++; PQ is enabled by `rustls/prefer-post-quantum` and adds no C build time.

## Handshake benchmark

Method: 1,000 loopback TLS 1.3 handshakes + 50 warm-up, ECDSA P-256 self-signed cert, one
single-threaded server, sequential client, no client auth, test-only disabled server-cert
verification (not production code), `TCP_NODELAY`. Latency is client-side
handshake-only (`complete_io`/`connect`), excluding TCP connect. Server CPU is server-thread
`CLOCK_THREAD_CPUTIME_ID`; process CPU is `getrusage(RUSAGE_SELF)` (client+server). Three runs each;
ranges are across runs. This VM is noisy; treat ±10-15% as noise.

| stack / config | p50 us | p99 us | server CPU us/handshake | process CPU us/handshake |
|---|---:|---:|---:|---:|
| rustls + ring (X25519) | 174-178 | 254-299 | 144-153 | 289-305 |
| rustls + aws-lc (X25519) | 188-192 | 287-322 | 249-255 | 467-478 |
| rustls + aws-lc PQ (`prefer-post-quantum`) | 256-338 | 412-505 | 301-354 | 588-704 |
| boring default (PQ hybrid) | 515-521 | 710-877 | 311-318 | 694-711 |
| boring `set_curves_list("X25519")` | 364-367 | 506-526 | 256-265 | 527-540 |

First aws-lc handshake pays ~28 ms provider initialization; initialize the provider at process start.
BoringSSL PQ and aws-lc PQ include X25519MLKEM768, so they are not apples-to-apples with the
classical rows; the fair stack comparison is ring vs boring-X25519 (2.1x p50, 1.8x CPU).

## Observed wire shape (first connection)

Sizes include TLS record headers; "server flight" is ServerHello..Finished.

| stack / config | ClientHello record | ClientHello body | Server flight records | Server bytes | ext count |
|---|---:|---:|---|---:|---:|
| rustls ring | 217 | 208 | 127,6,530,184,26 | 873 | 9 |
| rustls aws-lc X25519 | 227 | 218 | 127,6,532,184,26 | 875 | 9 |
| rustls aws-lc PQ | 1447 | 1438 | 1215,6,530,184,26 | 1961 | 9 |
| boring default PQ | 1422 | 1413 (callback body) | 1215,6,512,386,26 | 2145 | 6 |
| boring X25519 | 194 | 185 (callback body) | 127,6,511,386,26 | 1056 | 6 |

The legacy session id was 32 bytes on every stack, e.g. rustls
`a44a0e40e26214550f2cea68fce19e6e...`; boring `003b6e0f09caba6b...`. Extension sets observed:
rustls 002b,0005,000a,000d,0033,002d,0000,000b,0017; boring 0000,000a,000d,0033,002d,002b.
rustls randomizes order of order-insensitive **client** extensions by design; its server extension
order is fixed in code but was not compared byte-for-byte with the cover here. This matters for
cover fingerprinting.

Cover fallback proof:
- rustls: `COVER_FORWARD ch_bytes=219 cover_bytes=219 match=true sha256=7726005cc12c6820`.
- boring: `COVER_FORWARD ch_bytes=1424 cover_bytes=1424 match=true`.

## API capability matrix

| capability | rustls 0.23 | boring 5.3 (BoringSSL) |
|---|---|---|
| raw ClientHello before handshake | No public raw API. `Acceptor::read_tls` + a `Read` tap captures exact wire record (demonstrated). `Accepted::client_hello()` exposes SNI/ALPN/ciphers/groups only. | `set_select_certificate_callback` + `ClientHello::as_bytes()` gives raw CH **body** (no record/handshake headers) before most CH processing and before cert selection. Wire bytes require own pre-read (demonstrated). |
| legacy session id | Not exposed by `ClientHello`; parse wire bytes (32 B demonstrated). | Not exposed by wrapper; parse body at offset 34 (32 B demonstrated). C struct has `session_id`, wrapper omits it. |
| extensions | Parsed from raw wire; no typed extension list (ALPN/groups/ciphers are typed). | `ClientHello::get_extension` for individual extensions; full list from raw body. |
| dynamic cert by SNI | `ResolvesServerCert::resolve` -> `Arc<CertifiedKey>`; 3 distinct cert fingerprints demonstrated. | Callback can call `SslRef::set_certificate`/`set_private_key` per connection; 3 distinct fingerprints demonstrated. |
| pre-handshake cover forwarding | Yes: capture via tap, forward captured record(s) before `into_connection`, skip rustls, relay response. | No callback hand-back: `SelectCertError` only ERROR/RETRY; SSL owns the BIO. Pre-read wire CH + replay stream works (demonstrated). |
| record size cap | `ServerConfig::max_fragment_size` public. 8,000 B app payload: 1x8022 B default vs 5x1417 + 1047 B at 1400. | `SSL_set_max_send_fragment` exists in C but is not wrapped by the safe crate; no safe test. |
| record padding / size mirroring | None. No padding or arbitrary record sizing. | None. No record-padding callback in BoringSSL 5.3; no mirroring. |
| handshake message observation | Socket tap only (used here). No message callback. | Socket tap; C `SSL_CTX_set_msg_callback` exists but is not wrapped by `boring`. |
| GREASE / PQ / Chrome-like shape | ring: no GREASE, no PQ. aws-lc: PQ hybrid with `prefer-post-quantum`. | `set_grease_enabled`; PQ hybrid on by default (patch applied at build). |
| static/cross build | ring: pure Rust + cc/asm; easy musl/cross. aws-lc: cmake+C compiler. | C++/cmake/ninja/libclang, runtime libstdc++; hardest to cross-compile/static-link. |

## Recommendation

**Primary: rustls 0.23.** Use **ring** for the smallest/fastest build and an X25519-only cover.
Use **aws-lc-rs + `prefer-post-quantum`** when the cover/CDN negotiates PQ; it costs ~2x ring server
CPU but is still ~1.5x faster than BoringSSL PQ at p50 and has a much simpler deployment story.
Make the provider a compile-time Cargo feature, not a runtime switch.

**Do not choose boring for v1.** Its early-callback raw CH body is genuinely nicer than rustls'
`Acceptor`, but REALITY must pre-read/parse/authenticate the CH for HMAC and fallback anyway, so the
advantage does not repay 2-3x handshake latency/CPU, the 83 s C++ build, and libstdc++/cross-build
cost. Keep BoringSSL as a **fingerprint oracle** for comparing cover flights, not as the server.

**Do not build a custom TLS stack for v1.** Neither library can mirror record padding/flight shape,
but the realistic gap is negotiated groups/GREASE and extension order, which aws-lc/BoringSSL can
address. A custom record layer only becomes justified if measurement proves cover record sizes are
a reliable distinguisher; then fork rustls rather than write TLS.

## Risks

- rustls has no stable raw-CH/session-id API; offset parsing can break across versions. Pin 0.23,
  keep the parser in `beam-core`, bound every length, and fuzz it.
- ring cannot negotiate PQ/GREASE; if the cover enables them, authenticated connections are
  distinguishable. Choose provider from measured cover behavior, not preference.
- BoringSSL `boring` crate tracks upstream with patches and needs a non-hermetic C++ toolchain;
  its FFI requires `unsafe`, which beam only permits in `beam-sys`.
- Session-ticket counts, extension order, cert-chain length and record splitting differ between
  all three stacks; sizes above are one cert/one client. Real cover parity needs empirical testing.
- Our fallback demo relays a canned cover response, not a live TLS cover. Production needs
  bidirectional splice with timeouts, half-close, bounded buffers, and backpressure.
- Benchmark is one loopback host with a noisy shared CPU; absolute numbers are indicative only.

## Next steps

1. Implement the bounded CH parser + constant-time REALITY HMAC in `beam-core`; fuzz with proptest/
   cargo-fuzz; cover session-id auth and malformed/spanning records.
2. Add a replay stream (`prefix + TcpStream`) into rustls `Acceptor`; verify byte-exact fallback
   against a real cover TLS listener (nginx/OpenSSL, then a PQ-enabled cover).
3. Build a cover-parity harness: compare ServerHello/flight record sizes, extension order, ALPN,
   ticket counts and JA3/JA4 for ring, aws-lc-pq and boring against the chosen cover.
4. Decide provider per cover: ring if cover is classical, aws-lc-pq if cover offers PQ; document in
   `docs/01-compatibility.md` and add tests.
5. Measure static musl and aarch64 cross builds for ring vs aws-lc; package the selected provider.

## Artifacts

`/tmp/opencode/beam-spike-tls/`: `rustls-spike/`, `boring-spike/`, `bin-{ring,aws,aws-pq,boring}`,
`final-*.log`, `time-*.log`, `rs-fallback.log`, `boring-fallback.log`. Reproduce with the commands
above; server/client demos: `bin-ring server --port 9443 --max 3` and
`bin-ring client --port 9443 --sni alpha.test` (same CLI for `bin-boring`).
