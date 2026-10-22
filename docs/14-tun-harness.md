# Local full-TUN interoperability harness

Status: implemented and verified on 2026-10-22. This document describes
`tests/tun/run.sh`, the local lab that drives the real sing-box v1.14.3
full-TUN client through `beam`. The IPv6 UDP/DNS probes and the local HTTP/3
origin are part of this harness. The default UDP arm is `xudp`; `--udp-mode`
also selects the legacy VLESS UDP and packetaddr arms.

The harness is intentionally separate from `docs/06-benchmark-harness.md`: it
checks correctness and honest capability reporting, not throughput or latency.
The measured path never uses a VPS, an external network, or production
credentials; only the one-time H3 dependency build runs outside the private
network namespace.

## What it exercises

```text
client namespace                         server namespace                  target namespace
  10.10.1.2/24  -- vc | sc --  10.10.1.1/24
  tun0 198.18.0.1/15, fd00:1::1/64
  routes 10.10.2.0/24, fd00:2::/64 to tun0
                                          vs 10.10.2.1/24, fd00:2::1/64 -- ts 10.10.2.2/24
                                                                           fd00:2::2/64
  sing-box TUN inbound                    beam VLESS+REALITY+Vision :443    HTTP :8080 (v4/v6)
  VLESS outbound, udp mode, utls chrome                                     HTTPS :4443
                                                                            UDP echo :9999 (v4/v6)
                                                                            DNS :53 (v4/v6)
                                                                            HTTP/3 origin UDP :4443
```

The outer REALITY connection uses `10.10.1.1:443`. The target subnet
`10.10.2.0/24` exists only on the server/target link, so the client can reach
the target only through the TUN and the VLESS tunnel. The client namespace has
no default route; only the two target routes are installed. The server
namespace has no default route either. Accidental external traffic fails
immediately instead of leaving the host.

The target runs IPv4 and IPv6 UDP echo and DNS services on the same ports
(`9999` and `53`). The `quic-udp` row uses a real HTTP/3 origin on
`10.10.2.2:4443`, not a UDP echo: `tests/tun/h3-origin` terminates QUIC and
HTTP/3, then serves the fixed body `beam-tun-h3-ok`. If that helper cannot be
built, the harness falls back to a UDP sink on the same address and reports
`quic-udp` as BLOCKED with the build error; it never reports a fake pass.

The sing-box outbound is the production profile:

```json
{
  "type": "vless",
  "server": "10.10.1.1",
  "server_port": 443,
  "flow": "xtls-rprx-vision",
  "packet_encoding": "xudp",
  "tls": {
    "enabled": true,
    "server_name": "whatsapp.net",
    "utls": { "enabled": true, "fingerprint": "chrome" },
    "reality": {
      "enabled": true,
      "public_key": "<derived from the test private key>",
      "short_id": "0123456789abcdef"
    }
  }
}
```

`--udp-mode` rewrites `packet_encoding` to `packetaddr` or to the empty string
(`legacy`) for the compatibility arms; the default stays `xudp`.

`config.py` reads the UUID, private key, short id, and SNI from the test
fixture, derives the X25519 public key with a small RFC 7748 implementation,
and writes `beam.toml`, `singbox.json`, and optionally `xray-server.json` into
the run directory. Nothing is hard-coded except the lab addresses and the
fixture path.

## How to run

```bash
cd /home/demir/pi/beam        # or the worktree under test
source scripts/dev-env.sh
bash -n tests/tun/run.sh
bash tests/tun/run.sh
```

Optional arms and overrides:

```bash
bash tests/tun/run.sh --control          # add the stock Xray control arm
bash tests/tun/run.sh --release          # build target/release/beam
bash tests/tun/run.sh --no-build         # reuse the existing binaries
bash tests/tun/run.sh --out /tmp/my-run  # explicit run directory
bash tests/tun/run.sh --udp-mode packetaddr  # packetaddr UDP
bash tests/tun/run.sh --udp-mode legacy      # packet_encoding ""
SKIP_BUILD=1 bash tests/tun/run.sh       # same as --no-build
```

The first run also builds the H3 helper outside the private network namespace,
where crates.io is reachable. `--no-build` and `SKIP_BUILD=1` reuse
`tests/tun/h3-origin/target/debug/h3-origin`; set `H3_ORIGIN_BIN` to use a
different prebuilt binary. The measured path itself never reaches an external
network.

Environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `SING_BOX` | `/tmp/opencode/bench/bin/sing-box` | sing-box v1.14.3 binary |
| `XRAY_BIN` | `/tmp/opencode/xray-server-compare/xray` | stock Xray control |
| `TEST_CONFIG` | `/tmp/opencode/beam-test/beam.toml` | test REALITY fixture |
| `TUN_OUT` | `/tmp/opencode/beam-tun/<UTC>-<pid>` | run directory |
| `SKIP_BUILD` | `0` | reuse `target/<profile>/beam` and the H3 origin |
| `H3_ORIGIN_BIN` | built helper | use a prebuilt `h3-origin` binary |
| `UDP_MODE` | `xudp` | sing-box `packet_encoding`: `xudp`, `packetaddr`, or `legacy` |
| `TUN_FORCE_BLOCK` | `0` | force the TUN-blocked reporting path (test hook) |

### Local HTTP/3 origin

`tests/tun/h3-origin` is a separate Cargo workspace, deliberately not a member
of the root workspace. It uses `quinn` 0.11, `h3`, `h3-quinn`, `rustls`,
`rcgen`, and `tokio`; none of those become production `beam` dependencies. The
server generates a fresh self-signed certificate in memory, advertises the
`h3` ALPN, and answers every request with HTTP 200 and the fixed body
`beam-tun-h3-ok`.

Build it with:

```bash
source scripts/dev-env.sh
cargo build --locked --manifest-path tests/tun/h3-origin/Cargo.toml
```

Run it by hand on loopback:

```bash
tests/tun/h3-origin/target/debug/h3-origin --listen 127.0.0.1:4443
curl --http3-only --insecure --noproxy '*' https://127.0.0.1:4443/
```

`run.sh` builds the helper before entering the private network namespace and
starts it in the target namespace on `10.10.2.2:4443`. If the build fails, the
`quic-udp` row is BLOCKED with the last cargo error. If the binary builds but
does not become ready, that is a harness failure, not a fake pass.

The script re-execs itself under
`unshare --user --map-root-user --mount --net`. It mounts a private tmpfs on
`/run`, creates the three network namespaces, and tears everything down in an
`EXIT`/`INT`/`TERM` trap. Every process is killed, then each namespace is
deleted. Logs and probe results stay under the run directory.

## Result semantics

| Result | Meaning | Exit status |
|---|---|---|
| `PASS` | Probe succeeded and validated the expected payload/response. | 0 |
| `BLOCKED` | The current server lacks the path, or the environment cannot provide it. The exact error/log line is included. | 0 |
| `FAIL` | Unexpected failure. The run continues, but the script exits non-zero. | 1 |
| harness failure | Build, namespace, process startup, or fixture failure. | 1 |

A known server limitation is never reported as `PASS` and does not make the
run fail. A `BLOCKED` row is deliberately explicit; the table includes the
observed client error and the matching server log message.

## Verified result table (2026-10-22)

Default `--udp-mode xudp` arm:

| Test | beam | Detail |
|---|---|---|
| `tcp-http-v4` | **PASS** | HTTP 200, body `beam-tun-ok` through TUN → VLESS → target `10.10.2.2:8080` |
| `tcp-http-v6` | **PASS** | HTTP 200, body `beam-tun-ok` through TUN → VLESS → target `[fd00:2::2]:8080` |
| `udp-echo` | **PASS** | Exact payload echoed through XUDP to `10.10.2.2:9999` |
| `udp-echo-v6` | **PASS** | Exact payload echoed through XUDP to `[fd00:2::2]:9999` |
| `dns-udp` | **PASS** | `NOERROR`, A record `10.10.2.2` |
| `dns-udp-v6` | **PASS** | `NOERROR`, AAAA record `fd00:2::2` |
| `quic-udp` | **PASS** | HTTP/3 200, body `beam-tun-h3-ok` from the local origin |
| `https-direct` | **PASS** | `http=200` through the Vision Direct raw TLS handoff |

UDP encoding arms run on 2026-10-22 with the same sing-box v1.14.3 client:

| Arm | `packet_encoding` | Result | Evidence |
|---|---|---|---|
| `xudp` | `"xudp"` | **8/8 PASS** | default full-TUN arm |
| `packetaddr` | `"packetaddr"` | **8/8 PASS** | `/tmp/opencode/tun-packetaddr`; beam logs `Authenticated { command: Udp }` for the five UDP flows |
| `legacy` | `""` | **8/8 PASS** | `/tmp/opencode/tun-legacy`; beam logs `Authenticated { command: Udp }` for the five UDP flows |

The stock Xray control on the same topology and the same sing-box client
proves the harness itself is capable of every path:

| Test | stock Xray | Detail |
|---|---|---|
| `tcp-http-v4` | **PASS** | HTTP 200 |
| `tcp-http-v6` | **PASS** | HTTP 200 |
| `udp-echo` | **PASS** | Exact payload echoed through XUDP to `10.10.2.2:9999` |
| `udp-echo-v6` | **PASS** | Exact payload echoed through XUDP to `[fd00:2::2]:9999` |
| `dns-udp` | **PASS** | `NOERROR`, A record `10.10.2.2` |
| `dns-udp-v6` | **PASS** | `NOERROR`, AAAA record `fd00:2::2` |
| `quic-udp` | **PASS** | HTTP/3 200, body `beam-tun-h3-ok` from the local origin |
| `https-direct` | **PASS** | HTTP 200 through Vision Direct |

Run the control with:

```bash
bash tests/tun/run.sh --control
```

## Blockers, past and present

### XUDP / UDP / DNS / QUIC (resolved)

`Command::Mux` (XUDP), `Command::Udp` (legacy and packetaddr), and both
address families are implemented. The UDP echo, DNS, and QUIC rows pass in all
three UDP encoding arms. A connection that selects an unimplemented command
(such as `Command::Rvs`) is still logged and closed:

```text
WARN beam_core::tls::server: authenticated VLESS command is not implemented yet; closing command=Rvs
```

### Vision Direct / HTTPS (resolved)

The Direct raw TLS handoff is implemented and the `https-direct` row now
passes with `http=200`. The probe remains in the suite as a regression check;
it exercises the inner TLS connection through the same full-TUN client.

### QUIC / HTTP/3

QUIC uses UDP/443 (here UDP/4443). The target runs a real HTTP/3 origin that
terminates QUIC and serves `beam-tun-h3-ok`; the harness sends
`curl --http3-only --insecure` through the TUN and validates both the status
and the body. Both `beam` and the stock Xray control complete this request
(HTTP/3 200) in every UDP encoding arm.

When the H3 helper is unavailable, the target falls back to a UDP sink on 4443
to distinguish "packet reached the target" from "the tunnel dropped it". The
sink never speaks HTTP/3, so that fallback is reported as BLOCKED with the
build error, never as PASS.

### Full TUN unavailable

The script probes the client namespace with:

```bash
ip netns exec tun-client ip tuntap add dev tunprobe mode tun
```

If `/dev/net/tun` is missing or TUN creation is denied, all rows are reported
as `BLOCKED` with the exact `ip tuntap` error, and the script exits 0. There is
no SOCKS/redirect fallback: a TUN-less proxy path would not exercise the
full-TUN client path that this harness is meant to test. The same reporting
path can be checked with `TUN_FORCE_BLOCK=1`.

On this host `/dev/net/tun` is present (`crw-rw-rw-`) and the TUN device is
created successfully inside the user namespace, so the full-TUN tests run.

## Artifacts

A run directory contains:

```text
config/beam.toml          rewritten fixture (listen, cover, timeouts)
config/singbox.json       full-TUN client
config/xray-server.json   control only
config/target.{crt,key}   generated self-signed HTTPS test certificate
logs/beam.log             beam debug log
logs/singbox.log          sing-box debug log
logs/target.log           IPv4/IPv6 target services and optional QUIC sink
logs/h3-origin.log        local HTTP/3 origin and per-request log
logs/h3-origin-build.log  cargo output when run.sh built the helper
logs/xray.log             control only
probes/beam/*.log|json    per-probe client output and structured result
probes/*/quic-udp.body    HTTP/3 response body (must contain beam-tun-h3-ok)
probes/xray/*.log|json    control probes
network.txt               addresses, routes, links from all namespaces
results-beam.tsv          name, result, detail
results-xray.tsv          control only
environment.txt           binary paths and versions
```

The run directory is mode 0700 and files are 0600. The REALITY fixture and the
generated TLS key are test-only material under `/tmp/opencode`; they are not
repository files and must not be replaced with production values.

## Limits

- This is not a benchmark. It does not use `tc netem`, CPU pinning, or
  throughput/latency measurement; use `docs/06-benchmark-harness.md` for that.
- The REALITY cover is a local self-signed HTTPS target. Cover parity is
  covered by `scripts/cover-parity.sh`, not here.
- The client is sing-box v1.14.3. Hiddify and stock Xray clients are a separate
  compatibility matrix (`docs/01-compatibility.md`).
- The H3 helper is test-only and lives in its own workspace under
  `tests/tun/h3-origin`; `cargo build --workspace` at the repository root does
  not build it and production `beam` does not depend on it.
- QUIC has a real local HTTP/3 origin, and both `beam` and the stock Xray
  control complete the request. No further origin work is required.
- ICMP is not carried by VLESS and is not tested; stock Xray has the same
  limitation (`docs/00-scope.md`).
- The client namespace logs `network: missing default interface` at startup
  because only the target subnets are routed. Proxied TCP and IPv6 flows are
  unaffected; the message is recorded in `logs/singbox.log`.

## Verification

```bash
source scripts/dev-env.sh
bash -n tests/tun/run.sh
bash tests/tun/run.sh
bash tests/tun/run.sh --control
```

On a host without unprivileged user namespaces the outer `unshare` probe fails
before any test and the script exits non-zero as a harness failure. That is
expected: the full-TUN lab requires user namespaces and `/dev/net/tun`.
