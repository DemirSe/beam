# Local full-TUN interoperability harness

Status: implemented and verified on 2026-10-22. This document describes
`tests/tun/run.sh`, the local lab that drives the real sing-box v1.14.3
full-TUN client through `beam`.

The harness is intentionally separate from `docs/06-benchmark-harness.md`: it
checks correctness and honest capability reporting, not throughput or latency.
It never uses a VPS, an external network, or production credentials.

## What it exercises

```text
client namespace                         server namespace                  target namespace
  10.10.1.2/24  -- vc | sc --  10.10.1.1/24
  tun0 198.18.0.1/15, fd00:1::1/64
  routes 10.10.2.0/24, fd00:2::/64 to tun0
                                          vs 10.10.2.1/24, fd00:2::1/64 -- ts 10.10.2.2/24
                                                                           fd00:2::2/64
  sing-box TUN inbound                    beam VLESS+REALITY+Vision :443    HTTP :8080 (v4/v6)
  VLESS outbound, xudp, utls chrome                                         HTTPS :4443
                                                                            UDP echo :9999
                                                                            DNS :53
                                                                            QUIC sink UDP :4443
```

The outer REALITY connection uses `10.10.1.1:443`. The target subnet
`10.10.2.0/24` exists only on the server/target link, so the client can reach
the target only through the TUN and the VLESS tunnel. The client namespace has
no default route; only the two target routes are installed. The server
namespace has no default route either. Accidental external traffic fails
immediately instead of leaving the host.

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
bash tests/tun/run.sh --no-build         # reuse the existing binary
bash tests/tun/run.sh --out /tmp/my-run  # explicit run directory
SKIP_BUILD=1 bash tests/tun/run.sh       # same as --no-build
```

Environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `SING_BOX` | `/tmp/opencode/bench/bin/sing-box` | sing-box v1.14.3 binary |
| `XRAY_BIN` | `/tmp/opencode/xray-server-compare/xray` | stock Xray control |
| `TEST_CONFIG` | `/tmp/opencode/beam-test/beam.toml` | test REALITY fixture |
| `TUN_OUT` | `/tmp/opencode/beam-tun/<UTC>-<pid>` | run directory |
| `SKIP_BUILD` | `0` | reuse `target/<profile>/beam` |
| `TUN_FORCE_BLOCK` | `0` | force the TUN-blocked reporting path (test hook) |

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

## Verified result table (2026-10-22, beam worktree `feat/tun-harness`)

| Test | beam | Detail |
|---|---|---|
| `tcp-http-v4` | **PASS** | HTTP 200, body `beam-tun-ok` through TUN → VLESS → target `10.10.2.2:8080` |
| `tcp-http-v6` | **PASS** | HTTP 200, body `beam-tun-ok` through TUN → VLESS → target `[fd00:2::2]:8080` |
| `udp-echo` | **BLOCKED** | XUDP not integrated; target `10.10.2.2:9999` is never reached |
| `dns-udp` | **BLOCKED** | Same XUDP blocker; `dig @10.10.2.2 target.test` times out |
| `quic-udp` | **BLOCKED** | Same XUDP blocker; HTTP/3 attempt to UDP `10.10.2.2:4443` times out |
| `https-direct` | **BLOCKED** | Vision Direct not integrated; inner TLS reaches ServerHello, then the server closes |

The stock Xray control on the same topology and the same sing-box client
proves the harness itself is capable of the blocked paths:

| Test | stock Xray | Detail |
|---|---|---|
| `tcp-http-v4` | **PASS** | HTTP 200 |
| `tcp-http-v6` | **PASS** | HTTP 200 |
| `udp-echo` | **PASS** | Exact payload echoed through XUDP |
| `dns-udp` | **PASS** | `NOERROR`, A record `10.10.2.2` |
| `quic-udp` | **BLOCKED** | UDP reaches the target QUIC sink, but there is no local HTTP/3 origin |
| `https-direct` | **PASS** | HTTP 200 through Vision Direct |

Run the control with:

```bash
bash tests/tun/run.sh --control
```

## Exact blockers

### XUDP / UDP / DNS / QUIC

`beam-core/src/tls/server.rs` handles only `Command::Tcp`. Every other command
is logged and the connection is closed:

```text
WARN beam_core::tls::server: authenticated VLESS command is not implemented yet; closing command=Mux
```

sing-box with `packet_encoding: xudp` sends UDP as a Mux command, so the UDP
echo, DNS, and QUIC probes all hit this line. The target services are healthy;
the stock Xray control echoes UDP and answers DNS on the same topology. This is
a server capability blocker, not a harness failure.

### Vision Direct / HTTPS

`crates/beam-core/src/vision/stream.rs` rejects the Direct transition with:

```text
DEBUG beam: connection failed peer=... error=I/O error: Vision Direct mode is not supported in this milestone
```

The client completes the inner TLS handshake (an earlier probe variant reported
`TLSv1.3`), then the first inner application-data record asks for Vision Direct.
`beam` rejects that record instead of forwarding it, so the target never sees
the HTTP request and `curl` reports an unexpected EOF. The stock Xray control
returns HTTP 200 from the same origin. This is a server capability blocker.

### QUIC / HTTP/3

QUIC uses UDP/443 (here UDP/4443). It is blocked by the XUDP limitation before
any target is reached. In addition, this lab has no local HTTP/3 origin, so
even a server with working UDP cannot complete an HTTP/3 request. The harness
sends a real `curl --http3-only` attempt to UDP/4443 and records the failure.
The target has a UDP sink on 4443 only to distinguish "packet reached the
target" from "the tunnel dropped it"; the sink does not speak HTTP/3. This is
reported as `BLOCKED`, never as `PASS`.

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
logs/target.log           target services and QUIC sink
logs/xray.log             control only
probes/beam/*.log|json    per-probe client output and structured result
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
- QUIC has no local HTTP/3 origin, so the best possible result here is proving
  that a real HTTP/3 attempt reaches the intended UDP destination. It is
  `BLOCKED` until both XUDP and a local H3 origin exist.
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
