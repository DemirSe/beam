# beam

beam is a single-user VLESS + REALITY + Vision + XUDP server in Rust for Linux.
It replaces stock Xray on one small server and keeps compatibility with stock
VLESS clients. It is for one operator who runs one tunnel and wants a small,
auditable server with explicit resource bounds. It is not a multi-user proxy.

## What it does

- **REALITY:** authenticates a TLS 1.3 ClientHello with an X25519/AEAD envelope
  and forwards unauthenticated traffic to a cover destination without an
  authentication oracle.
- **VLESS:** parses the version, user UUID, addons, command, and target address
  inside the authenticated TCP connection.
- **Vision:** pads TLS blocks and switches one direction to raw Direct after a
  valid inner TLS 1.3 ServerHello, preserving bytes already read.
- **XUDP:** carries bounded UDP sessions inside VLESS Mux frames, with legacy
  VLESS UDP and packetaddr modes for stock clients.

## Should you run this?

beam is for one operator who runs one Linux server and one tunnel, can read
systemd journals, and can edit a TOML file. It is not for:

- Teams, shared access, or resold access. beam is not a shared proxy; see
  [Security notes](#security-notes).
- Panels, billing, or per-user limits. There is no account system.
- Windows or macOS as the server.
- Anyone without root, or anyone who wants a one-click client.

It does not protect against:

- Traffic analysis by an adversary who observes both ends.
- The server provider's own logging.
- A misconfigured host.
- A cover site that does not look plausible from the client's network.

Running a proxy may break the host provider's terms of service, and local law
also applies. That decision is the operator's.

## Requirements

- Linux x86_64 and a Rust toolchain. [`rust-toolchain.toml`](rust-toolchain.toml)
  pins the version together with the `clippy` and `rustfmt` components.
- Root to install the service, manage systemd, and bind a low port. Running
  `beam generate` and `beam --check` needs no root.
- **Single user, one inbound.** beam supports one configured user ID. See
  [Security notes](#security-notes) for what that rules out.

## Build

The Makefile's `build` target runs the locked release build. Build and validate
the example configuration with:

```bash
make build
target/release/beam --check -c config.example.toml
```

`make smoke` adds the same config check and a `bash -n` pass over tracked shell
scripts. The example config contains placeholder values only.

## Configure

Start from [`config.example.toml`](config.example.toml). Unknown fields are
errors, and `--check` validates scalar and derived limits before the server
binds a socket. The important keys are:

| Section | Keys |
|---|---|
| `[server]` | `listen` — listener address and port. |
| `[user]` | `id` — client UUID; `flow` — must be `xtls-rprx-vision` for configuration compatibility. |
| `[reality]` | `private_key`, `short_ids`, `server_names`, `dest` — server identity, accepted short IDs and SNI values, and cover destination. |
| `[log]` | `level` — log level. |
| `[limits]` | `max_connections`, `max_udp_destinations`, `max_preauth_per_ip`, `max_xudp_sessions`, `xudp_recv_buffer_bytes`, `listen_backlog`, `shutdown_drain_ms`, `handshake_timeout_ms`, `idle_timeout_ms`. |

`handshake_timeout_ms` must be at least 100 and `idle_timeout_ms` at least
1000; both are capped at 24 hours. `max_xudp_sessions` also sizes the legacy
UDP stream pool and the XUDP kernel buffer budget. Keep it at 200 or more when
a legacy or packetaddr client bursts short UDP flows.

Generate a new identity under a restrictive umask, then put the server fragment
into a copy of the example config:

```bash
cp config.example.toml config.toml
(umask 077; target/release/beam generate --host example.com --sni example.com > identity.txt)
chmod 600 config.toml identity.txt
target/release/beam --check -c config.toml
```

The umask applies only to the subshell, so later build and test commands keep
their normal modes. Both files hold secrets and are git-ignored.

Replace every placeholder. Keep secrets out of git. Use mode `0600` locally
and root:beam `0640` on the service host. See
[Security notes](#security-notes) for the full rule.

## Run

Start the built binary with the config path:

```bash
target/release/beam -c /etc/beam/config.toml
```

The default config path is `/etc/beam/config.toml`. For systemd, use
[`deploy/beam.service`](deploy/beam.service) as the unit. It runs
`/usr/local/bin/beam -c /etc/beam/config.toml` as the unprivileged `beam` user,
runs `--check` first, and sets resource and sandbox limits. It expects the
config to be readable by the service user. `SIGHUP` is ignored; restart the
service to reload configuration. `SIGTERM` stops accepting, drains for at most
`shutdown_drain_ms`, then bounds runtime shutdown.

Before you run an installer, read [Deploy](#deploy) below. The deploy scripts
make host policy changes. Do not run an installer unless you can reach the
host's provider console. The step-by-step mechanics are in
[`docs/DEPLOY.md`](docs/DEPLOY.md).

## Deploy

Read this section before you change a host. It gives the choices and checks
that must exist before you run any command in the runbook. If you cannot meet a
requirement, stop.

### Choose the host

- Use the smallest dedicated server that fits one tunnel.
- Choose a provider that allows the traffic you intend to send and receive.
- Choose a region that makes your cover name plausible.
- Choose a provider console or rescue mode that you tested.
- Do not use a shared host with other services. Other services on the host
  increase the blast radius.

### Prepare the host

1. Use your own account with key-only SSH and passwordless sudo. The scripts
   need root.
2. Use AlmaLinux 10 for `bootstrap-alma.sh` or Debian 13 for `bootstrap.sh`.
   Both scripts also require x86_64. `beam-install.sh` checks systemd, not a
   distribution.
3. Keep the provider console reachable while you work.
4. Take a snapshot or a backup that you can restore.
5. Install the required tools before you run a script. None of the three
   scripts installs OS packages. `bootstrap.sh` needs `/usr/sbin/sshd`,
   `ssh.service`, the `sshd_config.d` Include, `ip`, `ss`, `sysctl`, and
   `runuser`. When present, it uses `modprobe` and `tc`. `bootstrap-alma.sh`
   needs `ip`, `ss`, `sysctl`, `nft`, `chronyc`, `systemctl`, `runuser`, and
   `restorecon`. `beam-install.sh` needs `systemctl`, `sha256sum`, `getent`,
   `groupadd`, `useradd`, `runuser`, and `install`. It also needs `tar` with
   `BEAM_ARTIFACT`.

### Recommended minimum posture

- Keep the provider console open until the last verification passes.
- Take the snapshot before the first change.
- Pin the release artifact by hash with `BEAM_SHA256` or its sidecar file.
- Keep the config at 0600 and out of git.
- Change one thing at a time.
- Keep a rollback path for each changed file and for each host policy.
- Watch the journal after each step.

Each script has a fixed boundary. [`docs/DEPLOY.md`](docs/DEPLOY.md) lists what
it changes and what it leaves to you, and gives the order of operations with a
safe stopping point after each step.

## Verify

The Makefile is the single source for the local gate. Run it before you
commit:

```bash
make verify
```

It runs `cargo fmt --all --check`,
`cargo clippy --workspace --all-targets -- -D warnings`, and
`cargo test --workspace`. The `test` target runs these rootless script suites
before the cargo tests:

```bash
python3 tests/bench/test_report.py
python3 tests/tun/test_protocol_report.py
python3 tests/test_ipv4_only.py
python3 tests/deploy/test_deploy_contracts.py
python3 tests/deploy/test_restart_policy.py
python3 tests/deploy/test_liveness_check.py
python3 tests/release/test_release_artifact.py
bash tests/deploy/test_alma_install.sh
bash tests/deploy/test_beam_install.sh
bash tests/linux-tray/test_dns_state.sh
```

Parser changes also require the relevant fuzz target; hot-path changes require
a benchmark comparison. Root, TUN, netem, stress, soak, and long benchmark
runs belong in hosted CI, not in this local loop. See
[AGENTS.md](AGENTS.md#verification-before-every-commit) for the full rule.

## Architecture

- `beam` owns process lifecycle, CLI, config loading, logging, signals, and the
  listener. It contains no protocol implementation.
- `beam-core` owns TLS and ClientHello handling, REALITY, VLESS, Vision, XUDP,
  legacy UDP, packetaddr, relay logic, config validation, and metrics. It stays
  testable without root or a network.
- `beam-sys` owns the only `unsafe` code: `splice`, fd helpers, socket options,
  and eventfd. See [AGENTS.md](AGENTS.md#golden-rules) for the `unsafe` rule.

The TLS path pre-reads and authenticates ClientHello, then uses rustls through
a record-bounded `TlsStream` that owns the TLS record boundary. TCP uses a
blocking `splice(2)` fast path with a bounded async-copy fallback. XUDP uses
one outbound UDP socket per session, a per-mux session table, and a
process-wide session limiter.

## Repository layout

| Path | Holds |
|---|---|
| `crates/` | The Rust workspace: `beam`, `beam-core`, `beam-sys`. |
| `deploy/` | Files installed on a host: systemd units, sysctl and nftables drops, sshd and DNS drop-ins, installers. |
| `scripts/` | Developer tooling that runs on your machine and is never installed. |
| `bench/` | The TUN A/B benchmark and soak harness. Its own test is `tests/bench/`. |
| `tests/` | Rootless suites, plus the TUN harness and its Rust origin in `tests/tun/`. |
| `fuzz/` | cargo-fuzz targets, kept in a separate workspace. |
| `clients/` | Optional tray clients for Linux and Windows. Not needed to run the server. |
| `docs/` | Server runbook, client setup, and the historical audits. |

## Compatibility

This section is the single source of truth for wire behavior. Update it and
add a test when wire behavior changes. The server must stay compatible with
stock clients that use the same UUID, public key, short ID, SNI, and flow.

### REALITY

- REALITY uses the TLS 1.3 ClientHello `legacy_session_id` as a 32-byte
  envelope: client ciphertext then server tag.
- The plaintext carries client version, timestamp, and 8-byte short ID. The
  key is X25519 + HKDF-SHA256 with info `REALITY`; the payload is AES-256-GCM
  with the ClientHello as associated data. No HMAC is in the envelope; the
  temporary certificate is authenticated separately with HMAC-SHA512.
- Prefer a standalone X25519 key share; otherwise use the final 32 bytes of
  an exact 1216-byte `X25519MLKEM768` share. Reject low-order/non-contributory
  X25519 shares.
- Check SNI exactly, then the share, AEAD, client version range, optional
  timestamp skew, and constant-time short-ID membership. Never expose an
  authentication oracle: unauthenticated or failed probes go to the cover.
- Short IDs are validated and decoded at startup into fixed 8-byte values;
  comparisons are constant-time.
- Stock has no replay cache. beam reserves in-flight handshakes before TLS and
  inserts the first Finished handshake into a bounded exact-replay cache.
  Capacity scales with `max_connections` (128x, clamped to 4096..131072) and is
  wired to `limits.max_connections`. Each entry is retained until its
  authenticated envelope timestamp plus the REALITY timestamp window plus one
  second: a timestamp at the current time is retained for 301 s, and the worst
  case for a timestamp five minutes in the future is 601 s. A settled entry
  with admitted concurrent copies is held until those copies drain even past
  that deadline, so first-wins is preserved. The deadline is monotonic; keep
  the server clock disciplined, because a backward wall-clock step can keep an
  envelope timestamp acceptable past the cache deadline. A full cache rejects
  the new handshake instead of evicting a live id; `replay_cache_full` counts
  that case separately from a duplicate ClientHello. Concurrent duplicates are
  first-wins: a second Finished handshake is closed rather than served. This
  bounds the in-flight permit race, the post-cache window, and cache pressure.
- Unauthenticated traffic is relayed to the configured cover. Never send a
  TLS alert or a synthetic response on authentication failure.
- A cover relay ends on the first half-close: once the probe's write side
  finishes (FIN or reset), beam releases the relay and its cover permit as
  soon as that direction's shutdown completes, instead of holding them until
  the 30 s cover idle timeout. This is a deliberate parity tradeoff: a
  response the cover would send after the probe's FIN is not forwarded, and a
  cover-first close cancels the remaining upload. The authenticated relay keeps
  its TCP half-close semantics, so an idle direction cannot cut a
  download-only Vision stream. Bounding unauthenticated retention keeps the
  cover cap from being pinned by disconnected probes.

### VLESS and Vision

- VLESS request: version, 16-byte UUID, addons, command, optional port and
  target address. Commands: TCP, UDP, Mux, Rvs. The response is always
  `00 00`; unknown or malformed commands are rejected.
- Vision first block per direction carries the raw 16-byte UUID. Blocks carry
  command, content length, padding length, content, and zero padding. Padding
  follows the stock long/short rules, is clamped to the frame bound, and is
  symmetric in both directions.
- Direct is enabled only for a complete inner TLS application-data record
  after the expected TLS 1.3 ServerHello: TLS detected and the stock enable
  condition satisfied. The last padded block is Direct; subsequent raw reads
  and writes bypass Vision framing for that direction only.
- Direct handoff preserves bytes already read ahead and same-record leftovers;
  write pending outer TLS ciphertext before raw data. Each direction can be
  raw independently. There is no outer `close_notify` after Direct; FIN ends
  one direction.
- Unknown Vision commands, overlong lengths, and malformed state transitions
  are rejected rather than passed through and desynchronized.

### XUDP, legacy UDP, and packetaddr

- XUDP is carried in VLESS Mux frames: metadata length, stream ID, status,
  option, optional destination, optional GlobalID, payload length, payload.
  Statuses are New, Keep, End, KeepAlive; options are Data and Error.
- Clients generally send New/Keep and close the flow with TCP FIN; do not
  require an End. Keep frames may carry a per-datagram destination; empty or
  non-Data Keeps do not update the session destination, and address-less Keeps
  reuse the last destination accepted from `New` or a non-empty Data Keep.
  Replies are Keep with Data, plus End on closure (Error only when relay
  failed). An unknown stream ID gets a clean End and is discarded.
- Accept zero GlobalID and per-frame destinations from sing-box. A nonzero
  GlobalID may reattach a retained socket only within the same mux and user;
  never use GlobalID as identity or policy.
- XUDP datagram payloads are capped at 8192 bytes; empty or oversize
  datagrams are dropped. Legacy UDP is capped at 8190 bytes. packetaddr uses
  the magic `sp.packet-addr.v2fly.arpa` destination and carries an inner
  address per datagram. A 100 ms send timeout or a transient send error
  (`WouldBlock`, `TimedOut`, `Interrupted`) on the fixed-destination legacy
  path drops only that datagram; other send errors close the association.
- Session sockets remain unconnected and accept replies from arbitrary UDP
  sources. This preserves stock XUDP/full-cone behavior (STUN, WebRTC, P2P).
  Only a valid, non-empty reply that passes size/frame/queue/byte-budget checks
  and is handed to the writer refreshes the idle clock. Zero-length, oversize,
  encoding-drop, queue-drop, and budget-drop datagrams do **not** refresh it.
  "Valid" here means size/frame/admission-valid, not application-validated: a
  sender that can reach the ephemeral port with an admissible datagram can
  still keep the session active while the mux remains open. The queue and byte
  budgets bound outstanding memory, not session lifetime; this is inherent to
  keeping arbitrary-source/full-cone replies.
- Domain `New`/`Keep` frames are queued per session id while a bounded
  per-mux resolver performs DNS; the lookup owner and suffix are tracked
  separately, results carry a generation, and a newer GlobalID cancels older
  pending New frames. IP frames, queued suffixes, and rejected replies retain
  their ordering. Resolved domains are cached for 300 seconds. A mux runs at
  most four concurrent lookups; the resolver permit is held until the result
  is queued, so a full result channel backpressures the request queue instead
  of spawning unbounded tasks. Pending payload has a process-wide 4 MiB budget
  plus bounded metadata, and UDP send/close waits are capped at 100 ms. This is
  not universally nonblocking: a sequence of slow domains, a congested send,
  or many close operations can still delay a mux briefly.
- Reply bytes are bounded by a 2 MiB per-mux budget inside the 32 MiB
  process-wide budget; one slow reader cannot hold the whole global allowance.
- An empty mux closes after `session_idle_timeout` even while KeepAlive frames
  arrive or a retained GlobalID socket is waiting for `close_expiry`. Retained
  sockets do not extend the empty-mux timer.
- XUDP limits come from `limits.max_xudp_sessions` and
  `limits.xudp_recv_buffer_bytes` (example defaults: 256 sessions and 128 KiB
  per socket). A mux holds at most half the global active slots. XUDP idle
  expiry is at most 60 seconds even when `idle_timeout_ms` is 300 seconds.
- Legacy/packetaddr UDP holds one stream permit per VLESS `Command::Udp`
  connection, and the pool equals `max_xudp_sessions` (256 with the example
  config); a stream owns one relay socket, or up to two in packetaddr mode when
  both address families bind. The legacy idle clock is capped at 60 seconds
  like the XUDP one, so with the documented 300 s `idle_timeout_ms` an idle
  flow releases its permit five times sooner than the TCP relay would; a send
  or an admitted reply resets the clock. The effective clock is
  `min(idle_timeout_ms, 60 s)`, so a smaller configured value shortens UDP
  flows too. Legacy relay sockets keep the kernel's default receive buffer;
  only XUDP requests `xudp_recv_buffer_bytes`. A stub resolver opens one UDP
  socket per query, so a DNS burst is a burst of streams: it is admitted from
  this pool and, at the cap, refused as `TlsServerError::LegacyUdpLimited` and
  counted in `legacy_udp_limited`. `max_xudp_sessions` also sizes the XUDP
  kernel buffer budget, so lowering it to save memory lowers this pool as well.

### TLS stack, cover, and MTU

- TLS is rustls 0.23 + aws-lc-rs with the `prefer-post-quantum` feature.
  Initialize `aws_lc_rs::default_provider()` at startup. Do not replace it
  with BoringSSL or a custom TLS implementation for v1.
- Cover parity is **SNI-level**: matching SNI, certificate, TLS 1.3/PQ group,
  cipher behavior, and normal unauthenticated forwarding are enough. Plaintext
  extension order and encrypted-flight size may differ; do not gate a deploy
  on them.
- The default cover is `whatsapp.net:443`, PQ-capable (`X25519MLKEM768`), TLS
  1.3, AES-128-GCM, ALPN `h2`. Authenticated connections do not dial the cover.
- Set `TCP_MAXSEG=1400` before connecting every target and cover socket. This
  creates an effective advertised MSS around 1388 and avoids 1460-byte PMTU
  black holes on some paths. Host TCP traffic is not clamped.
- Keep `net.ipv4.tcp_mtu_probing=0` unless a measured PMTU failure justifies a
  change. Client TUN profiles use MTU 1500; lowering that MTU loses some
  HTTP/3 paths and stalls large H3 bodies in gVisor.

## Security notes

- **Single-user only.** One user ID, one inbound, and no account system. beam
  makes no multi-tenant claim and has no per-user isolation, panels, billing,
  or per-user limits. Do not expose it as a shared proxy.
- Treat every byte from the network as hostile. Authentication failures go to
  the cover; malformed authenticated input is rejected.
- Keep the config and private key out of git. Use mode `0600` locally and
  root:beam `0640` on the service host. Never log secrets or raw key material.
- Authentication material uses constant-time comparison. `unsafe` stays in
  `beam-sys`, and each block needs a `// SAFETY:` invariant. See
  [AGENTS.md](AGENTS.md#golden-rules).
- Known gaps and test gaps are tracked in [`ISSUES.md`](docs/ISSUES.md) and
  [`TODO.md`](docs/TODO.md). Report vulnerabilities privately per
  [`SECURITY.md`](SECURITY.md); contributions follow
  [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the build and test commands, the
change rules, and the paths to the architecture and audit notes.

## License

Released under the [MIT License](LICENSE).
