# Fix: Vision Direct eagerly duplicates four fds per connection

> **TEMPORARY FILE — delete after the fix is merged and verified.** This note
> is the detailed work item behind `STRESS-FINDINGS.md` #10. Remove this file
> and the pointer in `STRESS-FINDINGS.md` when #10 is closed.

## Summary

`relay_vision` eagerly duplicates four descriptors for every Vision TCP
connection, before it knows whether either direction will actually hand off to
the raw-socket blocking splice path. A connection that never reaches Vision
Direct still pays the cost for the lifetime of the relay.

- **Severity:** low, resource/churn only. No correctness bug, no fd leak, and
  fds return to baseline when the relay ends.
- **Current cost:** four `F_DUPFD_CLOEXEC` duplicates per active Vision
  connection (two copies of the client socket, two of the target socket).
- **Observed total:** about 7 fds per active Vision TCP flow; four of those
  are the eager duplicates.
- **At `max_connections = 1024`:** about 7k fds if all connections are active
  Vision flows; `LimitNOFILE=65536` keeps this safe (roughly 11%), but the
  allocation/churn cost is real.
- **Fix:** clone lazily, per direction, only after that direction's raw handoff
  is confirmed and a splice permit is held. Expected cost becomes 0 copies
  before handoff, 2 for one raw direction, and 4 only when both directions are
  raw.

## Code path

All paths are in `crates/beam-core/src/tls/server.rs` except the helpers noted.

1. `relay_vision` creates the tuple before splitting the streams:

   ```rust
   let clones = (|| -> Result<_, TlsServerError> {
       Ok((
           vision.try_clone_raw_socket()?,
           vision.try_clone_raw_socket()?,
           try_clone_tcp(&target)?,
           try_clone_tcp(&target)?,
       ))
   })();
   ```

   The clones are created for every `relay_vision` call, not only for a
   connection that reaches raw Vision Direct.

2. The clone helpers duplicate the underlying fd:

   - `VisionStream::try_clone_raw_socket` (`crates/beam-core/src/vision/stream.rs`)
     delegates to `TlsStream::try_clone_socket`.
   - `TlsStream::try_clone_socket` (`crates/beam-core/src/tls/stream.rs`) calls
     `beam_sys::try_clone_fd(self.socket.as_raw_fd())`.
   - `try_clone_tcp` (`crates/beam-core/src/tls/server.rs`) does the same for
     the target `TcpStream`.
   - `beam_sys::try_clone_fd` (`crates/beam-sys/src/lib.rs`) uses
     `fcntl(fd, F_DUPFD_CLOEXEC, 0)`.

3. The four clones are captured by the `up` and `down` futures:

   - upload: `client_read` + `target_write_splice`
   - download: `client_write` + `target_read_splice`

   If a direction never becomes raw, its two clones are dropped when that
   direction future finishes. If a direction becomes raw, its two clones move
   into `spawn_blocking` for `copy_one_way` and remain open until the splice
   finishes. If a splice permit is unavailable, the code explicitly drops that
   direction's two clones before falling back to the async copy path.

4. `tokio::try_join!(up, down)` waits for both directions; after it returns, all
   remaining clones are dropped. The original client and target sockets are
   owned by the split async halves for the same lifetime.

## Why the clones exist

The raw handoff moves a direction to a blocking `splice(2)` task. That task
must be `'static` and needs its own fd ownership while the opposite async
direction still owns the original socket. Duplicating the client and target
fds is the clean way to give each blocking splice an fd without closing the
socket used by the other direction. The cost is avoidable **until handoff**,
which is what this fix changes.

## Measured behaviour

A loopback probe (`socks5 -> sing-box 1.14.4 -> beam -> echo`) held Vision TCP
connections open and sampled `/proc/<beam-pid>/fd`:

| State | fds | Delta |
|---|---:|---:|
| idle server | 10 | — |
| one active Vision flow | 17 | +7 |
| after that flow closes | 10 | 0 |
| 16 concurrent Vision flows | 122 | +112, or 7 per flow |
| after all close | 10 | 0 |

The 4-byte payload does not need a bulk Vision Direct splice, yet each flow
still paid the four eager duplicates. The four duplicates are the fixable part
of the 7 per-flow fds; the remainder is the accepted client socket, the target
socket, and relay overhead.

Production observations under live traffic were 208–215 fds with 53 threads
(not at the 1024-connection ceiling); no monotonic growth was observed.

## Recommended fix

Clone lazily inside each direction, after handoff and after the splice permit
is acquired. Do not create any duplicate before that point.

1. Capture the original raw fds before `tokio::io::split`:

   ```rust
   let client_fd = vision.raw_fd(); // new accessor delegating to TlsStream
   let target_fd = target.as_raw_fd();
   ```

   Add a small `raw_fd()` accessor to `VisionStream`/`TlsStream` (or extend
   `RawTlsHandoff` with one) rather than exposing the private socket field.

2. In the upload direction, after `raw_read` is true and the splice permit is
   held:

   ```rust
   let client = beam_sys::try_clone_fd(client_fd)?; // OwnedFd
   let target = beam_sys::try_clone_fd(target_fd)?; // OwnedFd
   let result = tokio::task::spawn_blocking(move || {
       let _keep = (&client, &target);
       copy_one_way(
           client.as_raw_fd(),
           target.as_raw_fd(),
           &config,
           Some(&relay_activity),
       )
   })
   .await;
   ```

   The `OwnedFd` values stay alive for the blocking call; a bare `RawFd` would
   not keep the duplicate open.

3. Do the symmetric change in the download direction (`target_fd` source,
   `client_fd` sink).

4. If `try_clone_fd` fails after the permit is acquired, release the permit,
   record the existing `splice_fallback` metric, log the error, and use the
   async `copy_direction` path. Do not return an error solely because the
   optimisation could not allocate two fds; the copy path is correct.

5. Delete the eager clone tuple, the `try_clone_tcp` helper if it becomes
   unused, and the explicit `drop(...)` fallback lines that only exist to
   release eager clones.

6. Keep the independent one-way splice design and the shared `RelayActivity`
   deadline unchanged. Do not switch to a single bidirectional blocking relay;
   that would change half-close behaviour.

Expected per-connection cost after the fix:

| State | Extra duplicates |
|---|---:|
| no raw handoff | 0 |
| one direction raw | 2 |
| both directions raw | 4 |
| after relay ends | 0 |

At 1024 active Vision connections the worst case remains 4 duplicates per
connection only while both directions are raw; the common short-flow case
drops to zero.

## Verification

1. **FD assertion:** extend `tests/stress/vless_client.py --selftest` or add a
   small probe that holds N Vision TCP flows. Baseline, one flow, 16 flows,
   and after-close counts must show no eager clones before handoff and a return
   to baseline. Suggested threshold: one non-handoff flow adds no more than the
   two base connection fds plus relay overhead; 16 concurrent flows must stay
   well below the current +112.
2. **Behaviour:** `tests/stress/vless_variants.py`, `vless_interop.py`,
   `vless_halfclose.py`, and `tests/stress/loopback.py` must pass byte-exact,
   including Vision Direct, plain flow, xudp/packetaddr/legacy, and
   target-initiated half-close.
3. **Fallback:** force `try_clone_fd` failure (test hook or tiny `RLIMIT_NOFILE`)
   and verify the async copy path still serves the flow and increments
   `splice_fallback`.
4. **Soak:** 900 s `soak.yml` with fds stable; `pressure.yml` for session
   saturation and datagram blast.
5. **Release:** `cargo fmt --all --check`, clippy with `-D warnings`,
   `cargo test --workspace`; no new fd warnings.

## Acceptance criteria

- No `try_clone_fd`/`try_clone_raw_socket`/`try_clone_tcp` call occurs before
  a direction's raw handoff.
- One active non-handoff Vision flow does not add four duplicates.
- One raw direction uses at most two duplicates; both raw at most four; all are
  released when the relay ends.
- 1024 concurrent Vision flows remain below `LimitNOFILE=65536` with margin.
- Vision Direct bytes, half-close, splice fallback, and shutdown drain are
  unchanged.
- `STRESS-FINDINGS.md` #10 is marked fixed with the new regression test named;
  then delete this file.

## After the fix

1. Remove the temporary pointer in `STRESS-FINDINGS.md` #10.
2. Mark #10 fixed with the test name and measured before/after fd counts.
3. Delete `fix.md`.
4. If the fd-cost fix changes the documented concurrency model or resolver
   limits, update `README.md` and `STATE-MACHINES.md` in the same commit.
