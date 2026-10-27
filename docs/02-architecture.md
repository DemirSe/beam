# Architecture

## Shape

```text
client --TCP/443--> listener
                      |
                      v
                REALITY handler
                 /          \
        authenticated      unauthenticated
             |                    |
             v                    v
        VLESS handler        cover forward
             |
        +----+----+
        |         |
      TCP       XUDP
        |         |
      Vision    UDP relay
        |         |
        +----+----+
             |
          freedom
```

## Crates

### `beam`

Process entry point. Owns:

- CLI parsing and config path selection.
- TOML loading and validation.
- Logging initialization.
- Runtime construction and signal handling.
- Listener lifecycle.
- Graceful shutdown and exit codes.

It does not contain protocol logic.

### `beam-core`

All server behavior that can be tested without root or a real network:

- TLS 1.3 record parsing needed by REALITY.
- REALITY authentication and cover forwarding.
- VLESS request/response parsing.
- Vision padding and direct-mode transition.
- XUDP framing and session state.
- Relay orchestration.
- Config types and validation.
- Metrics and error types.

`#![forbid(unsafe_code)]` is mandatory here.

### `beam-sys`

The only crate allowed to use `unsafe`:

- `splice(2)` and pipe setup.
- Socket options (`TCP_NODELAY`, keepalive, buffers, `SO_REUSEADDR`).
- `io_uring` if the benchmark proves it is worth the complexity.
- Low-level address and fd helpers.

Every `unsafe` block carries a `// SAFETY:` comment.

## TLS and REALITY

REALITY needs more control than a normal TLS server:

- Inspect the ClientHello before choosing a certificate.
- Authenticate using the REALITY envelope carried in the ClientHello.
- Forward unauthenticated connections to the cover byte-for-byte.
- Emit the same TLS 1.3 flight shape as the cover.

The preparation spike compares three options:

1. **rustls + aws-lc-rs** - safest build, least control over raw records.
2. **BoringSSL via `boring`** - best control and speed, C/C++ build dependency.
3. **Minimal custom TLS 1.3** - maximum control, highest security risk.

Decision rule: pass the compatibility and probe tests first; then pick the
fastest option that meets the gates. The choice is recorded in an ADR and in
`docs/01-compatibility.md`.

The wire details of the stock REALITY envelope, cover mirroring, target-flight
parsing, certificate HMAC, and record shaping are recorded in
`docs/07-reality-spec.md`. The VLESS request/response, Vision framing, XUDP
frames, legacy UDP, and packetaddr details are in
`docs/08-vision-xudp-spec.md`. Those documents are the reference for the
protocol modules.

The initial ClientHello parser handles one TLS record carrying one complete
ClientHello. It rejects fragmentation across records. Key-share entries expose
both group IDs and zero-copy key-exchange bytes, with a bounded entry count, so
the REALITY handler can derive the shared secret directly. The complete raw
record and handshake message remain available for fallback or auditing. A later
change can add multi-record reassembly.

The TLS server adapter pre-reads one record, authenticates it, and replays it
into rustls through a prefix stream. Authenticated connections use a
per-connection Ed25519 certificate whose outer signature is
`HMAC-SHA512(auth_key, ed25519_public_key)`; unauthenticated connections are
forwarded to the cover without a TLS alert. Stock Xray Chrome fingerprints omit
Ed25519 from `signature_algorithms`, so the adapter deliberately forces the
Ed25519 CertificateVerify scheme to match stock REALITY behavior.

## Data path

### TCP

1. Accept the connection and set socket options.
2. Read and parse the ClientHello.
3. Authenticate or forward to the cover.
4. Complete TLS 1.3 and read the VLESS request.
5. Set up Vision and switch to direct mode.
6. Dial the destination with `freedom`.
7. Relay with `splice(2)` in both directions when the raw-fd gates pass.
8. Fall back to a bounded buffered copy on the exceptional paths.

The relay must remain fair between directions and must not busy-loop. Pipe
size starts at 512 KiB; it is not increased without a new measurement.

### UDP

1. Decode XUDP frames from the VLESS stream.
2. Create or reuse a UDP socket per destination.
3. Enforce destination and concurrency limits.
4. Relay replies with the actual source (no source allowlist; matches stock
   Xray, as documented in `docs/08-vision-xudp-spec.md`).
5. Expire idle sessions and release sockets.
6. Support legacy VLESS UDP for clients that do not use XUDP.

## Configuration

TOML, loaded once at startup. The schema is deliberately small:

- listener address and port
- user UUID and flow
- REALITY private key, short IDs, server names, cover destination
- log level and optional development counters
- resource limits

Unknown fields are errors. Validation happens before the listener is bound.
The file contains secrets and must be readable only by the service user.

## Errors and limits

- Typed errors with `thiserror`; no stringly-typed control flow.
- No `unwrap`/`expect` on network paths.
- Handshake, request, frame, and idle timeouts.
- Maximum ClientHello, request, frame, and queue sizes.
- Maximum concurrent connections and UDP destinations.
- Rate limits for cover forwarding to avoid amplification.

## Observability

Development profile:

- `debug` logging with connection IDs.
- Frame and state-transition counters.
- Optional syscall and buffer statistics.

Deployment profile:

- `warn` logging only.
- Aggregate counters exposed through the process exit report or a future
  minimal stats endpoint.
- No payload, UUID, key, or destination logging.

## Performance principles

- One allocation per buffer, reused per connection.
- No per-packet logging or formatting.
- Batch reads and writes where the kernel allows it.
- Keep the hot path free of dynamic dispatch and locks.
- Measure before optimizing; keep a benchmark for every hot-path change.
