# ADR 0003: TLS stack and cover fidelity

## Status

Proposed. The spike and cover probe are complete. The final choice depends on
whether "1:1" means client compatibility plus observably cover-like handshakes,
or byte-for-byte internal mirroring of the stock REALITY server.

## Context

REALITY needs raw ClientHello access, session-id inspection, dynamic
certificate selection, cover forwarding, and a cover-like TLS 1.3 handshake.
Stock Xray reuses the cover's ServerHello bytes (only the key share is
replaced), reuses the target flight lengths for padding, and serves a temporary
Ed25519 certificate whose signature carries an HMAC.

Measured facts:

- The production cover `whatsapp.net:443` is PQ-capable. It negotiates
  `X25519MLKEM768`, `TLS_AES_128_GCM_SHA256`, ALPN `h2`, with a two-certificate
  EC chain.
- `rustls + ring` falls back to X25519. Its ServerHello is 127 bytes versus the
  cover's 1215 bytes. This is a cheap distinguisher and is not acceptable for
  this cover.
- `rustls + aws-lc-rs` with `prefer-post-quantum` negotiates the cover's group,
  cipher, ALPN, extension order, ServerHello size, and server-flight sizes.
- BoringSSL matches the same public parameters but is slower, has a C++
  toolchain, and adds a `libstdc++` runtime dependency.
- Neither library exposes record padding or arbitrary flight mirroring. Stock's
  exact ServerHello reuse and padding require a custom TLS 1.3 layer or a fork.

The observable difference matters mainly to an unauthenticated prober. Such a
prober is forwarded to the cover and sees the real cover. The remaining
difference is visible only to an authenticated client or to an observer that
can compare per-connection random fields, which are not predictable.

## Decision

Pending. Two viable paths:

1. **rustls + aws-lc-rs (prefer-post-quantum)**: client-compatible, observably
   cover-like for this cover, much smaller risk and faster to deliver. Verify
   with a cover-parity harness before release.
2. **Custom TLS 1.3 mirroring**: reproduce stock's exact cover ServerHello
   reuse and record padding. Highest fidelity, highest cost and security risk.

BoringSSL remains a fingerprint oracle, not the production stack.

## Consequences

- Path 1 can start immediately and keeps the TLS adapter replaceable.
- Path 2 needs a dedicated TLS implementation: record layer, TLS 1.3 key
  schedule, transcript, certificate HMAC, Ed25519, hybrid ML-KEM/X25519, and
  record padding.
- The provider must be initialized at process start to avoid the aws-lc
  first-handshake initialization cost.
- The cover probe must be repeated from the deployment region before freezing
  the provider.
