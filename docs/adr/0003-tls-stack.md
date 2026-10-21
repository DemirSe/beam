# ADR 0003: TLS stack and cover fidelity

## Status

Accepted.

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
- BoringSSL matches the same public parameters but is slower, has a C++/libclang
  toolchain, and adds a `libstdc++` runtime dependency.
- Neither library exposes arbitrary record padding. Stock's exact ServerHello
  reuse and padding would require a custom TLS 1.3 layer or a fork.

An unauthenticated prober is forwarded to the real cover. The remaining
difference is visible only to an authenticated client, or to an observer that
can compare per-connection random fields that are not predictable.

## Decision

Use **rustls 0.23 + aws-lc-rs with `prefer-post-quantum`** for the production
REALITY server. Do not build a custom TLS stack for v1. Keep BoringSSL only as a
fingerprint oracle.

The authenticated handshake does not need to dial the cover: the client checks
the REALITY certificate HMAC, not the cover's ServerHello. This removes the
cover round trip from the authenticated path and is a deliberate performance
advantage over stock.

Unauthenticated connections are still forwarded to the cover byte-for-byte.

## Consequences

- Client compatibility and full TUN work with the unchanged client profile.
- The ServerHello group, cipher, ALPN, extension order, and size match the
  cover for this PQ-capable cover.
- The temporary Ed25519 certificate is smaller than the cover's EC chain, so
  encrypted flight sizes may differ. The cover-parity harness must measure this;
  certificate-size padding is the first remedy if the gap matters.
- The aws-lc provider must be initialized at process start to avoid the
  first-handshake initialization cost.
- Re-run the cover probe from the deployment region before freezing the
  provider.
- Revisit a custom TLS layer or a rustls fork only if the cover-parity harness
  shows a reliable distinguisher that matters to the threat model.
