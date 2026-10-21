# ADR 0003: TLS stack selected by spike

## Status

Proposed. Spike complete; provider and cover-parity decision pending the
cover probe and the owner's definition of "1:1".

## Context

REALITY needs raw ClientHello access, session-id inspection, dynamic
certificate selection, byte-for-byte cover forwarding, and some control over
the TLS record flight. The main candidates are:

1. `rustls` with `ring` or `aws-lc-rs`
2. BoringSSL through the `boring` crate
3. A minimal custom TLS 1.3 implementation

`rustls` is the easiest to build and audit but exposes less of the raw record
layer. BoringSSL offers the most control but adds a C/C++ build dependency.
A custom stack offers maximum control but carries the highest security risk.

## Decision

Defer the decision until the spike in `docs/05-roadmap.md` Phase 1 produces
evidence for:

- raw ClientHello and session-id access
- dynamic certificate selection
- pre-handshake cover forwarding
- record-size control or observability
- build complexity
- handshake latency and CPU

## Consequences

`beam-core` must keep the TLS adapter behind a narrow internal interface so the
stack can be replaced without rewriting the VLESS, Vision, or XUDP layers.
