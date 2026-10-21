# ADR 0004: Relative performance acceptance

## Status

Accepted.

## Context

The goal is for `beam` to be better than stock Xray in every tested condition.
A fixed multiplier such as "1.15x single-flow" is useful as a target but can
block delivery on a noisy 1 vCPU VPS or on a condition where the measurement
itself is unstable. The user explicitly asked for "better" rather than a fixed
guarantee.

## Decision

Hard requirements:

- `beam` is better than stock Xray in the aggregate benchmark.
- No tested condition regresses beyond measurement noise.
- 24-hour soak and 10,000-connection churn pass with stable memory, file
  descriptors, threads, and pipes.
- No crash, panic, data corruption, or cross-session leakage.

Numeric targets are goals, not release blockers:

- single-flow throughput >= 1.15x stock
- multi-flow throughput >= 1.10x stock
- p99 latency <= stock
- RSS <= 50% of stock
- CPU per GiB < stock

A missed target is recorded with the measured result and the likely cause. It
does not block the release if the aggregate result is better and no condition
regressed.

## Consequences

- Benchmarks must report raw samples and per-condition results, not only an
  average.
- A regression in any single condition is a release blocker even if the
  aggregate is better.
- Optimization work is driven by measured gaps, not by a single headline
  number.
