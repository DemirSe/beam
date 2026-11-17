# Security policy

## Report a vulnerability

Use GitHub private vulnerability reporting on this repository (Security tab,
"Report a vulnerability"). If that is not enabled, contact the maintainer
through the repository's published contact before any public disclosure.

Do not open a public issue for a security report. Do not attach real keys,
client UUIDs, or captured traffic.

There is no bug bounty program.

## In scope

- ClientHello and REALITY authentication in `crates/beam-core/src/reality`.
- VLESS, Vision, and XUDP frame parsing in `crates/beam-core/src/vless`,
  `crates/beam-core/src/vision`, and `crates/beam-core/src/xudp`.
- Release artifact and installer integrity. `scripts/release-artifact.sh`
  writes `SHA256SUMS` and an archive pin. `deploy/beam-install.sh` checks
  those hashes before it installs files.

## Out of scope

- A misconfigured single-user deployment. beam has one user ID and one inbound.
  It has no account system or per-user isolation. See "Security notes" in
  `README.md`.
