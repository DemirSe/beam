# Todo

This file holds open work only. Closed decisions and accepted risks are not
repeated here.

## Open

None.

The real hang check is closed: `hang_recovery` in
`scripts/windows-live-checks.ps1` points a running client at an unreachable
server, drives traffic through the tunnel, and requires a failure signal (state
change, reason token, or a rising `dial_failures`), a live process, no CPU
spin, and a real link that reconnects. Evidence: `windows-live-e2e` run
46063427533.
