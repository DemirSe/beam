# Todo

This file holds open work only. Closed decisions and accepted risks are not
repeated here.

## Open

1. **Windows device check.** The Windows client profile passes `sing-box
   check`. No Windows device has run it.
2. **Real hang test.** The liveness path is proven with forced failures, not
   with a frozen process. The check needs about 15 minutes without the tunnel
   and must show the timer restarting a process that stays `active` but cannot
   finish a handshake.
