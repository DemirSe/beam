# Windows tray client

`clients/windows-tray/` builds a small Windows tray launcher for sing-box. It
does not build the server. It is Windows-only.

## Build

A MinGW-w64 toolchain is required. `build.sh` uses
`x86_64-w64-mingw32-gcc` and `x86_64-w64-mingw32-windres` by default. Set `CC`
and `WINDRES` to use other tools. The script lists an LLVM-MinGW example.

From this directory, run `./build.sh`. The output is `beam-tray.exe` here.
The executable carries a requireAdministrator manifest. The TUN inbound needs
elevation.

## Files beside the executable

`main.c` starts `sing-box.exe run -c config.json`. It expects `sing-box.exe`
and `config.json` next to `beam-tray.exe`. TUN, DNS, and routing stay in
`config.json`. The tray only starts, stops, and restarts the process, and
opens the config and the log.

`build.sh` produces the executable only. There is no Windows installer script
in this directory.
