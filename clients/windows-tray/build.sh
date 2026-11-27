#!/usr/bin/env bash
# Cross-compile the unelevated beam Windows tray client.
#
# A MinGW-w64 compiler is required. With LLVM-MinGW:
#   CC=x86_64-w64-mingw32-clang \
#   WINDRES=x86_64-w64-mingw32-windres ./build.sh
#
# The tray needs no administrator rights: it only talks to the BeamClient
# service over the \\.\pipe\beam-client-ipc named pipe.
#
# MSVC equivalent, from a "x64 Native Tools Command Prompt":
#   rc /nologo /fo app.res app.rc
#   cl /nologo /std:c11 /W4 /WX /O2 /DUNICODE /D_UNICODE main.c app.res \
#      /Fe:beam-tray.exe /link /SUBSYSTEM:WINDOWS \
#      user32.lib shell32.lib gdi32.lib
set -euo pipefail

cd "$(dirname "$0")"

CC="${CC:-x86_64-w64-mingw32-gcc}"
WINDRES="${WINDRES:-x86_64-w64-mingw32-windres}"

if ! command -v "$CC" >/dev/null 2>&1; then
    echo "error: $CC not found; install MinGW-w64 or set CC" >&2
    exit 1
fi
if ! command -v "$WINDRES" >/dev/null 2>&1; then
    echo "error: $WINDRES not found; install MinGW-w64 or set WINDRES" >&2
    exit 1
fi

rm -f beam-tray.exe app-res.o

"$WINDRES" -O coff -i app.rc -o app-res.o
"$CC" -std=c11 -Os -s -fno-ident -ffunction-sections -fdata-sections \
    -Wall -Wextra -Werror -mwindows \
    -Wl,--gc-sections,--nxcompat,--dynamicbase -static -static-libgcc \
    -o beam-tray.exe main.c app-res.o \
    -lshell32 -luser32 -lgdi32

rm -f app-res.o
echo "built: $(pwd)/beam-tray.exe"
