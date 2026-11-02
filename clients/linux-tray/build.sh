#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
CC="${CC:-gcc}"
CFLAGS=(-std=c11 -O2 -s -Wall -Wextra -Werror -fPIE -pie \
  -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fcf-protection)
LDFLAGS=(-Wl,-z,relro,-z,now)
"$CC" "${CFLAGS[@]}" "${LDFLAGS[@]}" -o beam-helper helper.c
"$CC" "${CFLAGS[@]}" "${LDFLAGS[@]}" -o beam-tray tray.c \
    -Wl,-l:libayatana-appindicator3.so.1 \
    -Wl,-l:libgtk-3.so.0 \
    -Wl,-l:libgobject-2.0.so.0 \
    -Wl,-l:libglib-2.0.so.0
echo "built beam-tray and beam-helper"
