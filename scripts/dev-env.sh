#!/usr/bin/env bash
# Source this file before running cargo on this development host.
#
# The host has gcc and perl but no system cmake/ninja. Portable copies live
# under /tmp/opencode/tools and are used when present. On a normal build host
# the script falls back to the system toolchain.

if [ -d /tmp/opencode/tools/bin ]; then
  export PATH="/tmp/opencode/tools/bin:$PATH"
fi

export PATH="$HOME/.cargo/bin:$PATH"
export CC="${CC:-/usr/bin/gcc}"
# The host has gcc but no `c++` symlink. libfuzzer-sys builds a small C++
# runtime, so point CXX at the portable wrapper when it is available.
if [ -x /tmp/opencode/tools/bin/g++-portable ] && [ -z "${CXX:-}" ]; then
  export CXX=/tmp/opencode/tools/bin/g++-portable
fi
export CMAKE_GENERATOR="${CMAKE_GENERATOR:-Ninja}"

if [ -d /tmp/opencode/tools/fedora/usr/lib/gcc/x86_64-redhat-linux/16 ]; then
  export LIBRARY_PATH="/tmp/opencode/tools/fedora/usr/lib/gcc/x86_64-redhat-linux/16${LIBRARY_PATH:+:$LIBRARY_PATH}"
fi
