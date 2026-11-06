#!/usr/bin/env bash
# Source this file before running cargo on this development host.
# It only prepares the local Rust toolchain and portable build environment;
# external benchmark/lab tools are selected by the scripts that need them.

export PATH="$HOME/.cargo/bin:$PATH"
if [ -z "${CC:-}" ] && command -v gcc >/dev/null 2>&1; then
    export CC="$(command -v gcc)"
fi
if [ -z "${CXX:-}" ] && command -v c++ >/dev/null 2>&1; then
    export CXX="$(command -v c++)"
fi
export CMAKE_GENERATOR="${CMAKE_GENERATOR:-Ninja}"
