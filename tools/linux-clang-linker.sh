#!/bin/sh
# Final Rust links using Chromium's matching Clang/LLD, including CREL support.
# Never executes the target binary.
set -eu
: "${NAIVE_CLANG:?set NAIVE_CLANG to the pinned Chromium clang executable}"
: "${NAIVE_LINUX_SYSROOT:?set NAIVE_LINUX_SYSROOT to the pinned target sysroot}"
: "${NAIVE_LINUX_TARGET:?set NAIVE_LINUX_TARGET to the Rust target triple}"
case "$NAIVE_LINUX_TARGET" in
  x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu) ;;
  *) echo "unsupported Linux target: $NAIVE_LINUX_TARGET" >&2; exit 1 ;;
esac
exec "$NAIVE_CLANG" "--target=$NAIVE_LINUX_TARGET" "--sysroot=$NAIVE_LINUX_SYSROOT" -fuse-ld=lld "$@"
