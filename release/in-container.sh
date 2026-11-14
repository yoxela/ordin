#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 The Ordin Authors
#
# Runs inside the release container (release/Dockerfile), started by
# scripts/release/build.sh. The source is mounted read-only at /src/ordin.
#
#   in-container.sh fetch         download every dependency in Cargo.lock;
#                                 the only step with network access
#   in-container.sh build <tag>   build and pack the release, offline, into
#                                 /out/dist
set -euo pipefail

cd /src/ordin
export CARGO_HOME=/cargo

case "${1:-}" in
  fetch)
    [ "$#" -eq 1 ] || { echo "usage: in-container.sh fetch" >&2; exit 2; }
    exec cargo fetch --locked
    ;;
  build)
    [ "$#" -eq 2 ] || { echo "usage: in-container.sh build <tag>" >&2; exit 2; }
    : "${SOURCE_DATE_EPOCH:?SOURCE_DATE_EPOCH must be set}"
    export SOURCE_DATE_EPOCH
    export CARGO_NET_OFFLINE=true
    export CARGO_TARGET_DIR=/out/target
    # The container's cross compiler links both aarch64 targets; the musl
    # targets link Rust's own self-contained musl.
    export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
    export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-gnu-gcc
    # No build path ends up in a binary.
    export RUSTFLAGS="--remap-path-prefix=/src/ordin=/ordin"
    exec cargo xtask dist --tag "$2" --out /out/dist
    ;;
  *)
    echo "usage: in-container.sh fetch | build <tag>" >&2
    exit 2
    ;;
esac
