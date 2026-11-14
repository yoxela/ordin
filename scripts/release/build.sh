#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 The Ordin Authors
#
# Builds an Ordin release in the pinned container (ORD-004). The release
# workflow and `cargo xtask release-sign` both run this script, so the
# maintainer's rebuild can be compared with CI's byte for byte.
#
#   scripts/release/build.sh <source> <out> <tag>
#
# <source> is a clean git checkout of <tag>, mounted read-only. <out> must
# not exist yet. The release files end up in <out>/dist.
#
# Dependencies are downloaded in one container run, with network access but
# without building anything. Everything is then built in a second run with
# no network at all, as the calling user, with every capability dropped.
set -euo pipefail

fail() { echo "build.sh: $*" >&2; exit 1; }
[ "$#" -eq 3 ] || { echo "usage: $0 <source> <out> <tag>" >&2; exit 2; }
src="$(cd "$1" && pwd -P)"
out="$2"
tag="$3"

[[ "$tag" =~ ^v[0-9][0-9A-Za-z.-]*$ ]] || fail "$tag isn't a release tag"
[ -z "$(git -C "$src" status --porcelain --untracked-files=all)" ] || fail "$src isn't clean"
head="$(git -C "$src" rev-parse --verify HEAD)"
tagged="$(git -C "$src" rev-parse --verify "refs/tags/$tag^{commit}")" || fail "no tag $tag in $src"
[ "$head" = "$tagged" ] || fail "$src is at $head, not $tag ($tagged)"
[ ! -e "$out" ] || fail "$out already exists"
epoch="$(git -C "$src" log -1 --format=%ct HEAD)"

mkdir -p "$out/cargo-home" "$out/target"
out="$(cd "$out" && pwd -P)"

# The image is built from release/Dockerfile and rust-toolchain.toml only,
# and named after their contents.
context="$(mktemp -d)"
trap 'rm -rf "$context"' EXIT
cp "$src/release/Dockerfile" "$src/rust-toolchain.toml" "$context/"
digest="$(cat "$context/Dockerfile" "$context/rust-toolchain.toml" | sha256sum | cut -c 1-16)"
image="ordin-release:$digest"
docker build --progress=plain --tag "$image" "$context"

run=(docker run --rm
  --user "$(id -u):$(id -g)"
  --cap-drop ALL --security-opt no-new-privileges
  --read-only --tmpfs /tmp
  --volume "$src:/src/ordin:ro"
  --volume "$out/cargo-home:/cargo")
"${run[@]}" "$image" /src/ordin/release/in-container.sh fetch
"${run[@]}" --network none \
  --volume "$out:/out" \
  --env "SOURCE_DATE_EPOCH=$epoch" \
  "$image" /src/ordin/release/in-container.sh build "$tag"

echo "build.sh: $tag built at $head; files in $out/dist"
