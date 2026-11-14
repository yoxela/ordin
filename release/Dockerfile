# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 The Ordin Authors
#
# The pinned environment Ordin's release binaries are built in (ORD-004).
# CI and the maintainer's release machine both build from this file, so a
# release can be rebuilt and compared byte for byte. Everything is pinned:
# the base image by digest, Ubuntu's packages by archive snapshot, rustup by
# version and checksum, and Rust by rust-toolchain.toml, which
# scripts/release/build.sh copies in beside this file.
#
# This is only for building Ordin's own releases. Packages built by Ordin
# never use containers.

# ubuntu:24.04, x86_64.
FROM ubuntu@sha256:2198e4c65076e9cb0b3d695219df667c0e3b0072da64ca3c2648aca17dcecaf5

# Every package comes from the archive as it was at this moment.
ARG APT_SNAPSHOT=20261112T000000Z
ARG RUSTUP_VERSION=1.29.3
ARG RUSTUP_INIT_SHA256=b1c8cb14e30889e7e2999e6b69e62d9e9b9ffc0f4df8180564d306d9680e6c55

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/opt/rustup \
    PATH=/opt/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# snapshot.ubuntu.com is HTTPS-only, so the CA certificates come first, from
# the regular archive (apt verifies packages by the archive's signature
# either way). They only affect downloads, never the binaries.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && echo "APT::Snapshot \"${APT_SNAPSHOT}\";" > /etc/apt/apt.conf.d/50snapshot \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl gcc libc6-dev musl-tools \
      gcc-aarch64-linux-gnu libc6-dev-arm64-cross \
 && rm -rf /var/lib/apt/lists/*

# The toolchain and components rust-toolchain.toml names, plus the release
# targets, which only the release build needs.
COPY rust-toolchain.toml /opt/toolchain/rust-toolchain.toml
RUN curl -fsSL --proto '=https' --tlsv1.2 -o /tmp/rustup-init \
      "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/x86_64-unknown-linux-gnu/rustup-init" \
 && echo "${RUSTUP_INIT_SHA256}  /tmp/rustup-init" | sha256sum -c - \
 && chmod +x /tmp/rustup-init \
 && export CARGO_HOME=/opt/cargo \
 && /tmp/rustup-init -y --no-modify-path --profile minimal --default-toolchain none \
 && rm /tmp/rustup-init \
 && cd /opt/toolchain \
 && rustup toolchain install \
 && toolchain="$(rustup show active-toolchain | cut -d ' ' -f 1)" \
 && rustup default "${toolchain}" \
 && rustup target add --toolchain "${toolchain}" \
      x86_64-unknown-linux-musl aarch64-unknown-linux-gnu aarch64-unknown-linux-musl \
 && chmod -R a+rX /opt/rustup /opt/cargo
