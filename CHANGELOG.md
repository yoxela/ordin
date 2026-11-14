# Changelog

All notable changes to Ordin are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] (0.1.0)

### Added

- ORD-001: the Cargo workspace skeleton.
  - 31 crates in four layers (pure core, infrastructure, engines, programs), each recording its layer in `[package.metadata.ordin]`, with its layer's license, an SPDX header and a one-line README. The programs `ordin-build` and `ordin-repo` are packaged as `ordin-build-bin` and `ordin-repo-bin`, because the engines hold those package names.
  - Rust 1.99.1 pinned in `rust-toolchain.toml` and recorded as the MSRV.
  - Workspace lints: `unsafe` forbidden everywhere except `ordin-store` and `ordin-sandbox` (denied there), and `unwrap`, `expect` and `panic` denied outside tests.
  - A `cargo deny` policy: permissive licenses only for dependencies, known vulnerabilities and yanked crates denied, crates.io as the only source.
  - CI on GitHub Actions for x86_64 and native arm64 runners: rustfmt, clippy with warnings as errors, build, test and `cargo deny`. Actions are pinned by commit, and the workflow token is read-only.

### Fixed

- CI installs `cargo-deny` with the pinned toolchain named explicitly, which removes cargo's toolchain-override warning, and the cached binary's key now includes the toolchain.
