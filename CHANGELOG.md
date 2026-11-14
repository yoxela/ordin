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

- ORD-002: the layer and license rules, enforced in CI by `cargo xtask check-layers` (a new `xtask` tool crate) and by clippy.
  - Every crate must declare a valid layer, carry the license its layer requires, and depend only on its own layer or lower (dev dependencies included). Nothing may depend on a tool crate.
  - A permissive crate may not ship a GPL crate, a layer-0 crate may not ship an I/O crate (`tokio`, `reqwest`, `hyper`, `mio`, `rusqlite`, `async-std`), and `ordind` may not link archive, decompression, ELF or solver code. Violations name the dependency path.
  - Each layer-0 crate has a `clippy.toml` banning `std::fs`, `std::net` and `std::process` types and functions; clippy's `disallowed_types` and `disallowed_methods` are denied workspace-wide.
  - Every `.rs` file must start with the SPDX header for its crate's license, crates must inherit the workspace lints (`ordin-store` and `ordin-sandbox` must repeat them with `unsafe_code = "deny"`), and only layer-0 crates may have their own `clippy.toml`, kept in step with the workspace's.
- ORD-003: test harnesses.
  - `proptest` and `insta` are workspace dependencies, opted into with `proptest.workspace = true` or `insta.workspace = true`. `xtask` uses both: property tests for layer parsing, and a reviewed snapshot of the violation report.
  - `fuzz/` is a separate cargo-fuzz workspace with its own pinned nightly (`fuzz/rust-toolchain.toml`). It has no targets yet; the first arrives with ORD-011.
  - Coverage: a new workflow runs `cargo llvm-cov` on every pull request and fails below 85% line coverage unless the description has a `coverage-exception: <reason>` line, which the job repeats in its summary. On `main` it only reports.
  - Mutation testing: a new workflow runs `cargo mutants` on each pull request's changed code and fails if a mutant survives.
  - A nightly workflow fuzzes every target (a crash opens or updates a `fuzz-crash` issue that names the target; the reproducer stays in the run's artifact), runs `cargo mutants` over the whole workspace (reported only), and reports branch coverage on the pinned nightly.
  - `cargo xtask check-layers` also checks `fuzz/`: it must be GPL-3.0-or-later, with matching SPDX headers. It takes an optional `--manifest-path`.
  - New tests close three gaps that mutation testing found in `xtask`: the "violations found" path of the binary, and the dev and build dependency kinds.

### Fixed

- CI installs `cargo-deny` with the pinned toolchain named explicitly, which removes cargo's toolchain-override warning, and the cached binary's key now includes the toolchain.
