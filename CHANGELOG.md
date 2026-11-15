# Changelog

All notable changes to Ordin are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] (0.1.1)

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
- ORD-004: release builds.
  - `release/Dockerfile` is the pinned build environment: Ubuntu 24.04 by digest, packages from a dated archive snapshot, rustup by version and checksum, and the Rust toolchain from `rust-toolchain.toml`. `scripts/release/build.sh` builds a tagged checkout in it: dependencies are fetched first, then everything is built with no network, as the calling user, with all capabilities dropped and the source read-only. Two builds from different paths and at different times give identical files.
  - Four targets: x86\_64 and aarch64, glibc (2.34 or newer) and statically linked musl. Build paths are remapped, `SOURCE_DATE_EPOCH` comes from the tagged commit, and the release profile uses one codegen unit and strips debug information.
  - `cargo xtask dist` builds the six programs and packs one deterministic `.tar.gz` per target (sorted, owned by root, fixed modes and timestamps), with the license texts and README, plus a `SHA256SUMS` file. It refuses to build while a shipped program links third-party crates, because the archives don't carry their license notices yet.
  - `cargo xtask pre-release` (`make pre-release`) checks that `main` is clean and matches origin, that the version has a dated changelog heading and no tag yet, and that every check on the commit passed, then prints the tag commands.
  - A signed `v*` tag runs the new release workflow, which verifies the tag, builds in the container, records build provenance and creates a draft release. It is the only workflow allowed to write.
  - `cargo xtask release-sign` (`make release-sign TAG=…`) verifies the tag against the maintainer's own signers file, checks the draft's files, checksums and provenance, rebuilds the tag and requires every file to match, signs each file with the SSH release key, asks, uploads the signatures, checks the draft again and publishes it.
  - `release/allowed_signers` holds the public keys: one for tags (namespace `git`) and one for release files (namespace `ordin-release`). The README says how to verify a release.
  - CI runs `shellcheck` on the release scripts.
- ORD-011: versions and their ordering, in `ordin-version`.
  - `Version` parses `[epoch:]upstream[-release[+uN]]` and shows it as written, hiding an epoch or update level of 0. Bad versions are refused with the reason, and a version is at most 256 bytes.
  - One ordering for every package: Debian's algorithm, with `~` before everything and rpm's `^` after the end but before anything that continues the version. Versions compare by epoch, upstream, release, then update level, and equality follows the ordering (`1.0`, `1.00` and `1.0-0` are equal, as in dpkg). `compare_text` exposes the ordering for any version text.
  - `normalize_semver` turns semver pre-releases into `~` (`2.0.0-rc.1` becomes `2.0.0~rc.1`) and drops build metadata. `snapshot` builds versions for commits from a date, a commit count and the hash (`1.4.2^20261112.37.g3fa9c1e`).
  - The `~` compatible-with operator works like semver's caret: `~1.27` is at least 1.27 and below `2~`, and `~0.4` is below `0.5~`.
  - Ordin orders all 23,260 distinct versions in Debian trixie exactly as `dpkg --compare-versions` does. `cargo xtask version-corpus` builds the corpus from the census and requires dpkg to agree on every pair. CI checks the committed corpus against dpkg again.
  - Property tests for the ordering laws, for round trips, and against a port of dpkg's comparison. The first fuzz target, `version_parse`, makes `fuzz/` build. It found one bug before release: a release ending in `+u01` was accepted, then didn't read back.

### Changed

- The README describes Ordin's lifecycle model directly, without comparing it to other systems.
- `cargo xtask release-sign` checks that CI's draft exists, for the tag and with the expected files, before it clones or creates anything. Started while the release workflow is still running, it now stops at once, says so and leaves no work directory behind.
- The first release will be 0.1.1. The `v0.1.0` tag was used once to test the release flow end to end and then deleted, so it is never reused.

### Fixed

- CI installs `cargo-deny` with the pinned toolchain named explicitly, which removes cargo's toolchain-override warning, and the cached binary's key now includes the toolchain.
