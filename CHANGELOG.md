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
- ORD-114: facet classification, in `ordin-pack`.
  - `classify` splits a normalized tree into facets by path rules: `debug` under `/usr/lib/debug`; `doc` under `/usr/share/doc`, `man` and `info`; `locale:<ll>` under `/usr/share/locale/<ll>/`; `dev` under `/usr/include`, for `*.a` and for pkg-config files; `runtime` for everything else.
  - Overrides from the recipe move a path and everything below it, the most specific one winning. An override that matches nothing, or two for one path, is an error.
  - Each facet's tree carries the directories above its entries and its content size. `runtime` is always present. A hard link whose file is in another facet becomes a copy with the same content, so each facet stands alone.
  - Every path's facet and the reason for it are listed, for `ordin show --facets` (ORD-132).
  - `ordin-core` gains `Facet::runtime`, `Facet::doc`, `Facet::dev` and `Facet::debug`.
- ORD-111: layout normalization, in `ordin-pack`.
  - `normalize` maps a walked install root into Ordin's layout, so everything the package ships is under `/usr`. `bin/`, `sbin/`, `lib/` and `lib64/` move under `usr/`.
  - `etc/` becomes config defaults under `/usr/share/ordin/defaults/<name>/`: files are merged three ways, and empty directories are drop-in directories.
  - Directories under `var/lib`, `var/cache`, `var/log`, `var/spool` and `var/tmp` become state paths of that class with their owner, group and mode. Empty files become state files, and other files become seeds under `/usr/share/ordin/seeds/<name>/`.
  - A prefix the software was installed with (`--prefix /opt/foo`) moves its contents to `/usr`. Anything else outside the layout is refused with a hint, and so are runtime directories, unknown `var/` directories, links under `etc/` and `var/`, Ordin's own `/usr/share/ordin`, paths the manifest can't declare, and paths that collide.
  - `ordin-pack` now depends on `ordin-manifest`, whose declaration types the result uses.
- ORD-103: chunking and the chunk index, in `ordin-tree`.
  - `chunk::chunk_file` cuts a file into content-defined chunks with Ordin's own FastCDC 2020, in the same single read that computes its digests, and hands each chunk's bytes to the caller. Files under the whole-file threshold are one chunk, and a file cut into more chunks than an index can list is refused.
  - The default settings are ORD-100's: chunks of 256 KiB to 4 MiB, 1 MiB on average, normalization level 1, files under 1 MiB whole. The gear table and masks are fixed in the format, and the cut points match the `fastcdc` crate's (3.2.1), which is a test-only dependency.
  - Chunk index format 1 (`CHUNK-INDEX.md`): canonical JSON with a BLAKE3 identity. It records the chunker's settings and lists each file at or above the threshold by content digest, with its chunks' BLAKE3 digests and uncompressed lengths. Compression never enters it. Reading is strict, every rule is checked, and errors name the file, chunk and field.
  - `ChunkIndex::chunks_of` gives the chunks to fetch for a file a tree records. Cutting a file again with the recorded settings reproduces the index exactly.
  - A new fuzz target, `chunk_index_parse`.
- ORD-110: walking a tree, in `ordin-pack`.
  - `walk` records a directory as a tree: every path's type, mode, `user.*` attributes, file capabilities, size and digests. Timestamps are not recorded, and hard links become links to the first of their names in sort order.
  - Owners never come from the disk. Everything is `root:root` unless a `PATH=USER:GROUP` override says otherwise. An override covers the path and everything below it, the most specific one wins, and one that matches nothing is an error.
  - An undeclared setuid or setgid file draws a warning, which says when the file would run as root only because of the default owner.
  - The directory isn't trusted. Symlinks are never followed below the root, a FIFO can't hang the walk, a walk stays on one mount, and anything that changes during the walk is an error. Device nodes, sockets, FIFOs, names a tree can't hold and unreadable files are refused, naming the path, with control characters escaped.
  - Attributes a tree can't hold are refused rather than dropped, including POSIX ACLs. SELinux, IMA and EVM labels belong to the packing machine and are left behind.
  - `ordin-tree` gains `Capabilities::from_xattr`, which reads the kernel's `security.capability` value, with a fuzz target.
  - `rustix` is a new dependency, for system calls `std` doesn't offer.
- ORD-102: file digests, in `ordin-tree`.
  - `file_digests` reads any `Read` once and returns the file's size, its BLAKE3 digest and its fs-verity digest. `FileHasher` does the same for bytes given piece by piece, so later stories can digest a file while doing other work on it.
  - The fs-verity digest is Ordin's own implementation (SHA-256, 4 KiB blocks, no salt), through the `sha2` crate. Its memory use doesn't grow with the file beyond one block per tree level.
  - Tested against `fsverity digest` at every boundary of the tree's shape, and against composefs-rs's vector.
  - `ordin-core` gains `Blake3Hasher`, which computes a BLAKE3 digest piece by piece.
- ORD-101: trees, format 1, in `ordin-tree`, with `FORMAT.md` as its field-by-field reference.
  - A tree is one facet's file list as canonical JSON (RFC 8785), entries sorted by the bytes of their paths. Its identity is the BLAKE3 digest of its canonical bytes. `Tree::from_canonical_bytes` reads only canonical bytes, `Tree::new` builds a tree from entries in any order, and `to_canonical_bytes` and `digest` check every rule again.
  - Entries are files, directories, symlinks and hard links. A file records its mode, owner and group names, size, BLAKE3 digest and fs-verity digest (SHA-256, 4 KiB blocks, no salt, as ORD-100 settled). Defaults are left out, and no timestamp is recorded.
  - Paths are absolute, normalized UTF-8 without control characters, so real names with spaces, `~` and non-ASCII characters are kept. Every parent is a directory entry in the same tree, so no path passes through a symlink, and every hard link points at a file in the tree.
  - Only `user.*` extended attributes can be packaged, in canonical base64: `trusted.*` could point an overlay at another file, and SELinux labels come from policy. File capabilities are recorded by name (`cap_net_raw`), as permitted and inheritable sets and an effective flag.
  - Limits: 64 MiB and 262,144 entries per tree, 16 extended attributes of up to 4 KiB per entry. Every error names the entry and field.
  - Tests for every rule at the field it applies to, property tests (any order gives the same bytes; removed fields are refused or round-trip; damaged bytes never panic) and a new fuzz target, `tree_parse`.
  - `ordin-core` now holds the strict canonical JSON reader and the `Account` and `Mode` types, shared by manifests and trees; `ordin-manifest` re-exports them. `Mode::FILE` and `Mode::DIR` name the usual modes, and account errors are typed.
- ORD-013: the package manifest, format 1, in `ordin-manifest`, with `SCHEMA.md` as its field-by-field reference.
  - One Rust type for every field the spec names: kinds (base, update, system-base), license texts and presentation, facets, versioned provides, the requirement sets (`requires`, `conflicts`, `recommends`, `supplements`, `requires-at`, `obsoletes`, `replaces`), cumulative updates with their removals, declarations (users, groups, units, config, alternatives with followers, triggers, setuid files, boot), state with classes, files, seeds and migrations, settings, hooks, installed tests, SELinux and AppArmor policy, delegated payloads, switching, support dates, ABI digests, fixes and notices.
  - One encoding per package: signed bytes must be canonical JSON (RFC 8785) already, duplicate keys and non-integer numbers are refused, defaults must be left out, sets must be sorted, and every grammar (names, atoms, versions, dependency expressions, SPDX expressions, digests, paths, accounts, unit names) must be in canonical form. A package's identity is the BLAKE3 digest of its canonical bytes.
  - Format 1 grows without breaking: an unknown field is refused unless the manifest's signed `ignorable` list names it, and an unknown value is always refused. Every error names the field it is about.
  - `ordin-core` gains `Digest` (`blake3:` or `sha256:` and 64 hex digits), wrapping the `blake3` crate. New dependencies: `blake3` (CC0-1.0 OR Apache-2.0) and `regex-syntax` (MIT OR Apache-2.0), which checks setting patterns without running them.
  - Tests for every rule at the field it applies to, RFC 8785's string and key-order examples, property tests (formatting never changes identity; any subset of optional fields is refused or round-trips exactly; damaged bytes never panic) and a new fuzz target, `manifest_parse`. Checks that walk through text (SPDX expressions, `\xNN` escapes in unit names) always move forward without index arithmetic, so no mutation can make them loop forever.
- ORD-010 (follow-up): `so:` atoms may name a symbol version node, `so:libc.so.6@GLIBC_2.38` (`[A-Za-z0-9._]+`, up to 64 bytes). A library provides one atom per node it defines, so matching stays plain atom equality, and a binary built against a newer glibc requires a node nothing provides. `Soname::library` and `Soname::version_node` give the two parts. `#` and `/` are reserved in `so:` atoms for a future qualifier.
- ORD-012: the dependency grammar, in `ordin-depexpr`.
  - Requirements are boolean expressions over atoms: version constraints (`=`, `!=`, `<`, `<=`, `>`, `>=`, and `~` for compatible-with) on package and `cap:` atoms, facet selectors on package atoms (`nginx[doc,runtime]`), `not`, `and`, `or` and `a if b` (required only when `b` holds). Mixing `and` and `or` needs parentheses, and a group has at most one `if`, so an expression reads only one way.
  - Errors give their byte offset. Expressions are limited to 4096 bytes (as written and in canonical form), 32 levels of nesting and 256 atoms, so no input can exhaust the stack.
  - `Expr` shows as canonical text that parses back to the same tree, and `is_satisfied_by` evaluates it against a set of provides. A versioned requirement is met only by a provide with a version, as in Debian.
  - `ordin-core` gains `Facet` (`runtime`, `doc`, `locale:pt_BR`), and file paths in `file:` atoms may no longer contain the operators `= ! < > ~`, so no atom can contain one.
  - Property tests (round trips, the laws of logic for the evaluator) and a new fuzz target, `depexpr_parse`, which found one bug before release: an expression within the length limit whose canonical form wasn't.
- ORD-010: names, atoms and architectures, in `ordin-core`.
  - `PackageName` (`[a-z0-9][a-z0-9+.-]*`, 2 to 128 bytes, never `and`, `or`, `not` or `if`), `Capability` (`cap:` with the same grammar), `Soname` (`so:`), `FilePath` (`file:`, absolute and normalized), the `Atom` enum over the four, and `Arch` (`x86_64`, `aarch64` or `noarch`). Each is built by parsing, shows exactly as parsed, and reads and writes its string form through serde, so nothing invalid gets in.
  - Names are lowercase ASCII, so no two look alike, and atoms can't contain the dependency language's operators or brackets. Every Debian trixie package name fits except `and`.
  - Errors say what is wrong and where. Property tests and a new fuzz target, `atom_parse`, check that any input is refused or round-trips exactly.
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
- The `cargo deny` license allow list drops BSD-2-Clause, BSD-3-Clause and ISC, which no dependency uses. Adding one back is a deliberate decision when a dependency needs it.

### Fixed

- The `version-corpus` command-line tests no longer fail now and then with "Text file busy". Their parallel threads could start a process while another thread was still writing its fake `dpkg`, and the new process briefly kept that file open for writing. A lock now keeps the two apart.
- CI installs `cargo-deny` with the pinned toolchain named explicitly, which removes cargo's toolchain-override warning, and the cached binary's key now includes the toolchain.
