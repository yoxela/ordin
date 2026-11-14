# Ordin

Ordin is a package manager for Linux servers, written in Rust.

Changes are applied, then committed or rejected; packages come as base and update packages; and whole systems are pinned to tested levels. It is built on modern foundations: immutable, content-addressed generations (composefs-style `/usr` images protected by fs-verity), declarative actions instead of maintainer scripts, TUF-signed repositories, and a small privileged daemon with unprivileged helpers.

Ordin is the package manager of Yoxela, a Linux-based operating system for servers only.

## Status

The design is complete and development is starting. Nothing is usable yet.

## License

- Programs and engines: GPL-3.0-or-later
- Format and library crates that other tools may reuse (every pure-core crate, plus `ordin-archive`, `ordin-sign` and `ordin-api`): MIT OR Apache-2.0
- Documentation: CC-BY-4.0

Every source file carries an SPDX license header. The license texts are in [`LICENSES/`](LICENSES/).

Copyright The Ordin Authors (see [`AUTHORS`](AUTHORS)).
