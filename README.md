# Ordin

Ordin is a package manager for Linux servers, written in Rust.

Changes are applied, then committed or rejected; packages come as base and update packages; and whole systems are pinned to tested levels. It is built on modern foundations: immutable, content-addressed generations (composefs-style `/usr` images protected by fs-verity), declarative actions instead of maintainer scripts, TUF-signed repositories, and a small privileged daemon with unprivileged helpers.

Ordin is the package manager of Yoxela, a Linux-based operating system for servers only.

## Status

The design is complete and development is starting. Nothing is usable yet.

## Releases

Each release has one archive per target, a `SHA256SUMS` file, and an SSH signature (`.sig`) for every file.

| Target | Runs on |
| --- | --- |
| `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl` | Any Linux: the binaries are statically linked |
| `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu` | Linux with glibc 2.34 or newer (as of 0.1.0) |

CI builds every release in a pinned container ([`release/Dockerfile`](release/Dockerfile)) and records build provenance. The maintainer then rebuilds the tag separately, and signs and publishes the release only if every file matches CI's byte for byte.

To verify a download, take [`release/allowed_signers`](release/allowed_signers) from the repository at the release's tag (not from the release page), then run, with OpenSSH 8.1 or newer:

```
ssh-keygen -Y verify -f allowed_signers -I ordin-release -n ordin-release -s SHA256SUMS.sig < SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
```

To check that an archive was built by this repository's release workflow:

```
gh attestation verify ordin-<version>-<target>.tar.gz --repo yoxela/ordin
```

## License

- Programs and engines: GPL-3.0-or-later
- Format and library crates that other tools may reuse (every pure-core crate, plus `ordin-archive`, `ordin-sign` and `ordin-api`): MIT OR Apache-2.0
- Documentation: CC-BY-4.0

Every source file carries an SPDX license header. The license texts are in [`LICENSES/`](LICENSES/).

Copyright The Ordin Authors (see [`AUTHORS`](AUTHORS)).
