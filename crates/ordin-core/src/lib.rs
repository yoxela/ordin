// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Shared types: package names, capabilities, digests, architectures and
//! error types.
//!
//! Every type here can only hold a valid value: it is built by parsing,
//! and parsing what it shows gives back an equal value. Serde reads and
//! writes each one as its string form.
//!
//! | Type | Form | Example |
//! | --- | --- | --- |
//! | [`PackageName`] | `[a-z0-9][a-z0-9+.-]*`, 2 to 128 bytes, not `and`, `or`, `not` or `if` | `libstdc++6` |
//! | [`Capability`] | `cap:` and the package name grammar (keywords allowed) | `cap:http-server` |
//! | [`Soname`] | `so:` and `[A-Za-z0-9._+-]+` (up to 255 bytes, not `.` or `..`), optionally `@` and a symbol version node `[A-Za-z0-9._]+` (up to 64 bytes) | `so:libc.so.6@GLIBC_2.38` |
//! | [`FilePath`] | `file:` and an absolute, normalized path of printable ASCII without spaces, brackets, `,` or `= ! < > ~`, up to 4096 bytes | `file:/usr/bin/python3` |
//! | [`Atom`] | any of the four above; a bare name is a package | `cap:mta` |
//! | [`Arch`] | `x86_64`, `aarch64` or `noarch` | `aarch64` |
//! | [`Digest`] | `blake3:` or `sha256:` and 64 lowercase hex digits | `blake3:af13…3262` |
//! | [`Facet`] | `[a-z][a-z0-9-]*`, optionally `:` and `[A-Za-z0-9_@.+-]+`, up to 64 bytes | `locale:pt_BR` |
//!
//! Names are ASCII and package names are lowercase, so no two names can
//! look alike. The characters the dependency language uses for operators
//! and brackets can't appear in any atom, and its keywords can't be
//! package names, so an expression always parses one way.
//!
//! Nothing here does I/O, and no input makes it panic.

mod arch;
mod atom;
mod digest;
mod error;
mod name;
mod serde_str;

pub use arch::Arch;
pub use atom::Atom;
pub use digest::{Algorithm, Digest};
pub use error::{Error, Kind};
pub use name::{
    Capability, FACET_MAX, Facet, FilePath, KEYWORDS, NAME_MAX, NAME_MIN, PATH_MAX, PackageName,
    SONAME_MAX, Soname, VERSION_NODE_MAX,
};
