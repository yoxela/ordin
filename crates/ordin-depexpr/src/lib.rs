// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! The dependency grammar: parser, syntax tree and evaluation against a
//! set of provides.
//!
//! Requirements are boolean expressions over atoms (see `ordin-core`):
//!
//! ```text
//! so:libssl.so.3 and so:libpcre2-8.so.0 and (cap:zlib or zlib-ng-compat)
//! nginx[doc] >= 1.27 and not nginx-legacy
//! cap:systemd-units if cap:systemd
//! ```
//!
//! - **Atoms** are package names, `cap:`, `so:` and `file:` atoms.
//!   Package and `cap:` atoms can take a version constraint (`=`, `!=`,
//!   `<`, `<=`, `>`, `>=`, or `~` for compatible-with, like semver's
//!   caret), and package atoms can select facets (`nginx[doc,runtime]`).
//! - **`and` and `or`** can't be mixed without parentheses, so an
//!   expression reads only one way.
//! - **`not a`** is satisfied when `a` isn't.
//! - **`a if b`** requires `a` only when `b` holds, as in rpm's rich
//!   dependencies. It binds loosest, and a group has at most one `if`.
//! - **A versioned requirement** is met only by a provide with a version,
//!   as in Debian: `cap:go` with no version doesn't satisfy `cap:go >= 1.21`.
//!
//! [`Expr`] parses with [`str::parse`], reporting errors with their byte
//! offset, and shows as its canonical text: single spaces around keywords
//! and operators, facets sorted, and only the parentheses the tree needs,
//! so parsing the text gives back the same tree. Input may be spaced
//! differently (`cap:go>=1.21`).
//!
//! An expression is at most [`MAX_LEN`] bytes, nests at most [`MAX_DEPTH`]
//! deep and names at most [`MAX_ATOMS`] atoms, so no input can exhaust
//! the stack. Nothing here does I/O, and no input makes it panic.

mod error;
mod expr;
mod parse;

pub use error::{Error, ErrorKind};
pub use expr::{Expr, Op, Provide, Requirement};

/// The longest expression, in bytes.
pub const MAX_LEN: usize = 4096;
/// How deep parentheses and `not` may nest.
pub const MAX_DEPTH: usize = 32;
/// The most atoms an expression may name.
pub const MAX_ATOMS: usize = 256;
