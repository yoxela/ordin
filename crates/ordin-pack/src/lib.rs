// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Packaging rungs 0 and 1: scanning a tree, inferring requirements,
//! classifying facets and writing a package.
//!
//! So far this crate scans: [`walk`] records a directory as a tree, with
//! every file's metadata and digests. Later stories build on the result.

mod attrs;
mod error;
mod owners;
mod walk;

pub use error::{WalkError, WalkErrorKind};
pub use owners::OwnerOverride;
pub use walk::{Options, Walk, Warning, walk};
