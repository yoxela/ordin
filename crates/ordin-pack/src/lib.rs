// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Packaging rungs 0 and 1: scanning a tree, inferring requirements,
//! classifying facets and writing a package.
//!
//! So far:
//!
//! - [`walk`] records a directory as a tree, with every file's metadata
//!   and digests.
//! - [`normalize`] maps that tree into Ordin's layout: everything under
//!   `/usr`, with `etc/` as config defaults and `var/` as state.
//!
//! Later stories build on the result.

mod attrs;
mod error;
mod layout;
mod owners;
mod walk;

pub use error::{WalkError, WalkErrorKind};
pub use layout::{Layout, LayoutError, LayoutErrorKind, LayoutOptions, normalize};
pub use owners::OwnerOverride;
pub use walk::{Options, Walk, Warning, walk};
