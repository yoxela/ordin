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
//! - [`classify`] splits the normalized tree into facets by path rules and
//!   the recipe's overrides.
//!
//! Later stories build on the result.

mod attrs;
pub mod elf;
mod error;
mod facets;
pub mod git;
mod infer;
mod layout;
mod owners;
mod pack;
mod shebang;
mod source;
mod walk;

pub use error::{WalkError, WalkErrorKind};
pub use facets::{
    FacetError, FacetErrorKind, FacetNote, FacetOverride, FacetTree, Facets, Placement, Reason,
    classify,
};
pub use infer::{InferError, InferNote, Inferred, LIBRARY_DIRS, SKIPPED, infer};
pub use layout::{Layout, LayoutError, LayoutErrorKind, LayoutOptions, normalize};
pub use owners::OwnerOverride;
pub use pack::{Output, PackError, PackOptions, Packed, default_file_name, pack};
pub use source::RootSource;
pub use walk::{Options, Walk, Warning, walk};
