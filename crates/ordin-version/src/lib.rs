// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Version parsing and Ordin's universal version ordering.
//!
//! Every package version is compared with one algorithm, so an admin never
//! needs to know a package's version scheme. It is Debian's (text and
//! number runs compared separately, so `1.10` sorts after `1.9`, and `~`
//! sorts before everything, so `1.2~rc1` comes before `1.2`), extended
//! with rpm's `^`, which sorts after the end of a version but before any
//! further release (`1.2` < `1.2^git20261112` < `1.2.1`).
//!
//! - [`Version`] is `[epoch:]upstream[-release[+uN]]`, compared part by
//!   part. A missing epoch or update level counts as 0 and isn't shown.
//! - [`compare_text`] is the ordering on its own, for any version text,
//!   such as the version a self-updating payload reports.
//! - [`normalize_semver`] turns `2.0.0-rc.1` into `2.0.0~rc.1`, so semantic
//!   pre-releases sort before their release.
//! - [`snapshot`] builds a version for a build from a commit:
//!   `1.4.2^20261112.37.g3fa9c1e`.
//! - [`Version::is_compatible_with`] is the `~` operator in dependencies:
//!   `~1.27` is at least 1.27 and below 2.
//!
//! Nothing here does I/O, and no input makes it panic.

mod compare;
mod compat;
mod error;
mod semver;
mod snapshot;
mod version;

pub use compare::compare_text;
pub use error::{Error, Part};
pub use semver::normalize_semver;
pub use snapshot::{Position, snapshot};
pub use version::{MAX_LEN, Version};
