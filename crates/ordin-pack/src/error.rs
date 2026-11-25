// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Why a walk stopped.

use std::io;

use ordin_tree::MAX_ENTRIES;

/// A walk that couldn't finish, and the path it stopped at.
#[derive(Debug, thiserror::Error)]
#[error("{path}: {kind}")]
pub struct WalkError {
    /// Where, as a path in the tree. Characters a terminal could act on
    /// are escaped, because names come from the directory being walked.
    pub path: String,
    /// What went wrong.
    pub kind: WalkErrorKind,
}

/// What stopped a walk.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WalkErrorKind {
    /// A system call failed.
    #[error("can't {action}: {error}")]
    Io {
        /// What was being done.
        action: &'static str,
        /// The system's error. Shown in the message, so not also given as
        /// the error's source.
        error: io::Error,
    },
    /// A file name isn't UTF-8, which a tree requires.
    #[error("the name isn't valid UTF-8")]
    NotUtf8,
    /// A name makes a path a tree can't hold.
    #[error("{0}")]
    BadPath(String),
    /// A symlink's target isn't UTF-8.
    #[error("the symlink's target isn't valid UTF-8")]
    TargetNotUtf8,
    /// A symlink's target can't be recorded.
    #[error("{0}")]
    BadTarget(String),
    /// A kind of file that can't be packaged.
    #[error("{0} can't be packaged")]
    Unsupported(&'static str),
    /// Something is mounted here, so it belongs to another filesystem.
    #[error("this is a mount point, and a walk stays on one mount")]
    CrossesMount,
    /// The tree changed during the walk, so what was read can't be trusted.
    #[error("it changed during the walk")]
    Changed,
    /// More paths than a tree can hold.
    #[error("the directory holds more than {MAX_ENTRIES} entries, the most a tree can hold")]
    TooManyEntries,
    /// The kernel didn't say what a walk needs to know.
    #[error("the kernel didn't report the file's details; Linux 5.8 or later is needed")]
    MissingDetails,
    /// An extended attribute that can't be packaged.
    #[error("the extended attribute {name} can't be packaged")]
    RefusedAttribute {
        /// Its name, escaped.
        name: String,
    },
    /// A POSIX ACL, which a tree can't hold. Dropping it could widen
    /// access, so it is refused.
    #[error("it has a POSIX ACL ({name}), which can't be packaged; remove it with setfacl -b")]
    Acl {
        /// The attribute holding it.
        name: String,
    },
    /// An extended attribute's name isn't one a tree can hold.
    #[error("{0}")]
    BadAttribute(String),
    /// A `security.capability` value that can't be recorded.
    #[error("{0}")]
    BadCapabilities(String),
    /// An owner override that applied to nothing, probably a typo.
    #[error("the owner override matches nothing in the tree")]
    UnusedOwner,
    /// Two owner overrides for one path.
    #[error("the path has more than one owner override")]
    DuplicateOwner,
    /// The entries don't make a valid tree.
    #[error(transparent)]
    Tree(Box<ordin_tree::Error>),
}
