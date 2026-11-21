// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Why a `.ordin` file couldn't be written.

use std::io;

use ordin_core::{Digest, Facet};
use ordin_tree::TreePath;

/// Why a `.ordin` file couldn't be written. Nothing written before the
/// error is a usable file.
#[derive(Debug, thiserror::Error)]
pub enum WriteError {
    /// The zstd level is outside the range zstd offers.
    #[error("the zstd level {level} is outside 1 to {max}")]
    Level {
        /// The level asked for.
        level: i32,
        /// The highest level.
        max: i32,
    },
    /// The manifest breaks a rule.
    #[error("the manifest: {0}")]
    Manifest(Box<ordin_manifest::Error>),
    /// A facet's tree breaks a rule.
    #[error("the tree for facet {facet}: {source}")]
    Tree {
        /// The facet.
        facet: Facet,
        /// What is wrong.
        source: Box<ordin_tree::Error>,
    },
    /// The manifest lists a facet with no tree given for it.
    #[error("the manifest lists facet {0}, but no tree was given for it")]
    MissingTree(Facet),
    /// A tree was given for a facet the manifest doesn't list.
    #[error("a tree was given for facet {0}, which the manifest doesn't list")]
    ExtraTree(Facet),
    /// A tree isn't the one the manifest records.
    #[error("facet {facet}: the manifest records tree {recorded}, but the tree given is {given}")]
    TreeMismatch {
        /// The facet.
        facet: Facet,
        /// The digest in the manifest.
        recorded: Digest,
        /// The digest of the tree given.
        given: Digest,
    },
    /// A facet's size isn't the one the manifest records.
    #[error(
        "facet {facet}: the manifest records {recorded} bytes of file content, but its tree has {given}"
    )]
    SizeMismatch {
        /// The facet.
        facet: Facet,
        /// The size in the manifest.
        recorded: u64,
        /// The size of the files in the tree.
        given: u64,
    },
    /// The license records a text that wasn't given.
    #[error("no text was given for the license {0}")]
    MissingLicense(String),
    /// A text was given for a license the manifest doesn't record.
    #[error("a text was given for {0}, which the manifest's license doesn't record")]
    ExtraLicense(String),
    /// A license text isn't the one the manifest records.
    #[error("the text given for {id} is {given}, but the manifest records {recorded}")]
    LicenseMismatch {
        /// The license ID.
        id: String,
        /// The digest in the manifest.
        recorded: Digest,
        /// The digest of the text given.
        given: Digest,
    },
    /// A file couldn't be opened or read.
    #[error("{path}: {source}")]
    Read {
        /// The file's path in the tree.
        path: TreePath,
        /// What went wrong.
        source: io::Error,
    },
    /// A file isn't what its tree records: it changed after the tree was
    /// made, or the source gave another file.
    #[error(
        "{path}: the tree records {recorded_size} bytes with content {recorded}, \
         but the file read has {read_size} bytes with content {read}"
    )]
    Changed {
        /// The file's path in the tree.
        path: TreePath,
        /// The size the tree records.
        recorded_size: u64,
        /// The content digest the tree records.
        recorded: Digest,
        /// The size of what was read.
        read_size: u64,
        /// The content digest of what was read.
        read: Digest,
    },
    /// The chunk index breaks a rule, for example by listing too many
    /// chunks.
    #[error("the chunk index: {0}")]
    Index(Box<ordin_tree::chunk::IndexError>),
    /// A chunk pack would be too large for a ustar entry.
    #[error(
        "the chunk pack for facet {facet} would pass {max} bytes, the most a tar entry can hold"
    )]
    PackTooLarge {
        /// The facet.
        facet: Facet,
        /// The limit.
        max: u64,
    },
    /// zstd failed.
    #[error("compressing chunks: {0}")]
    Compress(io::Error),
    /// A temporary file for a chunk pack couldn't be made, written or read.
    #[error("spooling a chunk pack: {0}")]
    Spool(io::Error),
    /// A blob read back differently while it was copied into the file,
    /// for example a spooled chunk pack changed on disk.
    #[error("{path} changed before it was copied into the file")]
    BlobChanged {
        /// The blob's path in the layout.
        path: String,
    },
    /// Writing the output failed.
    #[error("writing the .ordin file: {0}")]
    Output(io::Error),
}

impl From<ordin_manifest::Error> for WriteError {
    fn from(e: ordin_manifest::Error) -> Self {
        Self::Manifest(Box::new(e))
    }
}

impl From<ordin_tree::chunk::IndexError> for WriteError {
    fn from(e: ordin_tree::chunk::IndexError) -> Self {
        Self::Index(Box::new(e))
    }
}
