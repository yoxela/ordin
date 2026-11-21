// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Why a chunk index was refused, and where.

use std::fmt;

use super::params::ParamsError;

/// Where in a chunk index an error is.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IndexLocation {
    /// The file, by position, and its content digest when it has a
    /// readable one.
    pub file: Option<(usize, Option<String>)>,
    /// The chunk within the file, by position.
    pub chunk: Option<usize>,
    /// The field, within the chunk, the file or the index.
    pub field: Option<String>,
}

impl fmt::Display for IndexLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.file {
            None => f.write_str("the chunk index")?,
            Some((index, None)) => write!(f, "file {index}")?,
            Some((index, Some(content))) => write!(f, "file {index} ({content})")?,
        }
        if let Some(chunk) = self.chunk {
            write!(f, ", chunk {chunk}")?;
        }
        if let Some(field) = &self.field {
            write!(f, ", field {field:?}")?;
        }
        Ok(())
    }
}

/// A chunk index that breaks a rule, or a file it can't give chunks for.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{at}: {kind}")]
pub struct IndexError {
    /// Where.
    pub at: IndexLocation,
    /// What is wrong.
    pub kind: IndexErrorKind,
}

/// What is wrong.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IndexErrorKind {
    /// Bigger than a chunk index may be.
    #[error("a chunk index is at most {max} bytes; this one is {len}")]
    TooLarge {
        /// The limit.
        max: usize,
        /// The size.
        len: usize,
    },
    /// Not UTF-8.
    #[error("a chunk index is UTF-8 JSON")]
    NotUtf8,
    /// Not acceptable JSON.
    #[error("not acceptable JSON: {0}")]
    Json(String),
    /// Valid, but not the canonical encoding.
    #[error("not canonical JSON (RFC 8785); the first difference is at byte {at}")]
    NotCanonical {
        /// The first byte that differs.
        at: usize,
    },
    /// A format version this reader doesn't know.
    #[error("unknown chunk index format {0}; this reader knows format 1")]
    UnknownFormat(String),
    /// A chunking algorithm this reader doesn't know.
    #[error("unknown chunking algorithm {0:?}; this reader knows \"fastcdc-2020\"")]
    UnknownAlgorithm(String),
    /// A value of the wrong JSON type.
    #[error("expected {expected}, found {found}")]
    WrongType {
        /// The type the field needs.
        expected: &'static str,
        /// The type it has.
        found: &'static str,
    },
    /// A required field is missing.
    #[error("missing")]
    Missing,
    /// A field this format doesn't have.
    #[error("unknown field")]
    UnknownField,
    /// A value that doesn't follow its grammar.
    #[error("{0}")]
    Invalid(String),
    /// A digest made with the wrong algorithm.
    #[error("expected a BLAKE3 digest")]
    NotBlake3,
    /// Chunker settings that can't be used.
    #[error(transparent)]
    Params(ParamsError),
    /// More files than an index may list.
    #[error("a chunk index lists at most {max} files; this one lists {len}")]
    TooManyFiles {
        /// The limit.
        max: usize,
        /// The count.
        len: usize,
    },
    /// More chunks than an index may list.
    #[error("a chunk index lists at most {max} chunks in all")]
    TooManyChunks {
        /// The limit.
        max: usize,
    },
    /// A file listed before one whose content digest is smaller.
    #[error("files are sorted by content digest; this one comes before {previous}")]
    NotSorted {
        /// The file before it.
        previous: String,
    },
    /// The same file listed twice.
    #[error("listed twice")]
    Duplicate,
    /// A file with no chunks.
    #[error("a listed file has at least one chunk")]
    NoChunks,
    /// A chunk shorter than the minimum that isn't its file's last.
    #[error(
        "only a file's last chunk is shorter than the minimum, {minimum} bytes; this one is {length}"
    )]
    ChunkTooShort {
        /// The minimum chunk length.
        minimum: u32,
        /// The chunk's length.
        length: u64,
    },
    /// A chunk longer than the maximum, or a last chunk that is empty.
    #[error("a chunk is 1 to {maximum} bytes; this one is {length}")]
    ChunkLength {
        /// The maximum chunk length.
        maximum: u32,
        /// The chunk's length.
        length: u64,
    },
    /// A file the index lists that is under the whole-file threshold.
    #[error("only files of at least {whole_below} bytes are listed; this one is {size}")]
    FileTooSmall {
        /// The threshold.
        whole_below: u32,
        /// The file's size.
        size: u64,
    },
    /// A file larger than any file may be.
    #[error("a file is at most {max} bytes")]
    FileTooLarge {
        /// The limit.
        max: u64,
    },
    /// A file of one chunk whose chunk isn't the file.
    #[error("a file's only chunk is the whole file, so its digest is the file's content digest")]
    SingleChunk,
    /// A file at or above the threshold that the index doesn't list.
    #[error("{content} is {size} bytes, so the index should list it, and it doesn't")]
    NotListed {
        /// The file's content digest.
        content: String,
        /// The file's size.
        size: u64,
    },
    /// A listed file whose chunks don't add up to its size.
    #[error("the file is {size} bytes, and its chunks add up to {listed}")]
    WrongSize {
        /// The size the chunks add up to.
        listed: u64,
        /// The file's size.
        size: u64,
    },
}

impl IndexError {
    /// An error about the whole index, or one of its own fields.
    pub(crate) fn index(field: Option<&str>, kind: IndexErrorKind) -> Self {
        Self {
            at: IndexLocation {
                field: field.map(str::to_owned),
                ..IndexLocation::default()
            },
            kind,
        }
    }

    /// An error about one file, one of its chunks, or one of their fields.
    pub(crate) fn file(
        index: usize,
        content: Option<&str>,
        chunk: Option<usize>,
        field: Option<&str>,
        kind: IndexErrorKind,
    ) -> Self {
        Self {
            at: IndexLocation {
                file: Some((index, content.map(str::to_owned))),
                chunk,
                field: field.map(str::to_owned),
            },
            kind,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locations_say_where() {
        assert_eq!(
            IndexError::index(None, IndexErrorKind::NotUtf8).to_string(),
            "the chunk index: a chunk index is UTF-8 JSON"
        );
        assert_eq!(
            IndexError::index(Some("files"), IndexErrorKind::Missing).to_string(),
            "the chunk index, field \"files\": missing"
        );
        assert_eq!(
            IndexError::file(3, None, None, None, IndexErrorKind::Duplicate).to_string(),
            "file 3: listed twice"
        );
        assert_eq!(
            IndexError::file(
                2,
                Some("blake3:ab"),
                Some(4),
                Some("length"),
                IndexErrorKind::Missing
            )
            .to_string(),
            "file 2 (blake3:ab), chunk 4, field \"length\": missing"
        );
    }
}
