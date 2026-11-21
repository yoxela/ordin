// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Content-defined chunks for transport, and the chunk index.
//!
//! `CHUNK-INDEX.md` beside this crate is the reference for the index and
//! the chunker. In short:
//!
//! - [`chunk_file`] reads a file once and cuts it with FastCDC 2020,
//!   giving its digests, its chunks and each chunk's bytes. A file under
//!   [`ChunkParams::whole_below`] is one chunk.
//! - A [`ChunkIndex`] records the settings and lists every file at or
//!   above the threshold, by content digest, with its chunks' digests and
//!   lengths. Readers follow it and never re-chunk.
//! - Chunks are addressed by the BLAKE3 digest of their uncompressed
//!   bytes, so compression never enters an index or its identity.
//!
//! The chunker and the index live together so that the cut points and
//! the format that records them change behind one version number.

mod cut;
mod error;
mod file;
mod index;
mod params;

pub use error::{IndexError, IndexErrorKind, IndexLocation};
pub use file::{ChunkRef, ChunkedFile, chunk_file};
pub use index::{ChunkIndex, IndexFile, MAX_CHUNKS, MAX_FILES, MAX_SIZE};
pub use params::{
    AVERAGE_BOUNDS, ChunkParams, MAXIMUM_BOUNDS, MINIMUM_BOUNDS, NORMALIZATION_MAX, ParamsError,
};
