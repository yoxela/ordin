// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Reading and writing `.ordin` files in the OCI image layout.
//!
//! `FORMAT.md` beside this crate is the reference. In short, a `.ordin`
//! file is an OCI artifact (`artifactType`
//! `application/vnd.ordin.package.v1`, the empty config) in a
//! deterministic ustar archive. Its layers are the Ordin manifest, the
//! license texts, one tree per facet, the chunk index, and per facet a
//! pack table and a chunk pack of independent zstd frames. Every
//! descriptor carries its blob's BLAKE3 digest in the annotation
//! `com.ordinpm.blake3`.
//!
//! [`write`] writes a package. It reads each file once through a
//! [`Source`], cuts it into chunks with `ordin-tree`'s chunker (this crate
//! never chooses chunk boundaries) and refuses any file that isn't what
//! its tree records. The same package, chunking and zstd level give the
//! same bytes on any number of threads, with the same zstd library.
//!
//! Reading `.ordin` files arrives with ORD-131.

mod blob;
mod compress;
mod error;
mod oci;
mod pack;
mod tar;
mod write;

pub use blob::BlobId;
pub use error::WriteError;
pub use oci::{EMPTY_CONFIG, OCI_LAYOUT, annotations, media};
pub use pack::{PACK_TABLE_VERSION, PackEntry, PackTable};
pub use tar::MAX_ENTRY_SIZE;
pub use write::{LEVEL, MAX_LEVEL, Options, Package, Source, Written, write};
