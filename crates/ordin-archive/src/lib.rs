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
//! [`Reader`] reads one in place. Opening it reads only the archive's
//! headers, the OCI JSON and the manifest, and refuses anything the
//! writer wouldn't have written. Every other part is read when asked for,
//! within its own limit, and checked against its digests: a chunk against
//! its BLAKE3 digest, and a file put together from its chunks against its
//! tree.

mod blob;
mod compress;
mod error;
mod oci;
mod pack;
mod read;
mod tar;
mod write;

pub use blob::BlobId;
pub use error::{PackTableError, PackTableErrorKind, Part, ReadError, ReadErrorKind, WriteError};
pub use oci::{EMPTY_CONFIG, OCI_LAYOUT, annotations, media};
pub use pack::{
    MAX_CHUNK, MAX_FRAME, MAX_PACK_CHUNKS, MAX_PACK_TABLE_SIZE, PACK_TABLE_VERSION, PackEntry,
    PackTable,
};
pub use read::{MAX_ENTRIES, MAX_IMAGE_MANIFEST_SIZE, MAX_INDEX_SIZE, MAX_LICENSE_TEXT, Reader};
pub use tar::MAX_ENTRY_SIZE;
pub use write::{LEVEL, MAX_LEVEL, Options, Package, Source, Written, write};
