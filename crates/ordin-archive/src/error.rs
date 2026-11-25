// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Why a `.ordin` file couldn't be written.

use std::io;

use ordin_core::{Digest, Facet};
use ordin_tree::TreePath;
use ordin_tree::chunk::ChunkParams;

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
    #[error("the tree for facet {facet}")]
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
    /// A license text is larger than a reader accepts.
    #[error(
        "the text given for {id} has {size} bytes, more than the {max} a license text may have"
    )]
    LicenseTooLarge {
        /// The license ID.
        id: String,
        /// The text's size.
        size: u64,
        /// The limit.
        max: u64,
    },
    /// The image manifest would be larger than a reader accepts, because
    /// the package has too many facets or license texts.
    #[error(
        "the image manifest would have {size} bytes, more than the {max} a registry must accept"
    )]
    ImageManifestTooLarge {
        /// Its size.
        size: u64,
        /// The limit.
        max: u64,
    },
    /// A signature is for another package.
    #[error("the signature by {key} is for package {signed}, not this package, {package}")]
    SignatureFor {
        /// Who signed.
        key: String,
        /// What it signs.
        signed: Digest,
        /// This package.
        package: Digest,
    },
    /// Two signatures are by one key.
    #[error("two signatures are by {0}; a package carries one per key")]
    DuplicateSignature(String),
    /// More signatures than a reader accepts.
    #[error("{count} signatures, more than the {max} a package may carry")]
    TooManySignatures {
        /// How many were given.
        count: usize,
        /// The limit.
        max: usize,
    },
    /// A file couldn't be opened or read.
    #[error("{path}")]
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
    /// Reading the package being signed again failed.
    #[error("reading the package: {0}")]
    Input(io::Error),
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

/// The part of a `.ordin` file a [`ReadError`] is about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Part {
    /// The tar archive around everything.
    Archive,
    /// The `oci-layout` file.
    OciLayout,
    /// `index.json`.
    Index,
    /// The OCI image manifest.
    ImageManifest,
    /// The empty config blob.
    Config,
    /// The Ordin manifest.
    Manifest,
    /// One signature, by its key: `ed25519:` and the key's hex.
    Signature(String),
    /// The text of one license, by SPDX ID.
    License(String),
    /// One facet's tree.
    Tree(Facet),
    /// The chunk index.
    ChunkIndex,
    /// One facet's pack table.
    PackTable(Facet),
    /// One facet's chunk pack.
    ChunkPack(Facet),
    /// One chunk in a facet's chunk pack.
    Chunk {
        /// The facet.
        facet: Facet,
        /// The chunk's BLAKE3 digest.
        digest: Digest,
    },
    /// One file of a facet, put together from its chunks.
    File {
        /// The facet.
        facet: Facet,
        /// The file's path in the tree.
        path: TreePath,
    },
}

impl std::fmt::Display for Part {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Archive => f.write_str("the archive"),
            Self::OciLayout => f.write_str("oci-layout"),
            Self::Index => f.write_str("index.json"),
            Self::ImageManifest => f.write_str("the image manifest"),
            Self::Config => f.write_str("the config"),
            Self::Manifest => f.write_str("the manifest"),
            Self::Signature(key) => write!(f, "the signature by {key}"),
            Self::License(id) => write!(f, "the license text for {id}"),
            Self::Tree(facet) => write!(f, "the tree for facet {facet}"),
            Self::ChunkIndex => f.write_str("the chunk index"),
            Self::PackTable(facet) => write!(f, "the pack table for facet {facet}"),
            Self::ChunkPack(facet) => write!(f, "the chunk pack for facet {facet}"),
            Self::Chunk { facet, digest } => {
                write!(f, "chunk {digest} in the chunk pack for facet {facet}")
            }
            Self::File { facet, path } => write!(f, "{path} in facet {facet}"),
        }
    }
}

/// Why a `.ordin` file, or a part of it, couldn't be read. Every error
/// names the [`Part`] that failed.
#[derive(Debug, thiserror::Error)]
#[error("{}: {}", .0.part, .0.kind)]
pub struct ReadError(pub(crate) Box<Failed>);

#[derive(Debug)]
pub(crate) struct Failed {
    pub(crate) part: Part,
    pub(crate) kind: ReadErrorKind,
}

impl ReadError {
    pub(crate) fn new(part: Part, kind: ReadErrorKind) -> Self {
        Self(Box::new(Failed { part, kind }))
    }

    /// The part that failed.
    #[must_use]
    pub fn part(&self) -> &Part {
        &self.0.part
    }

    /// What is wrong with it.
    #[must_use]
    pub fn kind(&self) -> &ReadErrorKind {
        &self.0.kind
    }
}

/// What is wrong with a part of a `.ordin` file.
#[derive(Debug, thiserror::Error)]
pub enum ReadErrorKind {
    /// Reading the input failed.
    #[error("reading the file: {0}")]
    Io(io::Error),
    /// The input ends inside the part.
    #[error("the file ends inside it")]
    Truncated,
    /// A tar header isn't the one this format writes for its name and
    /// size.
    #[error("the tar header at byte {at} isn't one a .ordin file has")]
    Header {
        /// Where the header starts.
        at: u64,
    },
    /// A tar entry has a name the format doesn't allow there.
    #[error("the entry at byte {at} is {name:?}, but {expected} comes there")]
    Entry {
        /// Where the entry's header starts.
        at: u64,
        /// The entry's name.
        name: String,
        /// What the format puts there.
        expected: &'static str,
    },
    /// The zero bytes after an entry aren't all zero.
    #[error("the padding at byte {at} isn't all zeros")]
    Padding {
        /// Where the padding starts.
        at: u64,
    },
    /// The archive doesn't end with exactly two zero blocks.
    #[error("the archive doesn't end with two zero blocks at byte {at} and nothing after them")]
    End {
        /// Where the closing blocks start.
        at: u64,
    },
    /// An entry the format requires isn't in the archive.
    #[error("there is no {0} entry")]
    MissingEntry(&'static str),
    /// The archive has more entries than any package needs.
    #[error("the archive has more than {max} entries")]
    TooManyEntries {
        /// The limit.
        max: usize,
    },
    /// The part is larger than this format allows for it.
    #[error("it has {size} bytes, more than the {max} allowed")]
    TooLarge {
        /// Its size.
        size: u64,
        /// The limit.
        max: u64,
    },
    /// The part's content isn't the fixed content the format requires.
    #[error("it isn't the content the format requires")]
    NotFixed,
    /// The part isn't valid JSON.
    #[error("{0}")]
    Json(String),
    /// A descriptor or field the format requires is missing or malformed.
    #[error("{0}")]
    Malformed(String),
    /// The JSON isn't encoded exactly as the format writes it.
    #[error("it isn't written as the format writes it, from byte {at}")]
    NotAsWritten {
        /// Where it first differs.
        at: usize,
    },
    /// A layer has a media type the format doesn't know.
    #[error("the layer type {0:?} is unknown")]
    UnknownLayer(String),
    /// The layers aren't in the format's order, or one is repeated.
    #[error("layer {index} ({media_type}) is out of order or repeated")]
    LayerOrder {
        /// The layer's position.
        index: usize,
        /// Its media type.
        media_type: &'static str,
    },
    /// A layer the format requires is missing.
    #[error("there is no {0} layer")]
    MissingLayer(&'static str),
    /// A blob that a descriptor names isn't in the archive.
    #[error("the blob {path} isn't in the archive")]
    MissingBlob {
        /// The blob's path.
        path: String,
    },
    /// A blob is in the archive that no descriptor names.
    #[error("the blob {path} is in the archive, but nothing names it")]
    UnusedBlob {
        /// The blob's path.
        path: String,
    },
    /// Two descriptors name the same blob with different digests or sizes.
    #[error("descriptors name the blob {path} with different digests or sizes")]
    Inconsistent {
        /// The blob's path.
        path: String,
    },
    /// The tar entry's size isn't the size its descriptor records.
    #[error("its descriptor records {recorded} bytes, but its tar entry has {actual}")]
    Size {
        /// The size the descriptor records.
        recorded: u64,
        /// The size in the archive.
        actual: u64,
    },
    /// The content doesn't have the digests its descriptor records.
    #[error("its content isn't what its descriptor records: BLAKE3 {read} instead of {recorded}")]
    Corrupt {
        /// The BLAKE3 digest recorded.
        recorded: Digest,
        /// The BLAKE3 digest of what was read.
        read: Digest,
    },
    /// The layers don't agree with the manifest.
    #[error("{0}")]
    Disagrees(String),
    /// A signature isn't in its format, names an unusable key, or doesn't
    /// verify.
    #[error("{0}")]
    Signature(ordin_sign::Error),
    /// More signature layers than a package may carry.
    #[error("a package carries at most {max} signatures")]
    TooManySignatures {
        /// The limit.
        max: usize,
    },
    /// The package has no such part.
    #[error("the package has no such part")]
    NoSuchPart,
    /// The manifest breaks a rule.
    #[error("{0}")]
    Manifest(Box<ordin_manifest::Error>),
    /// A tree breaks a rule.
    #[error("{0}")]
    Tree(Box<ordin_tree::Error>),
    /// The chunk index breaks a rule, or doesn't list a file it must.
    #[error("{0}")]
    ChunkIndex(Box<ordin_tree::chunk::IndexError>),
    /// A pack table breaks a rule.
    #[error("{0}")]
    PackTable(PackTableError),
    /// The pack table doesn't list the chunk.
    #[error("the pack table doesn't list it")]
    NotInPack,
    /// A chunk is longer than any chunking allows.
    #[error("it is {length} bytes long, more than the {max} any chunk can be")]
    ChunkTooLong {
        /// Its length.
        length: u64,
        /// The limit.
        max: u64,
    },
    /// The pack table places a frame outside the pack.
    #[error("its frame at {offset} with {length} bytes isn't inside the pack's {pack} bytes")]
    OutsidePack {
        /// The frame's offset.
        offset: u64,
        /// The frame's length.
        length: u64,
        /// The pack's size.
        pack: u64,
    },
    /// A chunk's frame isn't one independent zstd frame of exactly the
    /// chunk's length, or doesn't decompress.
    #[error("its zstd frame: {0}")]
    Frame(String),
    /// A file put together from its chunks isn't what its tree records.
    #[error(
        "the tree records {recorded_size} bytes with content {recorded}, \
         but its chunks give {read_size} bytes with content {read}"
    )]
    Content {
        /// The size the tree records.
        recorded_size: u64,
        /// The content digest the tree records.
        recorded: Digest,
        /// The size put together.
        read_size: u64,
        /// The content digest of what was put together.
        read: Digest,
    },
    /// Writing a file's content to the output failed.
    #[error("writing it out: {0}")]
    Output(io::Error),
    /// A file's content isn't the fs-verity digest its tree records.
    #[error("the tree records the fs-verity digest {recorded}, but its content gives {read}")]
    Fsverity {
        /// The fs-verity digest the tree records.
        recorded: Digest,
        /// The fs-verity digest of the content.
        read: Digest,
    },
    /// Cutting a file's content again with the chunking the chunk index
    /// records doesn't give the chunks the index lists for it.
    #[error(
        "cut again with the chunk index's chunking ({chunking}), it gives other chunks \
         than the index lists, from chunk {at}"
    )]
    Rechunked {
        /// The chunking the index records.
        chunking: ChunkParams,
        /// The first chunk that differs, counted from 0.
        at: usize,
    },
    /// A chunk pack holds a chunk that no file of its facet uses.
    #[error("it holds the chunk {digest}, which no file of the facet uses")]
    UnusedChunk {
        /// The chunk's digest.
        digest: Digest,
    },
    /// A chunk pack's chunks aren't in the order the facet's files first
    /// use them, the order the writer stores them in.
    #[error("its chunks aren't in the order the facet's files first use them, from chunk {at}")]
    ChunkOrder {
        /// The first chunk out of order, counted from 0.
        at: usize,
    },
    /// The chunk index lists content that no file of the package needs
    /// listed.
    #[error(
        "it lists the content {content}, which no file at or above the whole-file \
         threshold has"
    )]
    UnusedIndexEntry {
        /// The content listed.
        content: Digest,
    },
}

/// Why a pack table couldn't be read.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{kind}, at byte {at}")]
pub struct PackTableError {
    /// Where in the table.
    pub at: usize,
    /// What is wrong.
    pub kind: PackTableErrorKind,
}

/// What is wrong with a pack table.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PackTableErrorKind {
    /// The table is larger than any table can be.
    #[error("the table has {len} bytes, more than the {max} any table can have")]
    TooLarge {
        /// The limit.
        max: usize,
        /// The table's size.
        len: usize,
    },
    /// The text isn't the canonical table: something else is there.
    #[error("expected {0}")]
    Expected(&'static str),
    /// An integer isn't canonical or is too large.
    #[error("an integer must be 0 or start with 1 to 9, and be at most 2^53-1")]
    Integer,
    /// The format version isn't one this reader knows.
    #[error("the table format {0} is unknown")]
    Version(u64),
    /// The zstd level is outside 1 to 22.
    #[error("the zstd level {0} is outside 1 to 22")]
    Level(u64),
    /// The table lists more chunks than any facet can need.
    #[error("the table lists more than {max} chunks")]
    TooManyChunks {
        /// The limit.
        max: usize,
    },
    /// A frame doesn't start where the one before it ends.
    #[error("chunk {index} starts at {offset}, not at {expected}")]
    Gap {
        /// The chunk's position.
        index: usize,
        /// Where it starts.
        offset: u64,
        /// Where the one before it ends.
        expected: u64,
    },
    /// A frame's length is 0 or larger than any chunk's frame can be.
    #[error("chunk {index} has a frame of {length} bytes, outside 1 to {max}")]
    FrameLength {
        /// The chunk's position.
        index: usize,
        /// The frame's length.
        length: u64,
        /// The limit.
        max: u64,
    },
    /// A digest appears twice.
    #[error("chunk {index} repeats {digest}")]
    Repeated {
        /// The chunk's position.
        index: usize,
        /// The digest.
        digest: Digest,
    },
    /// The last frame doesn't end where the pack does.
    #[error("the frames end at {end}, but the pack has {pack} bytes")]
    End {
        /// Where the frames end.
        end: u64,
        /// The pack's size.
        pack: u64,
    },
}
