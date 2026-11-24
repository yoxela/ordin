// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Writing a package as a `.ordin` file.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::num::NonZeroUsize;
use std::path::Path;

use ordin_core::{Digest, Facet};
use ordin_manifest::Manifest;
use ordin_sign::Signature;
use ordin_tree::chunk::{ChunkIndex, ChunkParams, IndexFile, chunk_file};
use ordin_tree::{File, FileDigests, Kind, Tree, TreePath};

use crate::blob::{BlobId, HashingReader};
use crate::error::Part;
use crate::error::WriteError;
use crate::oci::{EMPTY_CONFIG, Layer, OCI_LAYOUT, annotations, image_manifest, index, media};
use crate::pack::PackBuilder;
use crate::read::{MAX_IMAGE_MANIFEST_SIZE, MAX_LICENSE_TEXT, MAX_SIGNATURES, Reader};
use crate::tar::{MAX_ENTRY_SIZE, TarWriter};

/// The zstd level packages are written at, the one ORD-100 measured.
pub const LEVEL: i32 = 19;

/// The highest zstd level.
pub const MAX_LEVEL: i32 = 22;

/// Where the writer reads each file's content from.
pub trait Source {
    /// A reader of one file's content.
    type Reader: Read;

    /// Opens the file a tree records at `path`. The writer reads it to its
    /// end once, and refuses the package if it isn't what `file` records.
    ///
    /// # Errors
    ///
    /// Any error opening the file.
    fn open(&mut self, path: &TreePath, file: &File) -> io::Result<Self::Reader>;
}

/// A package to write: its manifest and everything the manifest records.
#[derive(Clone, Copy, Debug)]
pub struct Package<'a> {
    /// The manifest.
    pub manifest: &'a Manifest,
    /// One tree for each facet the manifest lists.
    pub trees: &'a BTreeMap<Facet, Tree>,
    /// One text for each license ID the manifest records, by ID.
    pub licenses: &'a BTreeMap<String, Vec<u8>>,
    /// How files are cut into chunks.
    pub chunking: ChunkParams,
    /// Signatures over the package's identity, at most one per key, in
    /// any order. They are written sorted by key.
    pub signatures: &'a [Signature],
}

/// How to write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Options {
    /// The zstd level, 1 to [`MAX_LEVEL`]; [`LEVEL`] by default.
    pub level: i32,
    /// How many threads compress chunks; as many as the machine offers by
    /// default. The output is the same on any number.
    pub threads: NonZeroUsize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            level: LEVEL,
            threads: std::thread::available_parallelism().unwrap_or(NonZeroUsize::MIN),
        }
    }
}

/// What was written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Written {
    /// The package's identity: the BLAKE3 digest of its manifest.
    pub package: Digest,
    /// The SHA-256 digest of the OCI image manifest, as a registry names
    /// it.
    pub image: Digest,
    /// The chunk index's identity.
    pub chunk_index: Digest,
    /// The file's size in bytes.
    pub size: u64,
}

/// A blob's content: in memory, in a spooled temporary file, or in the
/// package being signed again, at an offset.
enum Data {
    Bytes(Vec<u8>),
    Spool(std::fs::File),
    Input(u64),
}

struct Blob {
    id: BlobId,
    data: Data,
}

/// The image manifest's layers, in order, and the blobs by path. Equal
/// blobs are stored once.
#[derive(Default)]
struct Contents {
    layers: Vec<Layer>,
    blobs: BTreeMap<String, Blob>,
}

impl Contents {
    fn blob(&mut self, id: BlobId, data: Data) {
        self.blobs.entry(id.path()).or_insert(Blob { id, data });
    }

    fn layer(&mut self, media_type: &'static str, notes: &[(&str, &str)], id: BlobId, data: Data) {
        let annotations = notes
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        self.layers.push(Layer {
            media_type,
            id,
            annotations,
        });
        self.blob(id, data);
    }

    fn bytes(&mut self, media_type: &'static str, notes: &[(&str, &str)], bytes: Vec<u8>) {
        self.layer(media_type, notes, BlobId::of(&bytes), Data::Bytes(bytes));
    }
}

/// A facet, its tree and the tree's canonical bytes.
type CheckedTree<'a> = (&'a Facet, &'a Tree, Vec<u8>);

/// Checks the trees against the manifest and returns each with its
/// canonical bytes, in facet order.
fn check_trees<'a>(package: &Package<'a>) -> Result<Vec<CheckedTree<'a>>, WriteError> {
    let recorded = &package.manifest.facets;
    if let Some(extra) = package.trees.keys().find(|f| !recorded.contains_key(*f)) {
        return Err(WriteError::ExtraTree(extra.clone()));
    }
    recorded
        .iter()
        .map(|(facet, entry)| {
            let tree = package
                .trees
                .get(facet)
                .ok_or_else(|| WriteError::MissingTree(facet.clone()))?;
            let bytes = tree
                .to_canonical_bytes()
                .map_err(|source| WriteError::Tree {
                    facet: facet.clone(),
                    source: Box::new(source),
                })?;
            let given = Digest::blake3(&bytes);
            if given != entry.tree {
                return Err(WriteError::TreeMismatch {
                    facet: facet.clone(),
                    recorded: entry.tree,
                    given,
                });
            }
            let size = tree
                .entries()
                .iter()
                .filter_map(|e| match &e.kind {
                    Kind::File(f) => Some(f.size),
                    _ => None,
                })
                .fold(0, u64::saturating_add);
            if size != entry.size {
                return Err(WriteError::SizeMismatch {
                    facet: facet.clone(),
                    recorded: entry.size,
                    given: size,
                });
            }
            Ok((facet, tree, bytes))
        })
        .collect()
}

/// Checks the license texts against the manifest and returns them in ID
/// order.
fn check_licenses<'a>(package: &Package<'a>) -> Result<Vec<(&'a str, &'a [u8])>, WriteError> {
    let recorded = &package.manifest.license.texts;
    if let Some(extra) = package
        .licenses
        .keys()
        .find(|id| !recorded.contains_key(*id))
    {
        return Err(WriteError::ExtraLicense(extra.clone()));
    }
    recorded
        .iter()
        .map(|(id, digest)| {
            let text = package
                .licenses
                .get(id)
                .ok_or_else(|| WriteError::MissingLicense(id.clone()))?;
            let size = text.len() as u64;
            if size > MAX_LICENSE_TEXT {
                return Err(WriteError::LicenseTooLarge {
                    id: id.clone(),
                    size,
                    max: MAX_LICENSE_TEXT,
                });
            }
            let given = Digest::blake3(text);
            if given != *digest {
                return Err(WriteError::LicenseMismatch {
                    id: id.clone(),
                    recorded: *digest,
                    given,
                });
            }
            Ok((id.as_str(), text.as_slice()))
        })
        .collect()
}

/// Reads each file of `tree` once per content, checks it against the
/// tree, and adds its chunks to the pack. Files at or above the
/// whole-file threshold go into `listed`, for the chunk index.
fn fill<W: Write>(
    pack: &mut PackBuilder<W>,
    tree: &Tree,
    params: &ChunkParams,
    source: &mut impl Source,
    listed: &mut BTreeMap<Digest, IndexFile>,
) -> Result<(), WriteError> {
    let mut done = BTreeSet::new();
    for entry in tree.entries() {
        let Kind::File(file) = &entry.kind else {
            continue;
        };
        if !done.insert(file.content) {
            continue;
        }
        let read_error = |source| WriteError::Read {
            path: entry.path.clone(),
            source,
        };
        let reader = source.open(&entry.path, file).map_err(read_error)?;
        let mut failed = None;
        let chunked = chunk_file(reader, params, |chunk, bytes| {
            pack.add(chunk.digest, bytes).map_err(|e| {
                failed = Some(e);
                io::Error::other("the chunk pack failed")
            })
        });
        if let Some(e) = failed {
            return Err(e);
        }
        let chunked = chunked.map_err(read_error)?;
        let recorded = FileDigests {
            size: file.size,
            content: file.content,
            fsverity: file.fsverity,
        };
        let read = chunked.digests();
        if *read != recorded {
            return Err(WriteError::Changed {
                path: entry.path.clone(),
                recorded_size: file.size,
                recorded: file.content,
                read_size: read.size,
                read: read.content,
            });
        }
        if let Some(listing) = chunked.index_entry() {
            listed.entry(file.content).or_insert(listing);
        }
    }
    Ok(())
}

/// Refuses an image manifest a reader wouldn't accept.
fn check_image_size(size: u64) -> Result<(), WriteError> {
    if size > MAX_IMAGE_MANIFEST_SIZE {
        return Err(WriteError::ImageManifestTooLarge {
            size,
            max: MAX_IMAGE_MANIFEST_SIZE,
        });
    }
    Ok(())
}

/// Copies one blob into the archive, checking that what is copied is the
/// blob its descriptor names.
fn copy_blob<W: Write>(
    tar: &mut TarWriter<W>,
    path: &str,
    id: &BlobId,
    data: impl Read,
) -> Result<(), WriteError> {
    let mut reader = HashingReader::new(data);
    tar.entry(path, id.size, &mut reader)
        .map_err(WriteError::Output)?;
    if reader.finish() != *id {
        return Err(WriteError::BlobChanged {
            path: path.to_owned(),
        });
    }
    Ok(())
}

/// Adds the signature layers, sorted by key, after checking that each is
/// for `package` and that no key signs twice.
fn add_signatures(
    contents: &mut Contents,
    package: Digest,
    signatures: &[Signature],
) -> Result<(), WriteError> {
    if signatures.len() > MAX_SIGNATURES {
        return Err(WriteError::TooManySignatures {
            count: signatures.len(),
            max: MAX_SIGNATURES,
        });
    }
    let mut sorted: Vec<&Signature> = signatures.iter().collect();
    sorted.sort_by_key(|s| s.key());
    for pair in sorted.windows(2) {
        if let [a, b] = pair
            && a.key() == b.key()
        {
            return Err(WriteError::DuplicateSignature(a.key().to_string()));
        }
    }
    for signature in sorted {
        if signature.package() != package {
            return Err(WriteError::SignatureFor {
                key: signature.key().to_string(),
                signed: signature.package(),
                package,
            });
        }
        let key = signature.key().to_string();
        contents.bytes(
            media::SIGNATURE,
            &[(annotations::KEY, key.as_str())],
            signature.to_bytes(),
        );
    }
    Ok(())
}

/// Reads from the package being signed again, keeping the first error so
/// it isn't taken for an error writing the output.
struct Input<'a, R> {
    inner: &'a mut R,
    failed: Option<io::Error>,
}

impl<R: Read> Read for Input<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf).inspect_err(|e| {
            self.failed = Some(io::Error::new(e.kind(), e.to_string()));
        })
    }
}

/// Writes the config, image manifest and `index.json` for `contents`,
/// then the whole archive, and returns the image manifest's identity and
/// the file's size. Blobs in the input are read from `input`.
fn finish<R: Read + Seek>(
    mut contents: Contents,
    input: &mut R,
    out: &mut impl Write,
) -> Result<(BlobId, u64), WriteError> {
    let config = BlobId::of(EMPTY_CONFIG);
    contents.blob(config, Data::Bytes(EMPTY_CONFIG.to_vec()));
    let image = image_manifest(&config, &contents.layers);
    check_image_size(image.len() as u64)?;
    let image_id = BlobId::of(&image);
    contents.blob(image_id, Data::Bytes(image));
    let index = index(&image_id);

    let mut tar = TarWriter::new(&mut *out);
    copy_blob(&mut tar, "oci-layout", &BlobId::of(OCI_LAYOUT), OCI_LAYOUT)?;
    copy_blob(
        &mut tar,
        "index.json",
        &BlobId::of(&index),
        index.as_slice(),
    )?;
    for (path, blob) in &mut contents.blobs {
        match &mut blob.data {
            Data::Bytes(bytes) => copy_blob(&mut tar, path, &blob.id, bytes.as_slice())?,
            Data::Spool(file) => {
                file.seek(SeekFrom::Start(0)).map_err(WriteError::Spool)?;
                copy_blob(&mut tar, path, &blob.id, BufReader::new(file))?;
            }
            Data::Input(offset) => {
                input
                    .seek(SeekFrom::Start(*offset))
                    .map_err(WriteError::Input)?;
                let mut reader = Input {
                    inner: &mut *input,
                    failed: None,
                };
                let copied = copy_blob(&mut tar, path, &blob.id, BufReader::new(&mut reader));
                if let Some(e) = reader.failed {
                    return Err(WriteError::Input(e));
                }
                copied?;
            }
        }
    }
    let (_, size) = tar.finish().map_err(WriteError::Output)?;
    out.flush().map_err(WriteError::Output)?;
    Ok((image_id, size))
}

/// Writes `package` to `out` as a `.ordin` file, reading each file's
/// content from `source`. Chunk packs are spooled to anonymous temporary
/// files in `spool` until every blob's digest is known; nothing is left
/// there afterwards.
///
/// The same package, chunking and level always give the same bytes, on
/// any number of threads, as long as the zstd library is the same.
///
/// # Errors
///
/// The manifest, trees and license texts must agree: every facet's tree
/// and size, and every license text, must be what the manifest records.
/// Every file read must be what its tree records. Besides those, any
/// error reading a file, compressing, spooling or writing. Bytes already
/// written to `out` are not a usable file.
pub fn write(
    package: &Package<'_>,
    source: &mut impl Source,
    options: &Options,
    spool: &Path,
    out: &mut impl Write,
) -> Result<Written, WriteError> {
    if !(1..=MAX_LEVEL).contains(&options.level) {
        return Err(WriteError::Level {
            level: options.level,
            max: MAX_LEVEL,
        });
    }
    let manifest = package.manifest.to_canonical_bytes()?;
    let trees = check_trees(package)?;
    let licenses = check_licenses(package)?;

    let mut listed = BTreeMap::new();
    let mut packs = Vec::with_capacity(trees.len());
    for (facet, tree, _) in &trees {
        let spooled = tempfile::tempfile_in(spool).map_err(WriteError::Spool)?;
        let mut pack = PackBuilder::new(
            (*facet).clone(),
            options.level,
            options.threads,
            MAX_ENTRY_SIZE,
            BufWriter::new(spooled),
        );
        fill(&mut pack, tree, &package.chunking, source, &mut listed)?;
        let (table, spooled, id) = pack.finish()?;
        let spooled = spooled
            .into_inner()
            .map_err(|e| WriteError::Spool(e.into_error()))?;
        packs.push((*facet, table, spooled, id));
    }
    let chunk_index = ChunkIndex::new(package.chunking, listed.into_values().collect())?;
    let chunk_index = chunk_index.to_canonical_bytes()?;

    let package_digest = Digest::blake3(&manifest);
    let index_digest = Digest::blake3(&chunk_index);
    let mut contents = Contents::default();
    contents.bytes(media::MANIFEST, &[], manifest);
    add_signatures(&mut contents, package_digest, package.signatures)?;
    for (id, text) in licenses {
        contents.bytes(media::LICENSE, &[(annotations::LICENSE, id)], text.to_vec());
    }
    for (facet, _, bytes) in trees {
        contents.bytes(media::TREE, &[(annotations::FACET, facet.as_str())], bytes);
    }
    contents.bytes(media::CHUNK_INDEX, &[], chunk_index);
    for (facet, table, _, _) in &packs {
        contents.bytes(
            media::PACK_TABLE,
            &[(annotations::FACET, facet.as_str())],
            table.to_canonical_bytes(),
        );
    }
    for (facet, _, spooled, id) in packs {
        contents.layer(
            media::CHUNK_PACK,
            &[(annotations::FACET, facet.as_str())],
            id,
            Data::Spool(spooled),
        );
    }
    let (image_id, size) = finish(contents, &mut io::Cursor::new(&[][..]), out)?;
    Ok(Written {
        package: package_digest,
        image: image_id.sha256,
        chunk_index: index_digest,
        size,
    })
}

/// Writes the package `reader` holds to `out` again, with exactly
/// `signatures` and every other part as it is, copied byte for byte. The
/// result is the file [`write`] gives for the same package and
/// signatures. The manifest, and so the package's identity, doesn't
/// change; the image manifest's digest does.
///
/// # Errors
///
/// A signature is for another package, two are by one key, or there are
/// too many; reading the package or writing the output failed; or a blob
/// read back differently.
pub fn rewrite<R: Read + Seek>(
    reader: &mut Reader<R>,
    signatures: &[Signature],
    out: &mut impl Write,
) -> Result<Written, WriteError> {
    let package = reader.package();
    let mut contents = Contents::default();
    let parts = reader.parts().to_vec();
    for (part, id) in &parts {
        let offset = reader
            .blob_offset(id)
            .ok_or_else(|| WriteError::Input(io::Error::other(format!("{part} has no blob"))))?;
        let data = Data::Input(offset);
        match part {
            Part::Manifest => {
                contents.layer(media::MANIFEST, &[], *id, data);
                add_signatures(&mut contents, package, signatures)?;
            }
            Part::License(license) => contents.layer(
                media::LICENSE,
                &[(annotations::LICENSE, license.as_str())],
                *id,
                data,
            ),
            Part::Tree(facet) => contents.layer(
                media::TREE,
                &[(annotations::FACET, facet.as_str())],
                *id,
                data,
            ),
            Part::ChunkIndex => contents.layer(media::CHUNK_INDEX, &[], *id, data),
            Part::PackTable(facet) => contents.layer(
                media::PACK_TABLE,
                &[(annotations::FACET, facet.as_str())],
                *id,
                data,
            ),
            Part::ChunkPack(facet) => contents.layer(
                media::CHUNK_PACK,
                &[(annotations::FACET, facet.as_str())],
                *id,
                data,
            ),
            // The old signatures are replaced, and the other parts aren't
            // layers.
            _ => {}
        }
    }
    let chunk_index = reader.chunk_index_digest();
    let (image, size) = finish(contents, reader.input_mut(), out)?;
    Ok(Written {
        package,
        image: image.sha256,
        chunk_index,
        size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_blob_that_reads_back_differently_is_refused() {
        let mut tar = TarWriter::new(Vec::new());
        let e =
            copy_blob(&mut tar, "blobs/sha256/x", &BlobId::of(b"abc"), &b"abd"[..]).unwrap_err();
        assert_eq!(
            e.to_string(),
            "blobs/sha256/x changed before it was copied into the file"
        );
        assert!(copy_blob(&mut tar, "a", &BlobId::of(b"abc"), &b"abc"[..]).is_ok());
    }

    struct One(Vec<u8>);

    impl Source for One {
        type Reader = io::Cursor<Vec<u8>>;

        fn open(&mut self, _: &TreePath, _: &File) -> io::Result<Self::Reader> {
            Ok(io::Cursor::new(self.0.clone()))
        }
    }

    #[test]
    fn a_pack_that_fails_while_a_file_is_cut_stops_the_write() {
        let bytes = b"hello".to_vec();
        let d = ordin_tree::file_digests(&bytes[..]).unwrap();
        let tree = Tree::new(vec![ordin_tree::Entry {
            path: "/a".parse().unwrap(),
            kind: Kind::File(File {
                mode: ordin_tree::FILE_MODE,
                owner: ordin_core::Account::root(),
                group: ordin_core::Account::root(),
                size: d.size,
                content: d.content,
                fsverity: d.fsverity,
                xattrs: ordin_tree::Xattrs::new(),
                capabilities: None,
            }),
        }])
        .unwrap();
        // A pack that may hold nothing at all.
        let mut pack = PackBuilder::new(
            "runtime".parse().unwrap(),
            LEVEL,
            NonZeroUsize::MIN,
            0,
            Vec::new(),
        );
        let mut listed = BTreeMap::new();
        fill(
            &mut pack,
            &tree,
            &ChunkParams::DEFAULT,
            &mut One(bytes),
            &mut listed,
        )
        .unwrap();
        // The chunk waits in the batch until the pack is finished.
        let e = pack.finish().err().unwrap();
        assert!(matches!(e, WriteError::PackTooLarge { max: 0, .. }), "{e}");

        // A full batch is compressed while the file is still being cut.
        let mut pack = PackBuilder::new(
            "runtime".parse().unwrap(),
            LEVEL,
            NonZeroUsize::MIN,
            0,
            Vec::new(),
        );
        let params = ChunkParams::new(64, 256, 1024, 256, 1).unwrap();
        let big: Vec<u8> = (0..300_000u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        let d = ordin_tree::file_digests(&big[..]).unwrap();
        let mut tree_entries = tree.entries().to_vec();
        if let Kind::File(f) = &mut tree_entries[0].kind {
            f.size = d.size;
            f.content = d.content;
            f.fsverity = d.fsverity;
        }
        let tree = Tree::new(tree_entries).unwrap();
        let e = fill(&mut pack, &tree, &params, &mut One(big), &mut listed).unwrap_err();
        assert!(matches!(e, WriteError::PackTooLarge { max: 0, .. }), "{e}");
    }

    #[test]
    fn an_image_manifest_a_reader_refuses_is_never_written() {
        assert!(check_image_size(MAX_IMAGE_MANIFEST_SIZE).is_ok());
        let e = check_image_size(MAX_IMAGE_MANIFEST_SIZE + 1).unwrap_err();
        assert_eq!(
            e.to_string(),
            "the image manifest would have 4194305 bytes, more than the 4194304 a registry must accept"
        );
    }

    #[test]
    fn packages_are_written_at_level_19_by_default() {
        let o = Options::default();
        assert_eq!(o.level, 19);
        assert_eq!(
            o.threads,
            std::thread::available_parallelism().unwrap_or(NonZeroUsize::MIN)
        );
    }
}
