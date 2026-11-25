// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Reading a `.ordin` file in place.
//!
//! [`Reader::open`] reads only the small parts: the tar headers, the OCI
//! JSON and the Ordin manifest. It refuses anything the writer wouldn't
//! have written. Every other part is read when it is asked for, within
//! its own limit, and checked against its digests as it is read, so a
//! hostile file can't make the reader hold more than one part at a time.

use std::collections::BTreeMap;
use std::io::{self, ErrorKind, Read, Seek, SeekFrom, Write};

use ordin_core::{Blake3Hasher, Digest, Facet};
use ordin_manifest::Manifest;
use ordin_tree::chunk::{ChunkIndex, ChunkRef};
use ordin_tree::{File, Kind, Tree, TreePath};
use zstd::bulk::Decompressor;
use zstd::zstd_safe::{self, DParameter};

use crate::blob::BlobId;
use crate::error::{Part, ReadError, ReadErrorKind};
use crate::oci::{
    EMPTY_CONFIG, LAYER_TYPES, Layer, OCI_LAYOUT, annotations, read_image_manifest, read_index,
};
use crate::pack::{MAX_CHUNK, MAX_FRAME, MAX_PACK_TABLE_SIZE, PackTable};
use crate::tar::{BLOCK, padding, parse_header};
use ordin_sign::{MAX_SIGNATURE_SIZE, Signature};

/// The most entries an archive may have. A package can't need more: the
/// image manifest is limited to [`MAX_IMAGE_MANIFEST_SIZE`], and every
/// descriptor in it takes more than 200 bytes.
pub const MAX_ENTRIES: usize = 1 << 16;

/// The most bytes `index.json` may have. It lists one manifest, so it is
/// always about 400 bytes.
pub const MAX_INDEX_SIZE: u64 = 4096;

/// The most bytes the image manifest may have: the size every OCI
/// registry must accept.
pub const MAX_IMAGE_MANIFEST_SIZE: u64 = 4 << 20;

/// The most signatures a package may carry.
pub const MAX_SIGNATURES: usize = 64;

/// The most bytes a license text may have.
pub const MAX_LICENSE_TEXT: u64 = 1 << 20;

/// zstd's window limit for decompressing a chunk: 2²⁴ bytes, the longest
/// chunk ([`MAX_CHUNK`]).
const WINDOW_LOG_MAX: u32 = 24;

/// The magic number every zstd frame starts with.
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];

/// Where a tar entry's content is.
#[derive(Clone, Copy, Debug)]
struct Span {
    offset: u64,
    size: u64,
}

/// A blob of the package: its identity and where its content starts.
#[derive(Clone, Copy, Debug)]
struct Blob {
    id: BlobId,
    offset: u64,
}

/// The archive's entries.
#[derive(Debug)]
struct Entries {
    layout: Span,
    index: Span,
    blobs: BTreeMap<String, Span>,
}

fn io_error(part: Part) -> impl FnOnce(io::Error) -> ReadError {
    move |e| {
        let kind = if e.kind() == ErrorKind::UnexpectedEof {
            ReadErrorKind::Truncated
        } else {
            ReadErrorKind::Io(e)
        };
        ReadError::new(part, kind)
    }
}

/// Reads `size` bytes from `offset`. The caller has checked `size`
/// against the part's limit.
fn read_at<R: Read + Seek>(
    input: &mut R,
    offset: u64,
    size: u64,
    part: &Part,
) -> Result<Vec<u8>, ReadError> {
    let len = usize::try_from(size).map_err(|_| {
        ReadError::new(
            part.clone(),
            ReadErrorKind::TooLarge {
                size,
                max: usize::MAX as u64,
            },
        )
    })?;
    input
        .seek(SeekFrom::Start(offset))
        .map_err(io_error(part.clone()))?;
    let mut bytes = vec![0; len];
    input
        .read_exact(&mut bytes)
        .map_err(io_error(part.clone()))?;
    Ok(bytes)
}

fn is_blob_name(name: &str) -> bool {
    name.strip_prefix("blobs/sha256/").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// Walks the tar headers without reading the entries' content, and
/// checks the archive's form: `oci-layout`, `index.json`, then blobs in
/// name order, each header exactly as the writer writes it, zero padding,
/// and two zero blocks at the very end.
fn walk<R: Read + Seek>(input: &mut R, len: u64, max_entries: usize) -> Result<Entries, ReadError> {
    let error = |kind| ReadError::new(Part::Archive, kind);
    let mut block = [0; 512];
    let mut read_block = |input: &mut R, at: u64| -> Result<[u8; 512], ReadError> {
        input
            .seek(SeekFrom::Start(at))
            .map_err(io_error(Part::Archive))?;
        input
            .read_exact(&mut block)
            .map_err(io_error(Part::Archive))?;
        Ok(block)
    };
    let mut layout = None;
    let mut index = None;
    let mut blobs = BTreeMap::new();
    let mut last_blob: Option<String> = None;
    let mut count = 0;
    let mut at = 0;
    // Reading past the end of the input fails with Truncated, so an
    // archive cut short anywhere is refused by the read that reaches its
    // end.
    loop {
        let header = read_block(input, at)?;
        if header == [0; 512] {
            if read_block(input, at + BLOCK)? != [0; 512] || at + 2 * BLOCK != len {
                return Err(error(ReadErrorKind::End { at }));
            }
            break;
        }
        let (name, size) = parse_header(&header).ok_or(error(ReadErrorKind::Header { at }))?;
        if count == max_entries {
            return Err(error(ReadErrorKind::TooManyEntries { max: max_entries }));
        }
        let unexpected = |expected| {
            error(ReadErrorKind::Entry {
                at,
                name: name.clone(),
                expected,
            })
        };
        match count {
            0 if name != "oci-layout" => return Err(unexpected("oci-layout")),
            1 if name != "index.json" => return Err(unexpected("index.json")),
            0 | 1 => {}
            _ if !is_blob_name(&name) => {
                return Err(unexpected(
                    "a blob, blobs/sha256/ and 64 lowercase hex digits",
                ));
            }
            _ if last_blob.as_ref().is_some_and(|last| *last >= name) => {
                return Err(unexpected("a blob named after the one before it"));
            }
            _ => {}
        }
        let offset = at + BLOCK;
        // A size has at most eleven octal digits, so none of this can
        // overflow.
        let end = offset + size;
        let pad = padding(size);
        let zeros = read_at(input, end, pad, &Part::Archive)?;
        if zeros.iter().any(|&b| b != 0) {
            return Err(error(ReadErrorKind::Padding { at: end }));
        }
        let span = Span { offset, size };
        match count {
            0 => layout = Some(span),
            1 => index = Some(span),
            _ => {
                blobs.insert(name.clone(), span);
                last_blob = Some(name);
            }
        }
        count += 1;
        at = end + pad;
    }
    Ok(Entries {
        layout: layout.ok_or(error(ReadErrorKind::MissingEntry("oci-layout")))?,
        index: index.ok_or(error(ReadErrorKind::MissingEntry("index.json")))?,
        blobs,
    })
}

/// Reads a whole tar entry of at most `max` bytes.
fn read_entry<R: Read + Seek>(
    input: &mut R,
    span: Span,
    max: u64,
    part: &Part,
) -> Result<Vec<u8>, ReadError> {
    if span.size > max {
        return Err(ReadError::new(
            part.clone(),
            ReadErrorKind::TooLarge {
                size: span.size,
                max,
            },
        ));
    }
    read_at(input, span.offset, span.size, part)
}

/// Reads a blob of at most `max` bytes and checks both its digests.
fn read_blob<R: Read + Seek>(
    input: &mut R,
    blob: Blob,
    max: u64,
    part: &Part,
) -> Result<Vec<u8>, ReadError> {
    let bytes = read_entry(
        input,
        Span {
            offset: blob.offset,
            size: blob.id.size,
        },
        max,
        part,
    )?;
    let read = BlobId::of(&bytes);
    if read != blob.id {
        return Err(ReadError::new(
            part.clone(),
            ReadErrorKind::Corrupt {
                recorded: blob.id.blake3,
                read: read.blake3,
            },
        ));
    }
    Ok(bytes)
}

/// The layers, sorted out by part.
#[derive(Default)]
struct Layers {
    manifest: Option<BlobId>,
    signatures: BTreeMap<String, BlobId>,
    licenses: BTreeMap<String, BlobId>,
    trees: BTreeMap<Facet, BlobId>,
    chunk_index: Option<BlobId>,
    tables: BTreeMap<Facet, BlobId>,
    packs: BTreeMap<Facet, BlobId>,
    parts: Vec<(Part, BlobId)>,
}

/// Sorts the layers into parts, checking their order and annotations:
/// the manifest, signatures by key, license texts by ID, trees by facet,
/// the chunk index, pack tables by facet, then chunk packs by facet.
fn sort_layers(layers: Vec<Layer>) -> Result<Layers, ReadError> {
    let error = |kind| ReadError::new(Part::ImageManifest, kind);
    let mut sorted = Layers::default();
    let mut last: Option<(usize, String)> = None;
    for (index, layer) in layers.into_iter().enumerate() {
        let stage = LAYER_TYPES
            .iter()
            .position(|t| *t == layer.media_type)
            .unwrap_or(LAYER_TYPES.len());
        let key = match stage {
            1 => Some(annotations::KEY),
            2 => Some(annotations::LICENSE),
            3 | 5 | 6 => Some(annotations::FACET),
            _ => None,
        };
        let value = key.and_then(|k| layer.annotations.get(k));
        let annotated = match key {
            Some(_) => layer.annotations.len() == 1 && value.is_some(),
            None => layer.annotations.is_empty(),
        };
        if !annotated {
            return Err(error(ReadErrorKind::Malformed(format!(
                "layer {index} ({}) must have {}",
                layer.media_type,
                key.map_or(
                    "no annotations but com.ordinpm.blake3".to_owned(),
                    |k| format!("the annotation {k} and com.ordinpm.blake3, and no others")
                )
            ))));
        }
        let value = value.cloned().unwrap_or_default();
        let in_order = match &last {
            None => stage == 0,
            Some((s, _)) if *s < stage => true,
            Some((s, v)) => *s == stage && key.is_some() && *v < value,
        };
        if !in_order {
            return Err(error(ReadErrorKind::LayerOrder {
                index,
                media_type: layer.media_type,
            }));
        }
        let facet = || {
            value.parse::<Facet>().map_err(|_| {
                error(ReadErrorKind::Malformed(format!(
                    "layer {index} names the facet {value:?}, which isn't a facet name"
                )))
            })
        };
        let id = layer.id;
        let part = match stage {
            0 => {
                sorted.manifest = Some(id);
                Part::Manifest
            }
            1 => {
                if sorted.signatures.len() == MAX_SIGNATURES {
                    return Err(error(ReadErrorKind::TooManySignatures {
                        max: MAX_SIGNATURES,
                    }));
                }
                sorted.signatures.insert(value.clone(), id);
                Part::Signature(value.clone())
            }
            2 => {
                sorted.licenses.insert(value.clone(), id);
                Part::License(value.clone())
            }
            3 => {
                let f = facet()?;
                sorted.trees.insert(f.clone(), id);
                Part::Tree(f)
            }
            4 => {
                sorted.chunk_index = Some(id);
                Part::ChunkIndex
            }
            5 => {
                let f = facet()?;
                sorted.tables.insert(f.clone(), id);
                Part::PackTable(f)
            }
            _ => {
                let f = facet()?;
                sorted.packs.insert(f.clone(), id);
                Part::ChunkPack(f)
            }
        };
        sorted.parts.push((part, id));
        last = Some((stage, value));
    }
    Ok(sorted)
}

/// Checks that `found` has a part for each facet the manifest lists, and
/// no others.
fn same_facets(
    manifest: &Manifest,
    found: &BTreeMap<Facet, BlobId>,
    what: &str,
    part: fn(Facet) -> Part,
) -> Result<(), ReadError> {
    let disagrees = |facet: &Facet, text: String| {
        ReadError::new(part(facet.clone()), ReadErrorKind::Disagrees(text))
    };
    if let Some(facet) = manifest.facets.keys().find(|f| !found.contains_key(*f)) {
        return Err(disagrees(
            facet,
            format!("the manifest lists facet {facet}, but the package has no {what} for it"),
        ));
    }
    if let Some(facet) = found.keys().find(|f| !manifest.facets.contains_key(*f)) {
        return Err(disagrees(
            facet,
            format!("the package has a {what} for facet {facet}, which the manifest doesn't list"),
        ));
    }
    Ok(())
}

/// Checks the layers against the manifest: a tree, pack table and chunk
/// pack for every facet it lists, each tree the one it records, and a
/// text for every license ID it records, each the one it records.
fn check_against(manifest: &Manifest, layers: &Layers) -> Result<(), ReadError> {
    same_facets(manifest, &layers.trees, "tree", Part::Tree)?;
    same_facets(manifest, &layers.tables, "pack table", Part::PackTable)?;
    same_facets(manifest, &layers.packs, "chunk pack", Part::ChunkPack)?;
    for (facet, entry) in &manifest.facets {
        if let Some(tree) = layers.trees.get(facet).filter(|t| t.blake3 != entry.tree) {
            return Err(ReadError::new(
                Part::Tree(facet.clone()),
                ReadErrorKind::Disagrees(format!(
                    "the manifest records tree {}, but the layer is {}",
                    entry.tree, tree.blake3
                )),
            ));
        }
    }
    let texts = &manifest.license.texts;
    let disagrees = |id: &String, text| {
        ReadError::new(Part::License(id.clone()), ReadErrorKind::Disagrees(text))
    };
    if let Some(id) = texts.keys().find(|id| !layers.licenses.contains_key(*id)) {
        return Err(disagrees(
            id,
            format!("the manifest records a text for {id}, but the package has none"),
        ));
    }
    for (id, blob) in &layers.licenses {
        match texts.get(id) {
            None => {
                return Err(disagrees(
                    id,
                    format!("the package has a text for {id}, which the manifest doesn't record"),
                ));
            }
            Some(recorded) if *recorded != blob.blake3 => {
                return Err(disagrees(
                    id,
                    format!(
                        "the manifest records the text {recorded}, but the layer is {}",
                        blob.blake3
                    ),
                ));
            }
            Some(_) => {}
        }
    }
    Ok(())
}

/// Places every blob a descriptor names in the archive, and refuses a
/// blob that is missing, has another size, is named with different
/// digests, or that nothing names.
fn place(entries: &Entries, named: &[(Part, BlobId)]) -> Result<BTreeMap<String, Blob>, ReadError> {
    let mut placed: BTreeMap<String, Blob> = BTreeMap::new();
    for (part, id) in named {
        let blob = place_one(entries, part, *id)?;
        let path = id.path();
        if placed.get(&path).is_some_and(|b| b.id != *id) {
            return Err(ReadError::new(
                part.clone(),
                ReadErrorKind::Inconsistent { path },
            ));
        }
        placed.insert(path, blob);
    }
    if let Some(path) = entries.blobs.keys().find(|p| !placed.contains_key(*p)) {
        return Err(ReadError::new(
            Part::Archive,
            ReadErrorKind::UnusedBlob { path: path.clone() },
        ));
    }
    Ok(placed)
}

/// Decompresses one chunk's frame into exactly `length` bytes.
fn decompress(d: &mut Decompressor<'_>, frame: &[u8], length: u64) -> Result<Vec<u8>, String> {
    if frame.get(..4) != Some(ZSTD_MAGIC.as_slice()) {
        return Err("it doesn't start with zstd's magic number".to_owned());
    }
    // The frame header descriptor: bit 2 is the checksum flag, and bits 0
    // and 1 the dictionary ID's size.
    if frame.get(4).is_none_or(|d| d & 0b111 != 0) {
        return Err("it has a checksum or a dictionary ID".to_owned());
    }
    if zstd_safe::find_frame_compressed_size(frame).ok() != Some(frame.len()) {
        return Err("it isn't exactly one frame".to_owned());
    }
    if zstd_safe::get_frame_content_size(frame).ok().flatten() != Some(length) {
        return Err(format!(
            "its header doesn't record the chunk's {length} bytes"
        ));
    }
    let capacity = usize::try_from(length).map_err(|_| "the chunk is too long".to_owned())?;
    let mut out = Vec::with_capacity(capacity);
    d.decompress_to_buffer(frame, &mut out)
        .map_err(|e| e.to_string())?;
    if out.len() != capacity {
        return Err(format!("it gave {} bytes instead of {length}", out.len()));
    }
    Ok(out)
}

/// A `.ordin` file opened for reading.
///
/// Opening reads and checks the archive, the OCI JSON and the manifest.
/// The other parts are read by the methods below, each when it is asked
/// for: nothing larger than one part is held at a time.
pub struct Reader<R> {
    input: R,
    manifest: Manifest,
    signatures: Vec<Signature>,
    package: Digest,
    image: Digest,
    parts: Vec<(Part, BlobId)>,
    blobs: BTreeMap<String, Blob>,
    licenses: BTreeMap<String, BlobId>,
    trees: BTreeMap<Facet, BlobId>,
    chunk_index: BlobId,
    tables: BTreeMap<Facet, BlobId>,
    packs: BTreeMap<Facet, BlobId>,
    decompressor: Option<Decompressor<'static>>,
}

impl<R> std::fmt::Debug for Reader<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reader")
            .field("package", &self.package)
            .field("image", &self.image)
            .finish_non_exhaustive()
    }
}

/// Reads each signature layer and checks that it verifies, is by the key
/// its annotation names, and is for this package.
fn read_signatures<R: Read + Seek>(
    input: &mut R,
    entries: &Entries,
    layers: &Layers,
    package: Digest,
) -> Result<Vec<Signature>, ReadError> {
    let mut signatures = Vec::with_capacity(layers.signatures.len());
    for (key, id) in &layers.signatures {
        let part = Part::Signature(key.clone());
        let blob = place_one(entries, &part, *id)?;
        let bytes = read_blob(input, blob, MAX_SIGNATURE_SIZE as u64, &part)?;
        let signature = Signature::from_bytes(&bytes)
            .map_err(|e| ReadError::new(part.clone(), ReadErrorKind::Signature(e)))?;
        if signature.key().to_string() != *key {
            return Err(ReadError::new(
                part,
                ReadErrorKind::Disagrees(format!(
                    "the layer is annotated with {key}, but the signature is by {}",
                    signature.key()
                )),
            ));
        }
        if signature.package() != package {
            return Err(ReadError::new(
                part,
                ReadErrorKind::Disagrees(format!(
                    "the signature is for package {}, not this package, {package}",
                    signature.package()
                )),
            ));
        }
        signatures.push(signature);
    }
    Ok(signatures)
}

impl<R: Read + Seek> Reader<R> {
    /// Opens a `.ordin` file. Only the tar headers, `oci-layout`,
    /// `index.json`, the image manifest, the config and the Ordin manifest
    /// are read.
    ///
    /// # Errors
    ///
    /// Anything the writer wouldn't have written: a tar header, entry
    /// order, padding or ending other than the format's; OCI JSON other
    /// than exactly what the writer writes; a layer out of order, unknown
    /// or with other annotations; a blob that is missing, unused, of
    /// another size or with other digests; a manifest that breaks a rule;
    /// layers that don't match the manifest's facets and license texts.
    /// Also any error reading the input.
    pub fn open(mut input: R) -> Result<Self, ReadError> {
        let len = input
            .seek(SeekFrom::End(0))
            .map_err(io_error(Part::Archive))?;
        let entries = walk(&mut input, len, MAX_ENTRIES)?;

        let layout = read_entry(
            &mut input,
            entries.layout,
            OCI_LAYOUT.len() as u64,
            &Part::OciLayout,
        )?;
        if layout != OCI_LAYOUT {
            return Err(ReadError::new(Part::OciLayout, ReadErrorKind::NotFixed));
        }
        let index = read_entry(&mut input, entries.index, MAX_INDEX_SIZE, &Part::Index)?;
        let image = read_index(&index).map_err(|k| ReadError::new(Part::Index, k))?;

        // The image manifest is placed on its own first: its layers say
        // where everything else is.
        let image_blob = place_one(&entries, &Part::ImageManifest, image)?;
        let image_bytes = read_blob(
            &mut input,
            image_blob,
            MAX_IMAGE_MANIFEST_SIZE,
            &Part::ImageManifest,
        )?;
        let (config, layers) = read_image_manifest(&image_bytes)
            .map_err(|k| ReadError::new(Part::ImageManifest, k))?;
        if config != BlobId::of(EMPTY_CONFIG) {
            return Err(ReadError::new(Part::Config, ReadErrorKind::NotFixed));
        }
        let layers = sort_layers(layers)?;
        let manifest_id = layers.manifest.ok_or(ReadError::new(
            Part::ImageManifest,
            ReadErrorKind::MissingLayer("manifest"),
        ))?;
        let chunk_index = layers.chunk_index.ok_or(ReadError::new(
            Part::ImageManifest,
            ReadErrorKind::MissingLayer("chunk index"),
        ))?;

        let mut named = vec![(Part::ImageManifest, image), (Part::Config, config)];
        named.extend(layers.parts.iter().cloned());
        let blobs = place(&entries, &named)?;
        let config_blob = place_one(&entries, &Part::Config, config)?;
        read_blob(&mut input, config_blob, config.size, &Part::Config)?;

        let manifest_blob = place_one(&entries, &Part::Manifest, manifest_id)?;
        let bytes = read_blob(
            &mut input,
            manifest_blob,
            ordin_manifest::MAX_SIZE as u64,
            &Part::Manifest,
        )?;
        let (manifest, package) = Manifest::from_signed_bytes(&bytes)
            .map_err(|e| ReadError::new(Part::Manifest, ReadErrorKind::Manifest(Box::new(e))))?;
        check_against(&manifest, &layers)?;
        let signatures = read_signatures(&mut input, &entries, &layers, package)?;

        Ok(Self {
            input,
            manifest,
            signatures,
            package,
            image: image.sha256,
            parts: layers.parts,
            blobs,
            licenses: layers.licenses,
            trees: layers.trees,
            chunk_index,
            tables: layers.tables,
            packs: layers.packs,
            decompressor: None,
        })
    }

    /// The manifest.
    #[must_use]
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// The signatures, by key. Each verifies and is for this package;
    /// whether its key is trusted is the caller's question.
    #[must_use]
    pub fn signatures(&self) -> &[Signature] {
        &self.signatures
    }

    /// The package's identity: the BLAKE3 digest of its manifest.
    #[must_use]
    pub fn package(&self) -> Digest {
        self.package
    }

    /// The SHA-256 digest of the OCI image manifest, as a registry names
    /// it.
    #[must_use]
    pub fn image(&self) -> Digest {
        self.image
    }

    /// Where the blob `id` starts in the input, if the package has it.
    pub(crate) fn blob_offset(&self, id: &BlobId) -> Option<u64> {
        self.blobs.get(&id.path()).map(|b| b.offset)
    }

    /// The chunk index's identity, as its descriptor records it.
    pub(crate) fn chunk_index_digest(&self) -> Digest {
        self.chunk_index.blake3
    }

    pub(crate) fn input_mut(&mut self) -> &mut R {
        &mut self.input
    }

    /// The layers in order, each with the identity its descriptor
    /// records.
    #[must_use]
    pub fn parts(&self) -> &[(Part, BlobId)] {
        &self.parts
    }

    fn blob(&self, id: Option<&BlobId>, part: &Part) -> Result<Blob, ReadError> {
        id.and_then(|id| self.blobs.get(&id.path()))
            .copied()
            .ok_or_else(|| ReadError::new(part.clone(), ReadErrorKind::NoSuchPart))
    }

    /// The text of the license `id`, at most [`MAX_LICENSE_TEXT`] bytes.
    ///
    /// # Errors
    ///
    /// The package has no text for `id`, the text is too large or isn't
    /// the one recorded, or reading failed.
    pub fn license_text(&mut self, id: &str) -> Result<Vec<u8>, ReadError> {
        let part = Part::License(id.to_owned());
        let blob = self.blob(self.licenses.get(id), &part)?;
        read_blob(&mut self.input, blob, MAX_LICENSE_TEXT, &part)
    }

    /// The tree of `facet`.
    ///
    /// # Errors
    ///
    /// The package has no such facet, the tree isn't the one the manifest
    /// records or breaks a rule, its files' sizes don't add up to the size
    /// the manifest records, or reading failed.
    pub fn tree(&mut self, facet: &Facet) -> Result<Tree, ReadError> {
        let part = Part::Tree(facet.clone());
        let blob = self.blob(self.trees.get(facet), &part)?;
        let bytes = read_blob(&mut self.input, blob, ordin_tree::MAX_SIZE as u64, &part)?;
        let (tree, _) = Tree::from_canonical_bytes(&bytes)
            .map_err(|e| ReadError::new(part.clone(), ReadErrorKind::Tree(Box::new(e))))?;
        let size = tree
            .entries()
            .iter()
            .filter_map(|e| match &e.kind {
                Kind::File(f) => Some(f.size),
                _ => None,
            })
            .fold(0, u64::saturating_add);
        let recorded = self.manifest.facets.get(facet).map_or(0, |f| f.size);
        if size != recorded {
            return Err(ReadError::new(
                part,
                ReadErrorKind::Disagrees(format!(
                    "the manifest records {recorded} bytes of file content, but the tree has {size}"
                )),
            ));
        }
        Ok(tree)
    }

    /// The chunk index.
    ///
    /// # Errors
    ///
    /// The index breaks a rule, or reading failed.
    pub fn chunk_index(&mut self) -> Result<ChunkIndex, ReadError> {
        let part = Part::ChunkIndex;
        let blob = self.blob(Some(&self.chunk_index), &part)?;
        let bytes = read_blob(
            &mut self.input,
            blob,
            ordin_tree::chunk::MAX_SIZE as u64,
            &part,
        )?;
        let (index, _) = ChunkIndex::from_canonical_bytes(&bytes)
            .map_err(|e| ReadError::new(part, ReadErrorKind::ChunkIndex(Box::new(e))))?;
        Ok(index)
    }

    /// The pack table of `facet`.
    ///
    /// # Errors
    ///
    /// The package has no such facet, the table breaks a rule or doesn't
    /// end where the facet's chunk pack does, or reading failed.
    pub fn pack_table(&mut self, facet: &Facet) -> Result<PackTable, ReadError> {
        let part = Part::PackTable(facet.clone());
        let blob = self.blob(self.tables.get(facet), &part)?;
        let pack = self.blob(self.packs.get(facet), &part)?;
        let bytes = read_blob(&mut self.input, blob, MAX_PACK_TABLE_SIZE as u64, &part)?;
        PackTable::from_canonical_bytes(&bytes, pack.id.size)
            .map_err(|e| ReadError::new(part, ReadErrorKind::PackTable(e)))
    }

    /// One chunk of `facet`, found with its pack `table`, decompressed and
    /// checked against its digest.
    ///
    /// # Errors
    ///
    /// The package has no such facet; the chunk is longer than any chunk
    /// can be; the table doesn't list it or places it outside the pack;
    /// its frame isn't one zstd frame of exactly its length without a
    /// checksum or dictionary; it doesn't decompress to its digest; or
    /// reading failed.
    pub fn chunk(
        &mut self,
        facet: &Facet,
        table: &PackTable,
        chunk: &ChunkRef,
    ) -> Result<Vec<u8>, ReadError> {
        let part = Part::Chunk {
            facet: facet.clone(),
            digest: chunk.digest,
        };
        let error = |kind| ReadError::new(part.clone(), kind);
        let pack = self.blob(self.packs.get(facet), &part)?;
        if chunk.length > MAX_CHUNK {
            return Err(error(ReadErrorKind::ChunkTooLong {
                length: chunk.length,
                max: MAX_CHUNK,
            }));
        }
        let entry = table
            .find(&chunk.digest)
            .ok_or_else(|| error(ReadErrorKind::NotInPack))?;
        let inside = entry
            .offset
            .checked_add(entry.length)
            .is_some_and(|end| end <= pack.id.size);
        if entry.length > MAX_FRAME || !inside {
            return Err(error(ReadErrorKind::OutsidePack {
                offset: entry.offset,
                length: entry.length,
                pack: pack.id.size,
            }));
        }
        let frame = read_at(
            &mut self.input,
            pack.offset + entry.offset,
            entry.length,
            &part,
        )?;
        let d = match &mut self.decompressor {
            Some(d) => d,
            empty => {
                let mut d = Decompressor::new().map_err(|e| error(ReadErrorKind::Io(e)))?;
                d.set_parameter(DParameter::WindowLogMax(WINDOW_LOG_MAX))
                    .map_err(|e| error(ReadErrorKind::Io(e)))?;
                empty.insert(d)
            }
        };
        let bytes =
            decompress(d, &frame, chunk.length).map_err(|e| error(ReadErrorKind::Frame(e)))?;
        let read = Digest::blake3(&bytes);
        if read != chunk.digest {
            return Err(error(ReadErrorKind::Corrupt {
                recorded: chunk.digest,
                read,
            }));
        }
        Ok(bytes)
    }

    /// Writes the content of the file `path` of `facet` to `out`, chunk by
    /// chunk, each chunk checked as it is read. The chunks come from the
    /// chunk `index` and the facet's pack `table`. The whole content is
    /// then checked against `file`, the tree's record.
    ///
    /// Each chunk written was checked against its own digest. If the
    /// content as a whole isn't the file, the error comes after some of it
    /// was written, so write to somewhere that can be thrown away.
    ///
    /// # Errors
    ///
    /// The index doesn't list a file it must or lists it with another
    /// size; any error from [`chunk`](Self::chunk); the content isn't the
    /// size and digest `file` records; or writing to `out` failed. Nothing
    /// beyond `file`'s size is ever written.
    pub fn read_file(
        &mut self,
        facet: &Facet,
        table: &PackTable,
        index: &ChunkIndex,
        path: &TreePath,
        file: &File,
        out: &mut impl Write,
    ) -> Result<(), ReadError> {
        let part = || Part::File {
            facet: facet.clone(),
            path: path.clone(),
        };
        let chunks = index
            .chunks_of(&file.content, file.size)
            .map_err(|e| ReadError::new(part(), ReadErrorKind::ChunkIndex(Box::new(e))))?;
        let mut hasher = Blake3Hasher::default();
        let mut size: u64 = 0;
        let wrong = |read_size, read| {
            ReadError::new(
                part(),
                ReadErrorKind::Content {
                    recorded_size: file.size,
                    recorded: file.content,
                    read_size,
                    read,
                },
            )
        };
        for chunk in &chunks {
            let bytes = self.chunk(facet, table, chunk)?;
            hasher.update(&bytes);
            size = size.saturating_add(chunk.length);
            if size > file.size {
                return Err(wrong(size, hasher.finish()));
            }
            out.write_all(&bytes)
                .map_err(|e| ReadError::new(part(), ReadErrorKind::Output(e)))?;
        }
        let read = hasher.finish();
        if size != file.size || read != file.content {
            return Err(wrong(size, read));
        }
        Ok(())
    }
}

/// Places one blob a descriptor names.
fn place_one(entries: &Entries, part: &Part, id: BlobId) -> Result<Blob, ReadError> {
    let path = id.path();
    let span = entries.blobs.get(&path).ok_or_else(|| {
        ReadError::new(
            part.clone(),
            ReadErrorKind::MissingBlob { path: path.clone() },
        )
    })?;
    if span.size != id.size {
        return Err(ReadError::new(
            part.clone(),
            ReadErrorKind::Size {
                recorded: id.size,
                actual: span.size,
            },
        ));
    }
    Ok(Blob {
        id,
        offset: span.offset,
    })
}

impl<R> Reader<R> {
    /// The facets, in order.
    pub fn facets(&self) -> impl Iterator<Item = &Facet> {
        self.trees.keys()
    }

    /// The license IDs with texts, in order.
    pub fn license_ids(&self) -> impl Iterator<Item = &str> {
        self.licenses.keys().map(String::as_str)
    }

    /// Gives back the input.
    pub fn into_inner(self) -> R {
        self.input
    }
}

mod verify;

pub use verify::{Verified, VerifiedFacet};

#[cfg(test)]
mod tests;
