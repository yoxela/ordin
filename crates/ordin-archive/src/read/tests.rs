// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Reading `.ordin` files: what the writer writes reads back, and
//! anything else is refused with the part that failed.

use std::collections::BTreeMap;
use std::io::Cursor;

use ordin_core::Account;
use ordin_tree::chunk::{ChunkParams, IndexFile};
use ordin_tree::{DIR_MODE, Dir, Entry, FILE_MODE, Xattrs, file_digests};
use proptest::prelude::*;

use super::*;
use crate::PackTableErrorKind;
use crate::error::PackTableError;
use crate::error::WriteError;
use crate::oci::{image_manifest, index, media};
use crate::pack::PackEntry;
use crate::tar::TarWriter;
use crate::write::{Options, Package, Source, Written, rewrite, write};
use ordin_sign::{PublicKey, SecretKey};

const MIT: &[u8] = b"Permission is hereby granted, free of charge...\n";

fn f(name: &str) -> Facet {
    name.parse().unwrap()
}

fn p(path: &str) -> TreePath {
    path.parse().unwrap()
}

fn dir(path: &str) -> Entry {
    Entry {
        path: p(path),
        kind: Kind::Dir(Dir {
            mode: DIR_MODE,
            owner: Account::root(),
            group: Account::root(),
            xattrs: Xattrs::new(),
        }),
    }
}

fn file_record(bytes: &[u8]) -> File {
    let d = file_digests(bytes).unwrap();
    File {
        mode: FILE_MODE,
        owner: Account::root(),
        group: Account::root(),
        size: d.size,
        content: d.content,
        fsverity: d.fsverity,
        xattrs: Xattrs::new(),
        capabilities: None,
    }
}

fn file(path: &str, bytes: &[u8]) -> Entry {
    Entry {
        path: p(path),
        kind: Kind::File(file_record(bytes)),
    }
}

/// Small chunks, so a few KiB give many.
fn params() -> ChunkParams {
    ChunkParams::new(64, 256, 1024, 256, 1).unwrap()
}

/// Bytes that don't repeat, from a fixed seed.
fn noise(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x.to_le_bytes()[0]
        })
        .collect()
}

struct Files(BTreeMap<String, Vec<u8>>);

impl Source for Files {
    type Reader = Cursor<Vec<u8>>;

    fn open(&mut self, path: &TreePath, _: &File) -> io::Result<Self::Reader> {
        Ok(Cursor::new(
            self.0.get(path.as_str()).cloned().unwrap_or_default(),
        ))
    }
}

fn size_of(tree: &Tree) -> u64 {
    tree.entries()
        .iter()
        .map(|e| match &e.kind {
            Kind::File(f) => f.size,
            _ => 0,
        })
        .sum()
}

/// A manifest for these facets (tree digest and size) and license texts.
fn manifest(facets: &[(Facet, Digest, u64)], texts: &[(&str, Digest)]) -> Manifest {
    let facets: Vec<String> = facets
        .iter()
        .map(|(facet, tree, size)| format!(r#""{facet}":{{"tree":"{tree}","size":{size}}}"#))
        .collect();
    let license = if texts.is_empty() {
        r#"{"spdx":"NOASSERTION"}"#.to_owned()
    } else {
        let spdx: Vec<&str> = texts.iter().map(|(id, _)| *id).collect();
        let texts: Vec<String> = texts
            .iter()
            .map(|(id, d)| format!(r#""{id}":"{d}""#))
            .collect();
        format!(
            r#"{{"spdx":"{}","texts":{{{}}}}}"#,
            spdx.join(" AND "),
            texts.join(",")
        )
    };
    Manifest::from_json(&format!(
        r#"{{"ordin":1,"name":"hello","version":{{"upstream":"2.12","release":"1"}},"kind":"base","arch":"x86_64","summary":"Prints a friendly greeting","license":{license},"facets":{{{}}}}}"#,
        facets.join(",")
    ))
    .unwrap()
}

/// A package to write.
struct Sample {
    trees: BTreeMap<Facet, Tree>,
    licenses: BTreeMap<String, Vec<u8>>,
    files: BTreeMap<String, Vec<u8>>,
}

impl Sample {
    /// A runtime and a doc facet. The doc facet shares a large file with
    /// the runtime, and the runtime has an empty file.
    fn new() -> Self {
        let hello = b"#!/bin/sh\necho hello\n".to_vec();
        let half = noise(1, 3000);
        let big = [half.clone(), half].concat();
        let readme = b"Says hello.\n".to_vec();
        let files = BTreeMap::from([
            ("/usr/bin/empty".to_owned(), Vec::new()),
            ("/usr/bin/hello".to_owned(), hello.clone()),
            ("/usr/lib/big".to_owned(), big.clone()),
            ("/usr/share/doc/README".to_owned(), readme.clone()),
            ("/usr/share/doc/big".to_owned(), big.clone()),
        ]);
        let runtime = Tree::new(vec![
            dir("/usr"),
            dir("/usr/bin"),
            file("/usr/bin/empty", b""),
            file("/usr/bin/hello", &hello),
            dir("/usr/lib"),
            file("/usr/lib/big", &big),
        ])
        .unwrap();
        let doc = Tree::new(vec![
            dir("/usr"),
            dir("/usr/share"),
            dir("/usr/share/doc"),
            file("/usr/share/doc/README", &readme),
            file("/usr/share/doc/big", &big),
        ])
        .unwrap();
        Self {
            trees: BTreeMap::from([(f("doc"), doc), (f("runtime"), runtime)]),
            licenses: BTreeMap::from([("MIT".to_owned(), MIT.to_vec())]),
            files,
        }
    }

    /// One facet of two small files, so every byte can be changed in
    /// turn quickly.
    fn tiny() -> Self {
        let hello = b"echo hello\n".to_vec();
        let files = BTreeMap::from([
            ("/a".to_owned(), hello.clone()),
            ("/b".to_owned(), Vec::new()),
        ]);
        let tree = Tree::new(vec![file("/a", &hello), file("/b", b"")]).unwrap();
        Self {
            trees: BTreeMap::from([(f("runtime"), tree)]),
            licenses: BTreeMap::from([("MIT".to_owned(), MIT.to_vec())]),
            files,
        }
    }

    fn facets(&self) -> Vec<(Facet, Digest, u64)> {
        self.trees
            .iter()
            .map(|(facet, tree)| (facet.clone(), tree.digest().unwrap(), size_of(tree)))
            .collect()
    }

    fn texts(&self) -> Vec<(&str, Digest)> {
        self.licenses
            .iter()
            .map(|(id, text)| (id.as_str(), Digest::blake3(text)))
            .collect()
    }

    fn manifest(&self) -> Manifest {
        manifest(&self.facets(), &self.texts())
    }

    fn write(&self) -> (Vec<u8>, Written) {
        self.write_signed(&[]).unwrap()
    }

    fn write_signed(&self, signatures: &[Signature]) -> Result<(Vec<u8>, Written), WriteError> {
        let manifest = self.manifest();
        let package = Package {
            manifest: &manifest,
            trees: &self.trees,
            licenses: &self.licenses,
            chunking: params(),
            signatures,
        };
        let spool = tempfile::tempdir().unwrap();
        let mut out = Vec::new();
        let written = write(
            &package,
            &mut Files(self.files.clone()),
            &Options {
                level: 3,
                threads: std::num::NonZeroUsize::MIN,
            },
            spool.path(),
            &mut out,
        )?;
        Ok((out, written))
    }

    /// The package's identity.
    fn package(&self) -> Digest {
        Digest::blake3(&self.manifest().to_canonical_bytes().unwrap())
    }
}

fn sample_file() -> Vec<u8> {
    Sample::new().write().0
}

fn open(bytes: Vec<u8>) -> Result<Reader<Cursor<Vec<u8>>>, ReadError> {
    Reader::open(Cursor::new(bytes))
}

/// The part and kind of the error opening `bytes` gives.
fn refused(bytes: Vec<u8>) -> (Part, ReadErrorKind) {
    let e = open(bytes).unwrap_err();
    let ReadError(failed) = e;
    (failed.part, failed.kind)
}

/// Everything a package holds, read through the reader.
#[derive(Debug, PartialEq, Eq)]
struct Everything {
    package: Digest,
    licenses: Vec<Vec<u8>>,
    trees: Vec<Tree>,
    index: ChunkIndex,
    tables: Vec<PackTable>,
    files: Vec<Vec<u8>>,
}

fn read_all(bytes: Vec<u8>) -> Result<Everything, ReadError> {
    let mut r = open(bytes)?;
    let ids: Vec<String> = r.license_ids().map(str::to_owned).collect();
    let licenses = ids
        .iter()
        .map(|id| r.license_text(id))
        .collect::<Result<_, _>>()?;
    let index = r.chunk_index()?;
    let facets: Vec<Facet> = r.facets().cloned().collect();
    let (mut trees, mut tables, mut files) = (Vec::new(), Vec::new(), Vec::new());
    for facet in &facets {
        let tree = r.tree(facet)?;
        let table = r.pack_table(facet)?;
        for entry in tree.entries() {
            if let Kind::File(file) = &entry.kind {
                let mut out = Vec::new();
                r.read_file(facet, &table, &index, &entry.path, file, &mut out)?;
                files.push(out);
            }
        }
        trees.push(tree);
        tables.push(table);
    }
    Ok(Everything {
        package: r.package(),
        licenses,
        trees,
        index,
        tables,
        files,
    })
}

/// A tar archive of these entries, in this order.
fn tar_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut tar = TarWriter::new(Vec::new());
    for (name, bytes) in entries {
        tar.entry(name, bytes.len() as u64, &mut &bytes[..])
            .unwrap();
    }
    tar.finish().unwrap().0
}

/// One layer, to be put back together.
#[derive(Clone, Debug)]
struct Piece {
    media_type: &'static str,
    notes: Vec<(&'static str, String)>,
    bytes: Vec<u8>,
    /// The identity the descriptor records, if not the bytes'.
    id: Option<BlobId>,
}

impl Piece {
    fn id(&self) -> BlobId {
        self.id.unwrap_or_else(|| BlobId::of(&self.bytes))
    }
}

/// A package taken apart, to be changed and put back together.
#[derive(Clone, Debug)]
struct Apart {
    layers: Vec<Piece>,
    config: Vec<u8>,
    /// The image manifest, if not the one the layers give.
    image: Option<Vec<u8>>,
    /// `index.json`, if not the one the image manifest gives.
    index: Option<Vec<u8>>,
    /// Blobs to add.
    extra: Vec<Vec<u8>>,
    /// Blob paths to leave out.
    skip: Vec<String>,
    /// Blob contents to store under another blob's path.
    swap: Vec<(String, Vec<u8>)>,
}

impl Apart {
    fn of(bytes: &[u8]) -> Self {
        let mut r = open(bytes.to_vec()).unwrap();
        let layers = r
            .parts
            .clone()
            .into_iter()
            .map(|(part, id)| {
                let blob = r.blobs[&id.path()];
                let bytes = read_at(&mut r.input, blob.offset, id.size, &part).unwrap();
                let (media_type, notes) = match part {
                    Part::Manifest => (media::MANIFEST, vec![]),
                    Part::Signature(key) => (media::SIGNATURE, vec![(annotations::KEY, key)]),
                    Part::License(id) => (media::LICENSE, vec![(annotations::LICENSE, id)]),
                    Part::Tree(f) => (media::TREE, vec![(annotations::FACET, f.to_string())]),
                    Part::ChunkIndex => (media::CHUNK_INDEX, vec![]),
                    Part::PackTable(f) => {
                        (media::PACK_TABLE, vec![(annotations::FACET, f.to_string())])
                    }
                    Part::ChunkPack(f) => {
                        (media::CHUNK_PACK, vec![(annotations::FACET, f.to_string())])
                    }
                    other => unreachable!("{other}"),
                };
                Piece {
                    media_type,
                    notes,
                    bytes,
                    id: None,
                }
            })
            .collect();
        Self {
            layers,
            config: EMPTY_CONFIG.to_vec(),
            image: None,
            index: None,
            extra: Vec::new(),
            skip: Vec::new(),
            swap: Vec::new(),
        }
    }

    fn sample() -> Self {
        Self::of(&sample_file())
    }

    /// The layer of this media type for this facet or license, if any.
    fn find(&self, media_type: &str, key: &str) -> usize {
        self.layers
            .iter()
            .position(|l| {
                l.media_type == media_type && l.notes.first().map_or("", |(_, v)| v.as_str()) == key
            })
            .unwrap()
    }

    fn image(&self) -> Vec<u8> {
        self.image.clone().unwrap_or_else(|| {
            let layers: Vec<Layer> = self
                .layers
                .iter()
                .map(|l| Layer {
                    media_type: l.media_type,
                    id: l.id(),
                    annotations: l
                        .notes
                        .iter()
                        .map(|(k, v)| ((*k).to_owned(), v.clone()))
                        .collect(),
                })
                .collect();
            image_manifest(&BlobId::of(&self.config), &layers)
        })
    }

    fn assemble(&self) -> Vec<u8> {
        let image = self.image();
        let index_bytes = self
            .index
            .clone()
            .unwrap_or_else(|| index(&BlobId::of(&image)));
        let mut blobs = BTreeMap::new();
        let contents = [image, self.config.clone()]
            .into_iter()
            .chain(self.layers.iter().map(|l| l.bytes.clone()))
            .chain(self.extra.iter().cloned());
        for bytes in contents {
            blobs.entry(BlobId::of(&bytes).path()).or_insert(bytes);
        }
        for path in &self.skip {
            blobs.remove(path);
        }
        for (path, bytes) in &self.swap {
            blobs.insert(path.clone(), bytes.clone());
        }
        let mut entries: Vec<(&str, &[u8])> =
            vec![("oci-layout", OCI_LAYOUT), ("index.json", &index_bytes)];
        entries.extend(blobs.iter().map(|(p, b)| (p.as_str(), b.as_slice())));
        tar_of(&entries)
    }

    fn refused(&self) -> (Part, ReadErrorKind) {
        refused(self.assemble())
    }

    fn opened(&self) -> Reader<Cursor<Vec<u8>>> {
        open(self.assemble()).unwrap()
    }
}

#[test]
fn a_written_package_reads_back() {
    let s = Sample::new();
    let (bytes, written) = s.write();
    let mut r = open(bytes.clone()).unwrap();
    assert_eq!(r.package(), written.package);
    assert_eq!(r.image(), written.image);
    assert_eq!(r.manifest(), &s.manifest());
    assert_eq!(r.facets().collect::<Vec<_>>(), [&f("doc"), &f("runtime")]);
    assert_eq!(r.license_ids().collect::<Vec<_>>(), ["MIT"]);
    assert_eq!(r.license_text("MIT").unwrap(), MIT);
    let parts: Vec<Part> = r.parts().iter().map(|(p, _)| p.clone()).collect();
    assert_eq!(
        parts,
        [
            Part::Manifest,
            Part::License("MIT".to_owned()),
            Part::Tree(f("doc")),
            Part::Tree(f("runtime")),
            Part::ChunkIndex,
            Part::PackTable(f("doc")),
            Part::PackTable(f("runtime")),
            Part::ChunkPack(f("doc")),
            Part::ChunkPack(f("runtime")),
        ]
    );
    let (_, manifest_id) = r.parts()[0];
    assert_eq!(manifest_id.blake3, written.package);
    let index = r.chunk_index().unwrap();
    assert_eq!(index.digest().unwrap(), written.chunk_index);
    assert_eq!(index.files().len(), 1, "the large file, listed once");
    for (facet, tree) in &s.trees {
        assert_eq!(&r.tree(facet).unwrap(), tree);
        let table = r.pack_table(facet).unwrap();
        for e in tree.entries() {
            if let Kind::File(file) = &e.kind {
                let mut out = Vec::new();
                r.read_file(facet, &table, &index, &e.path, file, &mut out)
                    .unwrap();
                assert_eq!(out, s.files[e.path.as_str()], "{}", e.path);
            }
        }
    }
    let debug = format!("{r:?}");
    assert!(debug.starts_with("Reader { package: "), "{debug}");
    assert!(debug.contains("image: "), "{debug}");
    assert_eq!(r.into_inner().into_inner(), bytes);
    // The test's own way of taking a file apart and putting it back
    // together gives the same bytes, so the tests below change only what
    // they mean to.
    assert_eq!(Apart::of(&bytes).assemble(), bytes);
}

#[test]
fn a_package_without_license_texts_or_files_reads_back() {
    let empty = Tree::new(Vec::new()).unwrap();
    let s = Sample {
        trees: BTreeMap::from([(f("runtime"), empty)]),
        licenses: BTreeMap::new(),
        files: BTreeMap::new(),
    };
    let all = read_all(s.write().0).unwrap();
    assert!(all.licenses.is_empty());
    assert!(all.files.is_empty());
    assert_eq!(all.tables[0].chunks(), []);
}

// The archive.

fn archive_error(bytes: Vec<u8>) -> ReadErrorKind {
    let (part, kind) = refused(bytes);
    assert_eq!(part, Part::Archive, "{kind}");
    kind
}

#[test]
fn an_archive_ends_with_two_zero_blocks_and_nothing_after_them() {
    let good = sample_file();
    let end = good.len() as u64 - 1024;
    for short in [0, 1, 1023] {
        assert!(matches!(
            archive_error(vec![0; short]),
            ReadErrorKind::Truncated
        ));
    }
    let mut block_more = good.clone();
    block_more.extend([0; 512]);
    let mut byte_more = good.clone();
    byte_more.push(0);
    let mut dirty = good.clone();
    *dirty.last_mut().unwrap() = 1;
    for bad in [block_more, byte_more, dirty] {
        assert!(matches!(archive_error(bad), ReadErrorKind::End { at } if at == end));
    }
    // One closing block only.
    let cut = good[..good.len() - 512].to_vec();
    assert!(matches!(archive_error(cut), ReadErrorKind::Truncated));
}

#[test]
fn an_entry_must_fit_before_the_closing_blocks() {
    let one = tar_of(&[("oci-layout", &[1; 1000])]);
    // The entry is whole, but the closing blocks are missing.
    for len in [1536, 1536 + 1023, 1200] {
        assert!(matches!(
            archive_error(one[..len].to_vec()),
            ReadErrorKind::Truncated
        ));
    }
    assert!(matches!(
        archive_error(one),
        ReadErrorKind::MissingEntry("index.json")
    ));
    assert!(matches!(
        archive_error(vec![0; 1024]),
        ReadErrorKind::MissingEntry("oci-layout")
    ));
}

#[test]
fn headers_must_be_the_writers() {
    let good = sample_file();
    let mut first = good.clone();
    first[257] = b'x';
    assert!(matches!(
        archive_error(first),
        ReadErrorKind::Header { at: 0 }
    ));
    // The third entry's header: the first blob.
    let at = 1024
        + 512
        + good[1024 + 124..1024 + 135]
            .iter()
            .fold(0, |n, d| n * 8 + u64::from(d - b'0'))
            .div_ceil(512)
            * 512;
    let mut third = good.clone();
    third[at as usize + 100] ^= 1;
    assert!(matches!(archive_error(third), ReadErrorKind::Header { at: a } if a == at));
}

#[test]
fn entries_come_in_the_formats_order() {
    let blob = |c: char| format!("blobs/sha256/{}", c.to_string().repeat(64));
    let entry = |bytes: Vec<u8>, at, name: &str, expected| match archive_error(bytes) {
        ReadErrorKind::Entry {
            at: a,
            name: n,
            expected: e,
        } => {
            assert_eq!((a, n.as_str(), e), (at, name, expected));
        }
        other => panic!("{other}"),
    };
    let layout: (&str, &[u8]) = ("oci-layout", OCI_LAYOUT);
    let index: (&str, &[u8]) = ("index.json", b"{}");
    entry(tar_of(&[index, layout]), 0, "index.json", "oci-layout");
    entry(tar_of(&[layout, layout]), 1024, "oci-layout", "index.json");
    let expected_blob = "a blob, blobs/sha256/ and 64 lowercase hex digits";
    for name in [
        "blobs/sha256/".to_owned() + &"A".repeat(64),
        "blobs/sha256/".to_owned() + &"g".repeat(64),
        "blobs/sha256/".to_owned() + &"a".repeat(63),
        "blobs/sha256/".to_owned() + &"a".repeat(65),
        "blobs/sha512/".to_owned() + &"a".repeat(64),
        "index.json".to_owned(),
    ] {
        entry(
            tar_of(&[layout, index, (&name, b"")]),
            2048,
            &name,
            expected_blob,
        );
    }
    let (a, b) = (blob('a'), blob('b'));
    let after = "a blob named after the one before it";
    entry(
        tar_of(&[layout, index, (&b, b""), (&a, b"")]),
        2560,
        &a,
        after,
    );
    entry(
        tar_of(&[layout, index, (&a, b""), (&a, b"")]),
        2560,
        &a,
        after,
    );
    // Digits and letters: 0-9 sort before a-f.
    let digits = blob('0');
    let both = tar_of(&[layout, index, (&digits, b""), (&a, b"x")]);
    let len = both.len() as u64;
    let mut names = walk(&mut Cursor::new(both), len, 8)
        .unwrap()
        .blobs
        .into_iter();
    assert_eq!(names.next().unwrap().0, digits);
    let (name, span) = names.next().unwrap();
    assert_eq!((name, span.offset, span.size), (a, 3072, 1));
}

#[test]
fn padding_is_zeros() {
    let mut bad = sample_file();
    bad[600] = 1;
    assert!(matches!(
        archive_error(bad),
        ReadErrorKind::Padding { at: 542 }
    ));
}

#[test]
fn an_archive_has_at_most_its_limit_of_entries() {
    let good = sample_file();
    let len = good.len() as u64;
    let count = 2 + Apart::of(&good).layers.len() + 2;
    let mut input = Cursor::new(good);
    assert!(walk(&mut input, len, count).is_ok());
    let e = walk(&mut input, len, count - 1).unwrap_err();
    assert!(matches!(e.kind(), ReadErrorKind::TooManyEntries { max } if *max == count - 1));
    assert_eq!(MAX_ENTRIES, 65_536);
}

// The OCI files.

#[test]
fn oci_layout_is_the_fixed_text() {
    let mut changed = sample_file();
    changed[512 + 3] ^= 1;
    assert!(matches!(
        refused(changed),
        (Part::OciLayout, ReadErrorKind::NotFixed)
    ));
    let longer = [OCI_LAYOUT, b" "].concat();
    assert!(matches!(
        refused(tar_of(&[("oci-layout", &longer), ("index.json", b"")])),
        (
            Part::OciLayout,
            ReadErrorKind::TooLarge { size: 31, max: 30 }
        )
    ));
}

#[test]
fn index_json_has_a_limit_and_must_be_the_writers() {
    let at_limit = vec![b' '; 4096];
    let over = vec![b' '; 4097];
    assert!(matches!(
        refused(tar_of(&[
            ("oci-layout", OCI_LAYOUT),
            ("index.json", &at_limit)
        ])),
        (Part::Index, ReadErrorKind::Json(_))
    ));
    assert!(matches!(
        refused(tar_of(&[("oci-layout", OCI_LAYOUT), ("index.json", &over)])),
        (
            Part::Index,
            ReadErrorKind::TooLarge {
                size: 4097,
                max: 4096
            }
        )
    ));
    let mut a = Apart::sample();
    let written = index(&BlobId::of(&a.image()));
    a.index = Some(
        String::from_utf8(written)
            .unwrap()
            .replacen(':', ": ", 1)
            .into_bytes(),
    );
    assert!(matches!(
        a.refused(),
        (Part::Index, ReadErrorKind::NotAsWritten { .. })
    ));
}

#[test]
fn the_image_manifest_must_be_present_whole_and_within_its_limit() {
    let mut a = Apart::sample();
    let image = BlobId::of(&a.image());
    a.skip = vec![image.path()];
    assert!(matches!(
        a.refused(),
        (Part::ImageManifest, ReadErrorKind::MissingBlob { path }) if path == image.path()
    ));

    let mut a = Apart::sample();
    a.index = Some(index(&BlobId {
        size: image.size + 1,
        ..image
    }));
    assert!(matches!(
        a.refused(),
        (Part::ImageManifest, ReadErrorKind::Size { recorded, actual })
            if recorded == image.size + 1 && actual == image.size
    ));

    let mut a = Apart::sample();
    let other = Digest::blake3(b"other");
    a.index = Some(index(&BlobId {
        blake3: other,
        ..image
    }));
    assert!(matches!(
        a.refused(),
        (Part::ImageManifest, ReadErrorKind::Corrupt { recorded, read })
            if recorded == other && read == image.blake3
    ));

    let mut a = Apart::sample();
    a.image = Some(vec![b' '; MAX_IMAGE_MANIFEST_SIZE as usize]);
    assert!(matches!(
        a.refused(),
        (Part::ImageManifest, ReadErrorKind::Json(_))
    ));
    a.image = Some(vec![b' '; MAX_IMAGE_MANIFEST_SIZE as usize + 1]);
    assert!(matches!(
        a.refused(),
        (Part::ImageManifest, ReadErrorKind::TooLarge { size, max })
            if size == MAX_IMAGE_MANIFEST_SIZE + 1 && max == MAX_IMAGE_MANIFEST_SIZE
    ));
    a.image = Some(b"{}".to_vec());
    assert!(matches!(
        a.refused(),
        (Part::ImageManifest, ReadErrorKind::Malformed(m)) if m == "it has no config"
    ));
}

#[test]
fn the_config_is_the_empty_one() {
    let mut a = Apart::sample();
    a.config = b"[]".to_vec();
    assert!(matches!(
        a.refused(),
        (Part::Config, ReadErrorKind::NotFixed)
    ));
    let mut a = Apart::sample();
    let empty = BlobId::of(EMPTY_CONFIG).path();
    a.swap = vec![(empty.clone(), b"[]".to_vec())];
    assert!(matches!(
        a.refused(),
        (Part::Config, ReadErrorKind::Corrupt { .. })
    ));
    let mut a = Apart::sample();
    a.skip = vec![empty.clone()];
    assert!(matches!(
        a.refused(),
        (Part::Config, ReadErrorKind::MissingBlob { path }) if path == empty
    ));
}

// The layers.

fn image_error(a: &Apart) -> ReadErrorKind {
    let (part, kind) = a.refused();
    assert_eq!(part, Part::ImageManifest, "{kind}");
    kind
}

fn out_of_order(a: &Apart, index: usize, media_type: &str) {
    match image_error(a) {
        ReadErrorKind::LayerOrder {
            index: i,
            media_type: m,
        } => assert_eq!((i, m), (index, media_type)),
        other => panic!("{other}"),
    }
}

#[test]
fn the_manifest_and_chunk_index_layers_are_required() {
    let mut a = Apart::sample();
    a.layers.clear();
    assert!(matches!(
        image_error(&a),
        ReadErrorKind::MissingLayer("manifest")
    ));
    let mut a = Apart::sample();
    a.layers.truncate(4);
    assert!(matches!(
        image_error(&a),
        ReadErrorKind::MissingLayer("chunk index")
    ));
}

#[test]
fn layers_come_in_the_formats_order() {
    let sample = Apart::sample();
    // The license first.
    let mut a = sample.clone();
    a.layers.swap(0, 1);
    out_of_order(&a, 0, media::LICENSE);
    // A second manifest.
    let mut a = sample.clone();
    let manifest = a.layers[0].clone();
    a.layers.insert(1, manifest);
    out_of_order(&a, 1, media::MANIFEST);
    // Trees by facet.
    let mut a = sample.clone();
    a.layers.swap(2, 3);
    out_of_order(&a, 3, media::TREE);
    let mut a = sample.clone();
    let tree = a.layers[2].clone();
    a.layers.insert(3, tree);
    out_of_order(&a, 3, media::TREE);
    // A second chunk index.
    let mut a = sample.clone();
    let i = a.find(media::CHUNK_INDEX, "");
    let index = a.layers[i].clone();
    a.layers.insert(i + 1, index);
    out_of_order(&a, i + 1, media::CHUNK_INDEX);
    // A tree after the chunk index.
    let mut a = sample.clone();
    let tree = a.layers.remove(2);
    a.layers.insert(i, tree);
    out_of_order(&a, i, media::TREE);
    // Licenses by ID.
    let mut a = sample.clone();
    let mut second = a.layers[1].clone();
    second.notes = vec![(annotations::LICENSE, "Apache-2.0".to_owned())];
    a.layers.insert(2, second);
    out_of_order(&a, 2, media::LICENSE);
    // Chunk packs last, by facet.
    let mut a = sample.clone();
    let last = a.layers.len() - 1;
    a.layers.swap(last - 1, last);
    out_of_order(&a, last, media::CHUNK_PACK);
}

#[test]
fn layers_have_exactly_their_annotations() {
    let malformed = |a: &Apart| match image_error(a) {
        ReadErrorKind::Malformed(m) => m,
        other => panic!("{other}"),
    };
    let mut a = Apart::sample();
    a.layers[0].notes = vec![(annotations::FACET, "doc".to_owned())];
    assert_eq!(
        malformed(&a),
        "layer 0 (application/vnd.ordin.manifest.v1+json) must have no annotations but com.ordinpm.blake3"
    );
    let mut a = Apart::sample();
    a.layers[2].notes.clear();
    assert_eq!(
        malformed(&a),
        "layer 2 (application/vnd.ordin.tree.v1+json) must have the annotation com.ordinpm.facet and com.ordinpm.blake3, and no others"
    );
    let mut a = Apart::sample();
    a.layers[2]
        .notes
        .push((annotations::LICENSE, "MIT".to_owned()));
    assert!(malformed(&a).starts_with("layer 2 "));
    let mut a = Apart::sample();
    a.layers[1].notes = vec![(annotations::FACET, "MIT".to_owned())];
    assert!(malformed(&a).starts_with("layer 1 "));
    for (i, media_type) in [
        (2, media::TREE),
        (5, media::PACK_TABLE),
        (7, media::CHUNK_PACK),
    ] {
        let mut a = Apart::sample();
        assert_eq!(a.layers[i].media_type, media_type);
        a.layers[i].notes = vec![(annotations::FACET, "Not A Facet".to_owned())];
        assert_eq!(
            malformed(&a),
            format!("layer {i} names the facet \"Not A Facet\", which isn't a facet name")
        );
    }
}

// The blobs.

#[test]
fn every_blob_is_named_once_with_its_size_and_digests() {
    let sample = Apart::sample();
    let tree = sample.find(media::TREE, "doc");
    let id = sample.layers[tree].id();

    let mut a = sample.clone();
    a.skip = vec![id.path()];
    assert!(matches!(
        a.refused(),
        (Part::Tree(facet), ReadErrorKind::MissingBlob { path }) if facet == f("doc") && path == id.path()
    ));

    let mut a = sample.clone();
    a.layers[tree].id = Some(BlobId {
        size: id.size + 1,
        ..id
    });
    assert!(matches!(
        a.refused(),
        (Part::Tree(_), ReadErrorKind::Size { recorded, actual })
            if recorded == id.size + 1 && actual == id.size
    ));

    let mut a = sample.clone();
    a.layers[tree + 1].id = Some(BlobId {
        blake3: Digest::blake3(b"other"),
        ..id
    });
    assert!(matches!(
        a.refused(),
        (Part::Tree(facet), ReadErrorKind::Inconsistent { path })
            if facet == f("runtime") && path == id.path()
    ));

    let mut a = sample.clone();
    a.extra = vec![b"unused".to_vec()];
    assert!(matches!(
        a.refused(),
        (Part::Archive, ReadErrorKind::UnusedBlob { path }) if path == BlobId::of(b"unused").path()
    ));

    // Two descriptors may name one blob, with the same digests.
    let mut a = sample.clone();
    let copy = a.layers[tree].bytes.clone();
    a.layers[tree + 1].bytes = copy;
    let (part, kind) = a.refused();
    assert_eq!(part, Part::Tree(f("runtime")), "{kind}");
    assert!(matches!(kind, ReadErrorKind::Disagrees(_)));
}

#[test]
fn the_manifest_is_read_and_checked() {
    let mut a = Apart::sample();
    a.layers[0].bytes = vec![b' '; ordin_manifest::MAX_SIZE + 1];
    assert!(matches!(
        a.refused(),
        (Part::Manifest, ReadErrorKind::TooLarge { .. })
    ));
    a.layers[0].bytes = b"{}".to_vec();
    assert!(matches!(
        a.refused(),
        (Part::Manifest, ReadErrorKind::Manifest(_))
    ));
}

// The layers against the manifest.

fn disagrees(a: &Apart) -> (Part, String) {
    match a.refused() {
        (part, ReadErrorKind::Disagrees(m)) => (part, m),
        (_, other) => panic!("{other}"),
    }
}

#[test]
fn every_facet_has_a_tree_pack_table_and_chunk_pack() {
    for (media_type, part, what) in [
        (media::TREE, Part::Tree(f("doc")), "tree"),
        (media::PACK_TABLE, Part::PackTable(f("doc")), "pack table"),
        (media::CHUNK_PACK, Part::ChunkPack(f("doc")), "chunk pack"),
    ] {
        let mut a = Apart::sample();
        let i = a.find(media_type, "doc");
        a.layers.remove(i);
        assert_eq!(
            disagrees(&a),
            (
                part.clone(),
                format!("the manifest lists facet doc, but the package has no {what} for it")
            )
        );
        let mut a = Apart::sample();
        let i = a.find(media_type, "runtime");
        let mut extra = a.layers[i].clone();
        extra.notes = vec![(annotations::FACET, "zz".to_owned())];
        a.layers.insert(i + 1, extra);
        let part = match part {
            Part::Tree(_) => Part::Tree(f("zz")),
            Part::PackTable(_) => Part::PackTable(f("zz")),
            _ => Part::ChunkPack(f("zz")),
        };
        assert_eq!(
            disagrees(&a),
            (
                part,
                format!("the package has a {what} for facet zz, which the manifest doesn't list")
            )
        );
    }
}

#[test]
fn each_tree_is_the_one_the_manifest_records() {
    let mut a = Apart::sample();
    let (doc, runtime) = (a.find(media::TREE, "doc"), a.find(media::TREE, "runtime"));
    let (d, r) = (a.layers[doc].id(), a.layers[runtime].id());
    let bytes = a.layers[doc].bytes.clone();
    a.layers[doc].bytes = a.layers[runtime].bytes.clone();
    a.layers[runtime].bytes = bytes;
    assert_eq!(
        disagrees(&a),
        (
            Part::Tree(f("doc")),
            format!(
                "the manifest records tree {}, but the layer is {}",
                d.blake3, r.blake3
            )
        )
    );
}

#[test]
fn each_license_text_is_the_one_the_manifest_records() {
    let mit = Part::License("MIT".to_owned());
    let mut a = Apart::sample();
    a.layers.remove(1);
    assert_eq!(
        disagrees(&a),
        (
            mit.clone(),
            "the manifest records a text for MIT, but the package has none".to_owned()
        )
    );
    let mut a = Apart::sample();
    let mut extra = a.layers[1].clone();
    extra.notes = vec![(annotations::LICENSE, "Zlib".to_owned())];
    a.layers.insert(2, extra);
    assert_eq!(
        disagrees(&a),
        (
            Part::License("Zlib".to_owned()),
            "the package has a text for Zlib, which the manifest doesn't record".to_owned()
        )
    );
    let mut a = Apart::sample();
    a.layers[1].bytes = b"Another text.\n".to_vec();
    assert_eq!(
        disagrees(&a),
        (
            mit,
            format!(
                "the manifest records the text {}, but the layer is {}",
                Digest::blake3(MIT),
                Digest::blake3(b"Another text.\n")
            )
        )
    );
}

// The parts read on request.

/// A sample whose manifest is `manifest`.
fn with_manifest(mut a: Apart, manifest: &Manifest) -> Apart {
    a.layers[0].bytes = manifest.to_canonical_bytes().unwrap();
    a
}

fn part_error(e: ReadError) -> (Part, ReadErrorKind) {
    let ReadError(failed) = e;
    (failed.part, failed.kind)
}

#[test]
fn parts_the_package_has_not_are_refused() {
    let mut r = open(sample_file()).unwrap();
    let none = f("none");
    let table = r.pack_table(&f("doc")).unwrap();
    let chunk = ChunkRef {
        digest: Digest::blake3(b""),
        length: 0,
    };
    for (e, part) in [
        (
            r.license_text("GPL-3.0-only").unwrap_err(),
            Part::License("GPL-3.0-only".to_owned()),
        ),
        (r.tree(&none).unwrap_err(), Part::Tree(none.clone())),
        (
            r.pack_table(&none).unwrap_err(),
            Part::PackTable(none.clone()),
        ),
        (
            r.chunk(&none, &table, &chunk).unwrap_err(),
            Part::Chunk {
                facet: none.clone(),
                digest: chunk.digest,
            },
        ),
    ] {
        let (p, kind) = part_error(e);
        assert_eq!(p, part);
        assert!(matches!(kind, ReadErrorKind::NoSuchPart), "{kind}");
    }
}

#[test]
fn a_license_text_has_a_limit() {
    let s = Sample::new();
    for (len, too_large) in [(MAX_LICENSE_TEXT, false), (MAX_LICENSE_TEXT + 1, true)] {
        let text = vec![b'x'; len as usize];
        let mut a = with_manifest(
            Apart::sample(),
            &manifest(&s.facets(), &[("MIT", Digest::blake3(&text))]),
        );
        a.layers[1].bytes = text.clone();
        let mut r = a.opened();
        let read = r.license_text("MIT");
        if too_large {
            assert!(matches!(
                part_error(read.unwrap_err()),
                (Part::License(_), ReadErrorKind::TooLarge { size, max })
                    if size == MAX_LICENSE_TEXT + 1 && max == MAX_LICENSE_TEXT
            ));
        } else {
            assert_eq!(read.unwrap(), text);
        }
    }
}

#[test]
fn a_tree_must_be_valid_and_of_the_size_the_manifest_records() {
    let s = Sample::new();
    let mut facets = s.facets();
    facets[0].2 += 1;
    let mut r = with_manifest(Apart::sample(), &manifest(&facets, &s.texts())).opened();
    let (part, kind) = part_error(r.tree(&f("doc")).unwrap_err());
    assert_eq!(part, Part::Tree(f("doc")));
    let recorded = facets[0].2;
    assert!(
        matches!(&kind, ReadErrorKind::Disagrees(m) if *m == format!("the manifest records {recorded} bytes of file content, but the tree has {}", recorded - 1)),
        "{kind}"
    );
    assert!(r.tree(&f("runtime")).is_ok());

    let mut facets = s.facets();
    facets[0].1 = Digest::blake3(b"not a tree");
    let mut a = with_manifest(Apart::sample(), &manifest(&facets, &s.texts()));
    a.layers[2].bytes = b"not a tree".to_vec();
    let mut r = a.opened();
    assert!(matches!(
        part_error(r.tree(&f("doc")).unwrap_err()),
        (Part::Tree(_), ReadErrorKind::Tree(_))
    ));
}

#[test]
fn the_chunk_index_and_pack_tables_are_checked_when_read() {
    let mut a = Apart::sample();
    let i = a.find(media::CHUNK_INDEX, "");
    a.layers[i].bytes = b"[]".to_vec();
    let mut r = a.opened();
    assert!(matches!(
        part_error(r.chunk_index().unwrap_err()),
        (Part::ChunkIndex, ReadErrorKind::ChunkIndex(_))
    ));

    // A table for another facet's pack doesn't end where the pack does.
    let mut a = Apart::sample();
    let (doc, runtime) = (
        a.find(media::PACK_TABLE, "doc"),
        a.find(media::PACK_TABLE, "runtime"),
    );
    let bytes = a.layers[doc].bytes.clone();
    a.layers[doc].bytes = a.layers[runtime].bytes.clone();
    a.layers[runtime].bytes = bytes;
    let mut r = a.opened();
    assert!(matches!(
        part_error(r.pack_table(&f("doc")).unwrap_err()),
        (
            Part::PackTable(_),
            ReadErrorKind::PackTable(PackTableError {
                kind: PackTableErrorKind::End { .. },
                ..
            })
        )
    ));
}

#[test]
fn a_chunk_must_be_listed_inside_its_pack_and_decompress_to_its_digest() {
    let s = Sample::new();
    let mut r = open(s.write().0).unwrap();
    let doc = f("doc");
    let table = r.pack_table(&doc).unwrap();
    let pack = r.packs[&doc].size;
    let readme = &s.files["/usr/share/doc/README"];
    let readme = ChunkRef {
        digest: Digest::blake3(readme),
        length: readme.len() as u64,
    };
    assert_eq!(r.chunk(&doc, &table, &readme).unwrap(), b"Says hello.\n");
    let kind = |r: &mut Reader<_>, table: &PackTable, chunk: &ChunkRef| {
        let (part, kind) = part_error(r.chunk(&doc, table, chunk).unwrap_err());
        assert_eq!(
            part,
            Part::Chunk {
                facet: doc.clone(),
                digest: chunk.digest
            }
        );
        kind
    };

    let long = ChunkRef {
        length: MAX_CHUNK + 1,
        ..readme
    };
    assert!(matches!(
        kind(&mut r, &table, &long),
        ReadErrorKind::ChunkTooLong { length, max } if length == MAX_CHUNK + 1 && max == MAX_CHUNK
    ));
    let unlisted = ChunkRef {
        digest: Digest::blake3(b"unlisted"),
        ..readme
    };
    assert!(matches!(
        kind(&mut r, &table, &unlisted),
        ReadErrorKind::NotInPack
    ));
    // The longest chunk is allowed as far as the table.
    let longest = ChunkRef {
        length: MAX_CHUNK,
        ..unlisted
    };
    assert!(matches!(
        kind(&mut r, &table, &longest),
        ReadErrorKind::NotInPack
    ));

    let x = Digest::blake3(b"x");
    let at = |offset, length| {
        PackTable::new(
            19,
            vec![PackEntry {
                digest: x,
                offset,
                length,
            }],
        )
    };
    let chunk = ChunkRef {
        digest: x,
        length: 1,
    };
    for (offset, length) in [(pack, 1), (pack - 1, 2), (u64::MAX, 1), (0, MAX_FRAME + 1)] {
        assert!(
            matches!(
                kind(&mut r, &at(offset, length), &chunk),
                ReadErrorKind::OutsidePack { offset: o, length: l, pack: p } if (o, l, p) == (offset, length, pack)
            ),
            "{offset} {length}"
        );
    }

    // A frame longer than any chunk compresses to is refused even inside
    // a pack that is large enough: here one the reader is told is huge.
    let mut huge = open(s.write().0).unwrap();
    let path = huge.packs[&doc].path();
    huge.blobs.get_mut(&path).unwrap().id.size = u64::MAX / 2;
    assert!(matches!(
        kind(&mut huge, &at(0, MAX_FRAME + 1), &chunk),
        ReadErrorKind::OutsidePack { .. }
    ));
    assert!(matches!(
        kind(&mut huge, &at(0, MAX_FRAME), &chunk),
        ReadErrorKind::Truncated
    ));

    // The README's frame, listed as another chunk of the same length.
    let entry = *table.find(&readme.digest).unwrap();
    let other = Digest::blake3(b"Says hello?\n");
    let lying = PackTable::new(
        19,
        vec![PackEntry {
            digest: other,
            ..entry
        }],
    );
    let claimed = ChunkRef {
        digest: other,
        ..readme
    };
    assert!(matches!(
        kind(&mut r, &lying, &claimed),
        ReadErrorKind::Corrupt { recorded, read } if recorded == other && read == readme.digest
    ));
    // The same frame, claimed to be longer.
    let longer = ChunkRef {
        length: readme.length + 1,
        ..readme
    };
    assert!(matches!(
        kind(&mut r, &table, &longer),
        ReadErrorKind::Frame(m) if m == format!("its header doesn't record the chunk's {} bytes", readme.length + 1)
    ));
}

fn frame_of(bytes: &[u8], checksum: bool, size: bool) -> Vec<u8> {
    let mut c = zstd::bulk::Compressor::new(3).unwrap();
    c.set_parameter(zstd_safe::CParameter::ChecksumFlag(checksum))
        .unwrap();
    c.set_parameter(zstd_safe::CParameter::ContentSizeFlag(size))
        .unwrap();
    c.set_parameter(zstd_safe::CParameter::DictIdFlag(false))
        .unwrap();
    c.compress(bytes).unwrap()
}

#[test]
fn a_frame_is_one_plain_zstd_frame_of_exactly_the_chunks_length() {
    let mut d = Decompressor::new().unwrap();
    d.set_parameter(DParameter::WindowLogMax(WINDOW_LOG_MAX))
        .unwrap();
    let text = b"hello hello hello hello".repeat(20);
    let len = text.len() as u64;
    let good = frame_of(&text, false, true);
    assert_eq!(decompress(&mut d, &good, len).unwrap(), text);
    assert_eq!(
        decompress(&mut d, &frame_of(b"", false, true), 0).unwrap(),
        b""
    );

    let refused =
        |d: &mut Decompressor<'_>, frame: &[u8], len| decompress(d, frame, len).unwrap_err();
    let magic = "it doesn't start with zstd's magic number";
    let mut bad_magic = good.clone();
    bad_magic[0] ^= 1;
    assert_eq!(refused(&mut d, &bad_magic, len), magic);
    assert_eq!(refused(&mut d, &good[..3], len), magic);
    let flags = "it has a checksum or a dictionary ID";
    assert_eq!(refused(&mut d, &frame_of(&text, true, true), len), flags);
    assert_eq!(refused(&mut d, &good[..4], len), flags);
    for bit in [0b001, 0b010] {
        let mut dict = good.clone();
        dict[4] |= bit;
        assert_eq!(refused(&mut d, &dict, len), flags);
    }
    let one = "it isn't exactly one frame";
    assert_eq!(
        refused(&mut d, &[good.clone(), good.clone()].concat(), 2 * len),
        one
    );
    assert_eq!(refused(&mut d, &good[..good.len() - 1], len), one);
    let skippable = [0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0];
    assert_eq!(refused(&mut d, &skippable, 0), magic);
    assert_eq!(
        refused(&mut d, &good, len - 1),
        format!("its header doesn't record the chunk's {} bytes", len - 1)
    );
    assert_eq!(
        refused(&mut d, &frame_of(&text, false, false), len),
        format!("its header doesn't record the chunk's {len} bytes")
    );
    // Damaged data after a good header doesn't decompress.
    let mut damaged = good.clone();
    let last = damaged.len() - 2;
    damaged[last] ^= 0xff;
    let e = decompress(&mut d, &damaged, len);
    assert!(e.is_err() || e.as_ref().is_ok_and(|b| *b != text), "{e:?}");
}

#[test]
fn a_file_is_its_chunks_checked_as_a_whole() {
    let s = Sample::new();
    let mut r = open(s.write().0).unwrap();
    let runtime = f("runtime");
    let table = r.pack_table(&runtime).unwrap();
    let index = r.chunk_index().unwrap();
    let big = &s.files["/usr/lib/big"];
    let record = file_record(big);
    let path = p("/usr/lib/big");
    let part = Part::File {
        facet: runtime.clone(),
        path: path.clone(),
    };

    let unlisted = ChunkIndex::new(params(), Vec::new()).unwrap();
    let (p1, kind) = part_error(
        r.read_file(&runtime, &table, &unlisted, &path, &record, &mut Vec::new())
            .unwrap_err(),
    );
    assert_eq!(p1, part);
    assert!(matches!(kind, ReadErrorKind::ChunkIndex(_)));

    // An index that lists the big file's chunks under another content
    // digest: every chunk is right, the file isn't.
    let other = Digest::blake3(b"other");
    let chunks = index.get(&record.content).unwrap().chunks().to_vec();
    let lying = ChunkIndex::new(params(), vec![IndexFile::new(other, chunks)]).unwrap();
    let claimed = File {
        content: other,
        ..record.clone()
    };
    let mut out = Vec::new();
    let (p2, kind) = part_error(
        r.read_file(&runtime, &table, &lying, &path, &claimed, &mut out)
            .unwrap_err(),
    );
    assert_eq!(p2, part);
    assert!(
        matches!(kind, ReadErrorKind::Content { recorded_size, recorded, read_size, read }
            if recorded_size == record.size && recorded == other && read_size == record.size && read == record.content),
        "{kind}"
    );
    assert_eq!(&out, big, "each chunk was right");

    struct Full;
    impl Write for Full {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("disk full"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let e = r
        .read_file(&runtime, &table, &index, &path, &record, &mut Full)
        .unwrap_err();
    assert_eq!(
        e.to_string(),
        "/usr/lib/big in facet runtime: writing it out: disk full"
    );
}

#[test]
fn input_errors_are_reported() {
    struct Failing;
    impl Read for Failing {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("unreadable"))
        }
    }
    impl Seek for Failing {
        fn seek(&mut self, _: SeekFrom) -> io::Result<u64> {
            Ok(4096)
        }
    }
    let e = Reader::open(Failing).unwrap_err();
    assert_eq!(e.to_string(), "the archive: reading the file: unreadable");
    assert_eq!(e.part(), &Part::Archive);
    assert!(matches!(e.kind(), ReadErrorKind::Io(_)));
}

#[test]
fn every_part_is_named_in_errors() {
    let d = Digest::blake3(b"");
    for (part, text) in [
        (Part::Archive, "the archive".to_owned()),
        (Part::OciLayout, "oci-layout".to_owned()),
        (Part::Index, "index.json".to_owned()),
        (Part::ImageManifest, "the image manifest".to_owned()),
        (Part::Config, "the config".to_owned()),
        (Part::Manifest, "the manifest".to_owned()),
        (
            Part::License("MIT".to_owned()),
            "the license text for MIT".to_owned(),
        ),
        (Part::Tree(f("doc")), "the tree for facet doc".to_owned()),
        (Part::ChunkIndex, "the chunk index".to_owned()),
        (
            Part::PackTable(f("doc")),
            "the pack table for facet doc".to_owned(),
        ),
        (
            Part::ChunkPack(f("doc")),
            "the chunk pack for facet doc".to_owned(),
        ),
        (
            Part::Chunk {
                facet: f("doc"),
                digest: d,
            },
            format!("chunk {d} in the chunk pack for facet doc"),
        ),
        (
            Part::File {
                facet: f("doc"),
                path: p("/a"),
            },
            "/a in facet doc".to_owned(),
        ),
    ] {
        assert_eq!(part.to_string(), text);
    }
    let e = ReadError::new(Part::Index, ReadErrorKind::NotAsWritten { at: 7 });
    assert_eq!(
        e.to_string(),
        "index.json: it isn't written as the format writes it, from byte 7"
    );
}

// Whole files.

#[test]
fn no_changed_byte_gives_other_content() {
    let (good, _) = Sample::tiny().write();
    let expected = read_all(good.clone()).unwrap();
    let mut accepted = Vec::new();
    for at in 0..good.len() {
        let mut changed = good.clone();
        changed[at] ^= 0x01;
        match read_all(changed) {
            Err(_) => {}
            Ok(all) => {
                assert_eq!(all, expected, "byte {at}");
                accepted.push(at);
            }
        }
    }
    // Only bytes inside a chunk pack's frames could ever be accepted, and
    // then only if zstd decodes them to the same chunk.
    assert!(accepted.is_empty(), "accepted changes at {accepted:?}");
}

fn facet_strategy() -> impl Strategy<Value = Vec<(u64, usize)>> {
    prop::collection::vec((any::<u64>(), 0usize..3000), 0..5)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn any_written_package_reads_back(
        runtime in facet_strategy(),
        doc in facet_strategy(),
        with_doc in any::<bool>(),
    ) {
        let mut trees = BTreeMap::new();
        let mut files = BTreeMap::new();
        let mut contents: BTreeMap<Facet, Vec<Vec<u8>>> = BTreeMap::new();
        let mut facets = vec![(f("runtime"), runtime)];
        if with_doc {
            facets.push((f("doc"), doc));
        }
        for (facet, specs) in facets {
            let mut entries = vec![dir("/usr")];
            for (i, (seed, len)) in specs.into_iter().enumerate() {
                let path = format!("/usr/{facet}-{i}");
                let bytes = noise(seed, len);
                entries.push(file(&path, &bytes));
                contents.entry(facet.clone()).or_default().push(bytes.clone());
                files.insert(path, bytes);
            }
            trees.insert(facet, Tree::new(entries).unwrap());
        }
        let s = Sample {
            trees,
            licenses: BTreeMap::from([("MIT".to_owned(), MIT.to_vec())]),
            files,
        };
        let (bytes, written) = s.write();
        let all = read_all(bytes).unwrap();
        prop_assert_eq!(all.package, written.package);
        prop_assert_eq!(&all.trees, &s.trees.values().cloned().collect::<Vec<_>>());
        prop_assert_eq!(all.files, contents.into_values().flatten().collect::<Vec<_>>());
        prop_assert_eq!(all.licenses, vec![MIT.to_vec()]);
    }
}

// Signatures (ORD-140).

/// Fresh keys, sorted by public key.
fn keys(n: usize) -> Vec<SecretKey> {
    let mut keys: Vec<SecretKey> = (0..n).map(|_| SecretKey::generate().unwrap()).collect();
    keys.sort_by_key(|k| k.public_key());
    keys
}

fn signed(sample: &Sample, keys: &[SecretKey]) -> Vec<Signature> {
    keys.iter()
        .map(|k| k.sign(&sample.package()).unwrap())
        .collect()
}

#[test]
fn a_signed_package_reads_back_its_signatures_sorted_by_key() {
    let sample = Sample::new();
    let keys = keys(2);
    let mut signatures = signed(&sample, &keys);
    signatures.reverse();
    let (bytes, written) = sample.write_signed(&signatures).unwrap();
    let r = open(bytes.clone()).unwrap();
    let read: Vec<PublicKey> = r.signatures().iter().map(Signature::key).collect();
    let expected: Vec<PublicKey> = keys.iter().map(|k| k.public_key()).collect();
    assert_eq!(read, expected);
    assert!(r.signatures().iter().all(|s| s.package() == r.package()));
    assert_eq!(
        r.parts().get(1).map(|(p, _)| p.clone()),
        Some(Part::Signature(expected[0].to_string()))
    );
    // Signing changes the image manifest, never the package or its content.
    let (unsigned, plain) = sample.write_signed(&[]).unwrap();
    assert_eq!(written.package, plain.package);
    assert_ne!(written.image, plain.image);
    assert_eq!(
        read_all(bytes).unwrap(),
        read_all(unsigned.clone()).unwrap()
    );
    assert!(open(unsigned).unwrap().signatures().is_empty());
}

#[test]
fn signing_again_gives_what_signing_while_writing_gives() {
    let sample = Sample::new();
    let keys = keys(2);
    let signatures = signed(&sample, &keys);
    let (unsigned, _) = sample.write_signed(&[]).unwrap();
    let rewritten = |bytes: Vec<u8>, with: &[Signature]| {
        let mut r = open(bytes).unwrap();
        let mut out = Vec::new();
        let written = rewrite(&mut r, with, &mut out).unwrap();
        (out, written)
    };
    let (one, written) = rewritten(unsigned.clone(), &signatures[..1]);
    let (expected, expected_written) = sample.write_signed(&signatures[..1]).unwrap();
    assert_eq!(one, expected);
    assert_eq!(written, expected_written);
    let (both, _) = rewritten(one.clone(), &[signatures[1].clone(), signatures[0].clone()]);
    assert_eq!(both, sample.write_signed(&signatures).unwrap().0);
    let (none, _) = rewritten(both, &[]);
    assert_eq!(none, unsigned);
}

#[test]
fn the_writer_refuses_signatures_a_reader_would_refuse() {
    let sample = Sample::new();
    let key = &keys(1)[0];
    let other = Digest::blake3(b"another manifest");
    let e = sample
        .write_signed(&[key.sign(&other).unwrap()])
        .unwrap_err();
    assert!(
        matches!(&e, WriteError::SignatureFor { signed, package, .. }
            if *signed == other && *package == sample.package()),
        "{e}"
    );
    let twice = key.sign(&sample.package()).unwrap();
    let e = sample.write_signed(&[twice.clone(), twice]).unwrap_err();
    assert_eq!(
        e.to_string(),
        format!(
            "two signatures are by {}; a package carries one per key",
            key.public_key()
        )
    );
    let many = signed(&sample, &keys(MAX_SIGNATURES + 1));
    assert!(matches!(
        sample.write_signed(&many).unwrap_err(),
        WriteError::TooManySignatures { count, max: MAX_SIGNATURES } if count == MAX_SIGNATURES + 1
    ));
    assert!(sample.write_signed(&many[..MAX_SIGNATURES]).is_ok());
}

#[test]
fn a_package_carries_at_most_64_signatures() {
    let sample = Sample::new();
    let signatures = signed(&sample, &keys(MAX_SIGNATURES));
    let mut apart = Apart::of(&sample.write_signed(&signatures).unwrap().0);
    assert!(open(apart.assemble()).is_ok());
    let extra = keys(1).remove(0);
    let piece = Piece {
        media_type: media::SIGNATURE,
        // Sorts after every key: g is after every hex digit.
        notes: vec![(annotations::KEY, "ed25519:g".to_owned())],
        bytes: extra.sign(&sample.package()).unwrap().to_bytes(),
        id: None,
    };
    apart.layers.insert(MAX_SIGNATURES + 1, piece);
    assert!(matches!(
        refused(apart.assemble()),
        (
            Part::ImageManifest,
            ReadErrorKind::TooManySignatures {
                max: MAX_SIGNATURES
            }
        )
    ));
}

/// The sample with one signature, taken apart.
fn signed_apart() -> (Sample, Apart, SecretKey) {
    let sample = Sample::new();
    let key = keys(1).remove(0);
    let bytes = sample
        .write_signed(&[key.sign(&sample.package()).unwrap()])
        .unwrap()
        .0;
    (sample, Apart::of(&bytes), key)
}

#[test]
fn a_signature_must_verify_and_be_for_this_package_by_its_key() {
    let (sample, apart, key) = signed_apart();
    let named = key.public_key().to_string();
    let part = Part::Signature(named.clone());
    let at = apart.find(media::SIGNATURE, &named);

    let mut other = apart.clone();
    other.layers[at].bytes = key.sign(&Digest::blake3(b"x")).unwrap().to_bytes();
    let (failed, kind) = refused(other.assemble());
    assert_eq!(failed, part);
    assert!(
        matches!(&kind, ReadErrorKind::Disagrees(m)
            if *m == format!("the signature is for package {}, not this package, {}", Digest::blake3(b"x"), sample.package())),
        "{kind}"
    );

    let someone = keys(1).remove(0);
    let mut by_another = apart.clone();
    by_another.layers[at].bytes = someone.sign(&sample.package()).unwrap().to_bytes();
    let (failed, kind) = refused(by_another.assemble());
    assert_eq!(failed, part);
    let expected = format!(
        "the layer is annotated with {named}, but the signature is by {}",
        someone.public_key()
    );
    assert!(
        matches!(&kind, ReadErrorKind::Disagrees(m) if *m == expected),
        "{kind}"
    );

    let mut garbage = apart.clone();
    let mut bytes = garbage.layers[at].bytes.clone();
    let last = bytes.len() - 3;
    bytes[last] = if bytes[last] == b'0' { b'1' } else { b'0' };
    garbage.layers[at].bytes = bytes;
    let (failed, kind) = refused(garbage.assemble());
    assert_eq!(failed, part);
    assert!(
        matches!(&kind, ReadErrorKind::Signature(ordin_sign::Error::BadSignature { key }) if *key == named),
        "{kind}"
    );

    let mut large = apart.clone();
    large.layers[at].bytes = vec![b' '; MAX_SIGNATURE_SIZE + 1];
    let (failed, kind) = refused(large.assemble());
    assert_eq!(failed, part);
    assert!(matches!(kind, ReadErrorKind::TooLarge { .. }), "{kind}");
    let e = open(large.assemble()).unwrap_err().to_string();
    assert!(e.starts_with(&format!("the signature by {named}: ")), "{e}");
}

#[test]
fn signature_layers_are_annotated_and_sorted_by_key() {
    let sample = Sample::new();
    let keys = keys(2);
    let apart = Apart::of(&sample.write_signed(&signed(&sample, &keys)).unwrap().0);
    let mut swapped = apart.clone();
    swapped.layers.swap(1, 2);
    assert!(matches!(
        refused(swapped.assemble()),
        (
            Part::ImageManifest,
            ReadErrorKind::LayerOrder { index: 2, .. }
        )
    ));
    let mut twice = apart.clone();
    twice.layers[2] = twice.layers[1].clone();
    assert!(matches!(
        refused(twice.assemble()),
        (
            Part::ImageManifest,
            ReadErrorKind::LayerOrder { index: 2, .. }
        )
    ));
    let mut bare = apart.clone();
    bare.layers[1].notes.clear();
    assert!(matches!(
        refused(bare.assemble()),
        (Part::ImageManifest, ReadErrorKind::Malformed(m)) if m.contains("com.ordinpm.key")
    ));
    let mut after = apart;
    let signature = after.layers.remove(1);
    after.layers.insert(2, signature);
    assert!(matches!(
        refused(after.assemble()),
        (Part::ImageManifest, ReadErrorKind::LayerOrder { .. })
    ));
}

/// A reader that starts failing when told to.
struct Flaky {
    inner: Cursor<Vec<u8>>,
    fail: std::rc::Rc<std::cell::Cell<(bool, bool)>>,
}

impl Read for Flaky {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.fail.get().0 {
            return Err(io::Error::other("the disk went away"));
        }
        self.inner.read(buf)
    }
}

impl Seek for Flaky {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        if self.fail.get().1 {
            return Err(io::Error::other("no seeking"));
        }
        self.inner.seek(to)
    }
}

#[test]
fn signing_again_says_when_reading_the_package_fails() {
    for (read, seek, said) in [
        (true, false, "reading the package: the disk went away"),
        (false, true, "reading the package: no seeking"),
    ] {
        let fail = std::rc::Rc::new(std::cell::Cell::new((false, false)));
        let mut r = Reader::open(Flaky {
            inner: Cursor::new(sample_file()),
            fail: fail.clone(),
        })
        .unwrap();
        fail.set((read, seek));
        let e = rewrite(&mut r, &[], &mut Vec::new()).unwrap_err();
        assert_eq!(e.to_string(), said);
    }
}
