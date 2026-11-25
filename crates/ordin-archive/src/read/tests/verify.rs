// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Verifying `.ordin` files (ORD-133): everything the writer writes
//! verifies, a change anywhere fails and names the part it is in, and
//! anything else the writer wouldn't write is refused.

use std::collections::BTreeSet;

use ordin_tree::chunk::chunk_file;

use super::*;

/// One facet with a small file, an empty one, one exactly at the
/// whole-file threshold and one well above it, under a license.
fn small() -> Sample {
    sample_of(&[
        ("/a", b"echo hello\n".to_vec()),
        ("/b", Vec::new()),
        ("/c", noise(7, 700)),
        ("/d", noise(8, 256)),
    ])
}

/// A runtime facet of these files, under the MIT license.
fn sample_of(files: &[(&str, Vec<u8>)]) -> Sample {
    let tree = Tree::new(files.iter().map(|(p, b)| file(p, b)).collect()).unwrap();
    Sample {
        trees: BTreeMap::from([(f("runtime"), tree)]),
        licenses: BTreeMap::from([("MIT".to_owned(), MIT.to_vec())]),
        files: files
            .iter()
            .map(|(p, b)| ((*p).to_owned(), b.clone()))
            .collect(),
    }
}

/// Other chunking with the same whole-file threshold, so the same files
/// are listed in the index.
fn other_params() -> ChunkParams {
    ChunkParams::new(64, 512, 2048, 256, 1).unwrap()
}

/// Writes `sample`, unsigned, with this chunking.
fn written_with(sample: &Sample, chunking: ChunkParams) -> Vec<u8> {
    let manifest = sample.manifest();
    let package = Package {
        manifest: &manifest,
        trees: &sample.trees,
        licenses: &sample.licenses,
        chunking,
        signatures: &[],
    };
    let spool = tempfile::tempdir().unwrap();
    let mut out = Vec::new();
    write(
        &package,
        &mut Files(sample.files.clone()),
        &Options {
            level: 3,
            threads: std::num::NonZeroUsize::MIN,
        },
        spool.path(),
        &mut out,
    )
    .unwrap();
    out
}

/// Opens and verifies `bytes`.
fn verified(bytes: Vec<u8>) -> Result<Verified, ReadError> {
    open(bytes)?.verify()
}

/// The part and kind of the error verifying `bytes` gives. It must open.
fn unverified(bytes: Vec<u8>) -> (Part, ReadErrorKind) {
    let ReadError(failed) = open(bytes).unwrap().verify().unwrap_err();
    (failed.part, failed.kind)
}

fn file_part(path: &str) -> Part {
    Part::File {
        facet: f("runtime"),
        path: p(path),
    }
}

/// The layer of this media type, by its first annotation's value.
fn layer<'a>(apart: &'a mut Apart, media_type: &str, key: &str) -> &'a mut Piece {
    let at = apart.find(media_type, key);
    &mut apart.layers[at]
}

/// The distinct chunks of `tree`'s files, cut on their own with
/// `params`.
fn chunks_of(tree: &Tree, files: &BTreeMap<String, Vec<u8>>, params: &ChunkParams) -> usize {
    let mut chunks = BTreeSet::new();
    for entry in tree.entries() {
        if let Kind::File(_) = entry.kind {
            let bytes = &files[entry.path.as_str()];
            let cut = chunk_file(&bytes[..], params, |_, _| Ok(())).unwrap();
            chunks.extend(cut.chunks().iter().map(|c| c.digest));
        }
    }
    chunks.len()
}

#[test]
fn everything_the_writer_writes_verifies() {
    let mut sample = Sample::new();
    // A hard link: counted as a file each time, checked once.
    let mut runtime = sample.trees[&f("runtime")].entries().to_vec();
    let big = sample.files["/usr/lib/big"].clone();
    runtime.push(file("/usr/lib/big2", &big));
    sample
        .trees
        .insert(f("runtime"), Tree::new(runtime).unwrap());
    sample.files.insert("/usr/lib/big2".to_owned(), big);
    let keys = keys(2);
    let (bytes, _) = sample.write_signed(&signed(&sample, &keys)).unwrap();
    let expected = |facet: &str, files| {
        let tree = &sample.trees[&f(facet)];
        VerifiedFacet {
            facet: f(facet),
            files,
            chunks: chunks_of(tree, &sample.files, &params()),
            size: size_of(tree),
        }
    };
    assert_eq!(
        verified(bytes).unwrap(),
        Verified {
            facets: vec![expected("doc", 2), expected("runtime", 4)],
            licenses: 1,
            signatures: 2,
        }
    );
    // Without license texts or signatures, and with an empty facet.
    let empty = sample_of(&[]);
    let mut empty = Sample {
        licenses: BTreeMap::new(),
        ..empty
    };
    empty
        .trees
        .insert(f("doc"), Tree::new(vec![dir("/usr")]).unwrap());
    let v = verified(empty.write().0).unwrap();
    assert_eq!(v.licenses, 0);
    assert_eq!(v.signatures, 0);
    assert_eq!(
        v.facets,
        [
            VerifiedFacet {
                facet: f("doc"),
                files: 0,
                chunks: 0,
                size: 0,
            },
            VerifiedFacet {
                facet: f("runtime"),
                files: 0,
                chunks: 0,
                size: 0,
            },
        ]
    );
    // The small sample, whose files sit on and around the threshold.
    let s = small();
    let v = verified(s.write().0).unwrap();
    assert_eq!(v.facets[0].files, 4);
    assert_eq!(
        v.facets[0].chunks,
        chunks_of(&s.trees[&f("runtime")], &s.files, &params())
    );
}

/// The part each byte of `bytes` belongs to: tar headers, padding and
/// the closing blocks are the archive's.
fn regions(bytes: &[u8]) -> Vec<Part> {
    let mut r = open(bytes.to_vec()).unwrap();
    let mut names: BTreeMap<String, Part> = r
        .parts()
        .iter()
        .map(|(part, id)| (id.path(), part.clone()))
        .collect();
    names.insert(BlobId::of(EMPTY_CONFIG).path(), Part::Config);
    let entries = walk(&mut r.input, bytes.len() as u64, MAX_ENTRIES).unwrap();
    let mut at = vec![Part::Archive; bytes.len()];
    let mut mark = |span: Span, part: Part| {
        let end = span.offset + span.size;
        for b in &mut at[span.offset as usize..end as usize] {
            *b = part.clone();
        }
    };
    mark(entries.layout, Part::OciLayout);
    mark(entries.index, Part::Index);
    for (path, span) in &entries.blobs {
        // The one blob no layer names is the image manifest.
        let part = names.get(path).cloned().unwrap_or(Part::ImageManifest);
        mark(*span, part);
    }
    at
}

#[test]
fn every_changed_byte_fails_and_names_the_part_it_is_in() {
    let sample = small();
    let key = SecretKey::generate().unwrap();
    let (good, _) = sample
        .write_signed(&[key.sign(&sample.package()).unwrap()])
        .unwrap();
    verified(good.clone()).unwrap();
    let regions = regions(&good);
    // Every kind of part is there to be changed.
    for part in [
        Part::Archive,
        Part::OciLayout,
        Part::Index,
        Part::ImageManifest,
        Part::Config,
        Part::Manifest,
        Part::Signature(key.public_key().to_string()),
        Part::License("MIT".to_owned()),
        Part::Tree(f("runtime")),
        Part::ChunkIndex,
        Part::PackTable(f("runtime")),
        Part::ChunkPack(f("runtime")),
    ] {
        assert!(regions.contains(&part), "{part}");
    }
    let mut wrong = Vec::new();
    for at in 0..good.len() {
        let mut changed = good.clone();
        changed[at] ^= 0x01;
        let e = match verified(changed) {
            Ok(_) => {
                wrong.push(format!("byte {at} in {} was accepted", regions[at]));
                continue;
            }
            Err(e) => e,
        };
        let named = e.part();
        // index.json holds the image manifest's descriptor: a change to
        // it names a blob that isn't there, and that blob is the one
        // missing.
        let descriptor = regions[at] == Part::Index && *named == Part::ImageManifest;
        if *named != regions[at] && !descriptor {
            wrong.push(format!("byte {at} in {}: {e}", regions[at]));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

#[test]
fn a_chunk_index_must_record_the_chunking_its_chunks_were_cut_with() {
    // Written with other chunking, then given an index that records this
    // package's usual chunking over the same chunks.
    let s = small();
    let cut = |p: &ChunkParams| {
        chunk_file(&s.files["/c"][..], p, |_, _| Ok(()))
            .unwrap()
            .chunks()
            .to_vec()
    };
    assert_ne!(
        cut(&params()),
        cut(&other_params()),
        "the fixture needs a contrast"
    );
    let bytes = written_with(&s, other_params());
    let mut apart = Apart::of(&bytes);
    let mut r = open(bytes).unwrap();
    let index = r.chunk_index().unwrap();
    let claimed = ChunkIndex::new(params(), index.files().to_vec()).unwrap();
    layer(&mut apart, media::CHUNK_INDEX, "").bytes = claimed.to_canonical_bytes().unwrap();
    let (part, kind) = unverified(apart.assemble());
    assert_eq!(part, file_part("/c"));
    let actual = chunk_file(&s.files["/c"][..], &params(), |_, _| Ok(())).unwrap();
    let listed = index.chunks_of(&actual.digests().content, 700).unwrap();
    let at = actual
        .chunks()
        .iter()
        .zip(&listed)
        .position(|(a, b)| a != b)
        .unwrap();
    assert!(
        matches!(kind, ReadErrorKind::Rechunked { chunking, at: a } if chunking == params() && a == at),
        "{kind:?}"
    );
    assert_eq!(
        kind.to_string(),
        format!(
            "cut again with the chunk index's chunking ({}), it gives other chunks than \
             the index lists, from chunk {at}",
            params()
        )
    );
    // The index lists chunks the pack doesn't hold: reading one fails.
    let mut apart = Apart::of(&s.write().0);
    layer(&mut apart, media::CHUNK_INDEX, "").bytes =
        ChunkIndex::new(params(), index.files().to_vec())
            .unwrap()
            .to_canonical_bytes()
            .unwrap();
    let (part, kind) = unverified(apart.assemble());
    assert!(matches!(part, Part::Chunk { .. }), "{part}");
    assert!(matches!(kind, ReadErrorKind::NotInPack), "{kind:?}");
}

#[test]
fn a_file_is_put_together_from_the_chunks_its_index_entry_lists() {
    // Two files of the same size: the index lists the second's chunks for
    // the first.
    let one = noise(7, 700);
    let two = noise(9, 700);
    let s = sample_of(&[("/one", one.clone()), ("/two", two.clone())]);
    let bytes = s.write().0;
    let mut apart = Apart::of(&bytes);
    let index = open(bytes).unwrap().chunk_index().unwrap();
    let (one_d, two_d) = (Digest::blake3(&one), Digest::blake3(&two));
    let files = vec![
        IndexFile::new(one_d, index.get(&two_d).unwrap().chunks().to_vec()),
        index.get(&two_d).unwrap().clone(),
    ];
    layer(&mut apart, media::CHUNK_INDEX, "").bytes = ChunkIndex::new(params(), files)
        .unwrap()
        .to_canonical_bytes()
        .unwrap();
    let (part, kind) = unverified(apart.assemble());
    assert_eq!(part, file_part("/one"));
    assert!(
        matches!(kind, ReadErrorKind::Content { recorded, read, recorded_size: 700, read_size: 700 }
            if recorded == one_d && read == two_d),
        "{kind:?}"
    );
}

#[test]
fn each_file_is_checked_against_its_fs_verity_digest() {
    let s = small();
    let mut apart = Apart::of(&s.write().0);
    // A tree recording another fs-verity digest for /a, and a manifest
    // recording that tree.
    let mut entries = s.trees[&f("runtime")].entries().to_vec();
    let wrong = Digest::new(ordin_core::Algorithm::Sha256, [7; 32]);
    let Kind::File(a) = &mut entries[0].kind else {
        unreachable!()
    };
    let right = a.fsverity;
    a.fsverity = wrong;
    let tree = Tree::new(entries).unwrap();
    let manifest = manifest(
        &[(f("runtime"), tree.digest().unwrap(), size_of(&tree))],
        &s.texts(),
    );
    layer(&mut apart, media::TREE, "runtime").bytes = tree.to_canonical_bytes().unwrap();
    layer(&mut apart, media::MANIFEST, "").bytes = manifest.to_canonical_bytes().unwrap();
    let (part, kind) = unverified(apart.assemble());
    assert_eq!(part, file_part("/a"));
    assert!(
        matches!(kind, ReadErrorKind::Fsverity { recorded, read } if recorded == wrong && read == right),
        "{kind:?}"
    );
    assert_eq!(
        kind.to_string(),
        format!("the tree records the fs-verity digest {wrong}, but its content gives {right}")
    );
}

/// `base` with its runtime pack and pack table taken from `other`.
fn with_pack_of(base: &Sample, other: &Sample) -> Vec<u8> {
    let mut apart = Apart::of(&base.write().0);
    let from = Apart::of(&other.write().0);
    for media_type in [media::PACK_TABLE, media::CHUNK_PACK] {
        let piece = from.layers[from.find(media_type, "runtime")].clone();
        *layer(&mut apart, media_type, "runtime") = piece;
    }
    apart.assemble()
}

#[test]
fn a_pack_holds_only_the_chunks_its_files_use() {
    let base = small();
    let mut files: Vec<(&str, Vec<u8>)> = base
        .files
        .iter()
        .map(|(p, b)| (p.as_str(), b.clone()))
        .collect();
    files.push(("/e", b"extra\n".to_vec()));
    let (part, kind) = unverified(with_pack_of(&base, &sample_of(&files)));
    assert_eq!(part, Part::ChunkPack(f("runtime")));
    let extra = Digest::blake3(b"extra\n");
    assert!(
        matches!(kind, ReadErrorKind::UnusedChunk { digest } if digest == extra),
        "{kind:?}"
    );
    assert_eq!(
        kind.to_string(),
        format!("it holds the chunk {extra}, which no file of the facet uses")
    );
}

#[test]
fn a_pack_holds_its_chunks_in_the_order_its_files_first_use_them() {
    let (one, two, three) = (b"one\n".to_vec(), b"two\n".to_vec(), b"three\n".to_vec());
    let base = sample_of(&[
        ("/a", one.clone()),
        ("/b", two.clone()),
        ("/c", three.clone()),
    ]);
    // The same chunks, the last two the other way round.
    let other = sample_of(&[("/a", one), ("/b", three), ("/c", two)]);
    let (part, kind) = unverified(with_pack_of(&base, &other));
    assert_eq!(part, Part::ChunkPack(f("runtime")));
    assert!(
        matches!(kind, ReadErrorKind::ChunkOrder { at: 1 }),
        "{kind:?}"
    );
    assert_eq!(
        kind.to_string(),
        "its chunks aren't in the order the facet's files first use them, from chunk 1"
    );
}

#[test]
fn a_chunk_index_lists_only_content_a_file_needs_listed() {
    let s = small();
    let bytes = s.write().0;
    let index = open(bytes.clone()).unwrap().chunk_index().unwrap();
    let extra = |listing: IndexFile| {
        let mut apart = Apart::of(&bytes);
        let mut files = index.files().to_vec();
        files.push(listing);
        layer(&mut apart, media::CHUNK_INDEX, "").bytes = ChunkIndex::new(params(), files)
            .unwrap()
            .to_canonical_bytes()
            .unwrap();
        unverified(apart.assemble())
    };
    // Content no file has.
    let other = noise(11, 700);
    let cut = chunk_file(&other[..], &params(), |_, _| Ok(())).unwrap();
    let (part, kind) = extra(cut.index_entry().unwrap());
    assert_eq!(part, Part::ChunkIndex);
    let content = Digest::blake3(&other);
    assert!(
        matches!(kind, ReadErrorKind::UnusedIndexEntry { content: c } if c == content),
        "{kind:?}"
    );
    assert_eq!(
        kind.to_string(),
        format!(
            "it lists the content {content}, which no file at or above the whole-file \
             threshold has"
        )
    );
}

#[test]
fn a_blob_cut_short_under_the_reader_fails() {
    let mut r = open(small().write().0).unwrap();
    // The input shrinks after it was opened, inside the last blob checked.
    let (part, blob) = r
        .parts()
        .iter()
        .map(|(part, id)| (part.clone(), r.blobs[&id.path()]))
        .max_by_key(|(_, b)| b.offset)
        .unwrap();
    r.input.get_mut().truncate(blob.offset as usize + 1);
    let e = r.verify().unwrap_err();
    assert_eq!(*e.part(), part);
    assert!(matches!(e.kind(), ReadErrorKind::Corrupt { .. }), "{e}");
}
