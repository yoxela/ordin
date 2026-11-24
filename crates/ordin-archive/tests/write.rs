// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Writing `.ordin` files, read back with the `tar` crate and serde_json
//! as second opinions.

#[cfg(test)]
mod write {
    use std::collections::{BTreeMap, BTreeSet};
    use std::io::{self, Cursor, Read, Write};
    use std::num::NonZeroUsize;

    use ordin_archive::{
        BlobId, EMPTY_CONFIG, MAX_LICENSE_TEXT, OCI_LAYOUT, Options, Package, Source, WriteError,
        Written, annotations, media, write,
    };
    use ordin_core::{Account, Digest, Facet};
    use ordin_manifest::Manifest;
    use ordin_tree::chunk::{ChunkIndex, ChunkParams};
    use ordin_tree::{
        DIR_MODE, Dir, Entry, FILE_MODE, File, Kind, Symlink, Tree, TreePath, Xattrs, file_digests,
    };
    use proptest::prelude::*;
    use serde_json::Value;

    const LICENSE: &[u8] = b"Permission is hereby granted, free of charge...\n";

    fn p(path: &str) -> TreePath {
        path.parse().unwrap()
    }

    fn f(name: &str) -> Facet {
        name.parse().unwrap()
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

    fn file(path: &str, bytes: &[u8]) -> Entry {
        let d = file_digests(bytes).unwrap();
        Entry {
            path: p(path),
            kind: Kind::File(File {
                mode: FILE_MODE,
                owner: Account::root(),
                group: Account::root(),
                size: d.size,
                content: d.content,
                fsverity: d.fsverity,
                xattrs: Xattrs::new(),
                capabilities: None,
            }),
        }
    }

    fn symlink(path: &str, target: &str) -> Entry {
        Entry {
            path: p(path),
            kind: Kind::Symlink(Symlink {
                target: target.parse().unwrap(),
                owner: Account::root(),
                group: Account::root(),
            }),
        }
    }

    fn hard_link(path: &str, target: &str) -> Entry {
        Entry {
            path: p(path),
            kind: Kind::HardLink(p(target)),
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

    fn size(tree: &Tree) -> u64 {
        tree.entries()
            .iter()
            .map(|e| match &e.kind {
                Kind::File(f) => f.size,
                _ => 0,
            })
            .sum()
    }

    fn manifest(trees: &BTreeMap<Facet, Tree>, licenses: &BTreeMap<String, Vec<u8>>) -> Manifest {
        let facets: Vec<String> = trees
            .iter()
            .map(|(facet, tree)| {
                format!(
                    r#""{facet}":{{"tree":"{}","size":{}}}"#,
                    tree.digest().unwrap(),
                    size(tree)
                )
            })
            .collect();
        let texts: Vec<String> = licenses
            .iter()
            .map(|(id, text)| format!(r#""{id}":"{}""#, Digest::blake3(text)))
            .collect();
        let spdx = licenses.keys().cloned().collect::<Vec<_>>().join(" AND ");
        Manifest::from_json(&format!(
            r#"{{"ordin":1,"name":"hello","version":{{"upstream":"2.12","release":"1"}},"kind":"base","arch":"x86_64","summary":"Prints a friendly greeting","license":{{"spdx":"{spdx}","texts":{{{}}}}},"facets":{{{}}}}}"#,
            texts.join(","),
            facets.join(",")
        ))
        .unwrap()
    }

    /// A source of files by path, which records what it opened.
    #[derive(Default)]
    struct Files {
        files: BTreeMap<String, Vec<u8>>,
        opened: Vec<String>,
    }

    impl Source for Files {
        type Reader = Cursor<Vec<u8>>;

        fn open(&mut self, path: &TreePath, _: &File) -> io::Result<Self::Reader> {
            self.opened.push(path.to_string());
            self.files
                .get(path.as_str())
                .cloned()
                .map(Cursor::new)
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such file"))
        }
    }

    /// A test package: a runtime and a doc facet, with a large file in both,
    /// a copy of it, a hard link and a symlink.
    struct Fixture {
        trees: BTreeMap<Facet, Tree>,
        licenses: BTreeMap<String, Vec<u8>>,
        manifest: Manifest,
        files: Files,
    }

    impl Fixture {
        fn new() -> Self {
            let hello = b"#!/bin/sh\necho hello\n".to_vec();
            // Repeated, so the second half's chunks are the first half's.
            let half = noise(1, 3000);
            let big = [half.clone(), half].concat();
            let readme = b"Says hello.\n".to_vec();
            // Text, which compresses differently at each level; noise doesn't.
            let other: Vec<u8> = (0..60)
                .flat_map(|i| format!("Says hello, line {i}, to {} people.\n", i % 7).into_bytes())
                .collect();
            let files = Files {
                files: BTreeMap::from([
                    ("/usr/bin/hello".to_owned(), hello.clone()),
                    ("/usr/lib/hello/big".to_owned(), big.clone()),
                    ("/usr/lib/hello/big-copy".to_owned(), big.clone()),
                    ("/usr/lib/hello/other".to_owned(), other.clone()),
                    ("/usr/share/doc/hello/README".to_owned(), readme.clone()),
                    ("/usr/share/doc/hello/big".to_owned(), big.clone()),
                ]),
                opened: Vec::new(),
            };
            let runtime = Tree::new(vec![
                dir("/usr"),
                dir("/usr/bin"),
                file("/usr/bin/hello", &hello),
                symlink("/usr/bin/hi", "hello"),
                hard_link("/usr/bin/hello2", "/usr/bin/hello"),
                dir("/usr/lib"),
                dir("/usr/lib/hello"),
                file("/usr/lib/hello/big", &big),
                file("/usr/lib/hello/big-copy", &big),
                file("/usr/lib/hello/other", &other),
            ])
            .unwrap();
            let doc = Tree::new(vec![
                dir("/usr"),
                dir("/usr/share"),
                dir("/usr/share/doc"),
                dir("/usr/share/doc/hello"),
                file("/usr/share/doc/hello/README", &readme),
                file("/usr/share/doc/hello/big", &big),
            ])
            .unwrap();
            let trees = BTreeMap::from([(f("runtime"), runtime), (f("doc"), doc)]);
            let licenses = BTreeMap::from([("MIT".to_owned(), LICENSE.to_vec())]);
            let manifest = manifest(&trees, &licenses);
            Self {
                trees,
                licenses,
                manifest,
                files,
            }
        }

        /// Writes the package to `out`, reading from the fixture's files.
        fn write_into(
            &mut self,
            options: &Options,
            spool: &std::path::Path,
            out: &mut impl Write,
        ) -> Result<Written, WriteError> {
            let package = Package {
                manifest: &self.manifest,
                trees: &self.trees,
                licenses: &self.licenses,
                chunking: params(),
            };
            write(&package, &mut self.files, options, spool, out)
        }

        fn write_with(&mut self, options: &Options) -> Result<(Vec<u8>, Written), WriteError> {
            let spool = tempfile::tempdir().unwrap();
            let mut out = Vec::new();
            let written = self.write_into(options, spool.path(), &mut out)?;
            assert_eq!(
                std::fs::read_dir(spool.path()).unwrap().count(),
                0,
                "nothing is left in the spool directory"
            );
            Ok((out, written))
        }

        fn write(&mut self) -> (Vec<u8>, Written) {
            self.write_with(&options()).unwrap()
        }

        fn error(&mut self) -> String {
            self.write_with(&options()).unwrap_err().to_string()
        }
    }

    fn options() -> Options {
        Options {
            level: 19,
            threads: NonZeroUsize::new(3).unwrap(),
        }
    }

    /// The archive's entries, in order.
    fn entries(archive: &[u8]) -> Vec<(String, Vec<u8>)> {
        let mut a = tar::Archive::new(archive);
        a.entries()
            .unwrap()
            .map(|e| {
                let mut e = e.unwrap();
                let h = e.header();
                assert_eq!(h.mode().unwrap(), 0o644);
                assert_eq!((h.uid().unwrap(), h.gid().unwrap()), (0, 0));
                assert_eq!(h.mtime().unwrap(), 0);
                assert_eq!(h.username().unwrap(), Some(""));
                assert_eq!(h.groupname().unwrap(), Some(""));
                assert!(h.entry_type().is_file());
                assert!(h.as_ustar().is_some(), "ustar, not GNU or pax");
                let name = e.path().unwrap().to_string_lossy().into_owned();
                let mut bytes = Vec::new();
                e.read_to_end(&mut bytes).unwrap();
                (name, bytes)
            })
            .collect()
    }

    /// The parts of a written package.
    struct Parts {
        blobs: BTreeMap<String, Vec<u8>>,
        index: Value,
        image: Value,
    }

    fn read(archive: &[u8]) -> Parts {
        let entries = entries(archive);
        let names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names[..2], ["oci-layout", "index.json"]);
        assert_eq!(entries[0].1, OCI_LAYOUT);
        let blobs: BTreeMap<String, Vec<u8>> = entries[2..].iter().cloned().collect();
        let sorted: Vec<&str> = blobs.keys().map(String::as_str).collect();
        assert_eq!(
            names[2..],
            sorted[..],
            "blobs come sorted by path, once each"
        );
        let index: Value = serde_json::from_slice(&entries[1].1).unwrap();
        let image = blob(&blobs, &index["manifests"][0]);
        let image = serde_json::from_slice(&image).unwrap();
        Parts {
            blobs,
            index,
            image,
        }
    }

    /// The blob a descriptor names, after checking both its digests and size.
    fn blob(blobs: &BTreeMap<String, Vec<u8>>, descriptor: &Value) -> Vec<u8> {
        let sha256 = descriptor["digest"].as_str().unwrap();
        let hex = sha256.strip_prefix("sha256:").unwrap();
        let bytes = blobs[&format!("blobs/sha256/{hex}")].clone();
        let id = BlobId::of(&bytes);
        assert_eq!(sha256, id.sha256.to_string());
        assert_eq!(
            descriptor["annotations"][annotations::BLAKE3],
            id.blake3.to_string()
        );
        assert_eq!(descriptor["size"], id.size);
        bytes
    }

    fn layers(r: &Parts) -> &Vec<Value> {
        r.image["layers"].as_array().unwrap()
    }

    /// The layers' bytes with this media type, by facet annotation.
    fn by_facet(r: &Parts, media_type: &str) -> BTreeMap<String, Vec<u8>> {
        layers(r)
            .iter()
            .filter(|l| l["mediaType"] == media_type)
            .map(|l| {
                let facet = l["annotations"][annotations::FACET].as_str().unwrap();
                (facet.to_owned(), blob(&r.blobs, l))
            })
            .collect()
    }

    fn only(r: &Parts, media_type: &str) -> Vec<u8> {
        let found: Vec<&Value> = layers(r)
            .iter()
            .filter(|l| l["mediaType"] == media_type)
            .collect();
        assert_eq!(found.len(), 1, "{media_type}");
        blob(&r.blobs, found[0])
    }

    #[test]
    fn the_file_is_a_deterministic_ustar_archive() {
        let (out, written) = Fixture::new().write();
        assert_eq!(written.size, out.len() as u64);
        let entries = entries(&out);
        let expected: u64 = entries
            .iter()
            .map(|(_, b)| 512 + (b.len() as u64).div_ceil(512) * 512)
            .sum::<u64>()
            + 1024;
        assert_eq!(
            out.len() as u64,
            expected,
            "nothing after the two zero blocks"
        );
        assert!(out[out.len() - 1024..].iter().all(|&b| b == 0));
    }

    #[test]
    fn the_index_points_at_an_ordin_artifact() {
        let (out, written) = Fixture::new().write();
        let r = read(&out);
        assert_eq!(r.index["schemaVersion"], 2);
        assert_eq!(r.index["mediaType"], media::OCI_INDEX);
        let entry = &r.index["manifests"][0];
        assert_eq!(r.index["manifests"].as_array().unwrap().len(), 1);
        assert_eq!(entry["mediaType"], media::OCI_MANIFEST);
        assert_eq!(entry["artifactType"], media::PACKAGE);
        assert_eq!(entry["digest"], written.image.to_string());

        assert_eq!(r.image["schemaVersion"], 2);
        assert_eq!(r.image["mediaType"], media::OCI_MANIFEST);
        assert_eq!(r.image["artifactType"], media::PACKAGE);
        assert_eq!(r.image["config"]["mediaType"], media::OCI_EMPTY);
        assert_eq!(blob(&r.blobs, &r.image["config"]), EMPTY_CONFIG);
    }

    #[test]
    fn layers_come_in_order_with_their_annotations() {
        let (out, _) = Fixture::new().write();
        let r = read(&out);
        let seen: Vec<(String, Option<String>)> = layers(&r)
            .iter()
            .map(|l| {
                let notes = l["annotations"].as_object().unwrap();
                let extra: Vec<String> = notes
                    .iter()
                    .filter(|(k, _)| *k != annotations::BLAKE3)
                    .map(|(k, v)| format!("{k}={}", v.as_str().unwrap()))
                    .collect();
                assert!(extra.len() <= 1);
                (
                    l["mediaType"].as_str().unwrap().to_owned(),
                    extra.first().cloned(),
                )
            })
            .collect();
        let facet = |f: &str| Some(format!("com.ordinpm.facet={f}"));
        assert_eq!(
            seen,
            [
                (media::MANIFEST.to_owned(), None),
                (
                    media::LICENSE.to_owned(),
                    Some("com.ordinpm.license=MIT".to_owned())
                ),
                (media::TREE.to_owned(), facet("doc")),
                (media::TREE.to_owned(), facet("runtime")),
                (media::CHUNK_INDEX.to_owned(), None),
                (media::PACK_TABLE.to_owned(), facet("doc")),
                (media::PACK_TABLE.to_owned(), facet("runtime")),
                (media::CHUNK_PACK.to_owned(), facet("doc")),
                (media::CHUNK_PACK.to_owned(), facet("runtime")),
            ]
        );
        // Every blob is the config, the image manifest or a layer.
        let named: BTreeSet<String> = layers(&r)
            .iter()
            .chain([&r.image["config"], &r.index["manifests"][0]])
            .map(|d| {
                let digest = d["digest"].as_str().unwrap();
                format!("blobs/sha256/{}", digest.strip_prefix("sha256:").unwrap())
            })
            .collect();
        assert_eq!(named, r.blobs.keys().cloned().collect());
    }

    #[test]
    fn the_parts_are_the_packages() {
        let mut fx = Fixture::new();
        let (out, written) = fx.write();
        let r = read(&out);
        let manifest = only(&r, media::MANIFEST);
        assert_eq!(manifest, fx.manifest.to_canonical_bytes().unwrap());
        assert_eq!(written.package, fx.manifest.digest().unwrap());
        assert_eq!(only(&r, media::LICENSE), LICENSE);
        let trees = by_facet(&r, media::TREE);
        assert_eq!(trees.len(), 2);
        for (facet, tree) in &fx.trees {
            assert_eq!(trees[facet.as_str()], tree.to_canonical_bytes().unwrap());
        }
        let (index, digest) =
            ChunkIndex::from_canonical_bytes(&only(&r, media::CHUNK_INDEX)).unwrap();
        assert_eq!(digest, written.chunk_index);
        assert_eq!(index.chunking(), &params());
        // The two large contents are listed once each; small files aren't.
        let big = &fx.files.files["/usr/lib/hello/big"];
        let other = &fx.files.files["/usr/lib/hello/other"];
        let listed: BTreeSet<Digest> = index.files().iter().map(|f| f.content()).collect();
        assert_eq!(
            listed,
            BTreeSet::from([Digest::blake3(big), Digest::blake3(other)])
        );
    }

    #[test]
    fn every_file_can_be_rebuilt_from_its_facets_pack() {
        let mut fx = Fixture::new();
        let (out, _) = fx.write();
        let r = read(&out);
        let (index, _) = ChunkIndex::from_canonical_bytes(&only(&r, media::CHUNK_INDEX)).unwrap();
        let tables = by_facet(&r, media::PACK_TABLE);
        let packs = by_facet(&r, media::CHUNK_PACK);
        let mut stored = BTreeMap::new();
        for (facet, tree) in &fx.trees {
            let table: Value = serde_json::from_slice(&tables[facet.as_str()]).unwrap();
            assert_eq!(table["ordin-pack-table"], 1);
            assert_eq!(table["zstd-level"], 19);
            let pack = &packs[facet.as_str()];
            // Frames are back to back from 0, each chunk once.
            let mut frames = BTreeMap::new();
            let mut at = 0;
            for c in table["chunks"].as_array().unwrap() {
                let offset = c["offset"].as_u64().unwrap();
                let length = c["length"].as_u64().unwrap();
                assert_eq!(offset, at);
                at += length;
                let digest: Digest = c["digest"].as_str().unwrap().parse().unwrap();
                let frame = &pack[offset as usize..at as usize];
                assert!(frames.insert(digest, frame).is_none(), "stored once");
            }
            assert_eq!(at, pack.len() as u64);
            stored.insert(facet.clone(), frames.len());
            for e in tree.entries() {
                let Kind::File(file) = &e.kind else { continue };
                let mut rebuilt = Vec::new();
                for chunk in index.chunks_of(&file.content, file.size).unwrap() {
                    let bytes =
                        zstd::bulk::decompress(frames[&chunk.digest], chunk.length as usize)
                            .unwrap();
                    assert_eq!(Digest::blake3(&bytes), chunk.digest);
                    rebuilt.extend(bytes);
                }
                assert_eq!(rebuilt, fx.files.files[e.path.as_str()], "{}", e.path);
            }
            // Nothing in the pack that no file needs.
            let needed: BTreeSet<Digest> = tree
                .entries()
                .iter()
                .filter_map(|e| match &e.kind {
                    Kind::File(f) => Some(f),
                    _ => None,
                })
                .flat_map(|f| index.chunks_of(&f.content, f.size).unwrap())
                .map(|c| c.digest)
                .collect();
            assert_eq!(needed, frames.keys().copied().collect());
        }
        // The big file's repeated half is stored once: the doc pack holds the
        // README's chunk and big's distinct chunks, fewer than big lists.
        let big = Digest::blake3(&fx.files.files["/usr/lib/hello/big"]);
        let listed = index.get(&big).unwrap().chunks();
        let distinct: BTreeSet<Digest> = listed.iter().map(|c| c.digest).collect();
        assert!(distinct.len() < listed.len());
        assert_eq!(stored[&f("doc")], distinct.len() + 1);
    }

    #[test]
    fn each_content_is_read_once_per_facet() {
        let mut fx = Fixture::new();
        fx.write();
        assert_eq!(
            fx.files.opened,
            [
                // doc, in path order
                "/usr/share/doc/hello/README",
                "/usr/share/doc/hello/big",
                // runtime: the copy, the hard link and the symlink aren't read
                "/usr/bin/hello",
                "/usr/lib/hello/big",
                "/usr/lib/hello/other",
            ]
        );
    }

    #[test]
    fn the_same_package_gives_the_same_bytes_on_any_number_of_threads() {
        let (first, written) = Fixture::new().write();
        for threads in [1, 2, 8] {
            let options = Options {
                level: 19,
                threads: NonZeroUsize::new(threads).unwrap(),
            };
            let (again, w) = Fixture::new().write_with(&options).unwrap();
            assert_eq!(again, first, "{threads} threads");
            assert_eq!(w, written);
        }
        // The same on every architecture CI builds for, with the zstd version
        // Cargo.lock pins. A change here changes every package file.
        assert_eq!(
            BlobId::of(&first).sha256.to_string(),
            "sha256:0c43c0b2ab4f42640f4344fafc0c94a04108271fb90895d73dc900feeb79384c"
        );
    }

    #[test]
    fn the_level_is_recorded_and_changes_only_the_packs() {
        let (fast, _) = Fixture::new()
            .write_with(&Options {
                level: 1,
                threads: NonZeroUsize::MIN,
            })
            .unwrap();
        let (slow, _) = Fixture::new().write();
        let (fast, slow) = (read(&fast), read(&slow));
        for part in [media::MANIFEST, media::LICENSE, media::CHUNK_INDEX] {
            assert_eq!(only(&fast, part), only(&slow, part));
        }
        assert_eq!(by_facet(&fast, media::TREE), by_facet(&slow, media::TREE));
        let table: Value =
            serde_json::from_slice(&by_facet(&fast, media::PACK_TABLE)["doc"]).unwrap();
        assert_eq!(table["zstd-level"], 1);
        assert_ne!(
            by_facet(&fast, media::CHUNK_PACK),
            by_facet(&slow, media::CHUNK_PACK)
        );
    }

    #[test]
    fn levels_are_one_to_twenty_two() {
        for level in [0, -1, 23] {
            let e = Fixture::new()
                .write_with(&Options {
                    level,
                    threads: NonZeroUsize::MIN,
                })
                .unwrap_err();
            assert_eq!(
                e.to_string(),
                format!("the zstd level {level} is outside 1 to 22")
            );
        }
        for level in [1, 22] {
            assert!(
                Fixture::new()
                    .write_with(&Options {
                        level,
                        threads: NonZeroUsize::MIN,
                    })
                    .is_ok()
            );
        }
    }

    #[test]
    fn empty_facets_and_equal_blobs_are_stored_once() {
        let trees = BTreeMap::from([
            (f("runtime"), Tree::new(vec![dir("/usr")]).unwrap()),
            (f("doc"), Tree::new(vec![dir("/usr")]).unwrap()),
        ]);
        let licenses = BTreeMap::from([
            ("MIT".to_owned(), LICENSE.to_vec()),
            ("Apache-2.0".to_owned(), LICENSE.to_vec()),
        ]);
        let manifest = manifest(&trees, &licenses);
        let package = Package {
            manifest: &manifest,
            trees: &trees,
            licenses: &licenses,
            chunking: params(),
        };
        let spool = tempfile::tempdir().unwrap();
        let mut out = Vec::new();
        write(
            &package,
            &mut Files::default(),
            &options(),
            spool.path(),
            &mut out,
        )
        .unwrap();
        let r = read(&out);
        assert_eq!(layers(&r).len(), 10);
        // The manifest, one license text, one tree, the index, one table, one
        // empty pack, the config and the image manifest.
        assert_eq!(r.blobs.len(), 8);
        assert_eq!(by_facet(&r, media::CHUNK_PACK)["doc"], b"");
        let table = &by_facet(&r, media::PACK_TABLE)["runtime"];
        assert_eq!(
            table,
            br#"{"chunks":[],"ordin-pack-table":1,"zstd-level":19}"#
        );
    }

    #[test]
    fn a_manifest_that_breaks_a_rule_is_refused() {
        let mut fx = Fixture::new();
        fx.manifest.summary = "a bell \u{7}".to_owned();
        let e = fx.error();
        assert!(e.starts_with("the manifest: "), "{e}");
        assert!(fx.files.opened.is_empty());
    }

    #[test]
    fn trees_must_be_the_manifests() {
        let mut fx = Fixture::new();
        let doc = fx.trees.remove(&f("doc")).unwrap();
        assert_eq!(
            fx.error(),
            "the manifest lists facet doc, but no tree was given for it"
        );

        fx.trees.insert(f("doc"), doc.clone());
        fx.trees.insert(f("dev"), doc.clone());
        assert_eq!(
            fx.error(),
            "a tree was given for facet dev, which the manifest doesn't list"
        );
        fx.trees.remove(&f("dev"));

        let other = Tree::new(vec![dir("/usr")]).unwrap();
        fx.trees.insert(f("doc"), other.clone());
        assert_eq!(
            fx.error(),
            format!(
                "facet doc: the manifest records tree {}, but the tree given is {}",
                doc.digest().unwrap(),
                other.digest().unwrap()
            )
        );

        fx.trees.insert(f("doc"), doc);
        fx.manifest.facets.get_mut(&f("doc")).unwrap().size += 1;
        let recorded = fx.manifest.facets[&f("doc")].size;
        assert_eq!(
            fx.error(),
            format!(
                "facet doc: the manifest records {recorded} bytes of file content, but its tree has {}",
                recorded - 1
            )
        );
    }

    #[test]
    fn license_texts_must_be_the_manifests() {
        let mut fx = Fixture::new();
        fx.licenses.insert("Apache-2.0".to_owned(), b"x".to_vec());
        assert_eq!(
            fx.error(),
            "a text was given for Apache-2.0, which the manifest's license doesn't record"
        );
        fx.licenses.remove("Apache-2.0");

        fx.licenses.insert("MIT".to_owned(), b"other".to_vec());
        assert_eq!(
            fx.error(),
            format!(
                "the text given for MIT is {}, but the manifest records {}",
                Digest::blake3(b"other"),
                Digest::blake3(LICENSE)
            )
        );

        fx.licenses.clear();
        assert_eq!(fx.error(), "no text was given for the license MIT");
    }

    #[test]
    fn a_license_text_is_at_most_what_a_reader_accepts() {
        let mut fx = Fixture::new();
        let limit = MAX_LICENSE_TEXT as usize;
        fx.licenses.insert("MIT".to_owned(), vec![b'x'; limit]);
        fx.manifest = manifest(&fx.trees, &fx.licenses);
        assert!(fx.write_with(&options()).is_ok());
        fx.licenses.insert("MIT".to_owned(), vec![b'x'; limit + 1]);
        fx.manifest = manifest(&fx.trees, &fx.licenses);
        assert_eq!(
            fx.error(),
            "the text given for MIT has 1048577 bytes, more than the 1048576 a license text may have"
        );
    }

    #[test]
    fn a_file_that_isnt_what_its_tree_records_is_refused() {
        let mut fx = Fixture::new();
        let original = fx.files.files["/usr/bin/hello"].clone();
        // Longer.
        fx.files
            .files
            .insert("/usr/bin/hello".to_owned(), [&original[..], b"!"].concat());
        let e = fx.error();
        assert_eq!(
            e,
            format!(
                "/usr/bin/hello: the tree records {} bytes with content {}, but the file read has {} bytes with content {}",
                original.len(),
                Digest::blake3(&original),
                original.len() + 1,
                Digest::blake3(&[&original[..], b"!"].concat()),
            )
        );
        // The same size, other bytes.
        let mut same_size = original.clone();
        same_size[0] ^= 1;
        fx.files
            .files
            .insert("/usr/bin/hello".to_owned(), same_size.clone());
        assert!(fx.error().ends_with(&format!(
            "the file read has {} bytes with content {}",
            original.len(),
            Digest::blake3(&same_size)
        )));
        // A large file, cut into chunks.
        fx.files.files.insert("/usr/bin/hello".to_owned(), original);
        let mut big = fx.files.files["/usr/lib/hello/other"].clone();
        big[1500] ^= 1;
        fx.files
            .files
            .insert("/usr/lib/hello/other".to_owned(), big);
        assert!(
            fx.error()
                .starts_with("/usr/lib/hello/other: the tree records")
        );
    }

    #[test]
    fn a_file_that_cant_be_read_is_named() {
        let mut fx = Fixture::new();
        fx.files.files.remove("/usr/lib/hello/big");
        assert_eq!(fx.error(), "/usr/lib/hello/big: no such file");

        struct Failing;
        impl Read for Failing {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("read failed"))
            }
        }
        struct FailingSource;
        impl Source for FailingSource {
            type Reader = Failing;
            fn open(&mut self, _: &TreePath, _: &File) -> io::Result<Failing> {
                Ok(Failing)
            }
        }
        let fx = Fixture::new();
        let spool = tempfile::tempdir().unwrap();
        let package = Package {
            manifest: &fx.manifest,
            trees: &fx.trees,
            licenses: &fx.licenses,
            chunking: params(),
        };
        let e = write(
            &package,
            &mut FailingSource,
            &options(),
            spool.path(),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert_eq!(e.to_string(), "/usr/share/doc/hello/README: read failed");
    }

    #[test]
    fn a_spool_directory_that_doesnt_exist_is_an_error() {
        let mut fx = Fixture::new();
        let spool = tempfile::tempdir().unwrap();
        let missing = spool.path().join("missing");
        let e = fx
            .write_into(&options(), &missing, &mut Vec::new())
            .unwrap_err();
        assert!(e.to_string().starts_with("spooling a chunk pack: "), "{e}");
        assert!(fx.files.opened.is_empty());
    }

    /// Fails after `limit` bytes, or on flush.
    struct Output {
        written: usize,
        limit: usize,
        flush_fails: bool,
    }

    impl Write for Output {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.written + buf.len() > self.limit {
                return Err(io::Error::other("no space left"));
            }
            self.written += buf.len();
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            if self.flush_fails {
                return Err(io::Error::other("flush failed"));
            }
            Ok(())
        }
    }

    #[test]
    fn output_errors_are_reported() {
        let (out, _) = Fixture::new().write();
        for (limit, flush_fails, message) in [
            (100, false, "no space left"),
            (out.len() - 1, false, "no space left"),
            (out.len(), true, "flush failed"),
        ] {
            let spool = tempfile::tempdir().unwrap();
            let mut output = Output {
                written: 0,
                limit,
                flush_fails,
            };
            let e = Fixture::new()
                .write_into(&options(), spool.path(), &mut output)
                .unwrap_err();
            assert_eq!(e.to_string(), format!("writing the .ordin file: {message}"));
        }
        let spool = tempfile::tempdir().unwrap();
        let mut output = Output {
            written: 0,
            limit: out.len(),
            flush_fails: false,
        };
        let written = Fixture::new()
            .write_into(&options(), spool.path(), &mut output)
            .unwrap();
        assert_eq!(output.written as u64, written.size);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(24))]

        #[test]
        fn any_package_round_trips_and_repeats(
            contents in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..1500), 1..6),
            threads in 1usize..4,
        ) {
            let mut entries = vec![dir("/usr")];
            let mut files = Files::default();
            for (i, bytes) in contents.iter().enumerate() {
                let path = format!("/usr/f{i}");
                entries.push(file(&path, bytes));
                files.files.insert(path, bytes.clone());
            }
            let trees = BTreeMap::from([(f("runtime"), Tree::new(entries).unwrap())]);
            let licenses = BTreeMap::from([("MIT".to_owned(), LICENSE.to_vec())]);
            let manifest = manifest(&trees, &licenses);
            let package = Package { manifest: &manifest, trees: &trees, licenses: &licenses, chunking: params() };
            let spool = tempfile::tempdir().unwrap();
            let options = Options { level: 3, threads: NonZeroUsize::new(threads).unwrap() };
            let mut a = Vec::new();
            write(&package, &mut files, &options, spool.path(), &mut a).unwrap();
            let mut b = Vec::new();
            let one = Options { level: 3, threads: NonZeroUsize::MIN };
            write(&package, &mut files, &one, spool.path(), &mut b).unwrap();
            prop_assert_eq!(&a, &b);

            let r = read(&a);
            let (index, _) = ChunkIndex::from_canonical_bytes(&only(&r, media::CHUNK_INDEX)).unwrap();
            let table: Value = serde_json::from_slice(&by_facet(&r, media::PACK_TABLE)["runtime"]).unwrap();
            let pack = &by_facet(&r, media::CHUNK_PACK)["runtime"];
            let frames: BTreeMap<Digest, &[u8]> = table["chunks"].as_array().unwrap().iter().map(|c| {
                let offset = c["offset"].as_u64().unwrap() as usize;
                let length = c["length"].as_u64().unwrap() as usize;
                (c["digest"].as_str().unwrap().parse().unwrap(), &pack[offset..offset + length])
            }).collect();
            for (i, bytes) in contents.iter().enumerate() {
                let d = file_digests(&bytes[..]).unwrap();
                let mut rebuilt = Vec::new();
                for chunk in index.chunks_of(&d.content, d.size).unwrap() {
                    rebuilt.extend(zstd::bulk::decompress(frames[&chunk.digest], chunk.length as usize).unwrap());
                }
                prop_assert_eq!(&rebuilt, bytes, "file {}", i);
            }
        }
    }
}
