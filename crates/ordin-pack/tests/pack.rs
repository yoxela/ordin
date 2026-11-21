// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Rung 0 end to end (ORD-120): real directories packed into `.ordin`
//! files, read back with the `tar` crate and serde_json.

#[cfg(test)]
mod packing {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs::{self, FileTimes, Permissions};
    use std::io::Read;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::Path;
    use std::time::{Duration, SystemTime};

    use ordin_archive::{Options as WriteOptions, Source, media};
    use ordin_core::{Arch, Digest, Facet};
    use ordin_manifest::{Manifest, Merge};
    use ordin_pack::{OwnerOverride, PackError, PackOptions, Packed, RootSource, pack};
    use ordin_tree::chunk::{ChunkIndex, ChunkParams};
    use ordin_tree::{Kind, Tree, TreePath};
    use serde_json::Value;
    use tempfile::TempDir;

    fn temp() -> TempDir {
        tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap()
    }

    fn p(path: &str) -> TreePath {
        path.parse().unwrap()
    }

    fn write(root: &Path, path: &str, bytes: &[u8], mode: u32) {
        let at = root.join(path);
        fs::create_dir_all(at.parent().unwrap()).unwrap();
        fs::write(&at, bytes).unwrap();
        fs::set_permissions(&at, Permissions::from_mode(mode)).unwrap();
    }

    fn mkdir(root: &Path, path: &str) {
        let at = root.join(path);
        fs::create_dir_all(&at).unwrap();
        fs::set_permissions(&at, Permissions::from_mode(0o755)).unwrap();
    }

    /// Text large enough to be cut into chunks at the small settings.
    fn big() -> Vec<u8> {
        (0..400)
            .flat_map(|i| format!("line {i} of a large file, {}\n", i * 7919 % 1000).into_bytes())
            .collect()
    }

    /// An install root with a program, a setuid helper, config, state, a
    /// seed, docs, debug info and a large file. `reversed` creates
    /// everything in the opposite order, so directory order differs.
    fn root(at: &Path, reversed: bool) {
        let mut steps: Vec<Box<dyn Fn()>> = vec![
            Box::new(|| write(at, "usr/bin/hello", b"#!/bin/sh\necho hello\n", 0o755)),
            Box::new(|| write(at, "usr/bin/helper", b"helper\n", 0o4755)),
            Box::new(|| write(at, "bin/legacy", b"legacy\n", 0o755)),
            Box::new(|| write(at, "etc/hello.conf", b"greeting=hi\n", 0o644)),
            Box::new(|| mkdir(at, "var/lib/hello")),
            Box::new(|| write(at, "var/lib/hello/seed.db", b"seed\n", 0o644)),
            Box::new(|| write(at, "usr/share/doc/hello/README", b"Says hello.\n", 0o644)),
            Box::new(|| write(at, "usr/lib/debug/hello.debug", b"debug\n", 0o644)),
            Box::new(|| write(at, "usr/lib/hello/big", &big(), 0o644)),
        ];
        if reversed {
            steps.reverse();
        }
        for step in steps {
            step();
        }
    }

    fn options(root: &Path) -> PackOptions {
        PackOptions {
            root: root.to_path_buf(),
            name: "hello".parse().unwrap(),
            version: "2.12-1".parse().unwrap(),
            arch: Arch::X86_64,
            summary: "Prints a friendly greeting".to_owned(),
            license: "MIT".to_owned(),
            license_texts: BTreeMap::from([("MIT".to_owned(), b"MIT License\n".to_vec())]),
            owners: vec![
                "/usr/bin/helper=root:wheel"
                    .parse::<OwnerOverride>()
                    .unwrap(),
            ],
            setuid: BTreeSet::from([p("/usr/bin/helper")]),
            prefixes: Vec::new(),
            chunking: ChunkParams::new(64, 256, 1024, 256, 1).unwrap(),
            write: WriteOptions {
                level: 3,
                threads: std::num::NonZeroUsize::new(2).unwrap(),
            },
        }
    }

    fn packed(options: &PackOptions, out: &Path) -> (Packed, Vec<u8>) {
        let packed = pack(options, out).unwrap();
        (packed, fs::read(out).unwrap())
    }

    /// The archive's blobs by layer, as (media type, facet, bytes).
    fn layers(file: &[u8]) -> Vec<(String, Option<String>, Vec<u8>)> {
        let mut archive = tar::Archive::new(file);
        let blobs: BTreeMap<String, Vec<u8>> = archive
            .entries()
            .unwrap()
            .map(|e| {
                let mut e = e.unwrap();
                let name = e.path().unwrap().to_string_lossy().into_owned();
                let mut bytes = Vec::new();
                e.read_to_end(&mut bytes).unwrap();
                (name, bytes)
            })
            .collect();
        let blob = |d: &Value| {
            let hex = d["digest"]
                .as_str()
                .unwrap()
                .strip_prefix("sha256:")
                .unwrap();
            blobs[&format!("blobs/sha256/{hex}")].clone()
        };
        let index: Value = serde_json::from_slice(&blobs["index.json"]).unwrap();
        let image: Value = serde_json::from_slice(&blob(&index["manifests"][0])).unwrap();
        image["layers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| {
                (
                    l["mediaType"].as_str().unwrap().to_owned(),
                    l["annotations"]["com.ordinpm.facet"]
                        .as_str()
                        .map(str::to_owned),
                    blob(l),
                )
            })
            .collect()
    }

    /// Every file of every facet, rebuilt from the package's packs.
    fn rebuilt(file: &[u8]) -> BTreeMap<String, Vec<u8>> {
        let layers = layers(file);
        let one = |media: &str| {
            layers
                .iter()
                .find(|(m, _, _)| m == media)
                .map(|(_, _, b)| b.clone())
                .unwrap()
        };
        let facet = |media: &str| -> BTreeMap<String, Vec<u8>> {
            layers
                .iter()
                .filter(|(m, _, _)| m == media)
                .map(|(_, f, b)| (f.clone().unwrap(), b.clone()))
                .collect()
        };
        let (index, _) = ChunkIndex::from_canonical_bytes(&one(media::CHUNK_INDEX)).unwrap();
        let (trees, tables, packs) = (
            facet(media::TREE),
            facet(media::PACK_TABLE),
            facet(media::CHUNK_PACK),
        );
        let mut files = BTreeMap::new();
        for (name, tree) in &trees {
            let (tree, _) = Tree::from_canonical_bytes(tree).unwrap();
            let table: Value = serde_json::from_slice(&tables[name]).unwrap();
            let frames: BTreeMap<Digest, (usize, usize)> = table["chunks"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| {
                    let offset = c["offset"].as_u64().unwrap() as usize;
                    let length = c["length"].as_u64().unwrap() as usize;
                    (
                        c["digest"].as_str().unwrap().parse().unwrap(),
                        (offset, offset + length),
                    )
                })
                .collect();
            for e in tree.entries() {
                let Kind::File(f) = &e.kind else { continue };
                let mut bytes = Vec::new();
                for chunk in index.chunks_of(&f.content, f.size).unwrap() {
                    let (from, to) = frames[&chunk.digest];
                    bytes.extend(
                        zstd::bulk::decompress(&packs[name][from..to], chunk.length as usize)
                            .unwrap(),
                    );
                }
                files.insert(e.path.to_string(), bytes);
            }
        }
        files
    }

    #[test]
    fn an_install_root_becomes_a_package() {
        let dir = temp();
        root(&dir.path().join("root"), false);
        let out = dir.path().join("hello.ordin");
        let (packed, file) = packed(&options(&dir.path().join("root")), &out);
        let m = &packed.manifest;
        assert_eq!(packed.written.package, m.digest().unwrap());
        assert_eq!(packed.written.size, file.len() as u64);
        assert_eq!(m.license.spdx, "MIT");
        assert_eq!(m.license.texts["MIT"], Digest::blake3(b"MIT License\n"));

        let facets: Vec<(String, bool)> = m
            .facets
            .iter()
            .map(|(f, e)| (f.to_string(), e.default))
            .collect();
        assert_eq!(
            facets,
            [
                ("debug".to_owned(), false),
                ("doc".to_owned(), true),
                ("runtime".to_owned(), true)
            ]
        );
        // Config, state and the declared setuid file.
        let config: Vec<(String, String, Merge)> = m
            .declares
            .config
            .iter()
            .map(|c| (c.default.to_string(), c.target.to_string(), c.merge))
            .collect();
        assert_eq!(
            config,
            [(
                "/usr/share/ordin/defaults/hello/hello.conf".to_owned(),
                "/etc/hello.conf".to_owned(),
                Merge::ThreeWay
            )]
        );
        let state = m.state.as_ref().unwrap();
        assert_eq!(state.paths[0].path.to_string(), "/var/lib/hello");
        assert_eq!(state.seeds[0].path.to_string(), "/var/lib/hello/seed.db");
        let setuid: Vec<String> = m.declares.setuid.iter().map(ToString::to_string).collect();
        assert_eq!(setuid, ["/usr/bin/helper"]);
        assert!(packed.warnings.is_empty(), "{:?}", packed.warnings);

        // The file is readable by everyone, and nothing else is left.
        let mode = fs::metadata(&out).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
        let names: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        assert_eq!(names, ["hello.ordin", "root"]);

        // Every file comes back, from where the layout moved it.
        let files = rebuilt(&file);
        let expect = BTreeMap::from([
            (
                "/usr/bin/hello".to_owned(),
                b"#!/bin/sh\necho hello\n".to_vec(),
            ),
            ("/usr/bin/helper".to_owned(), b"helper\n".to_vec()),
            ("/usr/bin/legacy".to_owned(), b"legacy\n".to_vec()),
            ("/usr/lib/debug/hello.debug".to_owned(), b"debug\n".to_vec()),
            ("/usr/lib/hello/big".to_owned(), big()),
            (
                "/usr/share/doc/hello/README".to_owned(),
                b"Says hello.\n".to_vec(),
            ),
            (
                "/usr/share/ordin/defaults/hello/hello.conf".to_owned(),
                b"greeting=hi\n".to_vec(),
            ),
            (
                "/usr/share/ordin/seeds/hello/var/lib/hello/seed.db".to_owned(),
                b"seed\n".to_vec(),
            ),
        ]);
        assert_eq!(files, expect);
        // The manifest in the file is the one returned.
        let (_, _, bytes) = &layers(&file)[0];
        assert_eq!(Manifest::from_signed_bytes(bytes).unwrap().0, *m);
    }

    #[test]
    fn the_same_root_gives_the_same_file_wherever_and_whenever_it_was_made() {
        let dir = temp();
        let (a, b) = (dir.path().join("a/root"), dir.path().join("b/elsewhere"));
        root(&a, false);
        root(&b, true);
        let old = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        for e in fs::read_dir(b.join("usr/bin")).unwrap() {
            let f = fs::File::options()
                .write(true)
                .open(e.unwrap().path())
                .unwrap();
            f.set_times(FileTimes::new().set_modified(old).set_accessed(old))
                .unwrap();
        }
        let (pa, fa) = packed(&options(&a), &dir.path().join("a.ordin"));
        let (pb, fb) = packed(&options(&b), &dir.path().join("b.ordin"));
        assert_eq!(pa.written, pb.written);
        assert_eq!(fa, fb);
    }

    #[test]
    fn an_existing_file_is_replaced_and_a_failed_write_leaves_it() {
        let dir = temp();
        root(&dir.path().join("root"), false);
        let out = dir.path().join("hello.ordin");
        fs::write(&out, b"old").unwrap();
        let mut o = options(&dir.path().join("root"));
        let (_, file) = packed(&o, &out);
        assert_ne!(file, b"old");

        // A level the writer refuses fails after the temporary file is made.
        fs::write(&out, b"old").unwrap();
        o.write.level = 0;
        let e = pack(&o, &out).unwrap_err();
        assert_eq!(e.to_string(), "the zstd level 0 is outside 1 to 22");
        assert_eq!(fs::read(&out).unwrap(), b"old");
        assert_eq!(
            fs::read_dir(dir.path()).unwrap().count(),
            2,
            "no temporary file left"
        );
    }

    #[test]
    fn noassertion_needs_no_text() {
        let dir = temp();
        root(&dir.path().join("root"), false);
        let mut o = options(&dir.path().join("root"));
        o.license = "NOASSERTION".to_owned();
        o.license_texts.clear();
        let (p, file) = packed(&o, &dir.path().join("x.ordin"));
        assert!(p.manifest.license.texts.is_empty());
        assert!(layers(&file).iter().all(|(m, _, _)| m != media::LICENSE));
    }

    #[test]
    fn licenses_must_match_their_texts() {
        let dir = temp();
        root(&dir.path().join("root"), false);
        let out = dir.path().join("x.ordin");
        let mut o = options(&dir.path().join("root"));
        o.license = "MIT AND".to_owned();
        assert!(
            pack(&o, &out)
                .unwrap_err()
                .to_string()
                .starts_with("the license \"MIT AND\": ")
        );
        o.license = "MIT OR Apache-2.0".to_owned();
        let e = pack(&o, &out).unwrap_err();
        assert!(matches!(&e, PackError::MissingLicenseText(id) if id == "Apache-2.0"));
        assert_eq!(e.to_string(), "the license Apache-2.0 has no text");
        o.license = "NONE".to_owned();
        assert_eq!(
            pack(&o, &out).unwrap_err().to_string(),
            "a text was given for MIT, which the license NONE doesn't name"
        );
        assert!(!out.exists());
    }

    #[test]
    fn declared_setuid_files_must_be_setuid_files_in_the_package() {
        let dir = temp();
        root(&dir.path().join("root"), false);
        let out = dir.path().join("x.ordin");
        let mut o = options(&dir.path().join("root"));
        o.setuid.insert(p("/usr/bin/hello"));
        assert_eq!(
            pack(&o, &out).unwrap_err().to_string(),
            "/usr/bin/hello: declared setuid or setgid, but the file is neither"
        );
        o.setuid = BTreeSet::from([p("/usr/bin/helper"), p("/usr/bin/missing")]);
        assert_eq!(
            pack(&o, &out).unwrap_err().to_string(),
            "/usr/bin/missing: declared setuid or setgid, but no file in the package came from it"
        );
        // A directory came from somewhere, but isn't a setuid file.
        o.setuid = BTreeSet::from([p("/usr/share")]);
        assert_eq!(
            pack(&o, &out).unwrap_err().to_string(),
            "/usr/share: declared setuid or setgid, but the file is neither"
        );
        // Undeclared, it is packed with a warning.
        o.setuid.clear();
        let (p, _) = packed(&o, &out);
        assert!(p.manifest.declares.setuid.is_empty());
        assert_eq!(p.warnings.len(), 1);
        assert_eq!(p.warnings[0].path.as_str(), "/usr/bin/helper");
    }

    #[test]
    fn the_output_must_be_outside_the_install_root() {
        let dir = temp();
        let r = dir.path().join("root");
        root(&r, false);
        let o = options(&r);
        for out in [r.join("x.ordin"), r.join("usr/x.ordin")] {
            let e = pack(&o, &out).unwrap_err();
            assert!(matches!(e, PackError::OutputInsideRoot { .. }), "{e}");
            assert!(!out.exists());
        }
        // Through a symlink to the root, too.
        symlink(&r, dir.path().join("link")).unwrap();
        let e = pack(&o, &dir.path().join("link/x.ordin")).unwrap_err();
        assert!(
            e.to_string().ends_with(&format!(
                "the package can't be written inside the directory it packs ({})",
                r.display()
            )),
            "{e}"
        );
        // A missing output directory or root.
        let e = pack(&o, &dir.path().join("missing/x.ordin")).unwrap_err();
        assert!(matches!(e, PackError::Output { .. }), "{e}");
        let e = pack(
            &options(&dir.path().join("nothing")),
            &dir.path().join("x.ordin"),
        )
        .unwrap_err();
        assert!(matches!(e, PackError::Root { .. }), "{e}");
    }

    #[test]
    fn any_one_kind_of_state_is_declared() {
        let dir = temp();
        type Make = fn(&Path);
        let cases: [(&str, Make); 4] = [
            ("paths", |r| mkdir(r, "var/lib/hello")),
            ("files", |r| write(r, "var/lib/empty", b"", 0o644)),
            ("seeds", |r| write(r, "var/lib/seed", b"seed\n", 0o644)),
            ("none", |r| mkdir(r, "var/lib")),
        ];
        for (name, make) in cases {
            let r = dir.path().join(name);
            write(&r, "usr/bin/x", b"x", 0o755);
            make(&r);
            let mut o = options(&r);
            o.setuid.clear();
            o.owners.clear();
            let (p, _) = packed(&o, &dir.path().join(format!("{name}.ordin")));
            let state = p.manifest.state.as_ref();
            let counts = state.map(|s| (s.paths.len(), s.files.len(), s.seeds.len()));
            let expected = match name {
                "paths" => Some((1, 0, 0)),
                "files" => Some((0, 1, 0)),
                "seeds" => Some((0, 0, 1)),
                _ => None,
            };
            assert_eq!(counts, expected, "{name}");
        }
    }

    #[test]
    fn a_manifest_that_breaks_a_rule_is_refused_before_writing() {
        let dir = temp();
        root(&dir.path().join("root"), false);
        let mut o = options(&dir.path().join("root"));
        o.summary = String::new();
        let out = dir.path().join("x.ordin");
        let e = pack(&o, &out).unwrap_err();
        assert!(matches!(e, PackError::Manifest(_)), "{e}");
        assert!(e.to_string().starts_with("the manifest: summary"), "{e}");
        assert!(!out.exists());
    }

    #[test]
    fn an_output_directory_that_cant_be_written_is_an_error() {
        let dir = temp();
        root(&dir.path().join("root"), false);
        let ro = dir.path().join("ro");
        fs::create_dir(&ro).unwrap();
        fs::set_permissions(&ro, Permissions::from_mode(0o555)).unwrap();
        let out = ro.join("x.ordin");
        let e = pack(&options(&dir.path().join("root")), &out).unwrap_err();
        fs::set_permissions(&ro, Permissions::from_mode(0o755)).unwrap();
        assert!(
            e.to_string().starts_with(&format!("{}: ", out.display())),
            "{e}"
        );
        assert!(matches!(e, PackError::Output { .. }));
        assert_eq!(fs::read_dir(&ro).unwrap().count(), 0);
    }

    #[test]
    fn walk_layout_and_facet_errors_are_passed_on() {
        let dir = temp();
        let r = dir.path().join("root");
        write(&r, "srv/x", b"x", 0o644);
        let mut o = options(&r);
        o.setuid.clear();
        o.owners.clear();
        let e = pack(&o, &dir.path().join("x.ordin")).unwrap_err();
        assert!(matches!(e, PackError::Layout(_)), "{e}");
        fs::remove_dir_all(r.join("srv")).unwrap();
        write(&r, "usr/bin/x", b"x", 0o644);
        o.owners = vec!["/usr/nothing=root:root".parse().unwrap()];
        let e = pack(&o, &dir.path().join("x.ordin")).unwrap_err();
        assert!(matches!(e, PackError::Walk(_)), "{e}");
    }

    fn source_of(root: &Path, origins: &[(&str, &str)]) -> RootSource {
        let origins = origins.iter().map(|(a, b)| (p(a), p(b))).collect();
        RootSource::new(root, origins).unwrap()
    }

    fn file_entry() -> ordin_tree::File {
        let d = ordin_tree::file_digests(&b""[..]).unwrap();
        ordin_tree::File {
            mode: ordin_tree::FILE_MODE,
            owner: ordin_core::Account::root(),
            group: ordin_core::Account::root(),
            size: d.size,
            content: d.content,
            fsverity: d.fsverity,
            xattrs: ordin_tree::Xattrs::new(),
            capabilities: None,
        }
    }

    fn read(s: &mut RootSource, path: &str) -> std::io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        s.open(&p(path), &file_entry())?.read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    #[test]
    fn the_source_reads_files_where_they_came_from() {
        let dir = temp();
        write(dir.path(), "bin/x", b"x", 0o644);
        write(dir.path(), "top", b"top", 0o644);
        let mut s = source_of(dir.path(), &[("/usr/bin/x", "/bin/x")]);
        assert_eq!(read(&mut s, "/usr/bin/x").unwrap(), b"x");
        assert_eq!(read(&mut s, "/top").unwrap(), b"top");
        assert!(RootSource::new(&dir.path().join("top"), BTreeMap::new()).is_err());
    }

    #[test]
    fn the_source_never_follows_a_symlink_or_reads_a_fifo() {
        let dir = temp();
        let outside = temp();
        write(outside.path(), "secret", b"secret", 0o644);
        write(dir.path(), "usr/bin/x", b"x", 0o644);
        let mut s = source_of(dir.path(), &[]);
        // The file swapped for a symlink.
        fs::remove_file(dir.path().join("usr/bin/x")).unwrap();
        symlink(outside.path().join("secret"), dir.path().join("usr/bin/x")).unwrap();
        assert!(read(&mut s, "/usr/bin/x").is_err());
        // A directory on the way swapped for a symlink.
        fs::remove_dir_all(dir.path().join("usr")).unwrap();
        symlink(outside.path(), dir.path().join("usr")).unwrap();
        assert!(read(&mut s, "/usr/secret").is_err());
        // A FIFO, which would block a reader.
        fs::remove_file(dir.path().join("usr")).unwrap();
        mkdir(dir.path(), "usr");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            dir.path().join("usr/fifo"),
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o644),
            0,
        )
        .unwrap();
        assert_eq!(
            read(&mut s, "/usr/fifo").unwrap_err().to_string(),
            "it is a FIFO now, not a regular file"
        );
        // A file where a directory was.
        write(dir.path(), "usr/notdir", b"", 0o644);
        assert!(read(&mut s, "/usr/notdir/x").is_err());
        // A directory where a file was.
        assert_eq!(
            read(&mut s, "/usr").unwrap_err().to_string(),
            "it is a directory now, not a regular file"
        );
    }

    #[test]
    fn facets_follow_the_classification() {
        let dir = temp();
        root(&dir.path().join("root"), false);
        let (p, _) = packed(
            &options(&dir.path().join("root")),
            &dir.path().join("x.ordin"),
        );
        let debug = Facet::debug();
        assert!(!p.manifest.facets[&debug].default);
        assert!(p.notes.is_empty());
    }
}
