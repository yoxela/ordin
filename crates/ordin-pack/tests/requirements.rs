// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Requirements and provides from ELF files (ORD-112) and `#!` lines
//! (ORD-113), on ELF files written here with `object`'s writer.

#[cfg(test)]
mod requirements {
    use std::collections::BTreeMap;
    use std::io::{self, Cursor};

    use object::Endianness;
    use object::elf::{
        DT_NEEDED, DT_NULL, DT_SONAME, ELFOSABI_NONE, EM_386, EM_AARCH64, EM_RISCV, EM_X86_64,
        ET_DYN, ET_EXEC, ET_REL, FileFlags, FileType, Machine as EMachine, VER_FLG_BASE,
        VER_FLG_WEAK, VersionFlags, VersionIndex,
    };
    use object::write::elf::{FileHeader, Verdef, Vernaux, Verneed, Writer};
    use ordin_archive::Source;
    use ordin_core::{Account, Arch};
    use ordin_pack::elf::{self, Kind as ElfKind, Machine};
    use ordin_pack::{InferError, InferNote, infer};
    use ordin_tree::{
        DIR_MODE, Dir, Entry, File, Kind, Symlink, Tree, TreePath, Xattrs, file_digests,
    };

    /// The error and each cause after it, as `ordin` prints them.
    fn chain(e: &dyn std::error::Error) -> String {
        let mut text = e.to_string();
        let mut next = e.source();
        while let Some(cause) = next {
            text.push_str(": ");
            text.push_str(&cause.to_string());
            next = cause.source();
        }
        text
    }

    /// What an ELF fixture holds.
    #[derive(Clone, Default)]
    struct Spec {
        machine: u16,
        e_type: u16,
        is_64: bool,
        big: bool,
        soname: Option<&'static str>,
        needed: Vec<&'static str>,
        /// Version definitions, and whether each is the base.
        defines: Vec<(&'static str, bool)>,
        /// Per library, its version needs and whether each is weak.
        needs: Vec<(&'static str, Vec<(&'static str, bool)>)>,
    }

    fn spec(machine: u16, e_type: u16) -> Spec {
        Spec {
            machine,
            e_type,
            is_64: true,
            ..Spec::default()
        }
    }

    /// An ELF file with a dynamic section and the version sections `s`
    /// asks for.
    fn build(s: &Spec) -> Vec<u8> {
        let mut buf = Vec::new();
        let endian = if s.big {
            Endianness::Big
        } else {
            Endianness::Little
        };
        let mut w = Writer::new(endian, s.is_64, &mut buf);
        w.reserve_file_header();
        let soname = s.soname.map(|n| w.add_dynamic_string(n.as_bytes()));
        let needed: Vec<_> = s
            .needed
            .iter()
            .map(|n| w.add_dynamic_string(n.as_bytes()))
            .collect();
        let defines: Vec<_> = s
            .defines
            .iter()
            .map(|(n, base)| (w.add_dynamic_string(n.as_bytes()), *base))
            .collect();
        let needs: Vec<_> = s
            .needs
            .iter()
            .map(|(lib, nodes)| {
                (
                    w.add_dynamic_string(lib.as_bytes()),
                    nodes
                        .iter()
                        .map(|(n, weak)| (w.add_dynamic_string(n.as_bytes()), *weak))
                        .collect::<Vec<_>>(),
                )
            })
            .collect();
        w.reserve_null_section_index();
        w.reserve_dynstr_section_index();
        w.reserve_dynamic_section_index();
        if !defines.is_empty() {
            w.reserve_gnu_verdef_section_index();
        }
        if !needs.is_empty() {
            w.reserve_gnu_verneed_section_index();
        }
        w.reserve_shstrtab_section_index();
        w.reserve_dynstr().unwrap();
        let dynamic = needed.len() + usize::from(soname.is_some()) + 1;
        w.reserve_dynamic(dynamic);
        w.reserve_gnu_verdef(defines.len() as u16, defines.len());
        let aux: usize = needs.iter().map(|(_, n)| n.len()).sum();
        w.reserve_gnu_verneed(needs.len() as u16, aux);
        w.reserve_shstrtab().unwrap();
        w.reserve_section_headers();

        w.write_file_header(&FileHeader {
            os_abi: ELFOSABI_NONE,
            abi_version: 0,
            e_type: FileType(s.e_type),
            e_machine: EMachine(s.machine),
            e_entry: 0,
            e_flags: FileFlags(0),
        })
        .unwrap();
        w.write_dynstr();
        w.write_align_dynamic();
        if let Some(id) = soname {
            w.write_dynamic_string(DT_SONAME, id).unwrap();
        }
        for id in &needed {
            w.write_dynamic_string(DT_NEEDED, *id).unwrap();
        }
        w.write_dynamic(DT_NULL, 0).unwrap();
        if !defines.is_empty() {
            w.write_align_gnu_verdef();
            for (i, (id, base)) in defines.iter().enumerate() {
                let name = w.dynamic_string_offset(Some(*id));
                w.write_gnu_verdef(&Verdef {
                    version: 1,
                    flags: if *base { VER_FLG_BASE } else { VersionFlags(0) },
                    index: VersionIndex(i as u16 + 1),
                    aux_count: 1,
                    name,
                    hash: 0,
                });
            }
        }
        if !needs.is_empty() {
            w.write_align_gnu_verneed();
            let mut index = 2;
            for (lib, nodes) in &needs {
                let file = w.dynamic_string_offset(Some(*lib));
                w.write_gnu_verneed(&Verneed {
                    version: 1,
                    aux_count: nodes.len() as u16,
                    file,
                });
                for (id, weak) in nodes {
                    let name = w.dynamic_string_offset(Some(*id));
                    w.write_gnu_vernaux(&Vernaux {
                        flags: if *weak { VER_FLG_WEAK } else { VersionFlags(0) },
                        index: VersionIndex(index),
                        name,
                        hash: 0,
                    });
                    index += 1;
                }
            }
        }
        w.write_shstrtab();
        w.write_null_section_header();
        w.write_dynstr_section_header(0);
        w.write_dynamic_section_header(0);
        w.write_gnu_verdef_section_header(0);
        w.write_gnu_verneed_section_header(0);
        w.write_shstrtab_section_header();
        drop(w);
        buf
    }

    fn inspected(s: &Spec) -> elf::Info {
        elf::inspect(build(s).as_slice()).unwrap().unwrap()
    }

    /// A program needing libc and libssl, with versions.
    fn program() -> Spec {
        Spec {
            needed: vec!["libc.so.6", "libssl.so.3"],
            needs: vec![
                (
                    "libc.so.6",
                    vec![
                        ("GLIBC_2.34", false),
                        ("GLIBC_2.38", false),
                        ("GLIBC_2.99", true),
                    ],
                ),
                ("libssl.so.3", vec![("OPENSSL_3.0.0", false)]),
            ],
            ..spec(EM_X86_64.0, ET_DYN.0)
        }
    }

    /// A library with a soname and versions.
    fn library(soname: &'static str) -> Spec {
        Spec {
            soname: Some(soname),
            needed: vec!["libc.so.6"],
            defines: vec![(soname, true), ("FOO_1.0", false), ("FOO_1.1", false)],
            ..spec(EM_X86_64.0, ET_DYN.0)
        }
    }

    #[test]
    fn a_program_says_what_it_needs() {
        let info = inspected(&program());
        assert_eq!(info.machine, Machine::X86_64);
        assert_eq!(info.kind, ElfKind::Shared);
        assert_eq!(info.soname, None);
        assert_eq!(
            info.needed,
            [b"libc.so.6".to_vec(), b"libssl.so.3".to_vec()]
        );
        let needs: Vec<(String, String, bool)> = info
            .needs
            .iter()
            .map(|n| {
                (
                    String::from_utf8(n.library.clone()).unwrap(),
                    String::from_utf8(n.node.clone()).unwrap(),
                    n.weak,
                )
            })
            .collect();
        assert_eq!(
            needs,
            [
                ("libc.so.6".into(), "GLIBC_2.34".into(), false),
                ("libc.so.6".into(), "GLIBC_2.38".into(), false),
                ("libc.so.6".into(), "GLIBC_2.99".into(), true),
                ("libssl.so.3".into(), "OPENSSL_3.0.0".into(), false),
            ]
        );
        assert!(info.defines.is_empty());
    }

    #[test]
    fn a_library_says_what_it_defines_without_its_base() {
        let info = inspected(&library("libfoo.so.1"));
        assert_eq!(info.soname, Some(b"libfoo.so.1".to_vec()));
        assert_eq!(info.defines, [b"FOO_1.0".to_vec(), b"FOO_1.1".to_vec()]);
        let exec = inspected(&spec(EM_AARCH64.0, ET_EXEC.0));
        assert_eq!(
            (exec.machine, exec.kind),
            (Machine::Aarch64, ElfKind::Executable)
        );
    }

    #[test]
    fn other_machines_and_kinds_are_read_from_the_header_only() {
        let rel = inspected(&spec(EM_X86_64.0, ET_REL.0));
        assert_eq!(rel.kind, ElfKind::Other);
        let riscv = inspected(&Spec {
            needed: vec!["libc.so.6"],
            ..spec(EM_RISCV.0, ET_DYN.0)
        });
        assert_eq!(
            riscv.machine,
            Machine::Other {
                class64: true,
                little: true,
                machine: EM_RISCV.0
            }
        );
        assert!(riscv.needed.is_empty(), "not read");
        let i386 = inspected(&Spec {
            is_64: false,
            ..spec(EM_386.0, ET_EXEC.0)
        });
        assert_eq!(
            (i386.machine, i386.kind),
            (
                Machine::Other {
                    class64: false,
                    little: true,
                    machine: EM_386.0
                },
                ElfKind::Executable
            )
        );
        let big = inspected(&Spec {
            big: true,
            ..spec(EM_AARCH64.0, ET_DYN.0)
        });
        assert_eq!(
            big.machine,
            Machine::Other {
                class64: true,
                little: false,
                machine: EM_AARCH64.0
            }
        );
    }

    #[test]
    fn files_that_arent_elf_or_are_broken_are_told_apart() {
        assert_eq!(elf::inspect(&b"#!/bin/sh\n"[..]).unwrap(), None);
        assert_eq!(elf::inspect(&b""[..]).unwrap(), None);
        assert_eq!(
            elf::inspect(&b"\x7fELF\x02\x01"[..])
                .unwrap_err()
                .to_string(),
            "the file is too short for an ELF header"
        );
        assert_eq!(elf::inspect(&b"\x7fEL"[..]).unwrap(), None);
        assert!(elf::inspect(&b"\x7fELF\x01\x01"[..]).is_err());
        assert!(elf::inspect(&b"\x7fELF\x02\x02"[..]).is_err());
        let mut truncated = build(&program());
        truncated.truncate(200);
        assert!(elf::inspect(truncated.as_slice()).is_err());
        // Every prefix and every single flipped byte is refused or read,
        // never a panic.
        let whole = build(&program());
        for len in 0..whole.len() {
            let _ = elf::inspect(&whole[..len]);
        }
        for i in 0..whole.len() {
            let mut bent = whole.clone();
            bent[i] ^= 0xff;
            let _ = elf::inspect(bent.as_slice());
        }
    }

    #[test]
    fn counts_are_limited() {
        let names: Vec<&'static str> = (0..=elf::MAX_NEEDED)
            .map(|i| &*Box::leak(format!("lib{i}.so").into_boxed_str()))
            .collect();
        let many = Spec {
            needed: names[..elf::MAX_NEEDED].to_vec(),
            ..spec(EM_X86_64.0, ET_DYN.0)
        };
        assert_eq!(inspected(&many).needed.len(), elf::MAX_NEEDED);
        let too_many = Spec {
            needed: names,
            ..spec(EM_X86_64.0, ET_DYN.0)
        };
        assert_eq!(
            elf::inspect(build(&too_many).as_slice())
                .unwrap_err()
                .to_string(),
            "more than 4096 needed libraries"
        );
    }

    fn names(prefix: &str, n: usize) -> Vec<&'static str> {
        (0..n)
            .map(|i| &*Box::leak(format!("{prefix}{i}").into_boxed_str()))
            .collect()
    }

    #[test]
    fn version_counts_are_limited() {
        let max = elf::MAX_VERSIONS;
        let defines = |n: usize| Spec {
            soname: Some("libmany.so"),
            defines: names("V_", n).into_iter().map(|n| (n, false)).collect(),
            ..spec(EM_X86_64.0, ET_DYN.0)
        };
        assert_eq!(inspected(&defines(max)).defines.len(), max);
        assert_eq!(
            elf::inspect(build(&defines(max + 1)).as_slice())
                .unwrap_err()
                .to_string(),
            "more than 8192 version definitions"
        );
        let needs = |n: usize| Spec {
            needed: vec!["libmany.so"],
            needs: vec![(
                "libmany.so",
                names("V_", n).into_iter().map(|n| (n, false)).collect(),
            )],
            ..spec(EM_X86_64.0, ET_DYN.0)
        };
        assert_eq!(inspected(&needs(max)).needs.len(), max);
        assert_eq!(
            elf::inspect(build(&needs(max + 1)).as_slice())
                .unwrap_err()
                .to_string(),
            "more than 8192 version needs"
        );
    }

    // Inference on a tree, with files from memory.

    #[derive(Default)]
    struct Files(BTreeMap<String, Vec<u8>>);

    impl Source for Files {
        type Reader = Cursor<Vec<u8>>;

        fn open(&mut self, path: &TreePath, _: &File) -> io::Result<Self::Reader> {
            self.0
                .get(path.as_str())
                .cloned()
                .map(Cursor::new)
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such file"))
        }
    }

    fn p(path: &str) -> TreePath {
        path.parse().unwrap()
    }

    /// A tree of `files` (path, bytes, mode), with every directory above
    /// them, and the source to read them from.
    fn tree(files: &[(&str, Vec<u8>, &str)], links: &[(&str, &str)]) -> (Tree, Files) {
        let mut entries = Vec::new();
        let mut dirs = std::collections::BTreeSet::new();
        let mut source = Files::default();
        let mut add_dirs = |path: &str| {
            let mut at = path;
            while let Some((up, _)) = at.rsplit_once('/').filter(|(up, _)| !up.is_empty()) {
                dirs.insert(up.to_owned());
                at = up;
            }
        };
        for (path, bytes, mode) in files {
            add_dirs(path);
            let d = file_digests(bytes.as_slice()).unwrap();
            entries.push(Entry {
                path: p(path),
                kind: Kind::File(File {
                    mode: mode.parse().unwrap(),
                    owner: Account::root(),
                    group: Account::root(),
                    size: d.size,
                    content: d.content,
                    fsverity: d.fsverity,
                    xattrs: Xattrs::new(),
                    capabilities: None,
                }),
            });
            source.0.insert((*path).to_owned(), bytes.clone());
        }
        for (path, target) in links {
            add_dirs(path);
            entries.push(Entry {
                path: p(path),
                kind: Kind::Symlink(Symlink {
                    target: target.parse().unwrap(),
                    owner: Account::root(),
                    group: Account::root(),
                }),
            });
        }
        for d in dirs {
            entries.push(Entry {
                path: p(&d),
                kind: Kind::Dir(Dir {
                    mode: DIR_MODE,
                    owner: Account::root(),
                    group: Account::root(),
                    xattrs: Xattrs::new(),
                }),
            });
        }
        (Tree::new(entries).unwrap(), source)
    }

    fn atoms(list: &[ordin_core::Atom]) -> Vec<String> {
        list.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn programs_need_versions_and_libraries_provide_them() {
        let (t, mut s) = tree(
            &[
                ("/usr/bin/hello", build(&program()), "0755"),
                (
                    "/usr/lib/libfoo.so.1",
                    build(&library("libfoo.so.1")),
                    "0644",
                ),
                (
                    "/usr/lib/x86_64-linux-gnu/libbar.so.2",
                    build(&library("libbar.so.2")),
                    "0644",
                ),
                // Not where the loader looks: meets the package's needs,
                // provides nothing.
                (
                    "/usr/lib/hello/plugins/libplug.so",
                    build(&library("libplug.so")),
                    "0644",
                ),
            ],
            &[],
        );
        let found = infer(&t, &mut s).unwrap();
        assert_eq!(found.arch, Some((Arch::X86_64, p("/usr/bin/hello"))));
        assert_eq!(
            atoms(&found.provides),
            [
                "so:libbar.so.2",
                "so:libbar.so.2@FOO_1.0",
                "so:libbar.so.2@FOO_1.1",
                "so:libfoo.so.1",
                "so:libfoo.so.1@FOO_1.0",
                "so:libfoo.so.1@FOO_1.1",
            ]
        );
        assert_eq!(
            atoms(&found.requires),
            [
                // Needed without a version by the libraries.
                "so:libc.so.6",
                "so:libc.so.6@GLIBC_2.34",
                "so:libc.so.6@GLIBC_2.38",
                "so:libssl.so.3@OPENSSL_3.0.0",
            ]
        );
        assert!(found.notes.is_empty(), "{:?}", found.notes);
    }

    #[test]
    fn what_the_package_ships_itself_isnt_required() {
        let mut needs_own = program();
        needs_own.needed.push("libplug.so");
        needs_own
            .needs
            .push(("libplug.so", vec![("FOO_1.0", false)]));
        let (t, mut s) = tree(
            &[
                ("/usr/bin/hello", build(&needs_own), "0755"),
                (
                    "/usr/lib/hello/libplug.so",
                    build(&library("libplug.so")),
                    "0644",
                ),
                ("/usr/bin/run", b"#!/usr/bin/hello\n".to_vec(), "0755"),
                ("/usr/bin/run2", b"#!/usr/bin/env hi\n".to_vec(), "0755"),
            ],
            &[("/usr/bin/hi", "hello")],
        );
        let found = infer(&t, &mut s).unwrap();
        assert!(!atoms(&found.requires).iter().any(|a| a.contains("libplug")));
        assert!(
            !atoms(&found.requires)
                .iter()
                .any(|a| a.starts_with("file:"))
        );
        assert!(found.provides.is_empty());
    }

    #[test]
    fn private_and_odd_versions_and_names_are_notes() {
        let odd = Spec {
            needed: vec!["libc.so.6", "libweird.so", "lib odd.so", "libonly.so.1"],
            needs: vec![
                (
                    "libc.so.6",
                    vec![("GLIBC_2.34", false), ("GLIBC_PRIVATE", false)],
                ),
                ("libweird.so", vec![("V-1", false), ("V_2", false)]),
                ("libonly.so.1", vec![("ONLY_PRIVATE", false)]),
            ],
            ..spec(EM_X86_64.0, ET_EXEC.0)
        };
        let (t, mut s) = tree(&[("/usr/bin/odd", build(&odd), "0755")], &[]);
        let found = infer(&t, &mut s).unwrap();
        assert_eq!(
            atoms(&found.requires),
            [
                "so:libc.so.6@GLIBC_2.34",
                // Only a private node was needed, so the bare atom stays.
                "so:libonly.so.1",
                // A node the grammar can't hold adds the bare atom.
                "so:libweird.so",
                "so:libweird.so@V_2",
            ]
        );
        let notes: Vec<String> = found.notes.iter().map(ToString::to_string).collect();
        assert_eq!(notes.len(), 4, "{notes:?}");
        assert!(matches!(
            &found.notes[..],
            [
                InferNote::PrivateVersion { .. },
                InferNote::BadVersion { .. },
                InferNote::BadSoname { .. },
                InferNote::PrivateVersion { .. },
            ]
        ));
        let bad_lib = Spec {
            soname: Some("lib bad.so"),
            defines: vec![("V_1", false)],
            ..spec(EM_X86_64.0, ET_DYN.0)
        };
        let bad_node = Spec {
            soname: Some("libgood.so.1"),
            defines: vec![("V-1", false), ("V_1", false)],
            ..spec(EM_X86_64.0, ET_DYN.0)
        };
        let (t, mut s) = tree(
            &[
                ("/usr/lib/libbad.so", build(&bad_lib), "0644"),
                ("/usr/lib/libgood.so.1", build(&bad_node), "0644"),
            ],
            &[],
        );
        let found = infer(&t, &mut s).unwrap();
        assert_eq!(
            atoms(&found.provides),
            ["so:libgood.so.1", "so:libgood.so.1@V_1"]
        );
        assert!(matches!(
            &found.notes[..],
            [InferNote::BadSoname { .. }, InferNote::BadVersion { .. }]
        ));
    }

    #[test]
    fn scripts_need_their_interpreters() {
        let (t, mut s) = tree(
            &[
                ("/usr/bin/a", b"#!/usr/bin/python3\n".to_vec(), "0755"),
                ("/usr/bin/b", b"#!/usr/bin/env perl -w\n".to_vec(), "0750"),
                ("/usr/bin/c", b"#!/bin/sh\n".to_vec(), "0700"),
                ("/usr/bin/d", b"#!/usr/bin/env -S x\n".to_vec(), "0755"),
                // Not executable: never run directly.
                ("/usr/share/x/e.py", b"#!/usr/bin/ruby\n".to_vec(), "0644"),
                // Skipped subtrees.
                (
                    "/usr/share/doc/x/example",
                    b"#!/usr/bin/tcl\n".to_vec(),
                    "0755",
                ),
                (
                    "/usr/lib/debug/x.debug",
                    build(&spec(EM_AARCH64.0, ET_DYN.0)),
                    "0644",
                ),
                ("/usr/bin/plain", b"plain text\n".to_vec(), "0755"),
            ],
            &[],
        );
        let found = infer(&t, &mut s).unwrap();
        assert_eq!(
            atoms(&found.requires),
            [
                "file:/usr/bin/perl",
                "file:/usr/bin/python3",
                "file:/usr/bin/sh"
            ]
        );
        assert_eq!(found.arch, None, "no programs or libraries");
        assert_eq!(found.notes.len(), 1);
        assert_eq!(
            found.notes[0].to_string(),
            "/usr/bin/d: its interpreter isn't recorded: env is given options"
        );
    }

    #[test]
    fn one_package_has_one_architecture() {
        let (t, mut s) = tree(
            &[
                ("/usr/bin/a", build(&spec(EM_X86_64.0, ET_EXEC.0)), "0755"),
                ("/usr/bin/b", build(&spec(EM_AARCH64.0, ET_EXEC.0)), "0755"),
            ],
            &[],
        );
        let e = infer(&t, &mut s).unwrap_err();
        assert!(matches!(e, InferError::Mixed { .. }));
        assert_eq!(
            e.to_string(),
            "/usr/bin/b is built for aarch64, but /usr/bin/a is built for x86_64; a package has one"
        );
        let (t, mut s) = tree(
            &[
                ("/usr/bin/a", build(&spec(EM_AARCH64.0, ET_EXEC.0)), "0755"),
                ("/usr/bin/b", build(&spec(EM_AARCH64.0, ET_DYN.0)), "0755"),
                // An object file doesn't count.
                ("/usr/lib/x.o", build(&spec(EM_X86_64.0, ET_REL.0)), "0644"),
            ],
            &[],
        );
        assert_eq!(infer(&t, &mut s).unwrap().arch.unwrap().0, Arch::Aarch64);
        let i386 = Spec {
            is_64: false,
            ..spec(EM_386.0, ET_EXEC.0)
        };
        let (t, mut s) = tree(&[("/usr/bin/old", build(&i386), "0755")], &[]);
        assert_eq!(
            infer(&t, &mut s).unwrap_err().to_string(),
            "/usr/bin/old is a 32-bit little-endian ELF file for machine 3, and Ordin packages \
             only 64-bit x86_64 and aarch64"
        );
    }

    #[test]
    fn unreadable_elf_files_and_unreadable_files() {
        let mut broken = build(&program());
        broken.truncate(100);
        let (t, mut s) = tree(&[("/usr/bin/broken", broken, "0755")], &[]);
        let found = infer(&t, &mut s).unwrap();
        assert!(found.requires.is_empty());
        assert!(matches!(
            &found.notes[..],
            [InferNote::UnreadableElf { .. }]
        ));
        assert!(
            found.notes[0]
                .to_string()
                .starts_with("/usr/bin/broken: not read as ELF")
        );

        s.0.clear();
        let e = infer(&t, &mut s).unwrap_err();
        assert_eq!(chain(&e), "/usr/bin/broken: no such file");
    }

    #[test]
    fn the_test_program_itself_needs_libc_on_glibc() {
        // This test's own executable is a real, dynamically linked program.
        let exe = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        let info = elf::inspect(exe.as_slice()).unwrap().unwrap();
        let expected = match std::env::consts::ARCH {
            "x86_64" => Machine::X86_64,
            "aarch64" => Machine::Aarch64,
            other => panic!("Ordin builds only for x86_64 and aarch64, not {other}"),
        };
        assert_eq!(info.machine, expected);
        if cfg!(target_env = "gnu") {
            assert!(
                info.needed.contains(&b"libc.so.6".to_vec()),
                "{:?}",
                info.needed
            );
            assert!(
                info.needs
                    .iter()
                    .any(|n| n.library == b"libc.so.6" && n.node.starts_with(b"GLIBC_2.")),
                "{:?}",
                info.needs
            );
        }
    }

    // The whole pipeline, on a real directory.

    fn root_with(files: &[(&str, Vec<u8>, u32)]) -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
        for (path, bytes, mode) in files {
            let at = dir.path().join("root").join(path);
            std::fs::create_dir_all(at.parent().unwrap()).unwrap();
            std::fs::write(&at, bytes).unwrap();
            std::fs::set_permissions(&at, std::fs::Permissions::from_mode(*mode)).unwrap();
        }
        dir
    }

    fn pack_options(root: &std::path::Path) -> ordin_pack::PackOptions {
        ordin_pack::PackOptions {
            root: root.to_path_buf(),
            name: "hello".parse().unwrap(),
            version: "1.0-1".parse().unwrap(),
            arch: None,
            summary: "s".to_owned(),
            license: "NONE".to_owned(),
            license_texts: BTreeMap::new(),
            owners: Vec::new(),
            setuid: std::collections::BTreeSet::new(),
            prefixes: Vec::new(),
            chunking: ordin_tree::chunk::ChunkParams::DEFAULT,
            write: ordin_archive::Options {
                level: 1,
                threads: std::num::NonZeroUsize::MIN,
            },
            signer: None,
        }
    }

    #[test]
    fn packing_records_what_the_files_need_and_provide() {
        let dir = root_with(&[
            ("usr/bin/hello", build(&program()), 0o755),
            ("usr/lib/libfoo.so.1", build(&library("libfoo.so.1")), 0o644),
            ("usr/bin/run", b"#!/usr/bin/env python3\n".to_vec(), 0o755),
            ("usr/bin/odd", b"#!/usr/bin/env -S x\n".to_vec(), 0o755),
        ]);
        let options = pack_options(&dir.path().join("root"));
        let packed = ordin_pack::pack(
            &options,
            &ordin_pack::Output::Named(dir.path().to_path_buf()),
        )
        .unwrap();
        let m = &packed.manifest;
        assert_eq!(m.arch, Arch::X86_64);
        assert_eq!(packed.out, dir.path().join("hello-1.0-1.x86_64.ordin"));
        assert!(packed.out.is_file());
        let requires: Vec<String> = m.requires.iter().map(ToString::to_string).collect();
        assert_eq!(
            requires,
            [
                "file:/usr/bin/python3",
                "so:libc.so.6",
                "so:libc.so.6@GLIBC_2.34",
                "so:libc.so.6@GLIBC_2.38",
                "so:libssl.so.3@OPENSSL_3.0.0",
            ]
        );
        let provides: Vec<String> = m.provides.iter().map(|p| p.atom.to_string()).collect();
        assert_eq!(
            provides,
            [
                "so:libfoo.so.1",
                "so:libfoo.so.1@FOO_1.0",
                "so:libfoo.so.1@FOO_1.1"
            ]
        );
        assert_eq!(packed.inferred.len(), 1);
        assert!(packed.inferred[0].to_string().starts_with("/usr/bin/odd: "));
        // The manifest that was written is the one returned, so the
        // atoms are in its canonical bytes too.
        assert_eq!(m.digest().unwrap(), packed.written.package);
    }

    #[test]
    fn a_given_architecture_must_be_the_files() {
        let dir = root_with(&[("usr/bin/hello", build(&program()), 0o755)]);
        let mut options = pack_options(&dir.path().join("root"));
        options.arch = Some(Arch::Aarch64);
        let out = ordin_pack::Output::Named(dir.path().to_path_buf());
        let e = ordin_pack::pack(&options, &out).unwrap_err();
        assert_eq!(
            e.to_string(),
            "--arch aarch64 was given, but /usr/bin/hello is built for x86_64"
        );
        options.arch = Some(Arch::X86_64);
        assert!(ordin_pack::pack(&options, &out).is_ok());

        let mixed = root_with(&[
            ("usr/bin/a", build(&spec(EM_X86_64.0, ET_EXEC.0)), 0o755),
            ("usr/bin/b", build(&spec(EM_AARCH64.0, ET_EXEC.0)), 0o755),
        ]);
        let e = ordin_pack::pack(
            &pack_options(&mixed.path().join("root")),
            &ordin_pack::Output::Named(mixed.path().to_path_buf()),
        )
        .unwrap_err();
        assert!(matches!(e, ordin_pack::PackError::Infer(_)), "{e}");
        assert_eq!(
            std::fs::read_dir(mixed.path()).unwrap().count(),
            1,
            "nothing written"
        );
    }
}
