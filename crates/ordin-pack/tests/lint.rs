// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! `ordin lint` (ORD-151): packages made with likely mistakes, packed and
//! read back, and what the recipe's allows accept.

#[cfg(test)]
mod support;

#[cfg(test)]
mod lint {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs::{self, File, Permissions};
    use std::io::{BufReader, Read, Seek, SeekFrom, Write};
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::{Path, PathBuf};

    use object::elf::{EM_386, EM_X86_64, ET_DYN, ET_EXEC};
    use ordin_archive::Reader;
    use ordin_pack::{
        Finding, LintError, LintReport, Output, PackError, PackOptions, known_interpreter, lint,
        pack,
    };
    use ordin_recipe::Allow;
    use tempfile::TempDir;

    use crate::support::elf::{Spec, build, spec};

    fn temp() -> TempDir {
        tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap()
    }

    enum Item {
        File(&'static str, Vec<u8>, u32),
        Dir(&'static str, u32),
        Link(&'static str, &'static str),
        HardLink(&'static str, &'static str),
    }
    use Item::{Dir, File as F, HardLink, Link};

    /// An install root at `dir/root` holding `items`.
    fn root(dir: &Path, items: &[Item]) -> PathBuf {
        let root = dir.join("root");
        fs::create_dir_all(&root).unwrap();
        for item in items {
            match item {
                F(path, bytes, mode) => {
                    let at = root.join(path);
                    fs::create_dir_all(at.parent().unwrap()).unwrap();
                    fs::write(&at, bytes).unwrap();
                    fs::set_permissions(&at, Permissions::from_mode(*mode)).unwrap();
                }
                Dir(path, mode) => {
                    let at = root.join(path);
                    fs::create_dir_all(&at).unwrap();
                    fs::set_permissions(&at, Permissions::from_mode(*mode)).unwrap();
                }
                Link(path, target) => {
                    let at = root.join(path);
                    fs::create_dir_all(at.parent().unwrap()).unwrap();
                    symlink(target, &at).unwrap();
                }
                HardLink(path, to) => fs::hard_link(root.join(to), root.join(path)).unwrap(),
            }
        }
        root
    }

    fn options(root: &Path, recipe: &str) -> PackOptions {
        let recipe = ordin_recipe::parse(&format!("format = 1\n{recipe}")).unwrap();
        PackOptions {
            root: root.to_path_buf(),
            name: "hello".parse().unwrap(),
            version: "1.0-1".parse().unwrap(),
            arch: None,
            summary: "s".to_owned(),
            description: None,
            homepage: None,
            license: "MIT".to_owned(),
            presentation: ordin_manifest::Presentation::Informational,
            license_texts: BTreeMap::from([("MIT".to_owned(), b"MIT License\n".to_vec())]),
            owners: Vec::new(),
            setuid: BTreeSet::new(),
            prefixes: Vec::new(),
            chunking: ordin_tree::chunk::ChunkParams::DEFAULT,
            write: ordin_archive::Options {
                level: 1,
                threads: std::num::NonZeroUsize::MIN,
            },
            signer: None,
            commit: None,
            declared: recipe.declared,
        }
    }

    /// Packs `options` into `dir` and returns the file.
    fn packed(dir: &Path, options: &PackOptions) -> PathBuf {
        pack(options, &Output::Named(dir.to_path_buf()))
            .unwrap()
            .out
    }

    fn allows(recipe: &str) -> Vec<Allow> {
        ordin_recipe::parse(&format!("format = 1\n{recipe}"))
            .unwrap()
            .lint
    }

    fn linted(file: &Path, allows: &[Allow]) -> Result<LintReport, LintError> {
        let mut reader = Reader::open(BufReader::new(File::open(file).unwrap())).unwrap();
        lint(&mut reader, allows)
    }

    /// Each warning as (ID, path, message).
    fn seen(found: &[Finding]) -> Vec<(String, Option<String>, String)> {
        found
            .iter()
            .map(|f| (f.check.id().to_owned(), f.path.clone(), f.message.clone()))
            .collect()
    }

    fn w(id: &str, path: Option<&str>, message: &str) -> (String, Option<String>, String) {
        (id.to_owned(), path.map(str::to_owned), message.to_owned())
    }

    /// A program needing libc, as a real one does.
    fn program() -> Spec {
        Spec {
            needed: vec!["libc.so.6"],
            needs: vec![("libc.so.6", vec![("GLIBC_2.34", false)])],
            ..spec(EM_X86_64.0, ET_DYN.0)
        }
    }

    #[test]
    fn a_clean_package_has_no_warnings() {
        let dir = temp();
        let root = root(
            dir.path(),
            &[
                F("usr/bin/hello", build(&program()), 0o755),
                F("usr/bin/run", b"#!/bin/sh\nexec hello\n".to_vec(), 0o755),
                F("usr/share/doc/hello/README", b"Hello.\n".to_vec(), 0o644),
                F("usr/include/hello.h", b"int hello(void);\n".to_vec(), 0o644),
                Link("usr/lib/libhello.so", "libhello.so.1"),
                F("usr/lib/libhello.so.1", b"not elf\n".to_vec(), 0o644),
            ],
        );
        let file = packed(
            dir.path(),
            &options(&root, "[package]\nrequires = [\"so:libc.so.6\"]\n"),
        );
        // The development link moved to dev on purpose.
        let report = linted(&file, &[]).unwrap();
        assert_eq!(
            seen(&report.warnings),
            [w(
                "facet-misclassified",
                Some("/usr/lib/libhello.so"),
                "looks like a development link, but it is in runtime"
            )]
        );
        assert_eq!(
            report.warnings[0].hint.as_deref(),
            Some("move it with [facets.dev] extra = [\"/usr/lib/libhello.so\"] in the recipe")
        );
        let options = options(
            &root,
            "[package]\nrequires = [\"so:libc.so.6\"]\n[facets.dev]\nextra = [\"/usr/lib/libhello.so\"]\n",
        );
        let file = packed(dir.path(), &options);
        assert_eq!(linted(&file, &[]).unwrap(), LintReport::default());
    }

    /// An install root with one of each mistake, and things that look
    /// like mistakes but aren't.
    fn mistakes(dir: &Path) -> PackOptions {
        let prog = Spec {
            needed: vec!["libc.so.6", "libplain.so", "lib bad.so", "libodd.so.1"],
            needs: vec![
                (
                    "libc.so.6",
                    vec![("GLIBC_2.34", false), ("GLIBC_PRIVATE", false)],
                ),
                ("libodd.so.1", vec![("ODD-1", false)]),
            ],
            ..program()
        };
        let root = root(
            dir,
            &[
                F("usr/bin/prog", build(&prog), 0o755),
                F(
                    "usr/lib/hello/broken",
                    b"\x7fELF\x02\x01\x01".to_vec(),
                    0o644,
                ),
                // Setuid and setgid, declared and not.
                F("usr/bin/su", b"su\n".to_vec(), 0o4755),
                F("usr/bin/sg", b"sg\n".to_vec(), 0o2755),
                F("usr/bin/both", b"both\n".to_vec(), 0o6755),
                F("usr/bin/declared", b"declared\n".to_vec(), 0o4755),
                // A hard link to a declared file is the same file.
                F("usr/bin/alink", b"linked\n".to_vec(), 0o4755),
                HardLink("usr/bin/zlink", "usr/bin/alink"),
                // Writable by anyone.
                Dir("usr/share/hello/drop", 0o777),
                F("usr/share/hello/open", b"open\n".to_vec(), 0o666),
                F("usr/share/hello/fine", b"fine\n".to_vec(), 0o664),
                // Scripts.
                F("usr/bin/odd", b"#!/usr/bin/env -S x\n".to_vec(), 0o755),
                F("usr/bin/typo", b"#!/usr/bin/pyhton3\n".to_vec(), 0o755),
                F("usr/bin/py", b"#!/usr/bin/python3.12\n".to_vec(), 0o755),
                F("usr/bin/mine", b"#!/usr/lib/hello/own\n".to_vec(), 0o755),
                F("usr/lib/hello/own", b"own\n".to_vec(), 0o755),
                F("usr/bin/shell", b"#!/bin/sh\n".to_vec(), 0o755),
                // Files that look like another facet's.
                F("usr/man/man1/hello.1", b".TH\n".to_vec(), 0o644),
                F("usr/share/hello/man/man8/hello.8", b".TH\n".to_vec(), 0o644),
                F("usr/share/hello/man/man1", b"a file\n".to_vec(), 0o644),
                F("usr/share/hello/mann/man1/x", b"x\n".to_vec(), 0o644),
                F("usr/share/tcl/man/mann/foo.n", b".TH\n".to_vec(), 0o644),
                F(
                    "usr/share/other/man/html/index.html",
                    b"<p>\n".to_vec(),
                    0o644,
                ),
                F(
                    "usr/lib/cmake/Hello/HelloConfig.cmake",
                    b"#\n".to_vec(),
                    0o644,
                ),
                F("usr/lib/hello/include/hello.h", b"/**/\n".to_vec(), 0o644),
                F(
                    "usr/lib/hello/include/sub/more.hpp",
                    b"/**/\n".to_vec(),
                    0o644,
                ),
                F("usr/share/hello/one.hh", b"/**/\n".to_vec(), 0o644),
                F("usr/share/hello/include", b"a file\n".to_vec(), 0o644),
                F("usr/lib/libhello.la", b"# libtool\n".to_vec(), 0o644),
                F("usr/share/hello/hello.pc", b"Name: hello\n".to_vec(), 0o644),
                F("usr/lib/hello/hello.debug", b"debug\n".to_vec(), 0o644),
                F("usr/share/aclocal/hello.m4", b"dnl\n".to_vec(), 0o644),
                F("usr/doc/hello/README", b"Hello.\n".to_vec(), 0o644),
                F("usr/info/hello.info", b"Hello.\n".to_vec(), 0o644),
                F(
                    "usr/share/gtk-doc/html/hello/index.html",
                    b"<p>\n".to_vec(),
                    0o644,
                ),
                F(
                    "usr/lib64/cmake/Hello/HelloConfig.cmake",
                    b"#\n".to_vec(),
                    0o644,
                ),
                Link("usr/lib/libz.so", "libz.so.1"),
                Link("usr/lib/hello/libplugin.so", "x"),
                Link("usr/lib/zlib.so", "x"),
                F("usr/lib/libreal.so", b"a real library\n".to_vec(), 0o644),
            ],
        );
        let mut options = options(
            &root,
            r#"[package]
requires = [
    "so:libc.so.6",
    "so:libgone.so.1",
    "so:liba.so.1 or so:libb.so.2",
    "so:liba.so.1 or cap:foo",
    "so:libdev.so",
    "so:libodd.so.1@ODD_1",
]

[[state.path]]
path = "/var/lib/hello/drop"
class = "data"
mode = "0777"

[[state.path]]
path = "/var/lib/hello/data"
class = "data"
mode = "0775"

[[state.file]]
path = "/var/log/hello.log"
mode = "0666"
"#,
        );
        options.license = "NOASSERTION".to_owned();
        options.license_texts.clear();
        options.setuid = BTreeSet::from([
            "/usr/bin/declared".parse().unwrap(),
            "/usr/bin/alink".parse().unwrap(),
        ]);
        options
    }

    #[test]
    fn each_check_finds_its_mistake() {
        let dir = temp();
        let file = packed(dir.path(), &mistakes(dir.path()));
        let report = linted(&file, &[]).unwrap();
        assert!(report.allowed.is_empty());
        assert_eq!(
            seen(&report.warnings),
            [
                w(
                    "license-unknown",
                    None,
                    "the license is NOASSERTION: the package doesn't say what it is"
                ),
                w(
                    "setuid-undeclared",
                    Some("/usr/bin/both"),
                    "is setuid and setgid: it runs as root with group root, whoever starts it"
                ),
                w(
                    "setuid-undeclared",
                    Some("/usr/bin/sg"),
                    "is setgid: it runs with group root, whoever starts it"
                ),
                w(
                    "setuid-undeclared",
                    Some("/usr/bin/su"),
                    "is setuid: it runs as root, whoever starts it"
                ),
                w(
                    "world-writable",
                    Some("/usr/share/hello/drop"),
                    "a directory anyone can write to (mode 0777)"
                ),
                w(
                    "world-writable",
                    Some("/usr/share/hello/open"),
                    "a file anyone can write to (mode 0666)"
                ),
                w(
                    "world-writable",
                    Some("/var/lib/hello/drop"),
                    "a state directory anyone can write to (mode 0777)"
                ),
                w(
                    "world-writable",
                    Some("/var/log/hello.log"),
                    "a state file anyone can write to (mode 0666)"
                ),
                w(
                    "so-private-version",
                    Some("/usr/bin/prog"),
                    "needs the private version GLIBC_PRIVATE of libc.so.6, which only an exact \
                     version of the package providing it can promise"
                ),
                w(
                    "so-bad-name",
                    Some("/usr/bin/prog"),
                    "the library name \"lib bad.so\" can't be an so: atom, so it isn't recorded"
                ),
                w(
                    "so-bad-name",
                    Some("/usr/bin/prog"),
                    "the version \"ODD-1\" of libodd.so.1 can't be an so: atom, so it is left \
                     out and libodd.so.1 is taken without a version"
                ),
                w(
                    "so-unversioned",
                    None,
                    "so:libdev.so is required, but libdev.so has no version after .so, so any \
                     build of it meets the requirement"
                ),
                w(
                    "so-unversioned",
                    None,
                    "so:libplain.so is required, but libplain.so has no version after .so, so \
                     any build of it meets the requirement"
                ),
                // In the manifest's order of requirements.
                w(
                    "so-unneeded",
                    None,
                    "so:liba.so.1 or so:libb.so.2 is required, but no program or library in \
                     the package needs it"
                ),
                w(
                    "so-unneeded",
                    None,
                    "so:libdev.so is required, but no program or library in the package needs it"
                ),
                w(
                    "so-unneeded",
                    None,
                    "so:libgone.so.1 is required, but no program or library in the package \
                     needs it"
                ),
                w(
                    "elf-unreadable",
                    Some("/usr/lib/hello/broken"),
                    "has the ELF magic but can't be read, so it adds no requirements: the \
                     file is too short for an ELF header"
                ),
                w(
                    "shebang-unusual",
                    Some("/usr/bin/odd"),
                    "its interpreter isn't recorded: env is given options"
                ),
                w(
                    "interpreter-unknown",
                    Some("/usr/bin/typo"),
                    "its interpreter /usr/bin/pyhton3 isn't in the package, nor one Ordin knows"
                ),
                w(
                    "facet-misclassified",
                    Some("/usr/doc"),
                    "looks like documentation, but it is in runtime"
                ),
                w(
                    "facet-misclassified",
                    Some("/usr/info"),
                    "looks like info pages, but it is in runtime"
                ),
                w(
                    "facet-misclassified",
                    Some("/usr/lib/cmake"),
                    "looks like CMake package files, but it is in runtime"
                ),
                w(
                    "facet-misclassified",
                    Some("/usr/lib/hello/hello.debug"),
                    "looks like split debug information, but it is in runtime"
                ),
                w(
                    "facet-misclassified",
                    Some("/usr/lib/hello/include"),
                    "looks like C or C++ headers, but it is in runtime"
                ),
                w(
                    "facet-misclassified",
                    Some("/usr/lib/libhello.la"),
                    "looks like a libtool archive, but it is in runtime"
                ),
                w(
                    "facet-misclassified",
                    Some("/usr/lib/libz.so"),
                    "looks like a development link, but it is in runtime"
                ),
                w(
                    "facet-misclassified",
                    Some("/usr/lib64/cmake"),
                    "looks like CMake package files, but it is in runtime"
                ),
                w(
                    "facet-misclassified",
                    Some("/usr/man"),
                    "looks like man pages, but it is in runtime"
                ),
                w(
                    "facet-misclassified",
                    Some("/usr/share/aclocal"),
                    "looks like autoconf macros, but it is in runtime"
                ),
                w(
                    "facet-misclassified",
                    Some("/usr/share/gtk-doc"),
                    "looks like API documentation, but it is in runtime"
                ),
                w(
                    "facet-misclassified",
                    Some("/usr/share/hello/hello.pc"),
                    "looks like a pkg-config file, but it is in runtime"
                ),
                w(
                    "facet-misclassified",
                    Some("/usr/share/hello/man"),
                    "looks like man pages, but it is in runtime"
                ),
                w(
                    "facet-misclassified",
                    Some("/usr/share/hello/one.hh"),
                    "looks like C or C++ headers, but it is in runtime"
                ),
                w(
                    "facet-misclassified",
                    Some("/usr/share/tcl/man"),
                    "looks like man pages, but it is in runtime"
                ),
            ]
        );
        let hints: BTreeMap<&str, Option<&str>> = report
            .warnings
            .iter()
            .map(|f| (f.check.id(), f.hint.as_deref()))
            .collect();
        assert_eq!(
            hints,
            BTreeMap::from([
                (
                    "license-unknown",
                    Some(
                        "give it with --license, or license in the recipe's [package], with \
                         its text"
                    )
                ),
                (
                    "setuid-undeclared",
                    Some("declare it with --setuid /usr/bin/su if it must be, or drop the bit")
                ),
                (
                    "world-writable",
                    Some("take away write permission for others")
                ),
                (
                    "so-private-version",
                    Some("require that package at its exact version, in the recipe's requires")
                ),
                ("so-bad-name", None),
                (
                    "so-unversioned",
                    Some(
                        "link against the library's versioned soname; one ending in .so is \
                         usually a development link"
                    )
                ),
                (
                    "so-unneeded",
                    Some(
                        "drop it, or allow it with a reason if the package loads the library \
                         with dlopen"
                    )
                ),
                ("elf-unreadable", None),
                (
                    "shebang-unusual",
                    Some("declare what it needs in the recipe's requires")
                ),
                (
                    "interpreter-unknown",
                    Some(
                        "check its #! line: a misspelt name, or a path from the build \
                         machine, is the usual cause"
                    )
                ),
                (
                    "facet-misclassified",
                    Some(
                        "move it with [facets.doc] extra = [\"/usr/share/tcl/man\"] in the recipe"
                    )
                ),
            ])
        );
        // Each misplaced file's facet.
        let facets: Vec<(&str, &str)> = report
            .warnings
            .iter()
            .filter(|f| f.check.id() == "facet-misclassified")
            .map(|f| {
                let hint = f.hint.as_deref().unwrap();
                let facet = hint
                    .strip_prefix("move it with [facets.")
                    .and_then(|rest| rest.split_once(']'))
                    .unwrap()
                    .0;
                (f.path.as_deref().unwrap(), facet)
            })
            .collect();
        assert_eq!(
            facets,
            [
                ("/usr/doc", "doc"),
                ("/usr/info", "doc"),
                ("/usr/lib/cmake", "dev"),
                ("/usr/lib/hello/hello.debug", "debug"),
                ("/usr/lib/hello/include", "dev"),
                ("/usr/lib/libhello.la", "dev"),
                ("/usr/lib/libz.so", "dev"),
                ("/usr/lib64/cmake", "dev"),
                ("/usr/man", "doc"),
                ("/usr/share/aclocal", "dev"),
                ("/usr/share/gtk-doc", "doc"),
                ("/usr/share/hello/hello.pc", "dev"),
                ("/usr/share/hello/man", "doc"),
                ("/usr/share/hello/one.hh", "dev"),
                ("/usr/share/tcl/man", "doc"),
            ]
        );
    }

    #[test]
    fn allows_accept_warnings_and_unused_allows_are_warned() {
        let dir = temp();
        let file = packed(dir.path(), &mistakes(dir.path()));
        // Lines count from the format line the helper puts first.
        let recipe = r#"[[lint.allow]]
id = "world-writable"
reason = "a shared drop directory"
paths = ["/usr/share/hello/drop", "/var", "/usr/share/nothing"]

[[lint.allow]]
id = "license-unknown"
reason = "upstream is clarifying it"

[[lint.allow]]
id = "facet-misclassified"
reason = "read at run time"

[[lint.allow]]
id = "facet-empty"
reason = "nothing to accept"

[[lint.allow]]
id = "setuid-undeclared"
reason = "a path below"
paths = ["/usr/bin/sg"]
"#;
        let report = linted(&file, &allows(recipe)).unwrap();
        let accepted: Vec<(&str, Option<&str>, &str, usize)> = report
            .allowed
            .iter()
            .map(|a| {
                (
                    a.finding.check.id(),
                    a.finding.path.as_deref(),
                    a.reason.as_str(),
                    a.line,
                )
            })
            .collect();
        let misclassified = |p| ("facet-misclassified", Some(p), "read at run time", 11);
        assert_eq!(
            accepted,
            [
                ("license-unknown", None, "upstream is clarifying it", 7),
                ("setuid-undeclared", Some("/usr/bin/sg"), "a path below", 19),
                (
                    "world-writable",
                    Some("/usr/share/hello/drop"),
                    "a shared drop directory",
                    2
                ),
                (
                    "world-writable",
                    Some("/var/lib/hello/drop"),
                    "a shared drop directory",
                    2
                ),
                (
                    "world-writable",
                    Some("/var/log/hello.log"),
                    "a shared drop directory",
                    2
                ),
                misclassified("/usr/doc"),
                misclassified("/usr/info"),
                misclassified("/usr/lib/cmake"),
                misclassified("/usr/lib/hello/hello.debug"),
                misclassified("/usr/lib/hello/include"),
                misclassified("/usr/lib/libhello.la"),
                misclassified("/usr/lib/libz.so"),
                misclassified("/usr/lib64/cmake"),
                misclassified("/usr/man"),
                misclassified("/usr/share/aclocal"),
                misclassified("/usr/share/gtk-doc"),
                misclassified("/usr/share/hello/hello.pc"),
                misclassified("/usr/share/hello/man"),
                misclassified("/usr/share/hello/one.hh"),
                misclassified("/usr/share/tcl/man"),
            ]
        );
        let left: Vec<_> = seen(&report.warnings)
            .into_iter()
            .filter(|(id, ..)| {
                ["setuid-undeclared", "world-writable", "unused-allow"].contains(&id.as_str())
            })
            .collect();
        assert_eq!(
            left,
            [
                w(
                    "setuid-undeclared",
                    Some("/usr/bin/both"),
                    "is setuid and setgid: it runs as root with group root, whoever starts it"
                ),
                w(
                    "setuid-undeclared",
                    Some("/usr/bin/su"),
                    "is setuid: it runs as root, whoever starts it"
                ),
                w(
                    "world-writable",
                    Some("/usr/share/hello/open"),
                    "a file anyone can write to (mode 0666)"
                ),
                w(
                    "unused-allow",
                    Some("/usr/share/nothing"),
                    "the allow for world-writable at line 2 matches no warning here"
                ),
                w(
                    "unused-allow",
                    None,
                    "the allow for facet-empty at line 15 matches no warning"
                ),
            ]
        );
        let unused = report.warnings.last().unwrap();
        assert_eq!(unused.hint.as_deref(), Some("remove it from the recipe"));
        // Nothing else was accepted, and nothing accepted is warned too.
        assert_eq!(
            report.warnings.len() + report.allowed.len(),
            linted(&file, &[]).unwrap().warnings.len() + 2
        );
    }

    #[test]
    fn a_facet_with_no_files_is_warned() {
        let dir = temp();
        let root = root(
            dir.path(),
            &[
                Dir("usr/lib/hello", 0o755),
                F("usr/share/doc/hello/README", b"Hello.\n".to_vec(), 0o644),
            ],
        );
        let file = packed(dir.path(), &options(&root, ""));
        let report = linted(&file, &[]).unwrap();
        assert_eq!(
            seen(&report.warnings),
            [w("facet-empty", None, "the facet runtime holds no files")]
        );
        assert_eq!(report.warnings[0].hint, None);
    }

    #[test]
    fn interpreters_are_known_by_name_and_version() {
        for known in [
            "/usr/bin/sh",
            "/usr/sbin/nft",
            "/usr/bin/python3",
            "/usr/bin/python3.12",
            "/usr/bin/perl5.36.0",
            "/usr/bin/lua5.4",
        ] {
            assert!(known_interpreter(known), "{known}");
        }
        for unknown in [
            "/usr/bin/python",
            "/usr/bin/python2.7",
            "/usr/bin/python3x",
            "/usr/local/bin/perl",
            "/usr/bin/shx",
        ] {
            assert!(!known_interpreter(unknown), "{unknown}");
        }
    }

    /// The offset of the middle of the largest entry in a tar file.
    fn middle_of_largest(file: &Path) -> u64 {
        let mut archive = tar::Archive::new(File::open(file).unwrap());
        archive
            .entries()
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (e.size(), e.raw_file_position())
            })
            .max()
            .map(|(size, at)| at + size / 2)
            .unwrap()
    }

    #[test]
    fn a_damaged_file_stops_the_lint() {
        let dir = temp();
        // Bytes that don't compress, so their chunk pack is the largest
        // part of the file.
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        let noise: Vec<u8> = (0..65_536)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state.to_le_bytes()[0]
            })
            .collect();
        let root = root(dir.path(), &[F("usr/lib/hello/noise", noise, 0o644)]);
        let file = packed(dir.path(), &options(&root, ""));
        assert_eq!(linted(&file, &[]).unwrap(), LintReport::default());
        let at = middle_of_largest(&file);
        let mut f = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&file)
            .unwrap();
        let mut byte = [0];
        f.seek(SeekFrom::Start(at)).unwrap();
        f.read_exact(&mut byte).unwrap();
        f.seek(SeekFrom::Start(at)).unwrap();
        f.write_all(&[byte[0] ^ 0xff]).unwrap();
        drop(f);
        match linted(&file, &[]) {
            Err(LintError::Read(e)) => {
                assert!(
                    e.to_string()
                        .contains("in the chunk pack for facet runtime: its content isn't"),
                    "{e}"
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn skipped_paths_are_recorded_and_lint_skips_them_too() {
        let dir = temp();
        let i386 = Spec {
            is_64: false,
            ..spec(EM_386.0, ET_EXEC.0)
        };
        let root = root(
            dir.path(),
            &[
                F("usr/bin/hello", build(&program()), 0o755),
                F("usr/lib/hello/testdata/old", build(&i386), 0o644),
                F(
                    "usr/lib/hello/testdata/run.rc",
                    b"#!/bin/rc\n".to_vec(),
                    0o755,
                ),
                F("usr/lib/hello/plan9.rc", b"#!/bin/rc\n".to_vec(), 0o755),
            ],
        );
        // Without a skip, the test file stops the package.
        let e = pack(
            &options(&root, ""),
            &Output::Named(dir.path().to_path_buf()),
        )
        .unwrap_err();
        assert!(matches!(e, PackError::Infer(_)), "{e:?}");
        let recipe = "[[infer.skip]]\n\
                      paths = [\"/usr/lib/hello/testdata/**\"]\n\
                      reason = \"test files\"\n\
                      [[infer.skip]]\n\
                      paths = [\"/usr/lib/hello/plan9.rc\"]\n\
                      reason = \"a Plan 9 script\"\n";
        let out = dir.path().join("out");
        fs::create_dir(&out).unwrap();
        let packed = pack(&options(&root, recipe), &Output::Named(out.clone())).unwrap();
        let recorded: Vec<(String, String)> = packed
            .manifest
            .inference_skip
            .iter()
            .map(|s| (s.path.to_string(), s.reason.clone()))
            .collect();
        assert_eq!(
            recorded,
            [
                (
                    "/usr/lib/hello/plan9.rc".to_owned(),
                    "a Plan 9 script".to_owned()
                ),
                (
                    "/usr/lib/hello/testdata".to_owned(),
                    "test files".to_owned()
                ),
            ]
        );
        let requires: Vec<String> = packed
            .manifest
            .requires
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(requires, ["so:libc.so.6@GLIBC_2.34"]);
        // lint reads the skips from the manifest: no recipe, the same
        // inference, and the skipped scripts' interpreter isn't warned about.
        let report = linted(&packed.out, &[]).unwrap();
        assert_eq!(seen(&report.warnings), []);
        // A skip must match something in the package.
        let missing = "[[infer.skip]]\npaths = [\"/usr/lib/hello/nothing\"]\nreason = \"x\"\n";
        let e = pack(
            &options(&root, &format!("{recipe}{missing}")),
            &Output::Named(out),
        )
        .unwrap_err();
        assert!(matches!(e, PackError::SkipMissing(_)), "{e:?}");
        assert_eq!(
            e.to_string(),
            "/usr/lib/hello/nothing: left out of inference by [[infer.skip]], but nothing in the package is there"
        );
    }
}
