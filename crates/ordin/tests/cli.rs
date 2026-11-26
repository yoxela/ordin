// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! The `ordin` program, run as a packager runs it (ORD-120), and as an
//! admin looks at a package (ORD-132).

#[cfg(test)]
mod cli {
    use std::fs::{self, Permissions};
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::process::{Command, Output};

    use serde_json::Value;
    use tempfile::TempDir;

    /// A test directory that can always be removed, even after a test
    /// fails half-way: when it is dropped, every directory under it is
    /// first made its owner's to read, write and search again, so a
    /// read-only directory a failed test left can't stop `TempDir`
    /// removing it. Left behind, it would also stop cargo-mutants removing
    /// its scratch copy of the workspace, which holds `target/tmp`.
    struct Scratch(TempDir);

    impl Scratch {
        fn path(&self) -> &Path {
            self.0.path()
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            open_up(self.0.path());
        }
    }

    /// Gives the owner `rwx` on `dir` and every directory under it. It
    /// doesn't follow symlinks, and it ignores every error, so it can't
    /// panic while a failed test is already panicking.
    fn open_up(dir: &Path) {
        let Ok(meta) = fs::symlink_metadata(dir) else {
            return;
        };
        if !meta.is_dir() {
            return;
        }
        let mode = meta.permissions().mode();
        if mode & 0o700 != 0o700 {
            let _ = fs::set_permissions(dir, Permissions::from_mode(mode | 0o700));
        }
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                open_up(&entry.path());
            }
        }
    }

    fn temp() -> Scratch {
        Scratch(tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap())
    }

    #[test]
    fn a_test_directory_is_removed_even_after_a_failed_test() {
        // A directory outside it, reached through a symlink inside it.
        let outside = temp();
        let kept = outside.path().join("kept");
        fs::create_dir(&kept).unwrap();
        fs::set_permissions(&kept, Permissions::from_mode(0o500)).unwrap();
        let mut at = None;
        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let dir = temp();
            at = Some(dir.path().to_owned());
            let a = dir.path().join("a");
            fs::create_dir_all(a.join("b/c")).unwrap();
            fs::write(a.join("b/c/f"), b"x").unwrap();
            std::os::unix::fs::symlink(&kept, a.join("b/out")).unwrap();
            // Deepest first, so each can still be reached.
            for (path, mode) in [("a/b/c", 0o000), ("a/b", 0o500), ("a", 0o555)] {
                fs::set_permissions(dir.path().join(path), Permissions::from_mode(mode)).unwrap();
            }
            panic!("a test that fails on purpose, leaving read-only directories");
        }));
        assert!(failed.is_err());
        assert!(!at.unwrap().exists());
        // The symlink wasn't followed.
        assert_eq!(mode(&kept), 0o500);
    }

    fn write(root: &Path, path: &str, bytes: &[u8], mode: u32) {
        let at = root.join(path);
        fs::create_dir_all(at.parent().unwrap()).unwrap();
        fs::write(&at, bytes).unwrap();
        fs::set_permissions(&at, Permissions::from_mode(mode)).unwrap();
    }

    /// A directory holding `root/`, an install root, and `COPYING`.
    fn fixture() -> Scratch {
        let dir = temp();
        let root = dir.path().join("root");
        write(&root, "usr/bin/hello", b"#!/bin/sh\necho hello\n", 0o755);
        write(&root, "usr/share/doc/hello/README", b"Says hello.\n", 0o644);
        write(dir.path(), "COPYING", b"MIT License\n", 0o644);
        dir
    }

    /// Runs `ordin` in `dir` with `args`.
    fn ordin(dir: &Path, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_ordin"))
            .current_dir(dir)
            .args(args)
            .output()
            .unwrap()
    }

    fn stdout(o: &Output) -> String {
        String::from_utf8(o.stdout.clone()).unwrap()
    }

    fn stderr(o: &Output) -> String {
        String::from_utf8(o.stderr.clone()).unwrap()
    }

    #[test]
    fn a_name_and_a_version_are_enough() {
        let dir = fixture();
        let o = ordin(
            dir.path(),
            &["pack", "root", "--name", "hello", "--version", "2.12"],
        );
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        // Only a script, so no architecture: noarch.
        let file = "hello-2.12-1.noarch.ordin";
        assert!(dir.path().join(file).is_file());
        assert_eq!(
            stderr(&o),
            "ordin: warning: no --summary was given, so the summary is the package's name\n\
             ordin: warning: no --license was given, so the license is NOASSERTION\n"
        );
        let out = stdout(&o);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3);
        let size = fs::metadata(dir.path().join(file)).unwrap().len();
        assert_eq!(lines[0], format!("wrote {file} ({size} bytes)"));
        assert!(lines[1].starts_with("package blake3:"));
        assert_eq!(lines[2], "facets: doc (12 bytes), runtime (21 bytes)");
    }

    #[test]
    fn json_reports_the_package() {
        let dir = fixture();
        let o = ordin(
            dir.path(),
            &[
                "pack",
                "root",
                "--name",
                "hello",
                "--version",
                "1:2.12",
                "--release",
                "3",
                "--license",
                "MIT",
                "--license-file",
                "MIT=COPYING",
                "--summary",
                "Prints a greeting",
                "--arch",
                "noarch",
                "--json",
            ],
        );
        assert_eq!(o.status.code(), Some(0), "{}", stdout(&o));
        assert_eq!(stderr(&o), "");
        let text = stdout(&o);
        assert!(!text.ends_with('\n'), "one canonical JSON object");
        let v: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["name"], "hello");
        assert_eq!(v["version"], "1:2.12-3");
        assert_eq!(v["arch"], "noarch");
        assert_eq!(v["license"], "MIT");
        assert_eq!(v["file"], "hello-1_2.12-3.noarch.ordin");
        assert_eq!(v["warnings"], Value::Array(Vec::new()));
        assert_eq!(v["signatures"], Value::Array(Vec::new()));
        // The script's interpreter, from its #! line.
        assert_eq!(v["requires"], serde_json::json!(["file:/usr/bin/sh"]));
        assert_eq!(v["provides"], serde_json::json!([]));
        let size = fs::metadata(dir.path().join("hello-1_2.12-3.noarch.ordin"))
            .unwrap()
            .len();
        assert_eq!(v["size"], size);
        assert!(v["package"].as_str().unwrap().starts_with("blake3:"));
        assert!(v["image"].as_str().unwrap().starts_with("sha256:"));
        assert_eq!(v["facets"]["doc"]["size"], 12);
        assert!(
            v["facets"]["runtime"]["tree"]
                .as_str()
                .unwrap()
                .starts_with("blake3:")
        );
        // Without --version-from git, no commit is known.
        assert_eq!(v["commit"], Value::Null);
        let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
        assert_eq!(
            keys,
            [
                "arch",
                "commit",
                "facets",
                "file",
                "image",
                "license",
                "name",
                "package",
                "provides",
                "requires",
                "signatures",
                "size",
                "version",
                "warnings"
            ]
        );
    }

    #[test]
    fn owners_setuid_prefixes_and_out_are_passed_on() {
        let dir = fixture();
        let root = dir.path().join("root");
        write(&root, "opt/hello/bin/helper", b"helper\n", 0o4755);
        let o = ordin(
            dir.path(),
            &[
                "pack",
                "root",
                "--name",
                "hello",
                "--version",
                "2.12",
                "--license",
                "MIT",
                "--license-file",
                "MIT=COPYING",
                "--summary",
                "Prints a greeting",
                "--arch",
                "x86_64",
                "--prefix",
                "opt/hello",
                "--owner",
                "opt/hello/bin/helper=root:wheel",
                "--setuid",
                "/opt/hello/bin/helper",
                "-o",
                "out.ordin",
            ],
        );
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        assert_eq!(stderr(&o), "");
        assert!(dir.path().join("out.ordin").is_file());

        // Undeclared, the setuid file is a warning.
        let o = ordin(
            dir.path(),
            &[
                "pack",
                "root",
                "--name",
                "hello",
                "--version",
                "2.12",
                "--prefix",
                "opt/hello",
                "--arch",
                "x86_64",
                "--summary",
                "s",
                "--license",
                "NONE",
                "-o",
                "out.ordin",
            ],
        );
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        assert_eq!(
            stderr(&o),
            "ordin: warning: /opt/hello/bin/helper: not declared: setuid, so it runs as root, \
             the default (--owner sets another)\n"
        );
    }

    fn fails(dir: &Path, extra: &[&str]) -> (Option<i32>, String) {
        let mut args = vec!["pack", "root", "--name", "hello", "--version", "2.12"];
        args.extend(extra);
        let o = ordin(dir, &args);
        assert_eq!(stdout(&o), "");
        (o.status.code(), stderr(&o))
    }

    #[test]
    fn errors_say_what_to_do() {
        let dir = fixture();
        let cases: &[(&[&str], &str)] = &[
            (
                &["--license", "MIT"],
                "ordin: error: the license MIT has no text; give it with --license-file MIT=PATH\n",
            ),
            (
                &["--license", "NONE", "--license-file", "MIT=COPYING"],
                "ordin: error: a text was given for MIT, which the license NONE doesn't name; \
                 add MIT to --license, or drop its --license-file\n",
            ),
            (
                &[
                    "--license",
                    "MIT",
                    "--license-file",
                    "MIT=COPYING",
                    "--license-file",
                    "MIT=COPYING",
                ],
                "ordin: error: --license-file names MIT twice\n",
            ),
            (
                &["--license", "MIT", "--license-file", "MIT=root"],
                "ordin: error: root: a license text must be a regular file\n",
            ),
            (
                &["--release", "1+u2"],
                "ordin: error: the version \"2.12\" with release \"1+u2\" doesn't read back as given\n",
            ),
            (
                &["-o", "root/x.ordin"],
                "ordin: error: root/x.ordin: the package can't be written inside the directory it packs (root)\n",
            ),
        ];
        for (extra, message) in cases {
            let (code, err) = fails(dir.path(), extra);
            assert_eq!(code, Some(1), "{extra:?}");
            assert!(err.ends_with(message), "{extra:?}: {err}");
        }
        let (code, err) = fails(dir.path(), &["--license-file", "MIT=missing"]);
        assert_eq!(code, Some(1));
        assert!(err.starts_with("ordin: error: missing: "), "{err}");
        let o = ordin(
            dir.path(),
            &["pack", "root", "--name", "hello", "--version", "2 12"],
        );
        assert_eq!(o.status.code(), Some(1));
        assert_eq!(
            stderr(&o),
            "ordin: error: the version \"2 12\" with release \"1\": \
             the upstream version can't contain ' ' (at byte 1)\n"
        );
    }

    #[test]
    fn each_cause_is_named_once() {
        let dir = fixture();
        // A layout error, from inside the packer.
        write(&dir.path().join("root"), "x", b"x\n", 0o644);
        let (code, err) = fails(dir.path(), &[]);
        assert_eq!(code, Some(1));
        assert_eq!(
            err.lines().last().unwrap(),
            "ordin: error: /x: outside Ordin's layout, which packages usr/, etc/ and var/; \
             if the software was installed with a prefix here, pass it with --prefix to move \
             it under /usr"
        );
        fs::remove_file(dir.path().join("root/x")).unwrap();
        // The system's error, under the path it is about.
        let missing = ["pack", "missing", "--name", "hello", "--version", "2.12"];
        let o = ordin(dir.path(), &missing);
        assert_eq!(o.status.code(), Some(1));
        assert_eq!(
            stderr(&o),
            "ordin: error: missing: No such file or directory (os error 2)\n"
        );
        let o = ordin(dir.path(), &[&missing[..], &["--json"]].concat());
        assert_eq!(o.status.code(), Some(1));
        assert_eq!(
            stdout(&o),
            r#"{"error":"missing: No such file or directory (os error 2)"}"#
        );
        // An output directory that can't be written.
        let ro = dir.path().join("ro");
        fs::create_dir(&ro).unwrap();
        fs::set_permissions(&ro, Permissions::from_mode(0o555)).unwrap();
        let (code, err) = fails(dir.path(), &["--license", "NONE", "-o", "ro/x.ordin"]);
        fs::set_permissions(&ro, Permissions::from_mode(0o755)).unwrap();
        assert_eq!(code, Some(1));
        // The system's error only, without the temporary file's path.
        assert_eq!(
            err.lines().last().unwrap(),
            "ordin: error: ro/x.ordin: Permission denied (os error 13)"
        );
    }

    #[test]
    fn errors_are_safe_for_a_terminal_and_exact_in_json() {
        let dir = fixture();
        // A name that reverses the text after it on a terminal.
        write(&dir.path().join("root"), "x\u{202e}txt", b"x\n", 0o644);
        let rest = ": outside Ordin's layout, which packages usr/, etc/ and var/; \
                    if the software was installed with a prefix here, pass it with --prefix \
                    to move it under /usr";
        let (code, err) = fails(dir.path(), &[]);
        assert_eq!(code, Some(1));
        assert_eq!(
            err.lines().last().unwrap(),
            format!("ordin: error: /x\\u{{202e}}txt{rest}")
        );
        assert!(!err.contains('\u{202e}'), "{err}");
        let o = ordin(
            dir.path(),
            &[
                "pack",
                "root",
                "--name",
                "hello",
                "--version",
                "2.12",
                "--json",
            ],
        );
        assert_eq!(o.status.code(), Some(1));
        assert_eq!(stderr(&o), "");
        let v: Value = serde_json::from_str(&stdout(&o)).unwrap();
        assert_eq!(v["error"], format!("/x\u{202e}txt{rest}"));
    }

    #[test]
    fn license_texts_are_at_most_a_mebibyte() {
        let dir = fixture();
        let limit = 1 << 20;
        fs::write(dir.path().join("big"), vec![b'x'; limit]).unwrap();
        fs::write(dir.path().join("bigger"), vec![b'x'; limit + 1]).unwrap();
        let ok = ordin(
            dir.path(),
            &[
                "pack",
                "root",
                "--name",
                "hello",
                "--version",
                "2.12",
                "--license",
                "MIT",
                "--license-file",
                "MIT=big",
            ],
        );
        assert_eq!(ok.status.code(), Some(0), "{}", stderr(&ok));
        let (code, err) = fails(
            dir.path(),
            &["--license", "MIT", "--license-file", "MIT=bigger"],
        );
        assert_eq!(code, Some(1));
        assert!(
            err.ends_with("ordin: error: bigger: a license text is at most 1048576 bytes\n"),
            "{err}"
        );
    }

    #[test]
    fn json_errors_are_json_too() {
        let dir = fixture();
        let o = ordin(
            dir.path(),
            &[
                "pack",
                "root",
                "--name",
                "hello",
                "--version",
                "2.12",
                "--license",
                "MIT",
                "--json",
            ],
        );
        assert_eq!(o.status.code(), Some(1));
        assert_eq!(stderr(&o), "");
        assert_eq!(
            stdout(&o),
            r#"{"error":"the license MIT has no text; give it with --license-file MIT=PATH"}"#
        );
    }

    #[test]
    fn a_wrong_command_line_exits_with_2() {
        let dir = fixture();
        for args in [
            &["pack", "root", "--version", "2.12"][..],
            &["pack", "root", "--name", "Hello", "--version", "2.12"],
            &[
                "pack",
                "root",
                "--name",
                "hello",
                "--version",
                "2.12",
                "--arch",
                "riscv64",
            ],
            &[
                "pack",
                "root",
                "--name",
                "hello",
                "--version",
                "2.12",
                "--license-file",
                "MIT",
            ],
            &[
                "pack",
                "root",
                "--name",
                "hello",
                "--version",
                "2.12",
                "--owner",
                "usr",
            ],
            &[
                "pack",
                "root",
                "--name",
                "hello",
                "--version",
                "2.12",
                "--setuid",
                "a//b",
            ],
            &["unknown"],
        ] {
            let o = ordin(dir.path(), args);
            assert_eq!(o.status.code(), Some(2), "{args:?}");
            assert!(
                stderr(&o).starts_with("error: "),
                "{args:?}: {}",
                stderr(&o)
            );
        }
        let o = ordin(dir.path(), &["--version"]);
        assert_eq!(o.status.code(), Some(0));
        assert_eq!(stdout(&o), format!("ordin {}\n", env!("CARGO_PKG_VERSION")));
    }

    /// The fixture packed with a license, as `hello.ordin`.
    fn packed() -> Scratch {
        let dir = fixture();
        let o = ordin(
            dir.path(),
            &[
                "pack",
                "root",
                "--name",
                "hello",
                "--version",
                "2.12",
                "--license",
                "MIT",
                "--license-file",
                "MIT=COPYING",
                "--summary",
                "Prints a greeting",
                "-o",
                "hello.ordin",
            ],
        );
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        dir
    }

    #[test]
    fn show_says_what_a_package_holds() {
        let dir = packed();
        let o = ordin(dir.path(), &["show", "hello.ordin"]);
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        assert_eq!(stderr(&o), "");
        let out = stdout(&o);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines[..4],
            [
                "hello 2.12-1 (noarch, base)",
                "Prints a greeting",
                "",
                "license: MIT (texts: MIT)"
            ]
        );
        assert!(lines[4].starts_with("package: blake3:"), "{out}");
        assert!(lines[5].starts_with("image: sha256:"), "{out}");
        assert_eq!(
            lines[6..],
            [
                "signature: not signed",
                "",
                "facets:",
                "  doc      12 B",
                "  runtime  21 B",
                "",
                "requires:",
                "  file:/usr/bin/sh"
            ]
        );
        assert!(!out.contains("entries in"));
    }

    #[test]
    fn show_facets_lists_each_facets_entries() {
        let dir = packed();
        let o = ordin(dir.path(), &["show", "hello.ordin", "--facets"]);
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        let out = stdout(&o);
        assert!(
            out.contains("  doc      12 B, 5 entries\n  runtime  21 B, 3 entries\n"),
            "{out}"
        );
        let listed = out.split_once("\nentries in doc:\n").unwrap().1;
        assert_eq!(
            listed,
            "  drwxr-xr-x root:root    - /usr\n\
             \x20 drwxr-xr-x root:root    - /usr/share\n\
             \x20 drwxr-xr-x root:root    - /usr/share/doc\n\
             \x20 drwxr-xr-x root:root    - /usr/share/doc/hello\n\
             \x20 -rw-r--r-- root:root 12 B /usr/share/doc/hello/README\n\
             \n\
             entries in runtime:\n\
             \x20 drwxr-xr-x root:root    - /usr\n\
             \x20 drwxr-xr-x root:root    - /usr/bin\n\
             \x20 -rwxr-xr-x root:root 21 B /usr/bin/hello\n"
        );
    }

    #[test]
    fn show_json_holds_the_manifest_as_signed() {
        let dir = packed();
        let packed = ordin(
            dir.path(),
            &[
                "pack",
                "root",
                "--name",
                "hello",
                "--version",
                "2.12",
                "--license",
                "MIT",
                "--license-file",
                "MIT=COPYING",
                "--summary",
                "Prints a greeting",
                "-o",
                "again.ordin",
                "--json",
            ],
        );
        let packed: Value = serde_json::from_str(&stdout(&packed)).unwrap();
        let o = ordin(dir.path(), &["show", "hello.ordin", "--json"]);
        assert_eq!(o.status.code(), Some(0), "{}", stdout(&o));
        assert_eq!(stderr(&o), "");
        let text = stdout(&o);
        assert!(!text.ends_with('\n'), "one canonical JSON object");
        let v: Value = serde_json::from_str(&text).unwrap();
        let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["file", "image", "manifest", "package", "signatures"]);
        assert_eq!(v["file"], "hello.ordin");
        assert_eq!(v["package"], packed["package"]);
        assert_eq!(v["image"], packed["image"]);
        assert_eq!(v["signatures"], Value::Array(Vec::new()));
        assert_eq!(v["manifest"]["name"], "hello");
        assert_eq!(v["manifest"]["summary"], "Prints a greeting");
        assert_eq!(v["manifest"]["facets"]["doc"]["size"], 12);
        let o = ordin(dir.path(), &["show", "hello.ordin", "--json", "--facets"]);
        assert_eq!(o.status.code(), Some(0), "{}", stdout(&o));
        let v: Value = serde_json::from_str(&stdout(&o)).unwrap();
        assert_eq!(v["files"]["doc"].as_array().unwrap().len(), 5);
        assert_eq!(
            v["files"]["runtime"][2],
            serde_json::json!({
                "content": v["files"]["runtime"][2]["content"],
                "fsverity": v["files"]["runtime"][2]["fsverity"],
                "mode": "0755",
                "path": "/usr/bin/hello",
                "size": 21,
                "type": "file"
            })
        );
    }

    #[test]
    fn show_refuses_what_isnt_a_package() {
        let dir = packed();
        let bytes = fs::read(dir.path().join("hello.ordin")).unwrap();
        fs::write(dir.path().join("cut.ordin"), &bytes[..bytes.len() / 2]).unwrap();
        let cases: &[(&str, &str)] = &[
            (
                "missing.ordin",
                "ordin: error: missing.ordin: No such file or directory (os error 2)\n",
            ),
            ("root", "ordin: error: root: not a regular file\n"),
            ("/dev/null", "ordin: error: /dev/null: not a regular file\n"),
            (
                "cut.ordin",
                "ordin: error: cut.ordin: the archive: the file ends inside it\n",
            ),
        ];
        for (file, message) in cases {
            let o = ordin(dir.path(), &["show", file]);
            assert_eq!(o.status.code(), Some(1), "{file}");
            assert_eq!(stdout(&o), "", "{file}");
            assert_eq!(stderr(&o), *message, "{file}");
        }
        let o = ordin(dir.path(), &["show", "root", "--json"]);
        assert_eq!(o.status.code(), Some(1));
        assert_eq!(stderr(&o), "");
        assert_eq!(stdout(&o), r#"{"error":"root: not a regular file"}"#);
        let o = ordin(dir.path(), &["show"]);
        assert_eq!(o.status.code(), Some(2));
    }

    #[test]
    fn show_reads_a_tree_only_when_its_entries_are_listed() {
        let dir = packed();
        let mut bytes = fs::read(dir.path().join("hello.ordin")).unwrap();
        let at = bytes
            .windows(12)
            .position(|w| w == b"hello/README")
            .unwrap();
        assert_eq!(
            bytes.windows(12).filter(|w| *w == b"hello/README").count(),
            1,
            "only the doc tree names it"
        );
        bytes[at + 6] = b'S';
        fs::write(dir.path().join("hello.ordin"), &bytes).unwrap();
        let o = ordin(dir.path(), &["show", "hello.ordin"]);
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        for args in [
            &["show", "hello.ordin", "--facets"][..],
            &["show", "hello.ordin", "--facets", "--json"],
        ] {
            let o = ordin(dir.path(), args);
            assert_eq!(o.status.code(), Some(1), "{args:?}");
            let said = format!("{}{}", stdout(&o), stderr(&o));
            assert!(
                said.contains("hello.ordin: the tree for facet doc: its content isn't what its descriptor records"),
                "{said}"
            );
        }
    }

    // Signing (ORD-140).

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    /// A clear key `NAME` made in `dir`.
    fn clear_key(dir: &Path, name: &str) -> String {
        let o = ordin(dir, &["key", "generate", name, "--no-passphrase", "--json"]);
        assert_eq!(o.status.code(), Some(0), "{}", stdout(&o));
        let v: Value = serde_json::from_str(&stdout(&o)).unwrap();
        v["key"].as_str().unwrap().to_owned()
    }

    #[test]
    fn key_generate_writes_a_secret_and_a_public_key() {
        let dir = temp();
        let o = ordin(
            dir.path(),
            &[
                "key",
                "generate",
                "release",
                "--no-passphrase",
                "--comment",
                "release key",
            ],
        );
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        assert_eq!(
            stderr(&o),
            "ordin: warning: release isn't encrypted: anyone who can read it can sign as this key\n"
        );
        let out = stdout(&o);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines[..2],
            [
                "wrote release (the secret key, not encrypted)",
                "wrote release.pub (the public key)"
            ]
        );
        let key = lines[2].strip_prefix("key ").unwrap();
        assert!(key.starts_with("ed25519:") && key.len() == 72, "{key}");
        assert_eq!(mode(&dir.path().join("release")), 0o600);
        assert_eq!(mode(&dir.path().join("release.pub")), 0o644);
        let public = fs::read_to_string(dir.path().join("release.pub")).unwrap();
        assert_eq!(public, format!("ordin-ed25519 {} release key\n", &key[8..]));
        // A key is never replaced.
        let o = ordin(
            dir.path(),
            &["key", "generate", "release", "--no-passphrase"],
        );
        assert_eq!(o.status.code(), Some(1));
        assert_eq!(
            stderr(&o),
            "ordin: error: release: already exists; a key is never replaced\n"
        );
        fs::remove_file(dir.path().join("release")).unwrap();
        let o = ordin(
            dir.path(),
            &["key", "generate", "release", "--no-passphrase", "--json"],
        );
        assert_eq!(o.status.code(), Some(1));
        assert_eq!(
            stdout(&o),
            r#"{"error":"release.pub: already exists; a key is never replaced"}"#
        );
        assert!(!dir.path().join("release").exists());
    }

    #[test]
    fn key_generate_encrypts_with_a_passphrase() {
        let dir = temp();
        fs::write(dir.path().join("pass"), "correct horse\n").unwrap();
        let o = ordin(
            dir.path(),
            &[
                "key",
                "generate",
                "k",
                "--passphrase-file",
                "pass",
                "--json",
            ],
        );
        assert_eq!(o.status.code(), Some(0), "{}", stdout(&o));
        assert_eq!(stderr(&o), "");
        let v: Value = serde_json::from_str(&stdout(&o)).unwrap();
        let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["encrypted", "key", "public", "secret"]);
        assert_eq!(v["encrypted"], true);
        assert_eq!(
            (v["public"].as_str(), v["secret"].as_str()),
            (Some("k.pub"), Some("k"))
        );
        let secret = fs::read_to_string(dir.path().join("k")).unwrap();
        assert!(
            secret.contains(r#""cipher":"xchacha20-poly1305""#),
            "{secret}"
        );
        // Without a terminal, nobody can be asked.
        let o = ordin(dir.path(), &["key", "generate", "j"]);
        assert_eq!(o.status.code(), Some(1));
        assert_eq!(
            stderr(&o),
            "ordin: error: no terminal to ask for the passphrase on; give it with --passphrase-file\n"
        );
        assert!(!dir.path().join("j").exists());
        fs::write(dir.path().join("empty"), "\n").unwrap();
        let o = ordin(
            dir.path(),
            &["key", "generate", "j", "--passphrase-file", "empty"],
        );
        assert_eq!(
            stderr(&o),
            "ordin: error: empty: a passphrase can't be empty\n"
        );
        let o = ordin(dir.path(), &["key", "generate", "j", "--comment", "a\u{7}"]);
        assert_eq!(o.status.code(), Some(1));
        assert!(
            stderr(&o).contains("a comment can't hold control characters"),
            "{}",
            stderr(&o)
        );
        let o = ordin(
            dir.path(),
            &[
                "key",
                "generate",
                "j",
                "--no-passphrase",
                "--passphrase-file",
                "pass",
            ],
        );
        assert_eq!(o.status.code(), Some(2));
        assert!(!dir.path().join("j").exists());
    }

    fn show_json(dir: &Path, file: &str) -> Value {
        let o = ordin(dir, &["show", file, "--json"]);
        assert_eq!(o.status.code(), Some(0), "{}", stdout(&o));
        serde_json::from_str(&stdout(&o)).unwrap()
    }

    #[test]
    fn sign_adds_a_signature_and_never_changes_the_package() {
        let dir = packed();
        let alice = clear_key(dir.path(), "alice");
        let before = show_json(dir.path(), "hello.ordin");
        let o = ordin(dir.path(), &["sign", "hello.ordin", "--key", "alice"]);
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        let out = stdout(&o);
        assert_eq!(
            out,
            format!(
                "signed hello.ordin with {alice}\npackage {}\nsignatures: 1\n",
                before["package"].as_str().unwrap()
            )
        );
        let after = show_json(dir.path(), "hello.ordin");
        assert_eq!(after["package"], before["package"]);
        assert_eq!(after["manifest"], before["manifest"]);
        assert_ne!(after["image"], before["image"]);
        assert_eq!(after["signatures"], serde_json::json!([{ "key": alice }]));
        let o = ordin(dir.path(), &["show", "hello.ordin"]);
        assert!(
            stdout(&o).contains(&format!("\nsigned by {alice}\n")),
            "{}",
            stdout(&o)
        );
        // Signing again with the same key gives the same file.
        let once = fs::read(dir.path().join("hello.ordin")).unwrap();
        let o = ordin(
            dir.path(),
            &["sign", "hello.ordin", "--key", "alice", "--json"],
        );
        assert_eq!(o.status.code(), Some(0), "{}", stdout(&o));
        let v: Value = serde_json::from_str(&stdout(&o)).unwrap();
        let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
        assert_eq!(
            keys,
            ["file", "image", "key", "package", "replaced", "signatures"]
        );
        assert_eq!(v["replaced"], true);
        assert_eq!(v["image"], after["image"]);
        assert_eq!(fs::read(dir.path().join("hello.ordin")).unwrap(), once);
        let o = ordin(dir.path(), &["sign", "hello.ordin", "--key", "alice"]);
        assert!(stdout(&o).contains(", replacing its earlier signature\n"));
        // A second key, written elsewhere: the package itself is left alone.
        let bob = clear_key(dir.path(), "bob");
        let o = ordin(
            dir.path(),
            &["sign", "hello.ordin", "--key", "bob", "-o", "both.ordin"],
        );
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        assert_eq!(fs::read(dir.path().join("hello.ordin")).unwrap(), once);
        let mut expected = vec![alice, bob];
        expected.sort();
        let both: Vec<String> = show_json(dir.path(), "both.ordin")["signatures"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["key"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(both, expected);
        assert_eq!(mode(&dir.path().join("both.ordin")), 0o644);
        // An output directory that can't be written: the system's error
        // only, without the temporary file's path.
        let ro = dir.path().join("ro");
        fs::create_dir(&ro).unwrap();
        fs::set_permissions(&ro, Permissions::from_mode(0o555)).unwrap();
        let o = ordin(
            dir.path(),
            &["sign", "hello.ordin", "--key", "bob", "-o", "ro/x.ordin"],
        );
        fs::set_permissions(&ro, Permissions::from_mode(0o755)).unwrap();
        assert_eq!(o.status.code(), Some(1));
        assert_eq!(
            stderr(&o),
            "ordin: error: ro/x.ordin: Permission denied (os error 13)\n"
        );
        assert_eq!(fs::read_dir(&ro).unwrap().count(), 0);
    }

    #[test]
    fn sign_writes_beside_the_file_it_writes() {
        // The temporary file goes in the output's own directory: run from a
        // directory nobody can write to, the signature still gets written.
        let dir = packed();
        clear_key(dir.path(), "k");
        let out = dir.path().join("out");
        fs::create_dir(&out).unwrap();
        let locked = dir.path().join("locked");
        fs::create_dir(&locked).unwrap();
        fs::set_permissions(&locked, Permissions::from_mode(0o555)).unwrap();
        let o = ordin(
            &locked,
            &[
                "sign",
                "../hello.ordin",
                "--key",
                "../k",
                "-o",
                "../out/signed.ordin",
            ],
        );
        fs::set_permissions(&locked, Permissions::from_mode(0o755)).unwrap();
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        let left: Vec<_> = fs::read_dir(&out)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left, [std::ffi::OsString::from("signed.ordin")]);
    }

    #[test]
    fn signing_while_packing_gives_what_signing_afterwards_gives() {
        let dir = packed();
        clear_key(dir.path(), "k");
        let args = |out: &'static str, sign: bool| {
            let mut a = vec![
                "pack",
                "root",
                "--name",
                "hello",
                "--version",
                "2.12",
                "--license",
                "MIT",
                "--license-file",
                "MIT=COPYING",
                "--summary",
                "Prints a greeting",
                "-o",
                out,
            ];
            if sign {
                a.extend(["--sign-key", "k"]);
            }
            a
        };
        let o = ordin(dir.path(), &args("signed.ordin", true));
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        assert!(
            stdout(&o)
                .lines()
                .last()
                .unwrap()
                .starts_with("signed by ed25519:")
        );
        let o = ordin(dir.path(), &["sign", "hello.ordin", "--key", "k"]);
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        assert_eq!(
            fs::read(dir.path().join("signed.ordin")).unwrap(),
            fs::read(dir.path().join("hello.ordin")).unwrap()
        );
        let mut json = args("again.ordin", true);
        json.push("--json");
        let o = ordin(dir.path(), &json);
        let v: Value = serde_json::from_str(&stdout(&o)).unwrap();
        assert_eq!(v["signatures"].as_array().unwrap().len(), 1);
        let mut wrong = args("x.ordin", false);
        wrong.extend(["--passphrase-file", "pass"]);
        assert_eq!(ordin(dir.path(), &wrong).status.code(), Some(2));
    }

    #[test]
    fn a_key_must_be_its_owners_and_open() {
        let dir = packed();
        fs::write(dir.path().join("pass"), "right\n").unwrap();
        fs::write(dir.path().join("wrong"), "wrong\n").unwrap();
        let o = ordin(
            dir.path(),
            &["key", "generate", "sealed", "--passphrase-file", "pass"],
        );
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        clear_key(dir.path(), "clear");
        let sign = |extra: &[&str]| {
            let mut a = vec!["sign", "hello.ordin"];
            a.extend(extra);
            let o = ordin(dir.path(), &a);
            (o.status.code(), stderr(&o))
        };
        assert_eq!(
            sign(&["--key", "sealed", "--passphrase-file", "pass"]).0,
            Some(0)
        );
        assert_eq!(
            sign(&["--key", "sealed", "--passphrase-file", "wrong"]),
            (Some(1), "ordin: error: sealed: the passphrase is wrong, or the secret key file was changed\n".to_owned())
        );
        assert_eq!(
            sign(&["--key", "sealed"]),
            (Some(1), "ordin: error: no terminal to ask for the passphrase on; give it with --passphrase-file\n".to_owned())
        );
        assert_eq!(
            sign(&["--key", "clear", "--passphrase-file", "pass"]),
            (Some(1), "ordin: error: clear: the secret key isn't encrypted, so it takes no --passphrase-file\n".to_owned())
        );
        fs::set_permissions(dir.path().join("clear"), Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            sign(&["--key", "clear"]),
            (Some(1), "ordin: error: clear: a secret key file must be readable by its owner only, not mode 0644; run chmod 600 clear\n".to_owned())
        );
        let (code, err) = sign(&["--key", "clear.pub"]);
        assert_eq!(code, Some(1));
        assert!(err.contains("must be readable by its owner only"), "{err}");
        fs::set_permissions(dir.path().join("clear.pub"), Permissions::from_mode(0o600)).unwrap();
        let (code, err) = sign(&["--key", "clear.pub"]);
        assert_eq!(code, Some(1));
        assert!(
            err.starts_with("ordin: error: clear.pub: a secret key file: "),
            "{err}"
        );
        let o = ordin(
            dir.path(),
            &[
                "sign",
                "COPYING",
                "--key",
                "sealed",
                "--passphrase-file",
                "pass",
                "--json",
            ],
        );
        assert_eq!(o.status.code(), Some(1));
        assert!(
            stdout(&o).starts_with(r#"{"error":"COPYING: the archive"#),
            "{}",
            stdout(&o)
        );
        let o = ordin(
            dir.path(),
            &[
                "sign",
                "root",
                "--key",
                "sealed",
                "--passphrase-file",
                "pass",
            ],
        );
        assert_eq!(stderr(&o), "ordin: error: root: not a regular file\n");
        let o = ordin(
            dir.path(),
            &[
                "sign",
                "hello.ordin",
                "--key",
                "sealed",
                "--passphrase-file",
                "root",
            ],
        );
        assert_eq!(
            stderr(&o),
            "ordin: error: root: a passphrase file must be a regular file\n"
        );
    }

    // ordin verify (ORD-133).

    fn verify(dir: &Path, extra: &[&str]) -> (Option<i32>, String, String) {
        let mut args = vec!["verify", "hello.ordin"];
        args.extend(extra);
        let o = ordin(dir, &args);
        (o.status.code(), stdout(&o), stderr(&o))
    }

    /// What `ordin verify` prints about the packed fixture, before the
    /// signature lines.
    fn intact(dir: &Path) -> String {
        let shown = show_json(dir, "hello.ordin");
        format!(
            "hello.ordin is intact\npackage {}\nimage {}\n\
             facets: doc (1 file in 1 chunk, 12 B), runtime (1 file in 1 chunk, 21 B)\n",
            shown["package"].as_str().unwrap(),
            shown["image"].as_str().unwrap()
        )
    }

    #[test]
    fn verify_says_whether_a_key_you_trust_signed_the_package() {
        let dir = packed();
        let d = dir.path();
        let alice = clear_key(d, "alice");
        let bob = clear_key(d, "bob");
        assert_eq!(
            verify(d, &["--trust", "alice.pub"]),
            (
                Some(4),
                format!("{}not signed\n", intact(d)),
                "ordin: error: hello.ordin is intact but not signed\n".to_owned()
            )
        );
        let o = ordin(d, &["sign", "hello.ordin", "--key", "alice"]);
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        let untrusted = format!("{}signed by {alice}, not trusted\n", intact(d));
        assert_eq!(
            verify(d, &[]),
            (
                Some(5),
                untrusted.clone(),
                "ordin: error: hello.ordin is intact, but no key is trusted; \
                 give the keys you trust with --trust\n"
                    .to_owned()
            )
        );
        assert_eq!(
            verify(d, &["--trust", "bob.pub"]),
            (
                Some(5),
                untrusted,
                "ordin: error: hello.ordin is intact, but no key given with --trust signed it\n"
                    .to_owned()
            )
        );
        assert_eq!(
            verify(d, &["--trust", "bob.pub", "--trust", "alice.pub"]),
            (
                Some(0),
                format!("{}signed by {alice}, trusted\n", intact(d)),
                String::new()
            )
        );
        // Two signers: one trusted is enough, and each is listed by key.
        let o = ordin(d, &["sign", "hello.ordin", "--key", "bob"]);
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        let mut lines = [
            format!("signed by {alice}, not trusted"),
            format!("signed by {bob}, trusted"),
        ];
        lines.sort();
        assert_eq!(
            verify(d, &["--trust", "bob.pub"]),
            (
                Some(0),
                format!("{}{}\n", intact(d), lines.join("\n")),
                String::new()
            )
        );
    }

    #[test]
    fn verify_json_gives_the_result_and_each_signer() {
        let dir = packed();
        let d = dir.path();
        let alice = clear_key(d, "alice");
        clear_key(d, "bob");
        let json = |extra: &[&str]| {
            let (code, out, err) = verify(d, &[extra, &["--json"]].concat());
            assert_eq!(err, "");
            (code, serde_json::from_str::<Value>(&out).unwrap())
        };
        let (code, v) = json(&[]);
        assert_eq!(code, Some(4));
        let shown = show_json(d, "hello.ordin");
        assert_eq!(
            v,
            serde_json::json!({
                "facets": [
                    {"chunks": 1, "facet": "doc", "files": 1, "size": 12},
                    {"chunks": 1, "facet": "runtime", "files": 1, "size": 21},
                ],
                "file": "hello.ordin",
                "image": shown["image"],
                "licenses": 1,
                "package": shown["package"],
                "result": "unsigned",
                "signatures": [],
            })
        );
        ordin(d, &["sign", "hello.ordin", "--key", "alice"]);
        let (code, v) = json(&["--trust", "bob.pub"]);
        assert_eq!(code, Some(5));
        assert_eq!(v["result"], "untrusted");
        assert_eq!(
            v["signatures"],
            serde_json::json!([{"key": alice, "trusted": false}])
        );
        let (code, v) = json(&["--trust", "alice.pub"]);
        assert_eq!(code, Some(0));
        assert_eq!(v["result"], "trusted");
        assert_eq!(
            v["signatures"],
            serde_json::json!([{"key": alice, "trusted": true}])
        );
    }

    #[test]
    fn a_corrupt_package_fails_verify_and_names_the_part() {
        let dir = packed();
        let d = dir.path();
        clear_key(d, "alice");
        ordin(d, &["sign", "hello.ordin", "--key", "alice"]);
        let good = fs::read(d.join("hello.ordin")).unwrap();
        // One changed byte; the library's tests change every byte in turn.
        let mut bad = good.clone();
        let at = good.len() / 2;
        bad[at] ^= 1;
        fs::write(d.join("hello.ordin"), &bad).unwrap();
        let (code, out, err) = verify(d, &["--trust", "alice.pub"]);
        assert_eq!(code, Some(3));
        assert_eq!(out, "");
        assert!(
            err.starts_with("ordin: error: hello.ordin is corrupt: "),
            "{err}"
        );
        assert_eq!(err.lines().count(), 1, "{err}");
        let (code, out, err) = verify(d, &["--json"]);
        assert_eq!(code, Some(3));
        assert_eq!(err, "");
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["result"], "corrupt");
        assert_eq!(
            format!("ordin: error: {}\n", v["error"].as_str().unwrap()),
            stderr(&ordin(d, &["verify", "hello.ordin"]))
        );
        // Cut short: corrupt too, not a read error.
        fs::write(d.join("hello.ordin"), &good[..good.len() - 1]).unwrap();
        let (code, _, err) = verify(d, &[]);
        assert_eq!(code, Some(3));
        assert_eq!(
            err,
            "ordin: error: hello.ordin is corrupt: the archive: the file ends inside it\n"
        );
    }

    #[test]
    fn verify_fails_when_it_cant_check() {
        let dir = packed();
        let d = dir.path();
        clear_key(d, "alice");
        let o = ordin(d, &["verify", "missing.ordin"]);
        assert_eq!(o.status.code(), Some(1));
        assert_eq!(
            stderr(&o),
            "ordin: error: missing.ordin: No such file or directory (os error 2)\n"
        );
        let o = ordin(d, &["verify", "root"]);
        assert_eq!(o.status.code(), Some(1));
        assert_eq!(stderr(&o), "ordin: error: root: not a regular file\n");
        // A --trust file must be a public key file: not the secret key,
        // and not missing.
        let (code, _, err) = verify(d, &["--trust", "alice"]);
        assert_eq!(code, Some(1));
        assert!(
            err.starts_with("ordin: error: alice: a public key file: "),
            "{err}"
        );
        let (code, out, _) = verify(d, &["--trust", "nobody.pub", "--json"]);
        assert_eq!(code, Some(1));
        assert_eq!(
            out,
            r#"{"error":"nobody.pub: No such file or directory (os error 2)"}"#
        );
    }

    // ordin unpack (ORD-134).

    /// A package with a setuid program, a hard link, a symlink and a
    /// read-only directory, packed in `dir` as hello.ordin.
    fn rich() -> Scratch {
        let dir = fixture();
        let root = dir.path().join("root");
        fs::set_permissions(root.join("usr/bin/hello"), Permissions::from_mode(0o4755)).unwrap();
        fs::hard_link(root.join("usr/bin/hello"), root.join("usr/bin/hello2")).unwrap();
        std::os::unix::fs::symlink("hello", root.join("usr/bin/hi")).unwrap();
        write(&root, "usr/lib/ro/data", b"data\n", 0o644);
        fs::set_permissions(root.join("usr/lib/ro"), Permissions::from_mode(0o555)).unwrap();
        let o = ordin(
            dir.path(),
            &[
                "pack",
                "root",
                "--name",
                "hello",
                "--version",
                "2.12",
                "--license",
                "NONE",
                "--summary",
                "s",
                "-o",
                "hello.ordin",
            ],
        );
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        fs::set_permissions(root.join("usr/lib/ro"), Permissions::from_mode(0o755)).unwrap();
        dir
    }

    #[test]
    fn unpack_writes_every_file_with_its_permission_bits() {
        let dir = rich();
        let d = dir.path();
        let o = ordin(d, &["unpack", "hello.ordin", "--to", "out"]);
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        assert_eq!(stderr(&o), "");
        let shown = show_json(d, "hello.ordin");
        assert_eq!(
            stdout(&o),
            format!(
                "unpacked hello.ordin into out\npackage {}\nfacets: doc, runtime\n\
                 7 directories, 3 files (38 B), 1 symlink, 1 hard link\n\
                 not applied, recorded in out.ordin-meta.json: owners, setuid, setgid and \
                 sticky bits, extended attributes and capabilities\n",
                shown["package"].as_str().unwrap()
            )
        );
        let out = d.join("out");
        for path in [
            "usr/bin/hello",
            "usr/share/doc/hello/README",
            "usr/lib/ro/data",
        ] {
            assert_eq!(
                fs::read(out.join(path)).unwrap(),
                fs::read(d.join("root").join(path)).unwrap(),
                "{path}"
            );
        }
        // Only permission bits: the setuid bit is left out.
        assert_eq!(mode(&out.join("usr/bin/hello")), 0o755);
        assert_eq!(mode(&out.join("usr/share/doc/hello/README")), 0o644);
        assert_eq!(mode(&out.join("usr/lib/ro")), 0o555);
        assert_eq!(mode(&out), 0o700);
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            fs::metadata(out.join("usr/bin/hello2")).unwrap().ino(),
            fs::metadata(out.join("usr/bin/hello")).unwrap().ino()
        );
        assert_eq!(
            fs::read_link(out.join("usr/bin/hi")).unwrap(),
            Path::new("hello")
        );
        // The sidecar has each facet's tree exactly, setuid bit and all.
        let o = ordin(d, &["show", "hello.ordin", "--facets", "--json"]);
        let shown: Value = serde_json::from_str(&stdout(&o)).unwrap();
        let meta: Value =
            serde_json::from_slice(&fs::read(d.join("out.ordin-meta.json")).unwrap()).unwrap();
        assert_eq!(meta["ordin-unpack"], 1);
        assert_eq!(meta["package"], shown["package"]);
        for facet in ["doc", "runtime"] {
            assert_eq!(meta["facets"][facet]["ordin-tree"], 1);
            assert_eq!(meta["facets"][facet]["entries"], shown["files"][facet]);
        }
        assert!(
            meta["facets"]["runtime"]["entries"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["path"] == "/usr/bin/hello" && e["mode"] == "4755"),
            "{meta}"
        );
        assert_eq!(mode(&d.join("out.ordin-meta.json")), 0o644);
    }

    #[test]
    fn unpack_can_take_only_some_facets() {
        let dir = rich();
        let d = dir.path();
        let o = ordin(
            d,
            &[
                "unpack",
                "hello.ordin",
                "--to",
                "docs",
                "--facet",
                "doc",
                "--json",
            ],
        );
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        let v: Value = serde_json::from_str(&stdout(&o)).unwrap();
        let shown = show_json(d, "hello.ordin");
        assert_eq!(
            v,
            serde_json::json!({
                "dirs": 4,
                "facets": ["doc"],
                "file": "hello.ordin",
                "files": 1,
                "hard_links": 0,
                "meta": "docs.ordin-meta.json",
                "package": shown["package"],
                "size": 12,
                "symlinks": 0,
                "to": "docs",
            })
        );
        assert!(d.join("docs/usr/share/doc/hello/README").is_file());
        assert!(!d.join("docs/usr/bin").exists());
        let meta: Value =
            serde_json::from_slice(&fs::read(d.join("docs.ordin-meta.json")).unwrap()).unwrap();
        let facets: Vec<&String> = meta["facets"].as_object().unwrap().keys().collect();
        assert_eq!(facets, ["doc"]);
    }

    #[test]
    fn unpack_never_replaces_anything() {
        let dir = rich();
        let d = dir.path();
        let unpack = |to: &str, extra: &[&str]| {
            let mut args = vec!["unpack", "hello.ordin", "--to", to];
            args.extend(extra);
            let o = ordin(d, &args);
            (o.status.code(), stderr(&o))
        };
        fs::create_dir(d.join("there")).unwrap();
        fs::write(d.join("file"), b"mine").unwrap();
        fs::write(d.join("taken.ordin-meta.json"), b"mine").unwrap();
        for (to, said) in [
            (
                "there",
                "there: already exists; ordin unpack never replaces anything",
            ),
            (
                "file",
                "file: already exists; ordin unpack never replaces anything",
            ),
            (
                "taken",
                "taken.ordin-meta.json: already exists; ordin unpack never replaces anything",
            ),
            (
                ".",
                ".: --to must name a new directory, by a name that isn't '.' or '..'",
            ),
        ] {
            assert_eq!(
                unpack(to, &[]),
                (Some(1), format!("ordin: error: {said}\n")),
                "{to}"
            );
        }
        assert_eq!(fs::read(d.join("file")).unwrap(), b"mine");
        assert_eq!(fs::read(d.join("taken.ordin-meta.json")).unwrap(), b"mine");
        assert!(!d.join("taken").exists());
        assert_eq!(
            unpack("new", &["--facet", "man"]),
            (
                Some(1),
                "ordin: error: hello.ordin: the package has no facet man; it has doc, runtime\n"
                    .to_owned()
            )
        );
        assert!(!d.join("new").exists());
        let o = ordin(d, &["unpack", "missing.ordin", "--to", "new"]);
        assert_eq!(o.status.code(), Some(1));
        assert_eq!(
            stderr(&o),
            "ordin: error: missing.ordin: No such file or directory (os error 2)\n"
        );
        assert!(!d.join("new").exists());
    }

    /// The names in `dir`, sorted.
    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn a_failed_unpack_leaves_nothing_behind() {
        let dir = rich();
        let d = dir.path();
        // The README's one chunk is stored as it is: change a byte of it,
        // so the package opens and unpacking fails after other files
        // were written.
        let mut bytes = fs::read(d.join("hello.ordin")).unwrap();
        let readme = b"Says hello.\n";
        let at = bytes
            .windows(readme.len())
            .position(|w| w == readme)
            .expect("the fixture stores the README's chunk as it is");
        bytes[at] ^= 1;
        fs::write(d.join("hello.ordin"), &bytes).unwrap();
        let before = names(d);
        let o = ordin(d, &["unpack", "hello.ordin", "--to", "out"]);
        assert_eq!(o.status.code(), Some(1));
        let err = stderr(&o);
        assert!(
            err.starts_with("ordin: error: out/usr/share/doc/hello/README: chunk blake3:")
                && err.contains(" in the chunk pack for facet doc: "),
            "{err}"
        );
        assert_eq!(names(d), before);
    }

    // ordin pack --version-from git (ORD-122).

    /// Runs git in `dir` as nobody in particular, at a fixed date.
    fn git(dir: &Path, args: &[&str]) -> String {
        let o = Command::new("git")
            .current_dir(dir)
            .args([
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "tag.gpgsign=false",
            ])
            .args(args)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_DATE", "2026-11-14T12:00:00+00:00")
            .env("GIT_COMMITTER_DATE", "2026-11-14T12:00:00+00:00")
            .output()
            .unwrap();
        assert!(o.status.success(), "git {args:?}: {}", stderr(&o));
        String::from_utf8(o.stdout).unwrap().trim().to_owned()
    }

    /// A checkout outside any other repository: a tag, two commits after
    /// it, and an untracked install root.
    fn checkout() -> (TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        git(d, &["init", "-q"]);
        fs::write(d.join("src"), b"one\n").unwrap();
        git(d, &["add", "src"]);
        git(d, &["commit", "-q", "-m", "one"]);
        git(d, &["tag", "v1.4.2"]);
        for n in ["two\n", "three\n"] {
            fs::write(d.join("src"), n).unwrap();
            git(d, &["commit", "-q", "-am", "more"]);
        }
        write(
            &d.join("root"),
            "usr/bin/hello",
            b"#!/bin/sh\necho hello\n",
            0o755,
        );
        let head = git(d, &["rev-parse", "HEAD"]);
        (dir, head)
    }

    /// `ordin` in `dir`, with git kept from looking above it.
    fn ordin_in(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
        let mut c = Command::new(env!("CARGO_BIN_EXE_ordin"));
        c.current_dir(dir)
            .args(args)
            .env("GIT_CEILING_DIRECTORIES", dir.parent().unwrap());
        for (k, v) in env {
            c.env(k, v);
        }
        c.output().unwrap()
    }

    const FROM_GIT: [&str; 8] = [
        "pack",
        "root",
        "--name",
        "hello",
        "--version-from",
        "git",
        "--license",
        "NONE",
    ];

    #[test]
    fn a_snapshot_is_versioned_from_its_checkout() {
        let (dir, head) = checkout();
        let d = dir.path();
        let mut args = FROM_GIT.to_vec();
        args.extend(["--summary", "s"]);
        let o = ordin_in(d, &args, &[]);
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        let file = format!("hello-1.4.2^20261114.2.g{}-1.noarch.ordin", &head[..7]);
        let out = stdout(&o);
        assert!(out.starts_with(&format!("wrote {file} (")), "{out}");
        assert!(out.ends_with(&format!("\ncommit {head}\n")), "{out}");
        // The full commit is in the manifest's provenance.
        let v = show_json(d, &file);
        assert_eq!(
            v["manifest"]["version"]["upstream"],
            format!("1.4.2^20261114.2.g{}", &head[..7])
        );
        assert_eq!(v["manifest"]["provenance"]["commit"], head.as_str());
        let o = ordin(d, &["show", &file]);
        assert!(
            stdout(&o).contains(&format!("\ncommit: {head}\n")),
            "{}",
            stdout(&o)
        );
        // With --json, the commit is reported too.
        args.extend(["-o", "again.ordin", "--json", "--release", "2"]);
        let o = ordin_in(d, &args, &[]);
        assert_eq!(o.status.code(), Some(0), "{}", stdout(&o));
        let v: Value = serde_json::from_str(&stdout(&o)).unwrap();
        assert_eq!(v["commit"], head.as_str());
        assert_eq!(v["version"], format!("1.4.2^20261114.2.g{}-2", &head[..7]));
    }

    #[test]
    fn exactly_one_of_version_and_version_from_is_given() {
        let (dir, _) = checkout();
        let d = dir.path();
        let mut both = FROM_GIT.to_vec();
        both.extend(["--version", "1.0"]);
        let o = ordin_in(d, &both, &[]);
        assert_eq!(o.status.code(), Some(2));
        assert!(stderr(&o).contains("cannot be used with"), "{}", stderr(&o));
        let o = ordin_in(d, &["pack", "root", "--name", "hello"], &[]);
        assert_eq!(o.status.code(), Some(2));
        assert!(stderr(&o).contains("--version <VERSION>"), "{}", stderr(&o));
        let o = ordin_in(
            d,
            &["pack", "root", "--name", "hello", "--version-from", "svn"],
            &[],
        );
        assert_eq!(o.status.code(), Some(2));
    }

    #[test]
    fn version_from_git_says_why_it_cant() {
        let (dir, head) = checkout();
        let d = dir.path();
        // A changed tracked file.
        fs::write(d.join("src"), b"changed\n").unwrap();
        let o = ordin_in(d, &FROM_GIT, &[]);
        assert_eq!(o.status.code(), Some(1));
        assert_eq!(
            stderr(&o).lines().last().unwrap(),
            format!(
                "ordin: error: making the version from git: tracked files differ from the \
                 commit {head}; commit or stash them, so the version describes what is packed"
            )
        );
        // Not a repository.
        let none = tempfile::tempdir().unwrap();
        write(&none.path().join("root"), "usr/bin/x", b"x\n", 0o755);
        let o = ordin_in(none.path(), &FROM_GIT, &[]);
        assert_eq!(o.status.code(), Some(1));
        let err = stderr(&o);
        assert!(
            err.contains(
                "ordin: error: making the version from git: git rev-parse \
                 --is-shallow-repository failed: fatal: not a git repository"
            ),
            "{err}"
        );
        // No git at all.
        let o = ordin_in(d, &FROM_GIT, &[("PATH", "/nonexistent")]);
        assert_eq!(o.status.code(), Some(1));
        assert_eq!(
            stderr(&o).lines().last().unwrap(),
            "ordin: error: making the version from git: can't run git: No such file or \
             directory (os error 2)"
        );
    }
}
