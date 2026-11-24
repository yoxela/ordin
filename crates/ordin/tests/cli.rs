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

    fn temp() -> TempDir {
        tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap()
    }

    fn write(root: &Path, path: &str, bytes: &[u8], mode: u32) {
        let at = root.join(path);
        fs::create_dir_all(at.parent().unwrap()).unwrap();
        fs::write(&at, bytes).unwrap();
        fs::set_permissions(&at, Permissions::from_mode(mode)).unwrap();
    }

    /// A directory holding `root/`, an install root, and `COPYING`.
    fn fixture() -> TempDir {
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
        let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
        assert_eq!(
            keys,
            [
                "arch", "facets", "file", "image", "license", "name", "package", "provides",
                "requires", "size", "version", "warnings"
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
    fn packed() -> TempDir {
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
        assert_eq!(keys, ["file", "image", "manifest", "package", "signature"]);
        assert_eq!(v["file"], "hello.ordin");
        assert_eq!(v["package"], packed["package"]);
        assert_eq!(v["image"], packed["image"]);
        assert_eq!(v["signature"], Value::Null);
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
}
