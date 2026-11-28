// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! The whole run, with a fake for every program it starts.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::os::unix::ffi::OsStringExt;

use flate2::Compression;
use flate2::write::GzEncoder;
use serde_json::json;

use super::*;
use crate::release::dist::sha256_file;
use crate::release::exec::Captured;

/// A tar file with a directory, a file and a symlink at `top/`.
fn tar(top: &str, file: &str) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut b = tar::Builder::new(&mut out);
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Directory);
        h.set_mode(0o755);
        h.set_size(0);
        b.append_data(&mut h, format!("{top}/"), &b""[..]).unwrap();
        let mut h = tar::Header::new_gnu();
        h.set_mode(0o644);
        h.set_size(file.len() as u64);
        b.append_data(&mut h, format!("{top}/{file}"), file.as_bytes())
            .unwrap();
        b.finish().unwrap();
    }
    out
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut e = GzEncoder::new(Vec::new(), Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

/// What the fake programs do.
struct Fake {
    /// Each URL's content.
    downloads: BTreeMap<String, Vec<u8>>,
    /// Each downloaded deb's tar stream, by its content.
    debs: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Added to every `ordin show` output.
    extra: RefCell<Value>,
    /// What `ordin show` prints instead, if set.
    show: RefCell<Option<Vec<u8>>>,
    /// Every command run.
    runs: RefCell<Vec<Cmd>>,
}

impl Fake {
    fn programs(&self) -> Vec<String> {
        self.runs
            .borrow()
            .iter()
            .map(|c| {
                let first = c.arg_strings().into_iter().next().unwrap_or_default();
                format!(
                    "{} {first}",
                    Path::new(&c.program).file_name().unwrap().to_string_lossy()
                )
            })
            .collect()
    }
}

/// Every path below `root`, sorted, as `path` or `path -> target`.
fn listing(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for e in fs::read_dir(&dir).unwrap() {
            let p = e.unwrap().path();
            let rel = p.strip_prefix(root).unwrap().display().to_string();
            let meta = fs::symlink_metadata(&p).unwrap();
            if meta.file_type().is_symlink() {
                out.push(format!("{rel} -> {}", fs::read_link(&p).unwrap().display()));
            } else {
                out.push(rel);
                if meta.is_dir() {
                    stack.push(p);
                }
            }
        }
    }
    out.sort();
    out
}

impl Exec for Fake {
    fn run(&self, cmd: &Cmd) -> Result<Captured, Error> {
        self.runs.borrow_mut().push(cmd.clone());
        let args = cmd.arg_strings();
        let program = Path::new(&cmd.program)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        match (program.as_str(), args.first().map(String::as_str)) {
            ("cargo", _) => Ok(Captured::default()),
            ("curl", _) => {
                let out = &args[args.iter().position(|a| a == "--output").unwrap() + 1];
                let url = args.last().unwrap();
                fs::write(out, &self.downloads[url]).unwrap();
                Ok(Captured::default())
            }
            ("dpkg-deb", _) => {
                let deb = fs::read(&args[1]).unwrap();
                Ok(Captured {
                    stdout: self.debs[&deb].clone(),
                    stderr: Vec::new(),
                })
            }
            ("ordin", Some("pack")) => {
                // The package records what it was packed from.
                let dir = cmd.dir.clone().unwrap();
                let record = json!({
                    "files": listing(Path::new(&args[1])),
                    "licenses": args.iter().filter(|a| *a == "--license-file").count(),
                    "recipe": args[2] == "--manifest" && args[3].ends_with("ordin.toml"),
                });
                let out = &args[args.iter().position(|a| a == "-o").unwrap() + 1];
                fs::write(dir.join(out), record.to_string()).unwrap();
                Ok(Captured {
                    stdout: b"wrote it\n".to_vec(),
                    stderr: b"ordin: warning: one\nordin: warning: two\n".to_vec(),
                })
            }
            ("ordin", Some("show")) => {
                if let Some(show) = self.show.borrow().clone() {
                    return Ok(Captured {
                        stdout: show,
                        stderr: Vec::new(),
                    });
                }
                let dir = cmd.dir.clone().unwrap();
                let mut value: Value =
                    serde_json::from_slice(&fs::read(dir.join(&args[1])).unwrap()).unwrap();
                value["file"] = json!(args[1]);
                value["extra"] = self.extra.borrow().clone();
                Ok(Captured {
                    stdout: value.to_string().into_bytes(),
                    stderr: Vec::new(),
                })
            }
            _ => Err(Error::check(format!("unexpected {}", cmd.display()))),
        }
    }
}

fn sha256(data: &[u8]) -> String {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("f");
    fs::write(&f, data).unwrap();
    sha256_file(&f).unwrap()
}

/// A workspace with a two-package corpus, and the fake that serves it.
struct World {
    _dir: tempfile::TempDir,
    fake: Fake,
    opts: Options,
}

fn world() -> World {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("ws");
    let tgz = gzip(&tar("pkg-1", "COPYING"));
    let deb = b"a deb".to_vec();
    let deb_tar = tar(".", "usr/share/doc/b/copyright");
    let list = format!(
        "format = 1
[[package]]
name = \"a\"
about = \"a tarball\"
licenses = {{ MIT = \"usr/share/doc/a/COPYING\" }}
links = [{{ path = \"usr/bin/a\", target = \"../share/doc/a/COPYING\" }}]
[[package.source]]
url = \"https://example.org/a.tar.gz\"
size = {}
sha256 = \"{}\"
format = \"tar.gz\"
strip = 1
place = [{{ from = \"COPYING\", to = \"usr/share/doc/a/COPYING\" }}]
[[package]]
name = \"b\"
about = \"a deb\"
licenses = {{ MIT = \"usr/share/doc/b/copyright\", ISC = \"usr/share/doc/b/copyright\" }}
[[package.source]]
url = \"https://example.org/b.deb\"
size = {}
sha256 = \"{}\"
format = \"deb\"
",
        tgz.len(),
        sha256(&tgz),
        deb.len(),
        sha256(&deb)
    );
    for name in ["a", "b"] {
        fs::create_dir_all(root.join("corpus").join(name)).unwrap();
        fs::write(
            root.join("corpus").join(name).join("ordin.toml"),
            "format = 1\n",
        )
        .unwrap();
    }
    fs::write(root.join(LIST), list).unwrap();
    let fake = Fake {
        downloads: BTreeMap::from([
            ("https://example.org/a.tar.gz".to_owned(), tgz),
            ("https://example.org/b.deb".to_owned(), deb.clone()),
        ]),
        debs: BTreeMap::from([(deb, deb_tar)]),
        extra: RefCell::new(json!(1)),
        show: RefCell::new(None),
        runs: RefCell::new(Vec::new()),
    };
    let opts = Options {
        root,
        target: dir.path().join("target"),
        cargo: "cargo".to_owned(),
        update: false,
    };
    World {
        _dir: dir,
        fake,
        opts,
    }
}

impl World {
    fn run(&self, update: bool) -> (Result<Report, Error>, String) {
        let mut log = Vec::new();
        let opts = Options {
            update,
            ..self.opts.clone()
        };
        let result = run(&self.fake, &opts, &mut log);
        (result, String::from_utf8(log).unwrap())
    }

    fn golden(&self, name: &str) -> PathBuf {
        self.opts.root.join(DIR).join(name).join("show.json")
    }
}

#[test]
fn update_writes_the_golden_files_and_a_check_then_passes() {
    let w = world();
    let (report, log) = w.run(true);
    let report = report.unwrap();
    assert_eq!(report.packages, ["a", "b"]);
    assert_eq!(report.updated, ["a", "b"]);
    let a: Value = serde_json::from_str(&fs::read_to_string(w.golden("a")).unwrap()).unwrap();
    assert_eq!(
        a,
        json!({
            "extra": 1,
            "file": "a.ordin",
            "files": ["usr", "usr/bin", "usr/bin/a -> ../share/doc/a/COPYING", "usr/share", "usr/share/doc", "usr/share/doc/a", "usr/share/doc/a/COPYING"],
            "licenses": 1,
            "recipe": true,
        })
    );
    let b: Value = serde_json::from_str(&fs::read_to_string(w.golden("b")).unwrap()).unwrap();
    assert_eq!(b["licenses"], 2);
    assert_eq!(
        fs::read_to_string(w.golden("b")).unwrap(),
        snapshot::pretty(&b)
    );
    assert_eq!(
        log.lines().collect::<Vec<_>>(),
        [
            "corpus: building the release ordin",
            "corpus: a: a tarball",
            "corpus: downloading https://example.org/a.tar.gz",
            "corpus: a: laid out 7 paths",
            "corpus: a: ordin: warning: one",
            "corpus: a: ordin: warning: two",
            "corpus: a: wrote corpus/a/show.json",
            "corpus: b: a deb",
            "corpus: downloading https://example.org/b.deb",
            "corpus: b: laid out 5 paths",
            "corpus: b: ordin: warning: one",
            "corpus: b: ordin: warning: two",
            "corpus: b: wrote corpus/b/show.json",
        ]
    );
    assert_eq!(
        w.fake.programs(),
        [
            "cargo build",
            "curl --disable",
            "ordin pack",
            "ordin show",
            "curl --disable",
            "dpkg-deb --fsys-tarfile",
            "ordin pack",
            "ordin show"
        ]
    );
    // The build, and how pack and show are run.
    let runs = w.fake.runs.borrow();
    assert_eq!(
        runs[0].arg_strings(),
        ["build", "--release", "--locked", "-p", "ordin"]
    );
    assert_eq!(runs[0].dir.as_deref(), Some(w.opts.root.as_path()));
    assert!(runs[0].interactive);
    let target = &w.opts.target;
    assert_eq!(
        runs[2].program,
        target.join("release/ordin").display().to_string()
    );
    let stage = target.join("corpus/stage/a");
    assert_eq!(
        runs[2].arg_strings(),
        [
            "pack".to_owned(),
            stage.display().to_string(),
            "--manifest".to_owned(),
            w.opts
                .root
                .join("corpus/a/ordin.toml")
                .display()
                .to_string(),
            "--license-file".to_owned(),
            format!("MIT={}", stage.join("usr/share/doc/a/COPYING").display()),
            "-o".to_owned(),
            "a.ordin".to_owned(),
        ]
    );
    assert_eq!(
        runs[2].dir.as_deref(),
        Some(target.join("corpus/out").as_path())
    );
    assert_eq!(runs[3].arg_strings(), ["show", "a.ordin", "--json"]);
    assert_eq!(
        runs[3].dir.as_deref(),
        Some(target.join("corpus/out").as_path())
    );
    drop(runs);
    // The install roots are removed after a run; the packages are kept.
    assert!(!target.join("corpus/stage").exists());
    assert!(target.join("corpus/out/a.ordin").exists());

    // Nothing changed: nothing is written, nothing downloaded again.
    w.fake.runs.borrow_mut().clear();
    let (report, log) = w.run(true);
    assert!(report.unwrap().updated.is_empty());
    assert!(!log.contains("downloading") && !log.contains("wrote"));
    let (report, _) = w.run(false);
    assert_eq!(
        report.unwrap(),
        Report {
            packages: vec!["a".to_owned(), "b".to_owned()],
            updated: Vec::new()
        }
    );
}

#[test]
fn a_check_lists_every_difference() {
    let w = world();
    w.run(true).0.unwrap();
    *w.fake.extra.borrow_mut() = json!(2);
    fs::remove_file(w.golden("b")).unwrap();
    let (result, _) = w.run(false);
    assert_eq!(
        result.unwrap_err().to_string(),
        "a differs from corpus/a/show.json:
  /extra: 1 became 2
b differs from corpus/b/show.json:
  there is no show.json yet
run `cargo xtask corpus --update` and review the change with `git diff corpus/`"
    );
    // A failed check keeps the install roots to look at.
    assert!(w.opts.target.join("corpus/stage/a/usr").exists());
    // The same value, laid out another way.
    *w.fake.extra.borrow_mut() = json!(1);
    w.run(true).0.unwrap();
    let a: Value = serde_json::from_str(&fs::read_to_string(w.golden("a")).unwrap()).unwrap();
    fs::write(w.golden("a"), a.to_string()).unwrap();
    assert_eq!(
        w.run(false).0.unwrap_err().to_string(),
        "a differs from corpus/a/show.json:
  the same value, laid out differently
run `cargo xtask corpus --update` and review the change with `git diff corpus/`"
    );
    fs::write(w.golden("a"), "{").unwrap();
    assert!(
        w.run(false)
            .0
            .unwrap_err()
            .to_string()
            .starts_with(&format!("can't parse {}: ", w.golden("a").display()))
    );
    fs::remove_file(w.golden("a")).unwrap();
    fs::create_dir(w.golden("a")).unwrap();
    assert_eq!(
        w.run(false).0.unwrap_err().to_string(),
        format!("{}: Is a directory (os error 21)", w.golden("a").display())
    );
}

#[test]
fn the_corpus_directory_must_match_the_list() {
    let w = world();
    fs::create_dir(w.opts.root.join("corpus/old")).unwrap();
    assert_eq!(
        w.run(false).0.unwrap_err().to_string(),
        "corpus/old is no package's directory; remove it or add the package to corpus/corpus.toml"
    );
    fs::remove_dir(w.opts.root.join("corpus/old")).unwrap();
    fs::remove_file(w.opts.root.join("corpus/b/ordin.toml")).unwrap();
    assert_eq!(
        w.run(false).0.unwrap_err().to_string(),
        "b has no recipe, corpus/b/ordin.toml"
    );
    // Files beside the list are fine.
    fs::write(w.opts.root.join("corpus/b/ordin.toml"), "").unwrap();
    fs::write(w.opts.root.join("corpus/README.md"), "").unwrap();
    w.run(true).0.unwrap();
    fs::remove_file(w.opts.root.join(LIST)).unwrap();
    assert_eq!(
        w.run(false).0.unwrap_err().to_string(),
        format!(
            "{}: No such file or directory (os error 2)",
            w.opts.root.join(LIST).display()
        )
    );
    fs::write(w.opts.root.join(LIST), "format = 2").unwrap();
    assert!(w.run(false).0.is_err());
}

#[test]
fn a_license_text_must_be_a_file_in_the_install_root() {
    let w = world();
    let list = fs::read_to_string(w.opts.root.join(LIST)).unwrap();
    fs::write(
        w.opts.root.join(LIST),
        list.replace(
            "ISC = \"usr/share/doc/b/copyright\"",
            "ISC = \"usr/share/doc/b\"",
        ),
    )
    .unwrap();
    assert_eq!(
        w.run(true).0.unwrap_err().to_string(),
        "b: the license text usr/share/doc/b for ISC isn't a file in the install root"
    );
}

#[test]
fn a_work_directory_that_cant_be_emptied_stops_the_run() {
    let w = world();
    let stage = w.opts.target.join("corpus/stage");
    fs::create_dir_all(stage.parent().unwrap()).unwrap();
    fs::write(&stage, "not a directory").unwrap();
    assert_eq!(
        w.run(false).0.unwrap_err().to_string(),
        format!("{}: Not a directory (os error 20)", stage.display())
    );
}

#[test]
fn a_show_that_isnt_json_or_a_target_that_isnt_utf8_is_refused() {
    let w = world();
    *w.fake.show.borrow_mut() = Some(b"not json".to_vec());
    assert!(
        w.run(true)
            .0
            .unwrap_err()
            .to_string()
            .starts_with("can't parse ordin show --json of a.ordin: ")
    );
    let mut bad = w.opts.clone();
    bad.target = PathBuf::from(OsString::from_vec(b"/tmp/\xff".to_vec()));
    let e = run(&w.fake, &bad, &mut Vec::new()).unwrap_err();
    assert_eq!(
        e.to_string(),
        "/tmp/\u{fffd}/release/ordin isn't a UTF-8 path"
    );
    // A failing program stops the run.
    let mut no_cargo = w.opts.clone();
    no_cargo.cargo = "nothing".to_owned();
    assert_eq!(
        run(&w.fake, &no_cargo, &mut Vec::new())
            .unwrap_err()
            .to_string(),
        "unexpected nothing build --release --locked -p ordin"
    );
}
