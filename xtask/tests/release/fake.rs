// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! A fake for the programs a release test can't run: `gh` (GitHub, kept as
//! a directory of release files), the container build and `cargo build`.
//! git and ssh-keygen run for real.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use xtask::release::Error;
use xtask::release::exec::{Captured, Cmd, Exec, System};

/// Overrides one call: return `Some` to answer it instead of the fake.
pub type Hook = Box<dyn Fn(&Fake, &Cmd) -> Option<Result<Captured, Error>>>;

pub struct Fake {
    /// The draft release's files on "GitHub".
    pub server: PathBuf,
    /// The files the rebuild produces.
    pub rebuild: PathBuf,
    pub draft: RefCell<bool>,
    pub tag: String,
    /// `gh api` responses by path.
    pub api: BTreeMap<String, String>,
    pub calls: RefCell<Vec<Cmd>>,
    pub hook: Hook,
}

pub fn ok(stdout: &str) -> Result<Captured, Error> {
    Ok(Captured {
        stdout: stdout.as_bytes().to_vec(),
        stderr: Vec::new(),
    })
}

pub fn fail(cmd: &Cmd) -> Result<Captured, Error> {
    Err(Error::Command {
        command: cmd.display(),
        detail: "exit status: 1: refused by the fake".into(),
    })
}

fn io<T>(result: std::io::Result<T>, path: &Path) -> Result<T, Error> {
    result.map_err(|e| Error::io(path, &e))
}

/// Copies the files in `from` into `to`, creating it.
pub fn copy_dir(from: &Path, to: &Path) -> Result<(), Error> {
    io(fs::create_dir_all(to), to)?;
    for entry in io(fs::read_dir(from), from)? {
        let entry = io(entry, from)?;
        io(
            fs::copy(entry.path(), to.join(entry.file_name())),
            &entry.path(),
        )?;
    }
    Ok(())
}

/// The names of the files in `dir`, sorted.
pub fn names(dir: &Path) -> Result<Vec<String>, Error> {
    let mut names = Vec::new();
    for entry in io(fs::read_dir(dir), dir)? {
        names.push(io(entry, dir)?.file_name().to_string_lossy().into_owned());
    }
    names.sort();
    Ok(names)
}

impl Fake {
    pub fn new(server: PathBuf, rebuild: PathBuf, tag: &str) -> Self {
        Self {
            server,
            rebuild,
            draft: RefCell::new(true),
            tag: tag.to_owned(),
            api: BTreeMap::new(),
            calls: RefCell::new(Vec::new()),
            hook: Box::new(|_, _| None),
        }
    }

    /// The calls made to `program`, as argument lists.
    pub fn calls_to(&self, program: &str) -> Vec<Vec<String>> {
        self.calls
            .borrow()
            .iter()
            .filter(|c| c.program == program)
            .map(Cmd::arg_strings)
            .collect()
    }

    /// Whether any call to `program` starts with `prefix`.
    pub fn called(&self, program: &str, prefix: &[&str]) -> bool {
        self.calls_to(program)
            .iter()
            .any(|args| args.len() >= prefix.len() && args.iter().zip(prefix).all(|(a, p)| a == p))
    }

    fn gh(&self, cmd: &Cmd) -> Result<Captured, Error> {
        let args = cmd.arg_strings();
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        match a.as_slice() {
            ["api", .., path] => self
                .api
                .get(*path)
                .map_or_else(|| fail(cmd), |body| ok(body)),
            [
                "release",
                "view",
                tag,
                "--repo",
                _,
                "--json",
                "isDraft,tagName,assets",
            ] => {
                let assets: Vec<String> = names(&self.server)?
                    .iter()
                    .map(|n| format!("{{\"name\":\"{n}\"}}"))
                    .collect();
                ok(&format!(
                    "{{\"isDraft\":{},\"tagName\":\"{}\",\"assets\":[{}]}}",
                    self.draft.borrow(),
                    if *tag == self.tag { tag } else { "other" },
                    assets.join(",")
                ))
            }
            ["release", "download", _, "--repo", _, "--dir", dir] => {
                copy_dir(&self.server, Path::new(dir))?;
                ok("")
            }
            ["attestation", "verify", ..] => ok(""),
            ["release", "upload", _, "--repo", _, files @ ..] => {
                for f in files {
                    let f = Path::new(f);
                    let name = f.file_name().ok_or_else(|| Error::check("no file name"))?;
                    io(fs::copy(f, self.server.join(name)), f)?;
                }
                ok("")
            }
            ["release", "edit", _, "--repo", _, "--draft=false"] => {
                *self.draft.borrow_mut() = false;
                ok("")
            }
            _ => fail(cmd),
        }
    }

    /// `bash build.sh <src> <out> <tag>`: the rebuild's files appear in
    /// `<out>/dist`.
    fn build(&self, cmd: &Cmd) -> Result<Captured, Error> {
        match cmd.arg_strings().as_slice() {
            [script, _, out, tag]
                if script.ends_with("scripts/release/build.sh") && *tag == self.tag =>
            {
                copy_dir(&self.rebuild, &Path::new(out).join("dist"))?;
                ok("")
            }
            _ => fail(cmd),
        }
    }

    /// `cargo build --target <t>` in a workspace: writes a fake binary per
    /// program.
    fn cargo(cmd: &Cmd) -> Result<Captured, Error> {
        let args = cmd.arg_strings();
        let (Some(i), Some(root)) = (args.iter().position(|a| a == "--target"), &cmd.dir) else {
            return fail(cmd);
        };
        let target = args.get(i + 1).ok_or_else(|| Error::check("no target"))?;
        let dir = root.join("target").join(target).join("release");
        io(fs::create_dir_all(&dir), &dir)?;
        for (_, bin) in xtask::release::dist::PROGRAMS {
            let path = dir.join(bin);
            io(fs::write(&path, format!("{bin} for {target}")), &path)?;
        }
        ok("")
    }
}

impl Exec for Fake {
    fn run(&self, cmd: &Cmd) -> Result<Captured, Error> {
        self.calls.borrow_mut().push(cmd.clone());
        if let Some(answer) = (self.hook)(self, cmd) {
            return answer;
        }
        match cmd.program.as_str() {
            "gh" => self.gh(cmd),
            "bash" => self.build(cmd),
            "cargo" => Self::cargo(cmd),
            _ => System.run(cmd),
        }
    }
}
