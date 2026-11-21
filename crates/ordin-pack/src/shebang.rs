// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! The interpreter a script's `#!` line names (ORD-113).
//!
//! `#!/usr/bin/python3` and `#!/usr/bin/env python3` both name
//! `/usr/bin/python3`. `/bin`, `/sbin`, `/lib` and `/lib64` are read as
//! their `/usr` counterparts, as the layout moves them. Anything unusual
//! is reported rather than guessed at.

use ordin_core::FilePath;

/// How much of a file the kernel reads for its `#!` line, and so how much
/// is read here.
pub const HEAD: usize = 256;

/// The `env` programs whose first argument names the interpreter.
const ENV: &[&str] = &["/usr/bin/env", "/bin/env"];

/// Directories the layout moves under `/usr`.
const MERGED: &[&str] = &["/bin/", "/sbin/", "/lib/", "/lib64/"];

/// What a `#!` line says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Shebang {
    /// The interpreter, as a path a `file:` atom can hold.
    Interpreter(FilePath),
    /// A line Ordin won't guess about, and why.
    Unusual(String),
}

/// The interpreter named by `head`, the first [`HEAD`] bytes of a file,
/// or `None` if it doesn't start with `#!`.
#[must_use]
pub fn parse(head: &[u8]) -> Option<Shebang> {
    let rest = head.strip_prefix(b"#!")?;
    // A line may end at the end of a short file, but not at the end of
    // what was read.
    let end = match rest.iter().position(|&b| b == b'\n') {
        Some(end) => end,
        None if head.len() < HEAD => rest.len(),
        None => {
            return Some(Shebang::Unusual(format!(
                "the #! line is longer than {HEAD} bytes"
            )));
        }
    };
    let Ok(line) = std::str::from_utf8(rest.get(..end).unwrap_or_default()) else {
        return Some(Shebang::Unusual("the #! line isn't UTF-8".to_owned()));
    };
    Some(interpreter(line))
}

fn interpreter(line: &str) -> Shebang {
    let unusual = |why: &str| Shebang::Unusual(why.to_owned());
    let mut words = line.split([' ', '\t']).filter(|w| !w.is_empty());
    let Some(program) = words.next() else {
        return unusual("the #! line names no interpreter");
    };
    if !program.starts_with('/') {
        return unusual("the interpreter isn't an absolute path");
    }
    let path = if ENV.contains(&program) {
        match words.next() {
            None => return unusual("env names no program"),
            Some(word) if word.starts_with('-') => {
                return unusual("env is given options");
            }
            Some(word) if word.contains('=') => {
                return unusual("env sets a variable");
            }
            Some(word) if word.contains('/') => {
                return unusual("env is given a path rather than a program name");
            }
            Some(word) => format!("/usr/bin/{word}"),
        }
    } else {
        program.to_owned()
    };
    let path = match MERGED.iter().find(|dir| path.starts_with(**dir)) {
        Some(_) => format!("/usr{path}"),
        None => path,
    };
    if !path.starts_with("/usr/") {
        return Shebang::Unusual(format!(
            "the interpreter {path} is outside /usr, where packages install"
        ));
    }
    match path.parse::<FilePath>() {
        Ok(file) => Shebang::Interpreter(file),
        Err(e) => Shebang::Unusual(format!(
            "the interpreter {path:?} can't be a file: atom: {e}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(head: &str) -> String {
        match parse(head.as_bytes()) {
            Some(Shebang::Interpreter(f)) => f.to_string(),
            other => panic!("{head:?}: {other:?}"),
        }
    }

    fn unusual(head: &[u8]) -> String {
        match parse(head) {
            Some(Shebang::Unusual(why)) => why,
            other => panic!("{head:?}: {other:?}"),
        }
    }

    #[test]
    fn interpreters_are_found_directly_or_through_env() {
        assert_eq!(found("#!/usr/bin/python3\n"), "/usr/bin/python3");
        assert_eq!(
            found("#!/usr/bin/env python3\nprint()\n"),
            "/usr/bin/python3"
        );
        assert_eq!(found("#!/bin/env perl\n"), "/usr/bin/perl");
        assert_eq!(found("#! /usr/bin/perl -w\n"), "/usr/bin/perl");
        assert_eq!(found("#!\t/usr/bin/awk\t-f\n"), "/usr/bin/awk");
        assert_eq!(found("#!/bin/sh\n"), "/usr/bin/sh");
        assert_eq!(found("#!/sbin/openrc-run\n"), "/usr/sbin/openrc-run");
        assert_eq!(found("#!/lib/x/run\n"), "/usr/lib/x/run");
        assert_eq!(
            found("#!/lib64/ld-linux-x86-64.so.2\n"),
            "/usr/lib64/ld-linux-x86-64.so.2"
        );
        assert_eq!(found("#!/usr/bin/env  bash  -e\n"), "/usr/bin/bash");
        assert_eq!(found("#!/usr/bin/python3"), "/usr/bin/python3");
    }

    #[test]
    fn files_without_a_shebang_have_none() {
        assert_eq!(parse(b""), None);
        assert_eq!(parse(b"#"), None);
        assert_eq!(parse(b"echo hi\n"), None);
        assert_eq!(parse(b"\x7fELF"), None);
    }

    #[test]
    fn unusual_lines_are_reported_not_guessed() {
        let long = format!("#!/usr/bin/{}", "x".repeat(HEAD - 11));
        assert_eq!(long.len(), HEAD);
        assert_eq!(
            unusual(long.as_bytes()),
            "the #! line is longer than 256 bytes"
        );
        assert_eq!(found(&long[..HEAD - 1]), long[2..HEAD - 1].to_owned());
        assert_eq!(unusual(b"#!/usr/bin/\xff\n"), "the #! line isn't UTF-8");
        assert_eq!(unusual(b"#!\n"), "the #! line names no interpreter");
        assert_eq!(unusual(b"#!  \t\n"), "the #! line names no interpreter");
        assert_eq!(
            unusual(b"#!python3\n"),
            "the interpreter isn't an absolute path"
        );
        assert_eq!(unusual(b"#!/usr/bin/env\n"), "env names no program");
        assert_eq!(
            unusual(b"#!/usr/bin/env -S python3 -u\n"),
            "env is given options"
        );
        assert_eq!(
            unusual(b"#!/usr/bin/env A=1 python3\n"),
            "env sets a variable"
        );
        assert_eq!(
            unusual(b"#!/usr/bin/env /opt/x/python\n"),
            "env is given a path rather than a program name"
        );
        assert_eq!(
            unusual(b"#!/opt/python/bin/python3\n"),
            "the interpreter /opt/python/bin/python3 is outside /usr, where packages install"
        );
        assert_eq!(
            unusual(b"#!/binx/sh\n"),
            "the interpreter /binx/sh is outside /usr, where packages install"
        );
        assert!(
            unusual(b"#!/usr/bin/python3\r\n")
                .starts_with("the interpreter \"/usr/bin/python3\\r\" can't be a file: atom: ")
        );
    }
}
