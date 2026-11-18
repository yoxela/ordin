// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Paths in a tree, and symlink targets.

use core::fmt;
use core::str::FromStr;

/// The longest path, in bytes (Linux's `PATH_MAX`, which counts a
/// terminating NUL, so 4,095 usable bytes).
pub const PATH_MAX: usize = 4095;

/// The longest name in a path, in bytes (Linux's `NAME_MAX`).
pub const NAME_MAX: usize = 255;

/// The control characters refused in paths and targets: C0, DEL and C1.
fn is_control(c: char) -> bool {
    matches!(c, '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}')
}

/// Why a path or target was refused.
fn check_text(what: &str, text: &str) -> Result<(), String> {
    if text.len() > PATH_MAX {
        return Err(format!(
            "{what} is at most {PATH_MAX} bytes; this one is {}",
            text.len()
        ));
    }
    match text.char_indices().find(|&(_, c)| is_control(c)) {
        Some((at, c)) => Err(format!(
            "{what} can't contain the control character {c:?} (at byte {at})"
        )),
        None => Ok(()),
    }
}

/// A path in a tree: absolute and normalized, UTF-8 without control
/// characters, at most 4,095 bytes, with names of at most 255 bytes.
/// `/` itself is not a path in a tree.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TreePath(String);

impl TreePath {
    /// The path, exactly as given.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The parent directory: `/` for a top-level path.
    #[must_use]
    pub fn parent(&self) -> &str {
        match self.0.rfind('/') {
            Some(0) | None => "/",
            Some(at) => &self.0[..at],
        }
    }
}

impl FromStr for TreePath {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        check_text("a path", text)?;
        let Some(rest) = text.strip_prefix('/') else {
            return Err(format!("a path must be absolute: {text:?}"));
        };
        for name in rest.split('/') {
            let problem = match name {
                "" => Some("an empty name (a doubled or trailing '/', or '/' alone)"),
                "." | ".." => Some("a '.' or '..' name"),
                _ if name.len() > NAME_MAX => Some("a name longer than 255 bytes"),
                _ => None,
            };
            if let Some(problem) = problem {
                return Err(format!("a path can't have {problem}: {text:?}"));
            }
        }
        Ok(Self(text.to_owned()))
    }
}

impl fmt::Display for TreePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What a symlink points at, exactly as written: relative or absolute,
/// 1 to 4,095 bytes of UTF-8 without control characters.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SymlinkTarget(String);

impl SymlinkTarget {
    /// The target, exactly as given.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for SymlinkTarget {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        if text.is_empty() {
            return Err("a symlink target can't be empty".to_owned());
        }
        check_text("a symlink target", text)?;
        Ok(Self(text.to_owned()))
    }
}

impl fmt::Display for SymlinkTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(text: &str) -> Result<TreePath, String> {
        text.parse()
    }

    #[test]
    fn paths_are_absolute_and_normalized() {
        for ok in [
            "/usr",
            "/usr/bin/rg",
            "/usr/lib/x86_64-linux-gnu/libns-9.20.23-1~deb13u1-Debian.so",
            "/usr/share/doc/Third Party Licenses.txt",
            "/usr/share/go/test/\u{de}main.go",
            "/.hidden",
            "/a/...",
            "/a/.b",
        ] {
            assert_eq!(path(ok).unwrap().as_str(), ok);
            assert_eq!(path(ok).unwrap().to_string(), ok);
        }
        for (bad, why) in [
            ("", "absolute"),
            ("usr/bin", "absolute"),
            ("/", "empty name"),
            ("/usr/", "empty name"),
            ("/usr//bin", "empty name"),
            ("/usr/./bin", "'.' or '..'"),
            ("/usr/..", "'.' or '..'"),
            ("/./usr", "'.' or '..'"),
            ("/usr/a\nb", "control character '\\n' (at byte 6)"),
            ("/usr/a\u{7f}", "control character '\\u{7f}'"),
            ("/usr/a\u{9f}", "control character '\\u{9f}'"),
            ("/usr/\u{0}", "control character '\\0'"),
            ("/usr/a\u{1f}", "control character '\\u{1f}'"),
        ] {
            let e = path(bad).unwrap_err();
            assert!(e.contains(why), "{bad:?}: {e}");
        }
        // Just outside the control ranges.
        assert!(path("/a ").is_ok());
        assert!(path("/a\u{a0}").is_ok());
        assert!(path("/a~").is_ok());
    }

    #[test]
    fn paths_and_names_have_length_limits() {
        let name = "n".repeat(NAME_MAX);
        assert!(path(&format!("/{name}")).is_ok());
        let e = path(&format!("/{name}n")).unwrap_err();
        assert!(e.contains("longer than 255"), "{e}");
        let long = format!("/{}n", ["n"; 2047].join("/"));
        assert_eq!(long.len(), PATH_MAX);
        assert!(path(&long).is_ok());
        let e = path(&format!("{long}n")).unwrap_err();
        assert!(e.contains("at most 4095 bytes; this one is 4096"), "{e}");
    }

    #[test]
    fn a_parent_is_the_path_without_its_last_name() {
        assert_eq!(path("/usr").unwrap().parent(), "/");
        assert_eq!(path("/usr/bin").unwrap().parent(), "/usr");
        assert_eq!(path("/usr/bin/rg").unwrap().parent(), "/usr/bin");
    }

    #[test]
    fn symlink_targets_are_kept_as_written() {
        for ok in ["rg", "../lib/x.so", "/usr/bin/rg", "a//b/", ".", " "] {
            let t: SymlinkTarget = ok.parse().unwrap();
            assert_eq!(t.as_str(), ok);
            assert_eq!(t.to_string(), ok);
        }
        assert!(
            "".parse::<SymlinkTarget>()
                .unwrap_err()
                .contains("can't be empty")
        );
        assert!(
            "a\tb"
                .parse::<SymlinkTarget>()
                .unwrap_err()
                .contains("control character")
        );
        assert!("x".repeat(PATH_MAX).parse::<SymlinkTarget>().is_ok());
        assert!(
            "x".repeat(PATH_MAX + 1)
                .parse::<SymlinkTarget>()
                .unwrap_err()
                .contains("a symlink target is at most 4095 bytes")
        );
    }
}
