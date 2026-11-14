// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Release builds (ORD-004).
//!
//! - [`dist`] builds the release binaries and packs them into deterministic
//!   archives with a `SHA256SUMS` file. It runs inside the pinned build
//!   container (`release/Dockerfile`, driven by `scripts/release/build.sh`).
//! - [`pre_release`] checks that `main` is ready to tag, then prints the
//!   commands that tag and push it.
//! - [`sign`] verifies a draft release that CI built, by rebuilding the tag
//!   and comparing every file, then signs, uploads and publishes it.

use std::fmt;
use std::path::Path;

pub mod checks;
pub mod dist;
pub mod exec;
pub mod pre_release;
pub mod sign;
pub mod signers;
pub mod version;

/// The SSH signature namespace for release files. A signature made for git
/// (namespace `git`) never verifies as a release signature, and the other
/// way round.
pub const FILE_NAMESPACE: &str = "ordin-release";

/// The principal that signs release files in `release/allowed_signers`.
pub const FILE_PRINCIPAL: &str = "ordin-release";

/// The SSH signature namespace git uses for tags and commits.
pub const GIT_NAMESPACE: &str = "git";

/// Where the repository keeps its public signing keys.
pub const ALLOWED_SIGNERS: &str = "release/allowed_signers";

/// The workflow that builds draft releases, relative to the repository.
pub const RELEASE_WORKFLOW: &str = ".github/workflows/release.yml";

/// The build script, relative to the repository.
pub const BUILD_SCRIPT: &str = "scripts/release/build.sh";

/// Why a release step failed.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// A file couldn't be read or written.
    Io {
        /// The file.
        path: String,
        /// What went wrong.
        error: String,
    },
    /// A command couldn't start or failed.
    Command {
        /// The command line.
        command: String,
        /// Its exit status and error output.
        detail: String,
    },
    /// Something couldn't be parsed.
    Parse {
        /// What was being parsed.
        what: String,
        /// What is wrong with it.
        error: String,
    },
    /// A release check failed. The message says what to fix.
    Check(String),
}

impl Error {
    /// An I/O error on `path`.
    #[must_use]
    pub fn io(path: &Path, error: &std::io::Error) -> Self {
        Self::Io {
            path: path.display().to_string(),
            error: error.to_string(),
        }
    }

    /// A parse error in `what`.
    #[must_use]
    pub fn parse(what: &str, error: impl fmt::Display) -> Self {
        Self::Parse {
            what: what.to_owned(),
            error: error.to_string(),
        }
    }

    /// A failed check.
    #[must_use]
    pub fn check(message: impl Into<String>) -> Self {
        Self::Check(message.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, error } => write!(f, "{path}: {error}"),
            Self::Command { command, detail } => write!(f, "`{command}` failed: {detail}"),
            Self::Parse { what, error } => write!(f, "can't parse {what}: {error}"),
            Self::Check(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for Error {}

/// Writes a progress line. A failure to write progress never stops a
/// release, so it is ignored.
pub(crate) fn say(log: &mut dyn std::io::Write, line: &str) {
    let _ = writeln!(log, "{line}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_say_what_failed() {
        let io = Error::io(Path::new("/a/b"), &std::io::Error::other("denied"));
        assert_eq!(io.to_string(), "/a/b: denied");
        let cmd = Error::Command {
            command: "git status".into(),
            detail: "exit status: 1".into(),
        };
        assert_eq!(cmd.to_string(), "`git status` failed: exit status: 1");
        assert_eq!(
            Error::parse("Cargo.toml", "bad").to_string(),
            "can't parse Cargo.toml: bad"
        );
        assert_eq!(Error::check("fix it").to_string(), "fix it");
    }

    #[test]
    fn progress_lines_end_with_a_newline() {
        let mut log = Vec::new();
        say(&mut log, "one");
        say(&mut log, "two");
        assert_eq!(log, b"one\ntwo\n");
    }

    #[test]
    fn the_two_namespaces_differ() {
        assert_ne!(FILE_NAMESPACE, GIT_NAMESPACE);
    }
}
