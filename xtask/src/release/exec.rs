// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Running other programs (git, gh, cargo, ssh-keygen, the build script)
//! behind a trait, so the release flows can be tested with a fake.

use std::ffi::OsString;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::Error;

/// One command to run.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Cmd {
    /// The program, looked up on `PATH`.
    pub program: String,
    /// Its arguments.
    pub args: Vec<OsString>,
    /// The working directory, if not the current one.
    pub dir: Option<PathBuf>,
    /// Extra environment variables.
    pub env: Vec<(String, OsString)>,
    /// A file to read standard input from.
    pub stdin: Option<PathBuf>,
    /// Inherit the terminal (for progress output and passphrase prompts)
    /// instead of capturing the output.
    pub interactive: bool,
}

impl Cmd {
    /// A command with no arguments.
    #[must_use]
    pub fn new(program: &str) -> Self {
        Self {
            program: program.to_owned(),
            ..Self::default()
        }
    }

    /// A git command that ignores the user's global and system git
    /// configuration, so that nothing outside the repository (an
    /// `insteadOf` rewrite, a hook path, an include) can change what the
    /// release checks see, and that never prompts for credentials.
    #[must_use]
    pub fn git(dir: &Path) -> Self {
        Self::new("git")
            .dir(dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
    }

    /// Adds one argument.
    #[must_use]
    pub fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Adds several arguments.
    #[must_use]
    pub fn args<I, A>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = A>,
        A: Into<OsString>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Sets the working directory.
    #[must_use]
    pub fn dir(mut self, dir: &Path) -> Self {
        self.dir = Some(dir.to_path_buf());
        self
    }

    /// Sets an environment variable.
    #[must_use]
    pub fn env(mut self, key: &str, value: impl Into<OsString>) -> Self {
        self.env.push((key.to_owned(), value.into()));
        self
    }

    /// Reads standard input from a file.
    #[must_use]
    pub fn stdin(mut self, path: &Path) -> Self {
        self.stdin = Some(path.to_path_buf());
        self
    }

    /// Lets the command use the terminal.
    #[must_use]
    pub fn interactive(mut self) -> Self {
        self.interactive = true;
        self
    }

    /// The arguments as strings, for matching in tests and for messages.
    #[must_use]
    pub fn arg_strings(&self) -> Vec<String> {
        self.args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    /// Where standard input comes from: the given file, else the terminal
    /// for an interactive command, else nothing, so a captured command can
    /// never wait for input.
    #[must_use]
    pub fn stdin_source(&self) -> StdinSource<'_> {
        match (&self.stdin, self.interactive) {
            (Some(path), _) => StdinSource::File(path),
            (None, true) => StdinSource::Terminal,
            (None, false) => StdinSource::Empty,
        }
    }

    /// The command line, for messages.
    #[must_use]
    pub fn display(&self) -> String {
        std::iter::once(self.program.clone())
            .chain(self.arg_strings())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Where a command's standard input comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StdinSource<'a> {
    /// A file.
    File(&'a Path),
    /// The terminal.
    Terminal,
    /// Nothing: reads see end of file.
    Empty,
}

/// What a command printed. Empty for interactive commands.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Captured {
    /// Standard output.
    pub stdout: Vec<u8>,
    /// Standard error.
    pub stderr: Vec<u8>,
}

impl Captured {
    /// Standard output as text, without surrounding whitespace.
    #[must_use]
    pub fn stdout_text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).trim().to_owned()
    }

    /// Standard error as text, without surrounding whitespace.
    #[must_use]
    pub fn stderr_text(&self) -> String {
        String::from_utf8_lossy(&self.stderr).trim().to_owned()
    }
}

/// Runs commands.
pub trait Exec {
    /// Runs `cmd` to completion.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Command`] if the program can't start or exits with
    /// anything but success.
    fn run(&self, cmd: &Cmd) -> Result<Captured, Error>;
}

/// Runs commands on this machine.
#[derive(Clone, Copy, Debug, Default)]
pub struct System;

impl Exec for System {
    fn run(&self, cmd: &Cmd) -> Result<Captured, Error> {
        let fail = |detail: String| Error::Command {
            command: cmd.display(),
            detail,
        };
        let mut command = Command::new(&cmd.program);
        command.args(&cmd.args);
        if let Some(dir) = &cmd.dir {
            command.current_dir(dir);
        }
        for (key, value) in &cmd.env {
            command.env(key, value);
        }
        match cmd.stdin_source() {
            StdinSource::File(path) => {
                let file = File::open(path).map_err(|e| Error::io(path, &e))?;
                command.stdin(file);
            }
            StdinSource::Empty => {
                command.stdin(Stdio::null());
            }
            StdinSource::Terminal => {}
        }
        if cmd.interactive {
            let status = command.status().map_err(|e| fail(e.to_string()))?;
            if status.success() {
                Ok(Captured::default())
            } else {
                Err(fail(status.to_string()))
            }
        } else {
            let out = command.output().map_err(|e| fail(e.to_string()))?;
            let captured = Captured {
                stdout: out.stdout,
                stderr: out.stderr,
            };
            if out.status.success() {
                Ok(captured)
            } else {
                Err(fail(format!("{}: {}", out.status, captured.stderr_text())))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_builder_records_everything() {
        let cmd = Cmd::new("prog")
            .arg("a")
            .args(["b", "c"])
            .dir(Path::new("/w"))
            .env("K", "V")
            .stdin(Path::new("/in"))
            .interactive();
        assert_eq!(cmd.program, "prog");
        assert_eq!(cmd.arg_strings(), ["a", "b", "c"]);
        assert_eq!(cmd.dir.as_deref(), Some(Path::new("/w")));
        assert_eq!(cmd.env, [("K".to_owned(), OsString::from("V"))]);
        assert_eq!(cmd.stdin.as_deref(), Some(Path::new("/in")));
        assert!(cmd.interactive);
        assert_eq!(cmd.display(), "prog a b c");
    }

    #[test]
    fn stdin_is_a_file_the_terminal_or_nothing() {
        let file = Path::new("/in");
        assert_eq!(
            Cmd::new("a").stdin(file).stdin_source(),
            StdinSource::File(file)
        );
        assert_eq!(
            Cmd::new("a").stdin(file).interactive().stdin_source(),
            StdinSource::File(file)
        );
        assert_eq!(
            Cmd::new("a").interactive().stdin_source(),
            StdinSource::Terminal
        );
        assert_eq!(Cmd::new("a").stdin_source(), StdinSource::Empty);
    }

    #[test]
    fn git_commands_ignore_the_users_configuration() {
        let cmd = Cmd::git(Path::new("/repo"));
        assert_eq!(cmd.program, "git");
        assert_eq!(cmd.dir.as_deref(), Some(Path::new("/repo")));
        let env: Vec<(&str, &str)> = cmd
            .env
            .iter()
            .map(|(k, v)| (k.as_str(), v.to_str().unwrap()))
            .collect();
        assert_eq!(
            env,
            [
                ("GIT_CONFIG_NOSYSTEM", "1"),
                ("GIT_CONFIG_GLOBAL", "/dev/null"),
                ("GIT_TERMINAL_PROMPT", "0"),
            ]
        );
    }

    #[test]
    fn captured_text_is_trimmed() {
        let c = Captured {
            stdout: b"  out\n".to_vec(),
            stderr: b"\terr \n".to_vec(),
        };
        assert_eq!(c.stdout_text(), "out");
        assert_eq!(c.stderr_text(), "err");
    }

    #[test]
    fn system_captures_output_and_reads_stdin_from_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("in");
        std::fs::write(&input, "hello").unwrap();
        let out = System
            .run(
                &Cmd::new("sh")
                    .args(["-c", "cat; echo \" $K\" >&2; pwd"])
                    .env("K", "v")
                    .dir(dir.path())
                    .stdin(&input),
            )
            .unwrap();
        let canonical = dir.path().canonicalize().unwrap();
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            format!("hello{}\n", canonical.display())
        );
        assert_eq!(out.stderr_text(), "v");
    }

    #[test]
    fn system_gives_captured_commands_an_empty_stdin() {
        let out = System.run(&Cmd::new("sh").args(["-c", "cat"])).unwrap();
        assert!(out.stdout.is_empty());
    }

    #[test]
    fn system_reports_failures_with_stderr() {
        let e = System
            .run(&Cmd::new("sh").args(["-c", "echo nope >&2; exit 3"]))
            .unwrap_err();
        let shown = e.to_string();
        assert!(shown.contains("sh -c echo nope >&2; exit 3"), "{shown}");
        assert!(shown.contains("exit status: 3: nope"), "{shown}");
    }

    #[test]
    fn system_runs_interactive_commands() {
        assert_eq!(
            System.run(&Cmd::new("true").interactive()).unwrap(),
            Captured::default()
        );
        let e = System.run(&Cmd::new("false").interactive()).unwrap_err();
        assert!(e.to_string().contains("exit status: 1"), "{e}");
    }

    #[test]
    fn system_reports_programs_that_cannot_start_and_missing_stdin() {
        let e = System.run(&Cmd::new("/nonexistent/program")).unwrap_err();
        assert!(e.to_string().contains("/nonexistent/program"), "{e}");
        let e = System
            .run(&Cmd::new("/nonexistent/program").interactive())
            .unwrap_err();
        assert!(matches!(e, Error::Command { .. }), "{e}");
        let e = System
            .run(&Cmd::new("cat").stdin(Path::new("/nonexistent/input")))
            .unwrap_err();
        assert!(matches!(e, Error::Io { .. }), "{e}");
    }
}
