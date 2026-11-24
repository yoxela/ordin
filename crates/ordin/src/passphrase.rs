// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Passphrases for secret key files: from a file, or asked for on the
//! terminal with echo off. Every passphrase is cleared from memory once
//! dropped.

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};
use rustix::termios::{self, LocalModes, OptionalActions};
use zeroize::Zeroizing;

use crate::files;

/// The longest passphrase read, in bytes.
pub const MAX_PASSPHRASE: u64 = 1024;

/// A passphrase.
pub type Passphrase = Zeroizing<Vec<u8>>;

/// Drops one line break at the end, and refuses an empty passphrase.
fn finish(mut text: Passphrase, from: &str) -> Result<Passphrase> {
    if text.ends_with(b"\n") {
        text.pop();
        if text.ends_with(b"\r") {
            text.pop();
        }
    }
    if text.is_empty() {
        bail!("{from}: a passphrase can't be empty");
    }
    Ok(text)
}

/// Reads a passphrase from a file: its content, without one line break at
/// the end. The file must be a regular file of at most
/// [`MAX_PASSPHRASE`] bytes.
pub fn from_file(path: &Path) -> Result<Passphrase> {
    let text = Zeroizing::new(files::read_small(
        path,
        MAX_PASSPHRASE,
        "a passphrase file",
    )?);
    finish(text, &path.display().to_string())
}

/// Asks for a passphrase on the terminal, and again to confirm if asked
/// to. Only when standard input is a terminal: a script or a test never
/// waits on a prompt nobody sees.
pub fn ask(prompt: &str, confirm: bool) -> Result<Passphrase> {
    if !termios::isatty(std::io::stdin()) {
        bail!("no terminal to ask for the passphrase on; give it with --passphrase-file");
    }
    ask_on(Path::new("/dev/tty"), prompt, confirm)
}

/// Asks on the terminal at `tty`.
fn ask_on(tty: &Path, prompt: &str, confirm: bool) -> Result<Passphrase> {
    let first = read_hidden(tty, prompt)?;
    if confirm && read_hidden(tty, "Again: ")? != first {
        bail!("the passphrases differ");
    }
    Ok(first)
}

/// Reads one line from the terminal at `tty` with echo off, putting the
/// terminal back as it was whatever happens.
fn read_hidden(tty: &Path, prompt: &str) -> Result<Passphrase> {
    let shown = || tty.display().to_string();
    let mut terminal = OpenOptions::new()
        .read(true)
        .write(true)
        .open(tty)
        .with_context(shown)?;
    let before = termios::tcgetattr(&terminal).with_context(shown)?;
    let mut quiet = before.clone();
    quiet.local_modes.remove(LocalModes::ECHO);
    // Drain, not flush: what was already typed is the passphrase.
    termios::tcsetattr(&terminal, OptionalActions::Drain, &quiet).with_context(shown)?;
    let read = (|| -> Result<Passphrase> {
        terminal.write_all(prompt.as_bytes())?;
        terminal.flush()?;
        let mut line = Zeroizing::new(Vec::new());
        BufReader::new((&terminal).take(MAX_PASSPHRASE + 1)).read_until(b'\n', &mut line)?;
        Ok(line)
    })();
    let restored = termios::tcsetattr(&terminal, OptionalActions::Now, &before);
    let _ = terminal.write_all(b"\n");
    restored.with_context(shown)?;
    let line = read.with_context(shown)?;
    if line.len() as u64 > MAX_PASSPHRASE {
        bail!("a passphrase is at most {MAX_PASSPHRASE} bytes");
    }
    finish(line, "the terminal")
}

#[cfg(test)]
mod tests {
    use std::os::fd::OwnedFd;
    use std::path::PathBuf;

    use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};

    use super::*;

    /// A terminal of our own: its controlling side and its path.
    fn terminal() -> (std::fs::File, PathBuf) {
        let control: OwnedFd = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
        grantpt(&control).unwrap();
        unlockpt(&control).unwrap();
        let path = ptsname(&control, Vec::new()).unwrap();
        (
            std::fs::File::from(control),
            PathBuf::from(path.to_str().unwrap()),
        )
    }

    /// Asks on a terminal of our own, typing `typed` into it and then one
    /// more line, which nothing should read: reading too many lines then
    /// fails at once instead of waiting.
    fn typed(typed: &[u8], confirm: bool) -> Result<Passphrase> {
        let (mut control, path) = terminal();
        // Open it once first, so what is typed waits for the reader.
        let keep = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        control.write_all(typed).unwrap();
        control.write_all(b"never read\n").unwrap();
        let asked = ask_on(&path, "Passphrase: ", confirm);
        drop(keep);
        asked
    }

    #[test]
    fn a_passphrase_is_asked_for_with_echo_off_and_confirmed() {
        // Without confirming, only the first line is read.
        assert_eq!(
            typed(b"first\nsecond\n", false).unwrap().as_slice(),
            b"first"
        );
        assert_eq!(
            typed(b"correct horse\n", false).unwrap().as_slice(),
            b"correct horse"
        );
        assert_eq!(
            typed(b"correct horse\ncorrect horse\n", true)
                .unwrap()
                .as_slice(),
            b"correct horse"
        );
        assert_eq!(
            typed(b"one\ntwo\n", true).unwrap_err().to_string(),
            "the passphrases differ"
        );
        assert_eq!(
            typed(b"\n", false).unwrap_err().to_string(),
            "the terminal: a passphrase can't be empty"
        );
    }

    #[test]
    fn the_terminal_is_put_back_as_it_was() {
        let (mut control, path) = terminal();
        let keep = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let before = termios::tcgetattr(&keep).unwrap();
        assert!(before.local_modes.contains(LocalModes::ECHO));
        control.write_all(b"x\nnever read\n").unwrap();
        ask_on(&path, "", false).unwrap();
        let after = termios::tcgetattr(&keep).unwrap();
        assert!(after.local_modes.contains(LocalModes::ECHO));
        assert_eq!(after.local_modes, before.local_modes);
    }

    #[test]
    fn a_long_passphrase_is_refused() {
        let mut long = vec![b'a'; usize::try_from(MAX_PASSPHRASE).unwrap() + 1];
        long.push(b'\n');
        assert_eq!(
            typed(&long, false).unwrap_err().to_string(),
            "a passphrase is at most 1024 bytes"
        );
        let mut longest = vec![b'a'; usize::try_from(MAX_PASSPHRASE).unwrap() - 1];
        longest.push(b'\n');
        assert_eq!(typed(&longest, false).unwrap().len(), 1023);
    }

    #[test]
    fn a_missing_terminal_is_an_error() {
        let e = ask_on(Path::new("/nonexistent/tty"), "", false).unwrap_err();
        assert!(e.to_string().starts_with("/nonexistent/tty"), "{e}");
        // A file that isn't a terminal can't have its echo turned off.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("plain");
        std::fs::write(&file, b"x\n").unwrap();
        assert!(ask_on(&file, "", false).is_err());
    }

    #[test]
    fn line_breaks_are_dropped_once() {
        let f = |t: &[u8]| finish(Zeroizing::new(t.to_vec()), "f").map(|p| p.to_vec());
        assert_eq!(f(b"p\n").unwrap(), b"p");
        assert_eq!(f(b"p\r\n").unwrap(), b"p");
        assert_eq!(f(b"p\n\n").unwrap(), b"p\n");
        assert_eq!(f(b"p\r").unwrap(), b"p\r");
        assert_eq!(f(b" p ").unwrap(), b" p ");
        assert_eq!(
            f(b"\n").unwrap_err().to_string(),
            "f: a passphrase can't be empty"
        );
        assert_eq!(
            f(b"").unwrap_err().to_string(),
            "f: a passphrase can't be empty"
        );
    }
}
