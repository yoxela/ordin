// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! A ustar writer that gives the same bytes for the same entries: every
//! entry is a regular file with mode 0644, owner and group 0 with empty
//! names and modification time 0, and nothing follows the two closing
//! zero blocks.

use std::io::{self, ErrorKind, Read, Write};

/// A tar block.
pub(crate) const BLOCK: u64 = 512;

/// The largest entry ustar's eleven octal size digits can record:
/// 8 GiB − 1 bytes.
pub const MAX_ENTRY_SIZE: u64 = 0o777_7777_7777;

/// The longest name ustar's name field holds without its prefix field.
const NAME_MAX: usize = 100;

const ZEROS: [u8; 1024] = [0; 1024];

/// Copies `bytes` into `header` from `offset` on.
fn put(header: &mut [u8; 512], offset: usize, bytes: &[u8]) {
    for (to, from) in header.iter_mut().skip(offset).zip(bytes) {
        *to = *from;
    }
}

/// `value` in octal, zero-padded to fill a field of `width` bytes with
/// its closing NUL.
fn octal(value: u64, width: usize) -> Vec<u8> {
    let mut field = format!("{value:0digits$o}", digits = width.saturating_sub(1)).into_bytes();
    field.push(0);
    field
}

/// The header of a regular file entry.
///
/// # Errors
///
/// A name that isn't 1 to 100 printable ASCII bytes gives
/// [`ErrorKind::InvalidInput`], and a size over [`MAX_ENTRY_SIZE`] gives
/// [`ErrorKind::FileTooLarge`].
pub(crate) fn header(name: &str, size: u64) -> io::Result<[u8; 512]> {
    if name.is_empty() || name.len() > NAME_MAX || !name.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!("the tar entry name {name:?} isn't 1 to 100 printable ASCII bytes"),
        ));
    }
    if size > MAX_ENTRY_SIZE {
        return Err(io::Error::new(
            ErrorKind::FileTooLarge,
            format!("{name} has {size} bytes, more than a ustar entry can hold"),
        ));
    }
    let mut h = [0; 512];
    put(&mut h, 0, name.as_bytes());
    put(&mut h, 100, &octal(0o644, 8));
    put(&mut h, 108, &octal(0, 8));
    put(&mut h, 116, &octal(0, 8));
    put(&mut h, 124, &octal(size, 12));
    put(&mut h, 136, &octal(0, 12));
    // The checksum is computed with its own field as spaces.
    put(&mut h, 148, b"        ");
    put(&mut h, 156, b"0");
    put(&mut h, 257, b"ustar\x0000");
    let sum: u64 = h.iter().map(|&b| u64::from(b)).sum();
    // Six digits, a NUL and the space that is already there.
    put(&mut h, 148, &octal(sum, 7));
    Ok(h)
}

/// The name and size a header records, if it is exactly the header
/// [`header`] writes for them. Any other header, however valid as tar, is
/// refused.
pub(crate) fn parse_header(block: &[u8; 512]) -> Option<(String, u64)> {
    let field = block.get(..NAME_MAX)?;
    let len = field.iter().position(|&b| b == 0).unwrap_or(NAME_MAX);
    let name = std::str::from_utf8(field.get(..len)?).ok()?;
    // Eleven octal digits, which can't overflow: at most MAX_ENTRY_SIZE.
    let mut size = 0;
    for &digit in block.get(124..135)? {
        if !(b'0'..=b'7').contains(&digit) {
            return None;
        }
        size = size * 8 + u64::from(digit - b'0');
    }
    let written = header(name, size).ok()?;
    (written == *block).then(|| (name.to_owned(), size))
}

/// The zero bytes that pad an entry of `size` bytes to whole blocks.
pub(crate) fn padding(size: u64) -> u64 {
    (BLOCK - size % BLOCK) % BLOCK
}

/// Writes a tar archive entry by entry.
pub(crate) struct TarWriter<W> {
    out: W,
    size: u64,
}

impl<W: Write> TarWriter<W> {
    pub(crate) fn new(out: W) -> Self {
        Self { out, size: 0 }
    }

    fn put(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.out.write_all(bytes)?;
        self.size += u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        Ok(())
    }

    /// Appends a file of exactly `size` bytes read from `data`.
    ///
    /// # Errors
    ///
    /// Any error from [`header`], `data` or the output. `data` ending
    /// before `size` bytes gives [`ErrorKind::UnexpectedEof`]; bytes after
    /// them aren't read.
    pub(crate) fn entry(&mut self, name: &str, size: u64, data: &mut impl Read) -> io::Result<()> {
        self.put(&header(name, size)?)?;
        let copied = io::copy(&mut data.take(size), &mut self.out)?;
        self.size += copied;
        if copied != size {
            return Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                format!("{name} ended after {copied} of its {size} bytes"),
            ));
        }
        let pad = usize::try_from(padding(size)).unwrap_or_default();
        self.put(ZEROS.get(..pad).unwrap_or_default())
    }

    /// Writes the two closing zero blocks and returns the output and the
    /// archive's size.
    ///
    /// # Errors
    ///
    /// Any error from the output.
    pub(crate) fn finish(mut self) -> io::Result<(W, u64)> {
        self.put(&ZEROS)?;
        Ok((self.out, self.size))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest as _, Sha256};

    fn sha256(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    #[test]
    fn headers_match_pythons_tarfile() {
        // From Python's tarfile: TarInfo with mode 0o644, mtime 0, uid and
        // gid 0, empty user and group names, tobuf(format=USTAR_FORMAT).
        let h = header("oci-layout", 30).unwrap();
        assert_eq!(
            sha256(&h),
            "e0d9ba4a2dd0de3049a257ce8707f36fb809d03705467d275dcfb523b456c238"
        );
        assert_eq!(&h[148..156], b"007754\0 ");
        let name = format!("blobs/sha256/{}", "ab".repeat(32));
        let h = header(&name, MAX_ENTRY_SIZE).unwrap();
        assert_eq!(
            sha256(&h),
            "1c3d4e257f326d3fd9b6271236d73b700a99eb348a27c09622c620056b935aaa"
        );
    }

    #[test]
    fn names_are_one_to_a_hundred_printable_bytes() {
        assert!(header(&"a".repeat(100), 0).is_ok());
        for bad in [
            String::new(),
            "a".repeat(101),
            "a b".into(),
            "a\u{e9}".into(),
        ] {
            let e = header(&bad, 0).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::InvalidInput, "{bad:?}");
        }
    }

    #[test]
    fn sizes_beyond_eleven_octal_digits_are_refused() {
        let e = header("a", MAX_ENTRY_SIZE + 1).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::FileTooLarge);
        assert_eq!(
            e.to_string(),
            "a has 8589934592 bytes, more than a ustar entry can hold"
        );
    }

    #[test]
    fn entries_are_padded_to_whole_blocks() {
        assert_eq!(padding(0), 0);
        assert_eq!(padding(1), 511);
        assert_eq!(padding(511), 1);
        assert_eq!(padding(512), 0);
        assert_eq!(padding(513), 511);
        let mut tar = TarWriter::new(Vec::new());
        tar.entry("a", 3, &mut &b"abcdef"[..]).unwrap();
        tar.entry("b", 512, &mut &[7; 512][..]).unwrap();
        tar.entry("c", 0, &mut &b""[..]).unwrap();
        let (out, size) = tar.finish().unwrap();
        assert_eq!(size, 512 + 512 + 512 + 512 + 512 + 1024);
        assert_eq!(out.len() as u64, size);
        assert_eq!(&out[512..515], b"abc");
        assert!(out[515..1024].iter().all(|&b| b == 0));
        assert_eq!(&out[2048..2049], b"c");
        assert!(out[2560..].iter().all(|&b| b == 0));
    }

    #[test]
    fn a_short_entry_is_refused() {
        let mut tar = TarWriter::new(Vec::new());
        let e = tar.entry("a", 4, &mut &b"abc"[..]).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::UnexpectedEof);
        assert_eq!(e.to_string(), "a ended after 3 of its 4 bytes");
    }

    #[test]
    fn only_the_headers_the_writer_writes_are_read() {
        let long = "b".repeat(100);
        for (name, size) in [
            ("oci-layout", 30),
            ("a", 0),
            (long.as_str(), MAX_ENTRY_SIZE),
            ("index.json", 0o1234_5670),
        ] {
            let h = header(name, size).unwrap();
            assert_eq!(parse_header(&h), Some((name.to_owned(), size)));
            // Any change to any byte, even one tar readers ignore, is
            // refused.
            for at in 0..512 {
                for bit in [0x01, 0x08, 0x80] {
                    let mut changed = h;
                    changed[at] ^= bit;
                    assert_eq!(parse_header(&changed), None, "{name}: byte {at} ^ {bit}");
                }
            }
        }
        // A size field that isn't octal digits.
        let mut h = header("a", 0).unwrap();
        h[134] = b'8';
        assert_eq!(parse_header(&h), None);
        h[134] = b'/';
        assert_eq!(parse_header(&h), None);
        // A name that isn't UTF-8.
        let mut h = header("a", 0).unwrap();
        h[0] = 0xff;
        assert_eq!(parse_header(&h), None);
        assert_eq!(parse_header(&[0; 512]), None);
    }

    #[test]
    fn the_tar_crate_reads_what_is_written() {
        let mut tar = TarWriter::new(Vec::new());
        tar.entry("oci-layout", 3, &mut &b"abc"[..]).unwrap();
        tar.entry("index.json", 2, &mut &b"{}"[..]).unwrap();
        let (out, _) = tar.finish().unwrap();
        let mut archive = ::tar::Archive::new(&out[..]);
        let names: Vec<String> = archive
            .entries()
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                let h = e.header();
                assert_eq!(h.mode().unwrap(), 0o644);
                assert_eq!(h.uid().unwrap(), 0);
                assert_eq!(h.gid().unwrap(), 0);
                assert_eq!(h.mtime().unwrap(), 0);
                assert_eq!(h.username().unwrap(), Some(""));
                assert_eq!(h.groupname().unwrap(), Some(""));
                assert!(h.entry_type().is_file());
                e.path().unwrap().to_string_lossy().into_owned()
            })
            .collect();
        assert_eq!(names, ["oci-layout", "index.json"]);
    }
}
