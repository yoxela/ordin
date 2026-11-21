// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! What identifies a blob, and hashing it on the way in and out.

use std::io::{self, Read, Write};

use ordin_core::{Algorithm, Blake3Hasher, Digest};
use sha2::{Digest as _, Sha256};

/// What a descriptor records about a blob: its SHA-256 digest, which OCI
/// requires, its BLAKE3 digest, which Ordin verifies, and its size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobId {
    /// The SHA-256 digest: the blob's name in the layout.
    pub sha256: Digest,
    /// The BLAKE3 digest, in the `com.ordinpm.blake3` annotation.
    pub blake3: Digest,
    /// The size in bytes.
    pub size: u64,
}

impl BlobId {
    /// The identity of `bytes`.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        let mut h = Hashes::default();
        h.update(bytes);
        h.finish()
    }

    /// The blob's path in the layout: `blobs/sha256/` and 64 hex digits.
    #[must_use]
    pub fn path(&self) -> String {
        format!("blobs/sha256/{}", hex(self.sha256.bytes()))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Both digests and the size of bytes given piece by piece.
#[derive(Default)]
pub(crate) struct Hashes {
    sha256: Sha256,
    blake3: Blake3Hasher,
    size: u64,
}

impl Hashes {
    pub(crate) fn update(&mut self, bytes: &[u8]) {
        self.sha256.update(bytes);
        self.blake3.update(bytes);
        self.size += u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    }

    pub(crate) fn size(&self) -> u64 {
        self.size
    }

    pub(crate) fn finish(self) -> BlobId {
        BlobId {
            sha256: Digest::new(Algorithm::Sha256, self.sha256.finalize().into()),
            blake3: self.blake3.finish(),
            size: self.size,
        }
    }
}

/// A writer that hashes what goes through it.
pub(crate) struct HashingWriter<W> {
    inner: W,
    hashes: Hashes,
}

impl<W: Write> HashingWriter<W> {
    pub(crate) fn new(inner: W) -> Self {
        Self {
            inner,
            hashes: Hashes::default(),
        }
    }

    pub(crate) fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.inner.write_all(bytes)?;
        self.hashes.update(bytes);
        Ok(())
    }

    /// How many bytes have been written.
    pub(crate) fn size(&self) -> u64 {
        self.hashes.size()
    }

    pub(crate) fn finish(self) -> (W, BlobId) {
        (self.inner, self.hashes.finish())
    }
}

/// A reader that hashes what comes through it.
pub(crate) struct HashingReader<R> {
    inner: R,
    hashes: Hashes,
}

impl<R: Read> HashingReader<R> {
    pub(crate) fn new(inner: R) -> Self {
        Self {
            inner,
            hashes: Hashes::default(),
        }
    }

    pub(crate) fn finish(self) -> BlobId {
        self.hashes.finish()
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(buf)?;
        self.hashes.update(buf.get(..count).unwrap_or_default());
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // `sha256sum` and `b3sum` of "abc".
    const ABC_SHA256: &str =
        "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const ABC_BLAKE3: &str =
        "blake3:6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85";

    #[test]
    fn a_blob_is_named_by_its_sha256() {
        let id = BlobId::of(b"abc");
        assert_eq!(id.sha256.to_string(), ABC_SHA256);
        assert_eq!(id.blake3.to_string(), ABC_BLAKE3);
        assert_eq!(id.size, 3);
        assert_eq!(
            id.path(),
            "blobs/sha256/ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn writing_and_reading_hash_the_same_bytes() {
        let mut w = HashingWriter::new(Vec::new());
        w.write_all(b"a").unwrap();
        w.write_all(b"bc").unwrap();
        assert_eq!(w.size(), 3);
        let (out, id) = w.finish();
        assert_eq!(out, b"abc");
        assert_eq!(id, BlobId::of(b"abc"));

        let mut r = HashingReader::new(&b"abc"[..]);
        let mut first = [0; 2];
        assert_eq!(r.read(&mut first).unwrap(), 2);
        let mut rest = Vec::new();
        r.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, b"c");
        assert_eq!(r.finish(), BlobId::of(b"abc"));
    }
}
