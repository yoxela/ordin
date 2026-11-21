// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Cutting one file into chunks, in the same pass that computes its
//! digests.

use std::io::{self, ErrorKind, Read};

use ordin_core::Digest;

use super::cut::cut;
use super::index::{IndexFile, MAX_CHUNKS};
use super::params::ChunkParams;
use crate::digests::{FileDigests, FileHasher};

/// One chunk: the BLAKE3 digest of its bytes, and how many there are.
/// Compression never enters into either.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ChunkRef {
    /// The BLAKE3 digest of the chunk's uncompressed bytes.
    pub digest: Digest,
    /// The number of uncompressed bytes.
    pub length: u64,
}

/// A file cut into chunks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkedFile {
    digests: FileDigests,
    chunks: Vec<ChunkRef>,
    listed: bool,
}

impl ChunkedFile {
    /// The file's size and digests, as its tree entry records them.
    #[must_use]
    pub fn digests(&self) -> &FileDigests {
        &self.digests
    }

    /// The chunks, in order. A file under the whole-file threshold is one
    /// chunk, even when it's empty, and that chunk's digest is the file's
    /// content digest.
    #[must_use]
    pub fn chunks(&self) -> &[ChunkRef] {
        &self.chunks
    }

    /// The file's entry in a chunk index, if it has one: only files at or
    /// above the whole-file threshold are listed.
    #[must_use]
    pub fn index_entry(&self) -> Option<IndexFile> {
        self.listed
            .then(|| IndexFile::new(self.digests.content, self.chunks.clone()))
    }
}

/// Fills `buffer` from `filled` on, until it's full or the reader ends.
/// Returns how much is filled and whether the reader ended.
fn fill(reader: &mut impl Read, buffer: &mut [u8], mut filled: usize) -> io::Result<(usize, bool)> {
    while let Some(space) = buffer.get_mut(filled..).filter(|s| !s.is_empty()) {
        let room = space.len();
        match reader.read(space) {
            Ok(0) => return Ok((filled, true)),
            Ok(count) if count > room => {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "a reader claimed more bytes than its buffer holds",
                ));
            }
            Ok(count) => filled += count,
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok((filled, false))
}

/// The chunks so far and the file's digests.
struct Chunks<F> {
    hasher: FileHasher,
    chunks: Vec<ChunkRef>,
    sink: F,
}

impl<F: FnMut(&ChunkRef, &[u8]) -> io::Result<()>> Chunks<F> {
    fn add(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.chunks.len() >= MAX_CHUNKS {
            return Err(io::Error::new(
                ErrorKind::FileTooLarge,
                "the file is cut into more chunks than a chunk index can list",
            ));
        }
        let chunk = ChunkRef {
            digest: Digest::blake3(bytes),
            length: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        };
        self.hasher.update(bytes);
        (self.sink)(&chunk, bytes)?;
        self.chunks.push(chunk);
        Ok(())
    }
}

/// Reads `reader` to its end, once, and cuts what it gave into chunks
/// with `params`. Each chunk's bytes go to `sink` as soon as the chunk is
/// known, so they can be compressed or stored without reading the file
/// again. Memory stays at one buffer of [`ChunkParams::maximum`] bytes.
///
/// A file under [`ChunkParams::whole_below`] bytes is one chunk. A longer
/// one is cut with FastCDC 2020, so the same bytes always give the same
/// chunks.
///
/// # Errors
///
/// Any error from `reader` or `sink`, except that an interrupted read is
/// retried. A reader claiming to have read more than it was asked for
/// gives [`ErrorKind::InvalidData`]. A file cut into more chunks than a
/// chunk index can list ([`MAX_CHUNKS`]) gives
/// [`ErrorKind::FileTooLarge`]. Once the reader says it has ended, it
/// isn't read again.
pub fn chunk_file(
    mut reader: impl Read,
    params: &ChunkParams,
    sink: impl FnMut(&ChunkRef, &[u8]) -> io::Result<()>,
) -> io::Result<ChunkedFile> {
    let capacity = usize::try_from(params.maximum()).unwrap_or(usize::MAX);
    let threshold = usize::try_from(params.whole_below()).unwrap_or(usize::MAX);
    let mut buffer = vec![0; capacity];
    let mut out = Chunks {
        hasher: FileHasher::default(),
        chunks: Vec::new(),
        sink,
    };
    let (mut filled, mut ended) = fill(&mut reader, &mut buffer, 0)?;
    let listed = filled >= threshold;
    if listed {
        while let Some(data) = buffer.get(..filled).filter(|d| !d.is_empty()) {
            let length = cut(data, params);
            out.add(data.get(..length).unwrap_or_default())?;
            buffer.copy_within(length..filled, 0);
            filled -= length;
            if !ended {
                (filled, ended) = fill(&mut reader, &mut buffer, filled)?;
            }
        }
    } else {
        // The buffer holds at least the threshold, so a file under it was
        // read to its end.
        out.add(buffer.get(..filled).unwrap_or_default())?;
    }
    Ok(ChunkedFile {
        digests: out.hasher.finish(),
        chunks: out.chunks,
        listed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk::cut::GEAR;

    #[test]
    fn a_file_is_cut_into_at_most_as_many_chunks_as_an_index_lists() {
        // From the average on, level 3 uses the 5-bit mask. A byte whose
        // gear value has none of its bits ends a chunk wherever it's the
        // first byte searched, so a file of nothing else is cut every 256
        // bytes.
        let p = ChunkParams::new(256, 256, 1024, 256, 3).unwrap();
        let (_, large) = p.masks();
        let byte = (0..=255u8)
            .find(|&b| GEAR[usize::from(b)] & large == 0)
            .unwrap();
        let file = |chunks: u64| {
            let reader = io::repeat(byte).take(256 * chunks);
            chunk_file(reader, &p, |_, _| Ok(()))
        };
        let at_limit = file(MAX_CHUNKS as u64).unwrap();
        assert_eq!(at_limit.chunks().len(), MAX_CHUNKS);
        assert!(at_limit.chunks().iter().all(|c| c.length == 256));
        let over = file(MAX_CHUNKS as u64 + 1).unwrap_err();
        assert_eq!(over.kind(), ErrorKind::FileTooLarge);
        assert_eq!(
            over.to_string(),
            "the file is cut into more chunks than a chunk index can list"
        );
    }
}
