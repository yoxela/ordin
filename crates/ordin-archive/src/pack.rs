// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Chunk packs and their pack tables.
//!
//! A facet's chunk pack is its chunks as independent zstd frames, back to
//! back, each chunk once, in the order the facet's files first need them.
//! Its pack table says where each frame is, in compressed bytes. Neither
//! is part of any identity: compressed bytes may change with the zstd
//! version.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::num::NonZeroUsize;

use ordin_core::json::{self, MAX_INT, Value};
use ordin_core::{Digest, Facet};

use crate::blob::{BlobId, HashingWriter};
use crate::compress::{Batch, compress};
use crate::error::WriteError;

/// The pack table format's version: `"ordin-pack-table": 1`.
pub const PACK_TABLE_VERSION: i64 = 1;

/// Where one chunk's frame is in a chunk pack.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackEntry {
    /// The BLAKE3 digest of the chunk's uncompressed bytes.
    pub digest: Digest,
    /// Where the frame starts, in bytes from the start of the pack.
    pub offset: u64,
    /// The frame's length in bytes.
    pub length: u64,
}

/// A chunk pack's table: the zstd level its frames were made at, and
/// where each one is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackTable {
    level: i32,
    chunks: Vec<PackEntry>,
}

fn int(value: u64) -> Value {
    Value::Int(i64::try_from(value).unwrap_or(MAX_INT))
}

impl PackTable {
    /// The zstd level the frames were made at.
    #[must_use]
    pub fn level(&self) -> i32 {
        self.level
    }

    /// The chunks in pack order: each starts where the one before it ends,
    /// and the first at 0.
    #[must_use]
    pub fn chunks(&self) -> &[PackEntry] {
        &self.chunks
    }

    /// The pack's size: where the last frame ends.
    #[must_use]
    pub fn pack_size(&self) -> u64 {
        self.chunks.last().map_or(0, |c| c.offset + c.length)
    }

    /// The table's canonical JSON (RFC 8785).
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let chunks = self
            .chunks
            .iter()
            .map(|c| {
                Value::Object(BTreeMap::from([
                    ("digest".to_owned(), Value::Str(c.digest.to_string())),
                    ("length".to_owned(), int(c.length)),
                    ("offset".to_owned(), int(c.offset)),
                ]))
            })
            .collect();
        let table = Value::Object(BTreeMap::from([
            ("chunks".to_owned(), Value::Array(chunks)),
            (
                "ordin-pack-table".to_owned(),
                Value::Int(PACK_TABLE_VERSION),
            ),
            ("zstd-level".to_owned(), Value::Int(i64::from(self.level))),
        ]));
        json::canonical(&table).into_bytes()
    }
}

/// Builds one facet's chunk pack into `out`, chunk by chunk.
pub(crate) struct PackBuilder<W> {
    facet: Facet,
    level: i32,
    threads: NonZeroUsize,
    max_size: u64,
    out: HashingWriter<W>,
    stored: BTreeSet<Digest>,
    chunks: Vec<PackEntry>,
    batch: Batch,
}

impl<W: Write> PackBuilder<W> {
    /// A builder whose pack may grow to `max_size` bytes.
    pub(crate) fn new(
        facet: Facet,
        level: i32,
        threads: NonZeroUsize,
        max_size: u64,
        out: W,
    ) -> Self {
        Self {
            facet,
            level,
            threads,
            max_size,
            out: HashingWriter::new(out),
            stored: BTreeSet::new(),
            chunks: Vec::new(),
            batch: Batch::default(),
        }
    }

    /// Adds a chunk, unless the pack already has it.
    ///
    /// # Errors
    ///
    /// Compressing or spooling failed, or the pack grew too large.
    pub(crate) fn add(&mut self, digest: Digest, bytes: &[u8]) -> Result<(), WriteError> {
        if !self.stored.insert(digest) {
            return Ok(());
        }
        self.batch.push(digest, bytes);
        if self.batch.is_full() {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), WriteError> {
        let chunks = self.batch.take();
        let frames = compress(&chunks, self.level, self.threads).map_err(WriteError::Compress)?;
        for ((digest, _), frame) in chunks.iter().zip(frames) {
            let offset = self.out.size();
            let length = u64::try_from(frame.len()).unwrap_or(u64::MAX);
            if length > self.max_size.saturating_sub(offset) {
                return Err(WriteError::PackTooLarge {
                    facet: self.facet.clone(),
                    max: self.max_size,
                });
            }
            self.out.write_all(&frame).map_err(WriteError::Spool)?;
            self.chunks.push(PackEntry {
                digest: *digest,
                offset,
                length,
            });
        }
        Ok(())
    }

    /// Compresses what is left and returns the table, the output and the
    /// pack's identity.
    ///
    /// # Errors
    ///
    /// As for [`add`](Self::add).
    pub(crate) fn finish(mut self) -> Result<(PackTable, W, BlobId), WriteError> {
        self.flush()?;
        let (out, id) = self.out.finish();
        let table = PackTable {
            level: self.level,
            chunks: self.chunks,
        };
        Ok((table, out, id))
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;

    fn facet() -> Facet {
        "runtime".parse().unwrap()
    }

    fn builder<W: Write>(max_size: u64, out: W) -> PackBuilder<W> {
        PackBuilder::new(facet(), 19, NonZeroUsize::MIN, max_size, out)
    }

    #[test]
    fn each_chunk_is_stored_once_in_first_use_order() {
        let mut b = builder(u64::MAX, Vec::new());
        let (x, y) = (b"xxxxxxxx".as_slice(), b"yy".as_slice());
        for bytes in [x, y, x, y] {
            b.add(Digest::blake3(bytes), bytes).unwrap();
        }
        let (table, pack, id) = b.finish().unwrap();
        assert_eq!(id, BlobId::of(&pack));
        let digests: Vec<_> = table.chunks().iter().map(|c| c.digest).collect();
        assert_eq!(digests, [Digest::blake3(x), Digest::blake3(y)]);
        let [first, second] = table.chunks() else {
            panic!("two chunks")
        };
        assert_eq!(first.offset, 0);
        assert_eq!(second.offset, first.length);
        assert_eq!(table.pack_size(), pack.len() as u64);
        for (c, bytes) in table.chunks().iter().zip([x, y]) {
            let frame = &pack[c.offset as usize..(c.offset + c.length) as usize];
            assert_eq!(zstd::bulk::decompress(frame, bytes.len()).unwrap(), bytes);
        }
        assert_eq!(table.level(), 19);
    }

    #[test]
    fn a_full_batch_is_written_before_the_pack_ends() {
        let mut b = builder(u64::MAX, Vec::new());
        for i in 0..crate::compress::BATCH_CHUNKS {
            let bytes = i.to_le_bytes();
            b.add(Digest::blake3(&bytes), &bytes).unwrap();
        }
        assert_eq!(b.chunks.len(), crate::compress::BATCH_CHUNKS);
        assert!(b.out.size() > 0);
    }

    #[test]
    fn a_pack_may_reach_its_limit_but_not_pass_it() {
        let bytes = b"abc";
        let length = compress(
            &[(Digest::blake3(bytes), bytes.to_vec())],
            19,
            NonZeroUsize::MIN,
        )
        .unwrap()[0]
            .len() as u64;
        let mut b = builder(length, Vec::new());
        b.add(Digest::blake3(bytes), bytes).unwrap();
        assert_eq!(b.finish().unwrap().0.pack_size(), length);

        let mut b = builder(length - 1, Vec::new());
        b.add(Digest::blake3(bytes), bytes).unwrap();
        let e = b.finish().unwrap_err();
        assert_eq!(
            e.to_string(),
            format!(
                "the chunk pack for facet runtime would pass {} bytes, the most a tar entry can hold",
                length - 1
            )
        );
    }

    struct Broken;

    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("disk full"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_spool_that_fails_is_an_error() {
        let mut b = builder(u64::MAX, Broken);
        b.add(Digest::blake3(b"a"), b"a").unwrap();
        let e = b.finish().err().unwrap();
        assert_eq!(e.to_string(), "spooling a chunk pack: disk full");
    }

    #[test]
    fn the_table_is_canonical_json() {
        let table = PackTable {
            level: 19,
            chunks: vec![PackEntry {
                digest: Digest::blake3(b""),
                offset: 0,
                length: 9,
            }],
        };
        assert_eq!(
            String::from_utf8(table.to_canonical_bytes()).unwrap(),
            format!(
                r#"{{"chunks":[{{"digest":"{}","length":9,"offset":0}}],"ordin-pack-table":1,"zstd-level":19}}"#,
                Digest::blake3(b"")
            )
        );
        let empty = PackTable {
            level: 3,
            chunks: Vec::new(),
        };
        assert_eq!(
            empty.to_canonical_bytes(),
            br#"{"chunks":[],"ordin-pack-table":1,"zstd-level":3}"#
        );
        assert_eq!(empty.pack_size(), 0);
        assert_eq!(int(u64::MAX), Value::Int(MAX_INT));
    }
}
