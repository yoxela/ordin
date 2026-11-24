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
use crate::error::{PackTableError, PackTableErrorKind, WriteError};

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
    /// Positions in `chunks`, sorted by digest, for lookups.
    by_digest: Vec<u32>,
}

/// The most chunks a pack table can list: one per file under the
/// whole-file threshold, plus every chunk the chunk index can list.
pub const MAX_PACK_CHUNKS: usize = ordin_tree::MAX_ENTRIES + ordin_tree::chunk::MAX_CHUNKS;

/// The longest chunk any chunking allows: 16 MiB.
pub const MAX_CHUNK: u64 = ordin_tree::chunk::MAXIMUM_BOUNDS.1 as u64;

/// The longest frame a chunk can compress to: zstd's bound for
/// [`MAX_CHUNK`] bytes (`ZSTD_COMPRESSBOUND`).
pub const MAX_FRAME: u64 = MAX_CHUNK + (MAX_CHUNK >> 8);

const TABLE_START: &[u8] = br#"{"chunks":["#;
const ENTRY_START: &[u8] = br#"{"digest":"blake3:"#;
const ENTRY_LENGTH: &[u8] = br#"","length":"#;
const ENTRY_OFFSET: &[u8] = br#","offset":"#;
const TABLE_VERSION: &[u8] = br#"],"ordin-pack-table":"#;
const TABLE_LEVEL: &[u8] = br#","zstd-level":"#;

/// The most bytes a pack table can have: its longest form with
/// [`MAX_PACK_CHUNKS`] chunks, frames of up to [`MAX_FRAME`] bytes (8
/// digits) and offsets up to a tar entry's limit (10 digits).
pub const MAX_PACK_TABLE_SIZE: usize = TABLE_START.len()
    + MAX_PACK_CHUNKS
        * (ENTRY_START.len() + 64 + ENTRY_LENGTH.len() + 8 + ENTRY_OFFSET.len() + 10 + 2)
    + TABLE_VERSION.len()
    + 1
    + TABLE_LEVEL.len()
    + 2
    + 1;

fn int(value: u64) -> Value {
    Value::Int(i64::try_from(value).unwrap_or(MAX_INT))
}

impl PackTable {
    pub(crate) fn new(level: i32, chunks: Vec<PackEntry>) -> Self {
        let mut by_digest: Vec<u32> = (0..chunks.len())
            .map(|i| u32::try_from(i).unwrap_or(u32::MAX))
            .collect();
        by_digest.sort_by_key(|&i| chunks.get(i as usize).map(|c| c.digest));
        Self {
            level,
            chunks,
            by_digest,
        }
    }

    /// Reads a table from its canonical bytes, for a pack of `pack_size`
    /// bytes. Only the exact canonical form is accepted, and it is read
    /// without building a JSON value, so memory stays near the size of
    /// the entries.
    ///
    /// # Errors
    ///
    /// The first rule the bytes break, and where: the text isn't the
    /// canonical table, the version isn't 1, the level is outside 1 to 22,
    /// a digest repeats, a frame is empty, too long or not where the one
    /// before it ends, or the frames don't end where the pack does.
    pub fn from_canonical_bytes(bytes: &[u8], pack_size: u64) -> Result<Self, PackTableError> {
        Self::parse(bytes, pack_size, MAX_PACK_CHUNKS)
    }

    /// [`from_canonical_bytes`](Self::from_canonical_bytes) with at most
    /// `max_chunks` chunks.
    fn parse(bytes: &[u8], pack_size: u64, max_chunks: usize) -> Result<Self, PackTableError> {
        if bytes.len() > MAX_PACK_TABLE_SIZE {
            return Err(PackTableError {
                at: 0,
                kind: PackTableErrorKind::TooLarge {
                    max: MAX_PACK_TABLE_SIZE,
                    len: bytes.len(),
                },
            });
        }
        let mut text = Text { bytes, at: 0 };
        text.literal(TABLE_START, "the start of a pack table")?;
        let mut chunks = Vec::new();
        // Where each chunk's entry starts, for a repeated digest's error.
        let mut starts = Vec::new();
        let mut end = 0;
        if !text.next_is(b']') {
            loop {
                let at = text.at;
                let index = chunks.len();
                if index == max_chunks {
                    return Err(
                        text.error_at(at, PackTableErrorKind::TooManyChunks { max: max_chunks })
                    );
                }
                text.literal(ENTRY_START, "a chunk's blake3 digest")?;
                let digest = text.digest()?;
                text.literal(ENTRY_LENGTH, "the frame's length")?;
                let length = text.integer()?;
                text.literal(ENTRY_OFFSET, "the frame's offset")?;
                let offset = text.integer()?;
                text.literal(b"}", "the end of a chunk")?;
                if !(1..=MAX_FRAME).contains(&length) {
                    return Err(text.error_at(
                        at,
                        PackTableErrorKind::FrameLength {
                            index,
                            length,
                            max: MAX_FRAME,
                        },
                    ));
                }
                if offset != end {
                    return Err(text.error_at(
                        at,
                        PackTableErrorKind::Gap {
                            index,
                            offset,
                            expected: end,
                        },
                    ));
                }
                // Both are at most 2^53-1, so this can't overflow.
                end = offset + length;
                starts.push(at);
                chunks.push(PackEntry {
                    digest,
                    offset,
                    length,
                });
                if !text.next_is(b',') {
                    break;
                }
                text.at += 1;
            }
        }
        text.literal(
            TABLE_VERSION,
            "the end of the chunks and the format version",
        )?;
        let at = text.at;
        let version = text.integer()?;
        if version != 1 {
            return Err(text.error_at(at, PackTableErrorKind::Version(version)));
        }
        text.literal(TABLE_LEVEL, "the zstd level")?;
        let at = text.at;
        let level = text.integer()?;
        let level = i32::try_from(level)
            .ok()
            .filter(|l| (1..=crate::write::MAX_LEVEL).contains(l))
            .ok_or_else(|| text.error_at(at, PackTableErrorKind::Level(level)))?;
        text.literal(b"}", "the end of the table")?;
        if text.at != bytes.len() {
            return Err(text.error_at(text.at, PackTableErrorKind::Expected("the end of the text")));
        }
        if end != pack_size {
            return Err(text.error_at(
                text.at,
                PackTableErrorKind::End {
                    end,
                    pack: pack_size,
                },
            ));
        }
        let table = Self::new(level, chunks);
        // Sorting is stable, so of two equal digests the later chunk
        // comes second.
        for pair in table.by_digest.windows(2) {
            let &[first, second] = pair else { continue };
            let (Some(a), Some(b)) = (
                table.chunks.get(first as usize),
                table.chunks.get(second as usize),
            ) else {
                continue;
            };
            if a.digest == b.digest {
                let index = second as usize;
                return Err(PackTableError {
                    at: starts.get(index).copied().unwrap_or_default(),
                    kind: PackTableErrorKind::Repeated {
                        index,
                        digest: b.digest,
                    },
                });
            }
        }
        Ok(table)
    }

    /// Where the chunk with this digest is, if the table lists it.
    #[must_use]
    pub fn find(&self, digest: &Digest) -> Option<&PackEntry> {
        let at = self
            .by_digest
            .binary_search_by(|&i| {
                self.chunks
                    .get(i as usize)
                    .map_or(std::cmp::Ordering::Greater, |c| c.digest.cmp(digest))
            })
            .ok()?;
        self.chunks.get(*self.by_digest.get(at)? as usize)
    }

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

/// Pack table text, read from the front.
struct Text<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Text<'_> {
    fn error_at(&self, at: usize, kind: PackTableErrorKind) -> PackTableError {
        PackTableError { at, kind }
    }

    fn next_is(&self, byte: u8) -> bool {
        self.bytes.get(self.at) == Some(&byte)
    }

    fn literal(&mut self, literal: &[u8], what: &'static str) -> Result<(), PackTableError> {
        let end = self.at.saturating_add(literal.len());
        if self.bytes.get(self.at..end) != Some(literal) {
            return Err(self.error_at(self.at, PackTableErrorKind::Expected(what)));
        }
        self.at = end;
        Ok(())
    }

    /// 64 lowercase hex digits after `blake3:`, and the closing quote is
    /// left for the next literal.
    fn digest(&mut self) -> Result<Digest, PackTableError> {
        let end = self.at.saturating_add(64);
        let parsed = self
            .bytes
            .get(self.at..end)
            .and_then(|hex| std::str::from_utf8(hex).ok())
            .and_then(|hex| format!("blake3:{hex}").parse::<Digest>().ok())
            .ok_or_else(|| {
                self.error_at(
                    self.at,
                    PackTableErrorKind::Expected("64 lowercase hex digits"),
                )
            })?;
        self.at = end;
        Ok(parsed)
    }

    /// A canonical non-negative integer up to 2^53-1: `0`, or a digit 1
    /// to 9 followed by digits.
    fn integer(&mut self) -> Result<u64, PackTableError> {
        let start = self.at;
        let digits = self
            .bytes
            .get(start..)
            .unwrap_or_default()
            .iter()
            .take_while(|b| b.is_ascii_digit())
            .count();
        let bad = || PackTableError {
            at: start,
            kind: PackTableErrorKind::Integer,
        };
        let text = self.bytes.get(start..start + digits).ok_or_else(bad)?;
        if text.is_empty() || (text.len() > 1 && text.first() == Some(&b'0')) || text.len() > 16 {
            return Err(bad());
        }
        let value = text.iter().fold(0u64, |v, d| v * 10 + u64::from(*d - b'0'));
        if value > MAX_INT.unsigned_abs() {
            return Err(bad());
        }
        self.at = start + digits;
        Ok(value)
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
        let table = PackTable::new(self.level, self.chunks);
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
        let table = PackTable::new(
            19,
            vec![PackEntry {
                digest: Digest::blake3(b""),
                offset: 0,
                length: 9,
            }],
        );
        assert_eq!(
            String::from_utf8(table.to_canonical_bytes()).unwrap(),
            format!(
                r#"{{"chunks":[{{"digest":"{}","length":9,"offset":0}}],"ordin-pack-table":1,"zstd-level":19}}"#,
                Digest::blake3(b"")
            )
        );
        let empty = PackTable::new(3, Vec::new());
        assert_eq!(
            empty.to_canonical_bytes(),
            br#"{"chunks":[],"ordin-pack-table":1,"zstd-level":3}"#
        );
        assert_eq!(empty.pack_size(), 0);
        assert_eq!(int(u64::MAX), Value::Int(MAX_INT));
    }

    fn d(n: u8) -> Digest {
        Digest::blake3(&[n])
    }

    /// A table's text from its parts, so tests can write what the writer
    /// never would.
    fn text(entries: &[(Digest, u64, u64)], version: u64, level: u64) -> Vec<u8> {
        let chunks: Vec<String> = entries
            .iter()
            .map(|(digest, length, offset)| {
                format!(r#"{{"digest":"{digest}","length":{length},"offset":{offset}}}"#)
            })
            .collect();
        format!(
            r#"{{"chunks":[{}],"ordin-pack-table":{version},"zstd-level":{level}}}"#,
            chunks.join(",")
        )
        .into_bytes()
    }

    fn refused(bytes: &[u8], pack_size: u64) -> PackTableError {
        PackTable::from_canonical_bytes(bytes, pack_size).unwrap_err()
    }

    #[test]
    fn tables_read_back_as_they_were_written() {
        let mut b = builder(u64::MAX, Vec::new());
        let parts: Vec<Vec<u8>> = (0..300u32)
            .map(|i| i.to_le_bytes().repeat(i as usize % 7))
            .collect();
        for bytes in &parts {
            b.add(Digest::blake3(bytes), bytes).unwrap();
        }
        let (table, pack, _) = b.finish().unwrap();
        let read = PackTable::from_canonical_bytes(&table.to_canonical_bytes(), pack.len() as u64)
            .unwrap();
        assert_eq!(read, table);
        for entry in table.chunks() {
            assert_eq!(read.find(&entry.digest), Some(entry));
        }
        assert_eq!(read.find(&Digest::blake3(b"not stored")), None);

        let empty = PackTable::new(22, Vec::new());
        let read = PackTable::from_canonical_bytes(&empty.to_canonical_bytes(), 0).unwrap();
        assert_eq!(read, empty);
        assert_eq!(read.level(), 22);
        assert_eq!(read.find(&d(0)), None);
    }

    #[test]
    fn the_limits_fit_the_largest_table() {
        assert_eq!(MAX_PACK_CHUNKS, 786_432);
        assert_eq!(MAX_CHUNK, 16 << 20);
        assert_eq!(
            MAX_FRAME,
            zstd::zstd_safe::compress_bound(MAX_CHUNK as usize) as u64
        );
        let longest = crate::tar::MAX_ENTRY_SIZE - MAX_FRAME;
        let one = PackTable::new(
            22,
            vec![PackEntry {
                digest: d(0),
                offset: longest,
                length: MAX_FRAME,
            }],
        )
        .to_canonical_bytes()
        .len();
        let none = PackTable::new(22, Vec::new()).to_canonical_bytes().len();
        // Each entry and the comma after it.
        assert_eq!(
            MAX_PACK_TABLE_SIZE,
            none + MAX_PACK_CHUNKS * (one - none + 1)
        );

        let at_limit = vec![b' '; MAX_PACK_TABLE_SIZE];
        assert_eq!(
            refused(&at_limit, 0).kind,
            PackTableErrorKind::Expected("the start of a pack table")
        );
        let over = vec![b' '; MAX_PACK_TABLE_SIZE + 1];
        assert_eq!(
            refused(&over, 0),
            PackTableError {
                at: 0,
                kind: PackTableErrorKind::TooLarge {
                    max: MAX_PACK_TABLE_SIZE,
                    len: MAX_PACK_TABLE_SIZE + 1
                }
            }
        );
    }

    #[test]
    fn a_table_may_list_its_limit_of_chunks_but_no_more() {
        let two = text(&[(d(0), 5, 0), (d(1), 5, 5)], 1, 19);
        assert_eq!(PackTable::parse(&two, 10, 2).unwrap().chunks().len(), 2);
        let three = text(&[(d(0), 5, 0), (d(1), 5, 5), (d(2), 5, 10)], 1, 19);
        let e = PackTable::parse(&three, 15, 2).unwrap_err();
        let third = three.windows(2).rposition(|w| w == b",{").unwrap() + 1;
        assert_eq!(
            e,
            PackTableError {
                at: third,
                kind: PackTableErrorKind::TooManyChunks { max: 2 }
            }
        );
    }

    #[test]
    fn frames_follow_each_other_from_the_start_to_the_end_of_the_pack() {
        let ok = text(&[(d(0), 5, 0), (d(1), 7, 5)], 1, 19);
        assert_eq!(
            PackTable::from_canonical_bytes(&ok, 12)
                .unwrap()
                .pack_size(),
            12
        );
        for pack in [11, 13, 0] {
            assert_eq!(
                refused(&ok, pack).kind,
                PackTableErrorKind::End { end: 12, pack },
                "{pack}"
            );
        }
        let late_start = text(&[(d(0), 5, 1)], 1, 19);
        assert_eq!(
            refused(&late_start, 6),
            PackTableError {
                at: 11,
                kind: PackTableErrorKind::Gap {
                    index: 0,
                    offset: 1,
                    expected: 0
                }
            }
        );
        for offset in [4, 6] {
            let gap = text(&[(d(0), 5, 0), (d(1), 7, offset)], 1, 19);
            let e = refused(&gap, 12);
            assert_eq!(
                e.kind,
                PackTableErrorKind::Gap {
                    index: 1,
                    offset,
                    expected: 5
                }
            );
            assert_eq!(e.at, gap.windows(2).position(|w| w == b",{").unwrap() + 1);
        }
    }

    #[test]
    fn a_frame_is_one_to_max_frame_bytes() {
        let max = text(&[(d(0), MAX_FRAME, 0)], 1, 19);
        assert!(PackTable::from_canonical_bytes(&max, MAX_FRAME).is_ok());
        let one = text(&[(d(0), 1, 0)], 1, 19);
        assert!(PackTable::from_canonical_bytes(&one, 1).is_ok());
        for length in [0, MAX_FRAME + 1] {
            let bad = text(&[(d(0), length, 0)], 1, 19);
            assert_eq!(
                refused(&bad, length),
                PackTableError {
                    at: 11,
                    kind: PackTableErrorKind::FrameLength {
                        index: 0,
                        length,
                        max: MAX_FRAME
                    }
                }
            );
        }
    }

    #[test]
    fn a_digest_appears_once() {
        let repeated = text(&[(d(1), 5, 0), (d(0), 5, 5), (d(1), 5, 10)], 1, 19);
        let third = repeated.windows(2).rposition(|w| w == b",{").unwrap() + 1;
        assert_eq!(
            refused(&repeated, 15),
            PackTableError {
                at: third,
                kind: PackTableErrorKind::Repeated {
                    index: 2,
                    digest: d(1)
                }
            }
        );
        let next_to = text(&[(d(0), 5, 0), (d(0), 5, 5)], 1, 19);
        assert!(matches!(
            refused(&next_to, 10).kind,
            PackTableErrorKind::Repeated { index: 1, .. }
        ));
    }

    #[test]
    fn the_version_is_1_and_the_level_1_to_22() {
        for level in [1, 22] {
            let ok = text(&[], 1, level);
            assert_eq!(
                PackTable::from_canonical_bytes(&ok, 0).unwrap().level(),
                level as i32
            );
        }
        let v2 = text(&[], 2, 19);
        assert_eq!(
            refused(&v2, 0),
            PackTableError {
                at: 32,
                kind: PackTableErrorKind::Version(2)
            }
        );
        for level in [0, 23, 1 << 40] {
            let bad = text(&[], 1, level);
            assert_eq!(
                refused(&bad, 0),
                PackTableError {
                    at: 47,
                    kind: PackTableErrorKind::Level(level)
                },
                "{level}"
            );
        }
    }

    #[test]
    fn only_the_canonical_text_is_read() {
        let entry = format!(r#"{{"digest":"{}","length":5,"offset":0}}"#, d(0));
        let tail = r#"],"ordin-pack-table":1,"zstd-level":19}"#;
        let cases: Vec<(String, usize, &str)> = vec![
            (String::new(), 0, "the start of a pack table"),
            (
                format!(r#"{{ "chunks":[{entry}{tail}"#),
                0,
                "the start of a pack table",
            ),
            (
                format!(
                    r#"{{"chunks":[{{"digest":"sha256:{}","length":5,"offset":0}}{tail}"#,
                    "0".repeat(64)
                ),
                11,
                "a chunk's blake3 digest",
            ),
            (
                format!(
                    r#"{{"chunks":[{{"digest":"blake3:{}","length":5,"offset":0}}{tail}"#,
                    "A".repeat(64)
                ),
                29,
                "64 lowercase hex digits",
            ),
            (
                format!(
                    r#"{{"chunks":[{{"digest":"blake3:{}","length":5,"offset":0}}{tail}"#,
                    "0".repeat(63)
                ),
                29,
                "64 lowercase hex digits",
            ),
            (
                format!(
                    r#"{{"chunks":[{{"digest":"{}","offset":0,"length":5}}{tail}"#,
                    d(0)
                ),
                93,
                "the frame's length",
            ),
            (
                format!(r#"{{"chunks":[{{"digest":"{}","length":5}}{tail}"#, d(0)),
                105,
                "the frame's offset",
            ),
            (
                format!(
                    r#"{{"chunks":[{{"digest":"{}","length":5,"offset":0,"x":1}}{tail}"#,
                    d(0)
                ),
                116,
                "the end of a chunk",
            ),
            (
                format!(r#"{{"chunks":[{entry} {tail}"#),
                117,
                "the end of the chunks and the format version",
            ),
            (
                format!(r#"{{"chunks":[{entry}],"zstd-level":19,"ordin-pack-table":1}}"#),
                117,
                "the end of the chunks and the format version",
            ),
            (
                format!(r#"{{"chunks":[{entry}],"ordin-pack-table":1}}"#),
                139,
                "the zstd level",
            ),
            (
                format!(r#"{{"chunks":[{entry}],"ordin-pack-table":1,"zstd-level":19"#),
                155,
                "the end of the table",
            ),
            (
                format!(r#"{{"chunks":[{entry}{tail} "#),
                156,
                "the end of the text",
            ),
            (
                format!(r#"{{"chunks":[{entry}{tail}{{}}"#),
                156,
                "the end of the text",
            ),
        ];
        for (bytes, at, what) in cases {
            assert_eq!(
                refused(bytes.as_bytes(), 5),
                PackTableError {
                    at,
                    kind: PackTableErrorKind::Expected(what)
                },
                "{bytes}"
            );
        }
        let good = format!(r#"{{"chunks":[{entry}{tail}"#);
        assert!(PackTable::from_canonical_bytes(good.as_bytes(), 5).is_ok());
    }

    #[test]
    fn integers_are_canonical_and_at_most_2_to_the_53_minus_1() {
        let read = |t: &str| {
            let mut text = Text {
                bytes: t.as_bytes(),
                at: 0,
            };
            text.integer().map(|v| (v, text.at))
        };
        assert_eq!(read("0"), Ok((0, 1)));
        assert_eq!(read("0,"), Ok((0, 1)));
        assert_eq!(read("7}"), Ok((7, 1)));
        assert_eq!(read("9007199254740991"), Ok((9_007_199_254_740_991, 16)));
        assert_eq!(read("1234567890"), Ok((1_234_567_890, 10)));
        for bad in [
            "",
            "-1",
            "01",
            "00",
            "9007199254740992",
            "99999999999999999",
            "x",
        ] {
            assert_eq!(
                read(bad),
                Err(PackTableError {
                    at: 0,
                    kind: PackTableErrorKind::Integer
                }),
                "{bad}"
            );
        }
    }

    #[test]
    fn errors_say_what_and_where() {
        let e = PackTableError {
            at: 3,
            kind: PackTableErrorKind::Expected("the end of the table"),
        };
        assert_eq!(e.to_string(), "expected the end of the table, at byte 3");
    }
}
