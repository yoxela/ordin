// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Compressing chunks into independent zstd frames, on several threads.
//!
//! Each frame depends only on its chunk and the level, so the frames are
//! the same however the chunks are batched or shared between threads.

use std::io;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};

use ordin_core::Digest;
use zstd::bulk::Compressor;
use zstd::zstd_safe::CParameter;

/// The most chunks a batch holds before it is compressed.
pub(crate) const BATCH_CHUNKS: usize = 256;

/// The most uncompressed bytes a batch holds before it is compressed.
pub(crate) const BATCH_BYTES: usize = 64 << 20;

/// Chunks waiting to be compressed, in pack order.
#[derive(Default)]
pub(crate) struct Batch {
    chunks: Vec<(Digest, Vec<u8>)>,
    bytes: usize,
}

impl Batch {
    pub(crate) fn push(&mut self, digest: Digest, bytes: &[u8]) {
        self.bytes += bytes.len();
        self.chunks.push((digest, bytes.to_vec()));
    }

    /// Whether the batch should be compressed before it takes more.
    pub(crate) fn is_full(&self) -> bool {
        self.chunks.len() >= BATCH_CHUNKS || self.bytes >= BATCH_BYTES
    }

    /// Empties the batch and returns what it held.
    pub(crate) fn take(&mut self) -> Vec<(Digest, Vec<u8>)> {
        self.bytes = 0;
        std::mem::take(&mut self.chunks)
    }
}

/// A compressor for one frame per chunk: the uncompressed size is in
/// every frame header, and there is no checksum or dictionary ID, because
/// each chunk is verified by its BLAKE3 digest.
fn compressor(level: i32) -> io::Result<Compressor<'static>> {
    let mut c = Compressor::new(level)?;
    c.set_parameter(CParameter::ContentSizeFlag(true))?;
    c.set_parameter(CParameter::ChecksumFlag(false))?;
    c.set_parameter(CParameter::DictIdFlag(false))?;
    Ok(c)
}

/// Compresses each chunk into its own frame at `level`, on `threads`
/// threads, and returns the frames in the chunks' order.
///
/// # Errors
///
/// Any error from zstd.
pub(crate) fn compress(
    chunks: &[(Digest, Vec<u8>)],
    level: i32,
    threads: NonZeroUsize,
) -> io::Result<Vec<Vec<u8>>> {
    let next = AtomicUsize::new(0);
    let work = || -> io::Result<Vec<(usize, Vec<u8>)>> {
        let mut c = compressor(level)?;
        let mut done = Vec::new();
        loop {
            let i = next.fetch_add(1, Ordering::Relaxed);
            let Some((_, bytes)) = chunks.get(i) else {
                return Ok(done);
            };
            done.push((i, c.compress(bytes)?));
        }
    };
    let results: Vec<_> = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..threads.get()).map(|_| scope.spawn(work)).collect();
        workers.into_iter().map(|w| w.join()).collect()
    });
    let mut frames: Vec<Option<Vec<u8>>> = vec![None; chunks.len()];
    for result in results {
        let done = result.map_err(|_| io::Error::other("a compression thread panicked"))??;
        for (i, frame) in done {
            if let Some(slot) = frames.get_mut(i) {
                *slot = Some(frame);
            }
        }
    }
    frames
        .into_iter()
        .map(|f| f.ok_or_else(|| io::Error::other("a chunk was left uncompressed")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunks(n: usize) -> Vec<(Digest, Vec<u8>)> {
        (0..n)
            .map(|i| {
                let bytes = format!("chunk {i} ").repeat(i + 1).into_bytes();
                (Digest::blake3(&bytes), bytes)
            })
            .collect()
    }

    #[test]
    fn a_batch_is_full_at_either_limit() {
        let d = Digest::blake3(b"");
        let mut b = Batch::default();
        for _ in 0..BATCH_CHUNKS - 1 {
            b.push(d, b"x");
        }
        assert!(!b.is_full());
        b.push(d, b"x");
        assert!(b.is_full());
        assert_eq!(b.take().len(), BATCH_CHUNKS);
        assert!(!b.is_full());

        b.push(d, &vec![0; BATCH_BYTES - 1]);
        assert!(!b.is_full());
        b.push(d, b"x");
        assert!(b.is_full());
        assert_eq!(b.take().len(), 2);
        b.push(d, b"x");
        assert!(!b.is_full(), "taking resets the byte count");
    }

    #[test]
    fn frames_are_the_same_on_any_number_of_threads() {
        let chunks = chunks(40);
        let one = compress(&chunks, 19, NonZeroUsize::MIN).unwrap();
        let many = compress(&chunks, 19, NonZeroUsize::new(7).unwrap()).unwrap();
        assert_eq!(one, many);
        assert_eq!(one.len(), 40);
        for ((_, bytes), frame) in chunks.iter().zip(&one) {
            let mut c = compressor(19).unwrap();
            assert_eq!(frame, &c.compress(bytes).unwrap());
            assert_eq!(&zstd::bulk::decompress(frame, bytes.len()).unwrap(), bytes);
        }
        assert!(compress(&[], 19, NonZeroUsize::MIN).unwrap().is_empty());
    }

    #[test]
    fn frames_are_made_at_the_level_asked_for() {
        // Compressible enough that the level makes a difference.
        let bytes: Vec<u8> = (0..20_000u32)
            .flat_map(|i| format!("line {} of {}\n", i % 97, i % 13).into_bytes())
            .collect();
        let chunk = [(Digest::blake3(&bytes), bytes.clone())];
        let at_19 = &compress(&chunk, 19, NonZeroUsize::MIN).unwrap()[0];
        assert_eq!(at_19, &zstd::bulk::compress(&bytes, 19).unwrap());
        assert_ne!(at_19, &zstd::bulk::compress(&bytes, 0).unwrap());
        let at_1 = &compress(&chunk, 1, NonZeroUsize::MIN).unwrap()[0];
        assert_eq!(at_1, &zstd::bulk::compress(&bytes, 1).unwrap());
    }

    #[test]
    fn frames_record_their_size_and_no_checksum() {
        let bytes = b"hello hello hello hello";
        let frame = &compress(
            &[(Digest::blake3(bytes), bytes.to_vec())],
            19,
            NonZeroUsize::MIN,
        )
        .unwrap()[0];
        assert_eq!(
            zstd::zstd_safe::get_frame_content_size(frame).unwrap(),
            Some(bytes.len() as u64)
        );
        // The frame header descriptor: bit 2 is the checksum flag, and
        // bits 0 and 1 the dictionary ID's size.
        assert_eq!(&frame[..4], &[0x28, 0xb5, 0x2f, 0xfd]);
        assert_eq!(frame[4] & 0b111, 0);
    }
}
