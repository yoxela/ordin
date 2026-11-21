// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Cutting files into chunks: against fastcdc 3.2.1's streaming chunker,
//! at fixed vectors with the default settings, through readers that
//! misbehave, and back through a chunk index.
//!
//! The vectors' data is a fixed xorshift sequence (see `noise`). Their
//! chunk lengths are fastcdc 3.2.1's `v2020::StreamCDC` output with
//! normalization level 1, which the cross-checks below compare against at
//! random.

#[cfg(test)]
mod chunks {
    use std::collections::{BTreeMap, VecDeque};
    use std::io::{self, ErrorKind, Read};

    use ordin_core::Digest;
    use ordin_tree::chunk::{ChunkIndex, ChunkParams, ChunkRef, ChunkedFile, chunk_file};
    use ordin_tree::file_digests;
    use proptest::prelude::*;

    /// Bytes from a fixed xorshift sequence.
    fn noise(seed: u64, len: usize) -> Vec<u8> {
        let mut state = seed | 1;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state.to_le_bytes()[0]
            })
            .collect()
    }

    fn small(whole_below: u64, level: u64) -> ChunkParams {
        ChunkParams::new(64, 256, 1024, whole_below, level).unwrap()
    }

    fn level(p: &ChunkParams) -> fastcdc::v2020::Normalization {
        match p.normalization() {
            0 => fastcdc::v2020::Normalization::Level0,
            1 => fastcdc::v2020::Normalization::Level1,
            2 => fastcdc::v2020::Normalization::Level2,
            _ => fastcdc::v2020::Normalization::Level3,
        }
    }

    /// fastcdc 3.2.1's chunks of `data`, as Ordin records them.
    fn theirs(data: &[u8], p: &ChunkParams) -> Vec<ChunkRef> {
        fastcdc::v2020::StreamCDC::with_level(data, p.minimum(), p.average(), p.maximum(), level(p))
            .map(|c| {
                let c = c.unwrap();
                ChunkRef {
                    digest: Digest::blake3(&c.data),
                    length: c.length as u64,
                }
            })
            .collect()
    }

    /// Chunks `reader` and collects what the sink was given.
    fn chunked(reader: impl Read, p: &ChunkParams) -> io::Result<(ChunkedFile, Vec<u8>)> {
        let mut given = Vec::new();
        let file = chunk_file(reader, p, |chunk, bytes| {
            assert_eq!(chunk.length, bytes.len() as u64);
            assert_eq!(chunk.digest, Digest::blake3(bytes));
            given.extend_from_slice(bytes);
            Ok(())
        })?;
        Ok((file, given))
    }

    /// A reader that gives its data in the pieces it's told, and the
    /// results it's told in between.
    struct Scripted {
        data: VecDeque<u8>,
        steps: VecDeque<Step>,
        reads: usize,
    }

    enum Step {
        Give(usize),
        Fail(ErrorKind),
        /// Claims to have read more than the buffer holds.
        OverClaim,
        /// Says the data has ended, though it hasn't.
        End,
    }

    impl Scripted {
        fn new(data: &[u8], steps: Vec<Step>) -> Self {
            Self {
                data: data.iter().copied().collect(),
                steps: steps.into(),
                reads: 0,
            }
        }
    }

    impl Read for Scripted {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.reads += 1;
            let want = match self.steps.pop_front() {
                Some(Step::Give(n)) => n,
                Some(Step::Fail(kind)) => return Err(kind.into()),
                Some(Step::OverClaim) => return Ok(buf.len() + 1),
                Some(Step::End) => return Ok(0),
                None => usize::MAX,
            };
            let n = want.min(buf.len()).min(self.data.len());
            for (slot, byte) in buf.iter_mut().zip(self.data.drain(..n)) {
                *slot = byte;
            }
            Ok(n)
        }
    }

    #[test]
    fn a_file_under_the_threshold_is_one_chunk() {
        let p = small(512, 1);
        for len in [0, 1, 300, 511] {
            let data = noise(3, len);
            let (file, given) = chunked(&data[..], &p).unwrap();
            assert_eq!(given, data);
            assert_eq!(*file.digests(), file_digests(&data[..]).unwrap());
            assert_eq!(
                file.chunks(),
                [ChunkRef {
                    digest: Digest::blake3(&data),
                    length: len as u64
                }]
            );
            assert_eq!(file.index_entry(), None);
        }
    }

    #[test]
    fn a_file_at_the_threshold_is_cut_and_listed() {
        let p = small(512, 1);
        for len in [512, 513, 1500, 20_000] {
            let data = noise(5, len);
            let (file, given) = chunked(&data[..], &p).unwrap();
            assert_eq!(given, data);
            assert_eq!(*file.digests(), file_digests(&data[..]).unwrap());
            assert_eq!(file.chunks(), theirs(&data, &p));
            let entry = file.index_entry().unwrap();
            assert_eq!(entry.content(), Digest::blake3(&data));
            assert_eq!(entry.chunks(), file.chunks());
        }
        // Cut, not just listed: a file this long has many chunks.
        let (file, _) = chunked(&noise(5, 20_000)[..], &p).unwrap();
        assert!(file.chunks().len() > 20);
    }

    #[test]
    fn chunks_match_fastcdc_at_every_level() {
        for level in 0..=3 {
            let p = small(64, level);
            for seed in 1..60 {
                let data = noise(seed, 100 * seed as usize);
                let (file, _) = chunked(&data[..], &p).unwrap();
                assert_eq!(file.chunks(), theirs(&data, &p), "{p}, seed {seed}");
            }
        }
    }

    /// The default settings' chunk lengths for `noise(0x0bd1, 9_449_000)`.
    const DEFAULT_VECTOR: [u64; 9] = [
        1_108_502, 1_475_257, 1_429_091, 544_947, 1_118_260, 2_498_120, 381_132, 490_558, 403_133,
    ];

    #[test]
    fn the_default_settings_cut_as_recorded() {
        let data = noise(0x0bd1, 9_449_000);
        let (file, _) = chunked(&data[..], &ChunkParams::DEFAULT).unwrap();
        let lengths: Vec<u64> = file.chunks().iter().map(|c| c.length).collect();
        assert_eq!(lengths, DEFAULT_VECTOR);
        assert_eq!(file.chunks(), theirs(&data, &ChunkParams::DEFAULT));
        // Each chunk holds the bytes at its offset.
        let entry = file.index_entry().unwrap();
        for (offset, chunk) in entry.offsets() {
            let start = offset as usize;
            let bytes = &data[start..start + chunk.length as usize];
            assert_eq!(chunk.digest, Digest::blake3(bytes));
        }
    }

    #[test]
    fn the_default_threshold_is_one_mebibyte() {
        let p = ChunkParams::DEFAULT;
        let under = noise(9, 1_048_575);
        let (file, _) = chunked(&under[..], &p).unwrap();
        assert_eq!(file.chunks().len(), 1);
        assert_eq!(file.index_entry(), None);
        let at = noise(9, 1_048_576);
        let (file, _) = chunked(&at[..], &p).unwrap();
        assert!(file.index_entry().is_some());
        assert_eq!(file.chunks(), theirs(&at, &p));
    }

    #[test]
    fn interrupted_reads_are_retried() {
        let p = small(64, 1);
        let data = noise(11, 3000);
        let steps = vec![
            Step::Fail(ErrorKind::Interrupted),
            Step::Give(10),
            Step::Fail(ErrorKind::Interrupted),
        ];
        let (file, given) = chunked(Scripted::new(&data, steps), &p).unwrap();
        assert_eq!(given, data);
        assert_eq!(file.chunks(), theirs(&data, &p));
    }

    #[test]
    fn read_errors_are_returned() {
        let p = small(64, 1);
        let data = noise(11, 3000);
        for steps in [
            vec![Step::Fail(ErrorKind::PermissionDenied)],
            vec![
                Step::Give(1024),
                Step::Give(500),
                Step::Fail(ErrorKind::PermissionDenied),
            ],
        ] {
            let error = chunked(Scripted::new(&data, steps), &p).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::PermissionDenied);
        }
    }

    #[test]
    fn a_reader_claiming_too_much_is_refused() {
        let p = small(64, 1);
        let data = noise(11, 3000);
        for steps in [
            vec![Step::OverClaim],
            vec![Step::Give(1500), Step::OverClaim],
        ] {
            let error = chunked(Scripted::new(&data, steps), &p).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidData);
        }
    }

    #[test]
    fn a_reader_that_ended_is_not_read_again() {
        // The reader says it has ended after 700 bytes, then would give
        // more. Only the 700 bytes are the file.
        let p = small(64, 1);
        let data = noise(13, 3000);
        let mut reader = Scripted::new(&data, vec![Step::Give(700), Step::End]);
        let (file, given) = chunked(&mut reader, &p).unwrap();
        assert_eq!(given, data[..700]);
        assert_eq!(file.chunks(), theirs(&data[..700], &p));
        assert_eq!(reader.reads, 2);
    }

    #[test]
    fn a_full_buffer_is_cut_without_waiting_for_the_end() {
        // The first fill stops when the buffer is full, so a file exactly
        // one buffer long needs a read that finds the end.
        let p = small(64, 1);
        let data = noise(17, 1024);
        let mut reader = Scripted::new(&data, vec![]);
        let (file, _) = chunked(&mut reader, &p).unwrap();
        assert_eq!(file.chunks(), theirs(&data, &p));
        assert!(reader.reads >= 2);
    }

    #[test]
    fn sink_errors_stop_the_chunking() {
        let p = small(64, 1);
        let data = noise(19, 5000);
        let mut calls = 0;
        let error = chunk_file(&data[..], &p, |_, _| {
            calls += 1;
            if calls == 2 {
                return Err(io::Error::other("disk full"));
            }
            Ok(())
        })
        .unwrap_err();
        assert_eq!(error.to_string(), "disk full");
        assert_eq!(calls, 2);
        // A small file's only chunk goes to the sink too.
        let error = chunk_file(&data[..10], &p, |_, _| Err(io::Error::other("no")));
        assert_eq!(error.unwrap_err().to_string(), "no");
    }

    fn params() -> impl Strategy<Value = ChunkParams> {
        (6u32..=8, 8u32..=10, 10u32..=12, 0u64..=3, any::<u64>()).prop_map(
            |(min_bits, average_bits, max_bits, level, threshold)| {
                let minimum = 1u64 << min_bits;
                let maximum = 1u64 << max_bits;
                let whole_below = minimum + threshold % (maximum - minimum + 1);
                ChunkParams::new(minimum, 1 << average_bits, maximum, whole_below, level).unwrap()
            },
        )
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn reads_of_any_size_give_the_same_chunks(
            p in params(),
            seed in any::<u64>(),
            len in 0usize..12_000,
            pieces in prop::collection::vec(1usize..3000, 0..20),
        ) {
            let data = noise(seed, len);
            let whole = chunked(&data[..], &p).unwrap();
            let steps = pieces.into_iter().map(Step::Give).collect();
            let split = chunked(Scripted::new(&data, steps), &p).unwrap();
            prop_assert_eq!(&split, &whole);
            if len >= p.whole_below() as usize {
                prop_assert_eq!(whole.0.chunks(), &theirs(&data, &p)[..]);
            }
        }

        #[test]
        fn rechunking_reproduces_the_index(
            p in params(),
            files in prop::collection::vec((any::<u64>(), 0usize..8000), 0..12),
        ) {
            // Pack: cut every file and list the large ones.
            let mut entries = BTreeMap::new();
            let mut sizes = Vec::new();
            for (seed, len) in &files {
                let data = noise(*seed, *len);
                let (file, _) = chunked(&data[..], &p).unwrap();
                sizes.push((file.digests().content, file.digests().size, data));
                if let Some(entry) = file.index_entry() {
                    entries.insert(entry.content(), entry);
                }
            }
            let index = ChunkIndex::new(p, entries.into_values().collect()).unwrap();
            let bytes = index.to_canonical_bytes().unwrap();
            let (read, digest) = ChunkIndex::from_canonical_bytes(&bytes).unwrap();
            prop_assert_eq!(digest, Digest::blake3(&bytes));
            prop_assert_eq!(read.chunking(), &p);
            // Verify: cutting each file again with the recorded settings
            // gives exactly the chunks the index says to fetch.
            for (content, size, data) in sizes {
                let (again, _) = chunked(&data[..], read.chunking()).unwrap();
                prop_assert_eq!(read.chunks_of(&content, size).unwrap(), again.chunks());
            }
        }
    }
}
