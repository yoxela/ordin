// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! File digests against `fsverity digest`, against a separate whole-file
//! implementation of the same tree, and through readers that misbehave.
//!
//! The vectors are the output of fsverity-utils 1.6. To make one again:
//!
//! ```text
//! python3 -c 'import sys; n = int(sys.argv[1]); sys.stdout.buffer.write((bytes(range(251)) * (n // 251 + 1))[:n])' SIZE > file
//! fsverity digest --compact file
//! ```
//!
//! For the all-zero vectors, use `head -c SIZE /dev/zero > file`.

#[cfg(test)]
mod digests {
    use std::collections::VecDeque;
    use std::io::{self, ErrorKind, Read};

    use ordin_core::Digest;
    use ordin_tree::{FileHasher, file_digests};
    use proptest::prelude::*;
    use sha2::{Digest as _, Sha256};

    const BLOCK: usize = 4096;
    /// How many hashes fit in a block.
    const FANOUT: usize = 128;

    /// Sizes on each edge of the tree's shape: an empty file, one data
    /// block, one full block of hashes, and two full levels of them.
    const PATTERN: [(usize, &str); 13] = [
        (
            0,
            "3d248ca542a24fc62d1c43b916eae5016878e2533c88238480b26128a1f1af95",
        ),
        (
            1,
            "b803429503d95915829b29fdbc8bbad142f3abfd11b1cadf5526582e685c0551",
        ),
        (
            11,
            "462040da44cc96f06cac4fbd5f69d65f600b5cd00b21ef1e33a4bb8869597a5e",
        ),
        (
            BLOCK - 1,
            "5f4953aad672b0188023d6cd6fbce9d09508eb7dad165b6298ce0086bc1e72db",
        ),
        (
            BLOCK,
            "13e9b8848ae484a36acb3f3cac0ceb2f7601e96633d15c92f9bd3dd44e492157",
        ),
        (
            BLOCK + 1,
            "b0d074abef4d544404facfab6ba242f6a8ccbde90f1325cd286f3c8aa8d0f8aa",
        ),
        (
            2 * BLOCK,
            "e48d50c56c4f0178a98a035cb91d66be328eeff78bbddaa35c5ec4cc0d8340c0",
        ),
        (
            FANOUT * BLOCK - 1,
            "9735c4bb231d3222d1e5e23a4004d8b59dd33395d7de390530e15c2572000b47",
        ),
        (
            FANOUT * BLOCK,
            "d82861203d50ae9b60948504a704f35f5118bd229aeb1a22d6dae47b1767c4c4",
        ),
        (
            FANOUT * BLOCK + 1,
            "4dc6905041c9c4ee73e13b53f63f5d289c46da359b664a965ead7f8cc4d799d4",
        ),
        (
            (FANOUT + 1) * BLOCK,
            "dd56ffe5de24c1229fe22d25f91db9e735f6adc921510dcf480094624458c92a",
        ),
        (
            FANOUT * FANOUT * BLOCK,
            "196650e8bd05f8516c0ede56deeb4d1ff2be9809dc2d827261db4a7773957567",
        ),
        (
            FANOUT * FANOUT * BLOCK + 1,
            "acba6554fbff4e8b2fc0361086b9e8ed6afbbd3196ade159c0f3e2bf9ecb2ed1",
        ),
    ];

    /// All zeros, where padding looks exactly like data and every block
    /// of a level is the same.
    const ZEROS: [(usize, &str); 5] = [
        (
            BLOCK - 1,
            "5372beb83c78537c8970c8361e3254119fafdf1763854ecd57d3f0fe2da7c719",
        ),
        (
            BLOCK,
            "babc284ee4ffe7f449377fbf6692715b43aec7bc39c094a95878904d34bac97e",
        ),
        (
            BLOCK + 1,
            "093756e4ea9683329106d4a16982682ed182c14bf076463a9e7f97305cbac743",
        ),
        (
            FANOUT * BLOCK,
            "2d15bd7832895de85aa3d5bdfb57251e27bbec75ff467408340ab3eba858a2e1",
        ),
        (
            FANOUT * BLOCK + 1,
            "e4143a5705610b7ad2eb85482cfc033c7062a89b9faf9118603f592d53fd10e0",
        ),
    ];

    /// `size` bytes counting 0 to 250 from `start`. 251 is prime, so
    /// neighbouring blocks differ.
    fn pattern(size: usize, start: usize) -> Vec<u8> {
        let cycle: Vec<u8> = (0..=250).collect();
        let mut data = cycle.repeat((size + start) / cycle.len() + 1);
        data.drain(..start);
        data.truncate(size);
        data
    }

    fn sha256(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    /// The hash of a block given without its padding.
    fn block_hash(bytes: &[u8]) -> [u8; 32] {
        let mut block = bytes.to_vec();
        block.resize(BLOCK, 0);
        sha256(&block)
    }

    /// The fs-verity digest worked out level by level over the whole
    /// file in memory, sharing no code with the streaming hasher.
    fn whole_file_fsverity(data: &[u8]) -> String {
        let mut level: Vec<[u8; 32]> = data.chunks(BLOCK).map(block_hash).collect();
        while level.len() > 1 {
            level = level
                .chunks(FANOUT)
                .map(|hashes| block_hash(&hashes.concat()))
                .collect();
        }
        let mut descriptor = [0u8; 256];
        descriptor[..3].copy_from_slice(&[1, 1, 12]);
        descriptor[8..16].copy_from_slice(&(data.len() as u64).to_le_bytes());
        if let Some(root) = level.first() {
            descriptor[16..48].copy_from_slice(root);
        }
        let hex: String = sha256(&descriptor)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        format!("sha256:{hex}")
    }

    /// Checks `file_digests` and a one-piece `FileHasher` against `expected`.
    fn check(data: &[u8], expected: &str) {
        let read = file_digests(data).unwrap();
        assert_eq!(read.size, data.len() as u64);
        assert_eq!(read.content, Digest::blake3(data), "size {}", data.len());
        assert_eq!(
            read.fsverity.to_string(),
            format!("sha256:{expected}"),
            "size {}",
            data.len()
        );
        let mut hasher = FileHasher::default();
        hasher.update(data);
        assert_eq!(hasher.finish(), read, "size {}", data.len());
    }

    #[test]
    fn patterned_files_match_fsverity() {
        for (size, expected) in PATTERN {
            check(&pattern(size, 0), expected);
        }
    }

    #[test]
    fn zero_filled_files_match_fsverity() {
        for (size, expected) in ZEROS {
            check(&vec![0; size], expected);
        }
    }

    #[test]
    fn hello_world_matches_composefs() {
        check(
            b"hello world",
            "1e2eaa4202d750a41174ee454970b92c1bc2f925b1e35076d8c7d5f56362ba64",
        );
    }

    #[test]
    fn only_the_size_separates_a_file_from_its_padding() {
        // Both pad to the same block, so the same Merkle root.
        let short = file_digests(&[0u8; BLOCK - 1][..]).unwrap();
        let full = file_digests(&[0u8; BLOCK][..]).unwrap();
        assert_ne!(short.fsverity, full.fsverity);
        // A file of zero bytes isn't a file of one zero byte either.
        let empty = file_digests(&[][..]).unwrap();
        let one = file_digests(&[0u8][..]).unwrap();
        assert_ne!(empty.fsverity, one.fsverity);
    }

    #[test]
    fn the_whole_file_implementation_matches_fsverity() {
        // So that the property test below compares against something
        // known to be right.
        for (size, expected) in PATTERN.into_iter().filter(|(size, _)| *size < 1 << 20) {
            assert_eq!(
                whole_file_fsverity(&pattern(size, 0)),
                format!("sha256:{expected}")
            );
        }
    }

    /// A reader that follows a script, then reports the end of the file.
    struct Script(VecDeque<Step>);

    enum Step {
        Give(&'static [u8]),
        Fail(ErrorKind),
        Claim(usize),
    }

    impl Script {
        fn new(steps: impl IntoIterator<Item = Step>) -> Self {
            Self(steps.into_iter().collect())
        }
    }

    impl Read for Script {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            match self.0.pop_front() {
                None => Ok(0),
                Some(Step::Give(bytes)) => {
                    buffer[..bytes.len()].copy_from_slice(bytes);
                    Ok(bytes.len())
                }
                Some(Step::Fail(kind)) => Err(kind.into()),
                Some(Step::Claim(count)) => Ok(count),
            }
        }
    }

    #[test]
    fn short_and_interrupted_reads_change_nothing() {
        let read = file_digests(Script::new([
            Step::Fail(ErrorKind::Interrupted),
            Step::Give(b"hello"),
            Step::Fail(ErrorKind::Interrupted),
            Step::Give(b" "),
            Step::Give(b"world"),
        ]))
        .unwrap();
        assert_eq!(read, file_digests(&b"hello world"[..]).unwrap());
    }

    #[test]
    fn a_read_error_is_returned() {
        // The script ends after the error, so carrying on past it would
        // look like a clean end of file.
        let error = file_digests(Script::new([
            Step::Give(b"x"),
            Step::Fail(ErrorKind::PermissionDenied),
        ]))
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
    }

    #[test]
    fn a_reader_claiming_too_much_is_refused() {
        let error = file_digests(Script::new([Step::Claim(1 << 30)])).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    fn size() -> impl Strategy<Value = usize> {
        prop_oneof![
            0..3 * BLOCK,
            FANOUT * BLOCK - 2 * BLOCK..FANOUT * BLOCK + 2 * BLOCK,
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn any_split_gives_the_right_digests(
            size in size(),
            start in 0usize..251,
            cuts in prop::collection::vec(any::<prop::sample::Index>(), 0..8),
        ) {
            let data = pattern(size, start);
            let mut cuts: Vec<usize> = cuts.iter().map(|c| c.index(size + 1)).collect();
            cuts.sort_unstable();
            let mut hasher = FileHasher::default();
            let mut from = 0;
            for cut in cuts {
                hasher.update(&data[from..cut]);
                from = cut;
            }
            hasher.update(&data[from..]);
            let digests = hasher.finish();
            prop_assert_eq!(digests.size, size as u64);
            prop_assert_eq!(digests.content, Digest::blake3(&data));
            prop_assert_eq!(digests.fsverity.to_string(), whole_file_fsverity(&data));
        }
    }
}
