// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Chunk index parsing (ORD-103). Bytes either are refused, or encode back
//! to exactly themselves with the same identity, and every listed file's
//! chunks can be found again.

#![no_main]

use libfuzzer_sys::fuzz_target;
use ordin_tree::chunk::ChunkIndex;

fuzz_target!(|data: &[u8]| {
    if let Ok((index, digest)) = ChunkIndex::from_canonical_bytes(data) {
        match index.to_canonical_bytes() {
            Ok(bytes) => assert_eq!(bytes, data, "an index encodes to itself"),
            Err(e) => panic!("an index that was read can't be encoded: {e}"),
        }
        assert_eq!(index.digest().ok(), Some(digest));
        for file in index.files() {
            let chunks = index.chunks_of(&file.content(), file.size());
            assert_eq!(chunks.ok().as_deref(), Some(file.chunks()));
        }
    }
});
