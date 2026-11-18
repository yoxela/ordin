// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Tree parsing (ORD-101). Bytes either are refused, or encode back to
//! exactly themselves with the same identity.

#![no_main]

use libfuzzer_sys::fuzz_target;
use ordin_tree::Tree;

fuzz_target!(|data: &[u8]| {
    if let Ok((tree, digest)) = Tree::from_canonical_bytes(data) {
        match tree.to_canonical_bytes() {
            Ok(bytes) => assert_eq!(bytes, data, "a tree encodes to itself"),
            Err(e) => panic!("a tree that was read can't be encoded: {e}"),
        }
        assert_eq!(tree.digest().ok(), Some(digest));
        for entry in tree.entries() {
            assert_eq!(tree.get(entry.path.as_str()), Some(entry));
        }
    }
});
