// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! `security.capability` values (ORD-110). Bytes either are refused, or
//! give capabilities a tree can record.

#![no_main]

use libfuzzer_sys::fuzz_target;
use ordin_tree::Capabilities;

fuzz_target!(|data: &[u8]| {
    if let Ok(capabilities) = Capabilities::from_xattr(data) {
        assert!(!capabilities.is_empty(), "an accepted value names something");
    }
});
