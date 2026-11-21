// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Reading what a package needs from an ELF file (ORD-112). Any bytes are
//! read or refused, never a panic, and reading them from memory or through
//! a file cache, as `ordin pack` does, gives the same answer.

#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use object::read::ReadCache;
use ordin_pack::elf;

fuzz_target!(|data: &[u8]| {
    let direct = elf::inspect(data);
    let cache = ReadCache::new(Cursor::new(data));
    let cached = elf::inspect(&cache);
    assert_eq!(direct, cached, "the same bytes read two ways");
    if let Ok(Some(info)) = direct {
        assert!(info.needed.len() <= elf::MAX_NEEDED);
        assert!(info.needs.len() <= elf::MAX_VERSIONS);
        assert!(info.defines.len() <= elf::MAX_VERSIONS);
    }
});
