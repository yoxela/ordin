// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! TEMPORARY (ORD-011): crashes on every input, to prove once that the
//! nightly fuzz job opens a `fuzz-crash` issue naming only the target,
//! keeps the input as an artifact and fails. Removed before the merge.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    panic!("crash on purpose ({} bytes)", data.len());
});
