// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Version parsing (ORD-011). Any input either fails to parse or gives a
//! version that is equal to itself, survives being shown and read back
//! unchanged, and has a compatible bound above it. The semver and text
//! comparison entry points must not panic on any input either.

#![no_main]

use std::cmp::Ordering;

use libfuzzer_sys::fuzz_target;
use ordin_version::{Version, compare_text, normalize_semver};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = normalize_semver(text);
    // Split on a character boundary near the middle.
    let mid = (0..=text.len() / 2)
        .rev()
        .find(|&i| text.is_char_boundary(i))
        .unwrap_or(0);
    let (left, right) = text.split_at(mid);
    let forward = compare_text(left, right);
    assert_eq!(forward, compare_text(right, left).reverse());

    let Ok(v) = text.parse::<Version>() else {
        return;
    };
    assert_eq!(v.cmp(&v), Ordering::Equal);
    let shown = v.to_string();
    let again: Version = match shown.parse() {
        Ok(again) => again,
        Err(e) => panic!("{shown:?} (from {text:?}) doesn't parse back: {e}"),
    };
    assert_eq!(again, v);
    assert_eq!(again.to_string(), shown);
    let bound = v.compatible_bound();
    assert!(bound > v, "{bound} isn't above {v}");
    assert!(v.is_compatible_with(&v));
});
