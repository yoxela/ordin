// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Recipe parsing (ORD-121). Any text either reads as a recipe, the same
//! one every time, or is refused at a line and column inside it with a
//! one-line message.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    match ordin_recipe::parse(text) {
        Ok(recipe) => assert_eq!(ordin_recipe::parse(text).ok(), Some(recipe)),
        Err(e) => {
            let lines = text.matches('\n').count() + 1;
            assert!((1..=lines).contains(&e.line), "line {} of {lines}", e.line);
            assert!(e.column >= 1, "column {}", e.column);
            assert!(!e.message.contains('\n'), "{:?}", e.message);
        }
    }
});
