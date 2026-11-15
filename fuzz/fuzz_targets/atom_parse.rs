// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Atom and architecture parsing (ORD-010). Any input either fails to parse
//! or gives a value that shows exactly as the input and parses back equal.

#![no_main]

use libfuzzer_sys::fuzz_target;
use ordin_core::{Arch, Atom};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(atom) = text.parse::<Atom>() {
        let shown = atom.to_string();
        assert_eq!(shown, text, "an atom must show exactly as parsed");
        assert_eq!(shown.parse::<Atom>().ok(), Some(atom));
    }
    if let Ok(arch) = text.parse::<Arch>() {
        assert_eq!(arch.as_str(), text);
    }
});
