// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Manifest parsing (ORD-013). Signed bytes either are refused, or encode
//! back to exactly themselves with the same identity. Lenient JSON either
//! is refused, or gives a manifest whose canonical bytes read back as an
//! equal manifest.

#![no_main]

use libfuzzer_sys::fuzz_target;
use ordin_manifest::Manifest;

fuzz_target!(|data: &[u8]| {
    if let Ok((manifest, digest)) = Manifest::from_signed_bytes(data) {
        match manifest.to_canonical_bytes() {
            Ok(bytes) => assert_eq!(bytes, data, "a signed manifest encodes to itself"),
            Err(e) => panic!("a manifest that was read can't be encoded: {e}"),
        }
        assert_eq!(manifest.digest().ok(), Some(digest));
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(manifest) = Manifest::from_json(text) {
        let bytes = match manifest.to_canonical_bytes() {
            Ok(bytes) => bytes,
            Err(e) => panic!("a manifest that was read can't be encoded: {e}"),
        };
        match Manifest::from_signed_bytes(&bytes) {
            Ok((again, _)) => assert_eq!(again, manifest),
            Err(e) => panic!("canonical bytes don't read back: {e}"),
        }
    }
});
