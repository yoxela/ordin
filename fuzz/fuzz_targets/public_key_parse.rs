// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Reading public keys and public key files (ORD-140): any bytes are read
//! or refused, never a panic, and what is read writes back byte for byte.

#![no_main]

use libfuzzer_sys::fuzz_target;
use ordin_sign::{PublicKey, PublicKeyFile};

fuzz_target!(|data: &[u8]| {
    if let Ok(file) = PublicKeyFile::from_bytes(data) {
        assert_eq!(file.to_text().as_bytes(), data, "a key file writes back as read");
    }
    if let Ok(text) = std::str::from_utf8(data)
        && let Ok(key) = text.parse::<PublicKey>()
    {
        assert_eq!(key.to_string(), text, "a key writes back as read");
    }
});
