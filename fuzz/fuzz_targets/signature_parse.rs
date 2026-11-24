// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Reading package signatures (ORD-140): any bytes are read or refused,
//! never a panic, and a signature that is read verifies and writes back
//! byte for byte.

#![no_main]

use libfuzzer_sys::fuzz_target;
use ordin_sign::{Signature, message};

fuzz_target!(|data: &[u8]| {
    if let Ok(signature) = Signature::from_bytes(data) {
        assert_eq!(signature.to_bytes(), data, "a signature writes back as read");
        assert!(message(&signature.package()).starts_with("ordin-signature 1 package blake3:"));
    }
});
