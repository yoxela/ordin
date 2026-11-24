// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Reading secret key files (ORD-140): any bytes are read or refused,
//! never a panic, and what is read writes back byte for byte. A file is
//! only opened when it is in the clear, since opening an encrypted one
//! costs a key derivation.

#![no_main]

use libfuzzer_sys::fuzz_target;
use ordin_sign::SecretKeyFile;

fuzz_target!(|data: &[u8]| {
    if let Ok(file) = SecretKeyFile::from_bytes(data) {
        assert_eq!(file.to_bytes().as_slice(), data, "a key file writes back as read");
        if !file.is_encrypted()
            && let Ok(key) = file.open(None)
        {
            assert_eq!(Some(key.public_key()), Some(file.public_key()));
        }
    }
});
