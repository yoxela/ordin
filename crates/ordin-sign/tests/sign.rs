// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Signing packages and reading signatures and public key files (ORD-140).

#[cfg(test)]
mod sign {
    use ordin_core::{Algorithm, Digest};
    use ordin_sign::{
        Error, MAX_COMMENT, MAX_KEY_FILE_SIZE, MAX_SIGNATURE_SIZE, PublicKey, PublicKeyFile,
        SecretKey, SecretKeyFile, Signature, message,
    };
    use proptest::prelude::*;

    /// A fixed key: RFC 8032's first test key, from a clear key file.
    fn fixed() -> SecretKey {
        let file = r#"{"key":"ed25519:d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","ordin-secret-key":1,"secret":"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"}"#;
        SecretKeyFile::from_bytes(file.as_bytes())
            .unwrap()
            .open(None)
            .unwrap()
    }

    fn package() -> Digest {
        Digest::blake3(b"a manifest")
    }

    fn signed() -> String {
        String::from_utf8(fixed().sign(&package()).unwrap().to_bytes()).unwrap()
    }

    fn refused(text: &str) -> Error {
        Signature::from_bytes(text.as_bytes()).unwrap_err()
    }

    #[test]
    fn a_signature_is_written_as_documented() {
        insta::assert_snapshot!(signed());
        assert_eq!(
            message(&package()),
            format!("ordin-signature 1 package {}", package())
        );
    }

    #[test]
    fn a_signature_reads_back_and_names_its_key_and_package() {
        let key = SecretKey::generate().unwrap();
        let signature = key.sign(&package()).unwrap();
        let read = Signature::from_bytes(&signature.to_bytes()).unwrap();
        assert_eq!(read, signature);
        assert_eq!(read.key(), key.public_key());
        assert_eq!(read.package(), package());
        assert_ne!(
            SecretKey::generate().unwrap().public_key(),
            key.public_key()
        );
    }

    #[test]
    fn only_blake3_identities_are_signed() {
        let sha = Digest::new(Algorithm::Sha256, [1; 32]);
        assert_eq!(
            fixed().sign(&sha).unwrap_err(),
            Error::NotBlake3(sha.to_string())
        );
        let text = signed().replacen(&package().to_string(), &sha.to_string(), 1);
        assert_eq!(refused(&text), Error::NotBlake3(sha.to_string()));
    }

    #[test]
    fn every_changed_byte_is_refused() {
        let good = signed();
        for at in 0..good.len() {
            for flip in [1u8, 0x20, 0x80] {
                let mut bytes = good.clone().into_bytes();
                bytes[at] ^= flip;
                assert!(Signature::from_bytes(&bytes).is_err(), "byte {at} ^ {flip}");
            }
        }
    }

    #[test]
    fn a_signature_for_another_package_or_by_another_key_is_refused() {
        let good = signed();
        let other = Digest::blake3(b"another manifest");
        let text = good.replacen(&package().to_string(), &other.to_string(), 1);
        let key = fixed().public_key().to_string();
        assert_eq!(refused(&text), Error::BadSignature { key: key.clone() });
        let someone = SecretKey::generate().unwrap().public_key().to_string();
        let text = good.replacen(&key, &someone, 1);
        assert_eq!(refused(&text), Error::BadSignature { key: someone });
    }

    #[test]
    fn a_signature_is_exactly_its_format() {
        let good = signed();
        let malformed = |t: &str| match refused(t) {
            Error::Malformed { reason, .. } => reason,
            other => panic!("{t}: {other}"),
        };
        assert!(malformed(&good.replacen(":", ": ", 1)).contains("canonical"));
        assert!(malformed(&good.replacen("{", "{\"x\":1,", 1)).contains("unknown field \"x\""));
        assert!(
            malformed(&good.replacen("\"ordin-signature\":1,", "", 1))
                .contains("ordin-signature is missing")
        );
        assert!(malformed("[]").contains("an array, not an object"));
        assert!(malformed("{").contains("EOF"));
        assert!(malformed("\u{0}\u{ff}").contains("expected value"));
        assert!(matches!(
            Signature::from_bytes(b"\xff").unwrap_err(),
            Error::Malformed { reason, .. } if reason == "it isn't UTF-8"
        ));
        let sig_start = good.find("\"signature\":\"").unwrap() + 13;
        let short = format!("{}{}", &good[..sig_start], &good[sig_start + 2..]);
        assert!(malformed(&short).contains("128 lowercase hex"));
        let numeric = format!("{}1}}", &good[..sig_start - 1]);
        assert!(malformed(&numeric).contains("signature is an integer, not a string"));
        assert!(
            malformed(&good.replacen("\"package\":\"", "\"package\":\"x", 1)).contains("package:")
        );
        assert!(
            malformed(&good.replacen("\"key\":\"ed25519:", "\"key\":\"ed25519:x", 1))
                .contains("64 lowercase hex")
        );
        assert!(malformed(r#"{"key":"x","ordin-signature":1}"#).contains("isn't ed25519:"));
        assert!(malformed(r#"{"ordin-signature":1}"#).contains("key is missing"));
        assert_eq!(
            refused(r#"{"ordin-signature":"1","x":2}"#),
            Error::UnknownFormat {
                what: "a signature",
                version: "\"1\"".into()
            }
        );
        // Exactly the limit is read, and refused for what it holds.
        assert!(matches!(
            Signature::from_bytes(&vec![b' '; MAX_SIGNATURE_SIZE]).unwrap_err(),
            Error::Malformed { .. }
        ));
        assert_eq!(
            Signature::from_bytes(&vec![b' '; MAX_SIGNATURE_SIZE + 1]).unwrap_err(),
            Error::TooLarge {
                what: "a signature",
                max: MAX_SIGNATURE_SIZE,
                len: MAX_SIGNATURE_SIZE + 1
            }
        );
    }

    #[test]
    fn weak_and_impossible_keys_are_refused() {
        // The identity point, of small order: every signature would verify.
        let weak = format!("ed25519:01{}", "00".repeat(31));
        assert_eq!(weak.parse::<PublicKey>().unwrap_err(), Error::BadKey(weak));
        // Not every 32 bytes are a point on the curve.
        let refused: Vec<u8> = (0..=255u8)
            .filter(|n| PublicKey::from_bytes(&[*n; 32]).is_err())
            .collect();
        assert!(!refused.is_empty());
        for text in [
            "ed25519:",
            "Ed25519:00",
            &format!("ed25519:{}", "AA".repeat(32)),
        ] {
            assert!(
                matches!(
                    text.parse::<PublicKey>().unwrap_err(),
                    Error::Malformed { .. }
                ),
                "{text}"
            );
        }
    }

    #[test]
    fn keys_show_sort_and_compare_by_their_bytes() {
        let a = fixed().public_key();
        let b = SecretKey::generate().unwrap().public_key();
        assert_eq!(a.to_string().parse::<PublicKey>().unwrap(), a);
        assert_eq!(format!("{a:?}"), format!("PublicKey({a})"));
        assert_eq!(a.cmp(&b), a.to_bytes().cmp(&b.to_bytes()));
        assert_eq!(a.partial_cmp(&b), Some(a.to_string().cmp(&b.to_string())));
        assert_eq!(PublicKey::from_bytes(&a.to_bytes()).unwrap(), a);
    }

    fn public_file(comment: &str) -> String {
        PublicKeyFile::new(fixed().public_key(), comment)
            .unwrap()
            .to_text()
    }

    #[test]
    fn a_public_key_file_is_one_line() {
        let hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        assert_eq!(public_file(""), format!("ordin-ed25519 {hex}\n"));
        assert_eq!(
            public_file("packager key"),
            format!("ordin-ed25519 {hex} packager key\n")
        );
        for comment in ["", "packager key", "ünï"] {
            let text = public_file(comment);
            let read = PublicKeyFile::from_bytes(text.as_bytes()).unwrap();
            assert_eq!(read.comment, comment);
            assert_eq!(read.key, fixed().public_key());
        }
    }

    #[test]
    fn a_public_key_file_is_exactly_its_format() {
        let key = fixed().public_key();
        let good = public_file("x");
        let refused = |t: &str| {
            PublicKeyFile::from_bytes(t.as_bytes())
                .unwrap_err()
                .to_string()
        };
        assert!(refused(good.trim_end()).contains("one line"));
        assert!(refused(&format!("{good}{good}")).contains("one line"));
        assert!(
            refused(&good.replacen("ordin-ed25519 ", "ordin-ed25519\t", 1))
                .contains("starts with ordin-ed25519 and a space")
        );
        assert!(refused(&good.replacen("ordin-ed25519", "ssh-ed25519", 1)).contains("starts with"));
        assert!(refused(&good.replacen(" x", "  x", 1)).contains("start or end with a space"));
        assert!(refused(&good.replacen(" x", " x ", 1)).contains("start or end with a space"));
        assert!(refused(&good.replacen(" x", " ", 1)).contains("isn't written as Ordin writes it"));
        assert!(
            refused(&good.replacen("ordin-ed25519 d", "ordin-ed25519 D", 1))
                .contains("64 lowercase hex")
        );
        assert!(refused(&good.replacen(" x", " a\u{7}", 1)).contains("control characters"));
        assert!(refused("\u{ff}\n").contains("starts with ordin-ed25519"));
        assert!(
            matches!(PublicKeyFile::from_bytes(b"\xff\n").unwrap_err(), Error::Malformed { reason, .. } if reason == "it isn't UTF-8")
        );
        let long = "c".repeat(MAX_COMMENT);
        assert!(PublicKeyFile::new(key, &long).is_ok());
        assert!(
            PublicKeyFile::new(key, &format!("{long}c"))
                .unwrap_err()
                .to_string()
                .contains("at most 256")
        );
        assert!(matches!(
            PublicKeyFile::from_bytes(&vec![b'x'; MAX_KEY_FILE_SIZE]).unwrap_err(),
            Error::Malformed { .. }
        ));
        assert_eq!(
            PublicKeyFile::from_bytes(&vec![b'x'; MAX_KEY_FILE_SIZE + 1]).unwrap_err(),
            Error::TooLarge {
                what: "a public key file",
                max: MAX_KEY_FILE_SIZE,
                len: MAX_KEY_FILE_SIZE + 1
            }
        );
    }

    #[test]
    fn errors_say_what_is_wrong() {
        let shown: Vec<String> = [
            Error::NeedsPassphrase,
            Error::NotEncrypted,
            Error::WrongPassphrase,
            Error::EmptyPassphrase,
            Error::KeyMismatch("ed25519:00".into()),
            Error::Random("none".into()),
            Error::Kdf("no".into()),
        ]
        .iter()
        .map(ToString::to_string)
        .collect();
        assert_eq!(
            shown,
            [
                "the secret key is encrypted; a passphrase is needed",
                "the secret key isn't encrypted, so it takes no passphrase",
                "the passphrase is wrong, or the secret key file was changed",
                "a passphrase can't be empty",
                "the secret key isn't the public key ed25519:00 its file records",
                "no random bytes from the operating system: none",
                "deriving a key from the passphrase failed: no"
            ]
        );
    }

    proptest! {
        #[test]
        fn any_package_is_signed_and_reads_back(manifest in any::<Vec<u8>>()) {
            let secret = SecretKey::generate().unwrap();
            let package = Digest::blake3(&manifest);
            let signature = secret.sign(&package).unwrap();
            let read = Signature::from_bytes(&signature.to_bytes()).unwrap();
            prop_assert_eq!(read.package(), package);
            prop_assert_eq!(read, signature);
        }

        #[test]
        fn any_bytes_are_read_or_refused(bytes in prop::collection::vec(any::<u8>(), 0..600)) {
            let _ = Signature::from_bytes(&bytes);
            let _ = PublicKeyFile::from_bytes(&bytes);
            let _ = SecretKeyFile::from_bytes(&bytes);
        }
    }
}
