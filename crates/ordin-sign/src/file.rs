// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Key files: a public key on one line, and a secret key in canonical
//! JSON, encrypted with a passphrase unless asked otherwise.

use std::collections::BTreeMap;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use ordin_core::json::{self, Value};
use zeroize::Zeroizing;

use crate::error::Error;
use crate::hex;
use crate::key::{KEY_PREFIX, PublicKey, SecretKey};

/// The largest key file, in bytes.
pub const MAX_KEY_FILE_SIZE: usize = 4096;

/// The longest comment in a public key file, in characters.
pub const MAX_COMMENT: usize = 256;

/// What a public key file's line starts with.
pub const PUBLIC_KEY_FILE_PREFIX: &str = "ordin-ed25519";

/// The format version's key in a secret key file.
const FORMAT: &str = "ordin-secret-key";

/// The cipher secret key files are encrypted with.
const CIPHER: &str = "xchacha20-poly1305";

/// The function that derives the cipher's key from the passphrase.
const KDF: &str = "argon2id";

const PUBLIC: &str = "a public key file";
const SECRET: &str = "a secret key file";

fn too_large(what: &'static str, len: usize) -> Result<(), Error> {
    if len > MAX_KEY_FILE_SIZE {
        return Err(Error::TooLarge {
            what,
            max: MAX_KEY_FILE_SIZE,
            len,
        });
    }
    Ok(())
}

/// A public key file: `ordin-ed25519`, the key's 64 hex digits and an
/// optional comment, on one line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKeyFile {
    /// The key.
    pub key: PublicKey,
    /// Who or what the key is for. No control characters, at most
    /// [`MAX_COMMENT`] characters, and no space at either end.
    pub comment: String,
}

fn check_comment(comment: &str) -> Result<(), Error> {
    if comment.chars().count() > MAX_COMMENT {
        return Err(Error::malformed(
            PUBLIC,
            format!("a comment is at most {MAX_COMMENT} characters"),
        ));
    }
    if comment.chars().any(char::is_control) {
        return Err(Error::malformed(
            PUBLIC,
            "a comment can't hold control characters",
        ));
    }
    if comment.trim() != comment {
        return Err(Error::malformed(
            PUBLIC,
            "a comment can't start or end with a space",
        ));
    }
    Ok(())
}

impl PublicKeyFile {
    /// A key with a comment.
    ///
    /// # Errors
    ///
    /// The comment is too long, holds a control character, or starts or
    /// ends with a space.
    pub fn new(key: PublicKey, comment: &str) -> Result<Self, Error> {
        check_comment(comment)?;
        Ok(Self {
            key,
            comment: comment.to_owned(),
        })
    }

    /// The file's text: one line, ending with a line break.
    #[must_use]
    pub fn to_text(&self) -> String {
        let hex = hex::encode(&self.key.to_bytes());
        if self.comment.is_empty() {
            format!("{PUBLIC_KEY_FILE_PREFIX} {hex}\n")
        } else {
            format!("{PUBLIC_KEY_FILE_PREFIX} {hex} {}\n", self.comment)
        }
    }

    /// Reads a public key file. The bytes must be exactly what
    /// [`to_text`](Self::to_text) writes.
    ///
    /// # Errors
    ///
    /// The file is too large, isn't one line in the format, or names an
    /// unusable key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        too_large(PUBLIC, bytes.len())?;
        let text =
            std::str::from_utf8(bytes).map_err(|_| Error::malformed(PUBLIC, "it isn't UTF-8"))?;
        let line = text
            .strip_suffix('\n')
            .filter(|line| !line.contains('\n'))
            .ok_or_else(|| Error::malformed(PUBLIC, "it is one line, ending with a line break"))?;
        let rest = line
            .strip_prefix(PUBLIC_KEY_FILE_PREFIX)
            .and_then(|rest| rest.strip_prefix(' '))
            .ok_or_else(|| {
                Error::malformed(
                    PUBLIC,
                    format!("it starts with {PUBLIC_KEY_FILE_PREFIX} and a space"),
                )
            })?;
        let (hex, comment) = rest.split_once(' ').unwrap_or((rest, ""));
        let key: PublicKey = format!("{KEY_PREFIX}{hex}").parse()?;
        let file = Self::new(key, comment)?;
        if file.to_text() != text {
            return Err(Error::malformed(
                PUBLIC,
                "it isn't written as Ordin writes it",
            ));
        }
        Ok(file)
    }
}

/// How the cipher's key is derived from the passphrase: Argon2id with
/// these costs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory, in KiB.
    pub memory: u32,
    /// Passes over the memory.
    pub passes: u32,
    /// Lanes.
    pub lanes: u32,
}

impl KdfParams {
    /// What new key files use: 64 MiB, three passes, one lane, as RFC 9106
    /// recommends where memory is constrained.
    pub const DEFAULT: Self = Self {
        memory: 64 * 1024,
        passes: 3,
        lanes: 1,
    };

    /// The most memory a key file may ask for: 1 GiB.
    pub const MAX_MEMORY: u32 = 1 << 20;

    /// The most passes a key file may ask for.
    pub const MAX_PASSES: u32 = 64;

    /// The most lanes a key file may ask for.
    pub const MAX_LANES: u32 = 16;

    fn check(self) -> Result<Self, Error> {
        let bad = |reason: String| Err(Error::malformed(SECRET, reason));
        if !(1..=Self::MAX_LANES).contains(&self.lanes) {
            return bad(format!("lanes are 1 to {}", Self::MAX_LANES));
        }
        if !(1..=Self::MAX_PASSES).contains(&self.passes) {
            return bad(format!("passes are 1 to {}", Self::MAX_PASSES));
        }
        if !(8 * self.lanes..=Self::MAX_MEMORY).contains(&self.memory) {
            return bad(format!(
                "memory is 8 KiB per lane to {} KiB",
                Self::MAX_MEMORY
            ));
        }
        Ok(self)
    }

    /// The cipher's key for `passphrase` and `salt`.
    fn derive(self, passphrase: &[u8], salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>, Error> {
        let kdf_error = |e: argon2::Error| Error::Kdf(e.to_string());
        let params = argon2::Params::new(self.memory, self.passes, self.lanes, Some(32))
            .map_err(kdf_error)?;
        let argon =
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let mut key = Zeroizing::new([0u8; 32]);
        argon
            .hash_password_into(passphrase, salt, key.as_mut())
            .map_err(kdf_error)?;
        Ok(key)
    }
}

/// The secret, sealed or in the clear.
enum Sealed {
    Clear(Zeroizing<[u8; 32]>),
    Encrypted {
        kdf: KdfParams,
        salt: [u8; 16],
        nonce: [u8; 24],
        secret: [u8; 48],
    },
}

/// A secret key file. It shows its public key and whether it is
/// encrypted, and never its secret.
pub struct SecretKeyFile {
    key: PublicKey,
    sealed: Sealed,
}

impl std::fmt::Debug for SecretKeyFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretKeyFile")
            .field("key", &self.key)
            .field("encrypted", &self.is_encrypted())
            .finish_non_exhaustive()
    }
}

fn s(text: impl ToString) -> Value {
    Value::Str(text.to_string())
}

fn int(n: u32) -> Value {
    Value::Int(i64::from(n))
}

fn random<const N: usize>() -> Result<[u8; N], Error> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|e| Error::Random(e.to_string()))?;
    Ok(bytes)
}

fn field<'a>(map: &'a BTreeMap<String, Value>, name: &str) -> Result<&'a Value, Error> {
    map.get(name)
        .ok_or_else(|| Error::malformed(SECRET, format!("{name} is missing")))
}

fn string<'a>(map: &'a BTreeMap<String, Value>, name: &str) -> Result<&'a str, Error> {
    match field(map, name)? {
        Value::Str(text) => Ok(text),
        other => Err(Error::malformed(
            SECRET,
            format!("{name} is {}, not a string", other.type_name()),
        )),
    }
}

fn number(map: &BTreeMap<String, Value>, name: &str) -> Result<u32, Error> {
    match field(map, name)? {
        Value::Int(n) => u32::try_from(*n)
            .map_err(|_| Error::malformed(SECRET, format!("{name} is out of range"))),
        other => Err(Error::malformed(
            SECRET,
            format!("{name} is {}, not an integer", other.type_name()),
        )),
    }
}

fn hex_field<const N: usize>(map: &BTreeMap<String, Value>, name: &str) -> Result<[u8; N], Error> {
    hex::decode::<N>(string(map, name)?).ok_or_else(|| {
        Error::malformed(
            SECRET,
            format!("{name} isn't {} lowercase hex digits", 2 * N),
        )
    })
}

fn only(map: &BTreeMap<String, Value>, fields: &[&str], what: &str) -> Result<(), Error> {
    match map.keys().find(|k| !fields.contains(&k.as_str())) {
        Some(unknown) => Err(Error::malformed(
            SECRET,
            format!("unknown field {unknown:?} in {what}"),
        )),
        None => Ok(()),
    }
}

impl SecretKeyFile {
    /// Seals a secret key: encrypted with `passphrase`, or in the clear
    /// if there is none. A new random salt and nonce are drawn each time.
    ///
    /// # Errors
    ///
    /// The passphrase is empty, or there are no random bytes.
    pub fn seal(secret: &SecretKey, passphrase: Option<&[u8]>) -> Result<Self, Error> {
        match passphrase {
            None => Self::seal_with(secret, None, KdfParams::DEFAULT, [0; 16], [0; 24]),
            Some(p) => Self::seal_with(secret, Some(p), KdfParams::DEFAULT, random()?, random()?),
        }
    }

    /// Seals with the given costs, salt and nonce.
    pub(crate) fn seal_with(
        secret: &SecretKey,
        passphrase: Option<&[u8]>,
        kdf: KdfParams,
        salt: [u8; 16],
        nonce: [u8; 24],
    ) -> Result<Self, Error> {
        let key = secret.public_key();
        let Some(passphrase) = passphrase else {
            return Ok(Self {
                key,
                sealed: Sealed::Clear(secret.seed()),
            });
        };
        if passphrase.is_empty() {
            return Err(Error::EmptyPassphrase);
        }
        let mut file = Self {
            key,
            sealed: Sealed::Encrypted {
                kdf: kdf.check()?,
                salt,
                nonce,
                secret: [0; 48],
            },
        };
        let cipher = XChaCha20Poly1305::new(&Key::from(*kdf.derive(passphrase, &salt)?));
        let sealed = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: secret.seed().as_slice(),
                    aad: &file.header(),
                },
            )
            .map_err(|_| Error::Kdf("encryption failed".to_owned()))?;
        let bytes = <[u8; 48]>::try_from(sealed.as_slice())
            .map_err(|_| Error::Kdf("the cipher gave an unexpected length".to_owned()))?;
        if let Sealed::Encrypted { secret, .. } = &mut file.sealed {
            *secret = bytes;
        }
        Ok(file)
    }

    /// The public key the file is for.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        self.key
    }

    /// Whether opening it needs a passphrase.
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        matches!(self.sealed, Sealed::Encrypted { .. })
    }

    /// Everything but the secret, as a JSON object.
    fn fields(&self) -> BTreeMap<String, Value> {
        let mut map = BTreeMap::from([
            ("key".to_owned(), s(self.key)),
            (FORMAT.to_owned(), Value::Int(1)),
        ]);
        if let Sealed::Encrypted {
            kdf, salt, nonce, ..
        } = &self.sealed
        {
            map.insert("cipher".to_owned(), s(CIPHER));
            map.insert(
                "kdf".to_owned(),
                Value::Object(BTreeMap::from([
                    ("algorithm".to_owned(), s(KDF)),
                    ("lanes".to_owned(), int(kdf.lanes)),
                    ("memory".to_owned(), int(kdf.memory)),
                    ("passes".to_owned(), int(kdf.passes)),
                    ("salt".to_owned(), s(hex::encode(salt))),
                ])),
            );
            map.insert("nonce".to_owned(), s(hex::encode(nonce)));
        }
        map
    }

    /// What the cipher authenticates besides the secret: every other
    /// field, as canonical JSON, so none can be changed unnoticed.
    fn header(&self) -> Vec<u8> {
        json::canonical(&Value::Object(self.fields())).into_bytes()
    }

    /// The file as canonical JSON (RFC 8785).
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut map = self.fields();
        let secret = match &self.sealed {
            Sealed::Clear(seed) => Zeroizing::new(hex::encode(seed.as_slice())),
            Sealed::Encrypted { secret, .. } => Zeroizing::new(hex::encode(secret)),
        };
        map.insert("secret".to_owned(), s(secret.as_str()));
        let text = Zeroizing::new(json::canonical(&Value::Object(map)));
        Zeroizing::new(text.as_bytes().to_vec())
    }

    /// Reads a secret key file without opening it. The bytes must be
    /// exactly what [`to_bytes`](Self::to_bytes) writes, and the costs it
    /// asks for within [`KdfParams`]' limits. The format version is
    /// checked before any other field.
    ///
    /// # Errors
    ///
    /// The file is too large, isn't canonical JSON in the format, names an
    /// unusable key, or asks for costs beyond the limits.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        too_large(SECRET, bytes.len())?;
        let text =
            std::str::from_utf8(bytes).map_err(|_| Error::malformed(SECRET, "it isn't UTF-8"))?;
        let value = json::parse_bounded(text, 0, 16).map_err(|e| Error::malformed(SECRET, e.0))?;
        let Value::Object(map) = value else {
            return Err(Error::malformed(
                SECRET,
                format!("it is {}, not an object", value.type_name()),
            ));
        };
        match map.get(FORMAT) {
            None => return Err(Error::malformed(SECRET, format!("{FORMAT} is missing"))),
            Some(Value::Int(1)) => {}
            Some(other) => {
                return Err(Error::UnknownFormat {
                    what: SECRET,
                    version: json::canonical(other),
                });
            }
        }
        let key: PublicKey = string(&map, "key")?.parse()?;
        let sealed = if map.contains_key("cipher") {
            only(
                &map,
                &["cipher", "kdf", "key", "nonce", FORMAT, "secret"],
                "the file",
            )?;
            if string(&map, "cipher")? != CIPHER {
                return Err(Error::malformed(SECRET, format!("the cipher is {CIPHER}")));
            }
            let Value::Object(kdf) = field(&map, "kdf")? else {
                return Err(Error::malformed(SECRET, "kdf is an object"));
            };
            only(
                kdf,
                &["algorithm", "lanes", "memory", "passes", "salt"],
                "kdf",
            )?;
            if string(kdf, "algorithm")? != KDF {
                return Err(Error::malformed(SECRET, format!("the kdf is {KDF}")));
            }
            Sealed::Encrypted {
                kdf: KdfParams {
                    memory: number(kdf, "memory")?,
                    passes: number(kdf, "passes")?,
                    lanes: number(kdf, "lanes")?,
                }
                .check()?,
                salt: hex_field(kdf, "salt")?,
                nonce: hex_field(&map, "nonce")?,
                secret: hex_field(&map, "secret")?,
            }
        } else {
            only(&map, &["key", FORMAT, "secret"], "the file")?;
            Sealed::Clear(Zeroizing::new(hex_field(&map, "secret")?))
        };
        let file = Self { key, sealed };
        if file.to_bytes().as_slice() != bytes {
            return Err(Error::malformed(
                SECRET,
                "it isn't canonical JSON (RFC 8785) as Ordin writes it",
            ));
        }
        Ok(file)
    }

    /// Opens the file: decrypts the secret with `passphrase` if it is
    /// encrypted, and checks that it is the public key the file records.
    ///
    /// # Errors
    ///
    /// A passphrase is missing, or given for a file in the clear; the
    /// passphrase is wrong or the file was changed; or the secret isn't
    /// the recorded public key.
    pub fn open(&self, passphrase: Option<&[u8]>) -> Result<SecretKey, Error> {
        let secret = match (&self.sealed, passphrase) {
            (Sealed::Clear(_), Some(_)) => return Err(Error::NotEncrypted),
            (Sealed::Encrypted { .. }, None) => return Err(Error::NeedsPassphrase),
            (Sealed::Clear(seed), None) => SecretKey::from_seed(seed),
            (
                Sealed::Encrypted {
                    kdf,
                    salt,
                    nonce,
                    secret,
                },
                Some(passphrase),
            ) => {
                let cipher = XChaCha20Poly1305::new(&Key::from(*kdf.derive(passphrase, salt)?));
                let seed = Zeroizing::new(
                    cipher
                        .decrypt(
                            &XNonce::from(*nonce),
                            Payload {
                                msg: secret,
                                aad: &self.header(),
                            },
                        )
                        .map_err(|_| Error::WrongPassphrase)?,
                );
                let seed: Zeroizing<[u8; 32]> = Zeroizing::new(
                    seed.as_slice()
                        .try_into()
                        .map_err(|_| Error::WrongPassphrase)?,
                );
                SecretKey::from_seed(&seed)
            }
        };
        if secret.public_key() != self.key {
            return Err(Error::KeyMismatch(self.key.to_string()));
        }
        Ok(secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The cheapest costs, so the tests run quickly.
    const CHEAP: KdfParams = KdfParams {
        memory: 8,
        passes: 1,
        lanes: 1,
    };

    fn key() -> SecretKey {
        SecretKey::from_seed(&[1; 32])
    }

    fn sealed() -> SecretKeyFile {
        SecretKeyFile::seal_with(&key(), Some(b"correct horse"), CHEAP, [2; 16], [3; 24]).unwrap()
    }

    fn text(file: &SecretKeyFile) -> String {
        String::from_utf8(file.to_bytes().to_vec()).unwrap()
    }

    fn refused(text: &str) -> Error {
        SecretKeyFile::from_bytes(text.as_bytes()).unwrap_err()
    }

    #[test]
    fn an_encrypted_file_is_written_as_documented() {
        insta::assert_snapshot!(text(&sealed()));
    }

    #[test]
    fn an_encrypted_file_opens_with_its_passphrase_only() {
        let file = SecretKeyFile::from_bytes(&sealed().to_bytes()).unwrap();
        assert!(file.is_encrypted());
        assert_eq!(file.public_key(), key().public_key());
        let opened = file.open(Some(b"correct horse")).unwrap();
        assert_eq!(*opened.seed(), [1; 32]);
        assert_eq!(
            file.open(Some(b"correct horsf")).unwrap_err(),
            Error::WrongPassphrase
        );
        assert_eq!(file.open(None).unwrap_err(), Error::NeedsPassphrase);
        let shown = format!("{file:?}");
        assert!(shown.contains("encrypted: true"), "{shown}");
        assert!(!shown.contains("0101"), "{shown}");
    }

    #[test]
    fn every_field_is_bound_to_the_secret() {
        let good = text(&sealed());
        let other_key = SecretKey::from_seed(&[9; 32]).public_key().to_string();
        let changes = [
            ("\"salt\":\"0202", "\"salt\":\"1202"),
            ("\"nonce\":\"0303", "\"nonce\":\"1303"),
            ("\"passes\":1", "\"passes\":2"),
            ("\"memory\":8", "\"memory\":16"),
            (&key().public_key().to_string()[..], &other_key[..]),
        ];
        for (from, to) in changes {
            let changed = good.replacen(from, to, 1);
            assert_ne!(changed, good, "{from}");
            let file = SecretKeyFile::from_bytes(changed.as_bytes()).unwrap();
            assert_eq!(
                file.open(Some(b"correct horse")).unwrap_err(),
                Error::WrongPassphrase,
                "{from}"
            );
        }
        // The secret itself.
        let at = good.find("\"secret\":\"").unwrap() + 10;
        let mut changed = good.clone().into_bytes();
        changed[at] = if changed[at] == b'0' { b'1' } else { b'0' };
        let file = SecretKeyFile::from_bytes(&changed).unwrap();
        assert_eq!(
            file.open(Some(b"correct horse")).unwrap_err(),
            Error::WrongPassphrase
        );
    }

    #[test]
    fn a_clear_file_opens_without_a_passphrase() {
        let file = SecretKeyFile::seal(&key(), None).unwrap();
        assert!(!file.is_encrypted());
        let bytes = file.to_bytes();
        let shown = String::from_utf8(bytes.to_vec()).unwrap();
        assert_eq!(
            shown,
            format!(
                r#"{{"key":"{}","ordin-secret-key":1,"secret":"{}"}}"#,
                key().public_key(),
                "01".repeat(32)
            )
        );
        let file = SecretKeyFile::from_bytes(&bytes).unwrap();
        assert_eq!(*file.open(None).unwrap().seed(), [1; 32]);
        assert_eq!(file.open(Some(b"x")).unwrap_err(), Error::NotEncrypted);
        // A secret that isn't the recorded key.
        let other = shown.replacen(&"01".repeat(32), &"02".repeat(32), 1);
        let file = SecretKeyFile::from_bytes(other.as_bytes()).unwrap();
        assert_eq!(
            file.open(None).unwrap_err(),
            Error::KeyMismatch(key().public_key().to_string())
        );
    }

    #[test]
    fn sealing_needs_a_passphrase_with_something_in_it() {
        assert_eq!(
            SecretKeyFile::seal(&key(), Some(b"")).unwrap_err(),
            Error::EmptyPassphrase
        );
        let a = SecretKeyFile::seal(&key(), Some(b"p")).unwrap();
        let b = SecretKeyFile::seal(&key(), Some(b"p")).unwrap();
        assert_ne!(a.to_bytes(), b.to_bytes(), "a new salt and nonce each time");
        assert!(text(&a).contains(r#""memory":65536,"passes":3"#));
        assert_eq!(*a.open(Some(b"p")).unwrap().seed(), [1; 32]);
    }

    #[test]
    fn costs_are_limited() {
        let check = |memory, passes, lanes| {
            KdfParams {
                memory,
                passes,
                lanes,
            }
            .check()
            .is_ok()
        };
        assert!(check(8, 1, 1));
        assert!(check(
            KdfParams::MAX_MEMORY,
            KdfParams::MAX_PASSES,
            KdfParams::MAX_LANES
        ));
        assert!(!check(7, 1, 1));
        assert!(!check(15, 1, 2));
        assert!(check(16, 1, 2));
        assert!(!check(KdfParams::MAX_MEMORY + 1, 1, 1));
        assert!(!check(8, 0, 1));
        assert!(!check(8, KdfParams::MAX_PASSES + 1, 1));
        assert!(!check(8, 1, 0));
        assert!(!check(1 << 20, 1, KdfParams::MAX_LANES + 1));
        let good = text(&sealed());
        for (from, to) in [
            ("\"memory\":8", "\"memory\":1048577"),
            ("\"passes\":1", "\"passes\":0"),
            ("\"lanes\":1", "\"lanes\":17"),
        ] {
            assert!(
                matches!(
                    refused(&good.replacen(from, to, 1)),
                    Error::Malformed { .. }
                ),
                "{to}"
            );
        }
        assert_eq!(
            SecretKeyFile::seal_with(
                &key(),
                Some(b"p"),
                KdfParams { lanes: 0, ..CHEAP },
                [0; 16],
                [0; 24]
            )
            .unwrap_err()
            .to_string(),
            "a secret key file: lanes are 1 to 16"
        );
    }

    #[test]
    fn a_file_must_be_exactly_as_written() {
        let good = text(&sealed());
        let malformed = |t: &str| {
            let e = refused(t);
            assert!(matches!(e, Error::Malformed { .. }), "{t}: {e}");
            e.to_string()
        };
        assert!(malformed(&good.replacen(":", ": ", 1)).contains("canonical"));
        assert!(
            malformed(&good.replacen("argon2id", "argon2i", 1)).contains("the kdf is argon2id")
        );
        assert!(
            malformed(&good.replacen("xchacha20-poly1305", "aes", 1)).contains("the cipher is")
        );
        assert!(
            malformed(&good.replacen("\"algorithm\"", "\"x\":1,\"algorithm\"", 1))
                .contains("unknown field \"x\" in kdf")
        );
        assert!(
            malformed(&good.replacen("\"cipher\"", "\"a\":1,\"cipher\"", 1))
                .contains("unknown field \"a\" in the file")
        );
        assert!(
            malformed(&good.replacen("\"nonce\":\"0303", "\"nonce\":\"03", 1))
                .contains("nonce isn't 48")
        );
        assert!(
            malformed(&good.replacen("\"lanes\":1", "\"lanes\":\"1\"", 1))
                .contains("lanes is a string")
        );
        assert!(
            malformed(&good.replacen("\"lanes\":1", "\"lanes\":-1", 1))
                .contains("lanes is out of range")
        );
        assert!(malformed(&good.replacen("\"lanes\":1,", "", 1)).contains("lanes is missing"));
        assert!(
            malformed(&good.replacen("\"cipher\":\"xchacha20-poly1305\"", "\"cipher\":1", 1))
                .contains("cipher is an integer")
        );
        let kdf_start = good.find("\"kdf\":").unwrap() + 6;
        let kdf_end = good[kdf_start..].find('}').unwrap() + kdf_start + 1;
        let flat = format!("{}1{}", &good[..kdf_start], &good[kdf_end..]);
        assert!(malformed(&flat).contains("kdf is an object"));
        assert!(malformed("[]").contains("not an object"));
        assert!(malformed("{").contains("EOF"));
        assert!(
            matches!(SecretKeyFile::from_bytes(b"\xff").unwrap_err(), Error::Malformed { reason, .. } if reason == "it isn't UTF-8")
        );
        assert!(malformed(r#"{"key":"x"}"#).contains("ordin-secret-key is missing"));
        assert_eq!(
            refused(r#"{"ordin-secret-key":2}"#),
            Error::UnknownFormat {
                what: SECRET,
                version: "2".into()
            }
        );
        let clear = String::from_utf8(
            SecretKeyFile::seal(&key(), None)
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(
            malformed(&clear.replacen("\"key\"", "\"nonce\":\"\",\"key\"", 1))
                .contains("unknown field \"nonce\" in the file")
        );
        // Exactly the limit is read, and refused for what it holds.
        assert!(matches!(
            SecretKeyFile::from_bytes(&vec![b' '; MAX_KEY_FILE_SIZE]).unwrap_err(),
            Error::Malformed { .. }
        ));
        assert_eq!(
            SecretKeyFile::from_bytes(&vec![b' '; MAX_KEY_FILE_SIZE + 1]).unwrap_err(),
            Error::TooLarge {
                what: SECRET,
                max: MAX_KEY_FILE_SIZE,
                len: MAX_KEY_FILE_SIZE + 1
            }
        );
        assert!(matches!(
            refused(&good.replacen("ed25519:", "ed25519:0", 1)),
            Error::Malformed { .. }
        ));
    }

    #[test]
    fn deriving_fails_cleanly_on_costs_argon2_refuses() {
        let e = KdfParams {
            memory: 1,
            passes: 1,
            lanes: 1,
        }
        .derive(b"p", &[0; 16])
        .unwrap_err();
        assert!(matches!(e, Error::Kdf(_)), "{e}");
    }
}
