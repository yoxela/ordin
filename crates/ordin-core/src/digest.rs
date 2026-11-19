// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Digests: the identity of every Ordin object.

use core::fmt;
use core::str::FromStr;

use crate::error::Error;

/// A digest algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Algorithm {
    /// BLAKE3, 256 bits: the identity of every Ordin object.
    Blake3,
    /// SHA-256: only for things outside tools produce (attestations, OCI
    /// descriptors) and for fs-verity.
    Sha256,
}

impl Algorithm {
    /// The algorithm's prefix: `blake3` or `sha256`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Blake3 => "blake3",
            Self::Sha256 => "sha256",
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A 256-bit digest and its algorithm, written `blake3:<64 lowercase hex
/// digits>` or `sha256:<…>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest {
    algorithm: Algorithm,
    bytes: [u8; 32],
}

impl Digest {
    /// A digest from its parts.
    #[must_use]
    pub fn new(algorithm: Algorithm, bytes: [u8; 32]) -> Self {
        Self { algorithm, bytes }
    }

    /// The BLAKE3 digest of `data`.
    #[must_use]
    pub fn blake3(data: &[u8]) -> Self {
        Self::new(Algorithm::Blake3, *blake3::hash(data).as_bytes())
    }

    /// The algorithm.
    #[must_use]
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// The 32 digest bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

/// A BLAKE3 digest computed piece by piece, for data that doesn't fit in
/// memory at once. The pieces hash exactly as their concatenation does.
#[derive(Debug, Default)]
pub struct Blake3Hasher(blake3::Hasher);

impl Blake3Hasher {
    /// Adds the next piece of the data.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// The digest of everything added.
    #[must_use]
    pub fn finish(self) -> Digest {
        Digest::new(Algorithm::Blake3, *self.0.finalize().as_bytes())
    }
}

impl FromStr for Digest {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Error> {
        let bad = |reason| Error::BadDigest {
            text: text.chars().take(80).collect(),
            reason,
        };
        let (algorithm, hex) = match text.split_once(':') {
            Some(("blake3", hex)) => (Algorithm::Blake3, hex),
            Some(("sha256", hex)) => (Algorithm::Sha256, hex),
            _ => return Err(bad("it must start with 'blake3:' or 'sha256:'")),
        };
        if hex.len() != 64 {
            return Err(bad("it needs exactly 64 hex digits"));
        }
        let digit = |c: u8| match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        };
        let (pairs, _) = hex.as_bytes().as_chunks::<2>();
        let mut bytes = [0u8; 32];
        for (byte, &[high, low]) in bytes.iter_mut().zip(pairs) {
            let (Some(high), Some(low)) = (digit(high), digit(low)) else {
                return Err(bad("hex digits are 0-9 and lowercase a-f"));
            };
            *byte = high * 16 + low;
        }
        Ok(Self::new(algorithm, bytes))
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:", self.algorithm)?;
        for byte in self.bytes {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

crate::serde_str::impl_serde!(Digest);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hasher_gives_the_digest_of_its_pieces_joined() {
        let mut hasher = Blake3Hasher::default();
        hasher.update(b"hello ");
        hasher.update(b"");
        hasher.update(b"world");
        assert_eq!(hasher.finish(), Digest::blake3(b"hello world"));
        assert_eq!(Blake3Hasher::default().finish(), Digest::blake3(b""));
    }

    #[test]
    fn blake3_matches_the_reference_vector() {
        // The BLAKE3 reference test vector for the empty input.
        assert_eq!(
            Digest::blake3(b"").to_string(),
            "blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
        assert_eq!(Digest::blake3(b"a").algorithm(), Algorithm::Blake3);
        assert_ne!(Digest::blake3(b"a"), Digest::blake3(b"b"));
    }

    #[test]
    fn digests_round_trip_through_text() {
        let hex = "00ff10a0".repeat(8);
        for prefix in ["blake3", "sha256"] {
            let text = format!("{prefix}:{hex}");
            let d: Digest = text.parse().unwrap();
            assert_eq!(d.to_string(), text);
            assert_eq!(d.algorithm().as_str(), prefix);
            assert_eq!(d.algorithm().to_string(), prefix);
            assert_eq!(&d.bytes()[..4], &[0x00, 0xff, 0x10, 0xa0]);
        }
    }

    #[test]
    fn bad_digests_say_why() {
        let reason = |text: &str| match text.parse::<Digest>() {
            Err(Error::BadDigest { reason, .. }) => reason,
            other => panic!("{text}: {other:?}"),
        };
        let hex = "a".repeat(64);
        assert!(reason(&format!("md5:{hex}")).contains("'blake3:' or 'sha256:'"));
        assert!(reason(&hex).contains("'blake3:' or 'sha256:'"));
        assert!(reason(&format!("BLAKE3:{hex}")).contains("'blake3:'"));
        assert!(reason("blake3:abc").contains("exactly 64"));
        assert!(reason(&format!("blake3:{hex}a")).contains("exactly 64"));
        assert!(reason(&format!("blake3:{}", "A".repeat(64))).contains("lowercase"));
        assert!(reason(&format!("blake3:{}g", "a".repeat(63))).contains("lowercase"));
        assert!(reason(&format!("blake3:g{}", "a".repeat(63))).contains("lowercase"));
        // The error never echoes unbounded input.
        match format!("x{}", "a".repeat(500)).parse::<Digest>() {
            Err(Error::BadDigest { text, .. }) => assert_eq!(text.len(), 80),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn digests_order_by_algorithm_then_bytes() {
        let a = Digest::new(Algorithm::Blake3, [1; 32]);
        let b = Digest::new(Algorithm::Blake3, [2; 32]);
        let c = Digest::new(Algorithm::Sha256, [0; 32]);
        assert!(a < b && b < c);
    }
}
