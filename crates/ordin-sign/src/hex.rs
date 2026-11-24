// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Lowercase hex, read strictly.

const DIGITS: &[u8; 16] = b"0123456789abcdef";

/// `bytes` as lowercase hex.
#[must_use]
pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        for nibble in [b >> 4, b & 0xf] {
            out.push(char::from(DIGITS[usize::from(nibble)]));
        }
    }
    out
}

fn value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

/// Exactly `N` bytes from `2 × N` lowercase hex digits.
#[must_use]
pub(crate) fn decode<const N: usize>(text: &str) -> Option<[u8; N]> {
    let digits = text.as_bytes();
    if digits.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    let (pairs, _) = digits.as_chunks::<2>();
    for (byte, [high, low]) in out.iter_mut().zip(pairs) {
        *byte = 16 * value(*high)? + value(*low)?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips_and_is_strict() {
        let all: Vec<u8> = (0..=255).collect();
        let text = encode(&all);
        assert_eq!(&text[..8], "00010203");
        assert_eq!(&text[text.len() - 4..], "feff");
        assert_eq!(decode::<256>(&text).map(|b| b.to_vec()), Some(all));
        assert_eq!(decode::<2>("0aF0"), None);
        assert_eq!(decode::<2>("0a f"), None);
        assert_eq!(decode::<2>("0af"), None);
        assert_eq!(decode::<2>("0af00"), None);
        assert_eq!(decode::<1>("g0"), None);
        assert_eq!(decode::<1>("0g"), None);
        assert_eq!(decode::<1>("/0"), None);
        assert_eq!(decode::<1>(":0"), None);
        assert_eq!(decode::<1>("`0"), None);
        assert_eq!(decode::<1>("9f"), Some([0x9f]));
        assert_eq!(decode::<0>(""), Some([]));
    }
}
