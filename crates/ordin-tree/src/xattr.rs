// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Extended attributes. A tree records only `user.*` ones: `trusted.*`
//! could point an overlay at another file, `security.*` holds
//! capabilities (recorded on their own) and SELinux labels (which come
//! from policy), and `system.*` holds ACLs.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

/// The most extended attributes on one entry.
pub const XATTRS_MAX: usize = 16;

/// The longest attribute value, in bytes.
pub const XATTR_VALUE_MAX: usize = 4096;

/// The longest attribute name, prefix included (Linux's `XATTR_NAME_MAX`).
pub const XATTR_NAME_MAX: usize = 255;

/// An attribute name: `user.` and 1 or more printable ASCII characters
/// other than space, up to 255 bytes in all.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct XattrName(String);

impl XattrName {
    /// The name, exactly as given.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for XattrName {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        let Some(rest) = text.strip_prefix("user.") else {
            return Err(format!(
                "only user.* extended attributes can be packaged: {text:?}"
            ));
        };
        if rest.is_empty() || text.len() > XATTR_NAME_MAX {
            return Err(format!(
                "an extended attribute name is \"user.\" and 1 to 250 more bytes; {text:?} is {}",
                text.len()
            ));
        }
        match rest.char_indices().find(|&(_, c)| !c.is_ascii_graphic()) {
            Some((at, c)) => Err(format!(
                "an extended attribute name uses printable ASCII without spaces; {c:?} at byte {} isn't allowed",
                at + 5
            )),
            None => Ok(Self(text.to_owned())),
        }
    }
}

impl fmt::Display for XattrName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An entry's extended attributes, by name.
pub type Xattrs = BTreeMap<XattrName, Vec<u8>>;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 (RFC 4648) with padding.
#[must_use]
pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    let (whole, rest) = data.as_chunks::<3>();
    let mut emit = |group: [u8; 3], len: usize| {
        // `+`, not `|`: the bytes don't overlap, so both give the same
        // value, but only `+` has mutations a test can tell apart.
        let n = u32::from(group[0]) * 65536 + u32::from(group[1]) * 256 + u32::from(group[2]);
        for i in 0..4 {
            if i <= len {
                let index = (n >> (18 - 6 * i)) & 63;
                out.push(char::from(ALPHABET[index as usize]));
            } else {
                out.push('=');
            }
        }
    };
    for group in whole {
        emit(*group, 3);
    }
    match rest {
        [a] => emit([*a, 0, 0], 1),
        [a, b] => emit([*a, *b, 0], 2),
        _ => {}
    }
    out
}

/// The value of one base64 character.
fn sextet(c: u8) -> Option<u32> {
    let v = match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    };
    Some(u32::from(v))
}

/// Reads standard padded base64, accepting only the one text
/// [`base64_encode`] gives for the bytes.
///
/// # Errors
///
/// Returns why the text isn't canonical base64.
pub fn base64_decode(text: &str) -> Result<Vec<u8>, String> {
    let bad = || format!("{text:?} isn't canonical base64 (RFC 4648, padded)");
    let (groups, rest) = text.as_bytes().as_chunks::<4>();
    if !rest.is_empty() {
        return Err(bad());
    }
    let mut out = Vec::with_capacity(groups.len() * 3);
    for group in groups {
        let pad = group.iter().rev().take_while(|&&c| c == b'=').count();
        let mut n = 0;
        for &c in &group[..4 - pad] {
            n = n * 64 + sextet(c).ok_or_else(bad)?;
        }
        n <<= 6 * pad;
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        out.extend_from_slice(&bytes[..3usize.saturating_sub(pad)]);
    }
    // Refuses padding anywhere but the end, three '=', and bits set past
    // the end of the data, which would give a second text for the bytes.
    if base64_encode(&out) != text {
        return Err(bad());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_user_attributes() {
        for ok in [
            "user.a",
            "user.mime_type",
            "user.x.y-z",
            &format!("user.{}", "n".repeat(250)),
        ] {
            assert_eq!(ok.parse::<XattrName>().unwrap().as_str(), ok);
            assert_eq!(ok.parse::<XattrName>().unwrap().to_string(), ok);
        }
        for (bad, why) in [
            ("trusted.overlay.redirect", "only user.*"),
            ("security.capability", "only user.*"),
            ("security.selinux", "only user.*"),
            ("system.posix_acl_access", "only user.*"),
            ("User.a", "only user.*"),
            ("user.", "1 to 250 more bytes"),
            ("user.a b", "' ' at byte 6"),
            ("user.\u{e9}", "at byte 5"),
            ("user.a\n", "'\\n' at byte 6"),
        ] {
            let e = bad.parse::<XattrName>().unwrap_err();
            assert!(e.contains(why), "{bad:?}: {e}");
        }
        let long = format!("user.{}", "n".repeat(251));
        assert!(long.parse::<XattrName>().unwrap_err().contains("is 256"));
    }

    #[test]
    fn base64_matches_rfc_4648() {
        // RFC 4648, section 10.
        for (data, text) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_encode(data.as_bytes()), text);
            assert_eq!(base64_decode(text).unwrap(), data.as_bytes());
        }
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(base64_decode(&base64_encode(&all)).unwrap(), all);
        assert_eq!(base64_encode(&[0xfb, 0xff]), "+/8=");
        assert_eq!(base64_decode("+/8=").unwrap(), [0xfb, 0xff]);
    }

    #[test]
    fn only_canonical_base64_is_read() {
        for bad in [
            "Zg",       // no padding
            "Zg=",      // short padding
            "Zh==",     // bits past the end of the data
            "Zm9=",     // the same
            "Z===",     // three '='
            "====",     // padding only
            "Zg==Zg==", // padding in the middle
            "Zm 9v",    // a space
            "Zm9v\n",   // a newline
            "Zm9-",     // URL-safe alphabet
            "Zm9_", "Zm=v", // '=' before a character
        ] {
            assert!(base64_decode(bad).is_err(), "{bad:?}");
        }
        assert!(
            base64_decode("Zh==")
                .unwrap_err()
                .contains("canonical base64")
        );
    }
}
