// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Reads a tree's canonical text one entry at a time.
//!
//! The text is checked as JSON without building it, then walked as
//! written: the fixed object around the entries, then each entry, which is
//! built as a small JSON value, decoded, and freed. Only the entries
//! decoded so far and one entry's value are in memory at once.

use ordin_core::json::{self, JsonError, LayoutError, Member};

use crate::error::{Error, ErrorKind};
use crate::model::Entry;
use crate::{MAX_ENTRIES, decode, encode};

/// The most JSON values one entry may hold. The largest valid entry holds
/// about 120: its object, ten fields, 16 extended attributes and two full
/// capability sets.
pub(crate) const ENTRY_VALUES: usize = 1024;

/// The most JSON values an unknown format version may hold to be shown.
const VERSION_VALUES: usize = 64;

fn json_error(e: JsonError) -> Error {
    Error::tree(None, ErrorKind::Json(e.0))
}

/// A layout error, with `field` named if it is a value of the wrong type.
fn layout(field: Option<&str>, e: LayoutError) -> Error {
    match e {
        LayoutError::Json(e) => json_error(e),
        LayoutError::NotCanonical { at } => Error::tree(None, ErrorKind::NotCanonical { at }),
        LayoutError::WrongType { expected, found } => {
            Error::tree(field, ErrorKind::WrongType { expected, found })
        }
    }
}

/// Requires `written` to be exactly what `read` holds.
fn same(read: Member<'_>, written: &str) -> Result<(), Error> {
    if read.text == written {
        return Ok(());
    }
    Err(Error::tree(
        None,
        ErrorKind::NotCanonical {
            at: read.at + json::first_difference(read.text.as_bytes(), written.as_bytes()),
        },
    ))
}

/// Reads a tree's entries from its canonical text, in the order written.
/// The format version is checked before any other field.
pub(crate) fn tree(text: &str) -> Result<Vec<Entry>, Error> {
    json::check_syntax(text).map_err(json_error)?;
    let json::Object {
        members: [entries, version],
        unknown,
    } = json::object(text, 0, ["entries", "ordin-tree"]).map_err(|e| layout(None, e))?;
    match version {
        None => return Err(Error::tree(Some("ordin-tree"), ErrorKind::Missing)),
        Some(v) if v.text == "1" => {}
        Some(v) => {
            let shown = json::parse_bounded(v.text, v.at, VERSION_VALUES).map_err(json_error)?;
            return Err(Error::tree(
                Some("ordin-tree"),
                ErrorKind::UnknownFormat(json::canonical(&shown)),
            ));
        }
    }
    if let Some(name) = unknown {
        return Err(Error::tree(Some(&name), ErrorKind::UnknownField));
    }
    let Some(entries) = entries else {
        return Err(Error::tree(Some("entries"), ErrorKind::Missing));
    };
    let items = || json::array(entries.text, entries.at).map_err(|e| layout(Some("entries"), e));
    // Count the entries first, so an oversized list is refused before any
    // of it is decoded.
    let mut len = 0;
    for item in items()? {
        item.map_err(|e| layout(None, e))?;
        len += 1;
    }
    if len > MAX_ENTRIES {
        return Err(Error::tree(
            Some("entries"),
            ErrorKind::TooManyEntries {
                max: MAX_ENTRIES,
                len,
            },
        ));
    }
    let mut out = Vec::with_capacity(len);
    for (index, item) in items()?.enumerate() {
        let item = item.map_err(|e| layout(None, e))?;
        let value = json::parse_bounded(item.text, item.at, ENTRY_VALUES).map_err(json_error)?;
        same(item, &json::canonical(&value))?;
        let entry = decode::entry(index, &value)?;
        // Decoding refuses every choice the encoder wouldn't make, so
        // encoding gives back the same text. Check it anyway: the identity
        // must be the digest of exactly what was read.
        same(item, &json::canonical(&encode::entry(&entry)))?;
        out.push(entry);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use ordin_core::{Algorithm, Digest, Mode};

    use super::*;
    use crate::caps::{Capabilities, LinuxCap};
    use crate::model::{File, Kind};
    use crate::xattr::Xattrs;
    use crate::{Tree, XATTR_VALUE_MAX, XATTRS_MAX};

    fn refused(text: &str) -> Error {
        tree(text).unwrap_err()
    }

    fn dirs(names: &[&str]) -> String {
        let entries: Vec<String> = names
            .iter()
            .map(|n| format!(r#"{{"path":"/{n}","type":"dir"}}"#))
            .collect();
        format!(r#"{{"entries":[{}],"ordin-tree":1}}"#, entries.join(","))
    }

    /// The largest entry the rules allow: every field, the most extended
    /// attributes at the largest size, and every capability in both sets.
    fn largest() -> Entry {
        let all: std::collections::BTreeSet<LinuxCap> =
            (0..=u8::MAX).map_while(LinuxCap::from_number).collect();
        let mut xattrs = Xattrs::new();
        for i in 0..XATTRS_MAX {
            xattrs.insert(
                format!("user.k{i:02}").parse().unwrap(),
                vec![0xff; XATTR_VALUE_MAX],
            );
        }
        Entry {
            path: "/a".parse().unwrap(),
            kind: Kind::File(File {
                mode: Mode::new(0o4755).unwrap(),
                owner: "_apt".parse().unwrap(),
                group: "adm".parse().unwrap(),
                size: 1,
                content: Digest::blake3(b"a"),
                fsverity: Digest::new(Algorithm::Sha256, [1; 32]),
                xattrs,
                capabilities: Some(Capabilities {
                    permitted: all.clone(),
                    inheritable: all,
                    effective: true,
                }),
            }),
        }
    }

    #[test]
    fn the_largest_entry_is_well_within_the_value_limit() {
        let tree = Tree::new(vec![largest()]).unwrap();
        let bytes = tree.to_canonical_bytes().unwrap();
        let (read, _) = Tree::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(read, tree);
        let text = json::canonical(&encode::entry(&largest()));
        assert!(json::parse_bounded(&text, 0, 112).is_ok());
        assert!(json::parse_bounded(&text, 0, 111).is_err());
        const { assert!(112 * 8 < ENTRY_VALUES) };
    }

    #[test]
    fn an_entry_with_too_many_values_is_refused() {
        let many = vec!["\"\""; ENTRY_VALUES].join(",");
        let text =
            format!(r#"{{"entries":[{{"path":"/a","type":"dir","x":[{many}]}}],"ordin-tree":1}}"#);
        let e = refused(&text);
        assert!(
            matches!(&e.kind, ErrorKind::Json(m) if m.starts_with("more than 1024 values")),
            "{e}"
        );
        // One fewer is decoded, and refused for its unknown field.
        let many = vec!["\"\""; ENTRY_VALUES - 4].join(",");
        let text =
            format!(r#"{{"entries":[{{"path":"/a","type":"dir","x":[{many}]}}],"ordin-tree":1}}"#);
        assert_eq!(refused(&text).kind, ErrorKind::UnknownField);
    }

    #[test]
    fn the_layout_is_refused_where_it_differs() {
        let text = dirs(&["a", "b"]);
        assert_eq!(tree(&text).unwrap().len(), 2);
        let at = |at| ErrorKind::NotCanonical { at };
        // Between entries, while counting them.
        let between = text.find("},{").unwrap() + 2;
        assert_eq!(refused(&text.replacen("},{", "}, {", 1)).kind, at(between));
        // Inside an entry.
        let inside = text.find(r#""type""#).unwrap();
        assert_eq!(
            refused(&text.replacen(r#""type""#, r#" "type""#, 1)).kind,
            at(inside)
        );
        let escaped = text.find("\"/b\"").unwrap() + 1;
        assert_eq!(
            refused(&text.replacen("\"/b\"", "\"\\u002fb\"", 1)).kind,
            at(escaped)
        );
        // Around the entries.
        assert_eq!(refused(&format!("{text} ")).kind, at(text.len()));
        assert_eq!(refused(&format!(" {text}")).kind, at(0));
    }

    #[test]
    fn only_json_is_read() {
        assert!(matches!(refused("{").kind, ErrorKind::Json(_)));
        assert!(matches!(
            refused(&dirs(&["a"]).replacen("\"dir\"", "1.5", 1)).kind,
            ErrorKind::Json(m) if m.contains("integers")
        ));
    }

    #[test]
    fn an_unknown_version_is_shown_unless_it_is_too_large() {
        let text = |version: &str| format!(r#"{{"entries":[],"ordin-tree":{version}}}"#);
        assert_eq!(
            refused(&text("[1,2]")).kind,
            ErrorKind::UnknownFormat("[1,2]".into())
        );
        let large = format!("[{}]", vec!["1"; VERSION_VALUES].join(","));
        let e = refused(&text(&large));
        assert!(
            matches!(&e.kind, ErrorKind::Json(m) if m.starts_with("more than 64 values")),
            "{e}"
        );
        assert_eq!(e.at.field, None);
    }

    #[test]
    fn the_entries_are_an_array() {
        let e = refused(r#"{"entries":"x","ordin-tree":1}"#);
        assert_eq!(e.at.field.as_deref(), Some("entries"));
        assert_eq!(
            e.kind,
            ErrorKind::WrongType {
                expected: "an array",
                found: "a string"
            }
        );
        let e = refused("[]");
        assert_eq!(e.at.field, None);
    }

    #[test]
    fn entries_are_counted_before_any_is_decoded() {
        let mut names: Vec<String> = (0..=MAX_ENTRIES).map(|i| format!("d{i:06}")).collect();
        let text = dirs(&names.iter().map(String::as_str).collect::<Vec<_>>());
        let too_many = ErrorKind::TooManyEntries {
            max: MAX_ENTRIES,
            len: MAX_ENTRIES + 1,
        };
        // A broken last entry isn't reached: the count refuses the list
        // first.
        let broken = text.replacen(r#""type":"dir"}]"#, r#""type":"pipe"}]"#, 1);
        assert_ne!(broken, text);
        assert_eq!(refused(&broken).kind, too_many);
        // Within the limit, the broken entry is what is refused.
        names.pop();
        let text = dirs(&names.iter().map(String::as_str).collect::<Vec<_>>());
        let broken = text.replacen(r#""type":"dir"}]"#, r#""type":"pipe"}]"#, 1);
        assert_eq!(refused(&broken).kind, ErrorKind::UnknownType("pipe".into()));
    }

    #[test]
    fn a_text_that_differs_from_its_entrys_encoding_is_refused_where_it_differs() {
        let item = Member {
            at: 10,
            text: r#"{"a":1}"#,
        };
        assert!(same(item, r#"{"a":1}"#).is_ok());
        assert_eq!(
            same(item, r#"{"a":2}"#).unwrap_err().kind,
            ErrorKind::NotCanonical { at: 15 }
        );
    }
}
