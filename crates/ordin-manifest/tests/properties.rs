// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Property tests: formatting never changes a package's identity, any
//! subset of optional fields either is refused or round-trips exactly,
//! and damaged bytes never make the reader panic.

use ordin_manifest::Manifest;
use ordin_manifest::json::{self, Value};
use proptest::prelude::*;

const EVERYTHING: &str = include_str!("data/everything.json");

/// The top-level fields a manifest may leave out.
const OPTIONAL: [&str; 25] = [
    "description",
    "homepage",
    "source",
    "provenance",
    "provides",
    "requires",
    "conflicts",
    "recommends",
    "supplements",
    "requires-at",
    "obsoletes",
    "replaces",
    "declares",
    "state",
    "settings",
    "hooks",
    "tests",
    "security",
    "delegated",
    "switch",
    "support",
    "abi",
    "fixes",
    "notices",
    "ignorable",
];

/// Whitespace drawn from `space`.
fn gap(space: &mut impl Iterator<Item = u8>, out: &mut String) {
    for _ in 0..(space.next().unwrap_or(0) % 3) {
        out.push_str([" ", "\n", "\t"][usize::from(space.next().unwrap_or(0) % 3)]);
    }
}

/// Writes `v` as JSON with object keys in an order drawn from `order` and
/// whitespace drawn from `space`.
fn scramble(
    v: &Value,
    order: &mut impl Iterator<Item = u8>,
    space: &mut impl Iterator<Item = u8>,
    out: &mut String,
) {
    match v {
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            // A rotation and an optional reversal, chosen per object.
            if !entries.is_empty() {
                let k = usize::from(order.next().unwrap_or(0)) % entries.len();
                entries.rotate_left(k);
                if order.next().unwrap_or(0) % 2 == 1 {
                    entries.reverse();
                }
            }
            out.push('{');
            for (i, (key, value)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                gap(space, out);
                out.push_str(&json::canonical(&Value::Str(key.clone())));
                gap(space, out);
                out.push(':');
                scramble(value, order, space, out);
            }
            gap(space, out);
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                gap(space, out);
                scramble(item, order, space, out);
            }
            out.push(']');
        }
        other => out.push_str(&json::canonical(other)),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn formatting_never_changes_the_identity(order in prop::collection::vec(any::<u8>(), 0..400), space in prop::collection::vec(any::<u8>(), 0..400)) {
        let value = json::parse(EVERYTHING).map_err(|e| TestCaseError::fail(e.0))?;
        let mut text = String::new();
        scramble(&value, &mut order.iter().copied().cycle(), &mut space.iter().copied().chain(std::iter::repeat(0)), &mut text);
        let a = Manifest::from_json(EVERYTHING).map_err(|e| TestCaseError::fail(e.to_string()))?;
        let b = Manifest::from_json(&text).map_err(|e| TestCaseError::fail(format!("{e}\n{text}")))?;
        prop_assert_eq!(a.to_canonical_bytes().ok(), b.to_canonical_bytes().ok());
        prop_assert_eq!(a.digest().ok(), b.digest().ok());
    }

    #[test]
    fn leaving_out_fields_is_refused_or_round_trips(keep in prop::collection::vec(any::<bool>(), OPTIONAL.len())) {
        let Value::Object(mut map) = json::parse(EVERYTHING).map_err(|e| TestCaseError::fail(e.0))? else {
            return Err(TestCaseError::fail("not an object"));
        };
        for (field, keep) in OPTIONAL.iter().zip(keep) {
            if !keep {
                map.remove(*field);
            }
        }
        let text = json::canonical(&Value::Object(map));
        if let Ok(m) = Manifest::from_json(&text) {
            let bytes = m.to_canonical_bytes().map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert_eq!(&bytes, text.as_bytes());
            let (again, _) = Manifest::from_signed_bytes(&bytes).map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert_eq!(again, m);
        }
    }

    #[test]
    fn damaged_bytes_never_panic(changes in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..6)) {
        let m = Manifest::from_json(EVERYTHING).map_err(|e| TestCaseError::fail(e.to_string()))?;
        let mut bytes = m.to_canonical_bytes().map_err(|e| TestCaseError::fail(e.to_string()))?;
        for (at, b) in changes {
            let i = at.index(bytes.len());
            bytes[i] = b;
        }
        if let Ok((m, _)) = Manifest::from_signed_bytes(&bytes) {
            prop_assert_eq!(m.to_canonical_bytes().ok(), Some(bytes.clone()));
        }
        let _ = Manifest::from_json(&String::from_utf8_lossy(&bytes));
    }
}
