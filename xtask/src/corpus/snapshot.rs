// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! The golden `ordin show --json` files, and what differs from them.
//!
//! `ordin show --json` prints canonical JSON on one line. The golden file
//! holds the same value pretty-printed, so a change is a readable diff.

use serde_json::Value;

/// The most differences listed for one package.
pub const MAX_DIFFERENCES: usize = 20;

/// `value` as a golden file holds it: pretty-printed, keys in order, with a
/// line break at the end.
#[must_use]
pub fn pretty(value: &Value) -> String {
    let mut text = serde_json::to_string_pretty(value).unwrap_or_default();
    text.push('\n');
    text
}

/// Where `found` differs from `expected`, as JSON pointers with both
/// values, at most `MAX_DIFFERENCES` of them.
#[must_use]
pub fn differences(expected: &Value, found: &Value) -> Vec<String> {
    let mut out = Vec::new();
    walk(expected, found, &mut String::new(), &mut out);
    out
}

fn walk(expected: &Value, found: &Value, at: &mut String, out: &mut Vec<String>) {
    if out.len() >= MAX_DIFFERENCES || expected == found {
        return;
    }
    let len = at.len();
    match (expected, found) {
        (Value::Object(a), Value::Object(b)) => {
            let mut keys: Vec<&String> = a.keys().chain(b.keys()).collect();
            keys.sort();
            keys.dedup();
            for key in keys {
                at.push('/');
                at.push_str(&key.replace('~', "~0").replace('/', "~1"));
                match (a.get(key), b.get(key)) {
                    (Some(x), Some(y)) => walk(x, y, at, out),
                    (x, y) => push(at, x, y, out),
                }
                at.truncate(len);
            }
        }
        (Value::Array(a), Value::Array(b)) => {
            for i in 0..a.len().max(b.len()) {
                at.push_str(&format!("/{i}"));
                match (a.get(i), b.get(i)) {
                    (Some(x), Some(y)) => walk(x, y, at, out),
                    (x, y) => push(at, x, y, out),
                }
                at.truncate(len);
            }
        }
        (x, y) => push(at, Some(x), Some(y), out),
    }
}

fn push(at: &str, expected: Option<&Value>, found: Option<&Value>, out: &mut Vec<String>) {
    if out.len() < MAX_DIFFERENCES {
        let at = if at.is_empty() { "/" } else { at };
        out.push(format!("{at}: {} became {}", shown(expected), shown(found)));
    }
}

/// A value for a message: at most 100 characters.
fn shown(value: Option<&Value>) -> String {
    let Some(value) = value else {
        return "nothing".to_owned();
    };
    let text = value.to_string();
    if text.chars().count() > 100 {
        format!("{}…", text.chars().take(99).collect::<String>())
    } else {
        text
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn a_golden_file_is_pretty_with_a_final_line_break() {
        assert_eq!(
            pretty(&json!({"b": [1], "a": "x"})),
            "{\n  \"a\": \"x\",\n  \"b\": [\n    1\n  ]\n}\n"
        );
    }

    #[test]
    fn differences_name_where_and_what() {
        let expected = json!({"a": 1, "b": [1, 2], "c": {"d/e~": "x"}, "same": true, "gone": 1});
        let found = json!({"a": 2, "b": [1], "c": {"d/e~": "y"}, "same": true, "new": "z"});
        assert_eq!(
            differences(&expected, &found),
            [
                "/a: 1 became 2",
                "/b/1: 2 became nothing",
                "/c/d~1e~0: \"x\" became \"y\"",
                "/gone: 1 became nothing",
                "/new: nothing became \"z\"",
            ]
        );
        assert_eq!(differences(&json!(1), &json!("1")), ["/: 1 became \"1\""]);
        assert!(differences(&expected, &expected).is_empty());
        let long = json!("x".repeat(200));
        assert_eq!(
            differences(&long, &json!(1)),
            [format!("/: \"{}… became 1", "x".repeat(98))]
        );
        // 100 characters are shown whole.
        let fits = json!("x".repeat(98));
        assert_eq!(
            differences(&fits, &json!(1)),
            [format!("/: \"{}\" became 1", "x".repeat(98))]
        );
        let many: Vec<u32> = (0..30).collect();
        assert_eq!(differences(&json!(many), &json!([])).len(), MAX_DIFFERENCES);
        let nested = json!({"a": (0..30).collect::<Vec<u32>>(), "b": 1});
        let diffs = differences(&nested, &json!({"a": [], "b": 2}));
        assert_eq!(diffs.len(), MAX_DIFFERENCES);
        assert!(!diffs.iter().any(|d| d.starts_with("/b")));
    }
}
