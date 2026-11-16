// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! A strict JSON value and its canonical encoding (RFC 8785).
//!
//! Reading refuses what common parsers quietly accept: a repeated key
//! (serde_json keeps the last value), fractions and exponents, and
//! integers beyond ±(2⁵³−1). Writing follows RFC 8785: no whitespace,
//! object keys sorted by UTF-16 code units, and strings escaped exactly as
//! ECMAScript's `JSON.stringify` does. Numbers are always integers, so
//! RFC 8785's number formatting never comes into play.

use std::collections::BTreeMap;
use std::fmt::{self, Write as _};

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};

/// The largest integer magnitude: 2⁵³−1, the largest every JSON reader
/// represents exactly.
pub const MAX_INT: i64 = (1 << 53) - 1;

/// A JSON value. Numbers are integers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// `null`
    Null,
    /// `true` or `false`
    Bool(bool),
    /// An integer within ±[`MAX_INT`].
    Int(i64),
    /// A string.
    Str(String),
    /// An array.
    Array(Vec<Value>),
    /// An object. The map's order is irrelevant: encoding sorts keys.
    Object(BTreeMap<String, Value>),
}

impl Value {
    /// A short name for the value's type, for messages.
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Bool(_) => "a boolean",
            Self::Int(_) => "an integer",
            Self::Str(_) => "a string",
            Self::Array(_) => "an array",
            Self::Object(_) => "an object",
        }
    }
}

/// Why JSON text couldn't be read.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct JsonError(pub String);

/// Reads JSON text strictly.
///
/// # Errors
///
/// Returns where and why the text isn't acceptable JSON.
pub fn parse(text: &str) -> Result<Value, JsonError> {
    serde_json::from_str(text).map_err(|e| JsonError(e.to_string()))
}

impl<'de> Deserialize<'de> for Value {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(ValueVisitor)
    }
}

struct ValueVisitor;

impl<'de> Visitor<'de> for ValueVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
        if v.unsigned_abs() > MAX_INT.unsigned_abs() {
            return Err(E::custom(format!("the integer {v} is beyond ±(2^53-1)")));
        }
        Ok(Value::Int(v))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
        i64::try_from(v)
            .ok()
            .filter(|v| *v <= MAX_INT)
            .map(Value::Int)
            .ok_or_else(|| E::custom(format!("the integer {v} is beyond ±(2^53-1)")))
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Value, E> {
        Err(E::custom(
            "numbers must be integers within ±(2^53-1), without fractions or exponents",
        ))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
        Ok(Value::Str(v.to_owned()))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element()? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut object = BTreeMap::new();
        while let Some(key) = map.next_key::<String>()? {
            if object.contains_key(&key) {
                return Err(de::Error::custom(format!("the key {key:?} appears twice")));
            }
            let value = map.next_value()?;
            object.insert(key, value);
        }
        Ok(Value::Object(object))
    }
}

/// The canonical encoding of `value` (RFC 8785).
#[must_use]
pub fn canonical(value: &Value) -> String {
    let mut out = String::new();
    write(value, &mut out);
    out
}

fn write(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Int(n) => {
            let _ = write!(out, "{n}");
        }
        Value::Str(s) => write_str(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_str(key, out);
                out.push(':');
                if let Some(v) = map.get(key) {
                    write(v, out);
                }
            }
            out.push('}');
        }
    }
}

/// A string as RFC 8785 writes it: only `"`, `\` and control characters
/// are escaped, with the short forms where JSON has them.
fn write_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if c < ' ' => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canon(text: &str) -> String {
        canonical(&parse(text).unwrap())
    }

    #[test]
    fn rfc_8785_strings_and_literals() {
        // The string and literals of RFC 8785's example (section 3.2.4);
        // its numbers are fractions, which this format refuses.
        let input = r#"{
            "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
            "literals": [null, true, false]
        }"#;
        assert_eq!(
            canon(input),
            r#"{"literals":[null,true,false],"string":"€$\u000f\nA'B\"\\\\\"/"}"#
        );
    }

    #[test]
    fn rfc_8785_key_order_is_by_utf16_code_units() {
        // RFC 8785 section 3.2.3: the sorted order of these keys.
        let input = r#"{
            "\u20ac": "Euro Sign",
            "\r": "Carriage Return",
            "\ufb33": "Hebrew Letter Dalet With Dagesh",
            "1": "One",
            "\ud83d\ude00": "Emoji: Grinning Face",
            "\u0080": "Control",
            "\u00f6": "Latin Small Letter O With Diaeresis"
        }"#;
        let out = canon(input);
        let order: Vec<&str> = out
            .split("\":\"")
            .skip(1)
            .map(|rest| rest.split('"').next().unwrap())
            .collect();
        assert_eq!(
            order,
            [
                "Carriage Return",
                "One",
                "Control",
                "Latin Small Letter O With Diaeresis",
                "Euro Sign",
                "Emoji: Grinning Face",
                "Hebrew Letter Dalet With Dagesh"
            ]
        );
    }

    #[test]
    fn every_control_character_is_escaped() {
        assert_eq!(
            canonical(&Value::Str("\u{0}\u{1f}\u{7f}\u{8}\u{c}\t\r\n".into())),
            "\"\\u0000\\u001f\u{7f}\\b\\f\\t\\r\\n\""
        );
    }

    #[test]
    fn integers_are_written_plainly() {
        assert_eq!(
            canon("[0, -1, 9007199254740991, -9007199254740991]"),
            "[0,-1,9007199254740991,-9007199254740991]"
        );
    }

    #[test]
    fn what_common_parsers_accept_is_refused() {
        let err = |text: &str| parse(text).unwrap_err().0;
        assert!(err(r#"{"a":1,"a":2}"#).contains("the key \"a\" appears twice"));
        assert!(err(r#"{"x":{"b":true,"b":false}}"#).contains("appears twice"));
        assert!(err("1.5").contains("integers"));
        assert!(err("1e3").contains("integers"));
        assert!(err("1.0").contains("integers"));
        assert!(err("9007199254740992").contains("beyond"));
        assert!(err("-9007199254740992").contains("beyond"));
        assert!(err("18446744073709551616").contains("integers"));
        assert!(err("[1,]").contains("trailing comma") || !err("[1,]").is_empty());
        assert!(!err("{} x").is_empty());
        assert!(!err("").is_empty());
    }

    #[test]
    fn the_visitor_says_what_it_expects() {
        let e = <serde_json::Error as de::Error>::invalid_type(
            de::Unexpected::Bool(true),
            &ValueVisitor,
        );
        assert!(e.to_string().contains("a JSON value"), "{e}");
    }

    #[test]
    fn values_name_their_type() {
        let names: Vec<&str> = [
            Value::Null,
            Value::Bool(true),
            Value::Int(1),
            Value::Str(String::new()),
            Value::Array(vec![]),
            Value::Object(BTreeMap::new()),
        ]
        .iter()
        .map(Value::type_name)
        .collect();
        assert_eq!(
            names,
            [
                "null",
                "a boolean",
                "an integer",
                "a string",
                "an array",
                "an object"
            ]
        );
    }

    #[test]
    fn nested_values_round_trip() {
        let text = r#"{"a":[1,{"b":null,"c":"d"}],"e":{}}"#;
        assert_eq!(canon(text), text);
        assert_eq!(
            canon(" { \"e\" : { } , \"a\" : [ 1 , { \"c\" : \"d\" , \"b\" : null } ] } "),
            text
        );
    }
}
