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
//!
//! Large canonical texts are read a part at a time, so memory follows the
//! size of the result rather than of a full value tree: [`check_syntax`]
//! checks the whole text without building anything, [`object`] and
//! [`array`] walk an object's members and an array's elements as written,
//! refusing any layout the canonical encoding wouldn't write, and
//! [`parse_bounded`] builds one small part with a limit on how many values
//! it may hold.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt::{self, Write as _};

use serde::de::{
    self, Deserialize, DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor,
};

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
        let left = Cell::new(usize::MAX);
        Strict {
            max: usize::MAX,
            left: &left,
        }
        .deserialize(d)
    }
}

/// Builds a strict value, at most `max` values in all.
#[derive(Clone, Copy)]
struct Strict<'b> {
    max: usize,
    left: &'b Cell<usize>,
}

impl Strict<'_> {
    /// Counts one more value.
    fn take<E: de::Error>(&self) -> Result<(), E> {
        match self.left.get().checked_sub(1) {
            Some(left) => {
                self.left.set(left);
                Ok(())
            }
            None => Err(E::custom(format!(
                "more than {} values, the most this part holds",
                self.max
            ))),
        }
    }
}

impl<'de> DeserializeSeed<'de> for Strict<'_> {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Strict<'_> {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        self.take()?;
        Ok(Value::Null)
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
        self.take()?;
        Ok(Value::Bool(v))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
        self.take()?;
        if v.unsigned_abs() > MAX_INT.unsigned_abs() {
            return Err(E::custom(format!("the integer {v} is beyond ±(2^53-1)")));
        }
        Ok(Value::Int(v))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
        self.take()?;
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
        self.take()?;
        Ok(Value::Str(v.to_owned()))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        self.take()?;
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(self)? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        self.take()?;
        let mut object = BTreeMap::new();
        while let Some(key) = map.next_key::<String>()? {
            if object.contains_key(&key) {
                return Err(de::Error::custom(format!("the key {key:?} appears twice")));
            }
            let value = map.next_value_seed(self)?;
            object.insert(key, value);
        }
        Ok(Value::Object(object))
    }
}

/// Checks that `text` is one JSON value, with nothing but whitespace
/// around it, without building it. Only the syntax is checked: numbers and
/// repeated keys are left to [`parse_bounded`].
///
/// # Errors
///
/// Returns where and why the text isn't JSON.
pub fn check_syntax(text: &str) -> Result<(), JsonError> {
    serde_json::from_str::<IgnoredAny>(text)
        .map(|_| ())
        .map_err(|e| JsonError(e.to_string()))
}

/// How many bytes the JSON value at the start of `text` takes, with any
/// whitespace before it, without building it. Like [`check_syntax`], it
/// checks only the syntax.
///
/// # Errors
///
/// The text doesn't start with a JSON value.
pub fn value_len(text: &str) -> Result<usize, JsonError> {
    let mut values = serde_json::Deserializer::from_str(text).into_iter::<IgnoredAny>();
    match values.next() {
        Some(Ok(_)) => Ok(values.byte_offset()),
        Some(Err(e)) => Err(JsonError(e.to_string())),
        None => Err(JsonError("expected a value".into())),
    }
}

/// Reads `text`, found at byte `base` of a larger text, strictly as
/// [`parse`] does, building at most `max_values` values: every array,
/// object, string, number, boolean and null counts as one.
///
/// # Errors
///
/// Returns why the text isn't acceptable, with its byte in the larger
/// text, or that it holds more than `max_values` values.
pub fn parse_bounded(text: &str, base: usize, max_values: usize) -> Result<Value, JsonError> {
    let left = Cell::new(max_values);
    let mut d = serde_json::Deserializer::from_str(text);
    Strict {
        max: max_values,
        left: &left,
    }
    .deserialize(&mut d)
    .and_then(|v| d.end().map(|()| v))
    .map_err(|e| located(&e, text, base))
}

/// A serde_json error with its position as a byte of the larger text.
fn located(e: &serde_json::Error, text: &str, base: usize) -> JsonError {
    let full = e.to_string();
    if e.line() == 0 {
        return JsonError(full);
    }
    let position = format!(" at line {} column {}", e.line(), e.column());
    let message = full.strip_suffix(&position).unwrap_or(&full);
    let line_start: usize = text
        .split_inclusive('\n')
        .take(e.line().saturating_sub(1))
        .map(str::len)
        .sum();
    let at = base
        .saturating_add(line_start)
        .saturating_add(e.column().saturating_sub(1));
    JsonError(format!("{message} at byte {at}"))
}

/// What is wrong with how a canonical text is laid out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LayoutError {
    /// Not acceptable JSON.
    Json(JsonError),
    /// JSON, but not as the canonical encoding writes it.
    NotCanonical {
        /// The first byte the canonical encoding wouldn't write.
        at: usize,
    },
    /// Another type of value where an object or an array belongs.
    WrongType {
        /// The type that belongs there.
        expected: &'static str,
        /// The type found.
        found: &'static str,
    },
}

/// One value inside a larger text: an object member's value or an array
/// element, exactly as written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Member<'a> {
    /// Where the value starts in the larger text.
    pub at: usize,
    /// The value's text.
    pub text: &'a str,
}

/// An object's members as written: each known name's value, and the first
/// other name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Object<'a, const N: usize> {
    /// The value of each known name, in the order the names were given.
    pub members: [Option<Member<'a>>; N],
    /// The first name that isn't known, in the order written.
    pub unknown: Option<String>,
}

/// The type of the JSON value `text` starts with, named as
/// [`Value::type_name`] names it.
fn type_of(text: &str) -> &'static str {
    match text.as_bytes().first() {
        Some(b'{') => "an object",
        Some(b'[') => "an array",
        Some(b'"') => "a string",
        Some(b't' | b'f') => "a boolean",
        Some(b'n') => "null",
        Some(b'-' | b'0'..=b'9') => "an integer",
        _ => "no value",
    }
}

fn not_canonical(at: usize) -> LayoutError {
    LayoutError::NotCanonical { at }
}

/// Requires `text` to start with `open`. Whitespace there is a layout the
/// canonical encoding never writes; anything else is another type.
fn opens(text: &str, base: usize, open: u8, expected: &'static str) -> Result<(), LayoutError> {
    match text.as_bytes().first() {
        Some(b) if *b == open => Ok(()),
        Some(b' ' | b'\t' | b'\n' | b'\r') => Err(not_canonical(base)),
        _ => Err(LayoutError::WrongType {
            expected,
            found: type_of(text),
        }),
    }
}

/// The value at byte `i` of `text`, which must start right there.
fn value_at(text: &str, base: usize, i: usize) -> Result<Member<'_>, LayoutError> {
    let rest = text.get(i..).unwrap_or_default();
    if matches!(
        rest.as_bytes().first(),
        None | Some(b' ' | b'\t' | b'\n' | b'\r')
    ) {
        return Err(not_canonical(base.saturating_add(i)));
    }
    let len = value_len(rest).map_err(LayoutError::Json)?;
    Ok(Member {
        at: base.saturating_add(i),
        text: rest.get(..len).unwrap_or_default(),
    })
}

/// Reads the object that is exactly `text`, found at byte `base` of a
/// larger text, without building its values. The layout must be what the
/// canonical encoding writes: no whitespace, every name written as RFC
/// 8785 writes it, names in order and none repeated. Only the first
/// unknown name is kept, however many there are. `text` must already have
/// passed [`check_syntax`] as part of the larger text.
///
/// # Errors
///
/// `text` isn't an object, or isn't laid out canonically.
pub fn object<'a, const N: usize>(
    text: &'a str,
    base: usize,
    known: [&str; N],
) -> Result<Object<'a, N>, LayoutError> {
    opens(text, base, b'{', "an object")?;
    let bytes = text.as_bytes();
    let mut found = Object {
        members: [None; N],
        unknown: None,
    };
    let mut i = 1;
    let mut previous: Option<String> = None;
    if bytes.get(1) == Some(&b'}') {
        i = 2;
    } else {
        loop {
            let name = value_at(text, base, i)?;
            // Only unchecked text has a name that isn't a string.
            let Value::Str(key) =
                parse_bounded(name.text, name.at, 1).map_err(LayoutError::Json)?
            else {
                return Err(not_canonical(name.at));
            };
            let mut written = String::new();
            write_str(&key, &mut written);
            if written != name.text {
                return Err(not_canonical(
                    name.at + first_difference(name.text.as_bytes(), written.as_bytes()),
                ));
            }
            if let Some(previous) = &previous {
                match previous.encode_utf16().cmp(key.encode_utf16()) {
                    std::cmp::Ordering::Less => {}
                    std::cmp::Ordering::Equal => {
                        return Err(LayoutError::Json(JsonError(format!(
                            "the key {key:?} appears twice at byte {}",
                            name.at
                        ))));
                    }
                    std::cmp::Ordering::Greater => return Err(not_canonical(name.at)),
                }
            }
            i += name.text.len();
            if bytes.get(i) != Some(&b':') {
                return Err(not_canonical(base + i));
            }
            let value = value_at(text, base, i + 1)?;
            i += 1 + value.text.len();
            match known.iter().position(|k| *k == key) {
                Some(p) => {
                    if let Some(slot) = found.members.get_mut(p) {
                        *slot = Some(value);
                    }
                }
                None => {
                    if found.unknown.is_none() {
                        found.unknown = Some(key.clone());
                    }
                }
            }
            previous = Some(key);
            match bytes.get(i) {
                Some(b',') => i += 1,
                Some(b'}') => {
                    i += 1;
                    break;
                }
                _ => return Err(not_canonical(base + i)),
            }
        }
    }
    if i != text.len() {
        return Err(not_canonical(base + i));
    }
    Ok(found)
}

/// An array's elements as written, one at a time.
#[derive(Clone, Debug)]
pub struct Elements<'a> {
    text: &'a str,
    base: usize,
    at: usize,
    state: State,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// An element starts at `at`.
    Element,
    /// The array ended just before `at`.
    End,
    /// Nothing more to give.
    Finished,
}

/// Reads the array that is exactly `text`, found at byte `base` of a
/// larger text, one element at a time without building them. The layout
/// must be what the canonical encoding writes: no whitespace. `text` must
/// already have passed [`check_syntax`] as part of the larger text.
///
/// # Errors
///
/// `text` isn't an array. Layout errors further in come from the
/// iterator.
pub fn array(text: &str, base: usize) -> Result<Elements<'_>, LayoutError> {
    opens(text, base, b'[', "an array")?;
    let empty = text.as_bytes().get(1) == Some(&b']');
    Ok(Elements {
        text,
        base,
        at: if empty { 2 } else { 1 },
        state: if empty { State::End } else { State::Element },
    })
}

impl<'a> Elements<'a> {
    fn element(&mut self) -> Result<Member<'a>, LayoutError> {
        let element = value_at(self.text, self.base, self.at)?;
        self.at += element.text.len();
        match self.text.as_bytes().get(self.at) {
            Some(b',') => self.at += 1,
            Some(b']') => {
                self.at += 1;
                self.state = State::End;
            }
            _ => return Err(not_canonical(self.base + self.at)),
        }
        Ok(element)
    }
}

impl<'a> Iterator for Elements<'a> {
    type Item = Result<Member<'a>, LayoutError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.state {
            State::Finished => None,
            State::End => {
                self.state = State::Finished;
                // The array must be the whole text.
                (self.at != self.text.len()).then(|| Err(not_canonical(self.base + self.at)))
            }
            State::Element => {
                let element = self.element();
                if element.is_err() {
                    self.state = State::Finished;
                }
                Some(element)
            }
        }
    }
}

/// The first byte where `a` and `b` differ.
#[must_use]
pub fn first_difference(a: &[u8], b: &[u8]) -> usize {
    a.iter()
        .zip(b)
        .position(|(x, y)| x != y)
        .unwrap_or(a.len().min(b.len()))
}

/// The canonical encoding of `value` (RFC 8785).
#[must_use]
pub fn canonical(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

/// Appends the canonical encoding of `value` (RFC 8785) to `out`.
pub fn write_canonical(value: &Value, out: &mut String) {
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
                write_canonical(item, out);
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
                    write_canonical(v, out);
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
        let left = Cell::new(1);
        let e = <serde_json::Error as de::Error>::invalid_type(
            de::Unexpected::Bool(true),
            &Strict {
                max: 1,
                left: &left,
            },
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

    #[test]
    fn the_syntax_is_checked_without_the_strict_rules() {
        assert!(check_syntax(" {\"a\":[1,2.5,{}]} ").is_ok());
        assert!(check_syntax(r#"{"a":1,"a":2}"#).is_ok());
        let e = check_syntax("[1,]").unwrap_err().0;
        assert!(e.ends_with("at line 1 column 4"), "{e}");
        assert!(check_syntax("1 2").is_err());
        assert!(check_syntax("").is_err());
    }

    #[test]
    fn deep_nesting_is_checked_without_recursion() {
        let deep = format!("{}{}", "[".repeat(1 << 20), "]".repeat(1 << 20));
        assert!(check_syntax(&deep).is_ok());
        assert_eq!(value_len(&deep), Ok(deep.len()));
        assert_eq!(array(&deep, 0).unwrap().take(2).count(), 1);
        // Building it stops at serde_json's depth limit.
        let e = parse_bounded(&deep, 0, usize::MAX).unwrap_err().0;
        assert!(e.starts_with("recursion limit exceeded"), "{e}");
    }

    #[test]
    fn a_values_length_counts_whitespace_before_it_and_nothing_after() {
        assert_eq!(value_len("[1, 2] x"), Ok(6));
        assert_eq!(value_len(" 1"), Ok(2));
        assert_eq!(value_len("\"a\","), Ok(3));
        assert_eq!(value_len("{\"a\":1}  "), Ok(7));
        assert_eq!(value_len("1}"), Ok(1));
        assert_eq!(value_len(""), Err(JsonError("expected a value".into())));
        assert!(value_len("[1,").is_err());
    }

    #[test]
    fn a_bounded_parse_is_as_strict_as_a_full_one() {
        let text = r#"{"a":[1,{"b":null,"c":"d"}],"e":true}"#;
        assert_eq!(parse_bounded(text, 0, 7), parse(text));
        let e = parse_bounded(text, 0, 6).unwrap_err().0;
        assert_eq!(e, "more than 6 values, the most this part holds at byte 35");
        for bad in [
            "1.5",
            "[1,1e3]",
            r#"{"a":1,"a":2}"#,
            "9007199254740992",
            "1 x",
            "[1,",
        ] {
            assert!(parse_bounded(bad, 0, 100).is_err(), "{bad}");
        }
        assert_eq!(parse_bounded("[]", 0, 1), Ok(Value::Array(vec![])));
        assert!(parse_bounded("[]", 0, 0).is_err());
    }

    #[test]
    fn a_bounded_parse_says_where_in_the_larger_text() {
        let e = |text: &str| parse_bounded(text, 100, 10).unwrap_err().0;
        let float = "numbers must be integers within ±(2^53-1), without fractions or exponents";
        assert_eq!(e("1.5"), format!("{float} at byte 102"));
        assert_eq!(e("[1,1.5]"), format!("{float} at byte 105"));
        assert_eq!(e("[1,\n1.5]"), format!("{float} at byte 106"));
        assert_eq!(e("[1,\n\n 1.5]"), format!("{float} at byte 108"));
        assert_eq!(e("1 x"), "trailing characters at byte 102");
        assert_eq!(
            e(r#"{"a":1,"a":2}"#),
            "the key \"a\" appears twice at byte 109"
        );
    }

    #[test]
    fn errors_without_a_position_are_kept_as_they_are() {
        let e = <serde_json::Error as de::Error>::custom("no place");
        assert_eq!(located(&e, "", 5), JsonError("no place".into()));
    }

    #[test]
    fn types_are_named_from_the_first_byte() {
        let names: Vec<&str> = [
            "{}", "[]", "\"\"", "true", "false", "null", "-1", "0", "9", "",
        ]
        .into_iter()
        .map(type_of)
        .collect();
        assert_eq!(
            names,
            [
                "an object",
                "an array",
                "a string",
                "a boolean",
                "a boolean",
                "null",
                "an integer",
                "an integer",
                "an integer",
                "no value"
            ]
        );
    }

    fn member(at: usize, text: &str) -> Option<Member<'_>> {
        Some(Member { at, text })
    }

    #[test]
    fn an_objects_members_are_found_where_they_are_written() {
        let text = r#"{"a":[1,2],"b":{"x":1},"c":"d","z":null}"#;
        let o = object(text, 10, ["c", "a", "q"]).unwrap();
        assert_eq!(o.members, [member(37, "\"d\""), member(15, "[1,2]"), None]);
        assert_eq!(o.unknown.as_deref(), Some("b"));
        let o = object("{}", 0, ["a"]).unwrap();
        assert_eq!(
            o,
            Object {
                members: [None],
                unknown: None
            }
        );
        let o = object(r#"{"a":1}"#, 0, []).unwrap();
        assert_eq!(o.unknown.as_deref(), Some("a"));
    }

    #[test]
    fn an_object_is_laid_out_canonically() {
        let e = |text: &str| object(text, 100, ["a", "b"]).unwrap_err();
        let at = |at| LayoutError::NotCanonical { at };
        assert_eq!(e(" {}"), at(100));
        assert_eq!(e("{ }"), at(101));
        assert_eq!(e(r#"{ "a":1}"#), at(101));
        assert_eq!(e(r#"{"a" :1}"#), at(104));
        assert_eq!(e(r#"{"a": 1}"#), at(105));
        assert_eq!(e(r#"{"a":1 }"#), at(106));
        assert_eq!(e(r#"{"a":1, "b":2}"#), at(107));
        assert_eq!(e(r#"{"a":1} "#), at(107));
        assert_eq!(e(r#"{} "#), at(102));
        // Names as RFC 8785 writes them, in order.
        assert_eq!(e(r#"{"\u0061":1}"#), at(102));
        assert_eq!(e(r#"{"b":1,"a":2}"#), at(107));
        assert_eq!(
            e(r#"{"a":1,"a":2}"#),
            LayoutError::Json(JsonError("the key \"a\" appears twice at byte 107".into()))
        );
        assert_eq!(
            object("{\"\u{e9}\":1,\"\u{1f600}\":2,\"\u{fb33}\":3}", 0, []).map(|o| o.unknown),
            Ok(Some("\u{e9}".into()))
        );
        // U+FB33 is after U+1F600 in UTF-16: the emoji is a surrogate pair.
        assert_eq!(e("{\"\u{fb33}\":1,\"\u{1f600}\":2}"), at(109));
        // Values are found, not read.
        assert!(object(r#"{"a":1.5}"#, 0, ["a"]).is_ok());
    }

    #[test]
    fn unchecked_text_is_refused_too() {
        assert_eq!(
            object("{1:2}", 3, ["a"]),
            Err(LayoutError::NotCanonical { at: 4 })
        );
        assert!(matches!(
            object(r#"{"a" 1}"#, 0, ["a"]),
            Err(LayoutError::NotCanonical { at: 4 })
        ));
        assert!(matches!(
            object(r#"{"a":}"#, 0, ["a"]),
            Err(LayoutError::Json(_))
        ));
    }

    #[test]
    fn an_object_is_an_object() {
        for (text, found) in [("[]", "an array"), ("1", "an integer"), ("", "no value")] {
            assert_eq!(
                object(text, 0, ["a"]),
                Err(LayoutError::WrongType {
                    expected: "an object",
                    found
                })
            );
        }
    }

    /// The elements, at most 100: a broken walk that never ends fails the
    /// test instead of filling memory.
    fn elements(text: &str, base: usize) -> Vec<Result<Member<'_>, LayoutError>> {
        array(text, base).unwrap().take(100).collect()
    }

    #[test]
    fn an_arrays_elements_are_found_where_they_are_written() {
        assert_eq!(
            elements(r#"[1,"a",[2,3],{"b":[]}]"#, 5),
            [
                Ok(Member { at: 6, text: "1" }),
                Ok(Member {
                    at: 8,
                    text: "\"a\""
                }),
                Ok(Member {
                    at: 12,
                    text: "[2,3]"
                }),
                Ok(Member {
                    at: 18,
                    text: r#"{"b":[]}"#
                }),
            ]
        );
        assert_eq!(elements("[]", 0), []);
        assert_eq!(elements("[[]]", 0), [Ok(Member { at: 1, text: "[]" })]);
    }

    #[test]
    fn an_array_is_laid_out_canonically() {
        let at = |at| Err(LayoutError::NotCanonical { at });
        assert_eq!(elements("[ 1]", 10), [at(11)]);
        assert_eq!(elements("[1 ]", 10), [at(12)]);
        assert_eq!(
            elements("[1, 2]", 10),
            [Ok(Member { at: 11, text: "1" }), at(13)]
        );
        assert_eq!(elements("[ ]", 10), [at(11)]);
        assert_eq!(
            elements("[1] ", 10),
            [Ok(Member { at: 11, text: "1" }), at(13)]
        );
        assert_eq!(elements("[] ", 10), [at(12)]);
        assert_eq!(elements("[1,", 10).len(), 2);
        assert_eq!(
            array(" []", 10).unwrap_err(),
            LayoutError::NotCanonical { at: 10 }
        );
        assert_eq!(
            array("{}", 0).unwrap_err(),
            LayoutError::WrongType {
                expected: "an array",
                found: "an object"
            }
        );
    }

    #[test]
    fn write_canonical_appends() {
        let mut out = String::from("x");
        write_canonical(&Value::Array(vec![Value::Int(1), Value::Null]), &mut out);
        assert_eq!(out, "x[1,null]");
    }

    #[test]
    fn first_difference_finds_the_first_byte_that_differs() {
        assert_eq!(first_difference(b"abc", b"abd"), 2);
        assert_eq!(first_difference(b"ab", b"abc"), 2);
        assert_eq!(first_difference(b"abc", b"ab"), 2);
        assert_eq!(first_difference(b"", b"a"), 0);
        assert_eq!(first_difference(b"same", b"same"), 4);
    }
}
