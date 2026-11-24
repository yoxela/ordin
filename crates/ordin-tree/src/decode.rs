// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Reads a tree's JSON value, refusing anything the encoder wouldn't
//! write: unknown fields, defaults written out, unsorted sets, and
//! values of the wrong type.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use ordin_core::json::Value;
use ordin_core::{Account, Algorithm, Digest, Mode};

use crate::caps::{Capabilities, LinuxCap};
use crate::error::{Error, ErrorKind};
use crate::model::{DIR_MODE, Dir, Entry, FILE_MODE, File, Kind, Symlink};
use crate::path::TreePath;
use crate::xattr::{XattrName, Xattrs, base64_decode};

type R<T> = Result<T, Error>;

/// One entry's object, with the fields read so far.
struct Obj<'a> {
    index: usize,
    path: Option<&'a str>,
    map: &'a BTreeMap<String, Value>,
}

impl<'a> Obj<'a> {
    fn err(&self, field: &str, kind: ErrorKind) -> Error {
        Error::entry(self.index, self.path, Some(field), kind)
    }

    fn get(&self, field: &str) -> Option<&'a Value> {
        self.map.get(field)
    }

    fn req(&self, field: &str) -> R<&'a Value> {
        self.get(field)
            .ok_or_else(|| self.err(field, ErrorKind::Missing))
    }

    fn string(&self, field: &str, v: &'a Value) -> R<&'a str> {
        match v {
            Value::Str(text) => Ok(text),
            other => Err(self.wrong(field, "a string", other)),
        }
    }

    fn wrong(&self, field: &str, expected: &'static str, found: &Value) -> Error {
        self.err(
            field,
            ErrorKind::WrongType {
                expected,
                found: found.type_name(),
            },
        )
    }

    /// Parses a string field with `T`'s grammar.
    fn parse<T: FromStr>(&self, field: &str, v: &'a Value) -> R<T>
    where
        T::Err: std::fmt::Display,
    {
        self.string(field, v)?
            .parse()
            .map_err(|e: T::Err| self.err(field, ErrorKind::Invalid(e.to_string())))
    }

    /// Refuses any field outside `allowed`.
    fn only(&self, allowed: &[&str]) -> R<()> {
        match self.map.keys().find(|k| !allowed.contains(&k.as_str())) {
            Some(unknown) => Err(self.err(unknown, ErrorKind::UnknownField)),
            None => Ok(()),
        }
    }

    fn account(&self, field: &str) -> R<Account> {
        match self.get(field) {
            None => Ok(Account::root()),
            Some(v) => {
                let a: Account = self.parse(field, v)?;
                if a.is_root() {
                    return Err(self.err(field, ErrorKind::DefaultValue));
                }
                Ok(a)
            }
        }
    }

    fn mode(&self, default: Mode) -> R<Mode> {
        match self.get("mode") {
            None => Ok(default),
            Some(v) => {
                let m: Mode = self.parse("mode", v)?;
                if m == default {
                    return Err(self.err("mode", ErrorKind::DefaultValue));
                }
                Ok(m)
            }
        }
    }

    fn digest(&self, field: &str, algorithm: Algorithm) -> R<Digest> {
        let d: Digest = self.parse(field, self.req(field)?)?;
        if d.algorithm() != algorithm {
            return Err(self.err(
                field,
                ErrorKind::WrongAlgorithm {
                    expected: algorithm,
                },
            ));
        }
        Ok(d)
    }

    fn size(&self) -> R<u64> {
        match self.req("size")? {
            Value::Int(n) => u64::try_from(*n).map_err(|_| {
                self.err(
                    "size",
                    ErrorKind::Invalid("a size can't be negative".into()),
                )
            }),
            other => Err(self.wrong("size", "an integer", other)),
        }
    }

    fn xattrs(&self) -> R<Xattrs> {
        let Some(v) = self.get("xattrs") else {
            return Ok(Xattrs::new());
        };
        let Value::Object(map) = v else {
            return Err(self.wrong("xattrs", "an object", v));
        };
        if map.is_empty() {
            return Err(self.err("xattrs", ErrorKind::DefaultValue));
        }
        let mut out = Xattrs::new();
        for (name, value) in map {
            let field = format!("xattrs.{name}");
            let name: XattrName = name
                .parse()
                .map_err(|e: String| self.err(&field, ErrorKind::Invalid(e)))?;
            let text = self.string(&field, value)?;
            let bytes = base64_decode(text).map_err(|e| self.err(&field, ErrorKind::Invalid(e)))?;
            out.insert(name, bytes);
        }
        Ok(out)
    }

    fn capabilities(&self) -> R<Option<Capabilities>> {
        let Some(v) = self.get("capabilities") else {
            return Ok(None);
        };
        let Value::Object(map) = v else {
            return Err(self.wrong("capabilities", "an object", v));
        };
        if let Some(unknown) = map
            .keys()
            .find(|k| !["permitted", "inheritable", "effective"].contains(&k.as_str()))
        {
            return Err(self.err(&format!("capabilities.{unknown}"), ErrorKind::UnknownField));
        }
        let effective = match map.get("effective") {
            None => false,
            Some(Value::Bool(true)) => true,
            Some(Value::Bool(false)) => {
                return Err(self.err("capabilities.effective", ErrorKind::DefaultValue));
            }
            Some(other) => return Err(self.wrong("capabilities.effective", "a boolean", other)),
        };
        let caps = Capabilities {
            permitted: self.cap_set(map, "permitted")?,
            inheritable: self.cap_set(map, "inheritable")?,
            effective,
        };
        if caps.is_empty() {
            return Err(self.err("capabilities", ErrorKind::EmptyCapabilities));
        }
        Ok(Some(caps))
    }

    fn cap_set(&self, map: &BTreeMap<String, Value>, key: &str) -> R<BTreeSet<LinuxCap>> {
        let field = format!("capabilities.{key}");
        let Some(v) = map.get(key) else {
            return Ok(BTreeSet::new());
        };
        let Value::Array(items) = v else {
            return Err(self.wrong(&field, "an array", v));
        };
        if items.is_empty() {
            return Err(self.err(&field, ErrorKind::DefaultValue));
        }
        let mut caps = Vec::with_capacity(items.len());
        for item in items {
            caps.push(self.parse::<LinuxCap>(&field, item)?);
        }
        if !caps.is_sorted_by(|a, b| a < b) {
            return Err(self.err(
                &field,
                ErrorKind::Invalid("capabilities are sorted by name, without repeats".into()),
            ));
        }
        Ok(caps.into_iter().collect())
    }
}

const FILE_FIELDS: [&str; 10] = [
    "path",
    "type",
    "mode",
    "owner",
    "group",
    "size",
    "content",
    "fsverity",
    "xattrs",
    "capabilities",
];
const DIR_FIELDS: [&str; 6] = ["path", "type", "mode", "owner", "group", "xattrs"];
const SYMLINK_FIELDS: [&str; 5] = ["path", "type", "target", "owner", "group"];
const HARDLINK_FIELDS: [&str; 3] = ["path", "type", "target"];

pub(crate) fn entry(index: usize, v: &Value) -> R<Entry> {
    let Value::Object(map) = v else {
        return Err(Error::entry(
            index,
            None,
            None,
            ErrorKind::WrongType {
                expected: "an object",
                found: v.type_name(),
            },
        ));
    };
    let mut o = Obj {
        index,
        path: None,
        map,
    };
    let written = o.req("path")?;
    let path: TreePath = o.parse("path", written)?;
    o.path = Some(o.string("path", written)?);
    let kind = match o.string("type", o.req("type")?)? {
        "file" => {
            o.only(&FILE_FIELDS)?;
            Kind::File(File {
                mode: o.mode(FILE_MODE)?,
                owner: o.account("owner")?,
                group: o.account("group")?,
                size: o.size()?,
                content: o.digest("content", Algorithm::Blake3)?,
                fsverity: o.digest("fsverity", Algorithm::Sha256)?,
                xattrs: o.xattrs()?,
                capabilities: o.capabilities()?,
            })
        }
        "dir" => {
            o.only(&DIR_FIELDS)?;
            Kind::Dir(Dir {
                mode: o.mode(DIR_MODE)?,
                owner: o.account("owner")?,
                group: o.account("group")?,
                xattrs: o.xattrs()?,
            })
        }
        "symlink" => {
            o.only(&SYMLINK_FIELDS)?;
            Kind::Symlink(Symlink {
                target: o.parse("target", o.req("target")?)?,
                owner: o.account("owner")?,
                group: o.account("group")?,
            })
        }
        "hardlink" => {
            o.only(&HARDLINK_FIELDS)?;
            Kind::HardLink(o.parse("target", o.req("target")?)?)
        }
        other => return Err(o.err("type", ErrorKind::UnknownType(other.to_owned()))),
    };
    Ok(Entry { path, kind })
}

/// Reads a tree's entries from its JSON value, in the order written: the
/// reader before [`crate::read`], kept for the tests to compare with.
#[cfg(test)]
pub(crate) fn tree(v: &Value) -> R<Vec<Entry>> {
    let Value::Object(map) = v else {
        return Err(Error::tree(
            None,
            ErrorKind::WrongType {
                expected: "an object",
                found: v.type_name(),
            },
        ));
    };
    match map.get("ordin-tree") {
        None => return Err(Error::tree(Some("ordin-tree"), ErrorKind::Missing)),
        Some(Value::Int(1)) => {}
        Some(other) => {
            return Err(Error::tree(
                Some("ordin-tree"),
                ErrorKind::UnknownFormat(ordin_core::json::canonical(other)),
            ));
        }
    }
    if let Some(unknown) = map.keys().find(|k| *k != "ordin-tree" && *k != "entries") {
        return Err(Error::tree(Some(unknown), ErrorKind::UnknownField));
    }
    let items = match map.get("entries") {
        None => return Err(Error::tree(Some("entries"), ErrorKind::Missing)),
        Some(Value::Array(items)) => items,
        Some(other) => {
            return Err(Error::tree(
                Some("entries"),
                ErrorKind::WrongType {
                    expected: "an array",
                    found: other.type_name(),
                },
            ));
        }
    };
    // Refuse an oversized list before decoding any of it.
    if items.len() > crate::MAX_ENTRIES {
        return Err(Error::tree(
            Some("entries"),
            ErrorKind::TooManyEntries {
                max: crate::MAX_ENTRIES,
                len: items.len(),
            },
        ));
    }
    items.iter().enumerate().map(|(i, v)| entry(i, v)).collect()
}
