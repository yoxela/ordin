// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! A tree as a JSON value, with every default left out.

use std::collections::{BTreeMap, BTreeSet};

use ordin_core::json::Value;
use ordin_core::{Account, Mode};

use crate::caps::{Capabilities, LinuxCap};
use crate::model::{DIR_MODE, Entry, FILE_MODE, Kind};
use crate::xattr::{Xattrs, base64_encode};

fn s(text: impl ToString) -> Value {
    Value::Str(text.to_string())
}

/// Adds the owner and group unless they are `root`.
fn owner(o: &mut BTreeMap<String, Value>, owner: &Account, group: &Account) {
    if !owner.is_root() {
        o.insert("owner".into(), s(owner));
    }
    if !group.is_root() {
        o.insert("group".into(), s(group));
    }
}

/// Adds the mode unless it is the type's default.
fn mode(o: &mut BTreeMap<String, Value>, mode: Mode, default: Mode) {
    if mode != default {
        o.insert("mode".into(), s(mode));
    }
}

/// Adds the attributes unless there are none.
fn xattrs(o: &mut BTreeMap<String, Value>, xattrs: &Xattrs) {
    if !xattrs.is_empty() {
        let map = xattrs
            .iter()
            .map(|(name, value)| (name.to_string(), s(base64_encode(value))))
            .collect();
        o.insert("xattrs".into(), Value::Object(map));
    }
}

fn cap_set(o: &mut BTreeMap<String, Value>, key: &str, set: &BTreeSet<LinuxCap>) {
    if !set.is_empty() {
        o.insert(key.into(), Value::Array(set.iter().map(s).collect()));
    }
}

fn capabilities(caps: &Capabilities) -> Value {
    let mut o = BTreeMap::new();
    cap_set(&mut o, "permitted", &caps.permitted);
    cap_set(&mut o, "inheritable", &caps.inheritable);
    if caps.effective {
        o.insert("effective".into(), Value::Bool(true));
    }
    Value::Object(o)
}

pub(crate) fn entry(e: &Entry) -> Value {
    let mut o = BTreeMap::new();
    o.insert("path".into(), s(&e.path));
    o.insert("type".into(), s(e.kind.type_name()));
    match &e.kind {
        Kind::File(f) => {
            mode(&mut o, f.mode, FILE_MODE);
            owner(&mut o, &f.owner, &f.group);
            // Sizes above 2⁵³−1 are refused before encoding.
            o.insert(
                "size".into(),
                Value::Int(i64::try_from(f.size).unwrap_or(i64::MAX)),
            );
            o.insert("content".into(), s(f.content));
            o.insert("fsverity".into(), s(f.fsverity));
            xattrs(&mut o, &f.xattrs);
            if let Some(caps) = &f.capabilities {
                o.insert("capabilities".into(), capabilities(caps));
            }
        }
        Kind::Dir(d) => {
            mode(&mut o, d.mode, DIR_MODE);
            owner(&mut o, &d.owner, &d.group);
            xattrs(&mut o, &d.xattrs);
        }
        Kind::Symlink(l) => {
            o.insert("target".into(), s(&l.target));
            owner(&mut o, &l.owner, &l.group);
        }
        Kind::HardLink(target) => {
            o.insert("target".into(), s(target));
        }
    }
    Value::Object(o)
}

/// The tree's canonical text, written one entry at a time.
pub(crate) fn text(entries: &[Entry]) -> String {
    let mut out = String::from("{\"entries\":[");
    for (i, e) in entries.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        ordin_core::json::write_canonical(&entry(e), &mut out);
    }
    out.push_str("],\"ordin-tree\":1}");
    out
}

/// The tree's JSON value: the encoding before [`text`], kept for the tests
/// to compare with.
#[cfg(test)]
pub(crate) fn tree(entries: &[Entry]) -> Value {
    let mut o = BTreeMap::new();
    o.insert("ordin-tree".into(), Value::Int(1));
    o.insert(
        "entries".into(),
        Value::Array(entries.iter().map(entry).collect()),
    );
    Value::Object(o)
}
