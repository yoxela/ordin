// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Encoding a [`Manifest`] as a JSON value: defaults left out, sets
//! sorted, and ignorable fields put back where they were.

use std::collections::BTreeMap;
use std::fmt::Display;

use crate::error::Segment;
use crate::json::Value;
use crate::model::*;

/// Builds an object, leaving out fields that are `None`.
#[derive(Default)]
struct Obj(BTreeMap<String, Value>);

impl Obj {
    fn put(mut self, key: &str, value: impl Into<Option<Value>>) -> Self {
        if let Some(v) = value.into() {
            self.0.insert(key.to_owned(), v);
        }
        self
    }

    fn build(self) -> Option<Value> {
        (!self.0.is_empty()).then_some(Value::Object(self.0))
    }

    fn value(self) -> Value {
        Value::Object(self.0)
    }
}

fn s(text: impl Display) -> Value {
    Value::Str(text.to_string())
}

fn opt_s(text: Option<impl Display>) -> Option<Value> {
    text.map(s)
}

/// A set: the items' text, sorted and without duplicates, or nothing.
fn set<T: Display>(items: &[T]) -> Option<Value> {
    let mut texts: Vec<String> = items.iter().map(ToString::to_string).collect();
    texts.sort();
    texts.dedup();
    (!texts.is_empty()).then(|| Value::Array(texts.into_iter().map(Value::Str).collect()))
}

/// An array of objects, sorted by `key`, or nothing.
fn sorted<T>(
    items: &[T],
    key: impl Fn(&T) -> String,
    encode: impl Fn(&T) -> Value,
) -> Option<Value> {
    let mut items: Vec<&T> = items.iter().collect();
    items.sort_by_key(|i| key(i));
    (!items.is_empty()).then(|| Value::Array(items.into_iter().map(encode).collect()))
}

fn list<T>(items: &[T], encode: impl Fn(&T) -> Value) -> Option<Value> {
    (!items.is_empty()).then(|| Value::Array(items.iter().map(encode).collect()))
}

fn flag(value: bool, default: bool) -> Option<Value> {
    (value != default).then_some(Value::Bool(value))
}

fn int(n: i64) -> Value {
    Value::Int(n)
}

fn uint(n: u64) -> Value {
    Value::Int(i64::try_from(n).unwrap_or(i64::MAX))
}

fn unless<T: PartialEq>(value: T, default: T, encode: impl Fn(T) -> Value) -> Option<Value> {
    (value != default).then(|| encode(value))
}

fn map<K: Display, V>(entries: &BTreeMap<K, V>, encode: impl Fn(&V) -> Value) -> Option<Value> {
    (!entries.is_empty()).then(|| {
        Value::Object(
            entries
                .iter()
                .map(|(k, v)| (k.to_string(), encode(v)))
                .collect(),
        )
    })
}

/// Encodes a manifest.
pub(crate) fn manifest(m: &Manifest) -> Value {
    let version = Obj::default()
        .put("epoch", unless(m.version.epoch(), 0, |n| int(i64::from(n))))
        .put("upstream", s(m.version.upstream()))
        .put("release", opt_s(m.version.release()))
        .put(
            "update",
            unless(m.version.update(), 0, |n| int(i64::from(n))),
        )
        .value();
    let license = Obj::default()
        .put("spdx", s(&m.license.spdx))
        .put(
            "presentation",
            unless(m.license.presentation, Presentation::Informational, |p| {
                s(p.as_str())
            }),
        )
        .put("texts", map(&m.license.texts, |d| s(d)))
        .value();
    let source = m.source.as_ref().map(|src| {
        Obj::default()
            .put("repo", s(&src.repo))
            .put("rev", s(&src.rev))
            .put("recipe", s(src.recipe))
            .value()
    });
    let provenance = m.provenance.as_ref().and_then(|p| {
        Obj::default()
            .put("slsa", opt_s(p.slsa))
            .put("sbom", opt_s(p.sbom))
            .build()
    });
    let facets = map(&m.facets, |f| {
        Obj::default()
            .put("tree", s(f.tree))
            .put("size", uint(f.size))
            .put("default", flag(f.default, true))
            .value()
    });
    let requires_at = Obj::default()
        .put("apply", set(&m.requires_apply))
        .put("boot", set(&m.requires_boot))
        .build();
    let updates = map(&m.removes, |paths| {
        set(paths).unwrap_or(Value::Array(Vec::new()))
    })
    .map(|removes| Obj::default().put("removes", removes).value());
    let switch = Obj::default()
        .put("live-apply", flag(m.live_apply, false))
        .put("boot-critical", flag(m.boot_critical, false))
        .build();
    let support = m.support.as_ref().map(|sp| {
        Obj::default()
            .put("active-until", s(sp.active_until))
            .put("security-until", s(sp.security_until))
            .put("successor", opt_s(sp.successor.as_ref()))
            .value()
    });
    let mut value = Obj::default()
        .put("ordin", int(1))
        .put("name", s(&m.name))
        .put("version", version)
        .put("kind", s(m.kind.as_str()))
        .put("arch", s(m.arch))
        .put("summary", s(&m.summary))
        .put("description", opt_s(m.description.as_ref()))
        .put("homepage", opt_s(m.homepage.as_ref()))
        .put("license", license)
        .put("source", source)
        .put("provenance", provenance)
        .put("facets", facets)
        .put("provides", set(&m.provides))
        .put("requires", set(&m.requires))
        .put("conflicts", set(&m.conflicts))
        .put("recommends", set(&m.recommends))
        .put("supplements", set(&m.supplements))
        .put("requires-at", requires_at)
        .put("obsoletes", set(&m.obsoletes))
        .put("replaces", set(&m.replaces))
        .put("updates", updates)
        .put("declares", declares(&m.declares))
        .put("state", m.state.as_ref().map(state))
        .put(
            "settings",
            sorted(&m.settings, |x| x.name.to_string(), setting),
        )
        .put(
            "hooks",
            map(&m.hooks, |steps| {
                list(steps, step).unwrap_or(Value::Array(Vec::new()))
            }),
        )
        .put("tests", sorted(&m.tests, |t| t.name.to_string(), test))
        .put("security", m.security.as_ref().and_then(security))
        .put("delegated", m.delegated.as_ref().map(delegated))
        .put("switch", switch)
        .put("support", support)
        .put("abi", map(&m.abi, |d| s(d)))
        .put("fixes", set(&m.fixes))
        .put(
            "notices",
            sorted(
                &m.notices,
                |n| n.id.to_string(),
                |n| {
                    Obj::default()
                        .put("id", s(&n.id))
                        .put("text", s(&n.text))
                        .value()
                },
            ),
        )
        .put("ignorable", set(&m.ignorable))
        .value();
    for (at, ignored) in &m.ignored {
        insert(&mut value, at, ignored.clone());
    }
    value
}

/// Puts `new` back at `at` inside `value`, if the place still exists.
fn insert(value: &mut Value, at: &[Segment], new: Value) {
    let Some((last, parents)) = at.split_last() else {
        return;
    };
    let mut here = value;
    for segment in parents {
        let next = match (segment, here) {
            (Segment::Key(k) | Segment::Entry(k), Value::Object(m)) => m.get_mut(k),
            (Segment::Index(i), Value::Array(a)) => a.get_mut(*i),
            _ => None,
        };
        let Some(next) = next else {
            return;
        };
        here = next;
    }
    if let (Segment::Key(k) | Segment::Entry(k), Value::Object(m)) = (last, here) {
        m.insert(k.clone(), new);
    }
}

fn declares(d: &Declares) -> Option<Value> {
    Obj::default()
        .put(
            "users",
            sorted(
                &d.users,
                |u| u.name.to_string(),
                |u| {
                    Obj::default()
                        .put("name", s(&u.name))
                        .put("system", flag(u.system, true))
                        .put("home", opt_s(u.home.as_ref()))
                        .put("shell", opt_s(u.shell.as_ref()))
                        .put("groups", set(&u.groups))
                        .put("comment", opt_s(u.comment.as_ref()))
                        .value()
                },
            ),
        )
        .put(
            "groups",
            sorted(
                &d.groups,
                |g| g.name.to_string(),
                |g| {
                    Obj::default()
                        .put("name", s(&g.name))
                        .put("system", flag(g.system, true))
                        .value()
                },
            ),
        )
        .put(
            "units",
            sorted(
                &d.units,
                |u| u.name.to_string(),
                |u| {
                    Obj::default()
                        .put("name", s(&u.name))
                        .put("preset", s(u.preset.as_str()))
                        .put(
                            "if",
                            u.condition.as_ref().map(|c| match &c.value {
                                Some(v) => s(format!("setting.{} = {v}", c.setting)),
                                None => s(format!("setting.{}", c.setting)),
                            }),
                        )
                        .value()
                },
            ),
        )
        .put(
            "config",
            sorted(
                &d.config,
                |c| c.target.to_string(),
                |c| {
                    Obj::default()
                        .put("default", s(&c.default))
                        .put("target", s(&c.target))
                        .put("merge", unless(c.merge, Merge::DropIn, |m| s(m.as_str())))
                        .value()
                },
            ),
        )
        .put(
            "alternatives",
            sorted(
                &d.alternatives,
                |a| a.name.clone(),
                |a| {
                    Obj::default()
                        .put("name", s(&a.name))
                        .put("link", s(&a.link))
                        .put("target", s(&a.target))
                        .put("priority", int(a.priority))
                        .put(
                            "followers",
                            sorted(
                                &a.followers,
                                |f| f.link.to_string(),
                                |f| {
                                    Obj::default()
                                        .put("link", s(&f.link))
                                        .put("target", s(&f.target))
                                        .value()
                                },
                            ),
                        )
                        .value()
                },
            ),
        )
        .put(
            "triggers",
            list(&d.triggers, |t| {
                Obj::default()
                    .put("paths", set(&t.paths))
                    .put("action", s(&t.action))
                    .value()
            }),
        )
        .put("setuid", set(&d.setuid))
        .put(
            "boot",
            d.boot.as_ref().and_then(|b| {
                Obj::default()
                    .put("kernel", opt_s(b.kernel.as_ref()))
                    .put("uki", flag(b.uki, false))
                    .put("initrd-extensions", set(&b.initrd_extensions))
                    .build()
            }),
        )
        .build()
}

fn owner(o: Obj, owner: &crate::text::Account, group: &crate::text::Account) -> Obj {
    let root = |a: &crate::text::Account| (a.as_str() != "root").then(|| s(a));
    o.put("owner", root(owner)).put("group", root(group))
}

fn mode(m: crate::text::Mode, default: u16) -> Option<Value> {
    (m.value() != default).then(|| s(m))
}

fn state(st: &State) -> Value {
    Obj::default()
        .put("version", unless(st.version, 0, uint))
        .put(
            "migration",
            unless(st.migration, Migration::None, |m| s(m.as_str())),
        )
        .put(
            "paths",
            sorted(
                &st.paths,
                |p| p.path.to_string(),
                |p| {
                    owner(
                        Obj::default()
                            .put("path", s(&p.path))
                            .put("class", s(p.class.as_str())),
                        &p.owner,
                        &p.group,
                    )
                    .put("mode", mode(p.mode, 0o755))
                    .put("flush", unless(p.flush, Flush::Never, |f| s(f.as_str())))
                    .put("recurse", flag(p.recurse, false))
                    .put("on-remove", p.on_remove.map(|r| s(r.as_str())))
                    .value()
                },
            ),
        )
        .put(
            "files",
            sorted(
                &st.files,
                |f| f.path.to_string(),
                |f| {
                    owner(Obj::default().put("path", s(&f.path)), &f.owner, &f.group)
                        .put("mode", mode(f.mode, 0o644))
                        .value()
                },
            ),
        )
        .put(
            "seeds",
            sorted(
                &st.seeds,
                |x| x.path.to_string(),
                |x| {
                    Obj::default()
                        .put("path", s(&x.path))
                        .put("from", s(&x.from))
                        .value()
                },
            ),
        )
        .put("obsolete", set(&st.obsolete))
        .put(
            "migrations",
            sorted(
                &st.migrations,
                |m| format!("{:020}", m.from),
                |m| {
                    let o = Obj::default()
                        .put("from", uint(m.from))
                        .put("to", uint(m.to));
                    match &m.action {
                        MigrationAction::Ops(ops) => o.put("ops", list(ops, migration_op)),
                        MigrationAction::Run { run, reverse } => o
                            .put("run", s(run))
                            .put(
                                "reversibility",
                                s(if reverse.is_some() {
                                    "reversible"
                                } else {
                                    "irreversible"
                                }),
                            )
                            .put("reverse", opt_s(reverse.as_ref())),
                    }
                    .value()
                },
            ),
        )
        .value()
}

fn migration_op(op: &MigrationOp) -> Value {
    match op {
        MigrationOp::Rename { path, to } => Obj::default().put("rename", s(path)).put("to", s(to)),
        MigrationOp::Move { path, to } => Obj::default().put("move", s(path)).put("to", s(to)),
        MigrationOp::Link { path, to } => Obj::default().put("link", s(path)).put("to", s(to)),
        MigrationOp::Remove { path } => Obj::default().put("remove", s(path)),
        MigrationOp::Chown { path, owner, group } => Obj::default()
            .put("chown", s(path))
            .put("owner", opt_s(owner.as_ref()))
            .put("group", opt_s(group.as_ref())),
    }
    .value()
}

fn setting(x: &Setting) -> Value {
    let default = x.default.as_ref().map(|d| match d {
        SettingValue::Bool(b) => Value::Bool(*b),
        SettingValue::Int(n) => int(*n),
        SettingValue::Str(t) => s(t),
        SettingValue::List(items) if x.kind == SettingType::Multichoice => {
            set(items).unwrap_or(Value::Array(Vec::new()))
        }
        SettingValue::List(items) => Value::Array(items.iter().map(s).collect()),
    });
    Obj::default()
        .put("name", s(&x.name))
        .put("type", s(x.kind.as_str()))
        .put("default", default)
        .put("required", flag(x.required, false))
        .put("description", opt_s(x.description.as_ref()))
        .put("min", x.min.map(int))
        .put("max", x.max.map(int))
        .put("pattern", opt_s(x.pattern.as_ref()))
        .put("choices", set(&x.choices))
        .put("aliases", map(&x.aliases, |v| s(v)))
        .value()
}

fn command(exec: &[String]) -> Value {
    Value::Array(exec.iter().map(s).collect())
}

fn step(x: &Step) -> Value {
    Obj::default()
        .put("exec", command(&x.exec))
        .put("timeout", unless(x.timeout, 300, uint))
        .put("writes", set(&x.writes))
        .put("network", flag(x.network, false))
        .put("execs", set(&x.execs))
        .put("legacy", flag(x.legacy, false))
        .value()
}

fn test(t: &Test) -> Value {
    Obj::default()
        .put("name", s(&t.name))
        .put("exec", command(&t.exec))
        .put("timeout", unless(t.timeout, 60, uint))
        .value()
}

fn security(sec: &Security) -> Option<Value> {
    let selinux = sec.selinux.as_ref().and_then(|x| {
        Obj::default()
            .put("modules", set(&x.modules))
            .put("booleans", map(&x.booleans, |b| Value::Bool(*b)))
            .put(
                "ports",
                list(&x.ports, |p| {
                    Obj::default()
                        .put("type", s(&p.kind))
                        .put("proto", s(p.proto.as_str()))
                        .put("port", int(i64::from(p.port)))
                        .value()
                }),
            )
            .put(
                "fcontexts",
                list(&x.fcontexts, |f| {
                    Obj::default()
                        .put("pattern", s(&f.pattern))
                        .put("type", s(&f.kind))
                        .put(
                            "file-type",
                            unless(f.file_type, FileType::All, |t| s(t.as_str())),
                        )
                        .value()
                }),
            )
            .build()
    });
    let apparmor = sec.apparmor.as_ref().and_then(|x| {
        Obj::default()
            .put("profiles", set(&x.profiles))
            .put("tunables", map(&x.tunables, |v| s(v)))
            .build()
    });
    Obj::default()
        .put("selinux", selinux)
        .put("apparmor", apparmor)
        .build()
}

fn delegated(d: &Delegated) -> Value {
    Obj::default()
        .put(
            "authority",
            Obj::default()
                .put("kind", s(&d.authority.0))
                .put("exec", s(&d.authority.1))
                .value(),
        )
        .put("paths", set(&d.paths))
        .put("initial", s(format!("facet:{}", d.initial)))
        .put(
            "identify",
            list(&d.identify, |i| {
                let mut o = Obj::default().put("method", s(&i.method));
                for (k, v) in &i.fields {
                    o = o.put(k, v.clone());
                }
                o.value()
            }),
        )
        .put("require", s(d.require.as_str()))
        .put("on-insufficient", s(d.on_insufficient.as_str()))
        .put(
            "payload-on-upgrade",
            unless(d.payload_on_upgrade, PayloadOnUpgrade::KeepNewer, |p| {
                s(p.as_str())
            }),
        )
        .value()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(text: &str) -> Value {
        crate::json::parse(text).unwrap()
    }

    #[test]
    fn insert_puts_a_value_where_it_was_and_nowhere_else() {
        let key = |k: &str| Segment::Key(k.to_owned());
        let mut v = object(r#"{"a":[{"b":1}],"m":{"x":{}}}"#);
        insert(
            &mut v,
            &[key("a"), Segment::Index(0), key("c")],
            Value::Int(2),
        );
        insert(
            &mut v,
            &[key("m"), Segment::Entry("x".into()), key("d")],
            Value::Bool(true),
        );
        assert_eq!(
            crate::json::canonical(&v),
            r#"{"a":[{"b":1,"c":2}],"m":{"x":{"d":true}}}"#
        );
        // Paths that no longer exist, or lead through the wrong kind of
        // value, change nothing.
        let before = v.clone();
        insert(&mut v, &[], Value::Null);
        insert(&mut v, &[key("gone"), key("c")], Value::Null);
        insert(
            &mut v,
            &[key("a"), Segment::Index(5), key("c")],
            Value::Null,
        );
        insert(&mut v, &[key("a"), key("b")], Value::Null);
        insert(&mut v, &[key("a"), Segment::Index(0)], Value::Null);
        insert(&mut v, &[key("a"), key("x"), key("c")], Value::Null);
        assert_eq!(v, before);
    }
}
