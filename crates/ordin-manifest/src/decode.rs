// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Decoding a JSON value into a [`Manifest`], checking every rule of
//! `SCHEMA.md` and naming the field that breaks one.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Display;
use std::str::FromStr;

use ordin_core::{Atom, Digest, Facet, FilePath, PackageName, Soname};
use ordin_depexpr::{Expr, Requirement};
use ordin_version::Version;

use crate::error::{Error, ErrorKind, Path, Segment};
use crate::json::Value;
use crate::model::*;
use crate::spdx;
use crate::text::{self, Date, Id, UnitName, Url};
use ordin_core::{Account, Mode};

type R<T> = Result<T, Error>;

fn err<T>(path: &Path, kind: ErrorKind) -> R<T> {
    Err(Error::at(path, kind))
}

fn invalid<T>(path: &Path, why: impl Display) -> R<T> {
    err(path, ErrorKind::Invalid(why.to_string()))
}

fn rule<T>(path: &Path, why: impl Display) -> R<T> {
    err(path, ErrorKind::Rule(why.to_string()))
}

/// State shared while decoding: what may be ignored, and what was.
pub(crate) struct Decoder {
    ignorable: BTreeSet<String>,
    ignored: Vec<(Vec<Segment>, Value)>,
    /// Every field path the decoder looked for, present or not.
    pub(crate) known: BTreeSet<String>,
}

/// An object being read: which of its keys were used.
struct Obj<'v> {
    path: Path,
    map: &'v BTreeMap<String, Value>,
    used: BTreeSet<&'static str>,
}

impl<'v> Obj<'v> {
    fn new(v: &'v Value, path: &Path) -> R<Self> {
        let Value::Object(map) = v else {
            return err(
                path,
                ErrorKind::WrongType {
                    expected: "an object",
                    found: v.type_name(),
                },
            );
        };
        if map.is_empty() {
            return err(path, ErrorKind::Empty);
        }
        Ok(Self {
            path: path.clone(),
            map,
            used: BTreeSet::new(),
        })
    }

    fn opt(&mut self, d: &mut Decoder, key: &'static str) -> Option<(&'v Value, Path)> {
        self.used.insert(key);
        d.known.insert(self.path.key(key).schema());
        self.map.get(key).map(|v| (v, self.path.key(key)))
    }

    fn req(&mut self, d: &mut Decoder, key: &'static str) -> R<(&'v Value, Path)> {
        match self.opt(d, key) {
            Some(found) => Ok(found),
            None => err(&self.path, ErrorKind::Missing(key)),
        }
    }

    /// Refuses unused keys, unless `ignorable` lists them; those are kept.
    fn finish(self, d: &mut Decoder) -> R<()> {
        for (key, value) in self.map {
            if self.used.contains(key.as_str()) {
                continue;
            }
            let at = self.path.key(key);
            if !d.ignorable.contains(&at.schema()) {
                return err(&at, ErrorKind::UnknownField(key.clone()));
            }
            d.ignored.push((at.0, value.clone()));
        }
        Ok(())
    }
}

/// The entries of an object used as a map, checked non-empty.
fn map<'v>(v: &'v Value, path: &Path) -> R<&'v BTreeMap<String, Value>> {
    match v {
        Value::Object(m) if m.is_empty() => err(path, ErrorKind::Empty),
        Value::Object(m) => Ok(m),
        other => err(
            path,
            ErrorKind::WrongType {
                expected: "an object",
                found: other.type_name(),
            },
        ),
    }
}

fn array<'v>(v: &'v Value, path: &Path) -> R<&'v [Value]> {
    match v {
        Value::Array(a) if a.is_empty() => err(path, ErrorKind::Empty),
        Value::Array(a) => Ok(a),
        other => err(
            path,
            ErrorKind::WrongType {
                expected: "an array",
                found: other.type_name(),
            },
        ),
    }
}

fn string<'v>(v: &'v Value, path: &Path) -> R<&'v str> {
    match v {
        Value::Str(s) => Ok(s),
        other => err(
            path,
            ErrorKind::WrongType {
                expected: "a string",
                found: other.type_name(),
            },
        ),
    }
}

fn integer(v: &Value, path: &Path) -> R<i64> {
    match v {
        Value::Int(n) => Ok(*n),
        other => err(
            path,
            ErrorKind::WrongType {
                expected: "an integer",
                found: other.type_name(),
            },
        ),
    }
}

fn unsigned(v: &Value, path: &Path) -> R<u64> {
    let n = integer(v, path)?;
    u64::try_from(n).or_else(|_| err(path, ErrorKind::OutOfRange(format!("{n} is negative"))))
}

fn boolean(v: &Value, path: &Path) -> R<bool> {
    match v {
        Value::Bool(b) => Ok(*b),
        other => err(
            path,
            ErrorKind::WrongType {
                expected: "a boolean",
                found: other.type_name(),
            },
        ),
    }
}

fn parse<T: FromStr>(v: &Value, path: &Path) -> R<T>
where
    T::Err: Display,
{
    string(v, path)?.parse().or_else(|e| invalid(path, e))
}

/// Parses text whose form must be canonical: `canonical` gives the form
/// it must be written in.
fn canonical<T>(
    v: &Value,
    path: &Path,
    read: impl Fn(&str) -> Result<T, String>,
    show: impl Fn(&T) -> String,
) -> R<T> {
    let text = string(v, path)?;
    let value = read(text).or_else(|e| invalid(path, e))?;
    let shown = show(&value);
    if shown != text {
        return err(path, ErrorKind::NotCanonicalText(shown));
    }
    Ok(value)
}

/// An optional boolean that must be left out when it has its default.
fn flag(o: &mut Obj<'_>, d: &mut Decoder, key: &'static str, default: bool) -> R<bool> {
    match o.opt(d, key) {
        Some((v, p)) => {
            let b = boolean(v, &p)?;
            if b == default {
                return err(&p, ErrorKind::DefaultValue);
            }
            Ok(b)
        }
        None => Ok(default),
    }
}

/// An optional enumerated value that must be left out at its default.
macro_rules! enum_field {
    ($o:expr, $d:expr, $key:literal, $ty:ty, $default:expr) => {{
        match $o.opt($d, $key) {
            Some((v, p)) => {
                let e = enum_value::<$ty>(v, &p, <$ty>::from_text, <$ty>::allowed)?;
                if Some(e) == $default {
                    return err(&p, ErrorKind::DefaultValue);
                }
                Some(e)
            }
            None => None,
        }
    }};
}

fn enum_value<T>(
    v: &Value,
    path: &Path,
    from: fn(&str) -> Option<T>,
    allowed: fn() -> String,
) -> R<T> {
    let text = string(v, path)?;
    from(text).map_or_else(
        || {
            err(
                path,
                ErrorKind::UnknownValue {
                    found: text.to_owned(),
                    allowed: allowed(),
                },
            )
        },
        Ok,
    )
}

/// A set: an array of strings in strictly ascending byte order.
fn set<T>(v: &Value, path: &Path, read: impl Fn(&Value, &Path) -> R<T>) -> R<Vec<T>> {
    let items = array(v, path)?;
    let mut out = Vec::with_capacity(items.len());
    let mut previous: Option<&str> = None;
    for (i, item) in items.iter().enumerate() {
        let at = path.index(i);
        let text = string(item, &at)?;
        if let Some(prev) = previous {
            match prev.cmp(text) {
                Ordering::Less => {}
                Ordering::Equal => return err(&at, ErrorKind::Duplicate(text.to_owned())),
                Ordering::Greater => {
                    return err(&at, ErrorKind::NotSorted(prev.to_owned(), text.to_owned()));
                }
            }
        }
        previous = Some(text);
        out.push(read(item, &at)?);
    }
    Ok(out)
}

/// An array of objects sorted strictly by a key each one has.
fn sorted<T>(
    v: &Value,
    path: &Path,
    read: impl FnMut(&Value, &Path) -> R<T>,
    key: impl Fn(&T) -> String,
) -> R<Vec<T>> {
    let items = array(v, path)?;
    let mut read = read;
    let mut out: Vec<T> = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let at = path.index(i);
        let value = read(item, &at)?;
        if let Some(prev) = out.last() {
            let (a, b) = (key(prev), key(&value));
            match a.cmp(&b) {
                Ordering::Less => {}
                Ordering::Equal => return err(&at, ErrorKind::Duplicate(b)),
                Ordering::Greater => return err(&at, ErrorKind::NotSorted(a, b)),
            }
        }
        out.push(value);
    }
    Ok(out)
}

fn path_value(v: &Value, p: &Path) -> R<FilePath> {
    parse(v, p)
}

fn paths(v: &Value, p: &Path) -> R<Vec<FilePath>> {
    set(v, p, path_value)
}

fn digest(v: &Value, p: &Path, allow_sha256: bool) -> R<Digest> {
    let d: Digest = parse(v, p)?;
    if d.algorithm() != ordin_core::Algorithm::Blake3 && !allow_sha256 {
        return invalid(
            p,
            "this digest must be BLAKE3; only provenance may use SHA-256",
        );
    }
    Ok(d)
}

fn free(v: &Value, p: &Path, max: usize, lines: bool) -> R<String> {
    let s = string(v, p)?;
    text::free_text(s, max, lines).or_else(|e| invalid(p, e))?;
    Ok(s.to_owned())
}

fn ascii(v: &Value, p: &Path, max: usize, what: &str) -> R<String> {
    let s = string(v, p)?;
    if s.is_empty() || s.len() > max {
        return err(
            p,
            ErrorKind::OutOfRange(format!("{what} is 1 to {max} bytes")),
        );
    }
    text::printable_ascii(s, what).or_else(|e| invalid(p, e))?;
    Ok(s.to_owned())
}

/// A git commit's full object name: 40 lowercase hex digits (SHA-1) or
/// 64 (SHA-256).
fn commit(v: &Value, p: &Path) -> R<String> {
    let s = string(v, p)?;
    let hex = s
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !matches!(s.len(), 40 | 64) || !hex {
        return invalid(
            p,
            format!("a git commit is 40 or 64 lowercase hex digits, not {s:?}"),
        );
    }
    Ok(s.to_owned())
}

/// A name drawn from a small grammar: `allowed` characters, 1 to `max`.
fn word(v: &Value, p: &Path, max: usize, allowed: fn(char) -> bool, what: &str) -> R<String> {
    let s = string(v, p)?;
    if s.is_empty() || s.len() > max || !s.chars().all(allowed) {
        return invalid(p, format!("{what} isn't valid: {s:?}"));
    }
    Ok(s.to_owned())
}

fn exprs(v: &Value, p: &Path) -> R<Vec<Expr>> {
    set(v, p, |item, at| {
        canonical(
            item,
            at,
            |t| t.parse::<Expr>().map_err(|e| e.to_string()),
            Expr::to_string,
        )
    })
}

impl Decoder {
    pub(crate) fn new() -> Self {
        Self {
            ignorable: BTreeSet::new(),
            ignored: Vec::new(),
            known: BTreeSet::new(),
        }
    }

    /// Decodes a manifest, after the JSON layer has read it.
    pub(crate) fn manifest(&mut self, v: &Value) -> R<Manifest> {
        let root = Path::default();
        let mut o = Obj::new(v, &root)?;
        // The format and `ignorable` first: they decide how the rest is read.
        let (format, p) = o.req(self, "ordin")?;
        let format = integer(format, &p)?;
        if format != 1 {
            return err(&p, ErrorKind::UnknownFormat(format));
        }
        let ignorable = match o.opt(self, "ignorable") {
            Some((v, p)) => set(v, &p, |item, at| {
                let s = ascii(item, at, 256, "an ignorable path")?;
                if s.split('.').any(str::is_empty) {
                    return invalid(at, format!("{s:?} isn't a dotted path"));
                }
                Ok(s)
            })?,
            None => Vec::new(),
        };
        self.ignorable = ignorable.iter().cloned().collect();

        let (name, p) = o.req(self, "name")?;
        let name: PackageName = parse(name, &p)?;
        let (version, p) = o.req(self, "version")?;
        let version = self.version(version, &p)?;
        let (kind, p) = o.req(self, "kind")?;
        let kind = enum_value(kind, &p, Kind::from_text, Kind::allowed)?;
        let (arch, p) = o.req(self, "arch")?;
        let arch = parse(arch, &p)?;
        let (summary, p) = o.req(self, "summary")?;
        let summary = free(summary, &p, 120, false)?;
        let description = o
            .opt(self, "description")
            .map(|(v, p)| free(v, &p, 4000, true))
            .transpose()?;
        let homepage: Option<Url> = o
            .opt(self, "homepage")
            .map(|(v, p)| parse(v, &p))
            .transpose()?;
        let (license, p) = o.req(self, "license")?;
        let license = self.license(license, &p)?;
        let source = o
            .opt(self, "source")
            .map(|(v, p)| self.source(v, &p))
            .transpose()?;
        let provenance = o
            .opt(self, "provenance")
            .map(|(v, p)| self.provenance(v, &p))
            .transpose()?;
        let (facets, p) = o.req(self, "facets")?;
        let facets_path = p.clone();
        let facets = self.facets(facets, &p)?;
        let provides = match o.opt(self, "provides") {
            Some((v, p)) => set(v, &p, provide)?,
            None => Vec::new(),
        };
        let relation = |o: &mut Obj<'_>, d: &mut Decoder, key: &'static str| -> R<Vec<Expr>> {
            o.opt(d, key)
                .map(|(v, p)| exprs(v, &p))
                .transpose()
                .map(Option::unwrap_or_default)
        };
        let requires = relation(&mut o, self, "requires")?;
        let conflicts = relation(&mut o, self, "conflicts")?;
        let recommends = relation(&mut o, self, "recommends")?;
        let supplements = relation(&mut o, self, "supplements")?;
        let (requires_apply, requires_boot) = match o.opt(self, "requires-at") {
            Some((v, p)) => {
                let mut r = Obj::new(v, &p)?;
                let apply = relation(&mut r, self, "apply")?;
                let boot = relation(&mut r, self, "boot")?;
                r.finish(self)?;
                (apply, boot)
            }
            None => (Vec::new(), Vec::new()),
        };
        let obsoletes = match o.opt(self, "obsoletes") {
            Some((v, p)) => {
                let list = exprs(v, &p)?;
                for (i, e) in list.iter().enumerate() {
                    if e.requirements()
                        .iter()
                        .any(|r| !matches!(r.atom, Atom::Package(_)) || !r.facets.is_empty())
                    {
                        return invalid(
                            &p.index(i),
                            "obsoletes names packages only, without facets",
                        );
                    }
                }
                list
            }
            None => Vec::new(),
        };
        let replaces = match o.opt(self, "replaces") {
            Some((v, p)) => set(v, &p, replace)?,
            None => Vec::new(),
        };
        let removes = match o.opt(self, "updates") {
            Some((v, p)) => self.updates(v, &p)?,
            None => BTreeMap::new(),
        };
        let declares = match o.opt(self, "declares") {
            Some((v, p)) => self.declares(v, &p)?,
            None => Declares::default(),
        };
        let state = o
            .opt(self, "state")
            .map(|(v, p)| self.state(v, &p))
            .transpose()?;
        let settings = match o.opt(self, "settings") {
            Some((v, p)) => sorted(
                v,
                &p,
                |item, at| self.setting(item, at),
                |s: &Setting| s.name.to_string(),
            )?,
            None => Vec::new(),
        };
        let hooks = match o.opt(self, "hooks") {
            Some((v, p)) => self.hooks(v, &p)?,
            None => BTreeMap::new(),
        };
        let tests = match o.opt(self, "tests") {
            Some((v, p)) => sorted(
                v,
                &p,
                |item, at| self.test(item, at),
                |t: &Test| t.name.to_string(),
            )?,
            None => Vec::new(),
        };
        let security = o
            .opt(self, "security")
            .map(|(v, p)| self.security(v, &p))
            .transpose()?;
        let delegated = o
            .opt(self, "delegated")
            .map(|(v, p)| self.delegated(v, &p))
            .transpose()?;
        let (live_apply, boot_critical) = match o.opt(self, "switch") {
            Some((v, p)) => {
                let mut s = Obj::new(v, &p)?;
                let live = flag(&mut s, self, "live-apply", false)?;
                let critical = flag(&mut s, self, "boot-critical", false)?;
                s.finish(self)?;
                (live, critical)
            }
            None => (false, false),
        };
        let support = o
            .opt(self, "support")
            .map(|(v, p)| self.support(v, &p))
            .transpose()?;
        let abi = match o.opt(self, "abi") {
            Some((v, p)) => {
                let mut out = BTreeMap::new();
                for (key, value) in map(v, &p)? {
                    let at = p.entry(key);
                    let soname: Soname = key.parse().or_else(|e| invalid(&at, e))?;
                    if soname.version_node().is_some() {
                        return invalid(&at, "abi keys are sonames without a version node");
                    }
                    out.insert(soname, digest(value, &at, false)?);
                }
                out
            }
            None => BTreeMap::new(),
        };
        let fixes = match o.opt(self, "fixes") {
            Some((v, p)) => set(v, &p, |item, at| ascii(item, at, 64, "a fix ID"))?,
            None => Vec::new(),
        };
        let notices = match o.opt(self, "notices") {
            Some((v, p)) => sorted(
                v,
                &p,
                |item, at| self.notice(item, at),
                |n: &Notice| n.id.to_string(),
            )?,
            None => Vec::new(),
        };
        o.finish(self)?;

        // Every ignorable path must name a field the format doesn't define.
        for (i, entry) in ignorable.iter().enumerate() {
            if crate::known::KNOWN_FIELDS
                .binary_search(&entry.as_str())
                .is_ok()
            {
                return err(
                    &root.key("ignorable").index(i),
                    ErrorKind::KnownIgnorable(entry.clone()),
                );
            }
        }

        let m = Manifest {
            name,
            version,
            kind,
            arch,
            summary,
            description,
            homepage,
            license,
            source,
            provenance,
            facets,
            provides,
            requires,
            conflicts,
            recommends,
            supplements,
            requires_apply,
            requires_boot,
            obsoletes,
            replaces,
            removes,
            declares,
            state,
            settings,
            hooks,
            tests,
            security,
            delegated,
            live_apply,
            boot_critical,
            support,
            abi,
            fixes,
            notices,
            ignorable,
            ignored: std::mem::take(&mut self.ignored),
        };
        check_rules(&m, &facets_path)?;
        Ok(m)
    }

    fn version(&mut self, v: &Value, p: &Path) -> R<Version> {
        let mut o = Obj::new(v, p)?;
        let small = |v: &Value, p: &Path, what: &str| -> R<u32> {
            let n = unsigned(v, p)?;
            if n == 0 {
                return err(p, ErrorKind::DefaultValue);
            }
            u32::try_from(n)
                .or_else(|_| err(p, ErrorKind::OutOfRange(format!("{what} fits in 32 bits"))))
        };
        let epoch = o
            .opt(self, "epoch")
            .map(|(v, p)| small(v, &p, "an epoch"))
            .transpose()?
            .unwrap_or(0);
        let (upstream, up) = o.req(self, "upstream")?;
        let upstream = string(upstream, &up)?;
        let (release, rp) = o.req(self, "release")?;
        let release = string(release, &rp)?;
        let update = o
            .opt(self, "update")
            .map(|(v, p)| small(v, &p, "an update level"))
            .transpose()?
            .unwrap_or(0);
        o.finish(self)?;
        Version::new(epoch, upstream, Some(release), update).or_else(|e| invalid(p, e))
    }

    fn license(&mut self, v: &Value, p: &Path) -> R<License> {
        let mut o = Obj::new(v, p)?;
        let (spdx_value, sp) = o.req(self, "spdx")?;
        let parsed = canonical(spdx_value, &sp, spdx::parse, spdx::Spdx::to_string)?;
        let presentation = enum_field!(
            o,
            self,
            "presentation",
            Presentation,
            Some(Presentation::Informational)
        )
        .unwrap_or(Presentation::Informational);
        let ids = parsed.text_ids();
        let mut texts = BTreeMap::new();
        // NOASSERTION and NONE have no texts, and an empty object is
        // refused, so `texts` is then left out.
        let texts_path = if ids.is_empty() {
            if let Some((_, tp)) = o.opt(self, "texts") {
                return rule(&tp, format!("{parsed} has no license texts"));
            }
            None
        } else {
            let (texts_value, tp) = o.req(self, "texts")?;
            for (id, value) in map(texts_value, &tp)? {
                texts.insert(id.clone(), digest(value, &tp.entry(id), false)?);
            }
            Some(tp)
        };
        o.finish(self)?;
        let keys: BTreeSet<String> = texts.keys().cloned().collect();
        if let Some(tp) = texts_path.filter(|_| ids != keys) {
            let missing: Vec<&String> = ids.difference(&keys).collect();
            let extra: Vec<&String> = keys.difference(&ids).collect();
            return rule(
                &tp,
                format!(
                    "texts must name exactly the IDs in spdx; missing {missing:?}, not in spdx {extra:?}"
                ),
            );
        }
        Ok(License {
            spdx: parsed.to_string(),
            presentation,
            texts,
        })
    }

    fn source(&mut self, v: &Value, p: &Path) -> R<Source> {
        let mut o = Obj::new(v, p)?;
        let (repo, rp) = o.req(self, "repo")?;
        let repo = parse(repo, &rp)?;
        let (rev, vp) = o.req(self, "rev")?;
        let rev = ascii(rev, &vp, 128, "a revision")?;
        let (recipe, cp) = o.req(self, "recipe")?;
        let recipe = digest(recipe, &cp, false)?;
        o.finish(self)?;
        Ok(Source { repo, rev, recipe })
    }

    fn provenance(&mut self, v: &Value, p: &Path) -> R<Provenance> {
        let mut o = Obj::new(v, p)?;
        let slsa = o
            .opt(self, "slsa")
            .map(|(v, p)| digest(v, &p, true))
            .transpose()?;
        let sbom = o
            .opt(self, "sbom")
            .map(|(v, p)| digest(v, &p, true))
            .transpose()?;
        let commit = o
            .opt(self, "commit")
            .map(|(v, p)| commit(v, &p))
            .transpose()?;
        o.finish(self)?;
        Ok(Provenance { slsa, sbom, commit })
    }

    fn facets(&mut self, v: &Value, p: &Path) -> R<BTreeMap<Facet, FacetEntry>> {
        let mut out = BTreeMap::new();
        for (key, value) in map(v, p)? {
            let at = p.entry(key);
            let facet: Facet = key.parse().or_else(|e| invalid(&at, e))?;
            let mut o = Obj::new(value, &at)?;
            let (tree, tp) = o.req(self, "tree")?;
            let tree = digest(tree, &tp, false)?;
            let (size, sp) = o.req(self, "size")?;
            let size = unsigned(size, &sp)?;
            let default = flag(&mut o, self, "default", true)?;
            o.finish(self)?;
            if facet.as_str() == "debug" && default {
                return rule(&at, "the debug facet must have \"default\": false");
            }
            out.insert(
                facet,
                FacetEntry {
                    tree,
                    size,
                    default,
                },
            );
        }
        Ok(out)
    }

    fn updates(&mut self, v: &Value, p: &Path) -> R<BTreeMap<Facet, Vec<FilePath>>> {
        let mut o = Obj::new(v, p)?;
        let (removes, rp) = o.req(self, "removes")?;
        let mut out = BTreeMap::new();
        for (key, value) in map(removes, &rp)? {
            let at = rp.entry(key);
            let facet: Facet = key.parse().or_else(|e| invalid(&at, e))?;
            out.insert(facet, paths(value, &at)?);
        }
        o.finish(self)?;
        Ok(out)
    }

    fn declares(&mut self, v: &Value, p: &Path) -> R<Declares> {
        let mut o = Obj::new(v, p)?;
        let mut d = Declares::default();
        if let Some((v, p)) = o.opt(self, "users") {
            d.users = sorted(
                v,
                &p,
                |item, at| self.user(item, at),
                |u: &User| u.name.to_string(),
            )?;
        }
        if let Some((v, p)) = o.opt(self, "groups") {
            d.groups = sorted(
                v,
                &p,
                |item, at| {
                    let mut g = Obj::new(item, at)?;
                    let (name, np) = g.req(self, "name")?;
                    let name = parse(name, &np)?;
                    let system = flag(&mut g, self, "system", true)?;
                    g.finish(self)?;
                    Ok(Group { name, system })
                },
                |g: &Group| g.name.to_string(),
            )?;
        }
        if let Some((v, p)) = o.opt(self, "units") {
            d.units = sorted(
                v,
                &p,
                |item, at| {
                    let mut u = Obj::new(item, at)?;
                    let (name, np) = u.req(self, "name")?;
                    let name: UnitName = parse(name, &np)?;
                    let (preset, pp) = u.req(self, "preset")?;
                    let preset = enum_value(preset, &pp, Preset::from_text, Preset::allowed)?;
                    let condition = u
                        .opt(self, "if")
                        .map(|(v, p)| condition(v, &p))
                        .transpose()?;
                    u.finish(self)?;
                    Ok(Unit {
                        name,
                        preset,
                        condition,
                    })
                },
                |u: &Unit| u.name.to_string(),
            )?;
        }
        if let Some((v, p)) = o.opt(self, "config") {
            d.config = sorted(
                v,
                &p,
                |item, at| {
                    let mut c = Obj::new(item, at)?;
                    let (default, dp) = c.req(self, "default")?;
                    let default = path_value(default, &dp)?;
                    let (target, tp) = c.req(self, "target")?;
                    let target = path_value(target, &tp)?;
                    let merge = enum_field!(c, self, "merge", Merge, Some(Merge::DropIn))
                        .unwrap_or(Merge::DropIn);
                    c.finish(self)?;
                    if !target.as_str().starts_with("/etc/") {
                        return rule(&tp, "a config target is under /etc");
                    }
                    Ok(Config {
                        default,
                        target,
                        merge,
                    })
                },
                |c: &Config| c.target.to_string(),
            )?;
        }
        if let Some((v, p)) = o.opt(self, "alternatives") {
            d.alternatives = sorted(
                v,
                &p,
                |item, at| self.alternative(item, at),
                |a: &Alternative| a.name.clone(),
            )?;
        }
        if let Some((v, p)) = o.opt(self, "triggers") {
            let items = array(v, &p)?;
            for (i, item) in items.iter().enumerate() {
                let at = p.index(i);
                let mut t = Obj::new(item, &at)?;
                let (trigger_paths, tp) = t.req(self, "paths")?;
                let trigger_paths = paths(trigger_paths, &tp)?;
                let (action, ap) = t.req(self, "action")?;
                let action = word(
                    action,
                    &ap,
                    64,
                    |c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-',
                    "a trigger action",
                )?;
                t.finish(self)?;
                d.triggers.push(Trigger {
                    paths: trigger_paths,
                    action,
                });
            }
        }
        if let Some((v, p)) = o.opt(self, "setuid") {
            d.setuid = paths(v, &p)?;
        }
        if let Some((v, p)) = o.opt(self, "boot") {
            let mut b = Obj::new(v, &p)?;
            let kernel = b
                .opt(self, "kernel")
                .map(|(v, p)| path_value(v, &p))
                .transpose()?;
            let uki = flag(&mut b, self, "uki", false)?;
            let initrd_extensions = b
                .opt(self, "initrd-extensions")
                .map(|(v, p)| paths(v, &p))
                .transpose()?
                .unwrap_or_default();
            b.finish(self)?;
            d.boot = Some(Boot {
                kernel,
                uki,
                initrd_extensions,
            });
        }
        o.finish(self)?;
        Ok(d)
    }

    fn user(&mut self, v: &Value, p: &Path) -> R<User> {
        let mut o = Obj::new(v, p)?;
        let (name, np) = o.req(self, "name")?;
        let name: Account = parse(name, &np)?;
        let system = flag(&mut o, self, "system", true)?;
        let home = o
            .opt(self, "home")
            .map(|(v, p)| path_value(v, &p))
            .transpose()?;
        let shell = o
            .opt(self, "shell")
            .map(|(v, p)| path_value(v, &p))
            .transpose()?;
        let groups = o
            .opt(self, "groups")
            .map(|(v, p)| set(v, &p, parse))
            .transpose()?
            .unwrap_or_default();
        let comment = match o.opt(self, "comment") {
            Some((v, p)) => {
                let c = free(v, &p, 64, false)?;
                if c.contains(':') {
                    return invalid(&p, "a user comment can't contain ':'");
                }
                Some(c)
            }
            None => None,
        };
        o.finish(self)?;
        Ok(User {
            name,
            system,
            home,
            shell,
            groups,
            comment,
        })
    }

    fn alternative(&mut self, v: &Value, p: &Path) -> R<Alternative> {
        let mut o = Obj::new(v, p)?;
        let (name, np) = o.req(self, "name")?;
        let name = word(
            name,
            &np,
            255,
            |c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '_' | '-'),
            "an alternative name",
        )?;
        let (link, lp) = o.req(self, "link")?;
        let link = path_value(link, &lp)?;
        let (target, tp) = o.req(self, "target")?;
        let target = path_value(target, &tp)?;
        let (priority, pp) = o.req(self, "priority")?;
        let priority = integer(priority, &pp)?;
        let followers = match o.opt(self, "followers") {
            Some((v, p)) => sorted(
                v,
                &p,
                |item, at| {
                    let mut f = Obj::new(item, at)?;
                    let (link, lp) = f.req(self, "link")?;
                    let link = path_value(link, &lp)?;
                    let (target, tp) = f.req(self, "target")?;
                    let target = path_value(target, &tp)?;
                    f.finish(self)?;
                    Ok(Follower { link, target })
                },
                |f: &Follower| f.link.to_string(),
            )?,
            None => Vec::new(),
        };
        o.finish(self)?;
        Ok(Alternative {
            name,
            link,
            target,
            priority,
            followers,
        })
    }

    fn state(&mut self, v: &Value, p: &Path) -> R<State> {
        let mut o = Obj::new(v, p)?;
        let version = match o.opt(self, "version") {
            Some((v, p)) => {
                let n = unsigned(v, &p)?;
                if n == 0 {
                    return err(&p, ErrorKind::DefaultValue);
                }
                n
            }
            None => 0,
        };
        let migration = enum_field!(o, self, "migration", Migration, Some(Migration::None))
            .unwrap_or(Migration::None);
        let state_paths = match o.opt(self, "paths") {
            Some((v, p)) => sorted(
                v,
                &p,
                |item, at| self.state_path(item, at),
                |s: &StatePath| s.path.to_string(),
            )?,
            None => Vec::new(),
        };
        let files = match o.opt(self, "files") {
            Some((v, p)) => sorted(
                v,
                &p,
                |item, at| {
                    let mut f = Obj::new(item, at)?;
                    let (path, pp) = f.req(self, "path")?;
                    let path = path_value(path, &pp)?;
                    let (owner, group) = self.owner(&mut f)?;
                    let mode = self.mode(&mut f, 0o644)?;
                    f.finish(self)?;
                    under_state(&path, &pp)?;
                    Ok(StateFile {
                        path,
                        owner,
                        group,
                        mode,
                    })
                },
                |f: &StateFile| f.path.to_string(),
            )?,
            None => Vec::new(),
        };
        let seeds = match o.opt(self, "seeds") {
            Some((v, p)) => sorted(
                v,
                &p,
                |item, at| {
                    let mut s = Obj::new(item, at)?;
                    let (path, pp) = s.req(self, "path")?;
                    let path = path_value(path, &pp)?;
                    let (from, fp) = s.req(self, "from")?;
                    let from = path_value(from, &fp)?;
                    s.finish(self)?;
                    under_state(&path, &pp)?;
                    Ok(Seed { path, from })
                },
                |s: &Seed| s.path.to_string(),
            )?,
            None => Vec::new(),
        };
        let obsolete = o
            .opt(self, "obsolete")
            .map(|(v, p)| paths(v, &p))
            .transpose()?
            .unwrap_or_default();
        let migrations = match o.opt(self, "migrations") {
            Some((v, p)) => sorted(
                v,
                &p,
                |item, at| self.migration(item, at),
                |m: &StateMigration| format!("{:020}", m.from),
            )?,
            None => Vec::new(),
        };
        o.finish(self)?;
        Ok(State {
            version,
            migration,
            paths: state_paths,
            files,
            seeds,
            obsolete,
            migrations,
        })
    }

    fn owner(&mut self, o: &mut Obj<'_>) -> R<(Account, Account)> {
        let root = Account::root();
        let mut get = |key: &'static str| -> R<Account> {
            match o.opt(self, key) {
                Some((v, p)) => {
                    let a: Account = parse(v, &p)?;
                    if a == root {
                        return err(&p, ErrorKind::DefaultValue);
                    }
                    Ok(a)
                }
                None => Ok(root.clone()),
            }
        };
        Ok((get("owner")?, get("group")?))
    }

    fn mode(&mut self, o: &mut Obj<'_>, default: u16) -> R<Mode> {
        match o.opt(self, "mode") {
            Some((v, p)) => {
                let m: Mode = parse(v, &p)?;
                if m.value() == default {
                    return err(&p, ErrorKind::DefaultValue);
                }
                Ok(m)
            }
            None => Mode::new(default)
                .ok_or_else(|| Error::at(&o.path, ErrorKind::Invalid("bad default mode".into()))),
        }
    }

    fn state_path(&mut self, v: &Value, p: &Path) -> R<StatePath> {
        let mut o = Obj::new(v, p)?;
        let (path, pp) = o.req(self, "path")?;
        let path = path_value(path, &pp)?;
        let (class, cp) = o.req(self, "class")?;
        let class = enum_value(class, &cp, Class::from_text, Class::allowed)?;
        let (owner, group) = self.owner(&mut o)?;
        let mode = self.mode(&mut o, 0o755)?;
        let flush =
            enum_field!(o, self, "flush", Flush, Some(Flush::Never)).unwrap_or(Flush::Never);
        let recurse = flag(&mut o, self, "recurse", false)?;
        let on_remove = enum_field!(o, self, "on-remove", OnRemove, None::<OnRemove>);
        o.finish(self)?;
        under_state(&path, &pp)?;
        if recurse && !matches!(class, Class::Cache | Class::Log) {
            return rule(p, "recurse is only for cache and log paths");
        }
        Ok(StatePath {
            path,
            class,
            owner,
            group,
            mode,
            flush,
            recurse,
            on_remove,
        })
    }

    fn migration(&mut self, v: &Value, p: &Path) -> R<StateMigration> {
        let mut o = Obj::new(v, p)?;
        let (from, fp) = o.req(self, "from")?;
        let from = unsigned(from, &fp)?;
        let (to, tp) = o.req(self, "to")?;
        let to = unsigned(to, &tp)?;
        if from.checked_add(1) != Some(to) {
            return rule(
                &tp,
                "a migration goes from one state version to the next: to = from + 1",
            );
        }
        let ops = o.opt(self, "ops");
        let run = o.opt(self, "run");
        let reversibility = o.opt(self, "reversibility");
        let reverse = o.opt(self, "reverse");
        let action = match (ops, run) {
            (Some((v, p)), None) => {
                if reversibility.is_some() || reverse.is_some() {
                    return rule(
                        &p,
                        "a migration made of ops is reversible by construction; leave out reversibility and reverse",
                    );
                }
                let items = array(v, &p)?;
                let mut list = Vec::with_capacity(items.len());
                for (i, item) in items.iter().enumerate() {
                    list.push(self.op(item, &p.index(i))?);
                }
                MigrationAction::Ops(list)
            }
            (None, Some((v, rp))) => {
                let run = path_value(v, &rp)?;
                let Some((rv, rvp)) = reversibility else {
                    return err(p, ErrorKind::Missing("reversibility"));
                };
                let reverse = match (string(rv, &rvp)?, reverse) {
                    ("reversible", Some((v, p))) => Some(path_value(v, &p)?),
                    ("reversible", None) => return err(p, ErrorKind::Missing("reverse")),
                    ("irreversible", None) => None,
                    ("irreversible", Some((_, p))) => {
                        return rule(&p, "an irreversible migration has no reverse");
                    }
                    (other, _) => {
                        return err(
                            &rvp,
                            ErrorKind::UnknownValue {
                                found: other.to_owned(),
                                allowed: "reversible or irreversible".into(),
                            },
                        );
                    }
                };
                MigrationAction::Run { run, reverse }
            }
            _ => return rule(p, "a migration has either ops or run"),
        };
        o.finish(self)?;
        Ok(StateMigration { from, to, action })
    }

    fn op(&mut self, v: &Value, p: &Path) -> R<MigrationOp> {
        let mut o = Obj::new(v, p)?;
        let kinds = ["rename", "move", "link", "remove", "chown"];
        let present: Vec<&str> = kinds
            .iter()
            .copied()
            .filter(|k| o.map.contains_key(*k))
            .collect();
        let [kind] = present.as_slice() else {
            return rule(
                p,
                "an op is exactly one of rename, move, link, remove or chown",
            );
        };
        let op = match *kind {
            "rename" | "move" => {
                let (path, pp) = o.req(self, if *kind == "rename" { "rename" } else { "move" })?;
                let path = path_value(path, &pp)?;
                let (to, tp) = o.req(self, "to")?;
                let to = path_value(to, &tp)?;
                if *kind == "rename" {
                    MigrationOp::Rename { path, to }
                } else {
                    MigrationOp::Move { path, to }
                }
            }
            "link" => {
                let (path, pp) = o.req(self, "link")?;
                let path = path_value(path, &pp)?;
                let (to, tp) = o.req(self, "to")?;
                let to = ascii(to, &tp, 4096, "a link target")?;
                MigrationOp::Link { path, to }
            }
            "remove" => {
                let (path, pp) = o.req(self, "remove")?;
                MigrationOp::Remove {
                    path: path_value(path, &pp)?,
                }
            }
            _ => {
                let (path, pp) = o.req(self, "chown")?;
                let path = path_value(path, &pp)?;
                let owner = o
                    .opt(self, "owner")
                    .map(|(v, p)| parse(v, &p))
                    .transpose()?;
                let group = o
                    .opt(self, "group")
                    .map(|(v, p)| parse(v, &p))
                    .transpose()?;
                if owner.is_none() && group.is_none() {
                    return rule(p, "a chown names an owner, a group or both");
                }
                MigrationOp::Chown { path, owner, group }
            }
        };
        o.finish(self)?;
        Ok(op)
    }

    fn setting(&mut self, v: &Value, p: &Path) -> R<Setting> {
        let mut o = Obj::new(v, p)?;
        let (name, np) = o.req(self, "name")?;
        let name: Id = parse(name, &np)?;
        let (kind, kp) = o.req(self, "type")?;
        let kind = enum_value(kind, &kp, SettingType::from_text, SettingType::allowed)?;
        let default = o.opt(self, "default");
        let required = flag(&mut o, self, "required", false)?;
        let description = o
            .opt(self, "description")
            .map(|(v, p)| free(v, &p, 200, false))
            .transpose()?;
        let min = o
            .opt(self, "min")
            .map(|(v, p)| integer(v, &p).map(|n| (n, p)))
            .transpose()?;
        let max = o
            .opt(self, "max")
            .map(|(v, p)| integer(v, &p).map(|n| (n, p)))
            .transpose()?;
        let pattern = match o.opt(self, "pattern") {
            Some((v, p)) => {
                let s = string(v, &p)?;
                if s.is_empty() || s.len() > 256 {
                    return err(
                        &p,
                        ErrorKind::OutOfRange("a pattern is 1 to 256 bytes".into()),
                    );
                }
                pattern(s)
                    .or_else(|e| invalid(&p, format!("not a valid regular expression: {e}")))?;
                Some((s.to_owned(), p))
            }
            None => None,
        };
        let choices = match o.opt(self, "choices") {
            Some((v, p)) => Some((set(v, &p, |i, a| ascii(i, a, 128, "a choice"))?, p)),
            None => None,
        };
        let aliases = match o.opt(self, "aliases") {
            Some((v, p)) => {
                let mut out = BTreeMap::new();
                for (system, value) in map(v, &p)? {
                    let at = p.entry(system);
                    word(
                        &Value::Str(system.clone()),
                        &at,
                        32,
                        |c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-',
                        "an alias system",
                    )?;
                    out.insert(system.clone(), ascii(value, &at, 128, "an alias")?);
                }
                out
            }
            None => BTreeMap::new(),
        };
        o.finish(self)?;

        // Fields that belong to one type only.
        let int = matches!(kind, SettingType::Int);
        if let Some((_, p)) = min
            .as_ref()
            .filter(|_| !int)
            .or(max.as_ref().filter(|_| !int))
        {
            return rule(p, "min and max are only for int settings");
        }
        if let (Some((lo, _)), Some((hi, hp))) = (&min, &max)
            && lo > hi
        {
            return rule(hp, "max is below min");
        }
        if let Some((_, p)) = pattern.as_ref().filter(|_| kind != SettingType::String) {
            return rule(p, "pattern is only for string settings");
        }
        let has_choices = matches!(kind, SettingType::Choice | SettingType::Multichoice);
        match (&choices, has_choices) {
            (Some((_, p)), false) => {
                return rule(p, "choices are only for choice and multichoice settings");
            }
            (None, true) => return err(p, ErrorKind::Missing("choices")),
            _ => {}
        }
        if required && default.is_some() {
            return rule(p, "a required setting has no default");
        }
        let choices = choices.map(|(c, _)| c).unwrap_or_default();
        let default = default
            .map(|(v, dp)| {
                setting_value(
                    kind,
                    v,
                    &dp,
                    min.as_ref().map(|m| m.0),
                    max.as_ref().map(|m| m.0),
                    &choices,
                )
            })
            .transpose()?;
        Ok(Setting {
            name,
            kind,
            default,
            required,
            description,
            min: min.map(|m| m.0),
            max: max.map(|m| m.0),
            pattern: pattern.map(|(s, _)| s),
            choices,
            aliases,
        })
    }

    fn hooks(&mut self, v: &Value, p: &Path) -> R<BTreeMap<Phase, Vec<Step>>> {
        let mut out = BTreeMap::new();
        for (key, value) in map(v, p)? {
            let at = p.entry(key);
            let phase = Phase::from_text(key).ok_or_else(|| {
                Error::at(
                    &at,
                    ErrorKind::UnknownValue {
                        found: key.clone(),
                        allowed: Phase::allowed(),
                    },
                )
            })?;
            let items = array(value, &at)?;
            let mut steps = Vec::with_capacity(items.len());
            for (i, item) in items.iter().enumerate() {
                steps.push(self.step(item, &at.index(i))?);
            }
            out.insert(phase, steps);
        }
        Ok(out)
    }

    fn step(&mut self, v: &Value, p: &Path) -> R<Step> {
        let mut o = Obj::new(v, p)?;
        let (exec, ep) = o.req(self, "exec")?;
        let exec = command(exec, &ep)?;
        let timeout = seconds(&mut o, self, 300)?;
        let writes = o
            .opt(self, "writes")
            .map(|(v, p)| paths(v, &p))
            .transpose()?
            .unwrap_or_default();
        let network = flag(&mut o, self, "network", false)?;
        let execs = o
            .opt(self, "execs")
            .map(|(v, p)| paths(v, &p))
            .transpose()?
            .unwrap_or_default();
        let legacy = flag(&mut o, self, "legacy", false)?;
        o.finish(self)?;
        Ok(Step {
            exec,
            timeout,
            writes,
            network,
            execs,
            legacy,
        })
    }

    fn test(&mut self, v: &Value, p: &Path) -> R<Test> {
        let mut o = Obj::new(v, p)?;
        let (name, np) = o.req(self, "name")?;
        let name = parse(name, &np)?;
        let (exec, ep) = o.req(self, "exec")?;
        let exec = command(exec, &ep)?;
        let timeout = seconds(&mut o, self, 60)?;
        o.finish(self)?;
        Ok(Test {
            name,
            exec,
            timeout,
        })
    }

    fn security(&mut self, v: &Value, p: &Path) -> R<Security> {
        let mut o = Obj::new(v, p)?;
        let selinux = match o.opt(self, "selinux") {
            Some((v, p)) => {
                let mut s = Obj::new(v, &p)?;
                let modules = s
                    .opt(self, "modules")
                    .map(|(v, p)| paths(v, &p))
                    .transpose()?
                    .unwrap_or_default();
                let booleans = match s.opt(self, "booleans") {
                    Some((v, p)) => {
                        let mut out = BTreeMap::new();
                        for (name, value) in map(v, &p)? {
                            let at = p.entry(name);
                            word(
                                &Value::Str(name.clone()),
                                &at,
                                128,
                                |c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_',
                                "an SELinux boolean",
                            )?;
                            out.insert(name.clone(), boolean(value, &at)?);
                        }
                        out
                    }
                    None => BTreeMap::new(),
                };
                let ports = match s.opt(self, "ports") {
                    Some((v, p)) => {
                        let items = array(v, &p)?;
                        let mut out = Vec::with_capacity(items.len());
                        for (i, item) in items.iter().enumerate() {
                            let at = p.index(i);
                            let mut q = Obj::new(item, &at)?;
                            let (kind, kp) = q.req(self, "type")?;
                            let kind = selinux_type(kind, &kp)?;
                            let (proto, pp) = q.req(self, "proto")?;
                            let proto = enum_value(proto, &pp, Proto::from_text, Proto::allowed)?;
                            let (port, np) = q.req(self, "port")?;
                            let port = port_number(port, &np)?;
                            q.finish(self)?;
                            out.push(Port { kind, proto, port });
                        }
                        out
                    }
                    None => Vec::new(),
                };
                let fcontexts = match s.opt(self, "fcontexts") {
                    Some((v, p)) => {
                        let items = array(v, &p)?;
                        let mut out = Vec::with_capacity(items.len());
                        for (i, item) in items.iter().enumerate() {
                            let at = p.index(i);
                            let mut f = Obj::new(item, &at)?;
                            let (pattern, pp) = f.req(self, "pattern")?;
                            let pattern = ascii(pattern, &pp, 255, "a file-context pattern")?;
                            if !pattern.starts_with('/') {
                                return invalid(&pp, "a file-context pattern starts with '/'");
                            }
                            let (kind, kp) = f.req(self, "type")?;
                            let kind = selinux_type(kind, &kp)?;
                            let file_type =
                                enum_field!(f, self, "file-type", FileType, Some(FileType::All))
                                    .unwrap_or(FileType::All);
                            f.finish(self)?;
                            out.push(Fcontext {
                                pattern,
                                kind,
                                file_type,
                            });
                        }
                        out
                    }
                    None => Vec::new(),
                };
                s.finish(self)?;
                Some(SeLinux {
                    modules,
                    booleans,
                    ports,
                    fcontexts,
                })
            }
            None => None,
        };
        let apparmor = match o.opt(self, "apparmor") {
            Some((v, p)) => {
                let mut a = Obj::new(v, &p)?;
                let profiles = a
                    .opt(self, "profiles")
                    .map(|(v, p)| paths(v, &p))
                    .transpose()?
                    .unwrap_or_default();
                let tunables = match a.opt(self, "tunables") {
                    Some((v, p)) => {
                        let mut out = BTreeMap::new();
                        for (name, value) in map(v, &p)? {
                            let at = p.entry(name);
                            word(
                                &Value::Str(name.clone()),
                                &at,
                                128,
                                |c| c.is_ascii_alphanumeric() || c == '_',
                                "an AppArmor tunable",
                            )?;
                            out.insert(name.clone(), ascii(value, &at, 1024, "a tunable value")?);
                        }
                        out
                    }
                    None => BTreeMap::new(),
                };
                a.finish(self)?;
                Some(AppArmor { profiles, tunables })
            }
            None => None,
        };
        o.finish(self)?;
        Ok(Security { selinux, apparmor })
    }

    fn delegated(&mut self, v: &Value, p: &Path) -> R<Delegated> {
        let mut o = Obj::new(v, p)?;
        let (authority, ap) = o.req(self, "authority")?;
        let mut a = Obj::new(authority, &ap)?;
        let (kind, kp) = a.req(self, "kind")?;
        let kind = string(kind, &kp)?;
        if kind != "self" {
            return err(
                &kp,
                ErrorKind::UnknownValue {
                    found: kind.to_owned(),
                    allowed: "self".into(),
                },
            );
        }
        let (exec, ep) = a.req(self, "exec")?;
        let exec = path_value(exec, &ep)?;
        a.finish(self)?;
        let (dpaths, pp) = o.req(self, "paths")?;
        let dpaths = set(dpaths, &pp, |item, at| {
            let s = ascii(item, at, 255, "a delegated path")?;
            if s.starts_with('/') || s.split('/').any(|part| part == "..") {
                return invalid(
                    at,
                    "a delegated path is relative and stays inside the delegated area",
                );
            }
            Ok(s)
        })?;
        let (initial, ip) = o.req(self, "initial")?;
        let initial = string(initial, &ip)?;
        let initial: Facet = initial
            .strip_prefix("facet:")
            .ok_or_else(|| Error::at(&ip, ErrorKind::Invalid("initial is facet:<facet>".into())))?
            .parse()
            .or_else(|e| invalid(&ip, e))?;
        let (identify, idp) = o.req(self, "identify")?;
        let items = array(identify, &idp)?;
        let mut methods = Vec::with_capacity(items.len());
        for (i, item) in items.iter().enumerate() {
            methods.push(self.identify(item, &idp.index(i))?);
        }
        let (require, rp) = o.req(self, "require")?;
        let require = enum_value(require, &rp, Evidence::from_text, Evidence::allowed)?;
        let (insufficient, np) = o.req(self, "on-insufficient")?;
        let on_insufficient = enum_value(
            insufficient,
            &np,
            OnInsufficient::from_text,
            OnInsufficient::allowed,
        )?;
        let payload_on_upgrade = enum_field!(
            o,
            self,
            "payload-on-upgrade",
            PayloadOnUpgrade,
            Some(PayloadOnUpgrade::KeepNewer)
        )
        .unwrap_or(PayloadOnUpgrade::KeepNewer);
        o.finish(self)?;
        Ok(Delegated {
            authority: (kind.to_owned(), exec),
            paths: dpaths,
            initial,
            identify: methods,
            require,
            on_insufficient,
            payload_on_upgrade,
        })
    }

    fn identify(&mut self, v: &Value, p: &Path) -> R<Identify> {
        let mut o = Obj::new(v, p)?;
        let (method, mp) = o.req(self, "method")?;
        let method = string(method, &mp)?.to_owned();
        let fields: &[&'static str] = match method.as_str() {
            "signature" => &["issuer", "sigstore-identity"],
            "release-index" => &["signed-by", "url"],
            "elf-note" => &["field", "file", "note"],
            "go-buildinfo" | "cargo-auditable" => &["file"],
            "string" => &["file", "pattern"],
            "exec" => &["command", "match"],
            other => {
                return err(&mp, ErrorKind::UnknownValue {
                    found: other.to_owned(),
                    allowed: "signature, release-index, elf-note, go-buildinfo, cargo-auditable, string or exec".into(),
                });
            }
        };
        let mut out = BTreeMap::new();
        for &field in fields {
            let (value, fp) = o.req(self, field)?;
            match field {
                "command" => {
                    command(value, &fp)?;
                }
                "issuer" | "url" => {
                    parse::<Url>(value, &fp)?;
                }
                _ => {
                    ascii(value, &fp, 512, "an identify field")?;
                }
            }
            out.insert(field.to_owned(), value.clone());
        }
        o.finish(self)?;
        Ok(Identify {
            method,
            fields: out,
        })
    }

    fn support(&mut self, v: &Value, p: &Path) -> R<Support> {
        let mut o = Obj::new(v, p)?;
        let (active, ap) = o.req(self, "active-until")?;
        let active_until: Date = parse(active, &ap)?;
        let (security, sp) = o.req(self, "security-until")?;
        let security_until: Date = parse(security, &sp)?;
        let successor = o
            .opt(self, "successor")
            .map(|(v, p)| parse(v, &p))
            .transpose()?;
        o.finish(self)?;
        if security_until < active_until {
            return rule(&sp, "security-until can't be before active-until");
        }
        Ok(Support {
            active_until,
            security_until,
            successor,
        })
    }

    fn notice(&mut self, v: &Value, p: &Path) -> R<Notice> {
        let mut o = Obj::new(v, p)?;
        let (id, ip) = o.req(self, "id")?;
        let id = parse(id, &ip)?;
        let (text, tp) = o.req(self, "text")?;
        let text = free(text, &tp, 2000, true)?;
        o.finish(self)?;
        Ok(Notice { id, text })
    }
}

fn provide(v: &Value, p: &Path) -> R<Provide> {
    canonical(v, p, str::parse, Provide::to_string)
}

fn replace(v: &Value, p: &Path) -> R<Requirement> {
    let e = canonical(
        v,
        p,
        |t| t.parse::<Expr>().map_err(|e| e.to_string()),
        Expr::to_string,
    )?;
    match e {
        Expr::Req(r) if matches!(r.atom, Atom::Package(_)) && r.facets.is_empty() => Ok(r),
        _ => invalid(
            p,
            "replaces names one package, with an optional version constraint",
        ),
    }
}

fn condition(v: &Value, p: &Path) -> R<Condition> {
    canonical(v, p, str::parse, Condition::to_string)
}

fn command(v: &Value, p: &Path) -> R<Vec<String>> {
    let items = array(v, p)?;
    let mut out = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let at = p.index(i);
        if i == 0 {
            path_value(item, &at)?;
        }
        out.push(free(item, &at, 4096, false)?);
    }
    Ok(out)
}

fn seconds(o: &mut Obj<'_>, d: &mut Decoder, default: u64) -> R<u64> {
    match o.opt(d, "timeout") {
        Some((v, p)) => {
            let n = unsigned(v, &p)?;
            if n == default {
                return err(&p, ErrorKind::DefaultValue);
            }
            if n == 0 || n > 86_400 {
                return err(
                    &p,
                    ErrorKind::OutOfRange("a timeout is 1 to 86400 seconds".into()),
                );
            }
            Ok(n)
        }
        None => Ok(default),
    }
}

fn selinux_type(v: &Value, p: &Path) -> R<String> {
    word(
        v,
        p,
        128,
        |c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_',
        "an SELinux type",
    )
}

fn port_number(v: &Value, p: &Path) -> R<u16> {
    let n = integer(v, p)?;
    u16::try_from(n).ok().filter(|&n| n > 0).ok_or_else(|| {
        Error::at(
            p,
            ErrorKind::OutOfRange(format!("a port is 1 to 65535; {n} isn't")),
        )
    })
}

fn under_state(path: &FilePath, p: &Path) -> R<()> {
    let s = path.as_str();
    if s.starts_with("/var/") || s.starts_with("/run/") {
        Ok(())
    } else {
        rule(p, "state paths are under /var or /run")
    }
}

/// Placeholders a string default may use.
const HOST_FACTS: [&str; 4] = [
    "{host.fqdn}",
    "{host.hostname}",
    "{host.domain}",
    "{host.arch}",
];

fn setting_value(
    kind: SettingType,
    v: &Value,
    p: &Path,
    min: Option<i64>,
    max: Option<i64>,
    choices: &[String],
) -> R<SettingValue> {
    let has_placeholder = |s: &str| s.contains('{') || s.contains('}');
    let plain = |s: &str| -> R<()> {
        if has_placeholder(s) {
            return rule(p, "only string settings may use {host.*} placeholders");
        }
        Ok(())
    };
    match kind {
        SettingType::Bool => Ok(SettingValue::Bool(boolean(v, p)?)),
        SettingType::Int => {
            let n = integer(v, p)?;
            if min.is_some_and(|m| n < m) || max.is_some_and(|m| n > m) {
                return err(
                    p,
                    ErrorKind::OutOfRange("the default is outside min and max".into()),
                );
            }
            Ok(SettingValue::Int(n))
        }
        SettingType::Port => Ok(SettingValue::Int(i64::from(port_number(v, p)?))),
        SettingType::String => {
            let s = free(v, p, 1024, false)?;
            // Braces only as whole, known placeholders.
            let mut rest = s.clone();
            for fact in HOST_FACTS {
                rest = rest.replace(fact, "");
            }
            if has_placeholder(&rest) {
                return invalid(
                    p,
                    "the only placeholders are {host.fqdn}, {host.hostname}, {host.domain} and {host.arch}",
                );
            }
            Ok(SettingValue::Str(s))
        }
        SettingType::Choice => {
            let s = string(v, p)?;
            plain(s)?;
            if !choices.iter().any(|c| c == s) {
                return invalid(p, format!("{s:?} isn't one of the choices"));
            }
            Ok(SettingValue::Str(s.to_owned()))
        }
        SettingType::Path => {
            let path: FilePath = parse(v, p)?;
            Ok(SettingValue::Str(path.to_string()))
        }
        SettingType::Multichoice => {
            let list = set(v, p, |i, a| string(i, a).map(str::to_owned))?;
            if let Some(bad) = list.iter().find(|s| !choices.contains(s)) {
                return invalid(p, format!("{bad:?} isn't one of the choices"));
            }
            Ok(SettingValue::List(list))
        }
        SettingType::List => {
            let items = array(v, p)?;
            let mut out = Vec::with_capacity(items.len());
            for (i, item) in items.iter().enumerate() {
                let at = p.index(i);
                let s = free(item, &at, 1024, false)?;
                plain(&s)?;
                out.push(s);
            }
            Ok(SettingValue::List(out))
        }
    }
}

/// Checks a regular expression as `regex_syntax::Parser` does, in its two
/// steps, so a mistake is told on one line: what is wrong, and where.
/// The crate's own message quotes the pattern over several lines.
fn pattern(text: &str) -> Result<(), String> {
    let at = |offset: usize| format!("at byte {offset} of the pattern");
    let ast = regex_syntax::ast::parse::Parser::new()
        .parse(text)
        .map_err(|e| format!("{}, {}", e.kind(), at(e.span().start.offset)))?;
    regex_syntax::hir::translate::Translator::new()
        .translate(text, &ast)
        .map_err(|e| format!("{}, {}", e.kind(), at(e.span().start.offset)))?;
    Ok(())
}

/// Rules linking fields across the manifest.
fn check_rules(m: &Manifest, facets_path: &Path) -> R<()> {
    let root = Path::default();
    match m.kind {
        Kind::Update => {
            if m.version.update() == 0 {
                return rule(
                    &root.key("version"),
                    "an update package's version has an update level of 1 or more",
                );
            }
        }
        Kind::Base | Kind::SystemBase => {
            if m.version.update() != 0 {
                return rule(
                    &root.key("version").key("update"),
                    "only update packages have an update level",
                );
            }
            if !m.removes.is_empty() {
                return rule(&root.key("updates"), "only update packages have updates");
            }
            if !m.facets.keys().any(|f| f.as_str() == "runtime") {
                return rule(facets_path, "a base package has a runtime facet");
            }
        }
    }
    // Unit conditions name a setting of the package, with a matching value.
    for (i, unit) in m.declares.units.iter().enumerate() {
        let Some(cond) = &unit.condition else {
            continue;
        };
        let at = root.key("declares").key("units").index(i).key("if");
        let Some(setting) = m.settings.iter().find(|s| s.name == cond.setting) else {
            return rule(&at, format!("no setting is named {}", cond.setting));
        };
        if cond.value.is_none() && setting.kind != SettingType::Bool {
            return rule(
                &at,
                "setting.<name> alone needs a bool setting; compare others with '='",
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::known::KNOWN_FIELDS;

    #[test]
    fn the_known_field_list_is_exactly_what_the_decoder_reads() {
        let v = crate::json::parse(include_str!("../tests/data/everything.json")).unwrap();
        let mut d = Decoder::new();
        d.manifest(&v).unwrap();
        let listed: BTreeSet<String> = KNOWN_FIELDS.iter().map(|s| (*s).to_owned()).collect();
        let missing: Vec<&String> = d.known.difference(&listed).collect();
        let stale: Vec<&String> = listed.difference(&d.known).collect();
        assert!(
            missing.is_empty() && stale.is_empty(),
            "add to KNOWN_FIELDS: {missing:?}; remove: {stale:?}"
        );
        assert!(
            KNOWN_FIELDS.windows(2).all(|w| w[0] < w[1]),
            "KNOWN_FIELDS is sorted"
        );
    }
}
